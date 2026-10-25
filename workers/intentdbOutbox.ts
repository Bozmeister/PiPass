/**
 * Phase 1 IntentDB primitive: local ciphertext outbox.
 *
 * After a vault entry or secure note is saved or deleted, this appends
 * one SecureStore record containing either a ciphertext manifest or a
 * tombstone. It does not write the shared autofill blob, does not perform
 * network I/O, and does not read the master key or account auth hash.
 *
 * A record that is not fully authenticated v4 is not enqueued. The vault
 * write itself still stands. Deletion of a manifestable item binds the
 * tombstone to that item's content hash. Deletion of anything else records
 * an unbound tombstone (id and kind only) so plaintext is never copied in.
 */

import {
  buildSecureNoteManifest,
  buildVaultEntryManifest,
  ItemManifestError,
  sha256Utf8Hex,
  verifyItemManifest,
  type ItemKind,
  type ItemManifest,
} from "../lib/intentdb/itemManifest";
import {
  deletePlatformItem,
  readPlatformItem,
  writePlatformItem,
} from "../lib/platformStorage";
import type { SecureNote, VaultEntry } from "./vaultWorker";

export const OUTBOX_INDEX_KEY = "pipass_intentdb_outbox_index";
export const OUTBOX_KEY_PREFIX = "pipass_intentdb_outbox_";
export const TOMBSTONE_SCHEMA = "pipass-tombstone-v1" as const;

export type OutboxErrorCode = "corrupt-index" | "missing-record" | "corrupt-record";

export class OutboxError extends Error {
  readonly code: OutboxErrorCode;

  constructor(code: OutboxErrorCode, message: string) {
    super(message);
    this.name = "OutboxError";
    this.code = code;
  }
}

/**
 * Client-local delete marker. `contentBound` is true only when
 * `contentSha256` is the manifest hash of the ciphertext that was removed.
 */
export interface ItemTombstone {
  schema: typeof TOMBSTONE_SCHEMA;
  itemId: string;
  kind: ItemKind;
  itemVersion: number;
  contentSha256: string;
  contentBound: boolean;
  deletedAt: number;
}

export type OutboxRecord =
  | { kind: "manifest"; enqueuedAt: number; manifest: ItemManifest }
  | { kind: "tombstone"; enqueuedAt: number; tombstone: ItemTombstone };

export type OutboxAppendResult =
  | { enqueued: true; record: OutboxRecord }
  | { enqueued: false; reason: ItemManifestError["code"] };

function outboxKey(seq: number): string {
  return `${OUTBOX_KEY_PREFIX}${String(seq).padStart(10, "0")}`;
}

function unboundDeleteHash(kind: ItemKind, itemId: string): string {
  return sha256Utf8Hex(`pipass-intentdb-delete-v1|${kind}|${JSON.stringify(itemId)}`);
}

async function readIndex(): Promise<number[]> {
  const raw = await readPlatformItem(OUTBOX_INDEX_KEY);
  if (raw === null || raw === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OutboxError("corrupt-index", "IntentDB outbox index is not JSON");
  }
  if (
    !Array.isArray(parsed) ||
    parsed.some((value) => typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
  ) {
    throw new OutboxError("corrupt-index", "IntentDB outbox index is corrupt");
  }
  return parsed as number[];
}

function parseManifest(value: unknown): ItemManifest {
  if (!value || typeof value !== "object") {
    throw new OutboxError("corrupt-record", "Outbox manifest is not an object");
  }
  const manifest = value as ItemManifest;
  if (!verifyItemManifest(manifest)) {
    throw new OutboxError("corrupt-record", "Outbox manifest failed content-hash check");
  }
  return manifest;
}

function parseTombstone(value: unknown): ItemTombstone {
  if (!value || typeof value !== "object") {
    throw new OutboxError("corrupt-record", "Outbox tombstone is not an object");
  }
  const tombstone = value as ItemTombstone;
  if (tombstone.schema !== TOMBSTONE_SCHEMA) {
    throw new OutboxError("corrupt-record", "Outbox tombstone schema is not phase 1");
  }
  if (tombstone.kind !== "vault-entry" && tombstone.kind !== "secure-note") {
    throw new OutboxError("corrupt-record", "Outbox tombstone kind is invalid");
  }
  if (typeof tombstone.itemId !== "string" || tombstone.itemId.length === 0) {
    throw new OutboxError("corrupt-record", "Outbox tombstone itemId is invalid");
  }
  if (
    typeof tombstone.itemVersion !== "number" ||
    !Number.isSafeInteger(tombstone.itemVersion) ||
    tombstone.itemVersion < 0
  ) {
    throw new OutboxError("corrupt-record", "Outbox tombstone version is invalid");
  }
  if (typeof tombstone.contentSha256 !== "string" || !/^[0-9a-f]{64}$/.test(tombstone.contentSha256)) {
    throw new OutboxError("corrupt-record", "Outbox tombstone hash is invalid");
  }
  if (typeof tombstone.contentBound !== "boolean") {
    throw new OutboxError("corrupt-record", "Outbox tombstone contentBound is invalid");
  }
  if (
    typeof tombstone.deletedAt !== "number" ||
    !Number.isSafeInteger(tombstone.deletedAt) ||
    tombstone.deletedAt <= 0
  ) {
    throw new OutboxError("corrupt-record", "Outbox tombstone deletedAt is invalid");
  }
  return {
    schema: TOMBSTONE_SCHEMA,
    itemId: tombstone.itemId,
    kind: tombstone.kind,
    itemVersion: tombstone.itemVersion,
    contentSha256: tombstone.contentSha256,
    contentBound: tombstone.contentBound,
    deletedAt: tombstone.deletedAt,
  };
}

function parseOutboxRecord(raw: string): OutboxRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OutboxError("corrupt-record", "Outbox record is not JSON");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new OutboxError("corrupt-record", "Outbox record is not an object");
  }
  const record = parsed as OutboxRecord;
  if (
    typeof record.enqueuedAt !== "number" ||
    !Number.isSafeInteger(record.enqueuedAt) ||
    record.enqueuedAt <= 0
  ) {
    throw new OutboxError("corrupt-record", "Outbox record enqueuedAt is invalid");
  }
  if (record.kind === "manifest") {
    return { kind: "manifest", enqueuedAt: record.enqueuedAt, manifest: parseManifest(record.manifest) };
  }
  if (record.kind === "tombstone") {
    return {
      kind: "tombstone",
      enqueuedAt: record.enqueuedAt,
      tombstone: parseTombstone(record.tombstone),
    };
  }
  throw new OutboxError("corrupt-record", "Outbox record kind is invalid");
}

async function appendOutboxRecord(record: OutboxRecord): Promise<OutboxRecord> {
  const index = await readIndex();
  const seq = index.reduce((max, value) => Math.max(max, value), 0) + 1;
  await writePlatformItem(outboxKey(seq), JSON.stringify(record));
  index.push(seq);
  await writePlatformItem(OUTBOX_INDEX_KEY, JSON.stringify(index));
  return record;
}

function manifestRecord(manifest: ItemManifest, enqueuedAt: number): OutboxRecord {
  return { kind: "manifest", enqueuedAt, manifest };
}

function tombstoneFor(
  kind: ItemKind,
  itemId: string,
  manifest: ItemManifest | null,
  deletedAt: number,
): ItemTombstone {
  if (manifest && manifest.itemId === itemId && manifest.kind === kind) {
    return {
      schema: TOMBSTONE_SCHEMA,
      itemId,
      kind,
      itemVersion: manifest.version,
      contentSha256: manifest.contentSha256,
      contentBound: true,
      deletedAt,
    };
  }
  return {
    schema: TOMBSTONE_SCHEMA,
    itemId,
    kind,
    itemVersion: 0,
    contentSha256: unboundDeleteHash(kind, itemId),
    contentBound: false,
    deletedAt,
  };
}

/** Enqueue a vault entry manifest. Refused records are not written. */
export async function recordVaultEntrySaved(entry: VaultEntry): Promise<OutboxAppendResult> {
  let manifest: ItemManifest;
  try {
    manifest = buildVaultEntryManifest(entry);
  } catch (err) {
    if (err instanceof ItemManifestError) {
      return { enqueued: false, reason: err.code };
    }
    throw err;
  }
  const record = await appendOutboxRecord(manifestRecord(manifest, Date.now()));
  return { enqueued: true, record };
}

/** Enqueue a secure-note manifest. Refused records are not written. */
export async function recordSecureNoteSaved(note: SecureNote): Promise<OutboxAppendResult> {
  let manifest: ItemManifest;
  try {
    manifest = buildSecureNoteManifest(note);
  } catch (err) {
    if (err instanceof ItemManifestError) {
      return { enqueued: false, reason: err.code };
    }
    throw err;
  }
  const record = await appendOutboxRecord(manifestRecord(manifest, Date.now()));
  return { enqueued: true, record };
}

/**
 * Enqueue a deletion tombstone. `existing` is the record as it was before
 * the local delete. Pass null when the row was already gone.
 */
export async function recordVaultEntryDeleted(
  id: string,
  existing: VaultEntry | null,
): Promise<OutboxAppendResult> {
  return enqueueDeletion("vault-entry", id, existing, buildVaultEntryManifest);
}

/** Enqueue a secure-note deletion tombstone. */
export async function recordSecureNoteDeleted(
  id: string,
  existing: SecureNote | null,
): Promise<OutboxAppendResult> {
  return enqueueDeletion("secure-note", id, existing, buildSecureNoteManifest);
}

async function enqueueDeletion<T>(
  kind: ItemKind,
  id: string,
  existing: T | null,
  build: (record: T) => ItemManifest,
): Promise<OutboxAppendResult> {
  let manifest: ItemManifest | null = null;
  if (existing) {
    try {
      manifest = build(existing);
    } catch (err) {
      if (!(err instanceof ItemManifestError)) throw err;
      manifest = null;
    }
  }
  const deletedAt = Date.now();
  const record = await appendOutboxRecord({
    kind: "tombstone",
    enqueuedAt: deletedAt,
    tombstone: tombstoneFor(kind, id, manifest, deletedAt),
  });
  return { enqueued: true, record };
}

/** Read the outbox in append order. Does not contact the network. */
export async function listIntentdbOutbox(): Promise<OutboxRecord[]> {
  const index = await readIndex();
  const records: OutboxRecord[] = [];
  for (const seq of index) {
    const raw = await readPlatformItem(outboxKey(seq));
    if (raw === null) {
      throw new OutboxError("missing-record", `Missing IntentDB outbox record ${seq}`);
    }
    records.push(parseOutboxRecord(raw));
  }
  return records;
}

/**
 * Drop every outbox key. Called from nuclear reset so a wipe does not leave
 * a second copy of ciphertext manifests on the device.
 */
export async function clearIntentdbOutbox(): Promise<void> {
  const raw = await readPlatformItem(OUTBOX_INDEX_KEY);
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) {
        for (const seq of parsed) {
          if (typeof seq === "number" && Number.isSafeInteger(seq) && seq > 0) {
            await deletePlatformItem(outboxKey(seq));
          }
        }
      }
    } catch {
      // The index itself is still removed below.
    }
  }
  await deletePlatformItem(OUTBOX_INDEX_KEY);
}
