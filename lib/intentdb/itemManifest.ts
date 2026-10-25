/**
 * Phase 1 IntentDB primitive: ciphertext item manifest.
 *
 * Turns a local VaultEntry or SecureNote into a canonical, hashable
 * description of authenticated v4 field ciphertext. The manifest is safe
 * to stage outside the vault UI. It does not contain the master key, item
 * keys, or legacy plaintext titles, usernames, URLs, or note labels.
 *
 * Decryption stays in vaultWorker / crypto/encryption.ts. This module only
 * copies ciphertext and refuses records that are not fully authenticated.
 * A wrapped item key, when the record has one, is copied as the opaque v4
 * field "itemKey". The raw item key is not part of the manifest. Records
 * without that field omit it and keep the derived-key path.
 */

import CryptoJS from "crypto-js";
import { isAuthenticatedCiphertext } from "../../crypto/encryption";
import type { SecureNote, VaultEntry } from "../../workers/vaultWorker";

export const PIPASS_ITEM_SCHEMA = "pipass-item-v1" as const;

export type ItemKind = "vault-entry" | "secure-note";

export type ItemManifestErrorCode =
  | "invalid-record"
  | "invalid-id"
  | "invalid-salt"
  | "invalid-timestamp"
  | "missing-ciphertext"
  | "unauthenticated-ciphertext";

export class ItemManifestError extends Error {
  readonly code: ItemManifestErrorCode;

  constructor(code: ItemManifestErrorCode, message: string) {
    super(message);
    this.name = "ItemManifestError";
    this.code = code;
  }
}

/** One authenticated field. `name` is the AES-GCM AAD field name. */
export interface ManifestField {
  name: string;
  ciphertext: string;
}

/**
 * Ciphertext-only item. `contentSha256` is SHA-256 of
 * `canonicalManifestBody` and is not itself part of that body.
 * `version` is the record's `updatedAt` (phase 1 has no separate counter).
 */
export interface ItemManifest {
  schema: typeof PIPASS_ITEM_SCHEMA;
  itemId: string;
  kind: ItemKind;
  version: number;
  salt: string;
  createdAt: number;
  updatedAt: number;
  fields: ManifestField[];
  contentSha256: string;
}

interface ManifestBody {
  schema: typeof PIPASS_ITEM_SCHEMA;
  itemId: string;
  kind: ItemKind;
  version: number;
  salt: string;
  createdAt: number;
  updatedAt: number;
  fields: ManifestField[];
}

const ENTRY_FIELDS: { prop: keyof VaultEntry; name: string; required: boolean }[] = [
  { prop: "encryptedPassword", name: "password", required: true },
  { prop: "encryptedTitle", name: "title", required: true },
  { prop: "encryptedUsername", name: "username", required: true },
  { prop: "encryptedUrl", name: "url", required: false },
  { prop: "notes", name: "notes", required: false },
  { prop: "encryptedAux", name: "aux", required: false },
  { prop: "encryptedItemKey", name: "itemKey", required: false },
];

const NOTE_FIELDS: { prop: keyof SecureNote; name: string; required: boolean }[] = [
  { prop: "encryptedLabel", name: "label", required: true },
  { prop: "encryptedContent", name: "content", required: true },
  { prop: "encryptedItemKey", name: "itemKey", required: false },
];

/** SHA-256 of a UTF-8 string, lowercase hex. Shared by manifests and tombstones. */
export function sha256Utf8Hex(value: string): string {
  return CryptoJS.SHA256(value).toString(CryptoJS.enc.Hex);
}

function constantTimeEqualHex(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return diff === 0;
}

function requireRecord(value: object): void {
  if (value === null || Array.isArray(value)) {
    throw new ItemManifestError("invalid-record", "Item record must be an object");
  }
}

function requireItemId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128 ||
    /[\0\n\r:]/.test(value)
  ) {
    throw new ItemManifestError(
      "invalid-id",
      "Item id must be 1-128 characters without control characters or ':'",
    );
  }
  return value;
}

function requireSalt(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 16 ||
    value.length > 256 ||
    value.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(value)
  ) {
    throw new ItemManifestError(
      "invalid-salt",
      "Item salt must be even-length hex (16-256 chars)",
    );
  }
  return value.toLowerCase();
}

function requireTimestamp(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ItemManifestError(
      "invalid-timestamp",
      `${label} must be a safe non-negative integer`,
    );
  }
  return value;
}

/**
 * Copy a ciphertext field into the manifest, or refuse it.
 * Legacy plaintext properties are not read here. Callers omit them.
 */
function takeCiphertext(value: unknown, fieldName: string, required: boolean): string | undefined {
  if (value === undefined || value === null || value === "") {
    if (required) {
      throw new ItemManifestError(
        "missing-ciphertext",
        `Missing authenticated ciphertext for ${fieldName}`,
      );
    }
    return undefined;
  }
  if (typeof value !== "string" || !isAuthenticatedCiphertext(value)) {
    throw new ItemManifestError(
      "unauthenticated-ciphertext",
      `Field ${fieldName} is not authenticated v4 ciphertext`,
    );
  }
  return value;
}

function collectFields(
  record: object,
  specs: { prop: string; name: string; required: boolean }[],
): ManifestField[] {
  const source = record as unknown as Record<string, unknown>;
  const fields: ManifestField[] = [];
  for (const spec of specs) {
    const ciphertext = takeCiphertext(source[spec.prop], spec.name, spec.required);
    if (ciphertext !== undefined) {
      fields.push({ name: spec.name, ciphertext });
    }
  }
  fields.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return fields;
}

/**
 * Canonical UTF-8 JSON for the manifest hash.
 * Key order is fixed. `contentSha256` is excluded so the hash is not circular.
 * Legacy plaintext keys are not part of this document.
 */
export function canonicalManifestBody(body: ManifestBody): string {
  const fields = [...body.fields].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
  const fieldJson = fields
    .map(
      (field) =>
        `{"ciphertext":${JSON.stringify(field.ciphertext)},"name":${JSON.stringify(field.name)}}`,
    )
    .join(",");
  return `{${[
    `"createdAt":${body.createdAt}`,
    `"fields":[${fieldJson}]`,
    `"itemId":${JSON.stringify(body.itemId)}`,
    `"kind":${JSON.stringify(body.kind)}`,
    `"salt":${JSON.stringify(body.salt)}`,
    `"schema":${JSON.stringify(PIPASS_ITEM_SCHEMA)}`,
    `"updatedAt":${body.updatedAt}`,
    `"version":${body.version}`,
  ].join(",")}}`;
}

function seal(body: ManifestBody): ItemManifest {
  const contentSha256 = sha256Utf8Hex(canonicalManifestBody(body));
  return { ...body, fields: body.fields.map((field) => ({ ...field })), contentSha256 };
}

function buildBody(
  kind: ItemKind,
  record: { id: unknown; salt: unknown; createdAt: unknown; updatedAt: unknown },
  fields: ManifestField[],
): ManifestBody {
  const updatedAt = requireTimestamp(record.updatedAt, "updatedAt");
  return {
    schema: PIPASS_ITEM_SCHEMA,
    itemId: requireItemId(record.id),
    kind,
    version: updatedAt,
    salt: requireSalt(record.salt),
    createdAt: requireTimestamp(record.createdAt, "createdAt"),
    updatedAt,
    fields,
  };
}

/**
 * Build a vault-entry manifest.
 * Strips legacy `title`, `username`, and `url` plaintext. Required
 * password, title, and username ciphertext must already be v4.
 * Optional url, notes, aux, and itemKey ciphertext are included only when
 * present and authenticated.
 */
export function buildVaultEntryManifest(entry: VaultEntry): ItemManifest {
  requireRecord(entry);
  return seal(buildBody("vault-entry", entry, collectFields(entry, ENTRY_FIELDS)));
}

/**
 * Build a secure-note manifest.
 * Strips a legacy plaintext `label`. Label and content ciphertext must be v4.
 * Optional itemKey ciphertext is included when present and authenticated.
 */
export function buildSecureNoteManifest(note: SecureNote): ItemManifest {
  requireRecord(note);
  return seal(buildBody("secure-note", note, collectFields(note, NOTE_FIELDS)));
}

/** Recompute the content hash and confirm every field is still v4. */
export function verifyItemManifest(manifest: ItemManifest): boolean {
  if (!manifest || manifest.schema !== PIPASS_ITEM_SCHEMA) return false;
  if (manifest.kind !== "vault-entry" && manifest.kind !== "secure-note") return false;
  if (!Array.isArray(manifest.fields) || manifest.fields.length === 0) return false;
  if (typeof manifest.contentSha256 !== "string" || !/^[0-9a-f]{64}$/.test(manifest.contentSha256)) {
    return false;
  }
  try {
    requireItemId(manifest.itemId);
    requireSalt(manifest.salt);
    requireTimestamp(manifest.createdAt, "createdAt");
    const updatedAt = requireTimestamp(manifest.updatedAt, "updatedAt");
    if (manifest.version !== updatedAt) return false;
  } catch {
    return false;
  }
  const seen = new Set<string>();
  for (const field of manifest.fields) {
    if (!field || typeof field.name !== "string" || seen.has(field.name)) return false;
    if (!isAuthenticatedCiphertext(field.ciphertext)) return false;
    seen.add(field.name);
  }
  const expected = sha256Utf8Hex(
    canonicalManifestBody({
      schema: PIPASS_ITEM_SCHEMA,
      itemId: manifest.itemId,
      kind: manifest.kind,
      version: manifest.version,
      salt: manifest.salt,
      createdAt: manifest.createdAt,
      updatedAt: manifest.updatedAt,
      fields: manifest.fields,
    }),
  );
  return constantTimeEqualHex(expected, manifest.contentSha256);
}
