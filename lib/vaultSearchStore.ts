/**
 * Build and store the local search index.
 * Callers pass key shares. This module does not read the vault session.
 * Storage is ciphertext only. A locked call does not read or decrypt it.
 */

import type { KeyShares } from "../crypto/secureMemory";
import {
  decryptSecureNote,
  decryptVaultEntry,
  type SecureNote,
  type VaultEntry,
} from "../workers/vaultWorker";
import { clearChunkedCiphertext, readChunkedCiphertext, writeChunkedCiphertext } from "./vaultSearchChunks";
import {
  openSearchIndex,
  removeSearchRecordFromIndex,
  sealSearchIndex,
  upsertSearchRecord,
  type SearchIndexPlain,
  type SearchKind,
  type SearchRecord,
} from "./vaultSearch";

export type LoadSearchIndexResult =
  | { ok: true; index: SearchIndexPlain }
  | { ok: false; reason: "locked" | "missing" | "unreadable" };

export function recordFromVaultEntry(entry: VaultEntry, shares: KeyShares): SearchRecord {
  try {
    const decrypted = decryptVaultEntry(entry, shares);
    return {
      id: entry.id,
      kind: "vault-entry",
      title: decrypted.title ?? "",
      username: decrypted.username ?? "",
      url: decrypted.url ?? "",
      notes: decrypted.notes ?? "",
      label: "",
    };
  } catch {
    return {
      id: entry.id,
      kind: "vault-entry",
      title: "",
      username: "",
      url: "",
      notes: "",
      label: "",
    };
  }
}

export function recordFromSecureNote(note: SecureNote, shares: KeyShares): SearchRecord {
  try {
    const decrypted = decryptSecureNote(note, shares);
    return {
      id: note.id,
      kind: "secure-note",
      title: "",
      username: "",
      url: "",
      notes: "",
      label: decrypted.label ?? "",
    };
  } catch {
    return {
      id: note.id,
      kind: "secure-note",
      title: "",
      username: "",
      url: "",
      notes: "",
      label: "",
    };
  }
}

export function buildSearchIndex(
  entries: VaultEntry[],
  notes: SecureNote[],
  shares: KeyShares,
): SearchIndexPlain {
  return {
    v: 1,
    records: [
      ...entries.map((entry) => recordFromVaultEntry(entry, shares)),
      ...notes.map((note) => recordFromSecureNote(note, shares)),
    ],
  };
}

export async function loadSearchIndex(shares: KeyShares | null): Promise<LoadSearchIndexResult> {
  if (!shares) return { ok: false, reason: "locked" };
  const ciphertext = await readChunkedCiphertext();
  if (!ciphertext) return { ok: false, reason: "missing" };
  const opened = openSearchIndex(ciphertext, shares);
  if (!opened.ok) return { ok: false, reason: "unreadable" };
  return { ok: true, index: opened.index };
}

export async function persistSearchIndex(index: SearchIndexPlain, shares: KeyShares): Promise<void> {
  await writeChunkedCiphertext(sealSearchIndex(index, shares));
}

export async function rebuildSearchIndex(
  shares: KeyShares,
  entries: VaultEntry[],
  notes: SecureNote[],
): Promise<SearchIndexPlain> {
  const index = buildSearchIndex(entries, notes, shares);
  await persistSearchIndex(index, shares);
  return index;
}

export async function upsertVaultEntrySearch(
  shares: KeyShares,
  entry: VaultEntry,
): Promise<SearchIndexPlain | null> {
  const loaded = await loadSearchIndex(shares);
  if (!loaded.ok) return null;
  const next = upsertSearchRecord(loaded.index, recordFromVaultEntry(entry, shares));
  await persistSearchIndex(next, shares);
  return next;
}

export async function upsertSecureNoteSearch(
  shares: KeyShares,
  note: SecureNote,
): Promise<SearchIndexPlain | null> {
  const loaded = await loadSearchIndex(shares);
  if (!loaded.ok) return null;
  const next = upsertSearchRecord(loaded.index, recordFromSecureNote(note, shares));
  await persistSearchIndex(next, shares);
  return next;
}

export async function removeStoredSearchRecord(
  shares: KeyShares,
  id: string,
  kind: SearchKind,
): Promise<SearchIndexPlain | null> {
  const loaded = await loadSearchIndex(shares);
  if (!loaded.ok) return null;
  const next = removeSearchRecordFromIndex(loaded.index, id, kind);
  await persistSearchIndex(next, shares);
  return next;
}

export async function clearStoredSearchIndex(): Promise<void> {
  await clearChunkedCiphertext();
}
