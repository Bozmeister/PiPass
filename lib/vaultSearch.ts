/**
 * Local vault search index.
 *
 * The search key is HKDF(masterKey, info "pipass-search-v1") with a fixed
 * domain-separation salt. The sealed index is one v4 ciphertext. Plaintext
 * exists only in the caller's memory while shares are available.
 * This module does not read the vault session and does not talk to a server.
 */

import CryptoJS from "crypto-js";
import { decryptData, encryptData } from "../crypto/encryption";
import { deriveSubkey } from "../crypto/hkdf";
import {
  combineShares,
  hexToBytes,
  wipeBuffer,
  type KeyShares,
} from "../crypto/secureMemory";
import type { VaultEntry } from "../workers/vaultWorker";

export const SEARCH_HKDF_INFO = "pipass-search-v1";
export const SEARCH_AAD_RECORD = "pipass-search-index";

const SEARCH_SALT_HEX = CryptoJS.SHA256("pipass-search-salt-v1").toString(CryptoJS.enc.Hex);

export type SearchSort = "none" | "az" | "za";
export type SearchKind = "vault-entry" | "secure-note";

export interface SearchRecord {
  id: string;
  kind: SearchKind;
  title: string;
  username: string;
  url: string;
  notes: string;
  /** Secure-note label. Empty for vault entries. */
  label: string;
}

export interface SearchIndexPlain {
  v: 1;
  records: SearchRecord[];
}

export type OpenSearchIndexResult =
  | { ok: true; index: SearchIndexPlain }
  | { ok: false; reason: "locked" | "unreadable" };

function wipeHex(hex: string): void {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) return;
  wipeBuffer(hexToBytes(hex));
}

export function deriveSearchKey(masterKeyHex: string): string {
  return deriveSubkey(masterKeyHex, SEARCH_HKDF_INFO, SEARCH_SALT_HEX);
}

function asText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function parseIndex(plain: string): SearchIndexPlain {
  const parsed = JSON.parse(plain) as { v?: unknown; records?: unknown };
  if (!parsed || parsed.v !== 1 || !Array.isArray(parsed.records)) {
    throw new Error("Invalid search index");
  }
  const records: SearchRecord[] = [];
  for (const row of parsed.records) {
    if (!row || typeof row !== "object") throw new Error("Invalid search index");
    const candidate = row as Partial<SearchRecord>;
    if (typeof candidate.id !== "string" || candidate.id.length === 0) {
      throw new Error("Invalid search index");
    }
    if (candidate.kind !== "vault-entry" && candidate.kind !== "secure-note") {
      throw new Error("Invalid search index");
    }
    records.push({
      id: candidate.id,
      kind: candidate.kind,
      title: asText(candidate.title),
      username: asText(candidate.username),
      url: asText(candidate.url),
      notes: asText(candidate.notes),
      label: asText(candidate.label),
    });
  }
  return { v: 1, records };
}

export function sealSearchIndex(index: SearchIndexPlain, shares: KeyShares): string {
  const master = combineShares(shares);
  let searchKey = "";
  try {
    searchKey = deriveSearchKey(master);
    return encryptData(JSON.stringify(index), searchKey, {
      recordId: SEARCH_AAD_RECORD,
      field: "search",
    });
  } finally {
    wipeHex(searchKey);
    wipeHex(master);
  }
}

/** Decrypt the index. A missing share set does not attempt decryption. */
export function openSearchIndex(
  ciphertext: string,
  shares: KeyShares | null,
): OpenSearchIndexResult {
  if (!shares) return { ok: false, reason: "locked" };
  const master = combineShares(shares);
  let searchKey = "";
  try {
    searchKey = deriveSearchKey(master);
    const plain = decryptData(ciphertext, searchKey, {
      recordId: SEARCH_AAD_RECORD,
      field: "search",
    });
    return { ok: true, index: parseIndex(plain) };
  } catch {
    return { ok: false, reason: "unreadable" };
  } finally {
    wipeHex(searchKey);
    wipeHex(master);
  }
}

export function recordMatches(record: SearchRecord, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const haystack = [record.title, record.username, record.url, record.notes, record.label];
  return haystack.some((field) => field.toLowerCase().includes(needle));
}

function sortText(record: SearchRecord): string {
  if (record.kind === "secure-note") return record.label || record.title;
  return record.title || record.label;
}

export function compareSearchRecords(left: SearchRecord, right: SearchRecord, sort: SearchSort): number {
  if (sort === "none") return 0;
  const direction = sort === "az" ? 1 : -1;
  const a = sortText(left).toLowerCase();
  const b = sortText(right).toLowerCase();
  if (a < b) return -1 * direction;
  if (a > b) return 1 * direction;
  if (left.id < right.id) return -1;
  if (left.id > right.id) return 1;
  return 0;
}

export function querySearchIndex(
  index: SearchIndexPlain,
  query: string,
  sort: SearchSort,
  kind?: SearchKind,
): string[] {
  let records = index.records.filter((record) => !kind || record.kind === kind);
  const needle = query.trim();
  if (needle) records = records.filter((record) => recordMatches(record, needle));
  if (sort !== "none") {
    records = records.slice().sort((left, right) => compareSearchRecords(left, right, sort));
  }
  return records.map((record) => record.id);
}

export function upsertSearchRecord(index: SearchIndexPlain, record: SearchRecord): SearchIndexPlain {
  const records = index.records.slice();
  const at = records.findIndex((row) => row.id === record.id && row.kind === record.kind);
  if (at >= 0) records[at] = record;
  else records.push(record);
  return { v: 1, records };
}

export function removeSearchRecordFromIndex(
  index: SearchIndexPlain,
  id: string,
  kind: SearchKind,
): SearchIndexPlain {
  return {
    v: 1,
    records: index.records.filter((record) => !(record.id === id && record.kind === kind)),
  };
}

/**
 * List rows for the vault screen.
 * Titles come from the decrypted index. Filter and sort do not decrypt entries.
 * A null index leaves the entry list unchanged.
 */
export function visibleVaultEntries(
  entries: VaultEntry[],
  index: SearchIndexPlain | null,
  query: string,
  sort: SearchSort,
): VaultEntry[] {
  if (!index) return entries;
  const byId = new Map(
    index.records
      .filter((record) => record.kind === "vault-entry")
      .map((record) => [record.id, record]),
  );
  let rows = entries.map((entry) => {
    const record = byId.get(entry.id);
    if (!record) return entry;
    return {
      ...entry,
      title: record.title,
      username: record.username,
      url: record.url || entry.url,
    };
  });
  const needle = query.trim();
  if (needle) {
    rows = rows.filter((entry) => {
      const record = byId.get(entry.id);
      return record ? recordMatches(record, needle) : false;
    });
  }
  if (sort !== "none") {
    rows = rows.slice().sort((left, right) => {
      const a = byId.get(left.id);
      const b = byId.get(right.id);
      if (!a || !b) return 0;
      return compareSearchRecords(a, b, sort);
    });
  }
  return rows;
}
