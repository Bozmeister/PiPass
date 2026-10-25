/**
 * Optional item-key envelope.
 *
 * When EXPO_PUBLIC_INTENTDB_ENVELOPE is "1" (default off), a new item gets a
 * random 32-byte key. That key is wrapped with HKDF(masterKey, info
 * "pipass-item-wrap-v1", salt = the entry salt) and stored as the
 * authenticated v4 field "itemKey". Field encryption uses the unwrapped item
 * key. Records without encryptedItemKey keep deriveEntryKey.
 *
 * The master key and the item key stay on the device. This module does not
 * import a vault session and does not read key shares.
 */

import { decryptData, encryptData } from "./encryption";
import { deriveEntryKey, deriveSubkey, generateSaltHex } from "./hkdf";
import { hexToBytes, wipeBuffer } from "./secureMemory";

export const ITEM_WRAP_HKDF_INFO = "pipass-item-wrap-v1";
export const ITEM_KEY_FIELD = "itemKey" as const;
export const INTENTDB_ENVELOPE_ENV = "EXPO_PUBLIC_INTENTDB_ENVELOPE";

const ITEM_KEY_HEX = /^[0-9a-fA-F]{64}$/;

export interface EnvelopeRecord {
  id: string;
  salt: string;
  encryptedItemKey?: string;
}

export interface EnvelopeMigrationOptions {
  /** Explicit override. When omitted, EXPO_PUBLIC_INTENTDB_ENVELOPE is read. */
  enabled?: boolean;
  /** Caller reports unlock. This module does not read vault shares itself. */
  unlocked?: boolean;
}

export function intentdbEnvelopeEnabled(override?: boolean): boolean {
  if (typeof override === "boolean") return override;
  return process.env[INTENTDB_ENVELOPE_ENV] === "1";
}

export function envelopeMigrationAllowed(options?: EnvelopeMigrationOptions): boolean {
  return intentdbEnvelopeEnabled(options?.enabled) && options?.unlocked === true;
}

export function recordHasWrappedItemKey(record: { encryptedItemKey?: string }): boolean {
  return typeof record.encryptedItemKey === "string" && record.encryptedItemKey.length > 0;
}

/** Wrap key. The entry salt is required so wrap and unwrap use the same HKDF salt. */
export function deriveItemWrapKey(masterKeyHex: string, entrySaltHex: string): string {
  if (typeof entrySaltHex !== "string" || entrySaltHex.length < 16 || entrySaltHex.length % 2 !== 0) {
    throw new Error("Item wrap requires the entry salt");
  }
  return deriveSubkey(masterKeyHex, ITEM_WRAP_HKDF_INFO, entrySaltHex);
}

export function generateItemKeyHex(): string {
  return generateSaltHex(32);
}

function wipeHex(hex: string): void {
  if (!ITEM_KEY_HEX.test(hex)) return;
  wipeBuffer(hexToBytes(hex));
}

export function wrapItemKey(
  itemKeyHex: string,
  masterKeyHex: string,
  entrySaltHex: string,
  recordId: string,
): string {
  if (!ITEM_KEY_HEX.test(itemKeyHex)) {
    throw new Error("Invalid item key");
  }
  const wrapKey = deriveItemWrapKey(masterKeyHex, entrySaltHex);
  try {
    return encryptData(itemKeyHex.toLowerCase(), wrapKey, {
      recordId,
      field: ITEM_KEY_FIELD,
    });
  } finally {
    wipeHex(wrapKey);
  }
}

export function unwrapItemKey(
  wrapped: string,
  masterKeyHex: string,
  entrySaltHex: string,
  recordId: string,
): string {
  const wrapKey = deriveItemWrapKey(masterKeyHex, entrySaltHex);
  try {
    const plain = decryptData(wrapped, wrapKey, {
      recordId,
      field: ITEM_KEY_FIELD,
    });
    if (!ITEM_KEY_HEX.test(plain)) {
      throw new Error("Invalid item key");
    }
    return plain.toLowerCase();
  } finally {
    wipeHex(wrapKey);
  }
}

/**
 * Key passed to encryptData / decryptData.
 * Wrapped item key when present, otherwise the HKDF entry key, otherwise the master key.
 */
export function resolveFieldKey(record: EnvelopeRecord, masterKeyHex: string): string {
  if (recordHasWrappedItemKey(record)) {
    return unwrapItemKey(record.encryptedItemKey as string, masterKeyHex, record.salt, record.id);
  }
  if (record.salt) {
    return deriveEntryKey(masterKeyHex, record.id, record.salt);
  }
  return masterKeyHex;
}

export function rewrapItemKey(
  wrapped: string,
  oldMasterKeyHex: string,
  newMasterKeyHex: string,
  entrySaltHex: string,
  recordId: string,
): string {
  const itemKey = unwrapItemKey(wrapped, oldMasterKeyHex, entrySaltHex, recordId);
  try {
    return wrapItemKey(itemKey, newMasterKeyHex, entrySaltHex, recordId);
  } finally {
    wipeHex(itemKey);
  }
}
