import { aesGcmDecrypt, aesGcmEncrypt, randomNonce } from "./aesGcm";
import { deriveAesGcmKey } from "./hkdf";
import {
  bytesToHex,
  bytesToString,
  hexToBytes,
  stringToBytes,
  wipeBuffer,
} from "./secureMemory";

/**
 * Vault field encryption: AES-256-GCM (native OpenSSL).
 *
 * Ciphertext format (only supported version):
 *   v4:nonce(24hex / 12 bytes):ciphertext(hex):tag(32hex / 16 bytes)
 *
 * AAD is canonicalizeFieldAad({ recordId, field }) as UTF-8. It is bound
 * into the GCM tag and is not stored in the blob. Callers must supply the
 * same AAD on decrypt.
 *
 * Retired formats (crypto-js AES-CBC + HMAC EtM) are rejected:
 *   v3:iv:ct:mac, v2:iv:ct:mac, iv:ct:mac, iv:ct
 */

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const CIPHERTEXT_VERSION = "v4";

export type VaultCipherField =
  | "password"
  | "title"
  | "username"
  | "url"
  | "notes"
  | "aux"
  | "label"
  | "content"
  | "itemKey"
  | "sentinel";

/** Associated data bound into the GCM tag (not written into the ciphertext). */
export interface FieldAad {
  recordId: string;
  field: VaultCipherField | string;
}

export class CiphertextFormatError extends Error {
  readonly code:
    | "legacy-unsupported"
    | "invalid-format"
    | "aad-required"
    | "aad-invalid";

  constructor(code: CiphertextFormatError["code"], message: string) {
    super(message);
    this.name = "CiphertextFormatError";
    this.code = code;
  }
}

const LEGACY_UNSUPPORTED_MESSAGE =
  "This vault entry uses a retired crypto-js Encrypt-then-MAC format. " +
  "Wipe the local vault and recreate it — old ciphertexts cannot be decrypted.";

export function isLegacyUnsupportedCiphertext(ciphertext: string): boolean {
  if (typeof ciphertext !== "string" || ciphertext.length === 0) return false;
  const parts = ciphertext.split(":");
  if (parts.length === 2 && parts[0].length > 0 && parts[1].length > 0) {
    return true;
  }
  if (parts.length === 3 && parts.every((p) => p.length > 0)) {
    return true;
  }
  if (
    parts.length === 4 &&
    (parts[0] === "v2" || parts[0] === "v3") &&
    parts[1] &&
    parts[2] &&
    parts[3]
  ) {
    return true;
  }
  return false;
}

/** @deprecated Use isLegacyUnsupportedCiphertext. */
export function isLegacyUnauthenticatedCiphertext(ciphertext: string): boolean {
  return isLegacyUnsupportedCiphertext(ciphertext);
}

export function isAuthenticatedCiphertext(ciphertext: string): boolean {
  if (typeof ciphertext !== "string" || ciphertext.length === 0) return false;
  const parts = ciphertext.split(":");
  return (
    parts.length === 4 &&
    parts[0] === CIPHERTEXT_VERSION &&
    /^[0-9a-fA-F]{24}$/.test(parts[1]) &&
    /^([0-9a-fA-F]{2})*$/.test(parts[2]) &&
    /^[0-9a-fA-F]{32}$/.test(parts[3])
  );
}

export function canonicalizeFieldAad(aad: FieldAad): string {
  if (!aad || typeof aad !== "object") {
    throw new CiphertextFormatError("aad-invalid", "Field AAD is required");
  }
  const recordId = aad.recordId;
  const field = aad.field;
  if (typeof recordId !== "string" || recordId.length === 0 || recordId.length > 128) {
    throw new CiphertextFormatError("aad-invalid", "Invalid AAD recordId");
  }
  if (typeof field !== "string" || field.length === 0 || field.length > 64) {
    throw new CiphertextFormatError("aad-invalid", "Invalid AAD field name");
  }
  if (/[\0\n\r:]/.test(recordId) || /[\0\n\r:]/.test(field)) {
    throw new CiphertextFormatError(
      "aad-invalid",
      "AAD recordId/field must not contain control characters or ':'",
    );
  }
  return `pipass-aad-v1:${recordId}:${field}`;
}

function requireEntryKey(keyHex: string): string {
  if (typeof keyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error("Invalid entry key (expected 32-byte hex)");
  }
  return keyHex;
}

/**
 * Encrypt with AES-256-GCM. Always writes v4:nonce:ciphertext:tag.
 * AAD (recordId + field) is required and bound into the auth tag.
 */
export function encryptData(plaintext: string, keyHex: string, aad: FieldAad): string {
  const aadCanonical = canonicalizeFieldAad(aad);
  requireEntryKey(keyHex);

  const nonce = randomNonce(NONCE_BYTES);
  const key = hexToBytes(deriveAesGcmKey(keyHex));
  const aadBytes = stringToBytes(aadCanonical);
  const plainBytes = stringToBytes(plaintext);

  try {
    const { ciphertext, tag } = aesGcmEncrypt(plainBytes, key, nonce, aadBytes);
    if (tag.length !== TAG_BYTES) {
      throw new Error("AES-GCM produced an unexpected tag length");
    }
    return `${CIPHERTEXT_VERSION}:${bytesToHex(nonce)}:${bytesToHex(ciphertext)}:${bytesToHex(tag)}`;
  } finally {
    wipeBuffer(nonce);
    wipeBuffer(key);
    wipeBuffer(plainBytes);
  }
}

/**
 * Decrypt v4 AES-256-GCM ciphertext. AAD is required.
 * Retired EtM formats throw CiphertextFormatError("legacy-unsupported").
 */
export function decryptData(
  ciphertext: string,
  keyHex: string,
  aad?: FieldAad,
): string {
  if (typeof ciphertext !== "string" || ciphertext.length === 0) {
    throw new CiphertextFormatError("invalid-format", "Invalid ciphertext format");
  }

  if (isLegacyUnsupportedCiphertext(ciphertext)) {
    throw new CiphertextFormatError("legacy-unsupported", LEGACY_UNSUPPORTED_MESSAGE);
  }

  const parts = ciphertext.split(":");
  if (
    parts.length !== 4 ||
    parts[0] !== CIPHERTEXT_VERSION ||
    !/^[0-9a-fA-F]{24}$/.test(parts[1]) ||
    !/^([0-9a-fA-F]{2})*$/.test(parts[2]) ||
    !/^[0-9a-fA-F]{32}$/.test(parts[3])
  ) {
    throw new CiphertextFormatError(
      "invalid-format",
      "Invalid ciphertext format — expected v4:nonce:ciphertext:tag",
    );
  }

  if (!aad) {
    throw new CiphertextFormatError(
      "aad-required",
      "Field AAD is required to decrypt v4 ciphertext",
    );
  }

  requireEntryKey(keyHex);
  const aadCanonical = canonicalizeFieldAad(aad);
  const nonce = hexToBytes(parts[1]);
  const body = hexToBytes(parts[2]);
  const tag = hexToBytes(parts[3]);
  const key = hexToBytes(deriveAesGcmKey(keyHex));
  const aadBytes = stringToBytes(aadCanonical);

  try {
    const plainBytes = aesGcmDecrypt(body, tag, key, nonce, aadBytes);
    try {
      return bytesToString(plainBytes);
    } finally {
      wipeBuffer(plainBytes);
    }
  } catch (err) {
    if (err instanceof CiphertextFormatError) throw err;
    throw new Error("Authentication failed — data may be tampered");
  } finally {
    wipeBuffer(nonce);
    wipeBuffer(body);
    wipeBuffer(tag);
    wipeBuffer(key);
  }
}
