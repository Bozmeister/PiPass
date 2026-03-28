import CryptoJS from "crypto-js";
import * as ExpoCrypto from "expo-crypto";

// HKDF (HMAC-based Key Derivation Function) per RFC 5869
// Used to derive per-entry subkeys from the master key

function hkdfExtract(salt: string, ikm: string): string {
  return CryptoJS.HmacSHA256(
    CryptoJS.enc.Hex.parse(ikm),
    CryptoJS.enc.Hex.parse(salt)
  ).toString(CryptoJS.enc.Hex);
}

function hkdfExpand(prk: string, info: string, length: number): string {
  const hashLen = 32; // SHA-256 output in bytes
  const n = Math.ceil(length / hashLen);
  let okm = "";
  let prev = "";

  for (let i = 1; i <= n; i++) {
    const input = prev + info + String.fromCharCode(i);
    prev = CryptoJS.HmacSHA256(
      CryptoJS.enc.Utf8.parse(input),
      CryptoJS.enc.Hex.parse(prk)
    ).toString(CryptoJS.enc.Hex);
    okm += prev;
  }

  return okm.slice(0, length * 2); // hex chars = bytes * 2
}

export function deriveSubkey(
  masterKeyHex: string,
  context: string,
  saltHex?: string
): string {
  const salt = saltHex || generateSaltHex();
  const prk = hkdfExtract(salt, masterKeyHex);
  return hkdfExpand(prk, context, 32); // 32 bytes = 256-bit subkey
}

export function deriveEntryKey(
  masterKeyHex: string,
  entryId: string,
  entrySaltHex: string
): string {
  return deriveSubkey(masterKeyHex, "pipass-entry-key:" + entryId, entrySaltHex);
}

export function generateSaltHex(bytes: number = 16): string {
  const saltBytes = ExpoCrypto.getRandomBytes(bytes);
  return Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
