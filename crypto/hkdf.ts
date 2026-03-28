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
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let okm = "";
  let prevWordArray = CryptoJS.lib.WordArray.create();

  const infoWords = CryptoJS.enc.Utf8.parse(info);

  for (let i = 1; i <= n; i++) {
    const counterWord = CryptoJS.lib.WordArray.create(
      new Uint8Array([i]) as any
    );
    const input = prevWordArray.clone().concat(infoWords).concat(counterWord);
    prevWordArray = CryptoJS.HmacSHA256(input, CryptoJS.enc.Hex.parse(prk));
    okm += prevWordArray.toString(CryptoJS.enc.Hex);
  }

  return okm.slice(0, length * 2);
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

export function deriveFractalSeed(masterKeyHex: string): { seedNumber: number; fingerprint: string } {
  const fixedSalt = "00".repeat(16);
  const prk = hkdfExtract(fixedSalt, masterKeyHex);
  const seedHex = hkdfExpand(prk, "fractal", 32);
  const fingerprint = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(seedHex)).toString(CryptoJS.enc.Hex);
  const seedNumber = parseInt(seedHex.slice(0, 8), 16) % 999999;
  return { seedNumber, fingerprint };
}

export function generateSaltHex(bytes: number = 16): string {
  const saltBytes = ExpoCrypto.getRandomBytes(bytes);
  return Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
