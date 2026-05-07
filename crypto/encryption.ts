import CryptoJS from "crypto-js";
import { hexToBytes, wipeBuffer } from "./secureMemory";

// AES-256-GCM is not natively available in crypto-js or expo-crypto in Expo Go.
// We implement AES-256-CBC with HMAC-SHA256 for authenticated encryption (Encrypt-then-MAC).
// This provides the same security guarantees as GCM: confidentiality + integrity + authenticity.
// Format: iv(32hex) : ciphertext(hex) : mac(64hex)

const IV_BYTES = 16;
const MAC_KEY_OFFSET = "hmac-subkey";

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const aBytes = hexToBytes(a);
  const bBytes = hexToBytes(b);
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  wipeBuffer(aBytes);
  wipeBuffer(bBytes);
  return diff === 0;
}

function deriveHmacKey(encKey: string): string {
  return CryptoJS.HmacSHA256(MAC_KEY_OFFSET, encKey).toString(CryptoJS.enc.Hex);
}

export function encryptData(plaintext: string, keyHex: string): string {
  const ExpoCrypto = require("expo-crypto") as typeof import("expo-crypto");
  const ivBytes = ExpoCrypto.getRandomBytes(IV_BYTES);
  const ivHex = Array.from(ivBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  wipeBuffer(ivBytes);
  const iv = CryptoJS.enc.Hex.parse(ivHex);
  const key = CryptoJS.enc.Hex.parse(keyHex);

  const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const cipherHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);

  // Encrypt-then-MAC: HMAC covers iv + ciphertext to prevent tampering
  const hmacKey = deriveHmacKey(keyHex);
  const mac = CryptoJS.HmacSHA256(ivHex + cipherHex, hmacKey).toString(CryptoJS.enc.Hex);

  return ivHex + ":" + cipherHex + ":" + mac;
}

export function decryptData(ciphertext: string, keyHex: string): string {
  const parts = ciphertext.split(":");

  // Support legacy format (iv:ciphertext) for backward compatibility
  if (parts.length === 2) {
    return decryptLegacy(parts[0], parts[1], keyHex);
  }

  if (parts.length !== 3) {
    throw new Error("Invalid ciphertext format");
  }

  const [ivHex, encHex, mac] = parts;

  // Verify MAC before decryption (authenticate-then-decrypt)
  const hmacKey = deriveHmacKey(keyHex);
  const expectedMac = CryptoJS.HmacSHA256(ivHex + encHex, hmacKey).toString(CryptoJS.enc.Hex);

  if (!constantTimeEqual(mac, expectedMac)) {
    throw new Error("Authentication failed — data may be tampered");
  }

  const iv = CryptoJS.enc.Hex.parse(ivHex);
  const key = CryptoJS.enc.Hex.parse(keyHex);

  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Hex.parse(encHex),
  });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const result = decrypted.toString(CryptoJS.enc.Utf8);
  if (!result) {
    throw new Error("Decryption failed — invalid key or corrupted data");
  }

  return result;
}

function decryptLegacy(ivHex: string, encHex: string, keyHex: string): string {
  const iv = CryptoJS.enc.Hex.parse(ivHex);
  const key = CryptoJS.enc.Hex.parse(keyHex);

  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Hex.parse(encHex),
  });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const result = decrypted.toString(CryptoJS.enc.Utf8);
  if (!result) {
    throw new Error("Decryption failed — invalid key or corrupted data");
  }

  return result;
}
