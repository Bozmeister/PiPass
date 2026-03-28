import * as ExpoCrypto from "expo-crypto";
import CryptoJS from "crypto-js";
import { wipeBuffer } from "./secureMemory";

const RECOVERY_KEY_BYTES = 32;

export function generateRecoveryKey(): string {
  const bytes = ExpoCrypto.getRandomBytes(RECOVERY_KEY_BYTES);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  wipeBuffer(bytes);
  return hex;
}

export function formatRecoveryKey(hex: string): string {
  return hex
    .toUpperCase()
    .match(/.{1,4}/g)!
    .join("-");
}

export function normalizeRecoveryKey(input: string): string {
  return input.replace(/[\s-]/g, "").toLowerCase();
}

export function hashRecoveryKey(hex: string): string {
  return CryptoJS.SHA256(hex).toString(CryptoJS.enc.Hex);
}

export function verifyRecoveryKey(inputHex: string, storedHash: string): boolean {
  const inputHash = hashRecoveryKey(inputHex);
  if (inputHash.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < inputHash.length; i++) {
    diff |= inputHash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }
  return diff === 0;
}
