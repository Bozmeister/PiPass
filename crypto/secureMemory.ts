import * as ExpoCrypto from "expo-crypto";

export function wipeBuffer(buffer: Uint8Array): void {
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
}

export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

export function generateRandomBytes(length: number): Uint8Array {
  return ExpoCrypto.getRandomBytes(length);
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

export interface KeyShares {
  shareA: Uint8Array;
  shareB: Uint8Array;
}

export function splitKeyIntoShares(keyHex: string): KeyShares {
  const keyBytes = hexToBytes(keyHex);
  const shareA = generateRandomBytes(keyBytes.length);
  const shareB = xorBytes(keyBytes, shareA);
  wipeBuffer(keyBytes);
  return { shareA, shareB };
}

export function combineShares(shares: KeyShares): string {
  const combined = xorBytes(shares.shareA, shares.shareB);
  const hex = bytesToHex(combined);
  wipeBuffer(combined);
  return hex;
}

export function wipeShares(shares: KeyShares): void {
  wipeBuffer(shares.shareA);
  wipeBuffer(shares.shareB);
}

export function useKeyBriefly(
  shares: KeyShares,
  operation: (keyHex: string) => string
): string {
  const keyHex = combineShares(shares);
  try {
    const result = operation(keyHex);
    return result;
  } finally {
    const keyBytes = hexToBytes(keyHex);
    wipeBuffer(keyBytes);
  }
}
