import CryptoJS from "crypto-js";

// HKDF (HMAC-based Key Derivation Function) per RFC 5869
// Used to derive per-entry subkeys from the master key

const HKDF_SALT_V1 = CryptoJS.SHA256("pipass-hkdf-salt-v1").toString(CryptoJS.enc.Hex);

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

function hexBytesToUint64(hex: string, offset: number): number {
  let value = 0;
  for (let i = 0; i < 8; i++) {
    value = value * 256 + parseInt(hex.substring((offset + i) * 2, (offset + i) * 2 + 2), 16);
  }
  return value;
}

function mapRange(value: number, min: number, max: number): number {
  const normalized = value / Number.MAX_SAFE_INTEGER;
  return min + normalized * (max - min);
}

export interface FractalParams {
  cx: number;
  cy: number;
  zoom: number;
  maxIterations: number;
}

export const DEFAULT_FRACTAL_PARAMS: FractalParams = {
  cx: -0.75,
  cy: 0,
  zoom: 1,
  maxIterations: 300,
};

export function deriveFractalSeedLegacy(masterKeyHex: string): { fingerprint: string } {
  const legacySalt = "00".repeat(16);
  const prk = hkdfExtract(legacySalt, masterKeyHex);
  const seedHex = hkdfExpand(prk, "fractal", 32);
  const fingerprint = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(seedHex)).toString(CryptoJS.enc.Hex);
  return { fingerprint };
}

export function deriveFractalSeed(masterKeyHex: string): { seedNumber: number; fingerprint: string; fractalParams: FractalParams } {
  const prk = hkdfExtract(HKDF_SALT_V1, masterKeyHex);
  const seedHex = hkdfExpand(prk, "fractal", 32);
  const fingerprint = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(seedHex)).toString(CryptoJS.enc.Hex);
  const seedNumber = parseInt(seedHex.slice(0, 8), 16) % 999999;

  const raw0 = hexBytesToUint64(seedHex, 0);
  const raw1 = hexBytesToUint64(seedHex, 8);
  const raw2 = hexBytesToUint64(seedHex, 16);
  const raw3 = hexBytesToUint64(seedHex, 24);

  const safeCx = raw0 % Number.MAX_SAFE_INTEGER;
  const safeCy = raw1 % Number.MAX_SAFE_INTEGER;
  const safeZoom = raw2 % Number.MAX_SAFE_INTEGER;
  const safeIter = raw3 % Number.MAX_SAFE_INTEGER;

  const fractalParams: FractalParams = {
    cx: mapRange(safeCx, -2.5, 1),
    cy: mapRange(safeCy, -1, 1),
    zoom: mapRange(safeZoom, 0.5, 3),
    maxIterations: Math.round(mapRange(safeIter, 100, 1000)),
  };

  return { seedNumber, fingerprint, fractalParams };
}

export function generateSaltHex(bytes: number = 16): string {
  const ExpoCrypto = require("expo-crypto") as typeof import("expo-crypto");
  const saltBytes = ExpoCrypto.getRandomBytes(bytes);
  return Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
