import * as ExpoCrypto from "expo-crypto";

const EXP_TABLE = new Uint8Array(256);
const LOG_TABLE = new Uint8Array(256);

(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x = x ^ (x << 1);
    if (x & 0x100) x ^= 0x11b;
  }
  EXP_TABLE[255] = EXP_TABLE[0];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("Division by zero in GF(256)");
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
}

function evaluatePolynomial(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfMul(result, x) ^ coeffs[i];
  }
  return result;
}

function lagrangeInterpolate(points: Array<[number, number]>): number {
  let result = 0;
  for (let i = 0; i < points.length; i++) {
    const [xi, yi] = points[i];
    let basis = yi;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      const [xj] = points[j];
      basis = gfMul(basis, gfDiv(xj, xi ^ xj));
    }
    result ^= basis;
  }
  return result;
}

export interface ShamirShare {
  index: number;
  data: string;
}

export function splitSecret(
  secretHex: string,
  totalShares: number,
  threshold: number
): ShamirShare[] {
  if (threshold < 2) throw new Error("Threshold must be at least 2");
  if (totalShares < threshold) throw new Error("Total shares must be >= threshold");
  if (totalShares > 254) throw new Error("Maximum 254 shares");
  if (secretHex.length === 0 || secretHex.length % 2 !== 0) throw new Error("Invalid secret length");
  if (!/^[0-9a-f]+$/i.test(secretHex)) throw new Error("Invalid hex in secret");

  const secretBytes = new Uint8Array(secretHex.length / 2);
  for (let i = 0; i < secretBytes.length; i++) {
    secretBytes[i] = parseInt(secretHex.substr(i * 2, 2), 16);
  }

  const shares: Uint8Array[] = Array.from({ length: totalShares }, () =>
    new Uint8Array(secretBytes.length)
  );

  for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secretBytes[byteIdx];

    const randomBytes = ExpoCrypto.getRandomBytes(threshold - 1);
    for (let c = 1; c < threshold; c++) {
      coeffs[c] = randomBytes[c - 1];
      if (coeffs[c] === 0) coeffs[c] = 1;
    }

    for (let s = 0; s < totalShares; s++) {
      shares[s][byteIdx] = evaluatePolynomial(coeffs, s + 1);
    }

    coeffs.fill(0);
    randomBytes.fill(0);
  }

  secretBytes.fill(0);

  return shares.map((data, i) => ({
    index: i + 1,
    data: Array.from(data)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  }));
}

export function combineShares(shares: ShamirShare[]): string {
  if (shares.length < 2) throw new Error("Need at least 2 shares");

  const indices = new Set(shares.map((s) => s.index));
  if (indices.size !== shares.length) throw new Error("Duplicate share indices");
  for (const s of shares) {
    if (s.index < 1 || s.index > 254) throw new Error("Share index out of range");
    if (s.data.length !== shares[0].data.length) throw new Error("Share length mismatch");
    if (!/^[0-9a-f]+$/i.test(s.data)) throw new Error("Invalid hex in share");
  }

  const byteLen = shares[0].data.length / 2;
  const result = new Uint8Array(byteLen);

  for (let byteIdx = 0; byteIdx < byteLen; byteIdx++) {
    const points: Array<[number, number]> = shares.map((s) => [
      s.index,
      parseInt(s.data.substr(byteIdx * 2, 2), 16),
    ]);
    result[byteIdx] = lagrangeInterpolate(points);
  }

  const hex = Array.from(result)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  result.fill(0);
  return hex;
}

export function formatShare(share: ShamirShare): string {
  const prefix = share.index.toString().padStart(2, "0");
  const grouped = share.data
    .toUpperCase()
    .match(/.{1,4}/g)!
    .join("-");
  return `S${prefix}:${grouped}`;
}

export function parseShare(input: string): ShamirShare {
  const cleaned = input.trim();
  const match = cleaned.match(/^S(\d{2}):(.+)$/);
  if (!match) throw new Error("Invalid share format");
  const index = parseInt(match[1], 10);
  const data = match[2].replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(data)) throw new Error("Invalid share data");
  return { index, data };
}
