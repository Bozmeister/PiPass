/**
 * Phase 1 IntentDB primitive: movement and deletion receipts.
 *
 * A receipt binds an item content hash to an operation and a pair of
 * locators. PiPass (and later a verification bot) checks the signature
 * with an injected key. This module does not open sockets, does not import
 * a vault key, and does not decrypt ciphertext.
 *
 * Ed25519 is the intended bot algorithm. Tests and local checks can inject
 * HMAC-SHA256 instead. The signature is over the canonical unsigned body.
 */

import CryptoJS from "crypto-js";
import { bytesToHex, hexToBytes } from "../../crypto/secureMemory";

export const RECEIPT_VERSION = 1 as const;
export const GENESIS_RECEIPT_HASH = "0".repeat(64);
export const TOMBSTONE_LOCATOR = "tombstone";

export const RECEIPT_OPS = ["put", "copy", "move", "delete"] as const;
export type ReceiptOp = (typeof RECEIPT_OPS)[number];

export type ReceiptAlg = "ed25519" | "hmac-sha256";

export type ReceiptErrorCode =
  | "invalid-op"
  | "invalid-id"
  | "invalid-version"
  | "invalid-hash"
  | "invalid-locator"
  | "invalid-bot"
  | "invalid-time"
  | "invalid-signature";

export class ReceiptError extends Error {
  readonly code: ReceiptErrorCode;

  constructor(code: ReceiptErrorCode, message: string) {
    super(message);
    this.name = "ReceiptError";
    this.code = code;
  }
}

export interface ReceiptBody {
  v: typeof RECEIPT_VERSION;
  op: ReceiptOp;
  itemId: string;
  itemVersion: number;
  contentSha256: string;
  fromLocator: string;
  toLocator: string;
  botId: string;
  issuedAt: number;
  prevReceiptHash: string;
}

export interface MovementReceipt extends ReceiptBody {
  sigAlg: ReceiptAlg;
  signature: string;
}

/**
 * Injected signer/verifier. Production bot keys supply Ed25519.
 * `createHmacSha256ReceiptCrypto` is the test and local stand-in.
 */
export interface ReceiptCrypto {
  alg: ReceiptAlg;
  sign(payload: Uint8Array): Uint8Array;
  verify(payload: Uint8Array, signature: Uint8Array): boolean;
}

export interface BuildReceiptInput {
  op: ReceiptOp;
  itemId: string;
  itemVersion: number;
  contentSha256: string;
  fromLocator: string;
  toLocator: string;
  botId: string;
  issuedAt: number;
  /** Previous receipt chain hash. Defaults to the all-zero genesis hash. */
  prevReceiptHash?: string;
}

export type ReceiptVerifyFailure =
  | "invalid-receipt"
  | "alg-mismatch"
  | "prev-mismatch"
  | "bad-signature";

export type ReceiptVerifyResult =
  | { ok: true }
  | { ok: false; reason: ReceiptVerifyFailure };

const HEX64 = /^[0-9a-f]{64}$/;
const SIGNATURE_HEX = /^[0-9a-f]{64,512}$/;

function sha256Utf8(value: string): string {
  return CryptoJS.SHA256(value).toString(CryptoJS.enc.Hex);
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) {
    diff |= left[i] ^ right[i];
  }
  return diff === 0;
}

function requireItemId(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || /[\0\n\r:]/.test(value)) {
    throw new ReceiptError("invalid-id", "Receipt itemId is invalid");
  }
  return value;
}

function requireHash(value: string, label: string): string {
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new ReceiptError("invalid-hash", `${label} must be 64 lowercase hex characters`);
  }
  return value;
}

function requireLocator(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    /[\0-\x1f\x7f]/.test(value)
  ) {
    throw new ReceiptError("invalid-locator", `${label} must be 1-256 characters without controls`);
  }
  return value;
}

function requireBotId(value: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128 ||
    /[\0-\x1f\x7f]/.test(value)
  ) {
    throw new ReceiptError("invalid-bot", "botId must be 1-128 characters without controls");
  }
  return value;
}

function requireVersion(value: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ReceiptError("invalid-version", "itemVersion must be a safe non-negative integer");
  }
  return value;
}

function requireIssuedAt(value: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new ReceiptError("invalid-time", "issuedAt must be a safe positive integer");
  }
  return value;
}

/**
 * Unsigned receipt JSON. Alphabetical keys, no whitespace, no signature.
 * The signer and the verifier both use this exact string.
 */
export function canonicalReceiptBody(body: ReceiptBody): string {
  return `{${[
    `"botId":${JSON.stringify(body.botId)}`,
    `"contentSha256":${JSON.stringify(body.contentSha256)}`,
    `"fromLocator":${JSON.stringify(body.fromLocator)}`,
    `"issuedAt":${body.issuedAt}`,
    `"itemId":${JSON.stringify(body.itemId)}`,
    `"itemVersion":${body.itemVersion}`,
    `"op":${JSON.stringify(body.op)}`,
    `"prevReceiptHash":${JSON.stringify(body.prevReceiptHash)}`,
    `"toLocator":${JSON.stringify(body.toLocator)}`,
    `"v":${body.v}`,
  ].join(",")}}`;
}

export function receiptSigningPayload(body: ReceiptBody): Uint8Array {
  return new TextEncoder().encode(canonicalReceiptBody(body));
}

function bodyFromInput(input: BuildReceiptInput): ReceiptBody {
  if (!RECEIPT_OPS.includes(input.op)) {
    throw new ReceiptError("invalid-op", "Receipt op must be put, copy, move, or delete");
  }
  const fromLocator = requireLocator(input.fromLocator, "fromLocator");
  const toLocator = requireLocator(input.toLocator, "toLocator");
  if (input.op === "delete" && toLocator !== TOMBSTONE_LOCATOR) {
    throw new ReceiptError(
      "invalid-locator",
      `delete receipts must set toLocator to "${TOMBSTONE_LOCATOR}"`,
    );
  }
  if (input.op !== "delete" && toLocator === TOMBSTONE_LOCATOR) {
    throw new ReceiptError(
      "invalid-locator",
      "only delete receipts may use the tombstone locator",
    );
  }
  return {
    v: RECEIPT_VERSION,
    op: input.op,
    itemId: requireItemId(input.itemId),
    itemVersion: requireVersion(input.itemVersion),
    contentSha256: requireHash(input.contentSha256, "contentSha256"),
    fromLocator,
    toLocator,
    botId: requireBotId(input.botId),
    issuedAt: requireIssuedAt(input.issuedAt),
    prevReceiptHash: requireHash(input.prevReceiptHash ?? GENESIS_RECEIPT_HASH, "prevReceiptHash"),
  };
}

/** Sign a movement or deletion receipt. No network. */
export function buildReceipt(input: BuildReceiptInput, crypto: ReceiptCrypto): MovementReceipt {
  if (!crypto || (crypto.alg !== "ed25519" && crypto.alg !== "hmac-sha256")) {
    throw new ReceiptError("invalid-signature", "Receipt crypto adapter is missing");
  }
  const body = bodyFromInput(input);
  const signatureBytes = crypto.sign(receiptSigningPayload(body));
  if (!(signatureBytes instanceof Uint8Array) || signatureBytes.length === 0) {
    throw new ReceiptError("invalid-signature", "Signer returned an empty signature");
  }
  const signature = bytesToHex(signatureBytes);
  if (!SIGNATURE_HEX.test(signature)) {
    throw new ReceiptError("invalid-signature", "Signature must be lowercase hex");
  }
  return { ...body, sigAlg: crypto.alg, signature };
}

function isReceiptBody(value: MovementReceipt): boolean {
  try {
    bodyFromInput(value);
    return value.v === RECEIPT_VERSION;
  } catch {
    return false;
  }
}

/**
 * Check the canonical body, the injected signature, and an optional
 * expected previous chain hash.
 */
export function verifyReceipt(
  receipt: MovementReceipt,
  crypto: ReceiptCrypto,
  options?: { expectedPrevHash?: string },
): ReceiptVerifyResult {
  if (!receipt || typeof receipt !== "object" || !crypto) {
    return { ok: false, reason: "invalid-receipt" };
  }
  if (receipt.sigAlg !== crypto.alg) {
    return { ok: false, reason: "alg-mismatch" };
  }
  if (typeof receipt.signature !== "string" || !SIGNATURE_HEX.test(receipt.signature)) {
    return { ok: false, reason: "invalid-receipt" };
  }
  if (!isReceiptBody(receipt)) {
    return { ok: false, reason: "invalid-receipt" };
  }
  if (
    options?.expectedPrevHash !== undefined &&
    receipt.prevReceiptHash !== options.expectedPrevHash
  ) {
    return { ok: false, reason: "prev-mismatch" };
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = hexToBytes(receipt.signature);
  } catch {
    return { ok: false, reason: "invalid-receipt" };
  }
  const valid = crypto.verify(receiptSigningPayload(receipt), signatureBytes);
  if (!valid) return { ok: false, reason: "bad-signature" };
  return { ok: true };
}

/**
 * Hash that the next receipt should store in `prevReceiptHash`.
 * Covers the unsigned body, the algorithm, and the signature.
 */
export function receiptChainHash(receipt: MovementReceipt): string {
  const body = canonicalReceiptBody({
    v: receipt.v,
    op: receipt.op,
    itemId: receipt.itemId,
    itemVersion: receipt.itemVersion,
    contentSha256: receipt.contentSha256,
    fromLocator: receipt.fromLocator,
    toLocator: receipt.toLocator,
    botId: receipt.botId,
    issuedAt: receipt.issuedAt,
    prevReceiptHash: receipt.prevReceiptHash,
  });
  return sha256Utf8(`${body}.${receipt.sigAlg}.${receipt.signature}`);
}

/** HMAC-SHA256 adapter. The key never leaves the caller. */
export function createHmacSha256ReceiptCrypto(key: Uint8Array): ReceiptCrypto {
  if (!(key instanceof Uint8Array) || key.length === 0) {
    throw new ReceiptError("invalid-signature", "HMAC key must be a non-empty byte string");
  }
  const keyHex = bytesToHex(key);
  const sign = (payload: Uint8Array): Uint8Array => {
    const mac = CryptoJS.HmacSHA256(
      CryptoJS.enc.Hex.parse(bytesToHex(payload)),
      CryptoJS.enc.Hex.parse(keyHex),
    );
    return hexToBytes(mac.toString(CryptoJS.enc.Hex));
  };
  return {
    alg: "hmac-sha256",
    sign,
    verify(payload, signature) {
      return constantTimeEqual(sign(payload), signature);
    },
  };
}
