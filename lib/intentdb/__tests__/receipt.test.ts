/**
 * Phase 1 IntentDB movement and deletion receipts.
 * Signatures are checked with an injected key. No network.
 */
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { bytesToHex } from "../../../crypto/secureMemory";
import {
  buildReceipt,
  canonicalReceiptBody,
  createHmacSha256ReceiptCrypto,
  GENESIS_RECEIPT_HASH,
  ReceiptError,
  receiptChainHash,
  TOMBSTONE_LOCATOR,
  verifyReceipt,
  type MovementReceipt,
  type ReceiptCrypto,
} from "../receipt";

const CONTENT_HASH = "ab".repeat(32);
const HMAC_KEY = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

function hmacCrypto(): ReceiptCrypto {
  return createHmacSha256ReceiptCrypto(HMAC_KEY);
}

function ed25519Crypto(): ReceiptCrypto {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    alg: "ed25519",
    sign(payload) {
      return new Uint8Array(sign(null, Buffer.from(payload), privateKey));
    },
    verify(payload, signature) {
      return verify(null, Buffer.from(payload), publicKey, Buffer.from(signature));
    },
  };
}

function baseInput(overrides: Partial<Parameters<typeof buildReceipt>[0]> = {}) {
  return {
    op: "move" as const,
    itemId: "entryid1234567",
    itemVersion: 20,
    contentSha256: CONTENT_HASH,
    fromLocator: "local/vault",
    toLocator: "intentdb/tier-hot/1",
    botId: "bot-phase1",
    issuedAt: 1_700_000_000_000,
    prevReceiptHash: GENESIS_RECEIPT_HASH,
    ...overrides,
  };
}

test("HMAC adapter matches node:crypto over the raw payload bytes", () => {
  const payload = new TextEncoder().encode("pipass-receipt-payload");
  const expected = createHmac("sha256", HMAC_KEY).update(payload).digest("hex");
  const adapter = hmacCrypto();
  assert.equal(bytesToHex(adapter.sign(payload)), expected);
  assert.equal(adapter.verify(payload, adapter.sign(payload)), true);
});

test("put, copy, and move receipts verify and chain", () => {
  const crypto = hmacCrypto();
  const put = buildReceipt(baseInput({ op: "put", fromLocator: "local", toLocator: "intentdb/staging" }), crypto);
  const copy = buildReceipt(
    baseInput({
      op: "copy",
      fromLocator: "intentdb/staging",
      toLocator: "intentdb/replica-b",
      prevReceiptHash: receiptChainHash(put),
    }),
    crypto,
  );
  const move = buildReceipt(
    baseInput({
      op: "move",
      prevReceiptHash: receiptChainHash(copy),
    }),
    crypto,
  );

  assert.equal(verifyReceipt(put, crypto, { expectedPrevHash: GENESIS_RECEIPT_HASH }).ok, true);
  assert.equal(verifyReceipt(copy, crypto).ok, true);
  assert.equal(verifyReceipt(move, crypto, { expectedPrevHash: receiptChainHash(copy) }).ok, true);
  assert.deepEqual(verifyReceipt(move, crypto, { expectedPrevHash: GENESIS_RECEIPT_HASH }), {
    ok: false,
    reason: "prev-mismatch",
  });
  assert.notEqual(receiptChainHash(put), receiptChainHash(copy));
});

test("delete receipt requires the tombstone locator and covers the content hash", () => {
  const crypto = hmacCrypto();
  const receipt = buildReceipt(
    baseInput({
      op: "delete",
      fromLocator: "intentdb/tier-hot/1",
      toLocator: TOMBSTONE_LOCATOR,
    }),
    crypto,
  );
  assert.equal(receipt.toLocator, "tombstone");
  assert.equal(verifyReceipt(receipt, crypto).ok, true);
  assert.equal(canonicalReceiptBody(receipt).includes(CONTENT_HASH), true);

  assert.throws(
    () => buildReceipt(baseInput({ op: "delete", toLocator: "intentdb/still-there" }), crypto),
    (err: unknown) => err instanceof ReceiptError && err.code === "invalid-locator",
  );
  assert.throws(
    () => buildReceipt(baseInput({ op: "put", toLocator: TOMBSTONE_LOCATOR }), crypto),
    (err: unknown) => err instanceof ReceiptError && err.code === "invalid-locator",
  );
});

test("tampered content hash or signature fails verification", () => {
  const crypto = hmacCrypto();
  const receipt = buildReceipt(baseInput(), crypto);
  const tamperedHash: MovementReceipt = {
    ...receipt,
    contentSha256: "cd".repeat(32),
  };
  const tamperedResult = verifyReceipt(tamperedHash, crypto);
  assert.equal(tamperedResult.ok, false);
  if (!tamperedResult.ok) assert.equal(tamperedResult.reason, "bad-signature");

  const flipped = receipt.signature.slice(0, -1) + (receipt.signature.endsWith("a") ? "b" : "a");
  const flippedResult = verifyReceipt({ ...receipt, signature: flipped }, crypto);
  assert.equal(flippedResult.ok, false);
  if (!flippedResult.ok) assert.equal(flippedResult.reason, "bad-signature");
});

test("a different HMAC key and an Ed25519 adapter both reject the wrong signer", () => {
  const receipt = buildReceipt(baseInput(), hmacCrypto());
  const otherKey = createHmacSha256ReceiptCrypto(new Uint8Array([9, 9, 9, 9]));
  const otherKeyResult = verifyReceipt(receipt, otherKey);
  assert.equal(otherKeyResult.ok, false);
  if (!otherKeyResult.ok) assert.equal(otherKeyResult.reason, "bad-signature");

  const ed = ed25519Crypto();
  const edReceipt = buildReceipt(baseInput({ op: "copy" }), ed);
  assert.equal(verifyReceipt(edReceipt, ed).ok, true);
  const algMismatch = verifyReceipt(edReceipt, hmacCrypto());
  assert.equal(algMismatch.ok, false);
  if (!algMismatch.ok) assert.equal(algMismatch.reason, "alg-mismatch");
  const reverseMismatch = verifyReceipt(receipt, ed);
  assert.equal(reverseMismatch.ok, false);
  if (!reverseMismatch.ok) assert.equal(reverseMismatch.reason, "alg-mismatch");
});

test("receipt module does not perform network I/O", () => {
  const source = readFileSync(new URL("../receipt.ts", import.meta.url), "utf8");
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("/api/vault"), false);
  assert.equal(source.includes("http://"), false);
  assert.equal(source.includes("https://"), false);
});
