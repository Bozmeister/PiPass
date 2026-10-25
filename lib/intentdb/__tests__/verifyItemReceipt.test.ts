/**
 * Client checks of a fetched item receipt. A failure leaves local data alone.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit lib/intentdb/__tests__/verifyItemReceipt.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { bytesToHex } from "../../../crypto/secureMemory";
import {
  buildReceipt,
  GENESIS_RECEIPT_HASH,
  type MovementReceipt,
  type ReceiptCrypto,
} from "../receipt";
import { verifyFetchedItemReceipt } from "../verifyItemReceipt";

const CONTENT_HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);

function ed25519(): { crypto: ReceiptCrypto; publicKeyHex: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const publicKeyHex = Buffer.from(jwk.x, "base64url").toString("hex");
  return {
    publicKeyHex,
    crypto: {
      alg: "ed25519",
      sign(payload) {
        return new Uint8Array(sign(null, Buffer.from(payload), privateKey));
      },
      verify(payload, signature) {
        return verify(null, Buffer.from(payload), publicKey, Buffer.from(signature));
      },
    },
  };
}

function item(overrides: Partial<{ contentSha256: string; tombstone: boolean; version: number }> = {}) {
  return {
    itemId: "fetched-item-1",
    version: 1_700_000_000_000,
    contentSha256: CONTENT_HASH,
    tombstone: false,
    ...overrides,
  };
}

function receiptFor(
  crypto: ReceiptCrypto,
  overrides: Partial<Parameters<typeof buildReceipt>[0]> = {},
): MovementReceipt {
  return buildReceipt(
    {
      op: "put",
      itemId: "fetched-item-1",
      itemVersion: 1_700_000_000_000,
      contentSha256: CONTENT_HASH,
      fromLocator: "client",
      toLocator: "phone",
      botId: "pipass-server",
      issuedAt: 1_700_000_000_100,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
      ...overrides,
    },
    crypto,
  );
}

test("a matching receipt is accepted and a bad signature is not applied", () => {
  const { crypto, publicKeyHex } = ed25519();
  const local = { blob: "local-vault", adopted: 0 };
  const snapshot = JSON.stringify(local);
  const good = receiptFor(crypto);
  let commits = 0;
  const accepted = verifyFetchedItemReceipt({
    item: item(),
    receipt: good,
    publicKeyHex,
    commit: () => {
      commits += 1;
      local.adopted += 1;
    },
  });
  assert.equal(accepted.accepted, true);
  assert.equal(commits, 1);
  assert.equal(local.adopted, 1);

  const flipped: MovementReceipt = {
    ...good,
    signature: good.signature.slice(0, -1) + (good.signature.endsWith("a") ? "b" : "a"),
  };
  const logs: string[] = [];
  const before = JSON.stringify(local);
  const rejected = verifyFetchedItemReceipt({
    item: item(),
    receipt: flipped,
    publicKeyHex,
    log: (message) => logs.push(message),
    commit: () => {
      local.blob = "overwritten";
      local.adopted += 1;
    },
  });
  assert.equal(rejected.accepted, false);
  if (!rejected.accepted) assert.equal(rejected.reason, "bad-signature");
  assert.equal(JSON.stringify(local), before);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].includes("reason=bad-signature"), true);
  assert.equal(logs[0].includes("local-vault"), false);
  assert.equal(logs[0].includes(good.signature), false);
  assert.equal(bytesToHex(new Uint8Array([1])).length, 2);
  assert.notEqual(JSON.stringify(local), snapshot);
});

test("a content hash mismatch is rejected and local vault data stays", () => {
  const { crypto, publicKeyHex } = ed25519();
  const local = { entries: [{ id: "fetched-item-1", secret: "keep-me" }] };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  let commits = 0;
  const decision = verifyFetchedItemReceipt({
    item: item({ contentSha256: OTHER_HASH }),
    receipt: receiptFor(crypto),
    publicKeyHex,
    log: (message) => logs.push(message),
    commit: () => {
      commits += 1;
      local.entries[0].secret = "replaced";
    },
  });
  assert.equal(decision.accepted, false);
  if (!decision.accepted) assert.equal(decision.reason, "hash-mismatch");
  assert.equal(commits, 0);
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs[0].includes("reason=hash-mismatch"), true);
  assert.equal(logs[0].includes("keep-me"), false);
});

test("a missing receipt is not applied to the local vault", () => {
  const local = { entries: 2 };
  const snapshot = JSON.stringify(local);
  const decision = verifyFetchedItemReceipt({
    item: item(),
    receipt: null,
    publicKeyHex: "ab".repeat(32),
    commit: () => {
      local.entries = 0;
    },
  });
  assert.equal(decision.accepted, false);
  if (!decision.accepted) assert.equal(decision.reason, "missing");
  assert.equal(JSON.stringify(local), snapshot);
});

test("verification helper source does not write the vault", () => {
  const source = readFileSync("lib/intentdb/verifyItemReceipt.ts", "utf8");
  assert.equal(source.includes("saveEntry"), false);
  assert.equal(source.includes("deleteEntry"), false);
  assert.equal(source.includes("destroyAllData"), false);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("verifyReceipt"), true);
});
