/**
 * Client locator move. A failed receipt check does not change local data.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit lib/intentdb/__tests__/moveItem.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  buildReceipt,
  GENESIS_RECEIPT_HASH,
  type MovementReceipt,
  type ReceiptCrypto,
} from "../receipt";
import { INTENTDB_ITEM_UPLOAD_ENV } from "../uploadItem";
import { requestItemLocatorMove } from "../moveItem";

const CONTENT_HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);
const PROOF = "ef".repeat(32);
const ITEM_ID = "move-item-1";
const VERSION = 1_700_000_000_000;
const NOTES = "v4:00112233445566778899aabb:cc:00112233445566778899aabbccddeeff";

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

function moveReceipt(
  crypto: ReceiptCrypto,
  overrides: Partial<Parameters<typeof buildReceipt>[0]> = {},
): MovementReceipt {
  return buildReceipt(
    {
      op: "move",
      itemId: ITEM_ID,
      itemVersion: VERSION,
      contentSha256: CONTENT_HASH,
      fromLocator: "phone",
      toLocator: "desktop",
      botId: "pipass-server",
      issuedAt: 1_700_000_000_100,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
      ...overrides,
    },
    crypto,
  );
}

function responseFor(receipt: MovementReceipt, contentSha256 = CONTENT_HASH) {
  return {
    itemId: ITEM_ID,
    version: VERSION,
    contentSha256,
    locator: "desktop",
    tombstone: false,
    fields: [{ name: "notes", ciphertext: NOTES }],
    receipt,
    receiptPublicKey: "11".repeat(32),
  };
}

test("a move stays off unless the feature flag is enabled", async () => {
  const previous = process.env[INTENTDB_ITEM_UPLOAD_ENV];
  delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  let calls = 0;
  try {
    const disabled = await requestItemLocatorMove({
      itemId: ITEM_ID,
      newLocator: "desktop",
      version: VERSION,
      contentSha256: CONTENT_HASH,
      sessionToken: "session-token",
      vaultKeyProof: PROOF,
      publicKeyHex: "ab".repeat(32),
      fetchImpl: async () => {
        calls += 1;
        throw new Error("network must not run");
      },
      applyLocator: () => {
        local.locator = "desktop";
      },
    });
    assert.equal(disabled.moved, false);
    if (!disabled.moved) assert.equal(disabled.reason, "disabled");
    assert.equal(calls, 0);
    assert.equal(JSON.stringify(local), snapshot);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
    else process.env[INTENTDB_ITEM_UPLOAD_ENV] = previous;
  }
});

test("an accepted move updates only the local locator", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const local = { locator: "phone", secret: "keep-me" };
  const receipt = moveReceipt(crypto);
  let captured: { url: string; headers: Record<string, string>; body: string } | null = null;
  const result = await requestItemLocatorMove({
    itemId: ITEM_ID,
    newLocator: "desktop",
    version: VERSION,
    contentSha256: CONTENT_HASH,
    sessionToken: "session-token",
    vaultKeyProof: PROOF,
    publicKeyHex,
    enabled: true,
    apiBaseUrl: "http://127.0.0.1:9",
    applyLocator: (update) => {
      local.locator = update.locator;
    },
    fetchImpl: async (url, init) => {
      captured = { url, headers: init.headers, body: init.body };
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(responseFor(receipt)),
      };
    },
  });
  assert.equal(result.moved, true);
  if (result.moved) {
    assert.equal(result.locator, "desktop");
    assert.equal(result.contentSha256, CONTENT_HASH);
  }
  assert.equal(local.locator, "desktop");
  assert.equal(local.secret, "keep-me");
  assert.ok(captured);
  assert.equal(captured.url.endsWith(`/api/vault/items/${ITEM_ID}/move`), true);
  assert.equal(captured.headers["x-session-token"], "session-token");
  assert.equal("x-auth-hash" in captured.headers, false);
  assert.deepEqual(JSON.parse(captured.body), {
    newLocator: "desktop",
    vaultKeyProof: PROOF,
  });
});

test("a bad signature does not apply the move", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const good = moveReceipt(crypto);
  const flipped: MovementReceipt = {
    ...good,
    signature: good.signature.slice(0, -1) + (good.signature.endsWith("a") ? "b" : "a"),
  };
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await requestItemLocatorMove({
    itemId: ITEM_ID,
    newLocator: "desktop",
    version: VERSION,
    contentSha256: CONTENT_HASH,
    sessionToken: "session-token",
    vaultKeyProof: PROOF,
    publicKeyHex,
    enabled: true,
    apiBaseUrl: "http://127.0.0.1:9",
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = "desktop";
      local.secret = "replaced";
    },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseFor(flipped)),
    }),
  });
  assert.equal(result.moved, false);
  if (!result.moved) assert.equal(result.reason, "unverified");
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].includes("reason=bad-signature"), true);
  assert.equal(logs[0].includes("keep-me"), false);
  assert.equal(logs[0].includes(NOTES), false);
  assert.equal(logs[0].includes(good.signature), false);
});

test("a content hash change does not apply even when the receipt signature is valid", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const receipt = moveReceipt(crypto, { contentSha256: OTHER_HASH });
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await requestItemLocatorMove({
    itemId: ITEM_ID,
    newLocator: "desktop",
    version: VERSION,
    contentSha256: CONTENT_HASH,
    sessionToken: "session-token",
    vaultKeyProof: PROOF,
    publicKeyHex,
    enabled: true,
    apiBaseUrl: "http://127.0.0.1:9",
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = "desktop";
      local.secret = "replaced";
    },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseFor(receipt, OTHER_HASH)),
    }),
  });
  assert.equal(result.moved, false);
  if (!result.moved) assert.equal(result.reason, "unverified");
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs[0].includes("reason=hash-mismatch"), true);
  assert.equal(logs[0].includes("keep-me"), false);
  assert.equal(logs[0].includes(NOTES), false);
});

test("move helper source does not write the vault", () => {
  const source = readFileSync("lib/intentdb/moveItem.ts", "utf8");
  assert.equal(source.includes("saveEntry"), false);
  assert.equal(source.includes("deleteEntry"), false);
  assert.equal(source.includes("destroyAllData"), false);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("x-auth-hash"), false);
  assert.equal(source.includes("decrypt"), false);
  assert.equal(source.includes("verifyFetchedItemReceipt"), true);
});
