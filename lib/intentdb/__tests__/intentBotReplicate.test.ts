/**
 * IntentDB bot replicate proposal. A failed check keeps the local locators.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit lib/intentdb/__tests__/intentBotReplicate.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import {
  buildReceipt,
  GENESIS_RECEIPT_HASH,
  type MovementReceipt,
  type ReceiptCrypto,
} from "../receipt";
import {
  INTENTDB_BOT_ID,
  INTENTDB_BOT_MOVE_ENV,
  INTENTDB_BOT_REPLICA_LOCATOR,
  proposeIntentBotReplicate,
} from "../intentBot";

const CONTENT_HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);
const PROOF = "ef".repeat(32);
const ITEM_ID = "replica-item-1";
const VERSION = 1_700_000_000_000;

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

function copyReceipt(
  crypto: ReceiptCrypto,
  overrides: Partial<Parameters<typeof buildReceipt>[0]> = {},
): MovementReceipt {
  return buildReceipt(
    {
      op: "copy",
      itemId: ITEM_ID,
      itemVersion: VERSION,
      contentSha256: CONTENT_HASH,
      fromLocator: "phone",
      toLocator: INTENTDB_BOT_REPLICA_LOCATOR,
      botId: INTENTDB_BOT_ID,
      issuedAt: 1_700_000_000_100,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
      ...overrides,
    },
    crypto,
  );
}

function responseFor(
  receipt: MovementReceipt,
  locator = "phone",
  contentSha256 = CONTENT_HASH,
) {
  return {
    itemId: ITEM_ID,
    version: VERSION,
    contentSha256,
    locator,
    tombstone: false,
    receipt,
    receiptPublicKey: "11".repeat(32),
  };
}

const baseInput = {
  itemId: ITEM_ID,
  fromLocator: "phone",
  version: VERSION,
  contentSha256: CONTENT_HASH,
  sessionToken: "session-token",
  vaultKeyProof: PROOF,
  apiBaseUrl: "http://127.0.0.1:9",
};

test("a replicate proposal stays off unless the bot flag is enabled", async () => {
  const previous = process.env[INTENTDB_BOT_MOVE_ENV];
  delete process.env[INTENTDB_BOT_MOVE_ENV];
  const local = { locators: ["phone"], secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  let calls = 0;
  try {
    const disabled = await proposeIntentBotReplicate({
      ...baseInput,
      unlocked: true,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("network must not run");
      },
      applyLocators: () => {
        local.locators = ["phone", INTENTDB_BOT_REPLICA_LOCATOR];
      },
    });
    assert.equal(disabled.proposed, false);
    if (!disabled.proposed) assert.equal(disabled.reason, "disabled");
    assert.equal(calls, 0);
    assert.equal(JSON.stringify(local), snapshot);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_BOT_MOVE_ENV];
    else process.env[INTENTDB_BOT_MOVE_ENV] = previous;
  }
});

test("an accepted replicate records both locators", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const local = { locators: ["phone"], secret: "keep-me" };
  const receipt = copyReceipt(crypto);
  let captured: { url: string; body: string } | null = null;
  const result = await proposeIntentBotReplicate({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    applyLocators: (update) => {
      local.locators = update.locators;
    },
    fetchImpl: async (url, init) => {
      captured = { url, body: init.body };
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(responseFor(receipt)),
      };
    },
  });
  assert.equal(result.proposed, true);
  if (result.proposed) {
    assert.deepEqual(result.locators, ["phone", INTENTDB_BOT_REPLICA_LOCATOR]);
    assert.equal(result.botId, INTENTDB_BOT_ID);
    assert.equal(result.contentSha256, CONTENT_HASH);
  }
  assert.deepEqual(local.locators, ["phone", INTENTDB_BOT_REPLICA_LOCATOR]);
  assert.equal(local.secret, "keep-me");
  assert.ok(captured);
  assert.equal(captured.url.endsWith(`/api/vault/items/${ITEM_ID}/replicate`), true);
  assert.deepEqual(JSON.parse(captured.body), {
    newLocator: INTENTDB_BOT_REPLICA_LOCATOR,
    vaultKeyProof: PROOF,
    botId: INTENTDB_BOT_ID,
  });
});

test("a bad replicate signature does not record the replica", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const good = copyReceipt(crypto);
  const flipped: MovementReceipt = {
    ...good,
    signature: good.signature.slice(0, -1) + (good.signature.endsWith("a") ? "b" : "a"),
  };
  const local = { locators: ["phone"], secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await proposeIntentBotReplicate({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    log: (message) => logs.push(message),
    applyLocators: () => {
      local.locators = ["phone", INTENTDB_BOT_REPLICA_LOCATOR];
      local.secret = "replaced";
    },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseFor(flipped)),
    }),
  });
  assert.equal(result.proposed, false);
  if (!result.proposed) assert.equal(result.reason, "unverified");
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs[0].includes("reason=bad-signature"), true);
  assert.equal(logs[0].includes(good.signature), false);
});

test("a replicate hash change does not record the replica", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const receipt = copyReceipt(crypto, { contentSha256: OTHER_HASH });
  const local = { locators: ["phone"], secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await proposeIntentBotReplicate({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    log: (message) => logs.push(message),
    applyLocators: () => {
      local.locators = ["gone"];
      local.secret = "replaced";
    },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseFor(receipt, "phone", OTHER_HASH)),
    }),
  });
  assert.equal(result.proposed, false);
  if (!result.proposed) assert.equal(result.reason, "unverified");
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs[0].includes("reason=hash-mismatch"), true);
});
