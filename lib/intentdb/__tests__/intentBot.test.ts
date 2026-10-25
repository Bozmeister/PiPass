/**
 * IntentDB bot locator proposal. A failed check does not change local data.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit lib/intentdb/__tests__/intentBot.test.ts
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
import {
  INTENTDB_BOT_ID,
  INTENTDB_BOT_MOVE_ENV,
  INTENTDB_BOT_TIER_LOCATOR,
  proposeIntentBotMove,
} from "../intentBot";

const CONTENT_HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);
const PROOF = "ef".repeat(32);
const ITEM_ID = "bot-item-1";
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

function botReceipt(
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
      toLocator: INTENTDB_BOT_TIER_LOCATOR,
      botId: INTENTDB_BOT_ID,
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
    locator: INTENTDB_BOT_TIER_LOCATOR,
    tombstone: false,
    fields: [{ name: "notes", ciphertext: NOTES }],
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

test("the bot proposal stays off unless the feature flag is enabled", async () => {
  const previous = process.env[INTENTDB_BOT_MOVE_ENV];
  delete process.env[INTENTDB_BOT_MOVE_ENV];
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  let calls = 0;
  try {
    const disabled = await proposeIntentBotMove({
      ...baseInput,
      unlocked: true,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("network must not run");
      },
      applyLocator: () => {
        local.locator = INTENTDB_BOT_TIER_LOCATOR;
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

test("a locked vault does not send a bot proposal", async () => {
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  let calls = 0;
  const locked = await proposeIntentBotMove({
    ...baseInput,
    unlocked: false,
    enabled: true,
    fetchImpl: async () => {
      calls += 1;
      throw new Error("network must not run");
    },
    applyLocator: () => {
      local.locator = INTENTDB_BOT_TIER_LOCATOR;
    },
  });
  assert.equal(locked.proposed, false);
  if (!locked.proposed) assert.equal(locked.reason, "locked");
  assert.equal(calls, 0);
  assert.equal(JSON.stringify(local), snapshot);
});

test("an accepted bot proposal updates only the local locator", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const local = { locator: "phone", secret: "keep-me" };
  const receipt = botReceipt(crypto);
  let captured: { url: string; headers: Record<string, string>; body: string } | null = null;
  const result = await proposeIntentBotMove({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
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
  assert.equal(result.proposed, true);
  if (result.proposed) {
    assert.equal(result.botId, INTENTDB_BOT_ID);
    assert.equal(result.locator, INTENTDB_BOT_TIER_LOCATOR);
    assert.equal(result.contentSha256, CONTENT_HASH);
  }
  assert.equal(local.locator, INTENTDB_BOT_TIER_LOCATOR);
  assert.equal(local.secret, "keep-me");
  assert.ok(captured);
  assert.equal(captured.url.endsWith(`/api/vault/items/${ITEM_ID}/move`), true);
  assert.equal(captured.headers["x-session-token"], "session-token");
  assert.equal("x-auth-hash" in captured.headers, false);
  assert.deepEqual(JSON.parse(captured.body), {
    newLocator: INTENTDB_BOT_TIER_LOCATOR,
    vaultKeyProof: PROOF,
    botId: INTENTDB_BOT_ID,
  });
});

test("a bad signature does not apply the bot proposal", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const good = botReceipt(crypto);
  const flipped: MovementReceipt = {
    ...good,
    signature: good.signature.slice(0, -1) + (good.signature.endsWith("a") ? "b" : "a"),
  };
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await proposeIntentBotMove({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = INTENTDB_BOT_TIER_LOCATOR;
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
  assert.equal(logs[0].includes("keep-me"), false);
  assert.equal(logs[0].includes(NOTES), false);
  assert.equal(logs[0].includes(good.signature), false);
});

test("a content hash change does not apply the bot proposal", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const receipt = botReceipt(crypto, { contentSha256: OTHER_HASH });
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await proposeIntentBotMove({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = INTENTDB_BOT_TIER_LOCATOR;
      local.secret = "replaced";
    },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseFor(receipt, OTHER_HASH)),
    }),
  });
  assert.equal(result.proposed, false);
  if (!result.proposed) assert.equal(result.reason, "unverified");
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs[0].includes("reason=hash-mismatch"), true);
  assert.equal(logs[0].includes("keep-me"), false);
});

test("a receipt from another bot id is not applied", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const receipt = botReceipt(crypto, { botId: "pipass-server" });
  const local = { locator: "phone", secret: "keep-me" };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await proposeIntentBotMove({
    ...baseInput,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = INTENTDB_BOT_TIER_LOCATOR;
    },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseFor(receipt)),
    }),
  });
  assert.equal(result.proposed, false);
  if (!result.proposed) assert.equal(result.reason, "unverified");
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs[0].includes("reason=item-mismatch"), true);
});

test("bot proposal source does not touch the vault", () => {
  const source = readFileSync("lib/intentdb/intentBot.ts", "utf8");
  assert.equal(source.includes("saveEntry"), false);
  assert.equal(source.includes("deleteEntry"), false);
  assert.equal(source.includes("destroyAllData"), false);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("x-auth-hash"), false);
  assert.equal(source.includes("decrypt"), false);
  assert.equal(source.includes("vaultSession"), false);
  assert.equal(source.includes("getActiveKeyShares"), false);
  assert.equal(source.includes("requestItemLocatorMove"), true);
  assert.equal(source.includes("verifyFetchedItemReceipt"), true);
});
