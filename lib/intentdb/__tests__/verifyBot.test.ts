/**
 * Receipt verification bot and IntentDB feature status.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit --test-concurrency=1 lib/intentdb/__tests__/verifyBot.test.ts lib/intentdb/__tests__/syncOutbox.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { SEARCH_INDEX_STORAGE_KEY } from "../../vaultSearchKey";
import {
  formatFeatureStatus,
  INTENTDB_BOT_MOVE_ENV,
  INTENTDB_ENVELOPE_ENV,
  INTENTDB_ITEM_UPLOAD_ENV,
  INTENTDB_VERIFY_ENV,
  PIPASS_ACCOUNT_DELETE_ENV,
  reportFeatureStatus,
} from "../featureStatus";
import {
  buildReceipt,
  GENESIS_RECEIPT_HASH,
  type MovementReceipt,
  type ReceiptCrypto,
} from "../receipt";
import {
  INTENTDB_VERIFIER_BOT_ID,
  intentdbVerifyEnabled,
  verifyIntentItem,
} from "../verifyBot";

const CONTENT_HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);
const SESSION = "12".repeat(32);
const DECOY_PIN = "ff".repeat(32);
const SECRET_CIPHERTEXT = "v4:SECRET-CIPHERTEXT-DO-NOT-LOG";
const ITEM_ID = "fetched-item-1";

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

function receiptFor(
  crypto: ReceiptCrypto,
  contentSha256 = CONTENT_HASH,
): MovementReceipt {
  return buildReceipt(
    {
      op: "put",
      itemId: ITEM_ID,
      itemVersion: 1_700_000_000_000,
      contentSha256,
      fromLocator: "client",
      toLocator: "phone",
      botId: "pipass-server",
      issuedAt: 1_700_000_000_100,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
    },
    crypto,
  );
}

function payload(receipt: MovementReceipt | null, contentSha256 = CONTENT_HASH): string {
  return JSON.stringify({
    schema: "pipass-item-v1",
    itemId: ITEM_ID,
    kind: "vault-entry",
    version: 1_700_000_000_000,
    salt: "ab".repeat(16),
    createdAt: 1,
    updatedAt: 1_700_000_000_000,
    fields: [{ name: "password", ciphertext: SECRET_CIPHERTEXT }],
    contentSha256,
    locator: "phone",
    tombstone: false,
    receipt,
    receiptPublicKey: DECOY_PIN,
    vaultKeyProof: "ee".repeat(32),
    sessionToken: SESSION,
  });
}

function savedEnv(names: string[]): Map<string, string | undefined> {
  return new Map(names.map((name) => [name, process.env[name]]));
}

function restoreEnv(saved: Map<string, string | undefined>): void {
  for (const [name, value] of saved) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

test("a matching receipt verifies and does not change the phone item", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const local = { locator: "phone", blob: "phone-vault-blob", writes: 0 };
  const snapshot = JSON.stringify(local);
  const calls: string[] = [];
  let headerToken = "";
  const headerNames: string[] = [];
  const result = await verifyIntentItem({
    itemId: ITEM_ID,
    sessionToken: SESSION,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    apiBaseUrl: "https://items.example",
    fetchImpl: async (url, init) => {
      calls.push(`${init.method} ${url}`);
      headerToken = init.headers["x-session-token"] ?? "";
      headerNames.push(...Object.keys(init.headers));
      return { ok: true, status: 200, text: async () => payload(receiptFor(crypto)) };
    },
  });
  assert.equal(result.verified, true);
  if (result.verified) {
    assert.equal(result.itemId, ITEM_ID);
    assert.equal(result.op, "put");
    assert.equal(result.contentSha256, CONTENT_HASH);
    assert.equal(result.botId, INTENTDB_VERIFIER_BOT_ID);
  }
  assert.equal(calls.length, 1);
  assert.equal(calls[0], `GET https://items.example/api/vault/items/${ITEM_ID}`);
  assert.equal(headerToken, SESSION);
  assert.deepEqual(headerNames, ["x-session-token"]);
  assert.equal(JSON.stringify(local), snapshot);
});

test("a hash or signature mismatch is logged and not applied", async () => {
  const { crypto, publicKeyHex } = ed25519();
  const good = receiptFor(crypto);
  const local = { locator: "phone", blob: "phone-vault-blob", writes: 0 };
  const snapshot = JSON.stringify(local);

  const hashLogs: string[] = [];
  const hashCalls: string[] = [];
  const hashResult = await verifyIntentItem({
    itemId: ITEM_ID,
    sessionToken: SESSION,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    apiBaseUrl: "https://items.example",
    log: (message) => hashLogs.push(message),
    fetchImpl: async (_url, init) => {
      hashCalls.push(init.method);
      local.writes += init.method === "GET" ? 0 : 1;
      return { ok: true, status: 200, text: async () => payload(good, OTHER_HASH) };
    },
  });
  assert.equal(hashResult.verified, false);
  if (!hashResult.verified) assert.equal(hashResult.reason, "hash-mismatch");
  assert.deepEqual(hashCalls, ["GET"]);
  assert.equal(
    hashLogs.some((line) => line === `intentdb verifier audit itemId=${ITEM_ID} op=put reason=hash-mismatch`),
    true,
  );

  const flipped: MovementReceipt = {
    ...good,
    signature: good.signature.slice(0, -1) + (good.signature.endsWith("a") ? "b" : "a"),
  };
  const sigLogs: string[] = [];
  const sigCalls: string[] = [];
  const sigResult = await verifyIntentItem({
    itemId: ITEM_ID,
    sessionToken: SESSION,
    unlocked: true,
    enabled: true,
    publicKeyHex,
    apiBaseUrl: "https://items.example",
    log: (message) => sigLogs.push(message),
    fetchImpl: async (_url, init) => {
      sigCalls.push(init.method);
      local.writes += init.method === "GET" ? 0 : 1;
      return { ok: true, status: 200, text: async () => payload(flipped) };
    },
  });
  assert.equal(sigResult.verified, false);
  if (!sigResult.verified) assert.equal(sigResult.reason, "bad-signature");
  assert.deepEqual(sigCalls, ["GET"]);
  assert.equal(
    sigLogs.some((line) => line === `intentdb verifier audit itemId=${ITEM_ID} op=put reason=bad-signature`),
    true,
  );

  const joined = [...hashLogs, ...sigLogs].join("\n");
  assert.equal(joined.includes(good.signature), false);
  assert.equal(joined.includes(flipped.signature), false);
  assert.equal(joined.includes(SECRET_CIPHERTEXT), false);
  assert.equal(joined.includes(SESSION), false);
  assert.equal(joined.includes(publicKeyHex), false);
  assert.equal(joined.includes(DECOY_PIN), false);
  assert.equal(joined.includes("vaultKeyProof"), false);
  assert.equal(joined.includes("ee".repeat(32)), false);
  assert.equal(JSON.stringify(local), snapshot);
});

test("the verify flag defaults off and an explicit enable can override it", async () => {
  const previous = process.env[INTENTDB_VERIFY_ENV];
  delete process.env[INTENTDB_VERIFY_ENV];
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: true, status: 200, text: async () => "{}" };
  };
  try {
    assert.equal(intentdbVerifyEnabled(undefined), false);
    const disabled = await verifyIntentItem({
      itemId: ITEM_ID,
      sessionToken: SESSION,
      unlocked: true,
      apiBaseUrl: "https://items.example",
      fetchImpl,
    });
    assert.equal(disabled.verified, false);
    if (!disabled.verified) assert.equal(disabled.reason, "disabled");
    assert.equal(calls, 0);

    const locked = await verifyIntentItem({
      itemId: ITEM_ID,
      sessionToken: SESSION,
      unlocked: false,
      enabled: true,
      apiBaseUrl: "https://items.example",
      fetchImpl,
    });
    assert.equal(locked.verified, false);
    if (!locked.verified) assert.equal(locked.reason, "locked");
    assert.equal(calls, 0);

    process.env[INTENTDB_VERIFY_ENV] = "1";
    const forcedOff = await verifyIntentItem({
      itemId: ITEM_ID,
      sessionToken: SESSION,
      unlocked: true,
      enabled: false,
      apiBaseUrl: "https://items.example",
      fetchImpl,
    });
    assert.equal(forcedOff.verified, false);
    if (!forcedOff.verified) assert.equal(forcedOff.reason, "disabled");
    assert.equal(calls, 0);

    delete process.env[INTENTDB_VERIFY_ENV];
    const forcedOn = await verifyIntentItem({
      itemId: ITEM_ID,
      sessionToken: SESSION,
      unlocked: true,
      enabled: true,
      apiBaseUrl: "https://items.example",
      fetchImpl,
    });
    assert.equal(forcedOn.verified, false);
    if (!forcedOn.verified) assert.equal(forcedOn.reason, "rejected");
    assert.equal(calls, 1);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_VERIFY_ENV];
    else process.env[INTENTDB_VERIFY_ENV] = previous;
  }
});

test("the feature status line lists flags and the search index without key material", async () => {
  const flagNames = [
    INTENTDB_ITEM_UPLOAD_ENV,
    PIPASS_ACCOUNT_DELETE_ENV,
    INTENTDB_BOT_MOVE_ENV,
    INTENTDB_ENVELOPE_ENV,
    INTENTDB_VERIFY_ENV,
  ];
  const saved = savedEnv([
    ...flagNames,
    "EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY",
    "PIPASS_MASTER_SENTINEL",
  ]);
  const pin = "ab".repeat(32);
  const master = "master-key-" + "cd".repeat(32);
  const session = "session-SENTINEL-token";
  process.env.EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY = pin;
  process.env.PIPASS_MASTER_SENTINEL = master;
  process.env.PIPASS_SESSION_SENTINEL = session;
  try {
    for (const name of flagNames) delete process.env[name];
    const off = await reportFeatureStatus(async () => null);
    assert.deepEqual(off, {
      itemUpload: false,
      accountDelete: false,
      botMove: false,
      envelope: false,
      verify: false,
      searchIndexPresent: false,
    });
    assert.equal(
      formatFeatureStatus(off),
      "intentdb status upload=0 delete=0 bot=0 envelope=0 verify=0 searchIndex=0",
    );

    for (const name of flagNames) process.env[name] = "1";
    const on = await reportFeatureStatus(async (key) => {
      if (key === SEARCH_INDEX_STORAGE_KEY) {
        return JSON.stringify({ v: 1, chunks: 2, leak: pin, vaultKeyProof: "ee".repeat(32) });
      }
      return SECRET_CIPHERTEXT;
    });
    assert.equal(on.itemUpload, true);
    assert.equal(on.accountDelete, true);
    assert.equal(on.botMove, true);
    assert.equal(on.envelope, true);
    assert.equal(on.verify, true);
    assert.equal(on.searchIndexPresent, true);
    const line = formatFeatureStatus(on);
    assert.equal(
      line,
      "intentdb status upload=1 delete=1 bot=1 envelope=1 verify=1 searchIndex=1",
    );
    const blob = `${line}\n${JSON.stringify(on)}`;
    assert.equal(blob.includes(pin), false);
    assert.equal(blob.includes(master), false);
    assert.equal(blob.includes(session), false);
    assert.equal(blob.includes(SECRET_CIPHERTEXT), false);
    assert.equal(blob.includes("vaultKeyProof"), false);
    assert.equal(blob.includes("ee".repeat(32)), false);
    assert.match(
      line,
      /^intentdb status upload=[01] delete=[01] bot=[01] envelope=[01] verify=[01] searchIndex=[01]$/,
    );

    const rawCiphertext = await reportFeatureStatus(async () => SECRET_CIPHERTEXT + pin);
    assert.equal(rawCiphertext.searchIndexPresent, false);
    assert.equal(JSON.stringify(rawCiphertext).includes(pin), false);
  } finally {
    restoreEnv(saved);
    delete process.env.PIPASS_SESSION_SENTINEL;
  }
});

test("verifier and status sources do not open vault fields", () => {
  const verifier = readFileSync("lib/intentdb/verifyBot.ts", "utf8");
  assert.equal(verifier.includes(INTENTDB_VERIFIER_BOT_ID), true);
  assert.equal(verifier.includes("verifyFetchedItemReceipt"), true);
  assert.equal(verifier.includes("decrypt"), false);
  assert.equal(verifier.includes("vault_blobs"), false);
  assert.equal(verifier.includes("x-auth-hash"), false);
  assert.equal(verifier.includes("saveEntry"), false);
  assert.equal(verifier.includes("vaultSession"), false);
  assert.equal(verifier.includes("getActiveKeyShares"), false);
  assert.equal(verifier.includes("crypto/encryption"), false);
  assert.equal(verifier.includes("vaultWorker"), false);
  assert.equal(verifier.includes("vaultKeyProof"), false);

  const status = readFileSync("lib/intentdb/featureStatus.ts", "utf8");
  assert.equal(status.includes("decrypt"), false);
  assert.equal(status.includes("vaultKeyProof"), false);
  assert.equal(status.includes("x-auth-hash"), false);
  assert.equal(status.includes("vaultSession"), false);
  assert.equal(status.includes("getActiveKeyShares"), false);
  assert.equal(status.includes("vaultSearchStore"), false);

  const screen = readFileSync("screens/VaultScreen.tsx", "utf8");
  assert.equal(screen.includes("formatFeatureStatus"), true);
  assert.equal(screen.includes("console.info(line)"), true);

  const sync = readFileSync("lib/intentdb/syncOutbox.ts", "utf8");
  assert.equal(sync.includes("verifyIntentItem"), true);
  assert.equal(sync.includes("decrypt"), false);
  assert.equal(sync.includes("x-auth-hash"), false);
});
