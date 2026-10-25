/**
 * Outbox sync trigger. Flag default is off. A failed upload leaves local data alone.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit lib/intentdb/__tests__/syncOutbox.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { buildVaultEntryManifest } from "../itemManifest";
import {
  INTENTDB_BOT_ID,
  INTENTDB_BOT_MOVE_ENV,
  INTENTDB_BOT_TIER_LOCATOR,
} from "../intentBot";
import {
  buildReceipt,
  GENESIS_RECEIPT_HASH,
  type MovementReceipt,
  type ReceiptCrypto,
} from "../receipt";
import { INTENTDB_ITEM_UPLOAD_ENV } from "../uploadItem";
import { startIntentdbOutboxSync, syncIntentdbOutbox } from "../syncOutbox";
import type { VaultEntry } from "../../../workers/vaultWorker";
import type { OutboxRecord } from "../../../workers/intentdbOutbox";

function v4(label: string): string {
  const body = createHash("sha256").update(label).digest("hex");
  return `v4:${"11".repeat(12)}:${body}:${"22".repeat(16)}`;
}

function stagedRecord(): OutboxRecord {
  const updatedAt = 1_700_000_000_000;
  const entry: VaultEntry = {
    id: "sync-item-1",
    title: "PLAINTEXT_TITLE_SENTINEL",
    encryptedPassword: v4("password-field"),
    encryptedTitle: v4("title-field"),
    encryptedUsername: v4("username-field"),
    notes: v4("note-field"),
    salt: "ab".repeat(16),
    createdAt: updatedAt - 50,
    updatedAt,
  };
  return { kind: "manifest", enqueuedAt: updatedAt, manifest: buildVaultEntryManifest(entry) };
}

test("sync stays off unless the upload flag is enabled", async () => {
  const previous = process.env[INTENTDB_ITEM_UPLOAD_ENV];
  delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
  let listed = 0;
  let uploads = 0;
  const local = { vaultBlob: "monolith-blob", outbox: [stagedRecord()] };
  const snapshot = JSON.stringify(local);
  try {
    const result = await syncIntentdbOutbox({
      unlocked: true,
      sessionToken: "ab".repeat(32),
      vaultKeyProof: "cd".repeat(32),
      records: local.outbox,
      listRecords: async () => {
        listed += 1;
        return local.outbox;
      },
      upload: async () => {
        uploads += 1;
        throw new Error("upload must not run");
      },
    });
    assert.equal(result.ran, false);
    assert.equal(result.attempted, 0);
    assert.equal(listed, 0);
    assert.equal(uploads, 0);
    assert.equal(JSON.stringify(local), snapshot);

    const locked = await syncIntentdbOutbox({
      unlocked: false,
      enabled: true,
      sessionToken: "ab".repeat(32),
      vaultKeyProof: "cd".repeat(32),
      listRecords: async () => {
        listed += 1;
        return local.outbox;
      },
      upload: async () => {
        uploads += 1;
        return { uploaded: false, reason: "network" };
      },
    });
    assert.equal(locked.ran, false);
    assert.equal(listed, 0);
    assert.equal(uploads, 0);
    assert.equal(JSON.stringify(local), snapshot);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
    else process.env[INTENTDB_ITEM_UPLOAD_ENV] = previous;
  }
});

test("a failed sync leaves the outbox and local vault unchanged", async () => {
  const record = stagedRecord();
  const local = { vaultBlob: "monolith-blob-must-stay", outbox: [record] };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  let fetches = 0;
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: local.outbox,
    apiBaseUrl: "https://items.example",
    log: (message) => logs.push(message),
    fetchImpl: async () => {
      fetches += 1;
      throw new Error("offline");
    },
  });
  assert.equal(result.ran, true);
  assert.equal(result.attempted, 1);
  assert.equal(result.uploaded, 0);
  assert.equal(result.failed, 1);
  assert.equal(fetches, 1);
  assert.equal(local.outbox.length, 1);
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].includes("reason=network"), true);
  assert.equal(logs[0].includes("sync-item-1"), true);
  assert.equal(logs[0].includes("monolith-blob-must-stay"), false);
  assert.equal(logs[0].includes("PLAINTEXT_TITLE_SENTINEL"), false);
});

test("the sync timer can be stopped before it uploads", () => {
  let uploads = 0;
  const handle = startIntentdbOutboxSync(
    {
      unlocked: true,
      enabled: true,
      sessionToken: "ab".repeat(32),
      vaultKeyProof: "cd".repeat(32),
      records: [stagedRecord()],
      upload: async () => {
        uploads += 1;
        return { uploaded: false, reason: "network" };
      },
    },
    60_000,
  );
  handle.stop();
  assert.equal(uploads, 0);
});

test("sync helper source does not write the vault or the outbox", () => {
  const source = readFileSync("lib/intentdb/syncOutbox.ts", "utf8");
  assert.equal(source.includes("saveEntry"), false);
  assert.equal(source.includes("deleteEntry"), false);
  assert.equal(source.includes("destroyAllData"), false);
  assert.equal(source.includes("clearIntentdbOutbox"), false);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("x-auth-hash"), false);
  assert.equal(source.includes("decrypt"), false);
  assert.equal(source.includes("proposeIntentBotMove"), true);
  assert.equal(source.includes("verifyIntentItem"), true);
});

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

function moveResponse(receipt: MovementReceipt, manifest: { itemId: string; version: number; contentSha256: string }) {
  return {
    itemId: manifest.itemId,
    version: manifest.version,
    contentSha256: manifest.contentSha256,
    locator: INTENTDB_BOT_TIER_LOCATOR,
    tombstone: false,
    receipt,
    receiptPublicKey: "11".repeat(32),
  };
}

test("a bot move from sync updates only the locator when the bot flag is on", async () => {
  const record = stagedRecord();
  assert.equal(record.kind, "manifest");
  const manifest = record.manifest;
  const { crypto, publicKeyHex } = ed25519();
  const receipt = buildReceipt(
    {
      op: "move",
      itemId: manifest.itemId,
      itemVersion: manifest.version,
      contentSha256: manifest.contentSha256,
      fromLocator: "phone",
      toLocator: INTENTDB_BOT_TIER_LOCATOR,
      botId: INTENTDB_BOT_ID,
      issuedAt: manifest.version + 10,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
    },
    crypto,
  );
  const local = {
    locator: "phone",
    secret: "keep-me",
    vaultBlob: "monolith-blob",
    outbox: [record],
  };
  const outboxSnapshot = JSON.stringify(local.outbox);
  const calls: string[] = [];
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    botMove: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: local.outbox,
    apiBaseUrl: "https://items.example",
    receiptPublicKey: publicKeyHex,
    applyLocator: (update) => {
      local.locator = update.locator;
    },
    fetchImpl: async (url, init) => {
      calls.push(`${init.method} ${url}`);
      if (url.endsWith("/move")) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify(moveResponse(receipt, manifest)),
        };
      }
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, 1);
  assert.equal(result.failed, 0);
  assert.equal(local.locator, INTENTDB_BOT_TIER_LOCATOR);
  assert.equal(local.secret, "keep-me");
  assert.equal(local.vaultBlob, "monolith-blob");
  assert.equal(JSON.stringify(local.outbox), outboxSnapshot);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].startsWith("PUT "), true);
  assert.equal(calls[1].includes("/move"), true);
});

test("the bot move flag default does not call the move path", async () => {
  const previous = process.env[INTENTDB_BOT_MOVE_ENV];
  delete process.env[INTENTDB_BOT_MOVE_ENV];
  const record = stagedRecord();
  const local = { locator: "phone", secret: "keep-me", outbox: [record] };
  const snapshot = JSON.stringify(local);
  let calls = 0;
  try {
    const result = await syncIntentdbOutbox({
      unlocked: true,
      enabled: true,
      sessionToken: "ab".repeat(32),
      vaultKeyProof: "cd".repeat(32),
      records: local.outbox,
      apiBaseUrl: "https://items.example",
      applyLocator: () => {
        local.locator = INTENTDB_BOT_TIER_LOCATOR;
      },
      fetchImpl: async () => {
        calls += 1;
        return { ok: true, status: 200, text: async () => "" };
      },
    });
    assert.equal(result.uploaded, 1);
    assert.equal(result.failed, 0);
    assert.equal(calls, 1);
    assert.equal(JSON.stringify(local), snapshot);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_BOT_MOVE_ENV];
    else process.env[INTENTDB_BOT_MOVE_ENV] = previous;
  }
});

test("a failed bot proposal from sync leaves the locator and outbox unchanged", async () => {
  const record = stagedRecord();
  assert.equal(record.kind, "manifest");
  const local = { locator: "phone", secret: "keep-me", outbox: [record] };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    botMove: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: local.outbox,
    apiBaseUrl: "https://items.example",
    receiptPublicKey: "ab".repeat(32),
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = INTENTDB_BOT_TIER_LOCATOR;
      local.secret = "replaced";
    },
    fetchImpl: async (url) => {
      if (url.endsWith("/move")) {
        return { ok: false, status: 500, text: async () => "" };
      }
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, 1);
  assert.equal(result.failed, 0);
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs.some((line) => line.includes("reason=rejected")), true);
  assert.equal(logs.some((line) => line.includes("keep-me")), false);
});

test("a bad bot receipt from sync does not update the locator", async () => {
  const record = stagedRecord();
  assert.equal(record.kind, "manifest");
  const manifest = record.manifest;
  const { crypto, publicKeyHex } = ed25519();
  const good = buildReceipt(
    {
      op: "move",
      itemId: manifest.itemId,
      itemVersion: manifest.version,
      contentSha256: manifest.contentSha256,
      fromLocator: "phone",
      toLocator: INTENTDB_BOT_TIER_LOCATOR,
      botId: INTENTDB_BOT_ID,
      issuedAt: manifest.version + 10,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
    },
    crypto,
  );
  const flipped: MovementReceipt = {
    ...good,
    signature: good.signature.slice(0, -1) + (good.signature.endsWith("a") ? "b" : "a"),
  };
  const local = { locator: "phone", secret: "keep-me", outbox: [record] };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    botMove: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: local.outbox,
    apiBaseUrl: "https://items.example",
    receiptPublicKey: publicKeyHex,
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = INTENTDB_BOT_TIER_LOCATOR;
      local.secret = "replaced";
    },
    fetchImpl: async (url) => {
      if (url.endsWith("/move")) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify(moveResponse(flipped, manifest)),
        };
      }
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, 1);
  assert.equal(result.failed, 0);
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs.some((line) => line.includes("reason=bad-signature")), true);
  assert.equal(logs.some((line) => line.includes(good.signature)), false);
});

test("the verify flag default does not check a receipt", async () => {
  const previous = process.env.EXPO_PUBLIC_INTENTDB_VERIFY;
  delete process.env.EXPO_PUBLIC_INTENTDB_VERIFY;
  const record = stagedRecord();
  const local = { locator: "phone", secret: "keep-me", outbox: [record] };
  const snapshot = JSON.stringify(local);
  let checks = 0;
  try {
    const result = await syncIntentdbOutbox({
      unlocked: true,
      enabled: true,
      sessionToken: "ab".repeat(32),
      vaultKeyProof: "cd".repeat(32),
      records: local.outbox,
      apiBaseUrl: "https://items.example",
      verifyItem: async () => {
        checks += 1;
        throw new Error("verify must not run");
      },
      fetchImpl: async (_url, init) => {
        if (init.method === "GET") checks += 1;
        return { ok: true, status: 200, text: async () => "" };
      },
    });
    assert.equal(result.uploaded, 1);
    assert.equal(result.failed, 0);
    assert.equal(checks, 0);
    assert.equal(JSON.stringify(local), snapshot);
  } finally {
    if (previous === undefined) delete process.env.EXPO_PUBLIC_INTENTDB_VERIFY;
    else process.env.EXPO_PUBLIC_INTENTDB_VERIFY = previous;
  }
});

test("a verifier failure after upload does not change the outbox or the failure count", async () => {
  const record = stagedRecord();
  const local = { locator: "phone", secret: "keep-me", outbox: [record] };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    verify: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: local.outbox,
    log: (message) => logs.push(message),
    upload: async () => ({
      uploaded: true,
      itemId: record.kind === "manifest" ? record.manifest.itemId : "",
      contentSha256: "ab".repeat(32),
    }),
    verifyItem: async () => {
      throw new Error("SECRET-VERIFY-ERROR");
    },
  });
  assert.equal(result.uploaded, 1);
  assert.equal(result.failed, 0);
  assert.equal(JSON.stringify(local), snapshot);
  assert.equal(logs.some((line) => line.includes("reason=network")), true);
  assert.equal(logs.some((line) => line.includes("SECRET-VERIFY-ERROR")), false);
  assert.equal(logs.some((line) => line.includes("keep-me")), false);
});

test("sync logs a receipt mismatch and leaves the phone item in place", async () => {
  const record = stagedRecord();
  assert.equal(record.kind, "manifest");
  const manifest = record.manifest;
  const { crypto, publicKeyHex } = ed25519();
  const receipt = buildReceipt(
    {
      op: "put",
      itemId: manifest.itemId,
      itemVersion: manifest.version,
      contentSha256: manifest.contentSha256,
      fromLocator: "client",
      toLocator: "phone",
      botId: "pipass-server",
      issuedAt: manifest.version + 5,
      prevReceiptHash: GENESIS_RECEIPT_HASH,
    },
    crypto,
  );
  const local = { locator: "phone", secret: "keep-me", outbox: [record] };
  const snapshot = JSON.stringify(local);
  const logs: string[] = [];
  const calls: string[] = [];
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    verify: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: local.outbox,
    apiBaseUrl: "https://items.example",
    receiptPublicKey: publicKeyHex,
    log: (message) => logs.push(message),
    applyLocator: () => {
      local.locator = "tier-1";
      local.secret = "replaced";
    },
    fetchImpl: async (url, init) => {
      calls.push(`${init.method} ${url}`);
      if (init.method === "GET") {
        return {
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              itemId: manifest.itemId,
              version: manifest.version,
              contentSha256: "cd".repeat(32),
              tombstone: false,
              fields: [{ name: "password", ciphertext: "v4:SECRET-CIPHERTEXT" }],
              receipt,
              receiptPublicKey: "ff".repeat(32),
            }),
        };
      }
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, 1);
  assert.equal(result.failed, 0);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].startsWith("PUT "), true);
  assert.equal(calls[0].includes("/api/vault/items"), true);
  assert.equal(calls[1].startsWith("GET "), true);
  assert.equal(JSON.stringify(local), snapshot);
  const audit = logs.find((line) => line.startsWith("intentdb verifier audit "));
  assert.equal(audit, `intentdb verifier audit itemId=${manifest.itemId} op=put reason=hash-mismatch`);
  const joined = logs.join("\n");
  assert.equal(joined.includes(receipt.signature), false);
  assert.equal(joined.includes("v4:SECRET-CIPHERTEXT"), false);
  assert.equal(joined.includes("ff".repeat(32)), false);
  assert.equal(joined.includes("cd".repeat(32)), false);
  assert.equal(joined.includes("keep-me"), false);
});

test("a tombstone upload does not run the verifier", async () => {
  let checks = 0;
  const record: OutboxRecord = {
    kind: "tombstone",
    enqueuedAt: 9,
    tombstone: {
      schema: "pipass-tombstone-v1",
      itemId: "deleted-note-1",
      kind: "vault-entry",
      itemVersion: 1_700_000_000_000,
      contentSha256: "ab".repeat(32),
      contentBound: true,
      deletedAt: 1_700_000_000_123,
    },
  };
  const result = await syncIntentdbOutbox({
    unlocked: true,
    enabled: true,
    verify: true,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: "cd".repeat(32),
    records: [record],
    upload: async () => ({
      uploaded: true,
      itemId: record.tombstone.itemId,
      contentSha256: record.tombstone.contentSha256,
    }),
    verifyItem: async () => {
      checks += 1;
      return { verified: false, reason: "hash-mismatch" };
    },
  });
  assert.equal(checks, 0);
  assert.equal(result.uploaded, 1);
  assert.equal(result.failed, 0);
});
