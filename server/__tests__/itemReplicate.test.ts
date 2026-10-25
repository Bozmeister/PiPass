/**
 * Replica receipt. The item locator stays. The receipt op is copy.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/itemReplicate.test.ts
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createVaultKeyProof } from "../../crypto/vaultKeyProof";
import { buildVaultEntryManifest } from "../../lib/intentdb/itemManifest";
import {
  INTENTDB_BOT_ID,
  INTENTDB_BOT_REPLICA_LOCATOR,
  proposeIntentBotReplicate,
} from "../../lib/intentdb/intentBot";
import { receiptChainHash, type MovementReceipt } from "../../lib/intentdb/receipt";
import { verifyFetchedItemReceipt } from "../../lib/intentdb/verifyItemReceipt";
import type { VaultEntry } from "../../workers/vaultWorker";
import { getItemReceiptPublicKey } from "../itemReceipt";
import { registerRoutes } from "../routes";
import { DatabaseStorage } from "../storage";

const storage = new DatabaseStorage();
let server: Server;
let baseUrl: string;

before(async () => {
  const app = express();
  app.set("trust proxy", true);
  server = await registerRoutes(app, storage);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function uniqueUsername(): string {
  return `rep_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
}

function hex64(seed: string): string {
  return createHash("sha256").update(seed).update(randomBytes(16)).digest("hex");
}

function randomIp(): string {
  return `10.${randomBytes(1)[0]}.${randomBytes(1)[0]}.${randomBytes(1)[0]}`;
}

function v4(label: string): string {
  return `v4:${randomBytes(12).toString("hex")}:${createHash("sha256").update(label).digest("hex")}:${randomBytes(16).toString("hex")}`;
}

function testVaultKeyProof(userId: string): string {
  const masterKey = createHash("sha256").update(`test-mk:${userId}`).digest("hex");
  return createVaultKeyProof(masterKey, userId);
}

type Registered = { userId: string; username: string; authHash: string };

async function registerUser(): Promise<Registered> {
  const username = uniqueUsername();
  const authHash = hex64("ah");
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": randomIp() },
    body: JSON.stringify({
      username,
      authHash,
      salt: hex64("salt"),
      iterations: 100_000,
    }),
  });
  const text = await res.text();
  assert.equal(res.status, 201, text);
  return { userId: (JSON.parse(text) as { id: string }).id, username, authHash };
}

async function bindVaultProof(user: Registered): Promise<void> {
  const blob = `${hex64("iv").slice(0, 32)}:${hex64("cipher")}:${hex64("mac")}`;
  const res = await fetch(`${baseUrl}/api/vault/sync`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-user-id": user.userId,
      "x-auth-hash": user.authHash,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({
      encryptedBlob: blob,
      expectedPrevVersion: 0,
      vaultKeyProof: testVaultKeyProof(user.userId),
    }),
  });
  const text = await res.text();
  assert.equal(res.status, 200, text);
}

async function login(user: Registered): Promise<string> {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": randomIp() },
    body: JSON.stringify({ username: user.username, authHash: user.authHash }),
  });
  const text = await res.text();
  assert.equal(res.status, 200, text);
  return (JSON.parse(text) as { sessionToken: string }).sessionToken;
}

function entryWithNotes(itemId: string): { entry: VaultEntry; notes: string } {
  const notes = v4(`notes:${itemId}`);
  const updatedAt = 1_700_000_000_000;
  const entry: VaultEntry = {
    id: itemId,
    title: "PLAINTEXT_TITLE_SENTINEL",
    username: "PLAINTEXT_USER_SENTINEL",
    encryptedPassword: v4(`password:${itemId}`),
    encryptedTitle: v4(`title:${itemId}`),
    encryptedUsername: v4(`username:${itemId}`),
    notes,
    salt: "ab".repeat(16),
    createdAt: updatedAt - 1000,
    updatedAt,
  };
  return { entry, notes };
}

function putBody(manifest: ReturnType<typeof buildVaultEntryManifest>, userId: string) {
  return {
    schema: manifest.schema,
    itemId: manifest.itemId,
    kind: manifest.kind,
    version: manifest.version,
    salt: manifest.salt,
    createdAt: manifest.createdAt,
    updatedAt: manifest.updatedAt,
    fields: manifest.fields.map((field) => ({ ...field })),
    contentSha256: manifest.contentSha256,
    locator: "phone",
    tombstone: false,
    vaultKeyProof: testVaultKeyProof(userId),
  };
}

async function putItem(sessionToken: string, body: object) {
  const res = await fetch(`${baseUrl}/api/vault/items`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text, json: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

async function getItem(sessionToken: string, itemId: string) {
  const res = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}`, {
    headers: { "x-session-token": sessionToken, "x-forwarded-for": randomIp() },
  });
  const text = await res.text();
  return { status: res.status, text, json: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

function asReceipt(value: unknown): MovementReceipt {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  return value as MovementReceipt;
}

function notesCiphertext(body: Record<string, unknown>): string | undefined {
  const fields = body.fields as { name?: string; ciphertext?: string }[] | undefined;
  return fields?.find((field) => field.name === "notes")?.ciphertext;
}

test("a replicate stores a chained copy receipt and keeps the original locator", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const before = await storage.getVaultBlob(user.userId);
  const sessionToken = await login(user);
  const itemId = "replica-item-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, created.text);
  const putReceipt = asReceipt(created.json.receipt);

  const same = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}/replicate`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({
      newLocator: "phone",
      vaultKeyProof: testVaultKeyProof(user.userId),
      botId: INTENTDB_BOT_ID,
    }),
  });
  const sameText = await same.text();
  assert.equal(same.status, 400, sameText);
  assert.equal((JSON.parse(sameText) as { error?: string }).error, "Invalid locator");

  const local = { locators: ["phone"], secret: "keep-me" };
  const proposed = await proposeIntentBotReplicate({
    itemId,
    fromLocator: "phone",
    toLocator: INTENTDB_BOT_REPLICA_LOCATOR,
    version: manifest.version,
    contentSha256: manifest.contentSha256,
    sessionToken,
    vaultKeyProof: testVaultKeyProof(user.userId),
    unlocked: true,
    enabled: true,
    publicKeyHex: getItemReceiptPublicKey(),
    apiBaseUrl: baseUrl,
    applyLocators: (update) => {
      local.locators = update.locators;
    },
  });
  assert.equal(proposed.proposed, true, JSON.stringify(proposed));
  if (proposed.proposed) {
    assert.deepEqual(proposed.locators, ["phone", INTENTDB_BOT_REPLICA_LOCATOR]);
    assert.equal(proposed.botId, INTENTDB_BOT_ID);
  }
  assert.deepEqual(local.locators, ["phone", INTENTDB_BOT_REPLICA_LOCATOR]);
  assert.equal(local.secret, "keep-me");

  const fetched = await getItem(sessionToken, itemId);
  assert.equal(fetched.status, 200, fetched.text);
  const copyReceipt = asReceipt(fetched.json.receipt);
  assert.equal(copyReceipt.op, "copy");
  assert.equal(copyReceipt.botId, INTENTDB_BOT_ID);
  assert.equal(copyReceipt.fromLocator, "phone");
  assert.equal(copyReceipt.toLocator, INTENTDB_BOT_REPLICA_LOCATOR);
  assert.equal(copyReceipt.itemVersion, manifest.version);
  assert.equal(copyReceipt.contentSha256, manifest.contentSha256);
  assert.equal(copyReceipt.prevReceiptHash, receiptChainHash(putReceipt));
  assert.equal(fetched.json.locator, "phone");
  assert.equal(fetched.json.contentSha256, manifest.contentSha256);
  assert.equal(fetched.json.version, manifest.version);
  assert.equal(notesCiphertext(fetched.json), notes);
  assert.equal(fetched.text.includes("PLAINTEXT_TITLE_SENTINEL"), false);

  const tampered = { locators: ["phone", INTENTDB_BOT_REPLICA_LOCATOR], secret: "stay" };
  const flipped: MovementReceipt = {
    ...copyReceipt,
    signature: copyReceipt.signature.slice(0, -1) + (copyReceipt.signature.endsWith("a") ? "b" : "a"),
  };
  const logs: string[] = [];
  const rejectedSig = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: manifest.contentSha256,
      tombstone: false,
    },
    receipt: flipped,
    publicKeyHex: getItemReceiptPublicKey(),
    log: (message) => logs.push(message),
    commit: () => {
      tampered.locators = ["stolen"];
      tampered.secret = "replaced";
    },
  });
  assert.equal(rejectedSig.accepted, false);
  if (!rejectedSig.accepted) assert.equal(rejectedSig.reason, "bad-signature");
  assert.deepEqual(tampered.locators, ["phone", INTENTDB_BOT_REPLICA_LOCATOR]);
  assert.equal(tampered.secret, "stay");
  assert.equal(logs[0].includes("reason=bad-signature"), true);

  const hashLocal = { secret: "stay" };
  const hashLogs: string[] = [];
  const rejectedHash = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: "ef".repeat(32),
      tombstone: false,
    },
    receipt: copyReceipt,
    publicKeyHex: getItemReceiptPublicKey(),
    log: (message) => hashLogs.push(message),
    commit: () => {
      hashLocal.secret = "replaced";
    },
  });
  assert.equal(rejectedHash.accepted, false);
  if (!rejectedHash.accepted) assert.equal(rejectedHash.reason, "hash-mismatch");
  assert.equal(hashLocal.secret, "stay");

  const after = await storage.getVaultBlob(user.userId);
  assert.equal(after?.encryptedBlob, before?.encryptedBlob);
  assert.equal(after?.version, before?.version);
  assert.equal(after?.keyVerifier, before?.keyVerifier);
});
