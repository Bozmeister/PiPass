/**
 * Server-signed item receipts returned on put and get.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/itemReceipt.test.ts
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createVaultKeyProof } from "../../crypto/vaultKeyProof";
import { buildVaultEntryManifest } from "../../lib/intentdb/itemManifest";
import { tombstoneDocumentSha256 } from "../../lib/intentdb/tombstone";
import {
  GENESIS_RECEIPT_HASH,
  TOMBSTONE_LOCATOR,
  canonicalReceiptBody,
  receiptChainHash,
  type MovementReceipt,
} from "../../lib/intentdb/receipt";
import { verifyFetchedItemReceipt } from "../../lib/intentdb/verifyItemReceipt";
import type { VaultEntry } from "../../workers/vaultWorker";
import {
  ITEM_RECEIPT_BOT_ID,
  ITEM_RECEIPT_CLIENT_LOCATOR,
  ITEM_RECEIPT_GENESIS_HASH,
  ITEM_RECEIPT_TOMBSTONE_LOCATOR,
  canonicalItemReceiptBody,
  getItemReceiptPublicKey,
  itemReceiptChainHash,
} from "../itemReceipt";
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
  return `rcpt_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
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

async function bindVaultProof(user: Registered): Promise<string> {
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
  return blob;
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

test("server canonical receipt bytes match the client receipt module", () => {
  const body = {
    v: 1 as const,
    op: "put" as const,
    itemId: "item-1",
    itemVersion: 20,
    contentSha256: "ab".repeat(32),
    fromLocator: "client",
    toLocator: "phone",
    botId: "pipass-server",
    issuedAt: 1_700_000_000_100,
    prevReceiptHash: GENESIS_RECEIPT_HASH,
  };
  assert.equal(ITEM_RECEIPT_GENESIS_HASH, GENESIS_RECEIPT_HASH);
  assert.equal(ITEM_RECEIPT_TOMBSTONE_LOCATOR, TOMBSTONE_LOCATOR);
  const canonical = canonicalItemReceiptBody(body);
  assert.equal(canonical, canonicalReceiptBody(body));
  const signature = "cd".repeat(64);
  assert.equal(
    itemReceiptChainHash({ canonical, sigAlg: "ed25519", signature }),
    receiptChainHash({ ...body, sigAlg: "ed25519", signature }),
  );
});

test("put and get store a signed receipt and a later tombstone chains from it", async () => {
  const user = await registerUser();
  const blob = await bindVaultProof(user);
  const before = await storage.getVaultBlob(user.userId);
  const sessionToken = await login(user);
  const itemId = "receipt-item-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, created.text);
  const putReceipt = asReceipt(created.json.receipt);
  assert.equal(putReceipt.op, "put");
  assert.equal(putReceipt.itemId, itemId);
  assert.equal(putReceipt.itemVersion, manifest.version);
  assert.equal(putReceipt.contentSha256, manifest.contentSha256);
  assert.equal(putReceipt.fromLocator, ITEM_RECEIPT_CLIENT_LOCATOR);
  assert.equal(putReceipt.toLocator, "phone");
  assert.equal(putReceipt.botId, ITEM_RECEIPT_BOT_ID);
  assert.equal(putReceipt.prevReceiptHash, GENESIS_RECEIPT_HASH);
  assert.equal(putReceipt.sigAlg, "ed25519");
  assert.equal(created.json.receiptPublicKey, getItemReceiptPublicKey());
  assert.equal(notesCiphertext(created.json), notes);
  assert.equal(created.text.includes("PLAINTEXT_TITLE_SENTINEL"), false);
  assert.equal("canonical" in putReceipt, false);
  assert.equal("privateKey" in (created.json as object), false);
  assert.equal(created.text.includes("INTENTDB_RECEIPT_SIGNING_SEED"), false);

  const local = { blob, entries: [{ id: itemId, secret: "phone-copy" }] };
  const adopted: string[] = [];
  const decision = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: manifest.contentSha256,
      tombstone: false,
    },
    receipt: putReceipt,
    publicKeyHex: getItemReceiptPublicKey(),
    commit: () => adopted.push(itemId),
  });
  assert.equal(decision.accepted, true);
  assert.deepEqual(adopted, [itemId]);
  assert.equal(local.entries[0].secret, "phone-copy");

  const fetched = await getItem(sessionToken, itemId);
  assert.equal(fetched.status, 200, fetched.text);
  assert.deepEqual(fetched.json.receipt, created.json.receipt);
  assert.equal(notesCiphertext(fetched.json), notes);

  const again = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(again.status, 200, again.text);
  const chained = asReceipt(again.json.receipt);
  assert.equal(chained.prevReceiptHash, receiptChainHash(putReceipt));
  assert.equal(chained.contentSha256, manifest.contentSha256);
  const chainedOk = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: manifest.contentSha256,
      tombstone: false,
    },
    receipt: chained,
    publicKeyHex: getItemReceiptPublicKey(),
  });
  assert.equal(chainedOk.accepted, true);

  const document = {
    schema: "pipass-tombstone-v1" as const,
    itemId,
    kind: "vault-entry" as const,
    itemVersion: manifest.version,
    contentSha256: manifest.contentSha256,
    contentBound: true,
    deletedAt: manifest.version + 5,
  };
  const tombstoneRes = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}/tombstone`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({
      ...document,
      tombstoneSha256: tombstoneDocumentSha256(document),
      vaultKeyProof: testVaultKeyProof(user.userId),
    }),
  });
  const tombstoneText = await tombstoneRes.text();
  assert.equal(tombstoneRes.status, 200, tombstoneText);
  const tombstoneJson = JSON.parse(tombstoneText) as Record<string, unknown>;
  const deleteReceipt = asReceipt(tombstoneJson.receipt);
  assert.equal(deleteReceipt.op, "delete");
  assert.equal(deleteReceipt.toLocator, TOMBSTONE_LOCATOR);
  assert.equal(deleteReceipt.fromLocator, "phone");
  assert.equal(deleteReceipt.contentSha256, manifest.contentSha256);
  assert.equal(deleteReceipt.prevReceiptHash, receiptChainHash(chained));
  assert.equal(tombstoneJson.tombstone, true);
  assert.deepEqual(tombstoneJson.fields, []);
  assert.equal(tombstoneText.includes(notes), false);

  const afterDelete = await getItem(sessionToken, itemId);
  assert.equal(afterDelete.status, 200, afterDelete.text);
  assert.deepEqual(afterDelete.json.receipt, tombstoneJson.receipt);
  const deleteOk = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: manifest.contentSha256,
      tombstone: true,
    },
    receipt: deleteReceipt,
    publicKeyHex: getItemReceiptPublicKey(),
  });
  assert.equal(deleteOk.accepted, true);

  const mismatchLogs: string[] = [];
  const mismatchLocal = { secret: "stay" };
  const mismatch = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: "ef".repeat(32),
      tombstone: true,
    },
    receipt: deleteReceipt,
    publicKeyHex: getItemReceiptPublicKey(),
    log: (message) => mismatchLogs.push(message),
    commit: () => {
      mismatchLocal.secret = "replaced";
    },
  });
  assert.equal(mismatch.accepted, false);
  if (!mismatch.accepted) assert.equal(mismatch.reason, "hash-mismatch");
  assert.equal(mismatchLocal.secret, "stay");
  assert.equal(mismatchLogs[0].includes("reason=hash-mismatch"), true);

  const after = await storage.getVaultBlob(user.userId);
  assert.equal(after?.encryptedBlob, before?.encryptedBlob);
  assert.equal(after?.version, before?.version);
  assert.equal(after?.keyVerifier, before?.keyVerifier);
  assert.equal(blob.length > 0, true);
});

test("receipt signer source does not import the client vault", () => {
  const source = readFileSync("server/itemReceipt.ts", "utf8");
  assert.equal(source.includes("lib/intentdb"), false);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("decrypt"), false);
});
