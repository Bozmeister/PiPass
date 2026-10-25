/**
 * Locator move: chained receipt, client accept, tombstone rejection.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/itemMove.test.ts
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createVaultKeyProof } from "../../crypto/vaultKeyProof";
import { buildVaultEntryManifest } from "../../lib/intentdb/itemManifest";
import { requestItemLocatorMove } from "../../lib/intentdb/moveItem";
import { receiptChainHash, type MovementReceipt } from "../../lib/intentdb/receipt";
import { tombstoneDocumentSha256 } from "../../lib/intentdb/tombstone";
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
  return `mv_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
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

async function moveItem(
  sessionToken: string,
  itemId: string,
  body: object,
  headers: Record<string, string> = {},
) {
  const res = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}/move`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": randomIp(),
      ...headers,
    },
    body: JSON.stringify(body),
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

test("a move returns a chained receipt and the client applies only the locator", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const before = await storage.getVaultBlob(user.userId);
  const sessionToken = await login(user);
  const itemId = "move-item-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, created.text);
  const putReceipt = asReceipt(created.json.receipt);

  const local = { locator: "phone", secret: "keep-me" };
  const moved = await requestItemLocatorMove({
    itemId,
    newLocator: "desktop",
    version: manifest.version,
    contentSha256: manifest.contentSha256,
    sessionToken,
    vaultKeyProof: testVaultKeyProof(user.userId),
    publicKeyHex: getItemReceiptPublicKey(),
    enabled: true,
    apiBaseUrl: baseUrl,
    applyLocator: (update) => {
      local.locator = update.locator;
    },
  });
  assert.equal(moved.moved, true, JSON.stringify(moved));
  assert.equal(local.locator, "desktop");
  assert.equal(local.secret, "keep-me");

  const fetched = await getItem(sessionToken, itemId);
  assert.equal(fetched.status, 200, fetched.text);
  const moveReceipt = asReceipt(fetched.json.receipt);
  assert.equal(moveReceipt.op, "move");
  assert.equal(moveReceipt.itemId, itemId);
  assert.equal(moveReceipt.itemVersion, manifest.version);
  assert.equal(moveReceipt.contentSha256, manifest.contentSha256);
  assert.equal(moveReceipt.fromLocator, "phone");
  assert.equal(moveReceipt.toLocator, "desktop");
  assert.equal(moveReceipt.prevReceiptHash, receiptChainHash(putReceipt));
  assert.equal(fetched.json.locator, "desktop");
  assert.equal(fetched.json.contentSha256, manifest.contentSha256);
  assert.equal(fetched.json.version, manifest.version);
  assert.equal(fetched.json.schema, "pipass-item-v1");
  assert.equal(fetched.json.tombstone, false);
  assert.equal(notesCiphertext(fetched.json), notes);
  assert.equal(fetched.text.includes("PLAINTEXT_TITLE_SENTINEL"), false);
  assert.equal("canonical" in moveReceipt, false);
  assert.equal(fetched.text.includes("INTENTDB_RECEIPT_SIGNING_SEED"), false);

  const accepted = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: manifest.contentSha256,
      tombstone: false,
    },
    receipt: moveReceipt,
    publicKeyHex: getItemReceiptPublicKey(),
  });
  assert.equal(accepted.accepted, true);

  const tamperedLocal = { locator: "desktop", secret: "stay" };
  const flipped: MovementReceipt = {
    ...moveReceipt,
    signature: moveReceipt.signature.slice(0, -1) + (moveReceipt.signature.endsWith("a") ? "b" : "a"),
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
      tamperedLocal.locator = "stolen";
      tamperedLocal.secret = "replaced";
    },
  });
  assert.equal(rejectedSig.accepted, false);
  if (!rejectedSig.accepted) assert.equal(rejectedSig.reason, "bad-signature");
  assert.equal(tamperedLocal.locator, "desktop");
  assert.equal(tamperedLocal.secret, "stay");
  assert.equal(logs[0].includes("reason=bad-signature"), true);

  const hashLocal = { locator: "desktop", secret: "stay" };
  const hashLogs: string[] = [];
  const rejectedHash = verifyFetchedItemReceipt({
    item: {
      itemId,
      version: manifest.version,
      contentSha256: "ef".repeat(32),
      tombstone: false,
    },
    receipt: moveReceipt,
    publicKeyHex: getItemReceiptPublicKey(),
    log: (message) => hashLogs.push(message),
    commit: () => {
      hashLocal.secret = "replaced";
    },
  });
  assert.equal(rejectedHash.accepted, false);
  if (!rejectedHash.accepted) assert.equal(rejectedHash.reason, "hash-mismatch");
  assert.equal(hashLocal.secret, "stay");
  assert.equal(hashLogs[0].includes("reason=hash-mismatch"), true);

  const again = await moveItem(sessionToken, itemId, {
    newLocator: "laptop",
    vaultKeyProof: testVaultKeyProof(user.userId),
  }, { "x-session-token": sessionToken });
  assert.equal(again.status, 200, again.text);
  const chained = asReceipt(again.json.receipt);
  assert.equal(chained.op, "move");
  assert.equal(chained.fromLocator, "desktop");
  assert.equal(chained.toLocator, "laptop");
  assert.equal(chained.contentSha256, manifest.contentSha256);
  assert.equal(chained.prevReceiptHash, receiptChainHash(moveReceipt));
  assert.equal(again.json.locator, "laptop");
  assert.equal(notesCiphertext(again.json), notes);

  const after = await storage.getVaultBlob(user.userId);
  assert.equal(after?.encryptedBlob, before?.encryptedBlob);
  assert.equal(after?.version, before?.version);
  assert.equal(after?.keyVerifier, before?.keyVerifier);
});

test("a tombstone cannot be moved and the vault blob stays", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const before = await storage.getVaultBlob(user.userId);
  const sessionToken = await login(user);
  const itemId = "move-tomb-1";
  const { entry } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, created.text);
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

  const rejected = await moveItem(sessionToken, itemId, {
    newLocator: "desktop",
    vaultKeyProof: testVaultKeyProof(user.userId),
  }, { "x-session-token": sessionToken });
  assert.equal(rejected.status, 409, rejected.text);
  assert.equal(rejected.json.error, "Item is a tombstone");

  const fetched = await getItem(sessionToken, itemId);
  assert.equal(fetched.status, 200, fetched.text);
  assert.equal(fetched.json.locator, "");
  assert.equal(fetched.json.tombstone, true);
  assert.equal(asReceipt(fetched.json.receipt).op, "delete");
  assert.equal(fetched.json.contentSha256, manifest.contentSha256);

  const after = await storage.getVaultBlob(user.userId);
  assert.equal(after?.encryptedBlob, before?.encryptedBlob);
  assert.equal(after?.version, before?.version);
  assert.equal(after?.keyVerifier, before?.keyVerifier);
});

test("move rejects an empty locator, a missing session, and a bad proof", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const itemId = "move-reject-1";
  const { entry } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, created.text);

  const empty = await moveItem(sessionToken, itemId, {
    newLocator: "",
    vaultKeyProof: testVaultKeyProof(user.userId),
  }, { "x-session-token": sessionToken });
  assert.equal(empty.status, 400, empty.text);
  assert.equal(empty.json.error, "Invalid locator");

  const tombLocator = await moveItem(sessionToken, itemId, {
    newLocator: "tombstone",
    vaultKeyProof: testVaultKeyProof(user.userId),
  }, { "x-session-token": sessionToken });
  assert.equal(tombLocator.status, 400, tombLocator.text);
  assert.equal(tombLocator.json.error, "Invalid locator");

  for (const authHash of [user.authHash, "ab".repeat(32)]) {
    const res = await moveItem(sessionToken, itemId, {
      newLocator: "desktop",
      vaultKeyProof: testVaultKeyProof(user.userId),
    }, {
      "x-user-id": user.userId,
      "x-auth-hash": authHash,
    });
    assert.equal(res.status, 400, res.text);
    assert.equal(res.json.error, "Invalid authentication headers");
  }

  const badProof = await moveItem(sessionToken, itemId, {
    newLocator: "desktop",
    vaultKeyProof: "ab".repeat(32),
  }, { "x-session-token": sessionToken });
  assert.equal(badProof.status, 403, badProof.text);
  assert.equal(badProof.json.error, "Invalid vault key proof");

  const missing = await moveItem(sessionToken, "missing-move-item", {
    newLocator: "desktop",
    vaultKeyProof: testVaultKeyProof(user.userId),
  }, { "x-session-token": sessionToken });
  assert.equal(missing.status, 404, missing.text);

  const fetched = await getItem(sessionToken, itemId);
  assert.equal(fetched.status, 200, fetched.text);
  assert.equal(fetched.json.locator, "phone");
  assert.equal(asReceipt(fetched.json.receipt).op, "put");
  assert.equal(fetched.json.contentSha256, manifest.contentSha256);
});
