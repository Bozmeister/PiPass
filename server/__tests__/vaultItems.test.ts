// Opaque item store: session + vaultKeyProof writes, hash check, notes kept.
//
// Run:
//   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/vaultItems.test.ts

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createVaultKeyProof } from "../../crypto/vaultKeyProof";
import { buildVaultEntryManifest } from "../../lib/intentdb/itemManifest";
import type { VaultEntry } from "../../workers/vaultWorker";
import { registerRoutes } from "../routes";
import { DatabaseStorage } from "../storage";

const storage = new DatabaseStorage();
let server: Server;
let baseUrl: string;

before(async () => {
  const app = express();
  app.set("trust proxy", true);
  server = await registerRoutes(app, storage);
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function uniqueUsername(): string {
  return `item_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
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

type Registered = {
  userId: string;
  username: string;
  authHash: string;
};

async function registerUser(): Promise<Registered> {
  const username = uniqueUsername();
  const authHash = hex64("ah");
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({
      username,
      authHash,
      salt: hex64("salt"),
      iterations: 100_000,
    }),
  });
  const text = await res.text();
  assert.equal(res.status, 201, text);
  const body = JSON.parse(text) as { id: string };
  return { userId: body.id, username, authHash };
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
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({ username: user.username, authHash: user.authHash }),
  });
  const text = await res.text();
  assert.equal(res.status, 200, text);
  const body = JSON.parse(text) as { sessionToken?: string };
  assert.equal(typeof body.sessionToken, "string");
  return body.sessionToken as string;
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
    encryptedUrl: v4(`url:${itemId}`),
    notes,
    encryptedAux: v4(`aux:${itemId}`),
    salt: "ab".repeat(16),
    createdAt: updatedAt - 1000,
    updatedAt,
  };
  return { entry, notes };
}

function putBody(
  manifest: ReturnType<typeof buildVaultEntryManifest>,
  userId: string,
  tombstone = false,
) {
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
    tombstone,
    vaultKeyProof: testVaultKeyProof(userId),
  };
}

async function putItem(
  sessionToken: string,
  body: object,
): Promise<{ status: number; json: Record<string, unknown> }> {
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
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}

async function getItem(
  sessionToken: string,
  itemId: string,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}`, {
    headers: {
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
    },
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}

function notesCiphertext(body: Record<string, unknown>): string | undefined {
  const fields = body.fields as { name?: string; ciphertext?: string }[] | undefined;
  return fields?.find((field) => field.name === "notes")?.ciphertext;
}

test("put and get round-trip a manifest and keep notes ciphertext", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const before = await storage.getVaultBlob(user.userId);
  const sessionToken = await login(user);
  const { entry, notes } = entryWithNotes("item-notes-1");
  const manifest = buildVaultEntryManifest(entry);

  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, JSON.stringify(created.json));
  assert.equal(notesCiphertext(created.json), notes);
  assert.equal(created.json.tombstone, false);
  assert.equal(created.json.contentSha256, manifest.contentSha256);
  assert.equal("vaultKeyProof" in created.json, false);
  assert.equal("userId" in created.json, false);
  assert.equal(JSON.stringify(created.json).includes("PLAINTEXT_TITLE_SENTINEL"), false);
  assert.equal(JSON.stringify(created.json).includes("PLAINTEXT_USER_SENTINEL"), false);

  const fetched = await getItem(sessionToken, manifest.itemId);
  assert.equal(fetched.status, 200, JSON.stringify(fetched.json));
  assert.equal(notesCiphertext(fetched.json), notes);
  assert.equal(fetched.json.schema, "pipass-item-v1");
  assert.equal(fetched.json.kind, "vault-entry");
  assert.equal(fetched.json.locator, "phone");

  const again = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(again.status, 200, JSON.stringify(again.json));

  const marked = await putItem(sessionToken, putBody(manifest, user.userId, true));
  assert.equal(marked.status, 200, JSON.stringify(marked.json));
  assert.equal(marked.json.tombstone, true);
  assert.equal(notesCiphertext(marked.json), notes);

  const after = await storage.getVaultBlob(user.userId);
  assert.equal(after?.encryptedBlob, before?.encryptedBlob);
  assert.equal(after?.version, before?.version);
  assert.equal(after?.keyVerifier, before?.keyVerifier);
});

test("rejects a content hash that does not match the manifest", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const { entry } = entryWithNotes("item-mismatch-1");
  const manifest = buildVaultEntryManifest(entry);
  const body = putBody(manifest, user.userId);
  const last = body.contentSha256.slice(-1);
  body.contentSha256 = `${body.contentSha256.slice(0, -1)}${last === "0" ? "1" : "0"}`;

  const rejected = await putItem(sessionToken, body);
  assert.equal(rejected.status, 400, JSON.stringify(rejected.json));
  assert.equal(rejected.json.error, "Hash mismatch");

  const fetched = await getItem(sessionToken, manifest.itemId);
  assert.equal(fetched.status, 404);

  const stored = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(stored.status, 200, JSON.stringify(stored.json));
  const tamperedFields = putBody(manifest, user.userId);
  const notesField = tamperedFields.fields.find((field) => field.name === "notes");
  assert.ok(notesField);
  notesField.ciphertext = `${notesField.ciphertext.slice(0, -1)}${notesField.ciphertext.endsWith("a") ? "b" : "a"}`;
  const rejectedField = await putItem(sessionToken, tamperedFields);
  assert.equal(rejectedField.status, 400, JSON.stringify(rejectedField.json));
  assert.equal(rejectedField.json.error, "Hash mismatch");
  const still = await getItem(sessionToken, manifest.itemId);
  assert.equal(still.status, 200);
  assert.equal(notesCiphertext(still.json), manifest.fields.find((field) => field.name === "notes")?.ciphertext);
});

test("does not accept the long-lived auth hash as an item write credential", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const { entry } = entryWithNotes("item-authhash-1");
  const manifest = buildVaultEntryManifest(entry);
  for (const authHash of [user.authHash, "ab".repeat(32)]) {
    const res = await fetch(`${baseUrl}/api/vault/items`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "x-user-id": user.userId,
        "x-auth-hash": authHash,
        "x-forwarded-for": randomIp(),
      },
      body: JSON.stringify(putBody(manifest, user.userId)),
    });
    const text = await res.text();
    assert.equal(res.status, 400, text);
    assert.equal(JSON.parse(text).error, "Invalid authentication headers");
  }

  const sessionToken = await login(user);
  const fetched = await getItem(sessionToken, manifest.itemId);
  assert.equal(fetched.status, 404);

  const other = await registerUser();
  await bindVaultProof(other);
  const otherSession = await login(other);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, JSON.stringify(created.json));
  const hidden = await getItem(otherSession, manifest.itemId);
  assert.equal(hidden.status, 404);
});

test("rejects a vault key proof that does not match the bound verifier", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const { entry } = entryWithNotes("item-proof-1");
  const manifest = buildVaultEntryManifest(entry);
  const body = putBody(manifest, user.userId);
  body.vaultKeyProof = "ab".repeat(32);
  const rejected = await putItem(sessionToken, body);
  assert.equal(rejected.status, 403, JSON.stringify(rejected.json));
  assert.equal(rejected.json.error, "Invalid vault key proof");
  const fetched = await getItem(sessionToken, manifest.itemId);
  assert.equal(fetched.status, 404);
});
