// Tombstone item route: session + vaultKeyProof, canonical document hash.
//
// Run:
//   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/vaultItemTombstone.test.ts

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createVaultKeyProof } from "../../crypto/vaultKeyProof";
import { buildVaultEntryManifest } from "../../lib/intentdb/itemManifest";
import { tombstoneDocumentSha256 } from "../../lib/intentdb/tombstone";
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
  return `tomb_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
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

function manifestFor(itemId: string) {
  const notes = v4(`notes:${itemId}`);
  const updatedAt = 1_700_000_000_000;
  const entry: VaultEntry = {
    id: itemId,
    title: "PLAINTEXT_TITLE_SENTINEL",
    encryptedPassword: v4(`password:${itemId}`),
    encryptedTitle: v4(`title:${itemId}`),
    encryptedUsername: v4(`username:${itemId}`),
    notes,
    salt: "ab".repeat(16),
    createdAt: updatedAt - 1000,
    updatedAt,
  };
  return { manifest: buildVaultEntryManifest(entry), notes };
}

function putManifestBody(
  manifest: ReturnType<typeof buildVaultEntryManifest>,
  userId: string,
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
    tombstone: false,
    vaultKeyProof: testVaultKeyProof(userId),
  };
}

function tombstoneBody(
  manifest: ReturnType<typeof buildVaultEntryManifest>,
  userId: string,
  tombstoneSha256: string,
) {
  return {
    schema: "pipass-tombstone-v1" as const,
    itemId: manifest.itemId,
    kind: manifest.kind,
    itemVersion: manifest.version,
    contentSha256: manifest.contentSha256,
    contentBound: true,
    deletedAt: manifest.updatedAt + 50,
    tombstoneSha256,
    vaultKeyProof: testVaultKeyProof(userId),
  };
}

async function authed(
  method: string,
  path: string,
  sessionToken: string,
  body?: object,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}

test("put and get a content-bound tombstone and clear the body", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const before = await storage.getVaultBlob(user.userId);
  const sessionToken = await login(user);
  const { manifest, notes } = manifestFor("tomb-notes-1");
  const created = await authed(
    "PUT",
    "/api/vault/items",
    sessionToken,
    putManifestBody(manifest, user.userId),
  );
  assert.equal(created.status, 200, JSON.stringify(created.json));

  const document = {
    schema: "pipass-tombstone-v1" as const,
    itemId: manifest.itemId,
    kind: manifest.kind,
    itemVersion: manifest.version,
    contentSha256: manifest.contentSha256,
    contentBound: true,
    deletedAt: manifest.updatedAt + 50,
  };
  const marked = await authed(
    "PUT",
    `/api/vault/items/${manifest.itemId}/tombstone`,
    sessionToken,
    tombstoneBody(manifest, user.userId, tombstoneDocumentSha256(document)),
  );
  assert.equal(marked.status, 200, JSON.stringify(marked.json));
  assert.equal(marked.json.tombstone, true);
  assert.equal(marked.json.locator, "");
  assert.deepEqual(marked.json.fields, []);
  assert.equal(marked.json.schema, "pipass-tombstone-v1");
  assert.equal(marked.json.contentSha256, manifest.contentSha256);
  assert.equal(marked.json.createdAt, manifest.createdAt);
  assert.equal(JSON.stringify(marked.json).includes(notes), false);
  assert.equal("vaultKeyProof" in marked.json, false);

  const fetched = await authed(
    "GET",
    `/api/vault/items/${manifest.itemId}`,
    sessionToken,
  );
  assert.equal(fetched.status, 200, JSON.stringify(fetched.json));
  assert.equal(fetched.json.tombstone, true);
  assert.equal(fetched.json.locator, "");
  assert.deepEqual(fetched.json.fields, []);
  assert.equal(fetched.json.contentSha256, manifest.contentSha256);

  const after = await storage.getVaultBlob(user.userId);
  assert.equal(after?.encryptedBlob, before?.encryptedBlob);
  assert.equal(after?.version, before?.version);
  assert.equal(after?.keyVerifier, before?.keyVerifier);
});

test("rejects a tombstone document hash that does not match", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const { manifest, notes } = manifestFor("tomb-mismatch-1");
  const created = await authed(
    "PUT",
    "/api/vault/items",
    sessionToken,
    putManifestBody(manifest, user.userId),
  );
  assert.equal(created.status, 200, JSON.stringify(created.json));

  const document = {
    schema: "pipass-tombstone-v1" as const,
    itemId: manifest.itemId,
    kind: manifest.kind,
    itemVersion: manifest.version,
    contentSha256: manifest.contentSha256,
    contentBound: true,
    deletedAt: manifest.updatedAt + 50,
  };
  const hash = tombstoneDocumentSha256(document);
  const last = hash.slice(-1);
  const bad = `${hash.slice(0, -1)}${last === "0" ? "1" : "0"}`;
  const rejected = await authed(
    "PUT",
    `/api/vault/items/${manifest.itemId}/tombstone`,
    sessionToken,
    tombstoneBody(manifest, user.userId, bad),
  );
  assert.equal(rejected.status, 400, JSON.stringify(rejected.json));
  assert.equal(rejected.json.error, "Hash mismatch");

  const fetched = await authed(
    "GET",
    `/api/vault/items/${manifest.itemId}`,
    sessionToken,
  );
  assert.equal(fetched.status, 200, JSON.stringify(fetched.json));
  assert.equal(fetched.json.tombstone, false);
  const fields = fetched.json.fields as { name?: string; ciphertext?: string }[];
  assert.equal(fields.find((field) => field.name === "notes")?.ciphertext, notes);
});

test("does not accept the auth hash as a tombstone write credential", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const { manifest, notes } = manifestFor("tomb-auth-1");
  const created = await authed(
    "PUT",
    "/api/vault/items",
    sessionToken,
    putManifestBody(manifest, user.userId),
  );
  assert.equal(created.status, 200, JSON.stringify(created.json));
  const document = {
    schema: "pipass-tombstone-v1" as const,
    itemId: manifest.itemId,
    kind: manifest.kind,
    itemVersion: manifest.version,
    contentSha256: manifest.contentSha256,
    contentBound: true,
    deletedAt: manifest.updatedAt + 50,
  };
  const body = tombstoneBody(manifest, user.userId, tombstoneDocumentSha256(document));
  for (const authHash of [user.authHash, "ab".repeat(32)]) {
    const res = await fetch(`${baseUrl}/api/vault/items/${manifest.itemId}/tombstone`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "x-user-id": user.userId,
        "x-auth-hash": authHash,
        "x-forwarded-for": randomIp(),
      },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    assert.equal(res.status, 400, text);
    assert.equal(JSON.parse(text).error, "Invalid authentication headers");
  }
  const fetched = await authed(
    "GET",
    `/api/vault/items/${manifest.itemId}`,
    sessionToken,
  );
  assert.equal(fetched.status, 200);
  const fields = fetched.json.fields as { name?: string; ciphertext?: string }[];
  assert.equal(fields.find((field) => field.name === "notes")?.ciphertext, notes);
});
