/**
 * Retrieval-token item reads. Session writes stay on vaultKeyProof.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/retrievalToken.test.ts
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createVaultKeyProof } from "../../crypto/vaultKeyProof";
import { buildVaultEntryManifest } from "../../lib/intentdb/itemManifest";
import {
  generateRetrievalDeviceKey,
  mintRetrievalToken,
  signRetrievalToken,
} from "../../lib/intentdb/retrievalToken";
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
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function uniqueUsername(): string {
  return `rtok_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
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
    headers: { "content-type": "application/json", "x-forwarded-for": randomIp() },
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

function putBody(manifest: ReturnType<typeof buildVaultEntryManifest>, userId: string, tombstone = false) {
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

function notesCiphertext(body: Record<string, unknown>): string | undefined {
  const fields = body.fields as { name?: string; ciphertext?: string }[] | undefined;
  return fields?.find((field) => field.name === "notes")?.ciphertext;
}

async function putItem(sessionToken: string, body: object, extraHeaders: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}/api/vault/items`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text, json: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

async function getWithSession(sessionToken: string, itemId: string) {
  const res = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}`, {
    headers: { "x-session-token": sessionToken, "x-forwarded-for": randomIp() },
  });
  const text = await res.text();
  return { status: res.status, text, json: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

async function getWithBearer(token: string, itemId: string, extraHeaders: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}`, {
    headers: {
      authorization: `Bearer ${token}`,
      "x-forwarded-for": randomIp(),
      ...extraHeaders,
    },
  });
  const text = await res.text();
  return { status: res.status, text, json: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

async function registerDevice(sessionToken: string, publicKeyHex: string) {
  const res = await fetch(`${baseUrl}/api/auth/retrieval-device`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-session-token": sessionToken,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({ publicKey: publicKeyHex }),
  });
  const text = await res.text();
  assert.equal(res.status, 200, text);
  assert.equal(JSON.parse(text).registered, true);
  assert.equal(text.includes(publicKeyHex), false);
}

test("a retrieval token fetches ciphertext and the session read still works", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const key = generateRetrievalDeviceKey();
  await registerDevice(sessionToken, key.publicKeyHex);

  const itemId = "rtok-item-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  const created = await putItem(sessionToken, putBody(manifest, user.userId));
  assert.equal(created.status, 200, created.text);

  const token = mintRetrievalToken({
    privateKeyHex: key.privateKeyHex,
    publicKeyHex: key.publicKeyHex,
    userId: user.userId,
    ttlMs: 90_000,
    itemIds: [itemId],
  });
  const fetched = await getWithBearer(token, itemId);
  assert.equal(fetched.status, 200, fetched.text);
  assert.equal(notesCiphertext(fetched.json), notes);
  assert.equal(fetched.json.schema, "pipass-item-v1");
  assert.equal(fetched.json.tombstone, false);
  assert.equal(fetched.json.locator, "phone");
  assert.equal(fetched.json.contentSha256, manifest.contentSha256);
  assert.equal(typeof fetched.json.receipt, "object");
  assert.notEqual(fetched.json.receipt, null);
  assert.equal(
    (fetched.json.receipt as { contentSha256?: string; op?: string }).contentSha256,
    manifest.contentSha256,
  );
  assert.equal((fetched.json.receipt as { op?: string }).op, "put");
  assert.equal("vaultKeyProof" in fetched.json, false);
  assert.equal("userId" in fetched.json, false);
  assert.equal(fetched.text.includes(key.privateKeyHex), false);
  assert.equal(fetched.text.includes(key.publicKeyHex), false);
  assert.equal(fetched.text.includes(token), false);
  assert.equal(fetched.text.includes("PLAINTEXT_TITLE_SENTINEL"), false);
  assert.equal(fetched.text.includes("PLAINTEXT_USER_SENTINEL"), false);

  const bySession = await getWithSession(sessionToken, itemId);
  assert.equal(bySession.status, 200, bySession.text);
  assert.equal(notesCiphertext(bySession.json), notes);
  assert.equal(
    (bySession.json.receipt as { contentSha256?: string; op?: string }).contentSha256,
    manifest.contentSha256,
  );
  assert.equal((bySession.json.receipt as { op?: string }).op, "put");

  const write = await fetch(`${baseUrl}/api/vault/items`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify(putBody(manifest, user.userId, true)),
  });
  const writeText = await write.text();
  assert.equal(write.status, 400, writeText);
  assert.equal(JSON.parse(writeText).error, "Invalid authentication headers");
  const still = await getWithSession(sessionToken, itemId);
  assert.equal(still.json.tombstone, false);
  assert.equal(notesCiphertext(still.json), notes);

  const other = await registerUser();
  const otherSession = await login(other);
  const otherKey = generateRetrievalDeviceKey();
  await registerDevice(otherSession, otherKey.publicKeyHex);
  const otherToken = mintRetrievalToken({
    privateKeyHex: otherKey.privateKeyHex,
    publicKeyHex: otherKey.publicKeyHex,
    userId: other.userId,
    ttlMs: 60_000,
    itemIds: [itemId],
  });
  const hidden = await getWithBearer(otherToken, itemId);
  assert.equal(hidden.status, 404, hidden.text);
  assert.equal(hidden.text.includes(notes), false);
});

test("an expired retrieval token is rejected", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const key = generateRetrievalDeviceKey();
  await registerDevice(sessionToken, key.publicKeyHex);
  const itemId = "rtok-expired-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  assert.equal((await putItem(sessionToken, putBody(manifest, user.userId))).status, 200);

  const now = Date.now();
  const expired = signRetrievalToken(
    {
      aud: "intentdb",
      sub: user.userId,
      op: "read",
      exp: now - 5_000,
      nonce: randomBytes(32).toString("hex"),
      itemIds: [itemId],
    },
    key.privateKeyHex,
    key.publicKeyHex,
  );
  const rejected = await getWithBearer(expired, itemId);
  assert.equal(rejected.status, 401, rejected.text);
  assert.deepEqual(rejected.json, { error: "Invalid retrieval token" });
  assert.equal(rejected.text.includes(notes), false);

  const tooLong = signRetrievalToken(
    {
      aud: "intentdb",
      sub: user.userId,
      op: "read",
      exp: now + 180_000,
      nonce: randomBytes(32).toString("hex"),
      itemIds: [itemId],
    },
    key.privateKeyHex,
    key.publicKeyHex,
  );
  const overMax = await getWithBearer(tooLong, itemId);
  assert.equal(overMax.status, 401, overMax.text);
  assert.deepEqual(overMax.json, { error: "Invalid retrieval token" });
  assert.equal(overMax.text.includes(notes), false);

  const still = await getWithSession(sessionToken, itemId);
  assert.equal(still.status, 200, still.text);
  assert.equal(notesCiphertext(still.json), notes);
});

test("the wrong audience or scope is rejected", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const key = generateRetrievalDeviceKey();
  await registerDevice(sessionToken, key.publicKeyHex);
  const itemId = "rtok-scope-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  assert.equal((await putItem(sessionToken, putBody(manifest, user.userId))).status, 200);

  const now = Date.now();
  const base = {
    sub: user.userId,
    op: "read" as const,
    exp: now + 60_000,
  };
  const wrongAudience = signRetrievalToken(
    { ...base, aud: "elsewhere", nonce: randomBytes(32).toString("hex"), itemIds: [itemId] },
    key.privateKeyHex,
    key.publicKeyHex,
  );
  const wrongItems = signRetrievalToken(
    {
      ...base,
      aud: "intentdb",
      nonce: randomBytes(32).toString("hex"),
      itemIds: ["some-other-item"],
    },
    key.privateKeyHex,
    key.publicKeyHex,
  );
  const wrongPrefix = signRetrievalToken(
    { ...base, aud: "intentdb", nonce: randomBytes(32).toString("hex"), prefix: "zzz" },
    key.privateKeyHex,
    key.publicKeyHex,
  );
  const forgedSub = signRetrievalToken(
    {
      aud: "intentdb",
      sub: randomUUID(),
      op: "read",
      exp: now + 60_000,
      nonce: randomBytes(32).toString("hex"),
      itemIds: [itemId],
    },
    key.privateKeyHex,
    key.publicKeyHex,
  );

  for (const token of [wrongAudience, wrongItems, wrongPrefix, forgedSub]) {
    const rejected = await getWithBearer(token, itemId);
    assert.equal(rejected.status, 401, rejected.text);
    assert.deepEqual(rejected.json, { error: "Invalid retrieval token" });
    assert.equal(rejected.text.includes(notes), false);
    assert.equal(rejected.text.includes(key.privateKeyHex), false);
  }

  const still = await getWithSession(sessionToken, itemId);
  assert.equal(still.status, 200, still.text);
  assert.equal(notesCiphertext(still.json), notes);
});

test("item read does not inspect the long-lived auth hash", async () => {
  const user = await registerUser();
  await bindVaultProof(user);
  const sessionToken = await login(user);
  const itemId = "rtok-authhash-1";
  const { entry, notes } = entryWithNotes(itemId);
  const manifest = buildVaultEntryManifest(entry);
  assert.equal((await putItem(sessionToken, putBody(manifest, user.userId))).status, 200);

  for (const authHash of [user.authHash, "ab".repeat(32)]) {
    const res = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}`, {
      headers: {
        "x-user-id": user.userId,
        "x-auth-hash": authHash,
        "x-forwarded-for": randomIp(),
      },
    });
    const text = await res.text();
    assert.equal(res.status, 400, text);
    assert.equal(JSON.parse(text).error, "Invalid authentication headers");
    assert.equal(text.includes(notes), false);

    const bearer = await fetch(`${baseUrl}/api/vault/items/${encodeURIComponent(itemId)}`, {
      headers: {
        authorization: "Bearer not-a-token",
        "x-user-id": user.userId,
        "x-auth-hash": authHash,
        "x-forwarded-for": randomIp(),
      },
    });
    const bearerText = await bearer.text();
    assert.equal(bearer.status, 401, bearerText);
    assert.deepEqual(JSON.parse(bearerText), { error: "Invalid retrieval token" });
    assert.equal(bearerText.includes(notes), false);

    const register = await fetch(`${baseUrl}/api/auth/retrieval-device`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-user-id": user.userId,
        "x-auth-hash": authHash,
        "x-forwarded-for": randomIp(),
      },
      body: JSON.stringify({ publicKey: "ab".repeat(32) }),
    });
    const registerText = await register.text();
    assert.equal(register.status, 400, registerText);
    assert.equal(JSON.parse(registerText).error, "Invalid authentication headers");
  }

  const still = await getWithSession(sessionToken, itemId);
  assert.equal(still.status, 200, still.text);
  assert.equal(notesCiphertext(still.json), notes);
});
