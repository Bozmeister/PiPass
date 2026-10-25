// DELETE /api/account cascades user-owned rows. Session token only.
//
// Run:
//   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit server/__tests__/accountDelete.test.ts

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
import { DatabaseStorage, type AuditEventInput } from "../storage";

class ObservingStorage extends DatabaseStorage {
  audits: AuditEventInput[] = [];

  override async logAuditEvent(input: AuditEventInput): Promise<void> {
    this.audits.push(input);
    await super.logAuditEvent(input);
  }
}

const storage = new ObservingStorage();
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
  return `acct_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
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

test("account delete cascades items and blobs and logs safe metadata", async () => {
  const owner = await registerUser();
  await bindVaultProof(owner);
  const ownerSession = await login(owner);
  const updatedAt = 1_700_000_000_000;
  const entry: VaultEntry = {
    id: "acct-item-1",
    encryptedPassword: v4("password"),
    encryptedTitle: v4("title"),
    encryptedUsername: v4("username"),
    notes: v4("notes"),
    salt: "ab".repeat(16),
    createdAt: updatedAt - 10,
    updatedAt,
  };
  const manifest = buildVaultEntryManifest(entry);
  const put = await fetch(`${baseUrl}/api/vault/items`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-session-token": ownerSession,
      "x-forwarded-for": randomIp(),
    },
    body: JSON.stringify({
      schema: manifest.schema,
      itemId: manifest.itemId,
      kind: manifest.kind,
      version: manifest.version,
      salt: manifest.salt,
      createdAt: manifest.createdAt,
      updatedAt: manifest.updatedAt,
      fields: manifest.fields,
      contentSha256: manifest.contentSha256,
      locator: "phone",
      tombstone: false,
      vaultKeyProof: testVaultKeyProof(owner.userId),
    }),
  });
  assert.equal(put.status, 200, await put.text());

  const bystander = await registerUser();
  await bindVaultProof(bystander);
  const bystanderSession = await login(bystander);

  for (const authHash of [owner.authHash, "cd".repeat(32)]) {
    const rejected = await fetch(`${baseUrl}/api/account`, {
      method: "DELETE",
      headers: {
        "x-user-id": owner.userId,
        "x-auth-hash": authHash,
        "x-forwarded-for": randomIp(),
      },
    });
    const text = await rejected.text();
    assert.equal(rejected.status, 400, text);
    assert.equal(JSON.parse(text).error, "Invalid authentication headers");
  }

  const removed = await fetch(`${baseUrl}/api/account`, {
    method: "DELETE",
    headers: {
      "x-session-token": ownerSession,
      "x-forwarded-for": randomIp(),
    },
  });
  assert.equal(removed.status, 204, await removed.text());

  assert.equal(await storage.getUser(owner.userId), undefined);
  assert.equal(await storage.getVaultBlob(owner.userId), undefined);
  assert.equal(await storage.getVaultItem(owner.userId, manifest.itemId), undefined);
  assert.deepEqual(await storage.getAuditLog(owner.userId), []);

  const ownerAudit = storage.audits.filter(
    (row) => row.userId === owner.userId && row.action === "account_delete",
  );
  assert.equal(ownerAudit.length, 1);
  const auditJson = JSON.stringify(ownerAudit[0]);
  assert.equal(auditJson.includes(ownerSession), false);
  assert.equal(auditJson.includes(owner.authHash), false);
  assert.equal(ownerAudit[0].blobSize, null);
  assert.equal(ownerAudit[0].versionBefore, null);
  assert.equal(ownerAudit[0].versionAfter, null);

  const stillThere = await fetch(`${baseUrl}/api/vault/fetch`, {
    headers: {
      "x-session-token": bystanderSession,
      "x-forwarded-for": randomIp(),
    },
  });
  assert.equal(stillThere.status, 200, await stillThere.text());
  assert.equal((await storage.getUser(bystander.userId))?.id, bystander.userId);

  const deadSession = await fetch(`${baseUrl}/api/vault/items/${manifest.itemId}`, {
    headers: {
      "x-session-token": ownerSession,
      "x-forwarded-for": randomIp(),
    },
  });
  assert.equal(deadSession.status, 401);
});
