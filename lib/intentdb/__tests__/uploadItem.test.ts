import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { buildVaultEntryManifest, canonicalManifestBody, sha256Utf8Hex } from "../itemManifest";
import type { VaultEntry } from "../../../workers/vaultWorker";
import { canonicalItemBody, itemContentSha256 } from "../../../server/itemManifestProof";
import {
  INTENTDB_ITEM_UPLOAD_ENV,
  uploadStagedOutboxItem,
} from "../uploadItem";
import type { OutboxRecord } from "../../../workers/intentdbOutbox";

function v4(label: string): string {
  const body = createHash("sha256").update(label).digest("hex");
  return `v4:${"11".repeat(12)}:${body}:${"22".repeat(16)}`;
}

function manifestWithNotes() {
  const notes = v4("note-field-ciphertext");
  const updatedAt = 1_700_000_000_000;
  const entry: VaultEntry = {
    id: "upload-item-1",
    title: "PLAINTEXT_TITLE_SENTINEL",
    encryptedPassword: v4("password-field"),
    encryptedTitle: v4("title-field"),
    encryptedUsername: v4("username-field"),
    notes,
    salt: "ab".repeat(16),
    createdAt: updatedAt - 50,
    updatedAt,
  };
  return { manifest: buildVaultEntryManifest(entry), notes };
}

const PROOF = "cd".repeat(32);

function recordOf(manifest: ReturnType<typeof buildVaultEntryManifest>): OutboxRecord {
  return { kind: "manifest", enqueuedAt: 10, manifest };
}

test("server canonical hash matches the client manifest hash", () => {
  const { manifest } = manifestWithNotes();
  const body = {
    schema: manifest.schema,
    itemId: manifest.itemId,
    kind: manifest.kind,
    version: manifest.version,
    salt: manifest.salt,
    createdAt: manifest.createdAt,
    updatedAt: manifest.updatedAt,
    fields: manifest.fields,
  };
  assert.equal(canonicalItemBody(body), canonicalManifestBody(body));
  assert.equal(itemContentSha256(body), sha256Utf8Hex(canonicalManifestBody(body)));
  assert.equal(itemContentSha256(body), manifest.contentSha256);
});

test("upload stays off unless the feature flag is enabled", async () => {
  const { manifest } = manifestWithNotes();
  const previous = process.env[INTENTDB_ITEM_UPLOAD_ENV];
  delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
  let calls = 0;
  const record = recordOf(manifest);
  const snapshot = JSON.stringify(record);
  try {
    const disabled = await uploadStagedOutboxItem({
      record,
      sessionToken: "a".repeat(64),
      vaultKeyProof: PROOF,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("network must not run");
      },
    });
    assert.equal(disabled.uploaded, false);
    if (!disabled.uploaded) assert.equal(disabled.reason, "disabled");
    assert.equal(calls, 0);
    assert.equal(JSON.stringify(record), snapshot);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
    else process.env[INTENTDB_ITEM_UPLOAD_ENV] = previous;
  }
});

test("uploads a staged manifest with notes and does not send the auth hash", async () => {
  const { manifest, notes } = manifestWithNotes();
  const record = recordOf(manifest);
  const snapshot = JSON.stringify(record);
  let captured: { url: string; method: string; headers: Record<string, string>; body: string } | null = null;
  const result = await uploadStagedOutboxItem({
    record,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: PROOF,
    locator: "phone",
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async (url, init) => {
      captured = { url, method: init.method, headers: init.headers, body: init.body };
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, true);
  if (result.uploaded) {
    assert.equal(result.itemId, manifest.itemId);
    assert.equal(result.contentSha256, manifest.contentSha256);
  }
  assert.ok(captured);
  const request = captured as { url: string; method: string; headers: Record<string, string>; body: string };
  assert.equal(request.method, "PUT");
  assert.equal(request.url, "https://items.example/api/vault/items");
  assert.equal(request.headers["x-session-token"], "ab".repeat(32));
  assert.equal(request.headers["x-auth-hash"], undefined);
  assert.equal(request.headers["x-user-id"], undefined);
  const parsed = JSON.parse(request.body) as {
    fields: { name: string; ciphertext: string }[];
    contentSha256: string;
    tombstone: boolean;
    locator: string;
  };
  assert.equal(parsed.contentSha256, manifest.contentSha256);
  assert.equal(parsed.tombstone, false);
  assert.equal(parsed.locator, "phone");
  assert.equal(parsed.fields.find((field) => field.name === "notes")?.ciphertext, notes);
  assert.equal(request.body.includes("PLAINTEXT_TITLE_SENTINEL"), false);
  assert.equal(JSON.stringify(record), snapshot);
});

test("upload failure does not change the staged record", async () => {
  const { manifest } = manifestWithNotes();
  const record = recordOf(manifest);
  const snapshot = JSON.stringify(record);
  const offline = await uploadStagedOutboxItem({
    record,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: PROOF,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async () => {
      throw new Error("offline");
    },
  });
  assert.equal(offline.uploaded, false);
  if (!offline.uploaded) assert.equal(offline.reason, "network");
  assert.equal(JSON.stringify(record), snapshot);

  const rejected = await uploadStagedOutboxItem({
    record,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: PROOF,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async () => ({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({ error: "Hash mismatch" }),
    }),
  });
  assert.equal(rejected.uploaded, false);
  if (!rejected.uploaded) {
    assert.equal(rejected.reason, "rejected");
    assert.equal(rejected.status, 400);
  }
  assert.equal(JSON.stringify(record), snapshot);
});

test("a tombstone outbox record is uploaded when the flag is on", async () => {
  let calls = 0;
  const record = {
    kind: "tombstone" as const,
    enqueuedAt: 4,
    tombstone: {
      schema: "pipass-tombstone-v1" as const,
      itemId: "upload-item-1",
      kind: "vault-entry" as const,
      itemVersion: 1,
      contentSha256: "ab".repeat(32),
      contentBound: true,
      deletedAt: 4,
    },
  };
  const snapshot = JSON.stringify(record);
  let captured: { url: string; method: string; headers: Record<string, string> } | null = null;
  const result = await uploadStagedOutboxItem({
    record,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: PROOF,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async (url, init) => {
      calls += 1;
      captured = { url, method: init.method, headers: init.headers };
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, true);
  assert.equal(calls, 1);
  assert.ok(captured);
  const request = captured as { url: string; method: string; headers: Record<string, string> };
  assert.equal(request.method, "PUT");
  assert.equal(request.url, "https://items.example/api/vault/items/upload-item-1/tombstone");
  assert.equal(request.headers["x-auth-hash"], undefined);
  assert.equal(JSON.stringify(record), snapshot);
});

test("upload helper source does not send the auth hash or touch local storage", () => {
  const source = readFileSync("lib/intentdb/uploadItem.ts", "utf8");
  assert.equal(source.includes("x-auth-hash"), false);
  assert.equal(source.includes("deletePlatformItem"), false);
  assert.equal(source.includes("clearIntentdbOutbox"), false);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("decrypt"), false);
});
