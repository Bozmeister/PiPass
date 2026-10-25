import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  INTENTDB_ITEM_UPLOAD_ENV,
  uploadStagedOutboxItem,
} from "../uploadItem";
import {
  canonicalTombstoneBody as clientCanonical,
  tombstoneDocumentSha256,
} from "../tombstone";
import {
  canonicalTombstoneBody as serverCanonical,
  tombstoneDocumentSha256 as serverHash,
} from "../../../server/tombstoneProof";
import type { OutboxRecord } from "../../../workers/intentdbOutbox";

const PROOF = "cd".repeat(32);

function tombstoneRecord(): OutboxRecord {
  return {
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
}

test("client and server tombstone encodings match", () => {
  const record = tombstoneRecord();
  if (record.kind !== "tombstone") return;
  assert.equal(serverCanonical(record.tombstone), clientCanonical(record.tombstone));
  assert.equal(serverHash(record.tombstone), tombstoneDocumentSha256(record.tombstone));
});

test("tombstone upload stays off unless the feature flag is enabled", async () => {
  const previous = process.env[INTENTDB_ITEM_UPLOAD_ENV];
  delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
  const record = tombstoneRecord();
  const snapshot = JSON.stringify(record);
  let calls = 0;
  try {
    const result = await uploadStagedOutboxItem({
      record,
      sessionToken: "ab".repeat(32),
      vaultKeyProof: PROOF,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("network must not run");
      },
    });
    assert.equal(result.uploaded, false);
    if (!result.uploaded) assert.equal(result.reason, "disabled");
    assert.equal(calls, 0);
    assert.equal(JSON.stringify(record), snapshot);
  } finally {
    if (previous === undefined) delete process.env[INTENTDB_ITEM_UPLOAD_ENV];
    else process.env[INTENTDB_ITEM_UPLOAD_ENV] = previous;
  }
});

test("tombstone upload sends the document hash and leaves the local record unchanged", async () => {
  const record = tombstoneRecord();
  if (record.kind !== "tombstone") return;
  const snapshot = JSON.stringify(record);
  let captured: { url: string; body: string; headers: Record<string, string> } | null = null;
  const result = await uploadStagedOutboxItem({
    record,
    sessionToken: "ab".repeat(32),
    vaultKeyProof: PROOF,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async (url, init) => {
      captured = { url, body: init.body, headers: init.headers };
      return { ok: true, status: 200, text: async () => "" };
    },
  });
  assert.equal(result.uploaded, true);
  if (result.uploaded) assert.equal(result.contentSha256, record.tombstone.contentSha256);
  assert.ok(captured);
  const request = captured as { url: string; body: string; headers: Record<string, string> };
  assert.equal(
    request.url,
    "https://items.example/api/vault/items/deleted-note-1/tombstone",
  );
  assert.equal(request.headers["x-session-token"], "ab".repeat(32));
  assert.equal(request.headers["x-auth-hash"], undefined);
  const parsed = JSON.parse(request.body) as {
    contentSha256: string;
    contentBound: boolean;
    tombstoneSha256: string;
    vaultKeyProof: string;
  };
  assert.equal(parsed.contentSha256, record.tombstone.contentSha256);
  assert.equal(parsed.contentBound, true);
  assert.equal(parsed.tombstoneSha256, tombstoneDocumentSha256(record.tombstone));
  assert.equal(parsed.vaultKeyProof, PROOF);
  assert.equal(JSON.stringify(record), snapshot);
});

test("a failed tombstone upload does not change the local outbox record", async () => {
  const record = tombstoneRecord();
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

test("tombstone upload source does not recreate local vault entries", () => {
  const source = readFileSync("lib/intentdb/uploadItem.ts", "utf8");
  assert.equal(source.includes("saveEntry"), false);
  assert.equal(source.includes("deleteEntry"), false);
  assert.equal(source.includes("destroyAllData"), false);
  assert.equal(source.includes("x-auth-hash"), false);
});
