/**
 * Phase 1 IntentDB local outbox.
 * Appends ciphertext manifests and tombstones after vault mutations.
 * Does not write the shared autofill blob and does not call /api/vault.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Module from "node:module";
import test from "node:test";
import { setPlatformStorageDriverForTests, type PlatformStorageDriver } from "../../lib/platformStorage";
import {
  buildReceipt,
  GENESIS_RECEIPT_HASH,
  createHmacSha256ReceiptCrypto,
  verifyReceipt,
} from "../../lib/intentdb/receipt";
import type { VaultEntry } from "../vaultWorker";

const MASTER_KEY = "c3".repeat(32);
const PASSWORD = "Plaintext-Password!";
const TITLE = "Work Email";
const USERNAME = "ada@example.com";
const URL = "https://bank.example/login";
const NOTES = "mother's maiden name";
const NOTE_LABEL = "Tax Folder";
const NOTE_CONTENT = "Note-Content-Secret!";
const LEGACY_TITLE = "Visible Title";

class MemoryStorage {
  readonly items = new Map<string, string>();
  readonly driver: PlatformStorageDriver = {
    getItem: async (key: string) => this.items.get(key) ?? null,
    setItem: async (key: string, value: string) => {
      this.items.set(key, value);
    },
    deleteItem: async (key: string) => {
      this.items.delete(key);
    },
    isWeb: () => false,
  };
}

function installExpoCryptoStub(): () => void {
  const moduleLoader = Module as unknown as {
    _load: (request: string, parent: unknown, isMain: boolean) => unknown;
  };
  const originalLoad = moduleLoader._load;
  let counter = 7;
  moduleLoader._load = function patchedLoad(
    request: string,
    parent: unknown,
    isMain: boolean,
  ) {
    if (request === "expo-crypto") {
      return {
        getRandomBytes: (length: number) => {
          const bytes = new Uint8Array(length);
          for (let i = 0; i < length; i++) {
            bytes[i] = (counter + i * 13) & 0xff;
          }
          counter += 1;
          return bytes;
        },
      };
    }
    if (request === "react-native") {
      return {
        Platform: { OS: "web", select: (spec: { web?: unknown; default?: unknown }) => spec.web ?? spec.default },
        NativeModules: {},
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  return () => {
    moduleLoader._load = originalLoad;
  };
}

function outboxDump(storage: MemoryStorage): string {
  const chunks: string[] = [];
  for (const [key, value] of storage.items) {
    if (key.startsWith("pipass_intentdb_outbox")) chunks.push(value);
  }
  return chunks.join("\n");
}

function assertNoSecrets(dump: string): void {
  for (const secret of [
    PASSWORD,
    TITLE,
    USERNAME,
    URL,
    NOTES,
    NOTE_LABEL,
    NOTE_CONTENT,
    LEGACY_TITLE,
    "CACHED_MASTER_KEY_SENTINEL",
    "AUTH_HASH_SENTINEL",
    MASTER_KEY,
  ]) {
    assert.equal(dump.includes(secret), false, `outbox leaked ${secret}`);
  }
}

test("outbox source does not touch autofill storage or vault HTTP routes", () => {
  const source = readFileSync("workers/intentdbOutbox.ts", "utf8");
  assert.equal(source.includes("/api/vault"), false);
  assert.equal(source.includes("pipass_shared_vault"), false);
  assert.equal(source.includes("saveSharedVaultBlob"), false);
  assert.equal(source.includes("fetch("), false);
});

test("save and delete append manifests and tombstones without plaintext or autofill writes", async (t) => {
  const restoreCrypto = installExpoCryptoStub();
  const storage = new MemoryStorage();
  setPlatformStorageDriverForTests(storage.driver);
  t.after(() => {
    restoreCrypto();
    setPlatformStorageDriverForTests(null);
  });

  storage.items.set("pipass_master_key", "CACHED_MASTER_KEY_SENTINEL");
  storage.items.set("pipass.auth.authHash", "AUTH_HASH_SENTINEL");
  storage.items.set("pipass_shared_vault", "SHARED_BLOB_SENTINEL");

  const vault = await import("../vaultWorker");
  const store = await import("../storageWorker");
  const outbox = await import("../intentdbOutbox");
  const { splitKeyIntoShares, wipeShares } = await import("../../crypto/secureMemory");
  const shares = splitKeyIntoShares(MASTER_KEY);

  try {
    const entry = vault.encryptVaultEntry(
      { title: TITLE, username: USERNAME, password: PASSWORD, url: URL, notes: NOTES },
      shares,
    );
    const direct = await outbox.recordVaultEntrySaved(entry);
    assert.equal(direct.enqueued, true);
    assert.equal(storage.items.get("pipass_shared_vault"), "SHARED_BLOB_SENTINEL");

    storage.items.delete(outbox.OUTBOX_INDEX_KEY);
    for (const key of [...storage.items.keys()]) {
      if (key.startsWith(outbox.OUTBOX_KEY_PREFIX)) storage.items.delete(key);
    }

    await store.saveEntry(entry);
    const sharedRaw = storage.items.get("pipass_shared_vault");
    assert.ok(sharedRaw);
    assert.notEqual(sharedRaw, "SHARED_BLOB_SENTINEL");
    const shared = JSON.parse(sharedRaw) as { encryptedBlob: string; version: number };
    assert.equal(shared.version, 1);
    const sharedEntries = JSON.parse(shared.encryptedBlob) as VaultEntry[];
    assert.equal(sharedEntries.length, 1);
    assert.equal(sharedEntries[0].encryptedPassword, entry.encryptedPassword);

    const note = vault.encryptSecureNote({ label: NOTE_LABEL, content: NOTE_CONTENT }, shares);
    const noteWithLegacy = { ...note, label: NOTE_LABEL };
    await store.saveSecureNote(noteWithLegacy);
    assert.equal(storage.items.get(`pipass_note_${note.id}`)?.includes(NOTE_LABEL), false);

    const saved = await outbox.listIntentdbOutbox();
    assert.equal(saved.length, 2);
    assert.equal(saved[0].kind, "manifest");
    assert.equal(saved[1].kind, "manifest");
    if (saved[0].kind !== "manifest" || saved[1].kind !== "manifest") return;
    assert.equal(saved[0].manifest.kind, "vault-entry");
    assert.equal(saved[1].manifest.kind, "secure-note");
    assert.equal(saved[0].manifest.fields.some((field) => field.name === "notes"), true);
    assertNoSecrets(outboxDump(storage));

    await store.deleteSecureNote(note.id);
    await store.deleteEntry(entry.id);
    const afterDelete = await outbox.listIntentdbOutbox();
    const tombstones = afterDelete.filter((record) => record.kind === "tombstone");
    assert.equal(tombstones.length, 2);
    const noteTombstone = tombstones.find(
      (record) => record.kind === "tombstone" && record.tombstone.kind === "secure-note",
    );
    const entryTombstone = tombstones.find(
      (record) => record.kind === "tombstone" && record.tombstone.kind === "vault-entry",
    );
    assert.ok(noteTombstone && noteTombstone.kind === "tombstone");
    assert.ok(entryTombstone && entryTombstone.kind === "tombstone");
    assert.equal(noteTombstone.tombstone.contentBound, true);
    assert.equal(entryTombstone.tombstone.contentBound, true);
    assert.equal(noteTombstone.tombstone.contentSha256, saved[1].manifest.contentSha256);
    assert.equal(entryTombstone.tombstone.contentSha256, saved[0].manifest.contentSha256);
    assert.equal(storage.items.has(`pipass_note_${note.id}`), false);
    assert.equal(storage.items.has(`pipass_vault_${entry.id}`), false);
    assertNoSecrets(outboxDump(storage));

    const receipt = buildReceipt(
      {
        op: "delete",
        itemId: entryTombstone.tombstone.itemId,
        itemVersion: entryTombstone.tombstone.itemVersion,
        contentSha256: entryTombstone.tombstone.contentSha256,
        fromLocator: "local/vault",
        toLocator: "tombstone",
        botId: "phase1-test",
        issuedAt: entryTombstone.tombstone.deletedAt,
        prevReceiptHash: GENESIS_RECEIPT_HASH,
      },
      createHmacSha256ReceiptCrypto(new Uint8Array([4, 5, 6, 7])),
    );
    assert.equal(
      verifyReceipt(receipt, createHmacSha256ReceiptCrypto(new Uint8Array([4, 5, 6, 7]))).ok,
      true,
    );

    const legacy: VaultEntry = {
      id: "legacyentry0001",
      title: LEGACY_TITLE,
      username: "visible-user",
      encryptedPassword: "abcd:ef01",
      salt: "ab".repeat(16),
      createdAt: 1,
      updatedAt: 1,
    };
    const beforeLegacy = (await outbox.listIntentdbOutbox()).length;
    await store.saveEntry(legacy);
    assert.equal((await store.getEntry(legacy.id))?.title, LEGACY_TITLE);
    assert.equal((await outbox.listIntentdbOutbox()).length, beforeLegacy);
    assert.equal(outboxDump(storage).includes(LEGACY_TITLE), false);

    await store.deleteEntry(legacy.id);
    const legacyRows = await outbox.listIntentdbOutbox();
    const legacyTombstone = legacyRows[legacyRows.length - 1];
    assert.equal(legacyTombstone.kind, "tombstone");
    if (legacyTombstone.kind !== "tombstone") return;
    assert.equal(legacyTombstone.tombstone.contentBound, false);
    assert.equal(JSON.stringify(legacyTombstone).includes(LEGACY_TITLE), false);

    await store.destroyAllData();
    for (const key of storage.items.keys()) {
      assert.equal(key.startsWith("pipass_intentdb_outbox"), false, `${key} survived nuclear reset`);
    }
    assert.equal(storage.items.has("pipass_shared_vault"), false);
    assert.equal(storage.items.has("pipass_master_key"), false);
    assert.equal(storage.items.has("pipass.auth.authHash"), false);
  } finally {
    wipeShares(shares);
  }
});
