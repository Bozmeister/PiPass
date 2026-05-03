import assert from "node:assert/strict";
import test from "node:test";
import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  clearKdfMetadata,
  clearVault,
  destroyAllData,
  getKdfMetadata,
  hasLocalEncryptedVaultData,
  saveKdfMetadata,
} from "../storageWorker";
import { logoutCurrentSession } from "../../lib/logout";
import { setPlatformStorageDriverForTests } from "../../lib/platformStorage";
import type { PlatformStorageDriver } from "../../lib/platformStorage";

class MemoryStorage {
  readonly items = new Map<string, string>();

  readonly driver: PlatformStorageDriver = {
    getItem: (key) => this.items.get(key) ?? null,
    setItem: (key, value) => {
      this.items.set(key, value);
    },
    deleteItem: (key) => {
      this.items.delete(key);
    },
    isWeb: () => false,
  };
}

function installMemoryStorage(): MemoryStorage {
  const storage = new MemoryStorage();
  setPlatformStorageDriverForTests(storage.driver);
  return storage;
}

function seedBaseState(storage: MemoryStorage): void {
  storage.items.set("pipass_vault_index", JSON.stringify(["entry-a"]));
  storage.items.set(
    "pipass_vault_entry-a",
    JSON.stringify({
      id: "entry-a",
      title: "encrypted-title-placeholder",
      username: "encrypted-username-placeholder",
      encryptedPassword: "encrypted-password-placeholder",
      salt: "salt-placeholder",
      createdAt: 1,
      updatedAt: 1,
    }),
  );
  storage.items.set("pipass_notes_index", JSON.stringify(["note-a"]));
  storage.items.set(
    "pipass_note_note-a",
    JSON.stringify({
      id: "note-a",
      label: "encrypted-label-placeholder",
      encryptedLabel: "encrypted-label-placeholder",
      encryptedContent: "encrypted-content-placeholder",
      salt: "salt-placeholder",
      createdAt: 1,
      updatedAt: 1,
    }),
  );
  storage.items.set("pipass_master_hash", "TEST_MASTER_HASH");
  storage.items.set("pipass_master_salt", "TEST_MASTER_SALT");
  storage.items.set("pipass_security_profile", "100000");
  storage.items.set(
    "pipass_kdf_metadata",
    JSON.stringify(
      buildArgon2idKdfMetadata(
        100000,
        { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 32 },
        "setup",
        { createdAt: 1 },
      ),
    ),
  );
  storage.items.set("pipass_show_keyprints", "1");
  storage.items.set("pipass_vault_initialized", "1");
  storage.items.set("pipass_fractal_fingerprint", "TEST_FINGERPRINT");
  storage.items.set("pipass_recovery_key_hash", "TEST_RECOVERY_HASH");
  storage.items.set("pipass_shared_migration_done", "1");
  storage.items.set("pipass_shared_vault", "TEST_SHARED_VAULT");
  storage.items.set("pipass_master_key", "TEST_CACHED_MASTER_KEY");
  storage.items.set("pipass.auth.userId", "11111111-1111-4111-8111-111111111111");
  storage.items.set("pipass.auth.authHash", "a".repeat(64));
  storage.items.set("pipass.installId", "22222222-2222-4222-8222-222222222222");
  storage.items.set("deviceUUID", "33333333-3333-4333-8333-333333333333");
}

test("clearVault clears local vault data but preserves auth and install identity state", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  seedBaseState(storage);

  await clearVault();

  assert.equal(storage.items.has("pipass_vault_index"), false);
  assert.equal(storage.items.has("pipass_vault_entry-a"), false);
  assert.equal(storage.items.has("pipass_master_hash"), false);
  assert.equal(storage.items.has("pipass_shared_vault"), false);

  assert.equal(storage.items.has("pipass_kdf_metadata"), true);
  assert.equal(storage.items.get("pipass.auth.userId"), "11111111-1111-4111-8111-111111111111");
  assert.equal(storage.items.get("pipass.auth.authHash"), "a".repeat(64));
  assert.equal(storage.items.get("pipass.installId"), "22222222-2222-4222-8222-222222222222");
  assert.equal(storage.items.get("deviceUUID"), "33333333-3333-4333-8333-333333333333");
});

test("destroyAllData clears vault, notes, unlock metadata, credentials, installId, and deviceUUID", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  seedBaseState(storage);

  await destroyAllData();

  for (const key of [
    "pipass_vault_index",
    "pipass_vault_entry-a",
    "pipass_notes_index",
    "pipass_note_note-a",
    "pipass_master_hash",
    "pipass_master_salt",
    "pipass_security_profile",
    "pipass_kdf_metadata",
    "pipass_show_keyprints",
    "pipass_vault_initialized",
    "pipass_fractal_fingerprint",
    "pipass_recovery_key_hash",
    "pipass_shared_migration_done",
    "pipass_shared_vault",
    "pipass_master_key",
    "pipass.auth.userId",
    "pipass.auth.authHash",
    "pipass.installId",
    "deviceUUID",
  ]) {
    assert.equal(storage.items.has(key), false, `${key} should be cleared`);
  }
});

test("logoutCurrentSession clears credentials only and is idempotent without a stored session token", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  seedBaseState(storage);

  const result = await logoutCurrentSession();

  assert.deepEqual(result, {
    localCleared: true,
    serverLogoutAttempted: false,
    serverLogoutSucceeded: undefined,
    serverLogoutStatus: undefined,
  });
  assert.equal(storage.items.has("pipass.auth.userId"), false);
  assert.equal(storage.items.has("pipass.auth.authHash"), false);
  assert.equal(storage.items.has("pipass_vault_index"), true);
  assert.equal(storage.items.has("pipass_vault_entry-a"), true);
  assert.equal(storage.items.has("pipass_shared_vault"), true);
  assert.equal(storage.items.get("pipass.installId"), "22222222-2222-4222-8222-222222222222");
  assert.equal(storage.items.get("deviceUUID"), "33333333-3333-4333-8333-333333333333");

  const secondResult = await logoutCurrentSession();
  assert.equal(secondResult.localCleared, true);
  assert.equal(secondResult.serverLogoutAttempted, false);
  assert.equal(storage.items.has("pipass.auth.userId"), false);
  assert.equal(storage.items.has("pipass.auth.authHash"), false);
  assert.equal(storage.items.has("pipass_vault_entry-a"), true);
});

test("logoutCurrentSession still clears local credentials when server logout fails", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  seedBaseState(storage);
  let called = false;

  const result = await logoutCurrentSession({
    sessionToken: "TEST_SESSION_TOKEN",
    apiBaseUrl: "https://api.example.test",
    fetchImpl: async () => {
      called = true;
      throw new Error("network down");
    },
  });

  assert.equal(called, true);
  assert.deepEqual(result, {
    localCleared: true,
    serverLogoutAttempted: true,
    serverLogoutSucceeded: false,
    serverLogoutStatus: undefined,
  });
  assert.equal(storage.items.has("pipass.auth.userId"), false);
  assert.equal(storage.items.has("pipass.auth.authHash"), false);
  assert.equal(storage.items.has("pipass_vault_entry-a"), true);
  assert.equal(storage.items.get("pipass.installId"), "22222222-2222-4222-8222-222222222222");
  assert.equal(storage.items.get("deviceUUID"), "33333333-3333-4333-8333-333333333333");
});

test("hasLocalEncryptedVaultData detects indexed vault entries and secure notes", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  assert.equal(await hasLocalEncryptedVaultData(), false);

  storage.items.set("pipass_vault_index", JSON.stringify(["entry-a"]));
  assert.equal(await hasLocalEncryptedVaultData(), true);

  storage.items.delete("pipass_vault_index");
  assert.equal(await hasLocalEncryptedVaultData(), false);

  storage.items.set("pipass_notes_index", JSON.stringify(["note-a"]));
  assert.equal(await hasLocalEncryptedVaultData(), true);
});

test("KDF metadata helpers save and read valid Argon2id metadata", async (t) => {
  installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const metadata = buildArgon2idKdfMetadata(
    100000,
    { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 32 },
    "setup",
    { createdAt: 1234567890 },
  );

  await saveKdfMetadata(metadata);

  assert.deepEqual(await getKdfMetadata(), metadata);
});

test("KDF metadata helpers save and read valid PBKDF2 metadata", async (t) => {
  installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const metadata = buildPbkdf2KdfMetadata(
    100000,
    { iterations: 100000, outputBytes: 32 },
    "legacy-detected",
    { createdAt: 1234567890 },
  );

  await saveKdfMetadata(metadata);

  assert.deepEqual(await getKdfMetadata(), metadata);
});

test("KDF metadata read returns null for invalid JSON without throwing", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  storage.items.set("pipass_kdf_metadata", "{not-json");

  assert.equal(await getKdfMetadata(), null);
});

test("KDF metadata read returns null for unsupported algorithms", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  storage.items.set(
    "pipass_kdf_metadata",
    JSON.stringify({
      version: 1,
      algorithm: "scrypt",
      profileIterations: 100000,
      kdfVersion: "v1",
      parameters: { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 32 },
      saltKey: "pipass_master_salt",
      deviceBinding: "deviceUUID:v1",
      createdAt: 1234567890,
      source: "setup",
    }),
  );

  assert.equal(await getKdfMetadata(), null);
});

test("KDF metadata read returns null for missing required fields", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  storage.items.set(
    "pipass_kdf_metadata",
    JSON.stringify({
      version: 1,
      algorithm: "argon2id",
      profileIterations: 100000,
      kdfVersion: "v1",
      parameters: { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 32 },
      saltKey: "pipass_master_salt",
      createdAt: 1234567890,
      source: "setup",
    }),
  );

  assert.equal(await getKdfMetadata(), null);
});

test("KDF metadata read returns null for invalid parameter shape", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  storage.items.set(
    "pipass_kdf_metadata",
    JSON.stringify({
      version: 1,
      algorithm: "argon2id",
      profileIterations: 100000,
      kdfVersion: "v1",
      parameters: { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 64 },
      saltKey: "pipass_master_salt",
      deviceBinding: "deviceUUID:v1",
      createdAt: 1234567890,
      source: "setup",
    }),
  );

  assert.equal(await getKdfMetadata(), null);
});

test("clearKdfMetadata removes stored KDF metadata", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  await saveKdfMetadata(
    buildArgon2idKdfMetadata(
      100000,
      { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 32 },
      "setup",
      { createdAt: 1234567890 },
    ),
  );

  await clearKdfMetadata();

  assert.equal(storage.items.has("pipass_kdf_metadata"), false);
  assert.equal(await getKdfMetadata(), null);
});
