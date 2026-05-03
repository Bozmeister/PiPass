import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  clearKdfMetadata,
  clearVault,
  destroyAllData,
  getKdfMetadata,
  getKdfMetadataState,
  hasLocalEncryptedVaultData,
  saveKdfMetadata,
} from "../storageWorker";
import { logoutCurrentSession } from "../../lib/logout";
import {
  classifyBackupCompatibility,
  parsePipassBackup,
  type BackupCompatibilityContext,
  type BackupStageResult,
} from "../../lib/backupSchema";
import { verifyStagedBackupDecryptability } from "../../lib/backupDecryptVerification";
import {
  getBackupVerifierFromMetadata,
  isBackupVerifier,
  parseBackupVerifier,
  verifyBackupSentinel,
} from "../../lib/backupVerifier";
import {
  buildSetupImportCommitPlan,
  SETUP_IMPORT_STORAGE_KEYS,
} from "../../lib/setupImportCommitPlan";
import { setPlatformStorageDriverForTests } from "../../lib/platformStorage";
import type { KdfMetadata } from "../../crypto/kdfMetadata";
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

function validBackupFixture(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "pipass-backup",
    version: 1,
    format: "encrypted-local-records",
    createdAt: 1234567890,
    entries: [
      {
        id: "entry-a",
        title: "encrypted-title-placeholder",
        username: "encrypted-username-placeholder",
        encryptedPassword: "encrypted-password-placeholder",
        encryptedTitle: "encrypted-title-ciphertext",
        encryptedUsername: "encrypted-username-ciphertext",
        encryptedUrl: "encrypted-url-ciphertext",
        url: "encrypted-url-display-placeholder",
        notes: "encrypted-notes-ciphertext",
        salt: "entry-salt-placeholder",
        createdAt: 1,
        updatedAt: 2,
        encryptedAux: "encrypted-aux-placeholder",
      },
    ],
    secureNotes: [
      {
        id: "note-a",
        label: "encrypted-label-placeholder",
        encryptedLabel: "encrypted-label-ciphertext",
        encryptedContent: "encrypted-content-ciphertext",
        salt: "note-salt-placeholder",
        createdAt: 3,
        updatedAt: 4,
      },
    ],
    metadata: { app: "PiPass" },
    ...overrides,
  };
}

function validBackupVerifierFixture(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    type: "encrypted-sentinel",
    derivation: "entry-v1",
    recordId: "pipass-backup-verifier-v1",
    salt: "a".repeat(64),
    ciphertext: "encrypted-sentinel-ciphertext-placeholder",
    expectedPlaintextHash: "b".repeat(64),
    ...overrides,
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function testArgon2idMetadata(): KdfMetadata {
  return buildArgon2idKdfMetadata(
    100000,
    { memoryKiB: 131072, timeCost: 4, parallelism: 4, outputBytes: 32 },
    "setup",
    { createdAt: 1234567890 },
  );
}

function testKdfMetadataRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { ...testArgon2idMetadata(), ...overrides };
}

function compatibilityMetadata(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    format: "encrypted-local-records",
    kdfMetadata: testArgon2idMetadata(),
    saltKey: "pipass_master_salt",
    deviceBinding: "deviceUUID:v1",
    deviceScope: "same-install",
    requiresSameDeviceUUID: true,
    ...overrides,
  };
}

function stagedBackupWithCompatibility(
  compatibility: Record<string, unknown> | null = compatibilityMetadata(),
): BackupStageResult {
  const result = parsePipassBackup(
    validBackupFixture({
      metadata:
        compatibility === null
          ? { app: "PiPass" }
          : { app: "PiPass", compatibility },
    }),
  );

  assert.equal(result.ok, true);
  return result.backup;
}

function stagedBackupFixture(overrides: Record<string, unknown> = {}): BackupStageResult {
  const result = parsePipassBackup(validBackupFixture(overrides));

  assert.equal(result.ok, true);
  return result.backup;
}

function localCompatibilityContext(overrides: Record<string, unknown> = {}) {
  const context: BackupCompatibilityContext = {
    format: "encrypted-local-records",
    kdfMetadata: testArgon2idMetadata(),
    masterSaltPresent: true,
    deviceBinding: "deviceUUID:v1",
    deviceUUIDPresent: true,
  };

  return {
    ...context,
    ...overrides,
  } as BackupCompatibilityContext;
}

function commitSetupMetadataFixture(overrides: Record<string, unknown> = {}) {
  return {
    masterSalt: "setup-master-salt-placeholder",
    masterHash: "setup-master-hash-placeholder",
    securityProfile: 100000,
    kdfMetadata: testArgon2idMetadata(),
    recoveryKeyHash: "setup-recovery-hash-placeholder",
    ...overrides,
  };
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
  assert.deepEqual(await getKdfMetadataState(), { status: "valid", metadata });
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
  assert.deepEqual(await getKdfMetadataState(), { status: "valid", metadata });
});

test("KDF metadata state distinguishes missing metadata", async (t) => {
  installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  assert.deepEqual(await getKdfMetadataState(), { status: "missing", metadata: null });
});

test("KDF metadata read returns null for invalid JSON without throwing", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  storage.items.set("pipass_kdf_metadata", "{not-json");

  assert.equal(await getKdfMetadata(), null);
  assert.deepEqual(await getKdfMetadataState(), { status: "invalid", metadata: null });
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
  assert.deepEqual(await getKdfMetadataState(), { status: "invalid", metadata: null });
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
  assert.deepEqual(await getKdfMetadataState(), { status: "invalid", metadata: null });
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
  assert.deepEqual(await getKdfMetadataState(), { status: "invalid", metadata: null });
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
  assert.deepEqual(await getKdfMetadataState(), { status: "missing", metadata: null });
});

test("backup parser stages valid v1 encrypted-local-records backup with entries and notes", () => {
  const result = parsePipassBackup(JSON.stringify(validBackupFixture()));

  assert.equal(result.ok, true);

  assert.equal(result.backup.kind, "encrypted-local-records");
  assert.equal(result.backup.counts.entries, 1);
  assert.equal(result.backup.counts.secureNotes, 1);
  assert.equal(result.backup.entries[0].id, "entry-a");
  assert.equal(result.backup.secureNotes[0].id, "note-a");
  assert.equal(result.backup.warnings.length, 1);
});

test("backup parser stages valid backup with missing secureNotes as an empty array", () => {
  const backup = validBackupFixture();
  delete backup.secureNotes;

  const result = parsePipassBackup(backup);

  assert.equal(result.ok, true);

  assert.deepEqual(result.backup.secureNotes, []);
  assert.equal(result.backup.counts.secureNotes, 0);
});

test("backup parser rejects missing schema", () => {
  const backup = validBackupFixture();
  delete backup.schema;

  const result = parsePipassBackup(backup);

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "missing-schema");
});

test("backup parser rejects unsupported version", () => {
  const result = parsePipassBackup(validBackupFixture({ version: 2 }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "unsupported-version");
});

test("backup parser rejects unsupported format", () => {
  const result = parsePipassBackup(validBackupFixture({ format: "plaintext" }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "unsupported-format");
});

test("backup parser rejects entries that are not an array", () => {
  const result = parsePipassBackup(validBackupFixture({ entries: {} }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "entries-not-array");
});

test("backup parser rejects secureNotes that are present but not an array", () => {
  const result = parsePipassBackup(validBackupFixture({ secureNotes: {} }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "secure-notes-not-array");
});

test("backup parser rejects entries missing required encrypted-record fields", () => {
  const backup = validBackupFixture();
  const entries = backup.entries as Array<Record<string, unknown>>;
  delete entries[0].encryptedPassword;

  const result = parsePipassBackup(backup);

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "invalid-entry");
  assert.equal(result.error.path, "entries[0].encryptedPassword");
});

test("backup parser rejects secure notes missing encrypted content", () => {
  const backup = validBackupFixture();
  const secureNotes = backup.secureNotes as Array<Record<string, unknown>>;
  delete secureNotes[0].encryptedContent;

  const result = parsePipassBackup(backup);

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "invalid-secure-note");
  assert.equal(result.error.path, "secureNotes[0].encryptedContent");
});

test("backup parser returns a controlled error for invalid JSON", () => {
  const result = parsePipassBackup("{not-json");

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup parser failure");
  }
  assert.equal(result.error.code, "invalid-json");
});

test("backup parser does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const result = parsePipassBackup(validBackupFixture());

  assert.equal(result.ok, true);
  assert.equal(storage.items.size, 0);
});

test("backup compatibility classifier accepts matching same-install KDF metadata", () => {
  const backup = stagedBackupWithCompatibility();
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "compatible");
  assert.equal(result.reason, "same-install-metadata-match");
});

test("backup compatibility classifier returns unknown when metadata is missing", () => {
  const backup = stagedBackupWithCompatibility(null);
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "unknown");
  assert.equal(result.reason, "missing-compatibility-metadata");
});

test("backup compatibility classifier rejects portable encrypted backups for now", () => {
  const backup = stagedBackupWithCompatibility(
    compatibilityMetadata({ deviceScope: "portable", requiresSameDeviceUUID: false }),
  );
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "portable-encrypted-backups-not-supported");
});

test("backup compatibility classifier rejects same-device backups when local deviceUUID is missing", () => {
  const backup = stagedBackupWithCompatibility();
  const result = classifyBackupCompatibility(
    backup,
    localCompatibilityContext({ deviceUUIDPresent: false }),
  );

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "required-device-uuid-missing");
});

test("backup compatibility classifier rejects KDF algorithm mismatch", () => {
  const backup = stagedBackupWithCompatibility(
    compatibilityMetadata({
      kdfMetadata: buildPbkdf2KdfMetadata(
        100000,
        { iterations: 100000, outputBytes: 32 },
        "legacy-detected",
        { createdAt: 1234567890 },
      ),
    }),
  );
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "kdf-metadata-mismatch");
});

test("backup compatibility classifier rejects KDF parameter mismatch", () => {
  const backup = stagedBackupWithCompatibility(
    compatibilityMetadata({
      kdfMetadata: buildArgon2idKdfMetadata(
        100000,
        { memoryKiB: 65536, timeCost: 3, parallelism: 4, outputBytes: 32 },
        "setup",
        { createdAt: 1234567890 },
      ),
    }),
  );
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "kdf-metadata-mismatch");
});

test("backup compatibility classifier returns unknown when local KDF metadata is missing", () => {
  const backup = stagedBackupWithCompatibility();
  const result = classifyBackupCompatibility(backup, localCompatibilityContext({ kdfMetadata: null }));

  assert.equal(result.status, "unknown");
  assert.equal(result.reason, "local-kdf-metadata-missing");
});

test("backup compatibility classifier rejects invalid backup KDF metadata", () => {
  const backup = stagedBackupWithCompatibility(
    compatibilityMetadata({
      kdfMetadata: testKdfMetadataRecord({ algorithm: "scrypt" }),
    }),
  );
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "invalid-backup-kdf-metadata");
});

test("backup compatibility classifier rejects salt key mismatch", () => {
  const backup = stagedBackupWithCompatibility(
    compatibilityMetadata({ saltKey: "other_salt_key" }),
  );
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "salt-key-mismatch");
});

test("backup compatibility classifier rejects device binding mismatch", () => {
  const backup = stagedBackupWithCompatibility(
    compatibilityMetadata({ deviceBinding: "deviceUUID:v2" }),
  );
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "incompatible");
  assert.equal(result.reason, "device-binding-mismatch");
});

test("backup compatibility classifier warns when encryptedAux is present", () => {
  const backup = stagedBackupWithCompatibility();
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(
    result.warnings.includes(
      "backup contains encrypted honeytoken aux metadata that may require server-side reissue or review",
    ),
    true,
  );
});

test("backup compatibility classifier does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const backup = stagedBackupWithCompatibility();
  const result = classifyBackupCompatibility(backup, localCompatibilityContext());

  assert.equal(result.status, "compatible");
  assert.equal(storage.items.size, 0);
});

test("backup verifier parser accepts valid entry-v1 encrypted-sentinel verifier", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture());

  assert.equal(result.ok, true);
  assert.equal(isBackupVerifier(validBackupVerifierFixture()), true);
  assert.equal(result.verifier.derivation, "entry-v1");
});

test("backup verifier parser accepts valid note-v1 encrypted-sentinel verifier", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ derivation: "note-v1" }));

  assert.equal(result.ok, true);
  assert.equal(result.verifier.derivation, "note-v1");
});

test("backup verifier parser rejects unsupported version", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ version: 2 }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "unsupported-version");
});

test("backup verifier parser rejects unsupported type", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ type: "plain-sentinel" }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "unsupported-type");
});

test("backup verifier parser rejects unsupported derivation", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ derivation: "root-key-v1" }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "unsupported-derivation");
});

test("backup verifier parser rejects empty recordId", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ recordId: "" }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "invalid-record-id");
});

test("backup verifier parser rejects invalid salt hex", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ salt: "not-hex" }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "invalid-salt");
});

test("backup verifier parser rejects empty ciphertext", () => {
  const result = parseBackupVerifier(validBackupVerifierFixture({ ciphertext: "" }));

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "invalid-ciphertext");
});

test("backup verifier parser rejects invalid expectedPlaintextHash", () => {
  const result = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: "ABC123" }),
  );

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(result.error.code, "invalid-expected-plaintext-hash");
});

test("backup staging preserves valid verifier metadata when present", () => {
  const verifier = validBackupVerifierFixture();
  const result = parsePipassBackup(
    validBackupFixture({ metadata: { app: "PiPass", verifier } }),
  );

  assert.equal(result.ok, true);
  assert.deepEqual(result.backup.metadata.verifier, verifier);

  const verifierResult = getBackupVerifierFromMetadata(result.backup.metadata);
  assert.equal(verifierResult.ok, true);
});

test("backup staging preserves invalid verifier metadata for controlled verifier validation", () => {
  const verifier = validBackupVerifierFixture({ expectedPlaintextHash: "not-valid" });
  const result = parsePipassBackup(
    validBackupFixture({ metadata: { app: "PiPass", verifier } }),
  );

  assert.equal(result.ok, true);
  assert.deepEqual(result.backup.metadata.verifier, verifier);

  const verifierResult = getBackupVerifierFromMetadata(result.backup.metadata);
  assert.equal(verifierResult.ok, false);
  if (verifierResult.ok) {
    throw new Error("expected backup verifier parser failure");
  }
  assert.equal(verifierResult.error.code, "invalid-expected-plaintext-hash");
});

test("backup verifier parser does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const result = parseBackupVerifier(validBackupVerifierFixture());

  assert.equal(result.ok, true);
  assert.equal(storage.items.size, 0);
});

test("backup sentinel verifier accepts entry-v1 when decrypted plaintext hash matches", async () => {
  const plaintext = "pipass-backup-sentinel-v1";
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: sha256Hex(plaintext) }),
  );
  assert.equal(parsed.ok, true);

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "c".repeat(64),
    deriveAndDecryptEntrySentinel: ({ masterKeyHex, recordId, salt, ciphertext }) => {
      assert.equal(masterKeyHex, "c".repeat(64));
      assert.equal(recordId, parsed.verifier.recordId);
      assert.equal(salt, parsed.verifier.salt);
      assert.equal(ciphertext, parsed.verifier.ciphertext);
      return plaintext;
    },
  });

  assert.deepEqual(result, { ok: true });
});

test("backup sentinel verifier accepts note-v1 when decrypted plaintext hash matches", async () => {
  const plaintext = "pipass-backup-note-sentinel-v1";
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({
      derivation: "note-v1",
      expectedPlaintextHash: sha256Hex(plaintext),
    }),
  );
  assert.equal(parsed.ok, true);

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "d".repeat(64),
    deriveAndDecryptNoteSentinel: () => plaintext,
  });

  assert.deepEqual(result, { ok: true });
});

test("backup sentinel verifier fails on hash mismatch", async () => {
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: sha256Hex("expected") }),
  );
  assert.equal(parsed.ok, true);

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "e".repeat(64),
    deriveAndDecryptEntrySentinel: () => "actual",
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup sentinel verification failure");
  }
  assert.equal(result.reason, "hash-mismatch");
});

test("backup sentinel verifier fails on injected decrypt error", async () => {
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: sha256Hex("sentinel") }),
  );
  assert.equal(parsed.ok, true);

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "f".repeat(64),
    deriveAndDecryptEntrySentinel: () => {
      throw new Error("SECRET_DECRYPT_DETAILS");
    },
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup sentinel verification failure");
  }
  assert.equal(result.reason, "decrypt-failed");
  assert.equal(result.message.includes("SECRET_DECRYPT_DETAILS"), false);
});

test("backup sentinel verifier fails on unsupported derivation if reached", async () => {
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: sha256Hex("sentinel") }),
  );
  assert.equal(parsed.ok, true);
  const verifier = { ...parsed.verifier, derivation: "root-key-v1" as "entry-v1" };

  const result = await verifyBackupSentinel({
    verifier,
    masterKeyHex: "a".repeat(64),
    deriveAndDecryptEntrySentinel: () => "sentinel",
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup sentinel verification failure");
  }
  assert.equal(result.reason, "unsupported-derivation");
});

test("backup sentinel verifier does not call note decryptor for entry-v1", async () => {
  const plaintext = "entry-only";
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: sha256Hex(plaintext) }),
  );
  assert.equal(parsed.ok, true);
  let noteCalled = false;

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "b".repeat(64),
    deriveAndDecryptEntrySentinel: () => plaintext,
    deriveAndDecryptNoteSentinel: () => {
      noteCalled = true;
      return plaintext;
    },
  });

  assert.equal(result.ok, true);
  assert.equal(noteCalled, false);
});

test("backup sentinel verifier does not call entry decryptor for note-v1", async () => {
  const plaintext = "note-only";
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({
      derivation: "note-v1",
      expectedPlaintextHash: sha256Hex(plaintext),
    }),
  );
  assert.equal(parsed.ok, true);
  let entryCalled = false;

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "c".repeat(64),
    deriveAndDecryptEntrySentinel: () => {
      entryCalled = true;
      return plaintext;
    },
    deriveAndDecryptNoteSentinel: () => plaintext,
  });

  assert.equal(result.ok, true);
  assert.equal(entryCalled, false);
});

test("backup sentinel verifier does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  const plaintext = "no-storage";
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({ expectedPlaintextHash: sha256Hex(plaintext) }),
  );
  assert.equal(parsed.ok, true);

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "d".repeat(64),
    deriveAndDecryptEntrySentinel: () => plaintext,
  });

  assert.equal(result.ok, true);
  assert.equal(storage.items.size, 0);
});

test("backup sentinel verifier keeps secret values out of controlled error messages", async () => {
  const plaintext = "PLAINTEXT_SENTINEL_SECRET";
  const parsed = parseBackupVerifier(
    validBackupVerifierFixture({
      ciphertext: "CIPHERTEXT_SENTINEL_SECRET",
      expectedPlaintextHash: sha256Hex("different"),
    }),
  );
  assert.equal(parsed.ok, true);

  const result = await verifyBackupSentinel({
    verifier: parsed.verifier,
    masterKeyHex: "e".repeat(64),
    deriveAndDecryptEntrySentinel: () => plaintext,
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected backup sentinel verification failure");
  }
  assert.equal(result.message.includes(plaintext), false);
  assert.equal(result.message.includes(parsed.verifier.ciphertext), false);
  assert.equal(result.message.includes("e".repeat(64)), false);
  assert.equal(result.message.includes(parsed.verifier.salt), false);
  assert.equal(result.message.includes(parsed.verifier.recordId), false);
  assert.equal(result.message.includes(parsed.verifier.expectedPlaintextHash), false);
});

test("staged backup decrypt verification succeeds when all entries and notes decrypt", async () => {
  const stagedBackup = stagedBackupFixture();
  const result = await verifyStagedBackupDecryptability({
    stagedBackup,
    masterKeyHex: "a".repeat(64),
    decryptEntry: ({ entry, masterKeyHex }) => {
      assert.equal(entry.id, "entry-a");
      assert.equal(masterKeyHex, "a".repeat(64));
      return { title: "plaintext title", password: "plaintext password" };
    },
    decryptSecureNote: ({ note, masterKeyHex }) => {
      assert.equal(note.id, "note-a");
      assert.equal(masterKeyHex, "a".repeat(64));
      return { label: "plaintext label", content: "plaintext content" };
    },
  });

  assert.deepEqual(result, {
    ok: true,
    counts: {
      entriesChecked: 1,
      notesChecked: 1,
      entriesFailed: 0,
      notesFailed: 0,
    },
    failures: [],
  });
});

test("staged backup decrypt verification succeeds for an empty staged backup", async () => {
  const stagedBackup = stagedBackupFixture({ entries: [], secureNotes: [] });
  const result = await verifyStagedBackupDecryptability({ stagedBackup });

  assert.deepEqual(result, {
    ok: true,
    counts: {
      entriesChecked: 0,
      notesChecked: 0,
      entriesFailed: 0,
      notesFailed: 0,
    },
    failures: [],
  });
});

test("staged backup decrypt verification fails safely when one entry decrypt fails", async () => {
  const stagedBackup = stagedBackupFixture();
  const result = await verifyStagedBackupDecryptability({
    stagedBackup,
    masterKeyHex: "b".repeat(64),
    decryptEntry: () => {
      throw new Error("PLAINTEXT_OR_KEY_SHOULD_NOT_LEAK");
    },
    decryptSecureNote: () => ({ content: "note plaintext" }),
  });

  assert.equal(result.ok, false);
  assert.deepEqual(result.counts, {
    entriesChecked: 1,
    notesChecked: 1,
    entriesFailed: 1,
    notesFailed: 0,
  });
  assert.deepEqual(result.failures, [
    { kind: "entry", id: "entry-a", index: 0, reason: "decrypt-failed" },
  ]);
});

test("staged backup decrypt verification fails safely when one secure note decrypt fails", async () => {
  const stagedBackup = stagedBackupFixture();
  const result = await verifyStagedBackupDecryptability({
    stagedBackup,
    masterKeyHex: "c".repeat(64),
    decryptEntry: () => ({ password: "entry plaintext" }),
    decryptSecureNote: () => {
      throw new Error("NOTE_PLAINTEXT_SHOULD_NOT_LEAK");
    },
  });

  assert.equal(result.ok, false);
  assert.deepEqual(result.counts, {
    entriesChecked: 1,
    notesChecked: 1,
    entriesFailed: 0,
    notesFailed: 1,
  });
  assert.deepEqual(result.failures, [
    { kind: "secure-note", id: "note-a", index: 0, reason: "decrypt-failed" },
  ]);
});

test("staged backup decrypt verification checks every entry and secure note", async () => {
  const base = validBackupFixture();
  const entries = base.entries as Array<Record<string, unknown>>;
  const secureNotes = base.secureNotes as Array<Record<string, unknown>>;
  const stagedBackup = stagedBackupFixture({
    entries: [
      entries[0],
      { ...entries[0], id: "entry-b", salt: "entry-salt-b" },
      { ...entries[0], id: "entry-c", salt: "entry-salt-c" },
    ],
    secureNotes: [
      secureNotes[0],
      { ...secureNotes[0], id: "note-b", salt: "note-salt-b" },
    ],
  });
  const entriesSeen: string[] = [];
  const notesSeen: string[] = [];

  const result = await verifyStagedBackupDecryptability({
    stagedBackup,
    decryptEntry: ({ entry }) => {
      entriesSeen.push(entry.id);
      return {};
    },
    decryptSecureNote: ({ note }) => {
      notesSeen.push(note.id);
      return {};
    },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(entriesSeen, ["entry-a", "entry-b", "entry-c"]);
  assert.deepEqual(notesSeen, ["note-a", "note-b"]);
  assert.deepEqual(result.counts, {
    entriesChecked: 3,
    notesChecked: 2,
    entriesFailed: 0,
    notesFailed: 0,
  });
});

test("staged backup decrypt verification failure output omits plaintext ciphertext and key material", async () => {
  const stagedBackup = stagedBackupFixture({
    entries: [
      {
        id: "entry-secret",
        title: "display-secret",
        username: "username-secret",
        encryptedPassword: "CIPHERTEXT_SECRET_VALUE",
        salt: "SALT_SECRET_VALUE",
        createdAt: 1,
        updatedAt: 2,
      },
    ],
    secureNotes: [],
  });
  const result = await verifyStagedBackupDecryptability({
    stagedBackup,
    masterKeyHex: "d".repeat(64),
    decryptEntry: () => {
      throw new Error("PLAINTEXT_SECRET_VALUE CIPHERTEXT_SECRET_VALUE ddddd");
    },
  });

  assert.equal(result.ok, false);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes("PLAINTEXT_SECRET_VALUE"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET_VALUE"), false);
  assert.equal(serialized.includes("SALT_SECRET_VALUE"), false);
  assert.equal(serialized.includes("d".repeat(64)), false);
});

test("staged backup decrypt verification does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const result = await verifyStagedBackupDecryptability({
    stagedBackup: stagedBackupFixture(),
    decryptEntry: () => ({}),
    decryptSecureNote: () => ({}),
  });

  assert.equal(result.ok, true);
  assert.equal(storage.items.size, 0);
});

test("staged backup decrypt verification does not mix entry and note decryptors", async () => {
  const stagedBackup = stagedBackupFixture();
  let entryCalls = 0;
  let noteCalls = 0;

  const result = await verifyStagedBackupDecryptability({
    stagedBackup,
    decryptEntry: ({ entry }) => {
      entryCalls++;
      assert.equal(entry.id, "entry-a");
      return {};
    },
    decryptSecureNote: ({ note }) => {
      noteCalls++;
      assert.equal(note.id, "note-a");
      return {};
    },
  });

  assert.equal(result.ok, true);
  assert.equal(entryCalls, 1);
  assert.equal(noteCalls, 1);
});

test("staged backup decrypt verification handles missing decryptors as controlled failures", async () => {
  const stagedBackup = stagedBackupFixture();
  const result = await verifyStagedBackupDecryptability({ stagedBackup });

  assert.equal(result.ok, false);
  assert.deepEqual(result.counts, {
    entriesChecked: 1,
    notesChecked: 1,
    entriesFailed: 1,
    notesFailed: 1,
  });
  assert.deepEqual(result.failures, [
    { kind: "entry", id: "entry-a", index: 0, reason: "missing-decryptor" },
    { kind: "secure-note", id: "note-a", index: 0, reason: "missing-decryptor" },
  ]);
});

test("setup/import commit plan builds setup-only operations with initialized marker last", () => {
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
  });

  assert.equal(result.ok, true);
  const keys = result.plan.operations.map((operation) => operation.key);

  assert.deepEqual(keys, [
    SETUP_IMPORT_STORAGE_KEYS.masterSalt,
    SETUP_IMPORT_STORAGE_KEYS.securityProfile,
    SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
    SETUP_IMPORT_STORAGE_KEYS.masterHash,
    SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
    SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
  ]);
  assert.equal(result.plan.operations.at(-1)?.category, "initialized-marker");
});

test("setup/import commit plan orders entries notes indexes shared vault cache and initialized marker", () => {
  const stagedBackup = stagedBackupFixture();
  const sharedVaultBlob = {
    encryptedBlob: "shared-vault-blob-placeholder",
    version: 1,
    updatedAt: 1234567890,
  };

  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: stagedBackup.entries,
    secureNotes: stagedBackup.secureNotes,
    sharedVaultBlob,
    includeCachedMasterKey: true,
    cachedMasterKeyReference: "prepared-cached-master-key-reference",
  });

  assert.equal(result.ok, true);
  assert.deepEqual(
    result.plan.operations.map((operation) => operation.category),
    [
      "setup-metadata",
      "setup-metadata",
      "setup-metadata",
      "setup-metadata",
      "setup-metadata",
      "vault-entry",
      "vault-index",
      "secure-note",
      "secure-note-index",
      "shared-vault",
      "cached-master-key",
      "initialized-marker",
    ],
  );
  assert.deepEqual(
    result.plan.operations.map((operation) => operation.key),
    [
      SETUP_IMPORT_STORAGE_KEYS.masterSalt,
      SETUP_IMPORT_STORAGE_KEYS.securityProfile,
      SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
      SETUP_IMPORT_STORAGE_KEYS.masterHash,
      SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
      "pipass_vault_entry-a",
      SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
      "pipass_note_note-a",
      SETUP_IMPORT_STORAGE_KEYS.notesIndex,
      SETUP_IMPORT_STORAGE_KEYS.sharedVault,
      SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey,
      SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
    ],
  );
});

test("setup/import rollback manifest includes all planned storage keys", () => {
  const stagedBackup = stagedBackupFixture();
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: stagedBackup.entries,
    secureNotes: stagedBackup.secureNotes,
    sharedVaultBlob: {
      encryptedBlob: "shared-vault-blob-placeholder",
      version: 1,
      updatedAt: 1234567890,
    },
    includeCachedMasterKey: true,
    cachedMasterKeyReference: "prepared-cached-master-key-reference",
  });

  assert.equal(result.ok, true);
  const operationKeys = result.plan.operations.map((operation) => operation.key);
  const rollbackKeys = result.plan.rollbackManifest.targets.map((target) => target.key);

  assert.deepEqual(rollbackKeys, operationKeys);
  assert.deepEqual(result.plan.rollbackManifest.keysToSnapshot, operationKeys);
  assert.deepEqual(result.plan.rollbackManifest.keysToDeleteIfNew, operationKeys);
  assert.equal(
    result.plan.rollbackManifest.initializedMarkerKey,
    SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
  );
});

test("setup/import commit plan rejects missing required setup metadata", () => {
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture({ masterSalt: "" }),
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected setup/import commit plan failure");
  }
  assert.equal(result.error.code, "missing-setup-metadata");
  assert.equal(result.error.path, "setupMetadata.masterSalt");
});

test("setup/import commit plan rejects duplicate entry ids", () => {
  const stagedBackup = stagedBackupFixture();
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: [stagedBackup.entries[0], { ...stagedBackup.entries[0] }],
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected setup/import commit plan failure");
  }
  assert.equal(result.error.code, "duplicate-entry-id");
});

test("setup/import commit plan rejects duplicate secure note ids", () => {
  const stagedBackup = stagedBackupFixture();
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    secureNotes: [stagedBackup.secureNotes[0], { ...stagedBackup.secureNotes[0] }],
  });

  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected setup/import commit plan failure");
  }
  assert.equal(result.error.code, "duplicate-note-id");
});

test("setup/import commit plan rejects empty entry and secure note ids", () => {
  const stagedBackup = stagedBackupFixture();
  const invalidEntryResult = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: [{ ...stagedBackup.entries[0], id: "" }],
  });

  assert.equal(invalidEntryResult.ok, false);
  if (invalidEntryResult.ok) {
    throw new Error("expected setup/import commit plan failure");
  }
  assert.equal(invalidEntryResult.error.code, "invalid-entry-id");

  const invalidNoteResult = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    secureNotes: [{ ...stagedBackup.secureNotes[0], id: "   " }],
  });

  assert.equal(invalidNoteResult.ok, false);
  if (invalidNoteResult.ok) {
    throw new Error("expected setup/import commit plan failure");
  }
  assert.equal(invalidNoteResult.error.code, "invalid-note-id");
});

test("setup/import commit plan writes shared vault after entry records and index", () => {
  const stagedBackup = stagedBackupFixture();
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: stagedBackup.entries,
    sharedVaultBlob: {
      encryptedBlob: "shared-vault-blob-placeholder",
      version: 1,
      updatedAt: 1234567890,
    },
  });

  assert.equal(result.ok, true);
  const keys = result.plan.operations.map((operation) => operation.key);
  const entryIndex = keys.indexOf("pipass_vault_entry-a");
  const vaultIndex = keys.indexOf(SETUP_IMPORT_STORAGE_KEYS.vaultIndex);
  const sharedVaultIndex = keys.indexOf(SETUP_IMPORT_STORAGE_KEYS.sharedVault);

  assert.equal(entryIndex > -1, true);
  assert.equal(vaultIndex > entryIndex, true);
  assert.equal(sharedVaultIndex > vaultIndex, true);
});

test("setup/import commit plan always writes initialized marker last", () => {
  const stagedBackup = stagedBackupFixture();
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: stagedBackup.entries,
    secureNotes: stagedBackup.secureNotes,
    sharedVaultBlob: {
      encryptedBlob: "shared-vault-blob-placeholder",
      version: 1,
      updatedAt: 1234567890,
    },
    includeCachedMasterKey: true,
    cachedMasterKeyReference: "prepared-cached-master-key-reference",
  });

  assert.equal(result.ok, true);
  assert.equal(result.plan.operations.at(-1)?.key, SETUP_IMPORT_STORAGE_KEYS.vaultInitialized);
  assert.equal(result.plan.operations.at(-1)?.category, "initialized-marker");
});

test("setup/import commit plan is deterministic for the same input", () => {
  const stagedBackup = stagedBackupFixture();
  const input = {
    setupMetadata: commitSetupMetadataFixture(),
    entries: stagedBackup.entries,
    secureNotes: stagedBackup.secureNotes,
    sharedVaultBlob: {
      encryptedBlob: "shared-vault-blob-placeholder",
      version: 1,
      updatedAt: 1234567890,
    },
    includeCachedMasterKey: true,
    cachedMasterKeyReference: "prepared-cached-master-key-reference",
  };

  const first = buildSetupImportCommitPlan(input);
  const second = buildSetupImportCommitPlan(input);

  assert.deepEqual(first, second);
});

test("setup/import commit plan helper does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  const stagedBackup = stagedBackupFixture();

  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: stagedBackup.entries,
    secureNotes: stagedBackup.secureNotes,
    sharedVaultBlob: {
      encryptedBlob: "shared-vault-blob-placeholder",
      version: 1,
      updatedAt: 1234567890,
    },
  });

  assert.equal(result.ok, true);
  assert.equal(storage.items.size, 0);
});
