import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
import {
  verifyStagedBackupDecryptability,
  type BackupDecryptVerificationResult,
} from "../../lib/backupDecryptVerification";
import {
  getBackupVerifierFromMetadata,
  isBackupVerifier,
  parseBackupVerifier,
  verifyBackupSentinel,
} from "../../lib/backupVerifier";
import {
  executeSetupImportCommitPlan,
  type SetupImportStorageDriver,
} from "../../lib/setupImportCommitExecutor";
import {
  prepareAndExecuteSetupImportCommit,
  type SetupImportCommitOrchestrationDependencies,
  type SetupImportCommitOrchestrationResult,
} from "../../lib/setupImportCommitOrchestrator";
import {
  buildSetupImportCommitPlan,
  SETUP_IMPORT_STORAGE_KEYS,
  type SetupImportCommitPlan,
} from "../../lib/setupImportCommitPlan";
import {
  buildSetupImportRepairPlan,
  classifySetupImportLocalState,
} from "../../lib/setupImportRepairPlan";
import {
  executeSetupImportRepairPlan,
  type SetupImportRepairStorageDriver,
} from "../../lib/setupImportRepairExecutor";
import {
  confirmStartupRepairDecision,
  decideStartupRepairState,
  readAndDecideStartupRepairState,
  readSetupImportStateSnapshot,
  type SetupImportSnapshotReadDriver,
} from "../../lib/startupRepairDecision";
import { decideStagedBackupCommitGate } from "../../lib/stagedBackupCommitGate";
import { computeStagedBackupPreflightStatus } from "../../lib/stagedBackupBridgeStatus";
import { determineStagedBackupImportTransition } from "../../lib/stagedBackupImportTransition";
import { determineStagedBackupImportCommitEligibility } from "../../lib/stagedBackupImportEligibility";
import { prepareSetupImportCommitFromRuntimeState } from "../../lib/runtimeSetupImportCommit";
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

class CommitPlanMemoryStorage implements SetupImportStorageDriver {
  readonly items = new Map<string, string>();
  readonly calls: string[] = [];
  readonly failSetAttempts = new Set<string>();
  readonly failDeleteAttempts = new Set<string>();
  private readonly setAttempts = new Map<string, number>();
  private readonly deleteAttempts = new Map<string, number>();

  constructor(initialItems: Record<string, string> = {}) {
    for (const [key, value] of Object.entries(initialItems)) {
      this.items.set(key, value);
    }
  }

  async getItem(key: string): Promise<string | null> {
    this.calls.push(`get:${key}`);
    return this.items.get(key) ?? null;
  }

  async setItem(key: string, value: string): Promise<void> {
    const attempt = (this.setAttempts.get(key) ?? 0) + 1;
    this.setAttempts.set(key, attempt);
    this.calls.push(`set:${key}`);
    if (this.failSetAttempts.has(`${key}#${attempt}`)) {
      throw new Error(`set failed for ${key}`);
    }
    this.items.set(key, value);
  }

  async deleteItem(key: string): Promise<void> {
    const attempt = (this.deleteAttempts.get(key) ?? 0) + 1;
    this.deleteAttempts.set(key, attempt);
    this.calls.push(`delete:${key}`);
    if (this.failDeleteAttempts.has(`${key}#${attempt}`)) {
      throw new Error(`delete failed for ${key}`);
    }
    this.items.delete(key);
  }
}

class RepairPlanMemoryStorage implements SetupImportRepairStorageDriver {
  readonly items = new Map<string, string>();
  readonly deletedKeys: string[] = [];
  readonly failDeleteKeys = new Set<string>();

  constructor(initialItems: Record<string, string> = {}) {
    for (const [key, value] of Object.entries(initialItems)) {
      this.items.set(key, value);
    }
  }

  async deleteItem(key: string): Promise<void> {
    this.deletedKeys.push(key);
    if (this.failDeleteKeys.has(key)) {
      throw new Error(`delete failed for ${key}`);
    }
    this.items.delete(key);
  }
}

class StartupSnapshotMemoryReader implements SetupImportSnapshotReadDriver {
  readonly items = new Map<string, string>();
  readonly keysRead: string[] = [];
  readonly keysWritten: string[] = [];
  readonly keysDeleted: string[] = [];
  readonly failReadKeys = new Set<string>();

  constructor(initialItems: Record<string, string> = {}) {
    for (const [key, value] of Object.entries(initialItems)) {
      this.items.set(key, value);
    }
  }

  async getItem(key: string): Promise<string | null> {
    this.keysRead.push(key);
    if (this.failReadKeys.has(key)) {
      throw new Error(`read failed for ${key}`);
    }
    return this.items.get(key) ?? null;
  }
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

function compatibleBackupGateResult(warnings: string[] = []) {
  return {
    status: "compatible" as const,
    reason: "same-install-metadata-match",
    warnings,
  };
}

function incompatibleBackupGateResult(warnings: string[] = []) {
  return {
    status: "incompatible" as const,
    reason: "kdf-metadata-mismatch",
    warnings,
  };
}

function unknownBackupGateResult(warnings: string[] = []) {
  return {
    status: "unknown" as const,
    reason: "missing-compatibility-metadata",
    warnings,
  };
}

function decryptabilityGateResult(ok: boolean = true): BackupDecryptVerificationResult {
  if (ok) {
    return {
      ok: true as const,
      counts: {
        entriesChecked: 1,
        notesChecked: 1,
        entriesFailed: 0,
        notesFailed: 0,
      },
      failures: [],
    };
  }

  return {
    ok: false as const,
    counts: {
      entriesChecked: 1,
      notesChecked: 1,
      entriesFailed: 1,
      notesFailed: 0,
    },
    failures: [
      {
        kind: "entry" as const,
        id: "entry-a",
        index: 0,
        reason: "decrypt-failed" as const,
      },
    ],
  };
}

function eligibleImportCommitInput(
  overrides: Partial<Parameters<typeof determineStagedBackupImportCommitEligibility>[0]> = {},
): Parameters<typeof determineStagedBackupImportCommitEligibility>[0] {
  return {
    stagedBackupPresent: true,
    stagedBackupFormat: "encrypted-local-records",
    compatibilityStatus: "compatible",
    verifierStatus: "missing",
    sentinelStatus: "not-needed",
    decryptabilityStatus: "passed",
    featureFlagEnabled: true,
    ...overrides,
  };
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

function commitPlanFixture(options: {
  includeEntries?: boolean;
  includeNotes?: boolean;
  includeSharedVault?: boolean;
  includeCachedKey?: boolean;
} = {}): SetupImportCommitPlan {
  const stagedBackup = stagedBackupFixture();
  const result = buildSetupImportCommitPlan({
    setupMetadata: commitSetupMetadataFixture(),
    entries: options.includeEntries ? stagedBackup.entries : undefined,
    secureNotes: options.includeNotes ? stagedBackup.secureNotes : undefined,
    sharedVaultBlob: options.includeSharedVault
      ? {
          encryptedBlob: "shared-vault-blob-placeholder",
          version: 1,
          updatedAt: 1234567890,
        }
      : undefined,
    includeCachedMasterKey: options.includeCachedKey,
    cachedMasterKeyReference: options.includeCachedKey
      ? "prepared-cached-master-key-reference"
      : undefined,
  });

  assert.equal(result.ok, true);
  return result.plan;
}

function backupVerifierFixture() {
  const result = parseBackupVerifier(validBackupVerifierFixture());

  assert.equal(result.ok, true);
  return result.verifier;
}

function commitOrchestrationDependencies(
  calls: string[] = [],
  overrides: Partial<SetupImportCommitOrchestrationDependencies> = {},
): SetupImportCommitOrchestrationDependencies {
  return {
    classifyCompatibility: () => {
      calls.push("compatibility");
      return {
        status: "compatible",
        reason: "same-install-metadata-match",
        warnings: ["safe compatibility warning"],
      };
    },
    verifySentinel: () => {
      calls.push("sentinel");
      return { ok: true };
    },
    verifyDecryptability: (stagedBackup) => {
      calls.push("decryptability");
      return {
        ok: true,
        counts: {
          entriesChecked: stagedBackup.entries.length,
          notesChecked: stagedBackup.secureNotes.length,
          entriesFailed: 0,
          notesFailed: 0,
        },
        failures: [],
      };
    },
    buildSharedVaultBlob: () => {
      calls.push("shared-vault");
      return {
        encryptedBlob: "shared-vault-blob-placeholder",
        version: 1,
        updatedAt: 1234567890,
      };
    },
    buildPlan: (input) => {
      calls.push("plan");
      return buildSetupImportCommitPlan(input);
    },
    executePlan: (plan) => {
      calls.push("commit");
      return {
        success: true,
        operationsApplied: plan.operations.length,
        rollbackStatus: "not-needed",
      };
    },
    ...overrides,
  };
}

function assertOrchestrationFailure(
  result: SetupImportCommitOrchestrationResult,
): asserts result is Extract<SetupImportCommitOrchestrationResult, { ok: false }> {
  assert.equal(result.ok, false);
  if (result.ok) {
    throw new Error("expected setup/import commit orchestration failure");
  }
}

function setupMetadataSnapshot() {
  return {
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.masterHash]: "master-hash-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.securityProfile]: "100000",
    [SETUP_IMPORT_STORAGE_KEYS.kdfMetadata]: "kdf-metadata-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash]: "recovery-hash-placeholder",
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

test("staged backup commit gate allows setup-only when no backup is staged", () => {
  const decision = decideStagedBackupCommitGate({ stagedBackupPresent: false });

  assert.deepEqual(decision, {
    allowed: true,
    mode: "setup-only",
    reason: "no-backup",
    warnings: [],
    safeMessage: "No staged backup is attached. Setup can continue without importing backup records.",
  });
});

test("staged backup commit gate blocks unsupported format", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "portable-encrypted-records",
    compatibility: compatibleBackupGateResult(),
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.mode, "setup-only");
  assert.equal(decision.reason, "unsupported-format");
});

test("staged backup commit gate blocks incompatible compatibility", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: incompatibleBackupGateResult(),
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "incompatible");
});

test("staged backup commit gate blocks unknown compatibility by default", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: unknownBackupGateResult(),
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "unknown-compatibility");
});

test("staged backup commit gate allowUnknownCompatibility still requires decryptability", () => {
  const missingDecryptability = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: unknownBackupGateResult(),
    options: { allowUnknownCompatibility: true },
  });
  const passingDecryptability = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: unknownBackupGateResult(),
    decryptability: decryptabilityGateResult(),
    options: { allowUnknownCompatibility: true },
  });

  assert.equal(missingDecryptability.allowed, false);
  assert.equal(missingDecryptability.reason, "decryptability-not-run");
  assert.equal(passingDecryptability.allowed, true);
  assert.equal(passingDecryptability.mode, "commit-staged-backup");
});

test("staged backup commit gate blocks invalid verifier", () => {
  const verifier = parseBackupVerifier(validBackupVerifierFixture({ version: 2 }));
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    verifier,
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "invalid-verifier");
});

test("staged backup commit gate allows missing verifier by default when decryptability passes", () => {
  const verifier = getBackupVerifierFromMetadata({});
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    verifier,
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, true);
  assert.equal(decision.mode, "commit-staged-backup");
  assert.equal(decision.reason, "allowed");
});

test("staged backup commit gate blocks missing verifier when required", () => {
  const verifier = getBackupVerifierFromMetadata({});
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    verifier,
    decryptability: decryptabilityGateResult(),
    options: { requireVerifier: true },
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "missing-verifier");
});

test("staged backup commit gate blocks verifier present but sentinel not run", () => {
  const verifier = parseBackupVerifier(validBackupVerifierFixture());
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    verifier,
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "sentinel-failed");
});

test("staged backup commit gate blocks sentinel failure", () => {
  const verifier = parseBackupVerifier(validBackupVerifierFixture());
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    verifier,
    sentinelVerification: {
      ok: false,
      reason: "hash-mismatch",
      message: "Backup verifier hash did not match.",
    },
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "sentinel-failed");
});

test("staged backup commit gate blocks missing decryptability", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "decryptability-not-run");
});

test("staged backup commit gate blocks decryptability failure", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    decryptability: decryptabilityGateResult(false),
  });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, "decryptability-failed");
});

test("staged backup commit gate allows compatible backup with decryptability success", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    decryptability: decryptabilityGateResult(),
  });

  assert.deepEqual(decision, {
    allowed: true,
    mode: "commit-staged-backup",
    reason: "allowed",
    warnings: [],
    safeMessage: "This staged backup passed the required import gates.",
  });
});

test("staged backup commit gate blocks honeytoken warnings unless allowed", () => {
  const warning = "backup contains encrypted honeytoken aux metadata with SECRET_RECORD_ID";
  const blocked = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult([warning]),
    decryptability: decryptabilityGateResult(),
  });
  const allowed = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult([warning]),
    decryptability: decryptabilityGateResult(),
    options: { allowHoneytokenWarnings: true },
  });

  assert.equal(blocked.allowed, false);
  assert.equal(blocked.reason, "warnings-blocked");
  assert.deepEqual(blocked.warnings, [
    "Backup contains decoy trigger metadata that may need review after import.",
  ]);
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.reason, "allowed");
});

test("staged backup commit gate output contains no secret raw backup values", () => {
  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult([
      "CIPHERTEXT_SECRET SALT_SECRET HASH_SECRET deviceUUID SECRET_RECORD_ID",
    ]),
    decryptability: decryptabilityGateResult(false),
  });
  const serialized = JSON.stringify(decision);

  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("SALT_SECRET"), false);
  assert.equal(serialized.includes("HASH_SECRET"), false);
  assert.equal(serialized.includes("deviceUUID"), false);
  assert.equal(serialized.includes("SECRET_RECORD_ID"), false);
});

test("staged backup commit gate does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const decision = decideStagedBackupCommitGate({
    stagedBackupPresent: true,
    format: "encrypted-local-records",
    compatibility: compatibleBackupGateResult(),
    decryptability: decryptabilityGateResult(),
  });

  assert.equal(decision.allowed, true);
  assert.equal(storage.items.size, 0);
});

test("runtime staged backup preflight returns setup-only status when no backup is staged", () => {
  const status = computeStagedBackupPreflightStatus();

  assert.deepEqual(status, {
    kind: "no-backup",
    transitionStatus: "no-backup",
    stagedBackupPresent: false,
    setupAllowed: true,
    recordsWillBeCommitted: false,
    gateAllowed: true,
    gateReason: "no-backup",
    warnings: [],
    safeMessage: "Setup can continue without backup records.",
  });
});

test("runtime staged backup preflight uses checked-only transition when commit is disabled", () => {
  const status = computeStagedBackupPreflightStatus({
    stagedBackup: stagedBackupWithCompatibility(),
    gateInput: {
      compatibility: compatibleBackupGateResult(),
      decryptability: decryptabilityGateResult(),
    },
  });

  assert.equal(status.kind, "checked-only-not-imported-yet");
  assert.equal(status.transitionStatus, "checked-only");
  assert.equal(status.setupAllowed, true);
  assert.equal(status.recordsWillBeCommitted, false);
  assert.equal(status.gateAllowed, true);
  assert.equal(status.gateReason, "allowed");
  assert.equal(
    status.safeMessage,
    "Backup records are staged in memory and will not be added to this vault in this setup step.",
  );
  assert.equal(status.safeMessage.includes("will not be added"), true);
  assert.equal(status.safeMessage.includes("this setup step"), true);
  assert.equal(status.safeMessage.toLowerCase().includes("imported"), false);
  assert.equal(status.safeMessage.toLowerCase().includes("restored"), false);
});

test("runtime staged backup preflight stays checked-only for blocked gates while commit is disabled", () => {
  const status = computeStagedBackupPreflightStatus({
    stagedBackup: stagedBackupWithCompatibility(),
    gateInput: {
      compatibility: incompatibleBackupGateResult(),
    },
  });

  assert.equal(status.kind, "checked-only-not-imported-yet");
  assert.equal(status.transitionStatus, "checked-only");
  assert.equal(status.setupAllowed, true);
  assert.equal(status.recordsWillBeCommitted, false);
  assert.equal(status.gateAllowed, false);
  assert.equal(status.gateReason, "incompatible");
  assert.equal(
    status.safeMessage,
    "Backup records are staged in memory and will not be added to this vault in this setup step.",
  );
});

test("runtime staged backup preflight can require clearing blocked backup before setup", () => {
  const status = computeStagedBackupPreflightStatus({
    stagedBackup: stagedBackupWithCompatibility(),
    gateInput: {
      compatibility: incompatibleBackupGateResult(),
    },
    importCommitEnabled: true,
    blockSetupWhenGateBlocked: true,
  });

  assert.equal(status.kind, "gate-blocked-clear-required");
  assert.equal(status.transitionStatus, "blocked-import");
  assert.equal(status.setupAllowed, false);
  assert.equal(status.recordsWillBeCommitted, false);
  assert.equal(status.gateReason, "incompatible");
});

test("runtime staged backup preflight output contains no secret raw backup values", () => {
  const secret = "PLAINTEXT_SECRET CIPHERTEXT_SECRET HASH_SECRET SALT_SECRET deviceUUID SECRET_RECORD_ID";
  const backup = validBackupFixture();
  const [entry] = backup.entries as Record<string, unknown>[];
  const status = computeStagedBackupPreflightStatus({
    stagedBackup: stagedBackupFixture({
      entries: [
        {
          ...entry,
          id: "entry-secret",
          encryptedPassword: secret,
        },
      ],
    }),
    gateInput: {
      compatibility: compatibleBackupGateResult([secret]),
      decryptability: decryptabilityGateResult(),
    },
  });
  const serialized = JSON.stringify(status);

  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("HASH_SECRET"), false);
  assert.equal(serialized.includes("SALT_SECRET"), false);
  assert.equal(serialized.includes("deviceUUID"), false);
  assert.equal(serialized.includes("SECRET_RECORD_ID"), false);
  assert.equal(status.recordsWillBeCommitted, false);
});

test("runtime staged backup preflight does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const status = computeStagedBackupPreflightStatus({
    stagedBackup: stagedBackupWithCompatibility(),
    gateInput: {
      compatibility: compatibleBackupGateResult(),
      decryptability: decryptabilityGateResult(),
    },
  });

  assert.equal(status.kind, "checked-only-not-imported-yet");
  assert.equal(status.transitionStatus, "checked-only");
  assert.equal(storage.items.size, 0);
});

test("staged backup import transition returns no-backup setup continuation", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: false,
    importCommitEnabled: false,
    gateDecision: null,
  });

  assert.deepEqual(transition, {
    status: "no-backup",
    canContinueSetup: true,
    canAttemptImport: false,
    requiresClearOrDismiss: false,
    safeTitle: "No backup selected",
    safeMessage: "Setup can continue without backup records.",
    warnings: [],
  });
});

test("staged backup import transition keeps checked-only state when commit is disabled", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: false,
    gateDecision: {
      allowed: true,
      mode: "commit-staged-backup",
      reason: "allowed",
      warnings: [],
      safeMessage: "SECRET_GATE_MESSAGE",
    },
  });

  assert.equal(transition.status, "checked-only");
  assert.equal(transition.canContinueSetup, true);
  assert.equal(transition.canAttemptImport, false);
  assert.equal(
    transition.safeMessage,
    "Backup records are staged in memory and will not be added to this vault in this setup step.",
  );
});

test("staged backup import transition reports ready-to-import only for allowed gate with commit enabled", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    gateDecision: {
      allowed: true,
      mode: "commit-staged-backup",
      reason: "allowed",
      warnings: [],
      safeMessage: "This staged backup passed the required import gates.",
    },
  });
  const serialized = JSON.stringify({
    safeTitle: transition.safeTitle,
    safeMessage: transition.safeMessage,
  }).toLowerCase();

  assert.equal(transition.status, "ready-to-import");
  assert.equal(transition.canContinueSetup, true);
  assert.equal(transition.canAttemptImport, true);
  assert.equal(transition.requiresClearOrDismiss, false);
  assert.equal(serialized.includes("imported"), false);
  assert.equal(serialized.includes("restored"), false);
});

test("staged backup import transition blocks import by default when gate blocks", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    gateDecision: {
      allowed: false,
      mode: "setup-only",
      reason: "incompatible",
      warnings: [],
      safeMessage: "This backup does not match the current local vault setup.",
    },
  });

  assert.equal(transition.status, "blocked-import");
  assert.equal(transition.canAttemptImport, false);
  assert.equal(transition.canContinueSetup, false);
  assert.equal(transition.requiresClearOrDismiss, true);
});

test("staged backup import transition allows setup-only after blocked import dismissal", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    userDismissedImport: true,
    gateDecision: {
      allowed: false,
      mode: "setup-only",
      reason: "unknown-compatibility",
      warnings: [],
      safeMessage: "PiPass cannot prove this backup is compatible yet.",
    },
  });

  assert.equal(transition.status, "setup-only-dismissed");
  assert.equal(transition.canContinueSetup, true);
  assert.equal(transition.canAttemptImport, false);
  assert.equal(transition.requiresClearOrDismiss, false);
  assert.equal(
    transition.safeMessage,
    "Backup import was dismissed. Setup can continue without adding backup records.",
  );
});

test("staged backup import transition reports import-committed after durable success", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    importCommitted: true,
    gateDecision: {
      allowed: true,
      mode: "commit-staged-backup",
      reason: "allowed",
      warnings: [],
      safeMessage: "This staged backup passed the required import gates.",
    },
  });

  assert.equal(transition.status, "import-committed");
  assert.equal(transition.canContinueSetup, true);
  assert.equal(transition.canAttemptImport, false);
  assert.equal(transition.safeTitle, "Backup imported");
  assert.equal(
    transition.safeMessage,
    "Backup records were added only after setup/import commit completed.",
  );
});

test("staged backup import transition limits committed wording to committed state", () => {
  const states = [
    determineStagedBackupImportTransition({
      stagedBackupPresent: false,
      importCommitEnabled: false,
      gateDecision: null,
    }),
    determineStagedBackupImportTransition({
      stagedBackupPresent: true,
      importCommitEnabled: false,
      gateDecision: null,
    }),
    determineStagedBackupImportTransition({
      stagedBackupPresent: true,
      importCommitEnabled: true,
      gateDecision: {
        allowed: true,
        mode: "commit-staged-backup",
        reason: "allowed",
        warnings: [],
        safeMessage: "This staged backup passed the required import gates.",
      },
    }),
    determineStagedBackupImportTransition({
      stagedBackupPresent: true,
      importCommitEnabled: true,
      gateDecision: {
        allowed: false,
        mode: "setup-only",
        reason: "decryptability-failed",
        warnings: [],
        safeMessage: "PiPass could not verify every staged backup record.",
      },
    }),
    determineStagedBackupImportTransition({
      stagedBackupPresent: true,
      importCommitEnabled: true,
      userDismissedImport: true,
      gateDecision: {
        allowed: false,
        mode: "setup-only",
        reason: "warnings-blocked",
        warnings: [],
        safeMessage: "This backup has decoy trigger metadata that needs review before import.",
      },
    }),
  ];

  for (const state of states) {
    const serialized = JSON.stringify({
      safeTitle: state.safeTitle,
      safeMessage: state.safeMessage,
    }).toLowerCase();
    assert.equal(serialized.includes("imported"), false);
    assert.equal(serialized.includes("restored"), false);
    assert.equal(serialized.includes("committed"), false);
  }
});

test("staged backup import transition preserves only safe warning text", () => {
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    gateDecision: {
      allowed: false,
      mode: "setup-only",
      reason: "warnings-blocked",
      warnings: [
        "Backup has a non-blocking warning that should be reviewed before import.",
        "CIPHERTEXT_SECRET SALT_SECRET HASH_SECRET deviceUUID SECRET_RECORD_ID",
      ],
      safeMessage: "SECRET_GATE_MESSAGE",
    },
  });

  assert.deepEqual(transition.warnings, [
    "Backup has a non-blocking warning that should be reviewed before import.",
    "Backup has a warning that should be reviewed before records can be added.",
  ]);
});

test("staged backup import transition output contains no raw backup secrets", () => {
  const secret = "PLAINTEXT_SECRET CIPHERTEXT_SECRET HASH_SECRET SALT_SECRET deviceUUID SECRET_RECORD_ID";
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    gateDecision: {
      allowed: false,
      mode: "setup-only",
      reason: "decryptability-failed",
      warnings: [secret],
      safeMessage: secret,
    },
  });
  const serialized = JSON.stringify(transition);

  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("HASH_SECRET"), false);
  assert.equal(serialized.includes("SALT_SECRET"), false);
  assert.equal(serialized.includes("deviceUUID"), false);
  assert.equal(serialized.includes("SECRET_RECORD_ID"), false);
});

test("staged backup import transition helper does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled: true,
    gateDecision: {
      allowed: true,
      mode: "commit-staged-backup",
      reason: "allowed",
      warnings: [],
      safeMessage: "This staged backup passed the required import gates.",
    },
  });

  assert.equal(transition.status, "ready-to-import");
  assert.equal(storage.items.size, 0);
});

test("staged backup import eligibility returns not-selected without enabling import", () => {
  const eligibility = determineStagedBackupImportCommitEligibility({
    stagedBackupPresent: false,
    featureFlagEnabled: true,
  });

  assert.equal(eligibility.status, "not-selected");
  assert.equal(eligibility.reason, "no-backup");
  assert.equal(eligibility.importCommitEnabled, false);
  assert.equal(eligibility.setupOnlyAllowed, true);
  assert.equal(eligibility.canAttemptImport, false);
});

test("staged backup import eligibility stays not-yet-enabled when feature flag is disabled", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ featureFlagEnabled: false }),
  );

  assert.equal(eligibility.status, "not-yet-enabled");
  assert.equal(eligibility.reason, "feature-disabled");
  assert.equal(eligibility.importCommitEnabled, false);
  assert.equal(eligibility.setupOnlyAllowed, true);
  assert.equal(
    eligibility.safeMessage,
    "Backup records are staged in memory and will not be added to this vault in this setup step.",
  );
});

test("staged backup import eligibility blocks unsupported format", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ stagedBackupFormat: "portable-encrypted-records" }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "unsupported-format");
  assert.equal(eligibility.importCommitEnabled, false);
});

test("staged backup import eligibility blocks incompatible compatibility", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ compatibilityStatus: "incompatible" }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "incompatible");
  assert.equal(eligibility.requiresClearOrDismiss, true);
});

test("staged backup import eligibility blocks unknown compatibility by default", () => {
  const unknown = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ compatibilityStatus: "unknown" }),
  );
  const missing = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ compatibilityStatus: "missing" }),
  );

  assert.equal(unknown.status, "blocked");
  assert.equal(unknown.reason, "unknown-compatibility");
  assert.equal(missing.status, "blocked");
  assert.equal(missing.reason, "missing-compatibility");
});

test("staged backup import eligibility allows missing verifier by default", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ verifierStatus: "missing" }),
  );

  assert.equal(eligibility.status, "eligible");
  assert.equal(eligibility.importCommitEnabled, true);
  assert.equal(eligibility.canAttemptImport, true);
});

test("staged backup import eligibility blocks missing verifier when required", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      verifierStatus: "missing",
      options: { requireVerifier: true },
    }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "missing-verifier");
});

test("staged backup import eligibility blocks invalid verifier", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ verifierStatus: "invalid" }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "invalid-verifier");
});

test("staged backup import eligibility blocks valid verifier when sentinel is not run", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      verifierStatus: "valid",
      sentinelStatus: "not-run",
    }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "sentinel-not-run");
});

test("staged backup import eligibility blocks valid verifier when sentinel fails", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      verifierStatus: "valid",
      sentinelStatus: "failed",
    }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "sentinel-failed");
});

test("staged backup import eligibility with passed sentinel continues to decryptability gate", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      verifierStatus: "valid",
      sentinelStatus: "passed",
      decryptabilityStatus: "not-run",
    }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "decryptability-not-run");
});

test("staged backup import eligibility blocks decryptability not-run", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ decryptabilityStatus: "not-run" }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "decryptability-not-run");
});

test("staged backup import eligibility blocks decryptability failure", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({ decryptabilityStatus: "failed" }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "decryptability-failed");
});

test("staged backup import eligibility blocks honeytoken warnings by default", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      warningKinds: ["encryptedAux honeytoken SECRET_RECORD_ID"],
    }),
  );

  assert.equal(eligibility.status, "blocked");
  assert.equal(eligibility.reason, "warnings-blocked");
  assert.deepEqual(eligibility.warnings, [
    "Backup contains decoy trigger metadata that must be reviewed before import.",
  ]);
});

test("staged backup import eligibility can allow honeytoken warnings by option", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      warningKinds: ["encryptedAux honeytoken SECRET_RECORD_ID"],
      options: { blockHoneytokenWarnings: false },
    }),
  );

  assert.equal(eligibility.status, "eligible");
  assert.equal(eligibility.reason, "eligible");
  assert.equal(eligibility.importCommitEnabled, true);
  assert.deepEqual(eligibility.warnings, [
    "Backup contains decoy trigger metadata that must be reviewed before import.",
  ]);
});

test("staged backup import eligibility requires explicit import intent when configured", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      options: { requireExplicitImportIntent: true },
      userConfirmedImportIntent: false,
    }),
  );

  assert.equal(eligibility.status, "requires-clear-or-dismiss");
  assert.equal(eligibility.reason, "import-intent-required");
  assert.equal(eligibility.importCommitEnabled, false);
  assert.equal(eligibility.setupOnlyAllowed, false);
  assert.equal(eligibility.requiresClearOrDismiss, true);
});

test("staged backup import eligibility dismissal allows setup-only without import", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      options: { requireExplicitImportIntent: true },
      userConfirmedImportIntent: false,
      userDismissedImport: true,
    }),
  );

  assert.equal(eligibility.status, "requires-clear-or-dismiss");
  assert.equal(eligibility.importCommitEnabled, false);
  assert.equal(eligibility.setupOnlyAllowed, true);
  assert.equal(eligibility.canAttemptImport, false);
  assert.equal(
    eligibility.safeMessage,
    "Backup import was dismissed. Setup can continue without adding backup records.",
  );
});

test("staged backup import eligibility returns eligible when all gates pass", () => {
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      verifierStatus: "valid",
      sentinelStatus: "passed",
      userConfirmedImportIntent: true,
      options: { requireExplicitImportIntent: true },
    }),
  );

  assert.equal(eligibility.status, "eligible");
  assert.equal(eligibility.reason, "eligible");
  assert.equal(eligibility.importCommitEnabled, true);
  assert.equal(eligibility.setupOnlyAllowed, true);
  assert.equal(eligibility.canAttemptImport, true);
});

test("staged backup import eligibility output contains no raw backup secrets", () => {
  const secret = "PLAINTEXT_SECRET CIPHERTEXT_SECRET HASH_SECRET SALT_SECRET deviceUUID SECRET_RECORD_ID";
  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput({
      stagedBackupFormat: secret,
      warningKinds: [secret],
    }),
  );
  const serialized = JSON.stringify(eligibility);

  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("HASH_SECRET"), false);
  assert.equal(serialized.includes("SALT_SECRET"), false);
  assert.equal(serialized.includes("deviceUUID"), false);
  assert.equal(serialized.includes("SECRET_RECORD_ID"), false);
});

test("staged backup import eligibility helper does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const eligibility = determineStagedBackupImportCommitEligibility(
    eligibleImportCommitInput(),
  );

  assert.equal(eligibility.status, "eligible");
  assert.equal(storage.items.size, 0);
});

test("runtime setup/import commit shape uses setup-only orchestration with no staged backup", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: null,
    eligibilityInput: { stagedBackupPresent: false, featureFlagEnabled: true },
    dependencies: commitOrchestrationDependencies(calls),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "setup-only");
  assert.equal(result.recordsIncluded, false);
  assert.equal(result.activeSharesPublished, false);
  assert.deepEqual(calls, ["plan", "commit"]);
});

test("runtime setup/import commit shape keeps feature-disabled staged backup setup-only", async () => {
  const calls: string[] = [];
  let operationCategories: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput({ featureFlagEnabled: false }),
    dependencies: commitOrchestrationDependencies(calls, {
      executePlan: (plan) => {
        calls.push("commit");
        operationCategories = plan.operations.map((operation) => operation.category);
        return {
          success: true,
          operationsApplied: plan.operations.length,
          rollbackStatus: "not-needed",
        };
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "setup-only");
  assert.equal(result.eligibility.status, "not-yet-enabled");
  assert.equal(result.recordsIncluded, false);
  assert.deepEqual(calls, ["plan", "commit"]);
  assert.equal(operationCategories.includes("vault-entry"), false);
  assert.equal(operationCategories.includes("secure-note"), false);
});

test("runtime setup/import commit shape stops at blocked eligibility before staged commit work", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput({
      compatibilityStatus: "incompatible",
    }),
    dependencies: commitOrchestrationDependencies(calls),
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "eligibility");
  assert.equal(result.reason, "incompatible");
  assert.equal(result.recordsIncluded, false);
  assert.equal(result.activeSharesPublished, false);
  assert.deepEqual(calls, []);
});

test("runtime setup/import commit shape evaluates eligibility before staged orchestrator work", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput(),
    determineEligibility: (input) => {
      calls.push("eligibility");
      return determineStagedBackupImportCommitEligibility(input);
    },
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: (gateInput) => {
        calls.push("gate");
        return decideStagedBackupCommitGate(gateInput);
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "commit");
  assert.equal(result.recordsIncluded, true);
  assert.deepEqual(calls, [
    "eligibility",
    "compatibility",
    "decryptability",
    "gate",
    "shared-vault",
    "plan",
    "commit",
  ]);
});

test("runtime setup/import commit shape runs gate before shared vault plan and executor", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput(),
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: (gateInput) => {
        calls.push("gate");
        return decideStagedBackupCommitGate(gateInput);
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.deepEqual(calls.slice(-4), ["gate", "shared-vault", "plan", "commit"]);
});

test("runtime setup/import commit shape skips shared vault build when decryptability fails", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput(),
    dependencies: commitOrchestrationDependencies(calls, {
      verifyDecryptability: () => {
        calls.push("decryptability");
        return decryptabilityGateResult(false);
      },
      decideCommitGate: (gateInput) => {
        calls.push("gate");
        return decideStagedBackupCommitGate(gateInput);
      },
    }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "gate");
  assert.equal(result.reason, "decryptability-failed");
  assert.deepEqual(calls, ["compatibility", "decryptability", "gate"]);
});

test("runtime setup/import commit shape stops before plan and executor when shared vault build fails", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput(),
    dependencies: commitOrchestrationDependencies(calls, {
      buildSharedVaultBlob: () => {
        calls.push("shared-vault");
        throw new Error("SECRET_SHARED_VAULT_CONTENT");
      },
    }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "shared-vault");
  assert.equal(result.reason, "shared-vault-build-failed");
  assert.deepEqual(calls, ["compatibility", "decryptability", "shared-vault"]);
});

test("runtime setup/import commit shape returns safe executor failure without publishing shares", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput(),
    dependencies: commitOrchestrationDependencies(calls, {
      executePlan: () => {
        calls.push("commit");
        return {
          success: false,
          reason: "write-failed",
          message: "Setup/import commit write failed",
          operationsApplied: 2,
          rollbackStatus: "completed",
        };
      },
    }),
  });
  const serialized = JSON.stringify(result);

  assert.equal(result.ok, false);
  assert.equal(result.stage, "commit");
  assert.equal(result.reason, "write-failed");
  assert.equal(result.recordsIncluded, false);
  assert.equal(result.activeSharesPublished, false);
  assert.equal(serialized.includes("SECRET_SHARED_VAULT_CONTENT"), false);
});

test("runtime setup/import commit shape succeeds through injected staged path safely", async () => {
  const calls: string[] = [];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    eligibilityInput: eligibleImportCommitInput({
      verifierStatus: "valid",
      sentinelStatus: "passed",
    }),
    backupVerifier: backupVerifierFixture(),
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: (gateInput) => {
        calls.push("gate");
        return decideStagedBackupCommitGate(gateInput);
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "commit");
  assert.equal(result.recordsIncluded, true);
  assert.equal(result.activeSharesPublished, false);
  assert.deepEqual(calls, [
    "compatibility",
    "sentinel",
    "decryptability",
    "gate",
    "shared-vault",
    "plan",
    "commit",
  ]);
});

test("runtime setup/import commit shape output contains no raw backup or key material", async () => {
  const secret = "PLAINTEXT_SECRET CIPHERTEXT_SECRET HASH_SECRET SALT_SECRET deviceUUID RECOVERY_KEY MASTER_KEY";
  const backup = validBackupFixture();
  const [entry] = backup.entries as Record<string, unknown>[];
  const result = await prepareSetupImportCommitFromRuntimeState({
    setupMetadata: commitSetupMetadataFixture({
      masterHash: "HASH_SECRET",
      recoveryKeyHash: "RECOVERY_KEY",
    }),
    stagedBackup: stagedBackupFixture({
      entries: [
        {
          ...entry,
          id: "SECRET_RECORD_ID",
          encryptedPassword: secret,
        },
      ],
    }),
    eligibilityInput: eligibleImportCommitInput(),
    dependencies: commitOrchestrationDependencies(),
  });
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("HASH_SECRET"), false);
  assert.equal(serialized.includes("SALT_SECRET"), false);
  assert.equal(serialized.includes("deviceUUID"), false);
  assert.equal(serialized.includes("RECOVERY_KEY"), false);
  assert.equal(serialized.includes("MASTER_KEY"), false);
  assert.equal(serialized.includes("SECRET_RECORD_ID"), false);
});

test("SeedSetupScreen backup selection remains staged-only without immediate writes", () => {
  const source = readFileSync("screens/SeedSetupScreen.tsx", "utf8");
  const forbiddenImmediateWriteHelpers = [
    "saveEntry",
    "saveSecureNote",
    "syncSharedVaultBlob",
    "buildSetupImportCommitPlan",
    "executeSetupImportCommitPlan",
    "prepareAndExecuteSetupImportCommit",
  ];

  // This source-level guard is intentionally narrow: it protects the
  // first-time setup backup picker from reintroducing pre-confirmation
  // writes while staged-import UI automation is still lightweight.
  for (const helper of forbiddenImmediateWriteHelpers) {
    assert.equal(
      source.includes(helper),
      false,
      `SeedSetupScreen must not import or call ${helper} from backup selection`,
    );
  }
});

test("setup/import commit orchestrator builds and executes setup-only plan", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    dependencies: commitOrchestrationDependencies(calls),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "setup-only");
  assert.deepEqual(calls, ["plan", "commit"]);
});

test("setup/import commit orchestrator can gate setup-only before plan execution", async () => {
  const calls: string[] = [];
  let operationCategories: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: (gateInput) => {
        calls.push("gate");
        assert.equal(gateInput.stagedBackupPresent, false);
        return decideStagedBackupCommitGate(gateInput);
      },
      executePlan: (plan) => {
        calls.push("commit");
        operationCategories = plan.operations.map((operation) => operation.category);
        return {
          success: true,
          operationsApplied: plan.operations.length,
          rollbackStatus: "not-needed",
        };
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "setup-only");
  assert.deepEqual(calls, ["gate", "plan", "commit"]);
  assert.equal(operationCategories.includes("vault-entry"), false);
});

test("setup/import commit orchestrator runs staged gates before commit", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    backupVerifier: backupVerifierFixture(),
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: (gateInput) => {
        calls.push("gate");
        return decideStagedBackupCommitGate(gateInput);
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.deepEqual(calls, [
    "compatibility",
    "sentinel",
    "decryptability",
    "gate",
    "shared-vault",
    "plan",
    "commit",
  ]);
});

test("setup/import commit orchestrator stops before shared vault plan or executor when gate blocks", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: () => {
        calls.push("gate");
        return {
          allowed: false,
          mode: "setup-only",
          reason: "warnings-blocked",
          warnings: ["safe gate warning"],
          safeMessage: "Backup warnings must be reviewed before import.",
        };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "gate");
  assert.equal(result.reason, "warnings-blocked");
  assert.deepEqual(calls, ["compatibility", "decryptability", "gate"]);
  assert.equal(result.warnings.includes("safe gate warning"), true);
});

test("setup/import commit orchestrator honors gate setup-only mode without committing staged records", async () => {
  const calls: string[] = [];
  let operationCategories: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      decideCommitGate: () => {
        calls.push("gate");
        return {
          allowed: true,
          mode: "setup-only",
          reason: "no-backup",
          warnings: ["safe gate warning"],
          safeMessage: "Setup can continue without backup import.",
        };
      },
      executePlan: (plan) => {
        calls.push("commit");
        operationCategories = plan.operations.map((operation) => operation.category);
        return {
          success: true,
          operationsApplied: plan.operations.length,
          rollbackStatus: "not-needed",
        };
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "setup-only");
  assert.deepEqual(calls, ["compatibility", "decryptability", "gate", "plan", "commit"]);
  assert.equal(operationCategories.includes("vault-entry"), false);
  assert.equal(operationCategories.includes("secure-note"), false);
  assert.equal(result.warnings.includes("safe gate warning"), true);
});

test("setup/import commit orchestrator rejects incompatible backup before commit", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      classifyCompatibility: () => {
        calls.push("compatibility");
        return { status: "incompatible", reason: "kdf-metadata-mismatch", warnings: [] };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "gate");
  assert.equal(result.reason, "incompatible");
  assert.deepEqual(calls, ["compatibility"]);
});

test("setup/import commit orchestrator rejects unknown compatibility by default", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupFixture(),
    dependencies: commitOrchestrationDependencies(calls, {
      classifyCompatibility: () => {
        calls.push("compatibility");
        return {
          status: "unknown",
          reason: "missing-compatibility-metadata",
          warnings: ["safe unknown compatibility warning"],
        };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "gate");
  assert.equal(result.reason, "unknown-compatibility");
  assert.deepEqual(calls, ["compatibility"]);
});

test("setup/import commit orchestrator can allow unknown compatibility but still requires decryptability", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupFixture(),
    allowUnknownCompatibility: true,
    dependencies: commitOrchestrationDependencies(calls, {
      classifyCompatibility: () => {
        calls.push("compatibility");
        return {
          status: "unknown",
          reason: "missing-compatibility-metadata",
          warnings: [],
        };
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.deepEqual(calls, ["compatibility", "decryptability", "shared-vault", "plan", "commit"]);
});

test("setup/import commit orchestrator rejects sentinel failure before decryptability and commit", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    backupVerifier: backupVerifierFixture(),
    dependencies: commitOrchestrationDependencies(calls, {
      verifySentinel: () => {
        calls.push("sentinel");
        return { ok: false, reason: "hash-mismatch", message: "Backup verifier hash did not match." };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "gate");
  assert.equal(result.reason, "sentinel-failed");
  assert.deepEqual(calls, ["compatibility", "sentinel"]);
});

test("setup/import commit orchestrator rejects decryptability failure before commit", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      verifyDecryptability: () => {
        calls.push("decryptability");
        return {
          ok: false,
          counts: {
            entriesChecked: 1,
            notesChecked: 1,
            entriesFailed: 1,
            notesFailed: 0,
          },
          failures: [{ kind: "entry", id: "entry-a", index: 0, reason: "decrypt-failed" }],
        };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "gate");
  assert.equal(result.reason, "decryptability-failed");
  assert.deepEqual(calls, ["compatibility", "decryptability"]);
});

test("setup/import commit orchestrator rejects shared vault builder failure before plan", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      buildSharedVaultBlob: () => {
        calls.push("shared-vault");
        throw new Error("SECRET_SHARED_VAULT_CONTENT");
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "shared-vault");
  assert.equal(result.reason, "shared-vault-build-failed");
  assert.deepEqual(calls, ["compatibility", "decryptability", "shared-vault"]);
});

test("setup/import commit orchestrator rejects commit plan failure before executor", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      buildPlan: () => {
        calls.push("plan");
        return {
          ok: false,
          error: {
            code: "invalid-entry-id",
            path: "entries[0].id",
            message: "Setup/import commit plan input is invalid",
          },
        };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "plan");
  assert.equal(result.reason, "invalid-entry-id");
  assert.deepEqual(calls, ["compatibility", "decryptability", "shared-vault", "plan"]);
});

test("setup/import commit orchestrator returns commit-stage executor failure", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      executePlan: () => {
        calls.push("commit");
        return {
          success: false,
          reason: "write-failed",
          message: "Setup/import commit write failed",
          operationsApplied: 2,
          rollbackStatus: "completed",
          failedOperation: {
            key: SETUP_IMPORT_STORAGE_KEYS.masterHash,
            type: "write",
            category: "setup-metadata",
          },
          rollbackFailures: [],
        };
      },
    }),
  });

  assertOrchestrationFailure(result);
  assert.equal(result.stage, "commit");
  assert.equal(result.reason, "write-failed");
  assert.deepEqual(calls, ["compatibility", "decryptability", "shared-vault", "plan", "commit"]);
  assert.equal(result.commitResult?.success, false);
});

test("setup/import commit orchestrator executes successful staged backup commit", async () => {
  const calls: string[] = [];
  let operationCategories: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls, {
      executePlan: (plan) => {
        calls.push("commit");
        operationCategories = plan.operations.map((operation) => operation.category);
        return {
          success: true,
          operationsApplied: plan.operations.length,
          rollbackStatus: "not-needed",
        };
      },
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "commit");
  assert.equal(operationCategories.includes("vault-entry"), true);
  assert.equal(operationCategories.includes("secure-note"), true);
  assert.equal(operationCategories.includes("shared-vault"), true);
});

test("setup/import commit orchestrator preserves safe warnings", async () => {
  const calls: string[] = [];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(calls),
  });

  assert.equal(result.ok, true);
  assert.equal(
    result.warnings.includes(
      "encrypted-local-records backups are staged only and require a future compatibility or rekey flow before commit",
    ),
    true,
  );
  assert.equal(
    result.warnings.includes("Backup has a non-blocking warning that should be reviewed before import."),
    true,
  );
  assert.equal(result.warnings.includes("safe compatibility warning"), false);
});

test("setup/import commit orchestrator omits plaintext ciphertext and key material from failures", async () => {
  const secret = "PLAINTEXT_SECRET CIPHERTEXT_SECRET KEY_SECRET";
  const calls: string[] = [];
  const backup = validBackupFixture();
  const [entry] = backup.entries as Record<string, unknown>[];
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture({
      masterSalt: secret,
      masterHash: secret,
      recoveryKeyHash: secret,
    }),
    stagedBackup: stagedBackupFixture({
      entries: [
        {
          ...entry,
          id: "entry-secret",
          encryptedPassword: secret,
        },
      ],
    }),
    dependencies: commitOrchestrationDependencies(calls, {
      buildSharedVaultBlob: () => {
        calls.push("shared-vault");
        throw new Error(secret);
      },
    }),
  });
  const serialized = JSON.stringify(result);

  assertOrchestrationFailure(result);
  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("KEY_SECRET"), false);
  assert.equal(serialized.includes(secret), false);
});

test("setup/import commit orchestrator does not write platform storage directly", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));
  const result = await prepareAndExecuteSetupImportCommit({
    setupMetadata: commitSetupMetadataFixture(),
    stagedBackup: stagedBackupWithCompatibility(),
    dependencies: commitOrchestrationDependencies(),
  });

  assert.equal(result.ok, true);
  assert.equal(storage.items.size, 0);
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

test("setup/import atomic executor writes all operations in order", async () => {
  const plan = commitPlanFixture({
    includeEntries: true,
    includeNotes: true,
    includeSharedVault: true,
    includeCachedKey: true,
  });
  const storage = new CommitPlanMemoryStorage();

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.deepEqual(result, {
    success: true,
    operationsApplied: plan.operations.length,
    rollbackStatus: "not-needed",
  });
  const setCalls = storage.calls.filter((call) => call.startsWith("set:"));
  assert.deepEqual(
    setCalls,
    plan.operations.map((operation) => `set:${operation.key}`),
  );
  assert.equal(storage.items.get(SETUP_IMPORT_STORAGE_KEYS.vaultInitialized), "1");
});

test("setup/import atomic executor snapshots previous values before writes", async () => {
  const plan = commitPlanFixture();
  const storage = new CommitPlanMemoryStorage();

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, true);
  for (const operation of plan.operations) {
    const getIndex = storage.calls.indexOf(`get:${operation.key}`);
    const setIndex = storage.calls.indexOf(`set:${operation.key}`);
    assert.equal(getIndex > -1, true, `${operation.key} should be snapshotted`);
    assert.equal(setIndex > getIndex, true, `${operation.key} should be written after snapshot`);
  }
});

test("setup/import atomic executor failure on first write leaves new key state clean", async () => {
  const plan = commitPlanFixture();
  const firstKey = plan.operations[0].key;
  const storage = new CommitPlanMemoryStorage();
  storage.failSetAttempts.add(`${firstKey}#1`);

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit failure");
  }
  assert.equal(result.reason, "write-failed");
  assert.equal(result.rollbackStatus, "not-needed");
  assert.equal(storage.items.size, 0);
});

test("setup/import atomic executor middle failure restores previous values and deletes new keys", async () => {
  const plan = commitPlanFixture({ includeEntries: true });
  const failingKey = SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash;
  const storage = new CommitPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "previous-master-salt",
  });
  storage.failSetAttempts.add(`${failingKey}#1`);

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit failure");
  }
  assert.equal(result.rollbackStatus, "completed");
  assert.equal(storage.items.get(SETUP_IMPORT_STORAGE_KEYS.masterSalt), "previous-master-salt");
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.securityProfile), false);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.kdfMetadata), false);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterHash), false);
  assert.equal(storage.items.has("pipass_vault_entry-a"), false);
});

test("setup/import atomic executor failure on initialized marker rolls back earlier writes", async () => {
  const plan = commitPlanFixture({
    includeEntries: true,
    includeNotes: true,
    includeSharedVault: true,
    includeCachedKey: true,
  });
  const storage = new CommitPlanMemoryStorage();
  storage.failSetAttempts.add(`${SETUP_IMPORT_STORAGE_KEYS.vaultInitialized}#1`);

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit failure");
  }
  assert.equal(result.rollbackStatus, "completed");
  assert.equal(storage.items.size, 0);
});

test("setup/import atomic executor rollback restores previous overwritten value", async () => {
  const plan = commitPlanFixture();
  const storage = new CommitPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.securityProfile]: "25000",
  });
  storage.failSetAttempts.add(`${SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash}#1`);

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, false);
  assert.equal(storage.items.get(SETUP_IMPORT_STORAGE_KEYS.securityProfile), "25000");
});

test("setup/import atomic executor rollback deletes newly created key", async () => {
  const plan = commitPlanFixture();
  const storage = new CommitPlanMemoryStorage();
  storage.failSetAttempts.add(`${SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash}#1`);

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, false);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), false);
});

test("setup/import atomic executor reports rollback failures with safe key-only details", async () => {
  const plan = commitPlanFixture();
  const storage = new CommitPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "previous-master-salt",
  });
  storage.failSetAttempts.add(`${SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash}#1`);
  storage.failSetAttempts.add(`${SETUP_IMPORT_STORAGE_KEYS.masterSalt}#2`);

  const result = await executeSetupImportCommitPlan(plan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit failure");
  }
  assert.equal(result.rollbackStatus, "failed");
  assert.deepEqual(result.rollbackFailures, [
    { key: SETUP_IMPORT_STORAGE_KEYS.masterSalt, action: "restore" },
  ]);
  assert.equal(JSON.stringify(result).includes("previous-master-salt"), false);
});

test("setup/import atomic executor rejects plan where initialized marker is not last", async () => {
  const plan = commitPlanFixture();
  const invalidPlan: SetupImportCommitPlan = {
    ...plan,
    operations: [plan.operations[plan.operations.length - 1], ...plan.operations.slice(0, -1)],
  };
  const storage = new CommitPlanMemoryStorage();

  const result = await executeSetupImportCommitPlan(invalidPlan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit validation failure");
  }
  assert.equal(result.reason, "invalid-plan");
  assert.equal(result.validationError, "initialized-marker-not-last");
  assert.equal(storage.calls.length, 0);
  assert.equal(storage.items.size, 0);
});

test("setup/import atomic executor rejects duplicate write keys", async () => {
  const plan = commitPlanFixture();
  const invalidPlan: SetupImportCommitPlan = {
    ...plan,
    operations: [...plan.operations, plan.operations[plan.operations.length - 1]],
  };
  const storage = new CommitPlanMemoryStorage();

  const result = await executeSetupImportCommitPlan(invalidPlan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit validation failure");
  }
  assert.equal(result.reason, "invalid-plan");
  assert.equal(result.validationError, "duplicate-write-key");
  assert.equal(storage.calls.length, 0);
});

test("setup/import atomic executor rejects unknown operation types", async () => {
  const plan = commitPlanFixture();
  const invalidPlan = {
    ...plan,
    operations: [
      ...plan.operations.slice(0, -1),
      {
        type: "delete",
        key: "pipass_unknown",
        category: "setup-metadata",
        safeDescription: "unknown operation",
      },
      plan.operations[plan.operations.length - 1],
    ],
  } as SetupImportCommitPlan;
  const storage = new CommitPlanMemoryStorage();

  const result = await executeSetupImportCommitPlan(invalidPlan, storage);

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected setup/import commit validation failure");
  }
  assert.equal(result.reason, "invalid-plan");
  assert.equal(result.validationError, "unknown-operation-type");
  assert.equal(storage.calls.length, 0);
});

test("setup/import atomic executor omits values and secret-like content from failure output", async () => {
  const secretValue = "PLAINTEXT_SECRET CIPHERTEXT_SECRET KEY_SECRET";
  const plan = commitPlanFixture();
  const storage = new CommitPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
  });
  storage.failSetAttempts.add(`${SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash}#1`);

  const result = await executeSetupImportCommitPlan(plan, storage);
  const serialized = JSON.stringify(result);

  assert.equal(result.success, false);
  assert.equal(serialized.includes(secretValue), false);
  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("KEY_SECRET"), false);
  assert.equal(serialized.includes("setup-master-salt-placeholder"), false);
});

test("setup/import atomic executor does not write storage when validation fails", async () => {
  const plan = commitPlanFixture();
  const invalidPlan: SetupImportCommitPlan = {
    ...plan,
    operations: plan.operations.slice(0, -1),
  };
  const storage = new CommitPlanMemoryStorage();

  const result = await executeSetupImportCommitPlan(invalidPlan, storage);

  assert.equal(result.success, false);
  assert.equal(storage.calls.length, 0);
  assert.equal(storage.items.size, 0);
});

test("setup/import repair planner classifies clean uninitialized state with no action", () => {
  const snapshot = {};
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "clean-uninitialized");
  assert.equal(state.initialized, false);
  assert.equal(plan.action, "none");
  assert.deepEqual(plan.keysToDelete, []);
});

test("setup/import repair planner classifies initialized state with metadata with no action", () => {
  const snapshot = {
    ...setupMetadataSnapshot(),
    [SETUP_IMPORT_STORAGE_KEYS.vaultInitialized]: "1",
  };
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "initialized");
  assert.equal(state.initialized, true);
  assert.equal(plan.action, "none");
});

test("setup/import repair planner recommends clearing partial setup metadata", () => {
  const snapshot = setupMetadataSnapshot();
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "partial-setup");
  assert.equal(plan.action, "clear-local-setup-import-state");
  assert.equal(plan.keysToDelete.includes(SETUP_IMPORT_STORAGE_KEYS.masterSalt), true);
  assert.equal(plan.keysToDelete.includes(SETUP_IMPORT_STORAGE_KEYS.kdfMetadata), true);
  assert.equal(plan.keysToDelete.includes(SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash), true);
});

test("setup/import repair planner recommends clearing partial import records", () => {
  const snapshot = {
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "entry-record-placeholder",
  };
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "partial-import");
  assert.equal(plan.action, "clear-local-setup-import-state");
  assert.deepEqual(plan.keysToDelete, [
    "pipass_vault_entry-a",
    SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
  ]);
});

test("setup/import repair planner recommends clearing setup metadata plus imported records", () => {
  const snapshot = {
    ...setupMetadataSnapshot(),
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "entry-record-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.notesIndex]: JSON.stringify(["note-a"]),
    "pipass_note_note-a": "note-record-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.sharedVault]: "shared-vault-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey]: "cached-key-placeholder",
  };
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(plan.action, "clear-local-setup-import-state");
  for (const key of [
    SETUP_IMPORT_STORAGE_KEYS.masterSalt,
    SETUP_IMPORT_STORAGE_KEYS.masterHash,
    SETUP_IMPORT_STORAGE_KEYS.securityProfile,
    SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
    SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
    SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
    "pipass_vault_entry-a",
    SETUP_IMPORT_STORAGE_KEYS.notesIndex,
    "pipass_note_note-a",
    SETUP_IMPORT_STORAGE_KEYS.sharedVault,
    SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey,
  ]) {
    assert.equal(plan.keysToDelete.includes(key), true, `${key} should be in repair plan`);
  }
});

test("setup/import repair planner requires manual repair when initialized marker lacks metadata", () => {
  const snapshot = {
    [SETUP_IMPORT_STORAGE_KEYS.vaultInitialized]: "1",
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  };
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "inconsistent-initialized");
  assert.equal(plan.action, "manual-repair-required");
  assert.deepEqual(plan.keysToDelete, []);
});

test("setup/import repair planner clears malformed vault index before initialization", () => {
  const snapshot = {
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: "{not-json",
  };
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "unknown-inconsistent");
  assert.deepEqual(state.reasons, ["malformed-vault-index"]);
  assert.equal(plan.action, "clear-local-setup-import-state");
  assert.deepEqual(plan.keysToDelete, [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]);
});

test("setup/import repair planner clears dangling entry key before initialization", () => {
  const snapshot = {
    "pipass_vault_entry-a": "entry-record-placeholder",
  };
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "unknown-inconsistent");
  assert.deepEqual(state.reasons, ["dangling-vault-entry"]);
  assert.equal(plan.action, "clear-local-setup-import-state");
  assert.deepEqual(plan.keysToDelete, ["pipass_vault_entry-a"]);
});

test("setup/import repair planner requires manual repair for dangling entry after initialization", () => {
  const snapshot = {
    ...setupMetadataSnapshot(),
    [SETUP_IMPORT_STORAGE_KEYS.vaultInitialized]: "1",
    "pipass_vault_entry-a": "entry-record-placeholder",
  };
  const state = classifySetupImportLocalState(snapshot);
  const plan = buildSetupImportRepairPlan(snapshot);

  assert.equal(state.classification, "inconsistent-initialized");
  assert.deepEqual(state.reasons, ["dangling-vault-entry"]);
  assert.equal(plan.action, "manual-repair-required");
  assert.deepEqual(plan.keysToDelete, []);
});

test("setup/import repair plan includes keys only and omits stored values", () => {
  const secretValue = "PLAINTEXT_SECRET CIPHERTEXT_SECRET KEY_SECRET";
  const snapshot = {
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "CIPHERTEXT_SECRET",
  };
  const plan = buildSetupImportRepairPlan(snapshot);
  const serialized = JSON.stringify(plan);

  assert.equal(plan.action, "clear-local-setup-import-state");
  assert.equal(serialized.includes(secretValue), false);
  assert.equal(serialized.includes("PLAINTEXT_SECRET"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("KEY_SECRET"), false);
  assert.equal(serialized.includes(SETUP_IMPORT_STORAGE_KEYS.masterSalt), true);
  assert.equal(serialized.includes("pipass_vault_entry-a"), true);
});

test("setup/import repair planner is deterministic", () => {
  const snapshot = {
    "pipass_vault_entry-b": "entry-b-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.masterHash]: "master-hash-placeholder",
    "pipass_note_note-a": "note-a-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.notesIndex]: JSON.stringify(["note-a"]),
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "entry-a-placeholder",
  };

  assert.deepEqual(
    classifySetupImportLocalState(snapshot),
    classifySetupImportLocalState(snapshot),
  );
  assert.deepEqual(buildSetupImportRepairPlan(snapshot), buildSetupImportRepairPlan(snapshot));
});

test("setup/import repair planner does not write platform storage", async (t) => {
  const storage = installMemoryStorage();
  t.after(() => setPlatformStorageDriverForTests(null));

  const plan = buildSetupImportRepairPlan({
    ...setupMetadataSnapshot(),
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "entry-record-placeholder",
  });

  assert.equal(plan.action, "clear-local-setup-import-state");
  assert.equal(storage.items.size, 0);
});

test("setup/import repair executor action none performs no deletes", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "none",
      classification: "clean-uninitialized",
      keysToDelete: [],
      reason: "clean-uninitialized",
      userMessage: "No action",
    },
    storage,
  );

  assert.deepEqual(result, {
    success: true,
    action: "none",
    deletedKeys: [],
    failedKeys: [],
    message: "No setup/import repair action was needed",
  });
  assert.deepEqual(storage.deletedKeys, []);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), true);
});

test("setup/import repair executor refuses manual repair plans without deleting", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "manual-repair-required",
      classification: "inconsistent-initialized",
      keysToDelete: [SETUP_IMPORT_STORAGE_KEYS.masterSalt],
      reason: "manual",
      userMessage: "Manual repair required",
    },
    storage,
  );

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected repair executor refusal");
  }
  assert.equal(result.reason, "manual-repair-required");
  assert.deepEqual(storage.deletedKeys, []);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), true);
});

test("setup/import repair executor deletes exactly listed keys", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.kdfMetadata]: "kdf-placeholder",
    "pipass_vault_entry-a": "entry-placeholder",
    "pipass.auth.authHash": "auth-hash-should-remain",
    "deviceUUID": "device-uuid-should-remain",
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "clear-local-setup-import-state",
      classification: "partial-import",
      keysToDelete: [
        SETUP_IMPORT_STORAGE_KEYS.masterSalt,
        SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
        "pipass_vault_entry-a",
      ],
      reason: "partial-import",
      userMessage: "Clear partial import",
    },
    storage,
  );

  assert.equal(result.success, true);
  assert.deepEqual(storage.deletedKeys, [
    SETUP_IMPORT_STORAGE_KEYS.masterSalt,
    SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
    "pipass_vault_entry-a",
  ]);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), false);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.kdfMetadata), false);
  assert.equal(storage.items.has("pipass_vault_entry-a"), false);
  assert.equal(storage.items.get("pipass.auth.authHash"), "auth-hash-should-remain");
  assert.equal(storage.items.get("deviceUUID"), "device-uuid-should-remain");
});

test("setup/import repair executor de-duplicates duplicate keys safely", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterHash]: "master-hash-placeholder",
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "clear-local-setup-import-state",
      classification: "partial-setup",
      keysToDelete: [
        SETUP_IMPORT_STORAGE_KEYS.masterHash,
        SETUP_IMPORT_STORAGE_KEYS.masterHash,
      ],
      reason: "partial-setup",
      userMessage: "Clear partial setup",
    },
    storage,
  );

  assert.equal(result.success, true);
  assert.deepEqual(storage.deletedKeys, [SETUP_IMPORT_STORAGE_KEYS.masterHash]);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterHash), false);
});

test("setup/import repair executor reports delete failures with failed keys only", async () => {
  const secretValue = "PLAINTEXT_SECRET CIPHERTEXT_SECRET KEY_SECRET";
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
    [SETUP_IMPORT_STORAGE_KEYS.masterHash]: "master-hash-placeholder",
  });
  storage.failDeleteKeys.add(SETUP_IMPORT_STORAGE_KEYS.masterSalt);

  const result = await executeSetupImportRepairPlan(
    {
      action: "clear-local-setup-import-state",
      classification: "partial-setup",
      keysToDelete: [
        SETUP_IMPORT_STORAGE_KEYS.masterSalt,
        SETUP_IMPORT_STORAGE_KEYS.masterHash,
      ],
      reason: "partial-setup",
      userMessage: "Clear partial setup",
    },
    storage,
  );

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected repair executor partial failure");
  }
  assert.equal(result.reason, "delete-failed");
  assert.deepEqual(result.failedKeys, [SETUP_IMPORT_STORAGE_KEYS.masterSalt]);
  assert.equal(JSON.stringify(result).includes(secretValue), false);
  assert.equal(JSON.stringify(result).includes("PLAINTEXT_SECRET"), false);
  assert.equal(JSON.stringify(result).includes("CIPHERTEXT_SECRET"), false);
  assert.equal(JSON.stringify(result).includes("KEY_SECRET"), false);
});

test("setup/import repair executor attempts remaining keys after delete failure", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.masterHash]: "master-hash-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash]: "recovery-hash-placeholder",
  });
  storage.failDeleteKeys.add(SETUP_IMPORT_STORAGE_KEYS.masterHash);

  const result = await executeSetupImportRepairPlan(
    {
      action: "clear-local-setup-import-state",
      classification: "partial-setup",
      keysToDelete: [
        SETUP_IMPORT_STORAGE_KEYS.masterSalt,
        SETUP_IMPORT_STORAGE_KEYS.masterHash,
        SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
      ],
      reason: "partial-setup",
      userMessage: "Clear partial setup",
    },
    storage,
  );

  assert.equal(result.success, false);
  assert.deepEqual(storage.deletedKeys, [
    SETUP_IMPORT_STORAGE_KEYS.masterSalt,
    SETUP_IMPORT_STORAGE_KEYS.masterHash,
    SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
  ]);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), false);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash), false);
});

test("setup/import repair executor rejects unsafe malformed keys before deletion", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  for (const unsafeKey of [
    "",
    " ../pipass_master_salt",
    "pipass.auth.authHash",
    "pipass.installId",
    "deviceUUID",
    "pipass_vault_entry-a/other",
  ]) {
    const result = await executeSetupImportRepairPlan(
      {
        action: "clear-local-setup-import-state",
        classification: "partial-setup",
        keysToDelete: [unsafeKey, SETUP_IMPORT_STORAGE_KEYS.masterSalt],
        reason: "partial-setup",
        userMessage: "Clear partial setup",
      },
      storage,
    );

    assert.equal(result.success, false, `${unsafeKey} should be rejected`);
    if (result.success) {
      throw new Error("expected unsafe repair key rejection");
    }
    assert.equal(result.reason, "unsafe-key");
  }

  assert.deepEqual(storage.deletedKeys, []);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), true);
});

test("setup/import repair executor rejects unknown actions before deletion", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "delete-everything",
      classification: "partial-setup",
      keysToDelete: [SETUP_IMPORT_STORAGE_KEYS.masterSalt],
      reason: "unknown",
      userMessage: "Unknown",
    } as any,
    storage,
  );

  assert.equal(result.success, false);
  if (result.success) {
    throw new Error("expected unknown action rejection");
  }
  assert.equal(result.reason, "invalid-action");
  assert.deepEqual(storage.deletedKeys, []);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), true);
});

test("setup/import repair executor does not delete unlisted keys", async () => {
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.masterHash]: "master-hash-placeholder",
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: "vault-index-placeholder",
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "clear-local-setup-import-state",
      classification: "partial-setup",
      keysToDelete: [SETUP_IMPORT_STORAGE_KEYS.masterSalt],
      reason: "partial-setup",
      userMessage: "Clear partial setup",
    },
    storage,
  );

  assert.equal(result.success, true);
  assert.equal(storage.items.has(SETUP_IMPORT_STORAGE_KEYS.masterSalt), false);
  assert.equal(storage.items.get(SETUP_IMPORT_STORAGE_KEYS.masterHash), "master-hash-placeholder");
  assert.equal(storage.items.get(SETUP_IMPORT_STORAGE_KEYS.vaultIndex), "vault-index-placeholder");
});

test("setup/import repair executor output contains no stored values", async () => {
  const secretValue = "STORED_SECRET_VALUE CIPHERTEXT_SECRET";
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
  });

  const result = await executeSetupImportRepairPlan(
    {
      action: "clear-local-setup-import-state",
      classification: "partial-setup",
      keysToDelete: [SETUP_IMPORT_STORAGE_KEYS.masterSalt],
      reason: "partial-setup",
      userMessage: "Clear partial setup",
    },
    storage,
  );

  const serialized = JSON.stringify(result);
  assert.equal(result.success, true);
  assert.equal(serialized.includes(secretValue), false);
  assert.equal(serialized.includes("STORED_SECRET_VALUE"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
});

test("startup repair decision sends clean uninitialized snapshot to setup", () => {
  const decision = decideStartupRepairState({});

  assert.equal(decision.route, "setup");
  assert.equal(decision.classification, "clean-uninitialized");
  assert.equal(decision.repairPlan?.action, "none");
});

test("startup repair decision sends healthy initialized snapshot to unlock", () => {
  const decision = decideStartupRepairState({
    ...setupMetadataSnapshot(),
    [SETUP_IMPORT_STORAGE_KEYS.vaultInitialized]: "1",
  });

  assert.equal(decision.route, "unlock");
  assert.equal(decision.classification, "initialized");
  assert.equal(decision.repairPlan?.action, "none");
});

test("startup repair decision sends partial setup snapshot to repair prompt", () => {
  const decision = decideStartupRepairState(setupMetadataSnapshot());

  assert.equal(decision.route, "repair-prompt");
  assert.equal(decision.classification, "partial-setup");
  assert.equal(decision.repairPlan?.action, "clear-local-setup-import-state");
});

test("startup repair decision sends partial import snapshot to repair prompt", () => {
  const decision = decideStartupRepairState({
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "entry-record-placeholder",
  });

  assert.equal(decision.route, "repair-prompt");
  assert.equal(decision.classification, "partial-import");
  assert.equal(decision.repairPlan?.action, "clear-local-setup-import-state");
});

test("startup repair decision sends inconsistent initialized snapshot to manual repair", () => {
  const decision = decideStartupRepairState({
    [SETUP_IMPORT_STORAGE_KEYS.vaultInitialized]: "1",
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  assert.equal(decision.route, "manual-repair");
  assert.equal(decision.classification, "inconsistent-initialized");
  assert.equal(decision.repairPlan?.action, "manual-repair-required");
});

test("startup repair decision sends malformed uninitialized index to repair prompt", () => {
  const decision = decideStartupRepairState({
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: "{not-json",
  });

  assert.equal(decision.route, "repair-prompt");
  assert.equal(decision.classification, "unknown-inconsistent");
  assert.equal(decision.repairPlan?.action, "clear-local-setup-import-state");
});

test("startup repair decision returns safe-error on snapshot read failure", async () => {
  const secretValue = "READ_FAILURE_SECRET_VALUE CIPHERTEXT_SECRET";
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
  });
  reader.failReadKeys.add(SETUP_IMPORT_STORAGE_KEYS.masterHash);

  const snapshotResult = await readSetupImportStateSnapshot(reader);
  const decision = decideStartupRepairState(snapshotResult);
  const serialized = JSON.stringify(decision);

  assert.equal(snapshotResult.ok, false);
  assert.equal(decision.route, "safe-error");
  assert.equal(decision.classification, "read-failed");
  assert.equal(serialized.includes(secretValue), false);
  assert.equal(serialized.includes("READ_FAILURE_SECRET_VALUE"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
});

test("startup repair snapshot reader reads entry keys referenced by valid vault index", async () => {
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a", "entry-b"]),
    "pipass_vault_entry-a": "entry-a-placeholder",
    "pipass_vault_entry-b": "entry-b-placeholder",
  });

  const result = await readSetupImportStateSnapshot(reader);

  assert.equal(result.ok, true);
  if (!result.ok) {
    throw new Error("expected startup snapshot read success");
  }
  assert.equal(result.snapshot["pipass_vault_entry-a"], "entry-a-placeholder");
  assert.equal(result.snapshot["pipass_vault_entry-b"], "entry-b-placeholder");
  assert.equal(result.keysRead.includes("pipass_vault_entry-a"), true);
  assert.equal(result.keysRead.includes("pipass_vault_entry-b"), true);
});

test("startup repair snapshot reader reads note keys referenced by valid notes index", async () => {
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.notesIndex]: JSON.stringify(["note-a", "note-b"]),
    "pipass_note_note-a": "note-a-placeholder",
    "pipass_note_note-b": "note-b-placeholder",
  });

  const result = await readSetupImportStateSnapshot(reader);

  assert.equal(result.ok, true);
  if (!result.ok) {
    throw new Error("expected startup snapshot read success");
  }
  assert.equal(result.snapshot["pipass_note_note-a"], "note-a-placeholder");
  assert.equal(result.snapshot["pipass_note_note-b"], "note-b-placeholder");
  assert.equal(result.keysRead.includes("pipass_note_note-a"), true);
  assert.equal(result.keysRead.includes("pipass_note_note-b"), true);
});

test("startup repair snapshot reader handles malformed indexes without raw throws", async () => {
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: "{not-json",
    "pipass_vault_entry-a": "entry-a-placeholder",
  });

  const result = await readSetupImportStateSnapshot(reader);

  assert.equal(result.ok, true);
  if (!result.ok) {
    throw new Error("expected startup snapshot read success");
  }
  assert.equal(result.snapshot[SETUP_IMPORT_STORAGE_KEYS.vaultIndex], "{not-json");
  assert.equal(result.keysRead.includes("pipass_vault_entry-a"), false);
});

test("startup repair snapshot and decision helpers do not write or delete storage", async () => {
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "entry-a-placeholder",
  });

  const result = await readSetupImportStateSnapshot(reader);
  const decision = decideStartupRepairState(result);

  assert.equal(result.ok, true);
  assert.equal(decision.route, "repair-prompt");
  assert.deepEqual(reader.keysWritten, []);
  assert.deepEqual(reader.keysDeleted, []);
});

test("startup repair decision output contains no stored values", async () => {
  const secretValue = "STORED_SECRET_VALUE CIPHERTEXT_SECRET";
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
    [SETUP_IMPORT_STORAGE_KEYS.vaultIndex]: JSON.stringify(["entry-a"]),
    "pipass_vault_entry-a": "ENTRY_CIPHERTEXT_SECRET",
  });

  const result = await readSetupImportStateSnapshot(reader);
  const decision = decideStartupRepairState(result);
  const serialized = JSON.stringify(decision);

  assert.equal(result.ok, true);
  assert.equal(decision.route, "repair-prompt");
  assert.equal(serialized.includes(secretValue), false);
  assert.equal(serialized.includes("STORED_SECRET_VALUE"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
  assert.equal(serialized.includes("ENTRY_CIPHERTEXT_SECRET"), false);
});

test("startup repair orchestration reads snapshot and decides setup route", async () => {
  const reader = new StartupSnapshotMemoryReader();

  const decision = await readAndDecideStartupRepairState(reader);

  assert.equal(decision.route, "setup");
  assert.deepEqual(reader.keysWritten, []);
  assert.deepEqual(reader.keysDeleted, []);
});

test("startup repair confirmation deletes only after repair-prompt decision", async () => {
  const reader = new StartupSnapshotMemoryReader({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });
  const decision = await readAndDecideStartupRepairState(reader);
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  assert.equal(decision.route, "repair-prompt");
  assert.deepEqual(storage.deletedKeys, []);

  const result = await confirmStartupRepairDecision(decision, storage);

  assert.equal(result.success, true);
  assert.deepEqual(storage.deletedKeys, [SETUP_IMPORT_STORAGE_KEYS.masterSalt]);
});

test("startup repair confirmation refuses manual repair without deleting", async () => {
  const decision = decideStartupRepairState({
    [SETUP_IMPORT_STORAGE_KEYS.vaultInitialized]: "1",
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  const result = await confirmStartupRepairDecision(decision, storage);

  assert.equal(decision.route, "manual-repair");
  assert.equal(result.success, false);
  assert.equal(result.reason, "not-repairable");
  assert.deepEqual(storage.deletedKeys, []);
});

test("startup repair confirmation refuses safe-error without deleting", async () => {
  const reader = new StartupSnapshotMemoryReader();
  reader.failReadKeys.add(SETUP_IMPORT_STORAGE_KEYS.vaultInitialized);
  const decision = await readAndDecideStartupRepairState(reader);
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: "master-salt-placeholder",
  });

  const result = await confirmStartupRepairDecision(decision, storage);

  assert.equal(decision.route, "safe-error");
  assert.equal(result.success, false);
  assert.equal(result.reason, "not-repairable");
  assert.deepEqual(storage.deletedKeys, []);
});

test("startup repair confirmation output contains no stored values", async () => {
  const secretValue = "STORED_SECRET_VALUE CIPHERTEXT_SECRET";
  const decision = decideStartupRepairState({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
  });
  const storage = new RepairPlanMemoryStorage({
    [SETUP_IMPORT_STORAGE_KEYS.masterSalt]: secretValue,
  });

  const result = await confirmStartupRepairDecision(decision, storage);
  const serialized = JSON.stringify(result);

  assert.equal(result.success, true);
  assert.equal(serialized.includes(secretValue), false);
  assert.equal(serialized.includes("STORED_SECRET_VALUE"), false);
  assert.equal(serialized.includes("CIPHERTEXT_SECRET"), false);
});
