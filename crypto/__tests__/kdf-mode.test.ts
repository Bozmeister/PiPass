import assert from "node:assert/strict";
import test from "node:test";
import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
} from "../kdfMetadata";
import {
  detectLegacyKdfFromMasterHash,
  deriveMasterKeyFromKdfMetadata,
  deriveMasterKeyWithArgon2id,
  deriveMasterKeyWithPbkdf2,
  hashMasterKey,
  KdfDerivationError,
  planUnlockKdfDerivation,
} from "../keyDerivation";
import { setPlatformStorageDriverForTests } from "../../lib/platformStorage";
import type { PlatformStorageDriver } from "../../lib/platformStorage";
import type { KdfMetadata } from "../kdfMetadata";

const TEST_PASSWORD = "test password only";
const TEST_SALT = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const TEST_DEVICE_UUID = "11111111-2222-4333-8444-555555555555";
const OTHER_DEVICE_UUID = "99999999-8888-4777-8666-555555555555";

const PBKDF2_PARAMS = { iterations: 1000, outputBytes: 32 as const };
const ARGON2ID_PARAMS = {
  memoryKiB: 64,
  timeCost: 1,
  parallelism: 1,
  outputBytes: 32 as const,
};
const LEGACY_ARGON2ID_PARAMS = {
  memoryKiB: 65536,
  timeCost: 3,
  parallelism: 4,
  outputBytes: 32 as const,
};

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

function assertHexKey(value: string): void {
  assert.match(value, /^[0-9a-f]{64}$/);
}

test("explicit PBKDF2 helper is deterministic", async () => {
  const first = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });
  const second = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  assert.equal(first, second);
});

test("explicit PBKDF2 helper changes output when deviceUUID changes", async () => {
  const first = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });
  const second = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: OTHER_DEVICE_UUID,
  });

  assert.notEqual(first, second);
});

test("explicit PBKDF2 helper returns a lowercase 32-byte hex key", async () => {
  const key = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  assertHexKey(key);
});

test("metadata derivation with PBKDF2 matches the explicit PBKDF2 helper", async () => {
  const metadata = buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
    createdAt: 1234567890,
  });

  const explicit = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });
  const fromMetadata = await deriveMasterKeyFromKdfMetadata(TEST_PASSWORD, TEST_SALT, metadata, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  assert.equal(fromMetadata, explicit);
});

test("explicit Argon2id helper returns a lowercase 32-byte hex key when available", async (t) => {
  try {
    const key = await deriveMasterKeyWithArgon2id(TEST_PASSWORD, TEST_SALT, ARGON2ID_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });
    assertHexKey(key);
  } catch (err) {
    if (err instanceof KdfDerivationError) {
      t.skip("Argon2id is unavailable in this test environment");
      return;
    }
    throw err;
  }
});

test("metadata derivation with Argon2id matches the explicit Argon2id helper when available", async (t) => {
  const metadata = buildArgon2idKdfMetadata(1000, ARGON2ID_PARAMS, "setup", {
    createdAt: 1234567890,
  });

  try {
    const explicit = await deriveMasterKeyWithArgon2id(TEST_PASSWORD, TEST_SALT, ARGON2ID_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });
    const fromMetadata = await deriveMasterKeyFromKdfMetadata(TEST_PASSWORD, TEST_SALT, metadata, {
      deviceUUID: TEST_DEVICE_UUID,
    });

    assert.equal(fromMetadata, explicit);
  } catch (err) {
    if (err instanceof KdfDerivationError) {
      t.skip("Argon2id is unavailable in this test environment");
      return;
    }
    throw err;
  }
});

test("metadata derivation rejects invalid metadata with a controlled error", async () => {
  const invalid = {
    version: 1,
    algorithm: "scrypt",
    profileIterations: 1000,
    kdfVersion: "v1",
    parameters: { outputBytes: 32 },
    saltKey: "pipass_master_salt",
    deviceBinding: "deviceUUID:v1",
    createdAt: 1234567890,
    source: "setup",
  } as unknown as KdfMetadata;

  await assert.rejects(
    deriveMasterKeyFromKdfMetadata(TEST_PASSWORD, TEST_SALT, invalid, {
      deviceUUID: TEST_DEVICE_UUID,
    }),
    (err: unknown) =>
      err instanceof KdfDerivationError &&
      err.message === "Invalid KDF metadata",
  );
});

test("legacy KDF detection detects Argon2id when the stored master hash matches", async (t) => {
  let masterKeyHex: string;
  try {
    masterKeyHex = await deriveMasterKeyWithArgon2id(TEST_PASSWORD, TEST_SALT, LEGACY_ARGON2ID_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });
  } catch (err) {
    if (err instanceof KdfDerivationError) {
      t.skip("Argon2id is unavailable in this test environment");
      return;
    }
    throw err;
  }

  const result = await detectLegacyKdfFromMasterHash(
    TEST_PASSWORD,
    TEST_SALT,
    3,
    hashMasterKey(masterKeyHex),
    { deviceUUID: TEST_DEVICE_UUID, createdAt: 1234567890 },
  );

  assert.equal(result.matched, true);
  if (!result.matched) return;
  assert.equal(result.algorithm, "argon2id");
  assert.equal(result.masterKeyHex, masterKeyHex);
  assert.equal(result.metadata.source, "unlock-migration");
  assert.equal(result.metadata.profileIterations, 3);
  assert.equal(result.metadata.kdfVersion, "v1");
  assert.equal(result.metadata.saltKey, "pipass_master_salt");
  assert.equal(result.metadata.deviceBinding, "deviceUUID:v1");
  assert.deepEqual(result.metadata.parameters, LEGACY_ARGON2ID_PARAMS);
});

test("legacy KDF detection detects PBKDF2 when the stored master hash matches", async () => {
  const masterKeyHex = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  const result = await detectLegacyKdfFromMasterHash(
    TEST_PASSWORD,
    TEST_SALT,
    1000,
    hashMasterKey(masterKeyHex),
    {
      deviceUUID: TEST_DEVICE_UUID,
      createdAt: 1234567890,
      deriveArgon2id: async () => {
        throw new KdfDerivationError("Argon2id is unavailable");
      },
    },
  );

  assert.equal(result.matched, true);
  if (!result.matched) return;
  assert.equal(result.algorithm, "pbkdf2-sha256");
  assert.equal(result.masterKeyHex, masterKeyHex);
  assert.equal(result.metadata.source, "legacy-detected");
  assert.equal(result.metadata.profileIterations, 1000);
  assert.equal(result.metadata.kdfVersion, "legacy-pbkdf2-v1");
  assert.equal(result.metadata.saltKey, "pipass_master_salt");
  assert.equal(result.metadata.deviceBinding, "deviceUUID:v1");
  assert.deepEqual(result.metadata.parameters, PBKDF2_PARAMS);
});

test("legacy KDF detection returns no-match when neither candidate matches", async () => {
  const result = await detectLegacyKdfFromMasterHash(
    TEST_PASSWORD,
    TEST_SALT,
    1000,
    "0".repeat(64),
    {
      deviceUUID: TEST_DEVICE_UUID,
      deriveArgon2id: async () => {
        throw new KdfDerivationError("Argon2id derivation failed");
      },
    },
  );

  assert.deepEqual(result, { matched: false, reason: "no-match" });
});

test("legacy KDF detection still tries PBKDF2 after explicit Argon2id failure", async () => {
  const masterKeyHex = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  const result = await detectLegacyKdfFromMasterHash(
    TEST_PASSWORD,
    TEST_SALT,
    1000,
    hashMasterKey(masterKeyHex),
    {
      deviceUUID: TEST_DEVICE_UUID,
      deriveArgon2id: async () => {
        throw new KdfDerivationError("Argon2id derivation failed");
      },
    },
  );

  assert.equal(result.matched, true);
  if (!result.matched) return;
  assert.equal(result.algorithm, "pbkdf2-sha256");
});

test("legacy KDF detection returns invalid-input for malformed inputs", async () => {
  const result = await detectLegacyKdfFromMasterHash(
    "",
    TEST_SALT,
    1000,
    "not-a-hash",
    { deviceUUID: TEST_DEVICE_UUID },
  );

  assert.deepEqual(result, { matched: false, reason: "invalid-input" });
});

test("legacy KDF detection does not write KDF metadata to storage", async () => {
  const storage = new MemoryStorage();
  setPlatformStorageDriverForTests(storage.driver);
  try {
    const masterKeyHex = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });

    const result = await detectLegacyKdfFromMasterHash(
      TEST_PASSWORD,
      TEST_SALT,
      1000,
      hashMasterKey(masterKeyHex),
      {
        deviceUUID: TEST_DEVICE_UUID,
        deriveArgon2id: async () => {
          throw new KdfDerivationError("Argon2id is unavailable");
        },
      },
    );

    assert.equal(result.matched, true);
    assert.equal(storage.items.has("pipass_kdf_metadata"), false);
  } finally {
    setPlatformStorageDriverForTests(null);
  }
});

test("unlock KDF planner uses valid Argon2id metadata when the hash matches", async (t) => {
  const metadata = buildArgon2idKdfMetadata(1000, ARGON2ID_PARAMS, "setup", {
    createdAt: 1234567890,
  });
  let masterKeyHex: string;
  try {
    masterKeyHex = await deriveMasterKeyWithArgon2id(TEST_PASSWORD, TEST_SALT, ARGON2ID_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });
  } catch (err) {
    if (err instanceof KdfDerivationError) {
      t.skip("Argon2id is unavailable in this test environment");
      return;
    }
    throw err;
  }

  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: hashMasterKey(masterKeyHex),
    existingMetadata: metadata,
    metadataStatus: "valid",
    deviceUUID: TEST_DEVICE_UUID,
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.source, "metadata");
  assert.equal(result.masterKeyHex, masterKeyHex);
  assert.deepEqual(result.metadata, metadata);
  assert.equal(result.metadataToPersist, undefined);
});

test("unlock KDF planner uses valid PBKDF2 metadata when the hash matches", async () => {
  const metadata = buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
    createdAt: 1234567890,
  });
  const masterKeyHex = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: hashMasterKey(masterKeyHex),
    existingMetadata: metadata,
    metadataStatus: "valid",
    deviceUUID: TEST_DEVICE_UUID,
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.source, "metadata");
  assert.equal(result.masterKeyHex, masterKeyHex);
  assert.deepEqual(result.metadata, metadata);
});

test("unlock KDF planner fails closed on Argon2id metadata hash mismatch without legacy fallback", async () => {
  const metadata = buildArgon2idKdfMetadata(1000, ARGON2ID_PARAMS, "setup", {
    createdAt: 1234567890,
  });

  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: "0".repeat(64),
    existingMetadata: metadata,
    metadataStatus: "valid",
    deviceUUID: TEST_DEVICE_UUID,
    deriveFromMetadata: async () => "a".repeat(64),
    detectLegacy: async () => {
      throw new Error("legacy detection should not run");
    },
  });

  assert.deepEqual(result, { ok: false, reason: "metadata-hash-mismatch" });
});

test("unlock KDF planner fails closed on PBKDF2 metadata hash mismatch", async () => {
  const metadata = buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
    createdAt: 1234567890,
  });

  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: "0".repeat(64),
    existingMetadata: metadata,
    metadataStatus: "valid",
    deviceUUID: TEST_DEVICE_UUID,
  });

  assert.deepEqual(result, { ok: false, reason: "metadata-hash-mismatch" });
});

test("unlock KDF planner detects missing-metadata Argon2id legacy match and returns metadataToPersist", async (t) => {
  let masterKeyHex: string;
  try {
    masterKeyHex = await deriveMasterKeyWithArgon2id(TEST_PASSWORD, TEST_SALT, LEGACY_ARGON2ID_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });
  } catch (err) {
    if (err instanceof KdfDerivationError) {
      t.skip("Argon2id is unavailable in this test environment");
      return;
    }
    throw err;
  }

  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 3,
    storedMasterHash: hashMasterKey(masterKeyHex),
    metadataStatus: "missing",
    deviceUUID: TEST_DEVICE_UUID,
    createdAt: 1234567890,
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.source, "legacy-detected");
  assert.equal(result.masterKeyHex, masterKeyHex);
  assert.equal(result.metadata.algorithm, "argon2id");
  assert.equal(result.metadata.source, "unlock-migration");
  assert.deepEqual(result.metadataToPersist, result.metadata);
});

test("unlock KDF planner detects missing-metadata PBKDF2 legacy match and returns metadataToPersist", async () => {
  const masterKeyHex = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
    deviceUUID: TEST_DEVICE_UUID,
  });

  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: hashMasterKey(masterKeyHex),
    metadataStatus: "missing",
    deviceUUID: TEST_DEVICE_UUID,
    createdAt: 1234567890,
    detectLegacy: async () => ({
      matched: true,
      algorithm: "pbkdf2-sha256",
      masterKeyHex,
      metadata: buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
        createdAt: 1234567890,
      }),
    }),
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.source, "legacy-detected");
  assert.equal(result.masterKeyHex, masterKeyHex);
  assert.equal(result.metadata.algorithm, "pbkdf2-sha256");
  assert.equal(result.metadata.source, "legacy-detected");
  assert.deepEqual(result.metadataToPersist, result.metadata);
});

test("unlock KDF planner returns legacy-no-match when missing metadata has no matching candidate", async () => {
  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: "0".repeat(64),
    metadataStatus: "missing",
    deviceUUID: TEST_DEVICE_UUID,
    detectLegacy: async () => ({ matched: false, reason: "no-match" }),
  });

  assert.deepEqual(result, { ok: false, reason: "legacy-no-match" });
});

test("unlock KDF planner fails closed on invalid metadata status without legacy detection", async () => {
  const result = await planUnlockKdfDerivation({
    password: TEST_PASSWORD,
    saltHex: TEST_SALT,
    profileIterations: 1000,
    storedMasterHash: "0".repeat(64),
    metadataStatus: "invalid",
    deviceUUID: TEST_DEVICE_UUID,
    detectLegacy: async () => {
      throw new Error("legacy detection should not run");
    },
  });

  assert.deepEqual(result, { ok: false, reason: "invalid-metadata" });
});

test("unlock KDF planner does not write KDF metadata to storage", async () => {
  const storage = new MemoryStorage();
  setPlatformStorageDriverForTests(storage.driver);
  try {
    const masterKeyHex = await deriveMasterKeyWithPbkdf2(TEST_PASSWORD, TEST_SALT, PBKDF2_PARAMS, {
      deviceUUID: TEST_DEVICE_UUID,
    });

    const result = await planUnlockKdfDerivation({
      password: TEST_PASSWORD,
      saltHex: TEST_SALT,
      profileIterations: 1000,
      storedMasterHash: hashMasterKey(masterKeyHex),
      metadataStatus: "missing",
      deviceUUID: TEST_DEVICE_UUID,
      detectLegacy: async () => ({
        matched: true,
        algorithm: "pbkdf2-sha256",
        masterKeyHex,
        metadata: buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
          createdAt: 1234567890,
        }),
      }),
    });

    assert.equal(result.ok, true);
    assert.equal(storage.items.has("pipass_kdf_metadata"), false);
  } finally {
    setPlatformStorageDriverForTests(null);
  }
});
