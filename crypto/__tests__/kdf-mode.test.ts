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
import { performCurrentUnlockVerification } from "../../lib/currentUnlock";
import {
  FirstTimeVaultSetupError,
  performFirstTimeVaultSetup,
  prepareFirstTimeVaultSetup,
} from "../../lib/firstTimeSetup";
import type { PlatformStorageDriver } from "../../lib/platformStorage";
import type { KdfMetadata } from "../kdfMetadata";
import type { KeyShares } from "../secureMemory";

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

function fakeShares(): KeyShares {
  return {
    shareA: new Uint8Array([1, 2, 3, 4]),
    shareB: new Uint8Array([5, 6, 7, 8]),
  };
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

test("current unlock verification succeeds when the derived hash matches the stored master hash", async () => {
  const shares = fakeShares();
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => {
        events.push("get-stored-hash");
        return "stored-hash";
      },
      getKdfMetadataState: async () => {
        events.push("get-kdf-metadata");
        return {
          status: "valid",
          metadata: buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
            createdAt: 1234567890,
          }),
        };
      },
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async (input) => {
        events.push(`plan-${input.metadataStatus}`);
        return {
          ok: true,
          source: "metadata",
          masterKeyHex: "a".repeat(64),
          metadata: input.existingMetadata!,
        };
      },
      splitKeyIntoShares: (masterKeyHex) => {
        events.push(`split-${masterKeyHex}`);
        return shares;
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.deepEqual(result, { ok: true, shares });
  assert.deepEqual(events, [
    "get-stored-hash",
    "get-kdf-metadata",
    "plan-valid",
    `split-${"a".repeat(64)}`,
    "cache",
  ]);
});

test("current unlock verification uses valid Argon2id metadata without persisting metadata", async () => {
  const shares = fakeShares();
  const metadata = buildArgon2idKdfMetadata(1000, ARGON2ID_PARAMS, "setup", {
    createdAt: 1234567890,
  });
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => "stored-hash",
      getKdfMetadataState: async () => ({ status: "valid", metadata }),
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async (input) => {
        assert.equal(input.metadataStatus, "valid");
        assert.deepEqual(input.existingMetadata, metadata);
        events.push("plan");
        return {
          ok: true,
          source: "metadata",
          masterKeyHex: "9".repeat(64),
          metadata,
        };
      },
      splitKeyIntoShares: () => {
        events.push("split");
        return shares;
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {},
    },
  );

  assert.deepEqual(result, { ok: true, shares });
  assert.deepEqual(events, ["plan", "split", "cache"]);
});

test("current unlock verification fails missing-metadata no-match without writing metadata", async () => {
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => "stored-hash",
      getKdfMetadataState: async () => ({ status: "missing", metadata: null }),
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async (input) => {
        assert.equal(input.metadataStatus, "missing");
        events.push("plan");
        return { ok: false, reason: "legacy-no-match" };
      },
      splitKeyIntoShares: () => {
        events.push("split");
        return fakeShares();
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.deepEqual(result, { ok: false, reason: "hash-mismatch" });
  assert.deepEqual(events, ["plan"]);
});

test("current unlock verification fails and wipes newly derived shares when the hash mismatches", async () => {
  const shares = fakeShares();
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => {
        events.push("get-stored-hash");
        return "stored-hash";
      },
      getKdfMetadataState: async () => {
        events.push("get-kdf-metadata");
        return {
          status: "valid",
          metadata: buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
            createdAt: 1234567890,
          }),
        };
      },
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async () => {
        events.push("plan");
        return { ok: false, reason: "metadata-hash-mismatch" };
      },
      splitKeyIntoShares: () => {
        events.push("split");
        return shares;
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.deepEqual(result, { ok: false, reason: "hash-mismatch" });
  assert.deepEqual(events, ["get-stored-hash", "get-kdf-metadata", "plan"]);
});

test("current unlock verification preserves legacy tolerance when stored master hash is missing", async () => {
  const shares = fakeShares();
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        events.push("derive");
        return shares;
      },
      combineShares: () => {
        events.push("combine");
        return "c".repeat(64);
      },
      hashMasterKey: () => {
        events.push("hash");
        return "candidate-hash";
      },
      getMasterKeyHash: async () => {
        events.push("get-stored-hash");
        return null;
      },
      getKdfMetadataState: async () => {
        events.push("get-kdf-metadata");
        return { status: "missing", metadata: null };
      },
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async () => {
        events.push("plan");
        return { ok: false, reason: "legacy-no-match" };
      },
      splitKeyIntoShares: () => {
        events.push("split");
        return fakeShares();
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.deepEqual(result, { ok: true, shares });
  assert.deepEqual(events, ["get-stored-hash", "derive", "combine", "hash", "cache"]);
});

test("current unlock verification propagates cached-key failures before publishing shares", async () => {
  const shares = fakeShares();
  const events: string[] = [];

  await assert.rejects(
    performCurrentUnlockVerification(
      { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
      {
        deriveMasterKeyShares: async () => {
          throw new Error("legacy derivation should not run");
        },
        combineShares: () => {
          throw new Error("legacy combine should not run");
        },
        hashMasterKey: () => {
          throw new Error("legacy hash should not run");
        },
        getMasterKeyHash: async () => {
          events.push("get-stored-hash");
          return "stored-hash";
        },
        getKdfMetadataState: async () => {
          events.push("get-kdf-metadata");
          return { status: "missing", metadata: null };
        },
        saveKdfMetadata: async () => {
          events.push("save-kdf-metadata");
        },
        planUnlockKdfDerivation: async () => {
          events.push("plan");
          return {
            ok: true,
            source: "legacy-detected",
            masterKeyHex: "d".repeat(64),
            metadata: buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
              createdAt: 1234567890,
            }),
          };
        },
        splitKeyIntoShares: (masterKeyHex) => {
          events.push(`split-${masterKeyHex}`);
          return shares;
        },
        storeMasterKeySecurely: async () => {
          events.push("cache");
          throw new Error("cache failed");
        },
        wipeShares: (sharesToWipe) => {
          assert.equal(sharesToWipe, shares);
          events.push("wipe");
        },
      },
    ),
    /cache failed/,
  );

  assert.deepEqual(events, [
    "get-stored-hash",
    "get-kdf-metadata",
    "plan",
    `split-${"d".repeat(64)}`,
    "cache",
    "wipe",
  ]);
});

test("current unlock verification does not read or write KDF metadata when stored master hash is missing", async () => {
  const storage = new MemoryStorage();
  setPlatformStorageDriverForTests(storage.driver);
  try {
    const result = await performCurrentUnlockVerification(
      { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
      {
        deriveMasterKeyShares: async () => fakeShares(),
        combineShares: () => "e".repeat(64),
        hashMasterKey: () => "stored-hash",
        getMasterKeyHash: async () => null,
        getKdfMetadataState: async () => {
          throw new Error("KDF metadata should not be read without a stored master hash");
        },
        saveKdfMetadata: async () => {
          throw new Error("KDF metadata should not be written without a stored master hash");
        },
        planUnlockKdfDerivation: async () => {
          throw new Error("unlock KDF planner should not run without a stored master hash");
        },
        splitKeyIntoShares: () => {
          throw new Error("planner split path should not run without a stored master hash");
        },
        storeMasterKeySecurely: async () => {},
        wipeShares: () => {},
      },
    );

    assert.equal(result.ok, true);
    assert.equal(storage.items.has("pipass_kdf_metadata"), false);
  } finally {
    setPlatformStorageDriverForTests(null);
  }
});

test("current unlock verification saves metadataToPersist after verified missing-metadata Argon2id detection", async () => {
  const shares = fakeShares();
  const metadata = buildArgon2idKdfMetadata(1000, ARGON2ID_PARAMS, "unlock-migration", {
    createdAt: 1234567890,
  });
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => {
        events.push("get-stored-hash");
        return "stored-hash";
      },
      getKdfMetadataState: async () => {
        events.push("get-kdf-metadata");
        return { status: "missing", metadata: null };
      },
      saveKdfMetadata: async (metadataToSave) => {
        assert.deepEqual(metadataToSave, metadata);
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async (input) => {
        events.push(`plan-${input.metadataStatus}`);
        return {
          ok: true,
          source: "legacy-detected",
          masterKeyHex: "f".repeat(64),
          metadata,
          metadataToPersist: metadata,
        };
      },
      splitKeyIntoShares: (masterKeyHex) => {
        events.push(`split-${masterKeyHex}`);
        return shares;
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.deepEqual(result, { ok: true, shares });
  assert.deepEqual(events, [
    "get-stored-hash",
    "get-kdf-metadata",
    "plan-missing",
    "save-kdf-metadata",
    `split-${"f".repeat(64)}`,
    "cache",
  ]);
});

test("current unlock verification saves metadataToPersist after verified missing-metadata PBKDF2 detection", async () => {
  const shares = fakeShares();
  const metadata = buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
    createdAt: 1234567890,
  });
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => "stored-hash",
      getKdfMetadataState: async () => ({ status: "missing", metadata: null }),
      saveKdfMetadata: async (metadataToSave) => {
        assert.deepEqual(metadataToSave, metadata);
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async () => ({
        ok: true,
        source: "legacy-detected",
        masterKeyHex: "1".repeat(64),
        metadata,
        metadataToPersist: metadata,
      }),
      splitKeyIntoShares: () => shares,
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {},
    },
  );

  assert.deepEqual(result, { ok: true, shares });
  assert.deepEqual(events, ["save-kdf-metadata", "cache"]);
});

test("current unlock verification fails invalid KDF metadata closed without writing metadata", async () => {
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => "stored-hash",
      getKdfMetadataState: async () => ({ status: "invalid", metadata: null }),
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
      },
      planUnlockKdfDerivation: async (input) => {
        events.push(`plan-${input.metadataStatus}`);
        return { ok: false, reason: "invalid-metadata" };
      },
      splitKeyIntoShares: () => {
        events.push("split");
        return fakeShares();
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.deepEqual(result, { ok: false, reason: "invalid-kdf-metadata" });
  assert.deepEqual(events, ["plan-invalid"]);
});

test("current unlock verification allows unlock with warning when KDF metadata persistence fails after verification", async () => {
  const shares = fakeShares();
  const metadata = buildPbkdf2KdfMetadata(1000, PBKDF2_PARAMS, "legacy-detected", {
    createdAt: 1234567890,
  });
  const events: string[] = [];

  const result = await performCurrentUnlockVerification(
    { password: TEST_PASSWORD, salt: TEST_SALT, iterations: 1000 },
    {
      deriveMasterKeyShares: async () => {
        throw new Error("legacy derivation should not run");
      },
      combineShares: () => {
        throw new Error("legacy combine should not run");
      },
      hashMasterKey: () => {
        throw new Error("legacy hash should not run");
      },
      getMasterKeyHash: async () => "stored-hash",
      getKdfMetadataState: async () => ({ status: "missing", metadata: null }),
      saveKdfMetadata: async () => {
        events.push("save-kdf-metadata");
        throw new Error("storage write failed");
      },
      planUnlockKdfDerivation: async () => ({
        ok: true,
        source: "legacy-detected",
        masterKeyHex: "2".repeat(64),
        metadata,
        metadataToPersist: metadata,
      }),
      splitKeyIntoShares: () => {
        events.push("split");
        return shares;
      },
      storeMasterKeySecurely: async () => {
        events.push("cache");
      },
      wipeShares: () => {},
    },
  );

  assert.deepEqual(result, {
    ok: true,
    shares,
    warning: "kdf-metadata-persist-failed",
  });
  assert.deepEqual(events, ["save-kdf-metadata", "split", "cache"]);
});

test("first-time vault setup preparation derives setup data without storage writes", async () => {
  const shares = fakeShares();
  const events: string[] = [];

  const result = await prepareFirstTimeVaultSetup(
    { password: TEST_PASSWORD, iterations: 1000 },
    {
      generateMasterSalt: () => {
        events.push("salt");
        return TEST_SALT;
      },
      deriveMasterKeyWithArgon2id: async (_password, _salt, parameters) => {
        events.push(`argon2id-${parameters.memoryKiB}-${parameters.timeCost}-${parameters.parallelism}`);
        return "3".repeat(64);
      },
      splitKeyIntoShares: (masterKeyHex) => {
        events.push(`split-${masterKeyHex}`);
        return shares;
      },
      hashMasterKey: (masterKeyHex) => {
        events.push(`hash-${masterKeyHex}`);
        return "master-hash";
      },
      generateRecoveryKey: () => {
        events.push("recovery-key");
        return "4".repeat(64);
      },
      hashRecoveryKey: (rawKeyHex) => {
        events.push(`recovery-hash-${rawKeyHex}`);
        return "recovery-hash";
      },
    },
  );

  assert.equal(result.salt, TEST_SALT);
  assert.equal(result.iterations, 1000);
  assert.equal(result.shares, shares);
  assert.equal(result.masterKeyHex, "3".repeat(64));
  assert.equal(result.masterHash, "master-hash");
  assert.equal(result.recoveryKeyHash, "recovery-hash");
  assert.equal(result.rawRecoveryKeyHex, "4".repeat(64));
  assert.equal(result.kdfMetadata.algorithm, "argon2id");
  assert.equal(result.kdfMetadata.source, "setup");
  assert.deepEqual(events, [
    "salt",
    "argon2id-65536-3-4",
    `split-${"3".repeat(64)}`,
    `hash-${"3".repeat(64)}`,
    "recovery-key",
    `recovery-hash-${"4".repeat(64)}`,
  ]);
});

test("first-time vault setup derives with explicit Argon2id and writes setup metadata", async () => {
  const shares = fakeShares();
  const events: string[] = [];
  let savedMetadata: KdfMetadata | null = null;

  const result = await performFirstTimeVaultSetup(
    { password: TEST_PASSWORD, iterations: 1000 },
    {
      generateMasterSalt: () => {
        events.push("salt");
        return TEST_SALT;
      },
      deriveMasterKeyWithArgon2id: async (_password, _salt, parameters) => {
        events.push(`argon2id-${parameters.memoryKiB}-${parameters.timeCost}-${parameters.parallelism}`);
        return "3".repeat(64);
      },
      splitKeyIntoShares: (masterKeyHex) => {
        events.push(`split-${masterKeyHex}`);
        return shares;
      },
      hashMasterKey: (masterKeyHex) => {
        events.push(`hash-${masterKeyHex}`);
        return "master-hash";
      },
      generateRecoveryKey: () => {
        events.push("recovery-key");
        return "4".repeat(64);
      },
      hashRecoveryKey: (rawKeyHex) => {
        events.push(`recovery-hash-${rawKeyHex}`);
        return "recovery-hash";
      },
      saveMasterSalt: async (salt) => {
        events.push(`save-salt-${salt}`);
      },
      saveMasterKeyHash: async (hash) => {
        events.push(`save-master-hash-${hash}`);
      },
      saveSecurityProfile: async (iterations) => {
        events.push(`save-profile-${iterations}`);
      },
      saveKdfMetadata: async (metadata) => {
        savedMetadata = metadata;
        events.push(`save-kdf-${metadata.algorithm}-${metadata.source}`);
      },
      saveRecoveryKeyHash: async (hash) => {
        events.push(`save-recovery-hash-${hash}`);
      },
      storeMasterKeySecurely: async (masterKeyHex) => {
        events.push(`cache-${masterKeyHex}`);
      },
      wipeShares: () => {
        events.push("wipe");
      },
    },
  );

  assert.equal(result.salt, TEST_SALT);
  assert.equal(result.iterations, 1000);
  assert.equal(result.shares, shares);
  assert.equal(result.rawRecoveryKeyHex, "4".repeat(64));
  assert.equal(result.kdfMetadata.algorithm, "argon2id");
  assert.equal(result.kdfMetadata.source, "setup");
  assert.equal(result.kdfMetadata.profileIterations, 1000);
  assert.deepEqual(result.kdfMetadata.parameters, {
    memoryKiB: 65536,
    timeCost: 3,
    parallelism: 4,
    outputBytes: 32,
  });
  assert.deepEqual(savedMetadata, result.kdfMetadata);
  assert.deepEqual(events, [
    "salt",
    "argon2id-65536-3-4",
    `split-${"3".repeat(64)}`,
    `hash-${"3".repeat(64)}`,
    "recovery-key",
    `recovery-hash-${"4".repeat(64)}`,
    `save-salt-${TEST_SALT}`,
    "save-master-hash-master-hash",
    "save-profile-1000",
    "save-kdf-argon2id-setup",
    "save-recovery-hash-recovery-hash",
    `cache-${"3".repeat(64)}`,
  ]);
});

test("first-time vault setup failure does not fall back or write partial setup state", async () => {
  const events: string[] = [];

  await assert.rejects(
    performFirstTimeVaultSetup(
      { password: TEST_PASSWORD, iterations: 1000 },
      {
        generateMasterSalt: () => {
          events.push("salt");
          return TEST_SALT;
        },
        deriveMasterKeyWithArgon2id: async () => {
          events.push("argon2id");
          throw new Error("Argon2id unavailable");
        },
        splitKeyIntoShares: () => {
          events.push("split");
          return fakeShares();
        },
        hashMasterKey: () => {
          events.push("hash");
          return "master-hash";
        },
        generateRecoveryKey: () => {
          events.push("recovery-key");
          return "4".repeat(64);
        },
        hashRecoveryKey: () => {
          events.push("recovery-hash");
          return "recovery-hash";
        },
        saveMasterSalt: async () => {
          events.push("save-salt");
        },
        saveMasterKeyHash: async () => {
          events.push("save-master-hash");
        },
        saveSecurityProfile: async () => {
          events.push("save-profile");
        },
        saveKdfMetadata: async () => {
          events.push("save-kdf");
        },
        saveRecoveryKeyHash: async () => {
          events.push("save-recovery-hash");
        },
        storeMasterKeySecurely: async () => {
          events.push("cache");
        },
        wipeShares: () => {
          events.push("wipe");
        },
      },
    ),
    (err: unknown) =>
      err instanceof FirstTimeVaultSetupError &&
      err.message === "Argon2id setup derivation failed",
  );

  assert.deepEqual(events, ["salt", "argon2id"]);
});

test("first-time vault setup wipes derived shares if setup commit fails", async () => {
  const shares = fakeShares();
  const events: string[] = [];

  await assert.rejects(
    performFirstTimeVaultSetup(
      { password: TEST_PASSWORD, iterations: 1000 },
      {
        generateMasterSalt: () => TEST_SALT,
        deriveMasterKeyWithArgon2id: async () => "5".repeat(64),
        splitKeyIntoShares: () => {
          events.push("split");
          return shares;
        },
        hashMasterKey: () => "master-hash",
        generateRecoveryKey: () => "6".repeat(64),
        hashRecoveryKey: () => "recovery-hash",
        saveMasterSalt: async () => {},
        saveMasterKeyHash: async () => {},
        saveSecurityProfile: async () => {},
        saveKdfMetadata: async () => {
          events.push("save-kdf");
          throw new Error("write failed");
        },
        saveRecoveryKeyHash: async () => {
          events.push("save-recovery-hash");
        },
        storeMasterKeySecurely: async () => {
          events.push("cache");
        },
        wipeShares: (sharesToWipe) => {
          assert.equal(sharesToWipe, shares);
          events.push("wipe");
        },
      },
    ),
    /write failed/,
  );

  assert.deepEqual(events, ["split", "save-kdf", "wipe"]);
});
