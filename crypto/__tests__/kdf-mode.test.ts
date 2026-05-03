import assert from "node:assert/strict";
import test from "node:test";
import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
} from "../kdfMetadata";
import {
  deriveMasterKeyFromKdfMetadata,
  deriveMasterKeyWithArgon2id,
  deriveMasterKeyWithPbkdf2,
  KdfDerivationError,
} from "../keyDerivation";
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
