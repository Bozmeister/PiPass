import assert from "node:assert/strict";
import test from "node:test";
import {
  adaptNativeArgon2,
  diagnoseNativeArgon2,
  isAndroidNativeArgon2Platform,
  isNativeArgon2Confirmed,
  tryResolveNativeArgon2Fn,
} from "../nativeArgon2";

test("Node/web test env does not claim a native Android Argon2 bridge", () => {
  assert.equal(isAndroidNativeArgon2Platform(), false);
  assert.equal(isNativeArgon2Confirmed(), false);
  assert.equal(tryResolveNativeArgon2Fn(), null);
  const diag = diagnoseNativeArgon2();
  assert.equal(diag.ok, false);
});

test("native adapter rejects a salt that is not 32 bytes", async () => {
  const adapter = adaptNativeArgon2(async () => ({ rawHash: "aa".repeat(32) }));
  await assert.rejects(
    () =>
      adapter({
        password: new TextEncoder().encode("pw"),
        salt: new Uint8Array(16),
        iterations: 1,
        memorySize: 8,
        parallelism: 1,
        hashLength: 32,
      }),
    /exactly 32-byte salt/,
  );
});

test("native adapter decodes rawHash hex from the bridge", async () => {
  const adapter = adaptNativeArgon2(async (password, saltHex, config) => {
    assert.equal(password, "pw");
    assert.equal(saltHex.length, 64);
    assert.equal(config.mode, "argon2id");
    return { rawHash: "ab".repeat(32) };
  });
  const out = await adapter({
    password: new TextEncoder().encode("pw"),
    salt: new Uint8Array(32).fill(0x11),
    iterations: 2,
    memorySize: 64,
    parallelism: 1,
    hashLength: 32,
  });
  assert.equal(out.length, 32);
  assert.equal(out[0], 0xab);
  assert.equal(out[31], 0xab);
});
