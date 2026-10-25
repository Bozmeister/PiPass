/**
 * AES-256-GCM field encryption tests.
 *
 * Verifies:
 * - New encrypt writes v4:nonce(12B):ciphertext:tag(16B)
 * - Round-trip with field AAD
 * - Field swap / wrong recordId / wrong key fail closed
 * - Tag and ciphertext tampering fail authentication
 * - Independent node:crypto decrypt matches our output
 * - Retired EtM / unauthenticated formats are rejected
 */
import assert from "node:assert/strict";
import { createDecipheriv } from "node:crypto";
import test from "node:test";
import {
  CiphertextFormatError,
  canonicalizeFieldAad,
  decryptData,
  encryptData,
  isAuthenticatedCiphertext,
  isLegacyUnsupportedCiphertext,
  type FieldAad,
} from "../encryption";
import { deriveAesGcmKey } from "../hkdf";
import { hexToBytes, stringToBytes } from "../secureMemory";

const ENTRY_KEY = "a1".repeat(32);
const RECORD_ID = "entryid1234567";
const AAD_PASSWORD: FieldAad = { recordId: RECORD_ID, field: "password" };
const AAD_USERNAME: FieldAad = { recordId: RECORD_ID, field: "username" };

test("deriveAesGcmKey produces a 256-bit key distinct from the entry key", () => {
  const gcm = deriveAesGcmKey(ENTRY_KEY);
  assert.match(gcm, /^[0-9a-f]{64}$/i);
  assert.notEqual(gcm.toLowerCase(), ENTRY_KEY.toLowerCase());
  assert.equal(deriveAesGcmKey(ENTRY_KEY), gcm);
});

test("deriveAesGcmKey rejects non-32-byte keys", () => {
  assert.throws(() => deriveAesGcmKey("short"), /Invalid entry key/);
  assert.throws(() => deriveAesGcmKey("zz".repeat(32)), /Invalid entry key/);
});

test("canonicalizeFieldAad is stable and rejects bad input", () => {
  assert.equal(
    canonicalizeFieldAad(AAD_PASSWORD),
    `pipass-aad-v1:${RECORD_ID}:password`,
  );
  assert.throws(
    () => canonicalizeFieldAad({ recordId: "", field: "password" }),
    (err: unknown) => err instanceof CiphertextFormatError && err.code === "aad-invalid",
  );
  assert.throws(
    () => canonicalizeFieldAad({ recordId: "a:b", field: "password" }),
    (err: unknown) => err instanceof CiphertextFormatError && err.code === "aad-invalid",
  );
});

test("encryptData writes v4 AES-256-GCM format only", () => {
  const ct = encryptData("secret-password", ENTRY_KEY, AAD_PASSWORD);
  const parts = ct.split(":");
  assert.equal(parts[0], "v4");
  assert.equal(parts.length, 4);
  assert.equal(parts[1].length, 24);
  assert.match(parts[1], /^[0-9a-f]{24}$/);
  assert.match(parts[2], /^[0-9a-f]+$/);
  assert.equal(parts[2].length % 2, 0);
  assert.equal(parts[3].length, 32);
  assert.equal(isAuthenticatedCiphertext(ct), true);
});

test("encryptData / decryptData round-trip with AAD", () => {
  const plaintext = "hunter2-and-emoji-🔐";
  const ct = encryptData(plaintext, ENTRY_KEY, AAD_PASSWORD);
  assert.equal(decryptData(ct, ENTRY_KEY, AAD_PASSWORD), plaintext);
});

test("empty plaintext and unicode round-trip", () => {
  assert.equal(decryptData(encryptData("", ENTRY_KEY, AAD_PASSWORD), ENTRY_KEY, AAD_PASSWORD), "");
  const ja = "日本語パスワード";
  assert.equal(decryptData(encryptData(ja, ENTRY_KEY, AAD_PASSWORD), ENTRY_KEY, AAD_PASSWORD), ja);
});

test("v4 decrypt requires AAD", () => {
  const ct = encryptData("needs-aad", ENTRY_KEY, AAD_PASSWORD);
  assert.throws(
    () => decryptData(ct, ENTRY_KEY),
    (err: unknown) => err instanceof CiphertextFormatError && err.code === "aad-required",
  );
});

test("v4 decrypt rejects wrong entry key", () => {
  const ct = encryptData("vault-secret", ENTRY_KEY, AAD_PASSWORD);
  assert.throws(
    () => decryptData(ct, "b2".repeat(32), AAD_PASSWORD),
    /Authentication failed/,
  );
});

test("v4 field swap is rejected (AAD binds field name)", () => {
  const passwordCt = encryptData("the-password", ENTRY_KEY, AAD_PASSWORD);
  const usernameCt = encryptData("the-username", ENTRY_KEY, AAD_USERNAME);

  assert.equal(decryptData(passwordCt, ENTRY_KEY, AAD_PASSWORD), "the-password");
  assert.equal(decryptData(usernameCt, ENTRY_KEY, AAD_USERNAME), "the-username");

  assert.throws(
    () => decryptData(passwordCt, ENTRY_KEY, AAD_USERNAME),
    /Authentication failed/,
  );
  assert.throws(
    () => decryptData(usernameCt, ENTRY_KEY, AAD_PASSWORD),
    /Authentication failed/,
  );
});

test("v4 AAD binds recordId (cross-entry ciphertext reuse fails)", () => {
  const ct = encryptData("secret", ENTRY_KEY, AAD_PASSWORD);
  assert.throws(
    () =>
      decryptData(ct, ENTRY_KEY, {
        recordId: "other-entry-id",
        field: "password",
      }),
    /Authentication failed/,
  );
});

test("v4 tag and ciphertext tampering fail authentication", () => {
  const ct = encryptData("payload", ENTRY_KEY, AAD_PASSWORD);
  const parts = ct.split(":");
  const flipCt = parts[2].slice(0, -1) + (parts[2].endsWith("0") ? "1" : "0");
  assert.throws(
    () => decryptData(`${parts[0]}:${parts[1]}:${flipCt}:${parts[3]}`, ENTRY_KEY, AAD_PASSWORD),
    /Authentication failed/,
  );
  const flipTag = parts[3].slice(0, -1) + (parts[3].endsWith("a") ? "b" : "a");
  assert.throws(
    () => decryptData(`${parts[0]}:${parts[1]}:${parts[2]}:${flipTag}`, ENTRY_KEY, AAD_PASSWORD),
    /Authentication failed/,
  );
  const flipNonce = parts[1].slice(0, -1) + (parts[1].endsWith("0") ? "1" : "0");
  assert.throws(
    () => decryptData(`${parts[0]}:${flipNonce}:${parts[2]}:${parts[3]}`, ENTRY_KEY, AAD_PASSWORD),
    /Authentication failed/,
  );
});

test("v4 ciphertext decrypts with independent node:crypto AES-GCM", () => {
  const plaintext = "interop-secret";
  const ct = encryptData(plaintext, ENTRY_KEY, AAD_PASSWORD);
  const [, nonceHex, bodyHex, tagHex] = ct.split(":");
  const key = hexToBytes(deriveAesGcmKey(ENTRY_KEY));
  const decipher = createDecipheriv("aes-256-gcm", key, hexToBytes(nonceHex), {
    authTagLength: 16,
  });
  decipher.setAAD(stringToBytes(canonicalizeFieldAad(AAD_PASSWORD)));
  decipher.setAuthTag(hexToBytes(tagHex));
  const out = Buffer.concat([
    decipher.update(hexToBytes(bodyHex)),
    decipher.final(),
  ]).toString("utf8");
  assert.equal(out, plaintext);
});

test("two encryptions of the same plaintext produce different nonces", () => {
  const a = encryptData("same", ENTRY_KEY, AAD_PASSWORD);
  const b = encryptData("same", ENTRY_KEY, AAD_PASSWORD);
  assert.notEqual(a, b);
  assert.notEqual(a.split(":")[1], b.split(":")[1]);
  assert.equal(decryptData(a, ENTRY_KEY, AAD_PASSWORD), "same");
  assert.equal(decryptData(b, ENTRY_KEY, AAD_PASSWORD), "same");
});

test("retired EtM and unauthenticated formats are rejected", () => {
  const twoPart = `${"11".repeat(16)}:${"22".repeat(32)}`;
  const v1 = `${"ab".repeat(16)}:${"cd".repeat(32)}:${"ef".repeat(32)}`;
  const v2 = `v2:${"ab".repeat(16)}:${"cd".repeat(32)}:${"ef".repeat(32)}`;
  const v3 = `v3:${"ab".repeat(16)}:${"cd".repeat(32)}:${"ef".repeat(32)}`;

  assert.equal(isLegacyUnsupportedCiphertext(twoPart), true);
  assert.equal(isLegacyUnsupportedCiphertext(v1), true);
  assert.equal(isLegacyUnsupportedCiphertext(v2), true);
  assert.equal(isLegacyUnsupportedCiphertext(v3), true);
  assert.equal(isAuthenticatedCiphertext(v3), false);

  for (const blob of [twoPart, v1, v2, v3]) {
    assert.throws(
      () => decryptData(blob, ENTRY_KEY, AAD_PASSWORD),
      (err: unknown) =>
        err instanceof CiphertextFormatError && err.code === "legacy-unsupported",
    );
  }
});

test("garbage ciphertext is invalid-format, not a decrypt crash", () => {
  assert.throws(
    () => decryptData("not-a-blob", ENTRY_KEY, AAD_PASSWORD),
    (err: unknown) =>
      err instanceof CiphertextFormatError && err.code === "invalid-format",
  );
});
