/**
 * Vault-key proof-of-possession (cloud overwrite gate).
 */
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import test from "node:test";
import { createVaultKeyProof, isWellFormedVaultKeyProof } from "../vaultKeyProof";
import {
  decideVaultWriteProof,
  hashVaultKeyProof,
  vaultKeyProofMatches,
} from "../../server/vaultKeyProof";

const USER = "11111111-1111-4111-8111-111111111111";
const MASTER = "ab".repeat(32);

test("createVaultKeyProof matches node:crypto HMAC-SHA256", () => {
  const fromClient = createVaultKeyProof(MASTER, USER);
  const fromNode = createHmac("sha256", Buffer.from(MASTER, "hex"))
    .update(`pipass.vault.pop.v1|${USER}`, "utf8")
    .digest("hex");
  assert.equal(fromClient, fromNode);
  assert.equal(isWellFormedVaultKeyProof(fromClient), true);
});

test("createVaultKeyProof is bound to userId and master key", () => {
  const a = createVaultKeyProof(MASTER, USER);
  const otherUser = createVaultKeyProof(MASTER, "22222222-2222-4222-8222-222222222222");
  const otherKey = createVaultKeyProof("cd".repeat(32), USER);
  assert.notEqual(a, otherUser);
  assert.notEqual(a, otherKey);
});

test("first write binds SHA-256(proof); later write requires a match", () => {
  const proof = createVaultKeyProof(MASTER, USER);
  const first = decideVaultWriteProof({
    storedVerifier: null,
    hasExistingBlob: false,
    providedProof: proof,
  });
  assert.equal(first.ok, true);
  if (!first.ok) return;
  assert.equal(first.verifierToStore, hashVaultKeyProof(proof));

  const good = decideVaultWriteProof({
    storedVerifier: first.verifierToStore,
    hasExistingBlob: true,
    providedProof: proof,
  });
  assert.equal(good.ok, true);

  const bad = decideVaultWriteProof({
    storedVerifier: first.verifierToStore,
    hasExistingBlob: true,
    providedProof: "ab".repeat(32),
  });
  assert.equal(bad.ok, false);
  if (bad.ok) return;
  assert.equal(bad.code, "invalid");
});

test("existing blob without a verifier fails closed", () => {
  const proof = createVaultKeyProof(MASTER, USER);
  const decision = decideVaultWriteProof({
    storedVerifier: null,
    hasExistingBlob: true,
    providedProof: proof,
  });
  assert.equal(decision.ok, false);
  if (decision.ok) return;
  assert.equal(decision.code, "unbound");
});

test("nextProof rotates the stored verifier only after current proof matches", () => {
  const proof = createVaultKeyProof(MASTER, USER);
  const next = createVaultKeyProof("ef".repeat(32), USER);
  const first = decideVaultWriteProof({
    storedVerifier: null,
    hasExistingBlob: false,
    providedProof: proof,
  });
  assert.equal(first.ok, true);
  if (!first.ok) return;

  const rotate = decideVaultWriteProof({
    storedVerifier: first.verifierToStore,
    hasExistingBlob: true,
    providedProof: proof,
    nextProof: next,
  });
  assert.equal(rotate.ok, true);
  if (!rotate.ok) return;
  assert.equal(rotate.verifierToStore, hashVaultKeyProof(next));
  assert.equal(vaultKeyProofMatches(next, rotate.verifierToStore), true);
  assert.equal(vaultKeyProofMatches(proof, rotate.verifierToStore), false);
});

test("hashVaultKeyProof is not the raw HMAC", () => {
  const proof = createVaultKeyProof(MASTER, USER);
  assert.notEqual(hashVaultKeyProof(proof), proof);
  assert.equal(hashVaultKeyProof(proof), createHash("sha256").update(proof, "utf8").digest("hex"));
});
