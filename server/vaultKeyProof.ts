/**
 * Server-side vault-key proof checks.
 *
 * Uses node:crypto only (do not import the client `crypto/` tree).
 * Verifies a client HMAC proof against the SHA-256 verifier stored
 * on the vault row. The server never sees the master key.
 */

import { createHash, timingSafeEqual } from "node:crypto";

const HEX64 = /^[0-9a-f]{64}$/;

export function isWellFormedVaultKeyProof(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

export function hashVaultKeyProof(proof: string): string {
  return createHash("sha256").update(proof.toLowerCase(), "utf8").digest("hex");
}

export function vaultKeyProofMatches(
  providedProof: string,
  storedVerifierHex: string,
): boolean {
  if (!isWellFormedVaultKeyProof(providedProof) || !HEX64.test(storedVerifierHex)) {
    return false;
  }
  const provided = Buffer.from(hashVaultKeyProof(providedProof), "hex");
  const stored = Buffer.from(storedVerifierHex, "hex");
  if (provided.length !== stored.length) return false;
  return timingSafeEqual(provided, stored);
}

export type VaultWriteProofDecision =
  | { ok: true; verifierToStore: string }
  | { ok: false; code: "invalid" | "unbound" };

/**
 * Decide whether a write may proceed and which verifier to persist.
 *
 * - No current blob: first write binds SHA-256(proof).
 * - Blob with verifier: proof must match. Optional nextProof rotates it.
 * - Blob without verifier (legacy): fail closed — a stolen session must
 *   not be allowed to bind its own proof and then overwrite.
 */
export function decideVaultWriteProof(input: {
  storedVerifier: string | null | undefined;
  hasExistingBlob: boolean;
  providedProof: string;
  nextProof?: string;
}): VaultWriteProofDecision {
  if (!isWellFormedVaultKeyProof(input.providedProof)) {
    return { ok: false, code: "invalid" };
  }
  if (input.nextProof !== undefined && !isWellFormedVaultKeyProof(input.nextProof)) {
    return { ok: false, code: "invalid" };
  }

  if (!input.hasExistingBlob) {
    const bind = input.nextProof ?? input.providedProof;
    return { ok: true, verifierToStore: hashVaultKeyProof(bind) };
  }

  if (!input.storedVerifier) {
    return { ok: false, code: "unbound" };
  }

  if (!vaultKeyProofMatches(input.providedProof, input.storedVerifier)) {
    return { ok: false, code: "invalid" };
  }

  if (input.nextProof) {
    return { ok: true, verifierToStore: hashVaultKeyProof(input.nextProof) };
  }
  return { ok: true, verifierToStore: input.storedVerifier };
}
