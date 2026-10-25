import type { KeyShares } from "../crypto/secureMemory";
import type {
  UnlockKdfDerivationPlanInput,
  UnlockKdfDerivationPlanResult,
  UnlockKdfMetadataStatus,
} from "../crypto/keyDerivation";
import type { KdfMetadata } from "../crypto/kdfMetadata";

type CurrentUnlockWarning = "kdf-metadata-persist-failed";

export type CurrentUnlockVerificationResult =
  | {
      ok: true;
      shares: KeyShares;
      warning?: CurrentUnlockWarning;
    }
  | {
      ok: false;
      reason:
        | "hash-mismatch"
        | "invalid-kdf-metadata"
        | "argon2id-unavailable"
        | "kdf-derivation-failed";
    };

export type CurrentUnlockKdfMetadataState =
  | { status: "valid"; metadata: KdfMetadata }
  | { status: "missing"; metadata: null }
  | { status: "invalid"; metadata: null };

export interface CurrentUnlockVerificationDependencies {
  getMasterKeyHash: () => Promise<string | null>;
  getKdfMetadataState: () => Promise<CurrentUnlockKdfMetadataState>;
  saveKdfMetadata: (metadata: KdfMetadata) => Promise<void>;
  planUnlockKdfDerivation: (
    input: UnlockKdfDerivationPlanInput,
  ) => Promise<UnlockKdfDerivationPlanResult>;
  splitKeyIntoShares: (masterKeyHex: string) => KeyShares;
  storeMasterKeySecurely: (masterKeyHex: string) => Promise<void>;
  wipeShares: (shares: KeyShares) => void;
}

export interface CurrentUnlockVerificationInput {
  password: string;
  salt: string;
  iterations: number;
}

/**
 * Verifies master password against stored hash + KDF metadata only.
 * Does not publish shares or cache the master key. Used for nuclear-reset
 * confirmation and similar gates that must not silent-downgrade KDF.
 */
export async function verifyMasterPasswordWithStoredKdf(
  input: CurrentUnlockVerificationInput,
  dependencies: Pick<
    CurrentUnlockVerificationDependencies,
    "getMasterKeyHash" | "getKdfMetadataState" | "planUnlockKdfDerivation"
  >,
): Promise<boolean> {
  const storedHash = await dependencies.getMasterKeyHash();
  if (!storedHash) {
    // Fail closed: no verifier means we cannot prove password knowledge
    // without inventing a KDF path (silent downgrade risk).
    return false;
  }

  const metadataState = await dependencies.getKdfMetadataState();
  const plan = await dependencies.planUnlockKdfDerivation({
    password: input.password,
    saltHex: input.salt,
    profileIterations: input.iterations,
    storedMasterHash: storedHash,
    existingMetadata: metadataState.metadata,
    metadataStatus: metadataState.status as UnlockKdfMetadataStatus,
  });

  return plan.ok;
}

export async function performCurrentUnlockVerification(
  input: CurrentUnlockVerificationInput,
  dependencies: CurrentUnlockVerificationDependencies,
): Promise<CurrentUnlockVerificationResult> {
  const storedHash = await dependencies.getMasterKeyHash();

  if (!storedHash) {
    // Fail closed: do not derive with an invented/weak KDF when no hash exists.
    return { ok: false, reason: "kdf-derivation-failed" };
  }

  const metadataState = await dependencies.getKdfMetadataState();
  const plan = await dependencies.planUnlockKdfDerivation({
    password: input.password,
    saltHex: input.salt,
    profileIterations: input.iterations,
    storedMasterHash: storedHash,
    existingMetadata: metadataState.metadata,
    metadataStatus: metadataState.status as UnlockKdfMetadataStatus,
  });

  if (!plan.ok) {
    return { ok: false, reason: mapPlanFailureReason(plan.reason) };
  }

  let warning: CurrentUnlockWarning | undefined;

  if (plan.metadataToPersist) {
    try {
      await dependencies.saveKdfMetadata(plan.metadataToPersist);
    } catch {
      warning = "kdf-metadata-persist-failed";
    }
  }

  const shares = dependencies.splitKeyIntoShares(plan.masterKeyHex);
  try {
    await dependencies.storeMasterKeySecurely(plan.masterKeyHex);
  } catch (err) {
    dependencies.wipeShares(shares);
    throw err;
  }

  return warning ? { ok: true, shares, warning } : { ok: true, shares };
}

function mapPlanFailureReason(
  reason: Extract<UnlockKdfDerivationPlanResult, { ok: false }>["reason"],
): Extract<CurrentUnlockVerificationResult, { ok: false }>["reason"] {
  if (reason === "invalid-metadata") return "invalid-kdf-metadata";
  if (reason === "argon2id-unavailable") return "argon2id-unavailable";
  if (reason === "metadata-hash-mismatch" || reason === "legacy-no-match") {
    return "hash-mismatch";
  }
  return "kdf-derivation-failed";
}
