import type { KeyShares } from "../crypto/secureMemory";

export type CurrentUnlockVerificationResult =
  | { ok: true; shares: KeyShares }
  | { ok: false; reason: "hash-mismatch" };

export interface CurrentUnlockVerificationDependencies {
  deriveMasterKeyShares: (
    password: string,
    salt: string,
    iterations: number,
  ) => Promise<KeyShares>;
  combineShares: (shares: KeyShares) => string;
  hashMasterKey: (masterKeyHex: string) => string;
  getMasterKeyHash: () => Promise<string | null>;
  storeMasterKeySecurely: (masterKeyHex: string) => Promise<void>;
  wipeShares: (shares: KeyShares) => void;
}

export interface CurrentUnlockVerificationInput {
  password: string;
  salt: string;
  iterations: number;
}

export async function performCurrentUnlockVerification(
  input: CurrentUnlockVerificationInput,
  dependencies: CurrentUnlockVerificationDependencies,
): Promise<CurrentUnlockVerificationResult> {
  const shares = await dependencies.deriveMasterKeyShares(
    input.password,
    input.salt,
    input.iterations,
  );
  const keyHex = dependencies.combineShares(shares);
  const keyHash = dependencies.hashMasterKey(keyHex);
  const storedHash = await dependencies.getMasterKeyHash();

  if (storedHash && keyHash !== storedHash) {
    dependencies.wipeShares(shares);
    return { ok: false, reason: "hash-mismatch" };
  }

  await dependencies.storeMasterKeySecurely(keyHex);
  return { ok: true, shares };
}
