import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  type KdfMetadata,
  type Pbkdf2KdfParameters,
} from "../crypto/kdfMetadata";
import {
  getArgon2idKdfParameters,
  getPbkdf2Parameters,
  type KdfVersion,
} from "../crypto/keyDerivation";
import type { KeyShares } from "../crypto/secureMemory";

export class FirstTimeVaultSetupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FirstTimeVaultSetupError";
  }
}

export interface FirstTimeVaultSetupInput {
  password: string;
  iterations: number;
  kdfVersion?: KdfVersion;
}

export interface FirstTimeVaultSetupPrepareDependencies {
  generateMasterSalt: () => string;
  deriveMasterKeyWithArgon2id: (
    password: string,
    saltHex: string,
    parameters: ReturnType<typeof getArgon2idKdfParameters>,
  ) => Promise<string>;
  deriveMasterKeyWithPbkdf2?: (
    password: string,
    saltHex: string,
    parameters: Pbkdf2KdfParameters,
  ) => Promise<string>;
  splitKeyIntoShares: (masterKeyHex: string) => KeyShares;
  hashMasterKey: (masterKeyHex: string) => string;
  generateRecoveryKey: () => string;
  hashRecoveryKey: (rawKeyHex: string) => string;
}

export interface FirstTimeVaultSetupDependencies extends FirstTimeVaultSetupPrepareDependencies {
  saveMasterSalt: (saltHex: string) => Promise<void>;
  saveMasterKeyHash: (hashHex: string) => Promise<void>;
  saveSecurityProfile: (iterations: number) => Promise<void>;
  saveKdfMetadata: (metadata: KdfMetadata) => Promise<void>;
  saveRecoveryKeyHash: (hashHex: string) => Promise<void>;
  storeMasterKeySecurely: (masterKeyHex: string) => Promise<void>;
  wipeShares: (shares: KeyShares) => void;
}

export interface FirstTimeVaultSetupResult {
  salt: string;
  iterations: number;
  shares: KeyShares;
  rawRecoveryKeyHex: string;
  kdfMetadata: KdfMetadata;
}

export interface PreparedFirstTimeVaultSetupResult extends FirstTimeVaultSetupResult {
  masterKeyHex: string;
  masterHash: string;
  recoveryKeyHash: string;
}

export async function prepareFirstTimeVaultSetup(
  input: FirstTimeVaultSetupInput,
  dependencies: FirstTimeVaultSetupPrepareDependencies,
): Promise<PreparedFirstTimeVaultSetupResult> {
  const validIterations = Math.max(input.iterations || 100000, 3);
  const kdfVersion = input.kdfVersion ?? "v1";
  const salt = dependencies.generateMasterSalt();
  const argon2idParameters = getArgon2idKdfParameters(validIterations, kdfVersion);

  let masterKeyHex: string;
  let kdfMetadata: KdfMetadata;
  try {
    masterKeyHex = await dependencies.deriveMasterKeyWithArgon2id(
      input.password,
      salt,
      argon2idParameters,
    );
    kdfMetadata = buildArgon2idKdfMetadata(
      validIterations,
      argon2idParameters,
      "setup",
      { kdfVersion },
    );
  } catch (err: any) {
    // Critical: log the exact underlying exception so root cause (e.g. native/WASM init on Pixel arm64) is visible
    console.error(
      "[SETUP] deriveMasterKeyWithArgon2id failed during vault creation (Create Vault). Exact underlying exception:",
      err && (err.stack || err.message || String(err))
    );
    const pbDerive = dependencies.deriveMasterKeyWithPbkdf2;
    if (!pbDerive) {
      // Preserve legacy error for callers/tests that do not provide fallback (minimal change)
      throw new FirstTimeVaultSetupError("Argon2id setup derivation failed");
    }
    console.log("[SETUP] Falling back to PBKDF2-SHA256 (Fortress/selected profile iters preserved) so vault creation never fails due to KDF engine init.");
    const pbkdf2Parameters = getPbkdf2Parameters(validIterations);
    masterKeyHex = await pbDerive(
      input.password,
      salt,
      pbkdf2Parameters,
    );
    kdfMetadata = buildPbkdf2KdfMetadata(
      validIterations,
      pbkdf2Parameters,
      "setup",
      { kdfVersion },
    );
  }

  const shares = dependencies.splitKeyIntoShares(masterKeyHex);
  const masterHash = dependencies.hashMasterKey(masterKeyHex);
  const rawRecoveryKeyHex = dependencies.generateRecoveryKey();
  const recoveryKeyHash = dependencies.hashRecoveryKey(rawRecoveryKeyHex);

  return {
    salt,
    iterations: validIterations,
    shares,
    rawRecoveryKeyHex,
    kdfMetadata,
    masterKeyHex,
    masterHash,
    recoveryKeyHash,
  };
}

export async function performFirstTimeVaultSetup(
  input: FirstTimeVaultSetupInput,
  dependencies: FirstTimeVaultSetupDependencies,
): Promise<FirstTimeVaultSetupResult> {
  const prepared = await prepareFirstTimeVaultSetup(input, dependencies);

  try {
    await dependencies.saveMasterSalt(prepared.salt);
    await dependencies.saveMasterKeyHash(prepared.masterHash);
    await dependencies.saveSecurityProfile(prepared.iterations);
    await dependencies.saveKdfMetadata(prepared.kdfMetadata);
    await dependencies.saveRecoveryKeyHash(prepared.recoveryKeyHash);
    await dependencies.storeMasterKeySecurely(prepared.masterKeyHex);
  } catch (err) {
    dependencies.wipeShares(prepared.shares);
    throw err;
  }

  return {
    salt: prepared.salt,
    iterations: prepared.iterations,
    shares: prepared.shares,
    rawRecoveryKeyHex: prepared.rawRecoveryKeyHex,
    kdfMetadata: prepared.kdfMetadata,
  };
}
