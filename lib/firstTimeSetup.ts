import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  KDF_DEVICE_BINDING_NONE,
  type KdfMetadata,
  type Pbkdf2KdfParameters,
} from "../crypto/kdfMetadata";
import {
  getArgon2idKdfParameters,
  getStrongPbkdf2FallbackParameters,
  STRONG_PBKDF2_FALLBACK_FLOOR,
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
}

export interface FirstTimeVaultSetupDependencies extends FirstTimeVaultSetupPrepareDependencies {
  saveMasterSalt: (saltHex: string) => Promise<void>;
  saveMasterKeyHash: (hashHex: string) => Promise<void>;
  saveSecurityProfile: (iterations: number) => Promise<void>;
  saveKdfMetadata: (metadata: KdfMetadata) => Promise<void>;
  storeMasterKeySecurely: (masterKeyHex: string) => Promise<void>;
  wipeShares: (shares: KeyShares) => void;
}

export interface FirstTimeVaultSetupResult {
  salt: string;
  iterations: number;
  shares: KeyShares;
  kdfMetadata: KdfMetadata;
}

export interface PreparedFirstTimeVaultSetupResult extends FirstTimeVaultSetupResult {
  masterKeyHex: string;
  masterHash: string;
}

/** Production-safe: static label only — no password lengths, salts, or KDF params. */
function logSetupError(label: string, _err?: unknown): void {
  try {
    console.error(label);
  } catch {
    // never throw from logging
  }
}

/**
 * Prepare first-time vault setup (derive keys, build metadata) without writing storage.
 *
 * Security preference (v2.0+):
 * 1. Prefer Argon2id (Android native pipass-argon2, else hash-wasm).
 *    Fortress profile parameters are used for the selected iteration tier.
 * 2. On any Argon2 failure/unavailability: strong pure-JS PBKDF2-SHA256
 *    (OWASP-aligned high iteration count).
 * 3. Always store the actual algorithm in kdfMetadata so unlock matches.
 *
 * Crash-proof: only throws FirstTimeVaultSetupError; never requires Sphereon.
 */
export async function prepareFirstTimeVaultSetup(
  input: FirstTimeVaultSetupInput,
  dependencies: FirstTimeVaultSetupPrepareDependencies,
): Promise<PreparedFirstTimeVaultSetupResult> {
  try {
    const validIterations = Math.max(input.iterations || 100000, 3);
    const kdfVersion = input.kdfVersion ?? "v1";

    if (typeof input.password !== "string" || input.password.length === 0) {
      throw new FirstTimeVaultSetupError("Master password is required to create a vault.");
    }

    let salt: string;
    try {
      salt = dependencies.generateMasterSalt();
    } catch (saltErr: unknown) {
      logSetupError("[SETUP] generateMasterSalt failed", saltErr);
      throw new FirstTimeVaultSetupError(
        "Could not generate a secure salt on this device. Vault was not created.",
      );
    }

    const argon2idParameters = getArgon2idKdfParameters(validIterations, kdfVersion);
    // Strong PBKDF2 for fallback only — actual count stored in metadata for unlock.
    let pbkdf2Parameters = getStrongPbkdf2FallbackParameters(validIterations);
    if (pbkdf2Parameters.iterations < STRONG_PBKDF2_FALLBACK_FLOOR) {
      pbkdf2Parameters = {
        iterations: STRONG_PBKDF2_FALLBACK_FLOOR,
        outputBytes: 32,
      };
    }

    // Assigned in Argon2 success path or strong PBKDF2 fallback; both failures throw.
    let masterKeyHex!: string;
    let kdfMetadata!: KdfMetadata;
    const pbDerive = dependencies.deriveMasterKeyWithPbkdf2;

    const runPbkdf2 = async (_reason: string): Promise<void> => {
      if (!pbDerive) {
        throw new FirstTimeVaultSetupError("Argon2id setup derivation failed");
      }
      masterKeyHex = await pbDerive(input.password, salt, pbkdf2Parameters);
      kdfMetadata = buildPbkdf2KdfMetadata(validIterations, pbkdf2Parameters, "setup", {
        kdfVersion,
        deviceBinding: KDF_DEVICE_BINDING_NONE,
      });
    };

    // Primary: Argon2id (null-safe native path inside deriveMasterKeyWithArgon2id / loadArgon2)
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
        { kdfVersion, deviceBinding: KDF_DEVICE_BINDING_NONE },
      );
    } catch (err: unknown) {
      logSetupError("[SETUP] Argon2id failed; trying strong PBKDF2 fallback", err);
      try {
        await runPbkdf2("after Argon2id unavailable or failure");
      } catch (pbErr: unknown) {
        if (pbErr instanceof FirstTimeVaultSetupError) throw pbErr;
        logSetupError("[SETUP] Strong PBKDF2 fallback failed", pbErr);
        throw new FirstTimeVaultSetupError(
          "Key derivation failed on this device (Argon2 and PBKDF2). Vault was not created.",
        );
      }
    }

    let shares: KeyShares;
    let masterHash: string;
    try {
      shares = dependencies.splitKeyIntoShares(masterKeyHex);
      masterHash = dependencies.hashMasterKey(masterKeyHex);
    } catch (materialErr: unknown) {
      logSetupError("[SETUP] Vault material creation failed", materialErr);
      throw new FirstTimeVaultSetupError(
        "Vault could not be prepared safely after key derivation. Nothing was saved.",
      );
    }

    return {
      salt,
      iterations: validIterations,
      shares,
      kdfMetadata,
      masterKeyHex,
      masterHash,
    };
  } catch (outer: unknown) {
    if (outer instanceof FirstTimeVaultSetupError) {
      logSetupError("[SETUP] Create Vault prepare failed", outer);
      throw outer;
    }
    logSetupError("[SETUP] Create Vault prepare unexpected failure", outer);
    throw new FirstTimeVaultSetupError(
      "Vault creation failed unexpectedly. Nothing was saved. Please try again.",
    );
  }
}

export async function performFirstTimeVaultSetup(
  input: FirstTimeVaultSetupInput,
  dependencies: FirstTimeVaultSetupDependencies,
): Promise<FirstTimeVaultSetupResult> {
  let prepared: PreparedFirstTimeVaultSetupResult;
  try {
    prepared = await prepareFirstTimeVaultSetup(input, dependencies);
  } catch (prepErr: unknown) {
    logSetupError("[SETUP] prepare stage failed", prepErr);
    throw prepErr instanceof FirstTimeVaultSetupError
      ? prepErr
      : new FirstTimeVaultSetupError("Vault creation failed during key derivation.");
  }

  try {
    await dependencies.saveMasterSalt(prepared.salt);
    await dependencies.saveMasterKeyHash(prepared.masterHash);
    await dependencies.saveSecurityProfile(prepared.iterations);
    await dependencies.saveKdfMetadata(prepared.kdfMetadata);
    await dependencies.storeMasterKeySecurely(prepared.masterKeyHex);
  } catch (err: unknown) {
    logSetupError("[SETUP] Vault storage writes failed", err);
    try {
      dependencies.wipeShares(prepared.shares);
    } catch (wipeErr: unknown) {
      logSetupError("[SETUP] wipeShares after storage failure failed", wipeErr);
    }
    throw err;
  }

  return {
    salt: prepared.salt,
    iterations: prepared.iterations,
    shares: prepared.shares,
    kdfMetadata: prepared.kdfMetadata,
  };
}
