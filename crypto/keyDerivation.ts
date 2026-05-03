import CryptoJS from "crypto-js";
import { getDeviceUUID, clearDeviceUUID } from "./deviceUUIDStorage";
import {
  isValidKdfMetadata,
  type Argon2idKdfParameters,
  type KdfMetadata,
  type Pbkdf2KdfParameters,
} from "./kdfMetadata";

// Key derivation using industry-standard PBKDF2-SHA256.
// Argon2id is attempted first (if WebAssembly is available), with PBKDF2 as fallback.
// No custom cryptographic algorithms are used in the security-critical path.

type Argon2BinaryParams = {
  password: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  memorySize: number;
  parallelism: number;
  hashLength: number;
};

let argon2idFn: ((params: Argon2BinaryParams) => Promise<Uint8Array>) | null = null;
let argon2LoadFailed = false;

async function loadArgon2(): Promise<((params: Argon2BinaryParams) => Promise<Uint8Array>) | null> {
  if (argon2LoadFailed) return null;
  if (argon2idFn) return argon2idFn;
  try {
    const mod = await import("hash-wasm");
    argon2idFn = (params) =>
      mod.argon2id({
        ...params,
        outputType: "binary" as const,
      });
    return argon2idFn;
  } catch {
    argon2LoadFailed = true;
    return null;
  }
}

export { clearDeviceUUID };

export function generateMasterSalt(): string {
  const ExpoCrypto = require("expo-crypto") as typeof import("expo-crypto");
  const saltBytes = ExpoCrypto.getRandomBytes(32);
  return Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export type KdfVersion = "v1" | "v2";

export class KdfDerivationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KdfDerivationError";
  }
}

interface KdfDerivationOptions {
  deviceUUID?: string;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b: number) => b.toString(16).padStart(2, "0"))
    .join("");
}

function wipeBuffer(buffer: Uint8Array): void {
  buffer.fill(0);
}

async function getKdfMaterial(password: string, options: KdfDerivationOptions = {}): Promise<string> {
  const deviceUUID = options.deviceUUID ?? await getDeviceUUID();
  return password + ":" + deviceUUID;
}

const KDF_CONFIGS = {
  v1: {
    getTimeCost: (safeIterations: number) =>
      safeIterations <= 25000 ? 3 : safeIterations <= 100000 ? 4 : 6,
    getMemorySize: (safeIterations: number) =>
      safeIterations <= 25000 ? 65536 : safeIterations <= 100000 ? 131072 : 262144,
    parallelism: 4,
  },
  v2: {
    getTimeCost: (safeIterations: number) =>
      Math.max(safeIterations <= 25000 ? 3 : safeIterations <= 100000 ? 4 : 6, 3),
    getMemorySize: (safeIterations: number) =>
      Math.max(safeIterations <= 25000 ? 65536 : safeIterations <= 100000 ? 131072 : 262144, 65536),
    parallelism: 1,
  },
} as const;

export async function deriveMasterKeyWithArgon2id(
  password: string,
  saltHex: string,
  parameters: Argon2idKdfParameters,
  options: KdfDerivationOptions = {},
): Promise<string> {
  const argon2 = await loadArgon2();
  if (!argon2) {
    throw new KdfDerivationError("Argon2id is unavailable");
  }

  const material = await getKdfMaterial(password, options);
  const salt = new TextEncoder().encode(saltHex);
  const passwordBytes = new TextEncoder().encode(material);

  try {
    const keyBytes = await argon2({
      password: passwordBytes,
      salt,
      iterations: parameters.timeCost,
      memorySize: parameters.memoryKiB,
      parallelism: parameters.parallelism,
      hashLength: parameters.outputBytes,
    });
    const result = bytesToHex(keyBytes);
    wipeBuffer(keyBytes);
    return result;
  } catch {
    throw new KdfDerivationError("Argon2id derivation failed");
  } finally {
    wipeBuffer(passwordBytes);
    wipeBuffer(salt);
  }
}

export async function deriveMasterKeyWithPbkdf2(
  password: string,
  saltHex: string,
  parameters: Pbkdf2KdfParameters,
  options: KdfDerivationOptions = {},
): Promise<string> {
  const material = await getKdfMaterial(password, options);
  const stretched = CryptoJS.PBKDF2(material, saltHex, {
    keySize: parameters.outputBytes / 4,
    iterations: parameters.iterations,
    hasher: CryptoJS.algo.SHA256,
  });
  return stretched.toString(CryptoJS.enc.Hex);
}

export async function deriveMasterKeyFromKdfMetadata(
  password: string,
  saltHex: string,
  metadata: KdfMetadata,
  options: KdfDerivationOptions = {},
): Promise<string> {
  if (!isValidKdfMetadata(metadata)) {
    throw new KdfDerivationError("Invalid KDF metadata");
  }

  if (metadata.algorithm === "argon2id") {
    return deriveMasterKeyWithArgon2id(password, saltHex, metadata.parameters, options);
  }

  if (metadata.algorithm === "pbkdf2-sha256") {
    return deriveMasterKeyWithPbkdf2(password, saltHex, metadata.parameters, options);
  }

  throw new KdfDerivationError("Unsupported KDF metadata");
}

// Derives the master key from a user-provided password.
// Uses Argon2id when available, PBKDF2-SHA256 as fallback.
// The salt must be stored alongside the vault — it is NOT secret.
// kdfVersion defaults to "v1" for backward compatibility with existing vaults.
export async function deriveMasterKey(
  password: string,
  saltHex: string,
  iterations: number = 100000,
  kdfVersion: KdfVersion = "v1"
): Promise<string> {
  const safeIterations = Math.max(iterations || 100000, 3);
  const deviceUUID = await getDeviceUUID();

  // Mix password with device UUID so keys are device-bound
  const material = password + ":" + deviceUUID;
  const salt = new TextEncoder().encode(saltHex);

  const config = KDF_CONFIGS[kdfVersion];

  // Try Argon2id first (memory-hard, best protection)
  const argon2 = await loadArgon2();
  if (argon2) {
    try {
      const timeCost = config.getTimeCost(safeIterations);
      const memorySize = config.getMemorySize(safeIterations);

      if (kdfVersion === "v2") {
        if (memorySize < 65536) {
          throw new Error("Argon2id memoryCost must be at least 65536 (64MB)");
        }
        if (timeCost < 3) {
          throw new Error("Argon2id timeCost must be at least 3");
        }
      }

      const passwordBytes = new TextEncoder().encode(material);
      const keyBytes = await argon2({
        password: passwordBytes,
        salt,
        iterations: timeCost,
        memorySize,
        parallelism: config.parallelism,
        hashLength: 32,
      });
      const result = bytesToHex(keyBytes);
      wipeBuffer(keyBytes);
      wipeBuffer(passwordBytes);
      wipeBuffer(salt);
      return result;
    } catch {
      wipeBuffer(salt);
      // Fall through to PBKDF2
    }
  }

  // Fallback: PBKDF2-SHA256 (works everywhere)
  const stretched = CryptoJS.PBKDF2(material, saltHex, {
    keySize: 256 / 32,
    iterations: safeIterations,
    hasher: CryptoJS.algo.SHA256,
  });
  return stretched.toString(CryptoJS.enc.Hex);
}

// Verify a password against a known master key hash
export function hashMasterKey(masterKeyHex: string): string {
  return CryptoJS.SHA256(masterKeyHex).toString(CryptoJS.enc.Hex);
}
