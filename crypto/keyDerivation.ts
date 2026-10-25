import CryptoJS from "crypto-js";
import { getDeviceUUID, clearDeviceUUID } from "./deviceUUIDStorage";
import {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  isValidKdfMetadata,
  kdfUsesDeviceUuidBinding,
  KDF_DEVICE_BINDING_UUID_V1,
  type Argon2idKdfParameters,
  type KdfMetadata,
  type Pbkdf2KdfParameters,
} from "./kdfMetadata";
import {
  adaptNativeArgon2,
  isAndroidNativeArgon2Platform,
  tryResolveNativeArgon2Fn,
  type Argon2BinaryParams,
} from "./nativeArgon2";

export { diagnoseNativeArgon2, isNativeArgon2Confirmed } from "./nativeArgon2";

// Key derivation preference:
//   1) Android native Argon2id (modules/pipass-argon2 → NativeModules.RNArgon2)
//   2) hash-wasm Argon2id (iOS, web, Node, or native missing/failed)
//   3) Strong PBKDF2-SHA256 (Create Vault fallback; unlock follows KDF metadata)
//
// JS never requires @sphereon/react-native-argon2. Native is Android-only
// because iOS CatCrypto would treat hex salt as UTF-8 and disagree with wasm.

let argon2idFn: ((params: Argon2BinaryParams) => Promise<Uint8Array>) | null = null;
let argon2LoadFailed = false;
/** Once native Argon2 is missing or throws, skip it for the rest of the session. */
let nativeArgon2RuntimeFailed = false;
/** Last successful Argon2 backend for diagnostics. */
let argon2Backend: "native" | "wasm" | null = null;

/** Production-safe: static label only — never log params, lengths, or exception payloads. */
function logKdfError(label: string, _err?: unknown): void {
  try {
    console.error(label);
  } catch {
    // never throw from logging
  }
}

/**
 * loadArgon2 NEVER throws and NEVER requires @sphereon/react-native-argon2.
 * Order: Android native (probe) → hash-wasm → null (PBKDF2).
 */
async function loadArgon2(): Promise<((params: Argon2BinaryParams) => Promise<Uint8Array>) | null> {
  try {
    if (argon2LoadFailed) {
      return null;
    }
    if (argon2idFn) return argon2idFn;

    if (isAndroidNativeArgon2Platform() && !nativeArgon2RuntimeFailed) {
      const nativeArgon = tryResolveNativeArgon2Fn();

      if (typeof nativeArgon === "function") {
        const adaptedNative = async (params: Argon2BinaryParams): Promise<Uint8Array> => {
          try {
            return await adaptNativeArgon2(nativeArgon)(params);
          } catch (nativeErr: unknown) {
            nativeArgon2RuntimeFailed = true;
            argon2idFn = null;
            argon2Backend = null;
            logKdfError("[KDF] Native Argon2 invoke failed", nativeErr);
            throw nativeErr;
          }
        };

        try {
          const probeSalt = new Uint8Array(32);
          for (let i = 0; i < 32; i++) probeSalt[i] = (0x5a ^ i) & 0xff;
          if (probeSalt[0] === 0) probeSalt[0] = 0x81;
          const probePw = new TextEncoder().encode("pipass-argon2-probe");
          await adaptedNative({
            password: probePw,
            salt: probeSalt,
            iterations: 1,
            memorySize: 8192,
            parallelism: 1,
            hashLength: 32,
          });
          wipeBuffer(probePw);
          wipeBuffer(probeSalt);
          argon2idFn = adaptedNative;
          argon2Backend = "native";
          return argon2idFn;
        } catch (probeErr: unknown) {
          nativeArgon2RuntimeFailed = true;
          argon2idFn = null;
          logKdfError("[KDF] Native Argon2 probe failed", probeErr);
        }
      } else {
        nativeArgon2RuntimeFailed = true;
      }
    }

    // WASM Argon2id (preferred over PBKDF2 when native is missing)
    try {
      const mod = await import("hash-wasm");
      if (mod == null || typeof mod.argon2id !== "function") {
        throw new Error("hash-wasm.argon2id unavailable");
      }
      argon2idFn = (params) =>
        mod.argon2id({
          ...params,
          outputType: "binary" as const,
        });
      argon2Backend = "wasm";
      return argon2idFn;
    } catch (e: unknown) {
      logKdfError("[KDF] hash-wasm unavailable", e);
      argon2LoadFailed = true;
      argon2Backend = null;
      return null;
    }
  } catch (outer: unknown) {
    logKdfError("[KDF] loadArgon2 unexpected failure", outer);
    argon2LoadFailed = true;
    argon2Backend = null;
    return null;
  }
}

export function getArgon2BackendForDiagnostics(): "native" | "wasm" | null {
  return argon2Backend;
}

/**
 * @deprecated v2.0 always prefers Argon2id first (native/wasm) with strong PBKDF2 fallback.
 * Kept for any external callers; always returns false so setup tries Argon2 first.
 */
export function shouldPreferPbkdf2ForSetup(): boolean {
  return false;
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

export interface KdfDerivationOptions {
  /**
   * Legacy install UUID. Used only when the vault's KDF metadata (or an
   * explicit bindDeviceUUID / deviceUUID option) requests deviceUUID:v1.
   */
  deviceUUID?: string;
  /**
   * When true, mix `password + ":" + deviceUUID` (legacy vaults).
   * When false, use the password alone (new vaults).
   * Omitted: bind only if `deviceUUID` is provided (test / explicit callers).
   */
  bindDeviceUUID?: boolean;
}

type ExplicitArgon2idDeriver = typeof deriveMasterKeyWithArgon2id;
type ExplicitPbkdf2Deriver = typeof deriveMasterKeyWithPbkdf2;
type MetadataKdfDeriver = typeof deriveMasterKeyFromKdfMetadata;
type LegacyKdfDetector = typeof detectLegacyKdfFromMasterHash;

interface LegacyKdfDetectionOptions extends KdfDerivationOptions {
  kdfVersion?: KdfVersion;
  createdAt?: number;
  deriveArgon2id?: ExplicitArgon2idDeriver;
  derivePbkdf2?: ExplicitPbkdf2Deriver;
}

export type UnlockKdfMetadataStatus = "valid" | "missing" | "invalid";

export interface UnlockKdfDerivationPlanInput extends KdfDerivationOptions {
  password: string;
  saltHex: string;
  profileIterations: number;
  storedMasterHash: string;
  existingMetadata?: KdfMetadata | null;
  metadataStatus?: UnlockKdfMetadataStatus;
  kdfVersion?: KdfVersion;
  createdAt?: number;
  deriveFromMetadata?: MetadataKdfDeriver;
  detectLegacy?: LegacyKdfDetector;
}

export type LegacyKdfDetectionResult =
  | {
      matched: true;
      algorithm: "argon2id" | "pbkdf2-sha256";
      metadata: KdfMetadata;
      masterKeyHex: string;
    }
  | {
      matched: false;
      reason: "invalid-input" | "no-match";
    };

export type UnlockKdfDerivationPlanResult =
  | {
      ok: true;
      source: "metadata" | "legacy-detected";
      metadata: KdfMetadata;
      metadataToPersist?: KdfMetadata;
      masterKeyHex: string;
    }
  | {
      ok: false;
      reason:
        | "invalid-input"
        | "invalid-metadata"
        | "metadata-hash-mismatch"
        | "legacy-no-match"
        | "argon2id-unavailable";
    };

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b: number) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("Invalid hex salt");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function wipeBuffer(buffer: Uint8Array): void {
  buffer.fill(0);
}

function shouldBindDeviceUUID(options: KdfDerivationOptions): boolean {
  if (options.bindDeviceUUID === false) return false;
  if (options.bindDeviceUUID === true) return true;
  return typeof options.deviceUUID === "string" && options.deviceUUID.length > 0;
}

/**
 * Password material fed into Argon2id / PBKDF2.
 *
 * New vaults (`deviceBinding: "none"`): password only.
 * Legacy vaults (`deviceBinding: "deviceUUID:v1"`): `password + ":" + uuid`.
 */
async function getKdfMaterial(password: string, options: KdfDerivationOptions = {}): Promise<string> {
  if (!shouldBindDeviceUUID(options)) {
    return password;
  }
  const deviceUUID = options.deviceUUID ?? await getDeviceUUID();
  return password + ":" + deviceUUID;
}

function derivationOptionsForMetadata(
  metadata: KdfMetadata,
  options: KdfDerivationOptions = {},
): KdfDerivationOptions {
  if (kdfUsesDeviceUuidBinding(metadata.deviceBinding)) {
    return {
      bindDeviceUUID: true,
      deviceUUID: options.deviceUUID,
    };
  }
  return { bindDeviceUUID: false };
}

// Pixel-stable Argon2id profiles (still memory-hard / OWASP-aligned).
// Previous Fortress used 128 MiB + p=4 and Deep Vault 256 MiB + p=4, which could
// native-OOM (force-close) on some Google Pixels — uncatchable from JS.
// Fortress stays default/recommended; memory is capped at 64 MiB with p=2.
const KDF_CONFIGS = {
  v1: {
    getTimeCost: (safeIterations: number) =>
      safeIterations <= 25000 ? 3 : safeIterations <= 100000 ? 4 : 5,
    getMemorySize: (safeIterations: number) =>
      // Balanced/Fortress: 64 MiB; Deep Vault: 96 MiB (was 256 MiB)
      safeIterations <= 100000 ? 65536 : 98304,
    parallelism: 2,
  },
  v2: {
    getTimeCost: (safeIterations: number) =>
      Math.max(safeIterations <= 25000 ? 3 : safeIterations <= 100000 ? 4 : 5, 3),
    getMemorySize: (safeIterations: number) =>
      Math.max(safeIterations <= 100000 ? 65536 : 98304, 65536),
    parallelism: 1,
  },
} as const;

function isKdfVersion(value: unknown): value is KdfVersion {
  return value === "v1" || value === "v2";
}

function safeProfileIterations(iterations: number): number {
  return Math.max(iterations || 100000, 3);
}

export function getArgon2idKdfParameters(
  profileIterations: number,
  kdfVersion: KdfVersion = "v1",
): Argon2idKdfParameters {
  const safeIterations = safeProfileIterations(profileIterations);
  const config = KDF_CONFIGS[kdfVersion];
  return {
    memoryKiB: config.getMemorySize(safeIterations),
    timeCost: config.getTimeCost(safeIterations),
    parallelism: config.parallelism,
    outputBytes: 32,
  };
}

/**
 * Legacy / unlock PBKDF2 parameters (1:1 with security profile iteration label).
 * Used for unlock of existing vaults and legacy detection — do not raise floors here.
 */
export function getPbkdf2Parameters(profileIterations: number): Pbkdf2KdfParameters {
  return {
    iterations: safeProfileIterations(profileIterations),
    outputBytes: 32,
  };
}

/**
 * High-security pure-JS PBKDF2-SHA256 for Create Vault when Argon2id is unavailable.
 * Stores actual iteration count in KDF metadata so unlock uses the same parameters.
 *
 * Floor 600_000 aligns with OWASP PBKDF2-HMAC-SHA256 guidance; higher profiles scale up.
 * Fortress (100k profile) → 600k; Deep Vault (250k) → 1.5M.
 */
/** Hard floor for Create Vault PBKDF2 fallback (OWASP PBKDF2-HMAC-SHA256). */
export const STRONG_PBKDF2_FALLBACK_FLOOR = 600_000;

export function getStrongPbkdf2FallbackParameters(
  profileIterations: number,
): Pbkdf2KdfParameters {
  const profile = safeProfileIterations(profileIterations);
  // Fortress (100k) → 600k; Deep Vault (250k) → 1.5M. Never below floor.
  const iterations = Math.max(STRONG_PBKDF2_FALLBACK_FLOOR, profile * 6);
  if (iterations < STRONG_PBKDF2_FALLBACK_FLOOR) {
    // Defensive — Math.max above already enforces this.
    return { iterations: STRONG_PBKDF2_FALLBACK_FLOOR, outputBytes: 32 };
  }
  return {
    iterations,
    outputBytes: 32,
  };
}

export async function deriveMasterKeyWithArgon2id(
  password: string,
  saltHex: string,
  parameters: Argon2idKdfParameters,
  options: KdfDerivationOptions = {},
): Promise<string> {
  let argon2: ((params: Argon2BinaryParams) => Promise<Uint8Array>) | null = null;
  try {
    argon2 = await loadArgon2();
  } catch (loadErr: unknown) {
    logKdfError("[KDF] loadArgon2 failed", loadErr);
    throw new KdfDerivationError("Argon2id is unavailable");
  }
  if (!argon2) {
    logKdfError("[KDF] Argon2id is unavailable");
    throw new KdfDerivationError("Argon2id is unavailable");
  }

  let material: string;
  try {
    material = await getKdfMaterial(password, options);
  } catch (matErr: unknown) {
    logKdfError("[KDF] getKdfMaterial failed", matErr);
    throw new KdfDerivationError("Argon2id derivation failed");
  }

  // Use decoded 32-byte binary salt for argon2 (ensures native + wasm produce identical keys;
  // native expects the hex string and will decode equivalently).
  let salt: Uint8Array;
  let passwordBytes: Uint8Array;
  try {
    salt = hexToBytes(saltHex);
    if (salt.length !== 32) {
      throw new Error("Argon2id salt must be exactly 32 bytes");
    }
    passwordBytes = new TextEncoder().encode(material);
  } catch (prepErr: unknown) {
    logKdfError("[KDF] Argon2id input prep failed", prepErr);
    throw new KdfDerivationError("Argon2id derivation failed");
  }

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
  } catch (err: unknown) {
    logKdfError("[KDF] Argon2id derivation failed", err);
    // If native failed mid-flight, try wasm once more before giving up to caller
    // (caller / firstTimeSetup will fall back to PBKDF2 if this still throws).
    if (nativeArgon2RuntimeFailed && !argon2LoadFailed) {
      try {
        argon2idFn = null;
        argon2Backend = null;
        const wasmArgon = await loadArgon2();
        if (wasmArgon) {
          const keyBytes = await wasmArgon({
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
        }
      } catch (wasmRetryErr: unknown) {
        logKdfError("[KDF] wasm Argon2id retry failed", wasmRetryErr);
      }
    }
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
  try {
    const material = await getKdfMaterial(password, options);
    const stretched = CryptoJS.PBKDF2(material, saltHex, {
      keySize: parameters.outputBytes / 4,
      iterations: parameters.iterations,
      hasher: CryptoJS.algo.SHA256,
    });
    const hex = stretched.toString(CryptoJS.enc.Hex);
    return hex;
  } catch (err: unknown) {
    logKdfError("[KDF] PBKDF2 derivation failed", err);
    throw new KdfDerivationError("PBKDF2 derivation failed");
  }
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

  const boundOptions = derivationOptionsForMetadata(metadata, options);

  if (metadata.algorithm === "argon2id") {
    return deriveMasterKeyWithArgon2id(password, saltHex, metadata.parameters, boundOptions);
  }

  if (metadata.algorithm === "pbkdf2-sha256") {
    return deriveMasterKeyWithPbkdf2(password, saltHex, metadata.parameters, boundOptions);
  }

  throw new KdfDerivationError("Unsupported KDF metadata");
}

export async function detectLegacyKdfFromMasterHash(
  password: string,
  saltHex: string,
  profileIterations: number,
  storedMasterHash: string,
  options: LegacyKdfDetectionOptions = {},
): Promise<LegacyKdfDetectionResult> {
  const kdfVersion = options.kdfVersion ?? "v1";
  if (
    typeof password !== "string" ||
    password.length === 0 ||
    typeof saltHex !== "string" ||
    saltHex.length === 0 ||
    !Number.isSafeInteger(profileIterations) ||
    profileIterations <= 0 ||
    !/^[0-9a-f]{64}$/i.test(storedMasterHash) ||
    !isKdfVersion(kdfVersion)
  ) {
    return { matched: false, reason: "invalid-input" };
  }

  const createdAt = options.createdAt ?? Date.now();
  // Vaults with no KDF metadata were all created with deviceUUID:v1 binding.
  const derivationOptions: KdfDerivationOptions = {
    bindDeviceUUID: true,
    deviceUUID: options.deviceUUID,
  };
  const argon2idParameters = getArgon2idKdfParameters(profileIterations, kdfVersion);
  const pbkdf2Parameters = getPbkdf2Parameters(profileIterations);
  const deriveArgon2id = options.deriveArgon2id ?? deriveMasterKeyWithArgon2id;
  const derivePbkdf2 = options.derivePbkdf2 ?? deriveMasterKeyWithPbkdf2;

  try {
    const masterKeyHex = await deriveArgon2id(password, saltHex, argon2idParameters, derivationOptions);
    if (hashMasterKey(masterKeyHex) === storedMasterHash) {
      return {
        matched: true,
        algorithm: "argon2id",
        masterKeyHex,
        metadata: buildArgon2idKdfMetadata(profileIterations, argon2idParameters, "unlock-migration", {
          kdfVersion,
          createdAt,
          deviceBinding: KDF_DEVICE_BINDING_UUID_V1,
        }),
      };
    }
  } catch {
    // Legacy detection must continue to the PBKDF2 candidate when
    // explicit Argon2id is unavailable or fails.
  }

  try {
    const masterKeyHex = await derivePbkdf2(password, saltHex, pbkdf2Parameters, derivationOptions);
    if (hashMasterKey(masterKeyHex) === storedMasterHash) {
      return {
        matched: true,
        algorithm: "pbkdf2-sha256",
        masterKeyHex,
        metadata: buildPbkdf2KdfMetadata(profileIterations, pbkdf2Parameters, "legacy-detected", {
          createdAt,
          deviceBinding: KDF_DEVICE_BINDING_UUID_V1,
        }),
      };
    }
  } catch {
    return { matched: false, reason: "no-match" };
  }

  return { matched: false, reason: "no-match" };
}

export async function planUnlockKdfDerivation(
  input: UnlockKdfDerivationPlanInput,
): Promise<UnlockKdfDerivationPlanResult> {
  const {
    password,
    saltHex,
    profileIterations,
    storedMasterHash,
    existingMetadata = null,
    metadataStatus,
    kdfVersion = "v1",
    createdAt,
    deviceUUID,
  } = input;

  if (
    typeof password !== "string" ||
    password.length === 0 ||
    typeof saltHex !== "string" ||
    saltHex.length === 0 ||
    !Number.isSafeInteger(profileIterations) ||
    profileIterations <= 0 ||
    !/^[0-9a-f]{64}$/i.test(storedMasterHash) ||
    !isKdfVersion(kdfVersion)
  ) {
    return { ok: false, reason: "invalid-input" };
  }

  const status = metadataStatus ?? (existingMetadata ? "valid" : "missing");
  const derivationOptions: KdfDerivationOptions = deviceUUID ? { deviceUUID } : {};

  if (status === "invalid") {
    return { ok: false, reason: "invalid-metadata" };
  }

  if (status === "valid") {
    if (!existingMetadata || !isValidKdfMetadata(existingMetadata)) {
      return { ok: false, reason: "invalid-metadata" };
    }

    const deriveFromMetadata = input.deriveFromMetadata ?? deriveMasterKeyFromKdfMetadata;
    try {
      const masterKeyHex = await deriveFromMetadata(password, saltHex, existingMetadata, derivationOptions);
      if (hashMasterKey(masterKeyHex) !== storedMasterHash) {
        return { ok: false, reason: "metadata-hash-mismatch" };
      }

      return {
        ok: true,
        source: "metadata",
        masterKeyHex,
        metadata: existingMetadata,
      };
    } catch (err) {
      if (err instanceof KdfDerivationError && err.message === "Argon2id is unavailable") {
        return { ok: false, reason: "argon2id-unavailable" };
      }
      return { ok: false, reason: "metadata-hash-mismatch" };
    }
  }

  if (status !== "missing") {
    return { ok: false, reason: "invalid-input" };
  }

  const detectLegacy = input.detectLegacy ?? detectLegacyKdfFromMasterHash;
  const legacyResult = await detectLegacy(password, saltHex, profileIterations, storedMasterHash, {
    kdfVersion,
    createdAt,
    ...derivationOptions,
  });

  if (!legacyResult.matched) {
    return {
      ok: false,
      reason: legacyResult.reason === "invalid-input" ? "invalid-input" : "legacy-no-match",
    };
  }

  return {
    ok: true,
    source: "legacy-detected",
    masterKeyHex: legacyResult.masterKeyHex,
    metadata: legacyResult.metadata,
    metadataToPersist: legacyResult.metadata,
  };
}

/**
 * @deprecated Prefer planUnlockKdfDerivation / deriveMasterKeyFromKdfMetadata for unlock
 * and verify, and deriveMasterKeyWithArgon2id / deriveMasterKeyWithPbkdf2 (with explicit
 * metadata) for setup. This helper only runs Argon2id with profile-mapped parameters —
 * it does NOT silently fall back to weak PBKDF2 (that desynced vaults and under-strength keys).
 *
 * Does not mix deviceUUID (new-vault KDF). Unlock/verify must use
 * planUnlockKdfDerivation so stored deviceBinding is honored.
 *
 * The salt must be stored alongside the vault — it is NOT secret.
 */
export async function deriveMasterKey(
  password: string,
  saltHex: string,
  iterations: number = 100000,
  kdfVersion: KdfVersion = "v1"
): Promise<string> {
  const parameters = getArgon2idKdfParameters(iterations, kdfVersion);
  // Explicit Argon2 only — no silent algorithm/strength change without metadata.
  return deriveMasterKeyWithArgon2id(password, saltHex, parameters);
}

// Verify a password against a known master key hash
export function hashMasterKey(masterKeyHex: string): string {
  return CryptoJS.SHA256(masterKeyHex).toString(CryptoJS.enc.Hex);
}
