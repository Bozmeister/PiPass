export type KdfMetadataAlgorithm = "argon2id" | "pbkdf2-sha256";
export type KdfMetadataSource =
  | "setup"
  | "unlock-migration"
  | "password-rotation"
  | "profile-change"
  | "legacy-detected";

export interface Argon2idKdfParameters {
  memoryKiB: number;
  timeCost: number;
  parallelism: number;
  outputBytes: 32;
}

export interface Pbkdf2KdfParameters {
  iterations: number;
  outputBytes: 32;
}

interface BaseKdfMetadata {
  version: 1;
  algorithm: KdfMetadataAlgorithm;
  profileIterations: number;
  kdfVersion: string;
  parameters: object;
  saltKey: "pipass_master_salt";
  deviceBinding: "deviceUUID:v1";
  createdAt: number;
  source: KdfMetadataSource;
}

export interface Argon2idKdfMetadata extends BaseKdfMetadata {
  algorithm: "argon2id";
  parameters: Argon2idKdfParameters;
}

export interface Pbkdf2KdfMetadata extends BaseKdfMetadata {
  algorithm: "pbkdf2-sha256";
  parameters: Pbkdf2KdfParameters;
}

export type KdfMetadata = Argon2idKdfMetadata | Pbkdf2KdfMetadata;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafePositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0;
}

function isValidKdfMetadataSource(value: unknown): value is KdfMetadataSource {
  return (
    value === "setup" ||
    value === "unlock-migration" ||
    value === "password-rotation" ||
    value === "profile-change" ||
    value === "legacy-detected"
  );
}

function isValidArgon2idParameters(value: unknown): value is Argon2idKdfParameters {
  if (!isRecord(value)) return false;
  return (
    isSafePositiveInteger(value.memoryKiB) &&
    isSafePositiveInteger(value.timeCost) &&
    isSafePositiveInteger(value.parallelism) &&
    value.outputBytes === 32
  );
}

function isValidPbkdf2Parameters(value: unknown): value is Pbkdf2KdfParameters {
  if (!isRecord(value)) return false;
  return isSafePositiveInteger(value.iterations) && value.outputBytes === 32;
}

export function isValidKdfMetadata(value: unknown): value is KdfMetadata {
  if (!isRecord(value)) return false;

  if (
    value.version !== 1 ||
    !isSafePositiveInteger(value.profileIterations) ||
    typeof value.kdfVersion !== "string" ||
    value.kdfVersion.trim().length === 0 ||
    value.saltKey !== "pipass_master_salt" ||
    value.deviceBinding !== "deviceUUID:v1" ||
    !isSafePositiveInteger(value.createdAt) ||
    !isValidKdfMetadataSource(value.source)
  ) {
    return false;
  }

  if (value.algorithm === "argon2id") {
    return isValidArgon2idParameters(value.parameters);
  }

  if (value.algorithm === "pbkdf2-sha256") {
    return isValidPbkdf2Parameters(value.parameters);
  }

  return false;
}

export function buildArgon2idKdfMetadata(
  profileIterations: number,
  parameters: Argon2idKdfParameters,
  source: KdfMetadataSource,
  options: { kdfVersion?: string; createdAt?: number } = {},
): Argon2idKdfMetadata {
  const metadata: Argon2idKdfMetadata = {
    version: 1,
    algorithm: "argon2id",
    profileIterations,
    kdfVersion: options.kdfVersion ?? "v1",
    parameters,
    saltKey: "pipass_master_salt",
    deviceBinding: "deviceUUID:v1",
    createdAt: options.createdAt ?? Date.now(),
    source,
  };

  if (!isValidKdfMetadata(metadata)) {
    throw new Error("Invalid KDF metadata");
  }

  return metadata;
}

export function buildPbkdf2KdfMetadata(
  profileIterations: number,
  parameters: Pbkdf2KdfParameters,
  source: KdfMetadataSource,
  options: { kdfVersion?: string; createdAt?: number } = {},
): Pbkdf2KdfMetadata {
  const metadata: Pbkdf2KdfMetadata = {
    version: 1,
    algorithm: "pbkdf2-sha256",
    profileIterations,
    kdfVersion: options.kdfVersion ?? "legacy-pbkdf2-v1",
    parameters,
    saltKey: "pipass_master_salt",
    deviceBinding: "deviceUUID:v1",
    createdAt: options.createdAt ?? Date.now(),
    source,
  };

  if (!isValidKdfMetadata(metadata)) {
    throw new Error("Invalid KDF metadata");
  }

  return metadata;
}
