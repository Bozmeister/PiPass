export type BackupVerifierDerivation = "entry-v1" | "note-v1";

export interface BackupVerifier {
  version: 1;
  type: "encrypted-sentinel";
  derivation: BackupVerifierDerivation;
  recordId: string;
  salt: string;
  ciphertext: string;
  expectedPlaintextHash: string;
}

export type BackupVerifierParseErrorCode =
  | "missing-verifier"
  | "invalid-verifier"
  | "unsupported-version"
  | "unsupported-type"
  | "unsupported-derivation"
  | "invalid-record-id"
  | "invalid-salt"
  | "invalid-ciphertext"
  | "invalid-expected-plaintext-hash";

export interface BackupVerifierParseError {
  code: BackupVerifierParseErrorCode;
  message: string;
  path?: string;
}

export type BackupVerifierParseResult =
  | { ok: true; verifier: BackupVerifier }
  | { ok: false; error: BackupVerifierParseError };

const MAX_RECORD_ID_LENGTH = 128;
const MAX_SALT_HEX_LENGTH = 256;
const MAX_CIPHERTEXT_LENGTH = 1_000_000;
const SHA256_HEX_LENGTH = 64;

export function parseBackupVerifier(value: unknown): BackupVerifierParseResult {
  if (!isRecord(value)) {
    return verifierError("invalid-verifier", "Backup verifier must be an object.");
  }

  if (value.version !== 1) {
    return verifierError("unsupported-version", "Backup verifier version is not supported.", "version");
  }

  if (value.type !== "encrypted-sentinel") {
    return verifierError("unsupported-type", "Backup verifier type is not supported.", "type");
  }

  if (value.derivation !== "entry-v1" && value.derivation !== "note-v1") {
    return verifierError(
      "unsupported-derivation",
      "Backup verifier derivation is not supported.",
      "derivation",
    );
  }

  if (!isNonEmptyString(value.recordId) || value.recordId.length > MAX_RECORD_ID_LENGTH) {
    return verifierError("invalid-record-id", "Backup verifier recordId is invalid.", "recordId");
  }

  if (
    !isNonEmptyString(value.salt) ||
    value.salt.length > MAX_SALT_HEX_LENGTH ||
    !isLowercaseHex(value.salt)
  ) {
    return verifierError("invalid-salt", "Backup verifier salt is invalid.", "salt");
  }

  if (!isNonEmptyString(value.ciphertext) || value.ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
    return verifierError("invalid-ciphertext", "Backup verifier ciphertext is invalid.", "ciphertext");
  }

  if (
    typeof value.expectedPlaintextHash !== "string" ||
    value.expectedPlaintextHash.length !== SHA256_HEX_LENGTH ||
    !isLowercaseHex(value.expectedPlaintextHash)
  ) {
    return verifierError(
      "invalid-expected-plaintext-hash",
      "Backup verifier expectedPlaintextHash is invalid.",
      "expectedPlaintextHash",
    );
  }

  return {
    ok: true,
    verifier: {
      version: 1,
      type: "encrypted-sentinel",
      derivation: value.derivation,
      recordId: value.recordId,
      salt: value.salt,
      ciphertext: value.ciphertext,
      expectedPlaintextHash: value.expectedPlaintextHash,
    },
  };
}

export function isBackupVerifier(value: unknown): value is BackupVerifier {
  return parseBackupVerifier(value).ok;
}

export function getBackupVerifierFromMetadata(metadata: unknown): BackupVerifierParseResult {
  if (!isRecord(metadata) || metadata.verifier === undefined) {
    return verifierError("missing-verifier", "Backup verifier is missing.", "verifier");
  }

  return parseBackupVerifier(metadata.verifier);
}

function verifierError(
  code: BackupVerifierParseErrorCode,
  message: string,
  path?: string,
): BackupVerifierParseResult {
  return {
    ok: false,
    error: {
      code,
      message,
      path,
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isLowercaseHex(value: string): boolean {
  return /^[0-9a-f]+$/.test(value);
}
