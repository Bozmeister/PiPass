import type { SecureNote, VaultEntry } from "../workers/vaultWorker";
import { isValidKdfMetadata, type KdfMetadata } from "../crypto/kdfMetadata";

export const PIPASS_BACKUP_SCHEMA = "pipass-backup";
export const PIPASS_BACKUP_VERSION = 1;
export const PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS = "encrypted-local-records";

export type PipassBackupKind = typeof PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS;

export type BackupParseErrorCode =
  | "invalid-json"
  | "invalid-root"
  | "missing-schema"
  | "unsupported-schema"
  | "unsupported-version"
  | "unsupported-format"
  | "invalid-created-at"
  | "invalid-metadata"
  | "entries-not-array"
  | "secure-notes-not-array"
  | "invalid-entry"
  | "invalid-secure-note";

export interface BackupParseError {
  code: BackupParseErrorCode;
  message: string;
  path?: string;
}

export interface BackupStageResult {
  kind: PipassBackupKind;
  schema: typeof PIPASS_BACKUP_SCHEMA;
  version: typeof PIPASS_BACKUP_VERSION;
  format: PipassBackupKind;
  createdAt: number;
  entries: VaultEntry[];
  secureNotes: SecureNote[];
  counts: {
    entries: number;
    secureNotes: number;
  };
  warnings: string[];
  metadata: Record<string, unknown>;
}

export type BackupParseResult =
  | { ok: true; backup: BackupStageResult }
  | { ok: false; error: BackupParseError };

export interface BackupCompatibilityContext {
  format: PipassBackupKind | string;
  kdfMetadata: KdfMetadata | null;
  masterSaltPresent: boolean;
  deviceBinding: "deviceUUID:v1" | string;
  deviceUUIDPresent: boolean;
}

export interface BackupCompatibilityResult {
  status: "compatible" | "incompatible" | "unknown";
  reason: string;
  warnings: string[];
}

export function parsePipassBackup(input: unknown): BackupParseResult {
  const parsed = parseInput(input);
  if (!parsed.ok) {
    return parsed;
  }

  const candidate = parsed.value;
  if (!isRecord(candidate)) {
    return validationError("invalid-root", "Backup root must be a JSON object.");
  }

  if (candidate.schema === undefined) {
    return validationError("missing-schema", "Backup schema is required.", "schema");
  }
  if (candidate.schema !== PIPASS_BACKUP_SCHEMA) {
    return validationError("unsupported-schema", "Backup schema is not supported.", "schema");
  }

  if (candidate.version !== PIPASS_BACKUP_VERSION) {
    return validationError("unsupported-version", "Backup version is not supported.", "version");
  }

  if (candidate.format !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS) {
    return validationError("unsupported-format", "Backup format is not supported.", "format");
  }

  if (!isSafePositiveInteger(candidate.createdAt)) {
    return validationError("invalid-created-at", "Backup createdAt must be a safe positive integer.", "createdAt");
  }

  if (!Array.isArray(candidate.entries)) {
    return validationError("entries-not-array", "Backup entries must be an array.", "entries");
  }

  const secureNotesValue = candidate.secureNotes ?? [];
  if (!Array.isArray(secureNotesValue)) {
    return validationError("secure-notes-not-array", "Backup secureNotes must be an array.", "secureNotes");
  }

  const metadataValue = candidate.metadata ?? {};
  if (!isRecord(metadataValue)) {
    return validationError("invalid-metadata", "Backup metadata must be an object.", "metadata");
  }

  for (let index = 0; index < candidate.entries.length; index++) {
    const entryError = validateEncryptedEntry(candidate.entries[index], index);
    if (entryError) {
      return entryError;
    }
  }

  for (let index = 0; index < secureNotesValue.length; index++) {
    const noteError = validateEncryptedSecureNote(secureNotesValue[index], index);
    if (noteError) {
      return noteError;
    }
  }

  const entries = candidate.entries as VaultEntry[];
  const secureNotes = secureNotesValue as SecureNote[];

  return {
    ok: true,
    backup: {
      kind: PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS,
      schema: PIPASS_BACKUP_SCHEMA,
      version: PIPASS_BACKUP_VERSION,
      format: PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS,
      createdAt: candidate.createdAt,
      entries: [...entries],
      secureNotes: [...secureNotes],
      counts: {
        entries: entries.length,
        secureNotes: secureNotes.length,
      },
      warnings: [
        "encrypted-local-records backups are staged only and require a future compatibility or rekey flow before commit",
      ],
      metadata: { ...metadataValue },
    },
  };
}

export const stagePipassBackup = parsePipassBackup;

export function isVersionedPipassBackup(value: unknown): boolean {
  return (
    isRecord(value) &&
    value.schema === PIPASS_BACKUP_SCHEMA &&
    value.version === PIPASS_BACKUP_VERSION &&
    value.format === PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS
  );
}

export function classifyBackupCompatibility(
  backup: BackupStageResult,
  localContext: BackupCompatibilityContext,
): BackupCompatibilityResult {
  const warnings = collectCompatibilityWarnings(backup);

  if (
    backup.kind !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS ||
    backup.format !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS ||
    localContext.format !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS
  ) {
    return {
      status: "incompatible",
      reason: "unsupported-backup-format",
      warnings,
    };
  }

  const compatibility = getBackupCompatibilityMetadata(backup);
  if (compatibility === undefined) {
    return {
      status: "unknown",
      reason: "missing-compatibility-metadata",
      warnings: [
        ...warnings,
        "backup compatibility must be verified by a future rekey or full decrypt flow before commit",
      ],
    };
  }

  if (!isRecord(compatibility)) {
    return {
      status: "incompatible",
      reason: "invalid-compatibility-metadata",
      warnings,
    };
  }

  if (compatibility.format !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS) {
    return {
      status: "incompatible",
      reason: "compatibility-format-mismatch",
      warnings,
    };
  }

  if (compatibility.deviceScope === "portable") {
    return {
      status: "incompatible",
      reason: "portable-encrypted-backups-not-supported",
      warnings,
    };
  }

  if (compatibility.deviceScope !== undefined && compatibility.deviceScope !== "same-install") {
    return {
      status: "incompatible",
      reason: "unsupported-device-scope",
      warnings,
    };
  }

  if (compatibility.requiresSameDeviceUUID === true && !localContext.deviceUUIDPresent) {
    return {
      status: "incompatible",
      reason: "required-device-uuid-missing",
      warnings,
    };
  }

  if (compatibility.saltKey !== undefined && compatibility.saltKey !== "pipass_master_salt") {
    return {
      status: "incompatible",
      reason: "salt-key-mismatch",
      warnings,
    };
  }

  if (!localContext.masterSaltPresent) {
    return {
      status: "unknown",
      reason: "local-master-salt-missing",
      warnings,
    };
  }

  if (
    compatibility.deviceBinding !== undefined &&
    compatibility.deviceBinding !== localContext.deviceBinding
  ) {
    return {
      status: "incompatible",
      reason: "device-binding-mismatch",
      warnings,
    };
  }

  if (localContext.deviceBinding !== "deviceUUID:v1") {
    return {
      status: "incompatible",
      reason: "unsupported-local-device-binding",
      warnings,
    };
  }

  const backupKdfMetadata = compatibility.kdfMetadata;
  if (backupKdfMetadata === undefined) {
    return {
      status: "unknown",
      reason: "missing-kdf-metadata",
      warnings,
    };
  }

  if (!isValidKdfMetadata(backupKdfMetadata)) {
    return {
      status: "incompatible",
      reason: "invalid-backup-kdf-metadata",
      warnings,
    };
  }

  if (!localContext.kdfMetadata) {
    return {
      status: "unknown",
      reason: "local-kdf-metadata-missing",
      warnings,
    };
  }

  if (!kdfMetadataMatches(backupKdfMetadata, localContext.kdfMetadata)) {
    return {
      status: "incompatible",
      reason: "kdf-metadata-mismatch",
      warnings,
    };
  }

  return {
    status: "compatible",
    reason: "same-install-metadata-match",
    warnings,
  };
}

export interface BuildBackupCompatibilityContextInput {
  setupMetadata: {
    masterSalt: string;
    kdfMetadata: KdfMetadata;
  };
  deviceUUID?: string | null;
  deviceUUIDPresent?: boolean;
}

export function buildBackupCompatibilityContextFromSetup(
  input: BuildBackupCompatibilityContextInput,
): BackupCompatibilityContext {
  const deviceUUIDPresent = input.deviceUUIDPresent ?? (!!input.deviceUUID && input.deviceUUID.length > 0);
  const deviceBinding: "deviceUUID:v1" | string = deviceUUIDPresent
    ? "deviceUUID:v1"
    : "unknown";

  return {
    format: PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS,
    kdfMetadata: input.setupMetadata.kdfMetadata,
    masterSaltPresent: input.setupMetadata.masterSalt.length > 0,
    deviceBinding,
    deviceUUIDPresent,
  };
}

function parseInput(input: unknown): { ok: true; value: unknown } | { ok: false; error: BackupParseError } {
  if (typeof input !== "string") {
    return { ok: true, value: input };
  }

  try {
    return { ok: true, value: JSON.parse(input) as unknown };
  } catch {
    return {
      ok: false,
      error: {
        code: "invalid-json",
        message: "Backup file is not valid JSON.",
      },
    };
  }
}

function getBackupCompatibilityMetadata(backup: BackupStageResult): unknown {
  return backup.metadata.compatibility;
}

function collectCompatibilityWarnings(backup: BackupStageResult): string[] {
  const warnings: string[] = [];
  if (backup.entries.some((entry) => typeof entry.encryptedAux === "string" && entry.encryptedAux.length > 0)) {
    warnings.push("backup contains encrypted honeytoken aux metadata that may require server-side reissue or review");
  }
  return warnings;
}

function kdfMetadataMatches(left: KdfMetadata, right: KdfMetadata): boolean {
  return (
    left.version === right.version &&
    left.algorithm === right.algorithm &&
    left.profileIterations === right.profileIterations &&
    left.kdfVersion === right.kdfVersion &&
    left.saltKey === right.saltKey &&
    left.deviceBinding === right.deviceBinding &&
    jsonStableStringify(left.parameters) === jsonStableStringify(right.parameters)
  );
}

function jsonStableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => jsonStableStringify(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${jsonStableStringify(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function validateEncryptedEntry(value: unknown, index: number): BackupParseResult | null {
  const path = `entries[${index}]`;
  if (!isRecord(value)) {
    return validationError("invalid-entry", "Backup entry must be an object.", path);
  }

  const requiredStrings = ["id", "title", "username", "encryptedPassword", "salt"];
  for (const field of requiredStrings) {
    if (typeof value[field] !== "string") {
      return validationError("invalid-entry", "Backup entry is missing required encrypted-record fields.", `${path}.${field}`);
    }
  }

  if (!isSafeNonNegativeInteger(value.createdAt)) {
    return validationError("invalid-entry", "Backup entry createdAt must be a safe non-negative integer.", `${path}.createdAt`);
  }
  if (!isSafeNonNegativeInteger(value.updatedAt)) {
    return validationError("invalid-entry", "Backup entry updatedAt must be a safe non-negative integer.", `${path}.updatedAt`);
  }

  for (const field of ["encryptedTitle", "encryptedUsername", "encryptedUrl", "url", "notes", "encryptedAux"]) {
    if (value[field] !== undefined && typeof value[field] !== "string") {
      return validationError("invalid-entry", "Backup entry optional encrypted-record fields must be strings.", `${path}.${field}`);
    }
  }

  return null;
}

function validateEncryptedSecureNote(value: unknown, index: number): BackupParseResult | null {
  const path = `secureNotes[${index}]`;
  if (!isRecord(value)) {
    return validationError("invalid-secure-note", "Backup secure note must be an object.", path);
  }

  const requiredStrings = ["id", "label", "encryptedLabel", "encryptedContent", "salt"];
  for (const field of requiredStrings) {
    if (typeof value[field] !== "string") {
      return validationError(
        "invalid-secure-note",
        "Backup secure note is missing required encrypted-note fields.",
        `${path}.${field}`,
      );
    }
  }

  if (!isSafeNonNegativeInteger(value.createdAt)) {
    return validationError(
      "invalid-secure-note",
      "Backup secure note createdAt must be a safe non-negative integer.",
      `${path}.createdAt`,
    );
  }
  if (!isSafeNonNegativeInteger(value.updatedAt)) {
    return validationError(
      "invalid-secure-note",
      "Backup secure note updatedAt must be a safe non-negative integer.",
      `${path}.updatedAt`,
    );
  }

  return null;
}

function validationError(code: BackupParseErrorCode, message: string, path?: string): BackupParseResult {
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

function isSafePositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
