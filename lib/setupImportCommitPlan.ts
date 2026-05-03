import type { KdfMetadata } from "../crypto/kdfMetadata";
import { isValidKdfMetadata } from "../crypto/kdfMetadata";
import type { SharedVaultBlob } from "../workers/sharedVaultStorage";
import type { SecureNote, VaultEntry } from "../workers/vaultWorker";

export const SETUP_IMPORT_STORAGE_KEYS = {
  masterSalt: "pipass_master_salt",
  masterHash: "pipass_master_hash",
  securityProfile: "pipass_security_profile",
  kdfMetadata: "pipass_kdf_metadata",
  recoveryKeyHash: "pipass_recovery_key_hash",
  vaultIndex: "pipass_vault_index",
  notesIndex: "pipass_notes_index",
  sharedVault: "pipass_shared_vault",
  cachedMasterKey: "pipass_master_key",
  vaultInitialized: "pipass_vault_initialized",
} as const;

const VAULT_ENTRY_PREFIX = "pipass_vault_";
const SECURE_NOTE_PREFIX = "pipass_note_";

export type SetupImportCommitCategory =
  | "setup-metadata"
  | "vault-entry"
  | "vault-index"
  | "secure-note"
  | "secure-note-index"
  | "shared-vault"
  | "cached-master-key"
  | "initialized-marker";

export type SetupImportCommitOperation =
  | {
      type: "write";
      key: string;
      category: Exclude<SetupImportCommitCategory, "cached-master-key">;
      value: string;
      safeDescription: string;
    }
  | {
      type: "write-cached-master-key";
      key: string;
      category: "cached-master-key";
      valueReference: string;
      safeDescription: string;
    };

export interface SetupImportRollbackTarget {
  key: string;
  category: SetupImportCommitCategory;
  restorePolicy: "restore-previous-or-delete-new";
  safeDescription: string;
}

export interface SetupImportRollbackManifest {
  targets: SetupImportRollbackTarget[];
  keysToSnapshot: string[];
  keysToDeleteIfNew: string[];
  initializedMarkerKey: typeof SETUP_IMPORT_STORAGE_KEYS.vaultInitialized;
}

export interface SetupImportCommitPlan {
  operations: SetupImportCommitOperation[];
  rollbackManifest: SetupImportRollbackManifest;
}

export interface SetupImportSetupMetadata {
  masterSalt: string;
  masterHash: string;
  securityProfile: number;
  kdfMetadata: KdfMetadata;
  recoveryKeyHash: string;
}

export interface BuildSetupImportCommitPlanInput {
  setupMetadata: SetupImportSetupMetadata;
  entries?: VaultEntry[];
  secureNotes?: SecureNote[];
  sharedVaultBlob?: SharedVaultBlob | null;
  includeCachedMasterKey?: boolean;
  cachedMasterKeyReference?: string;
  initializedMarkerValue?: "1";
}

export type SetupImportCommitPlanErrorCode =
  | "missing-setup-metadata"
  | "invalid-security-profile"
  | "invalid-kdf-metadata"
  | "invalid-entry-id"
  | "duplicate-entry-id"
  | "invalid-note-id"
  | "duplicate-note-id"
  | "missing-cached-master-key-reference"
  | "invalid-initialized-marker";

export type SetupImportCommitPlanResult =
  | { ok: true; plan: SetupImportCommitPlan }
  | {
      ok: false;
      error: {
        code: SetupImportCommitPlanErrorCode;
        path: string;
        message: string;
      };
    };

export function buildSetupImportCommitPlan(
  input: BuildSetupImportCommitPlanInput,
): SetupImportCommitPlanResult {
  const validationFailure = validateInput(input);
  if (validationFailure) return validationFailure;

  const operations: SetupImportCommitOperation[] = [];
  const entries = input.entries ?? [];
  const secureNotes = input.secureNotes ?? [];
  const initializedMarkerValue = input.initializedMarkerValue ?? "1";

  pushWrite(
    operations,
    SETUP_IMPORT_STORAGE_KEYS.masterSalt,
    "setup-metadata",
    input.setupMetadata.masterSalt,
    "write setup master salt",
  );
  pushWrite(
    operations,
    SETUP_IMPORT_STORAGE_KEYS.securityProfile,
    "setup-metadata",
    input.setupMetadata.securityProfile.toString(),
    "write setup security profile",
  );
  pushWrite(
    operations,
    SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
    "setup-metadata",
    JSON.stringify(input.setupMetadata.kdfMetadata),
    "write setup KDF metadata",
  );
  pushWrite(
    operations,
    SETUP_IMPORT_STORAGE_KEYS.masterHash,
    "setup-metadata",
    input.setupMetadata.masterHash,
    "write setup master hash",
  );
  pushWrite(
    operations,
    SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
    "setup-metadata",
    input.setupMetadata.recoveryKeyHash,
    "write setup recovery key hash",
  );

  for (const entry of entries) {
    pushWrite(
      operations,
      vaultEntryKey(entry.id),
      "vault-entry",
      JSON.stringify(entry),
      "write staged vault entry",
    );
  }

  if (entries.length > 0) {
    pushWrite(
      operations,
      SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
      "vault-index",
      JSON.stringify(entries.map((entry) => entry.id)),
      "write staged vault index",
    );
  }

  for (const note of secureNotes) {
    pushWrite(
      operations,
      secureNoteKey(note.id),
      "secure-note",
      JSON.stringify(note),
      "write staged secure note",
    );
  }

  if (secureNotes.length > 0) {
    pushWrite(
      operations,
      SETUP_IMPORT_STORAGE_KEYS.notesIndex,
      "secure-note-index",
      JSON.stringify(secureNotes.map((note) => note.id)),
      "write staged secure note index",
    );
  }

  if (input.sharedVaultBlob) {
    pushWrite(
      operations,
      SETUP_IMPORT_STORAGE_KEYS.sharedVault,
      "shared-vault",
      JSON.stringify(input.sharedVaultBlob),
      "write staged shared vault blob",
    );
  }

  if (input.includeCachedMasterKey) {
    operations.push({
      type: "write-cached-master-key",
      key: SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey,
      category: "cached-master-key",
      valueReference: input.cachedMasterKeyReference as string,
      safeDescription: "write cached master key reference",
    });
  }

  pushWrite(
    operations,
    SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
    "initialized-marker",
    initializedMarkerValue,
    "write vault initialized marker",
  );

  return {
    ok: true,
    plan: {
      operations,
      rollbackManifest: buildRollbackManifest(operations),
    },
  };
}

function validateInput(
  input: BuildSetupImportCommitPlanInput,
): Extract<SetupImportCommitPlanResult, { ok: false }> | null {
  const setup = input.setupMetadata;
  if (!setup || !isNonEmptyString(setup.masterSalt)) {
    return failure("missing-setup-metadata", "setupMetadata.masterSalt");
  }
  if (!isNonEmptyString(setup.masterHash)) {
    return failure("missing-setup-metadata", "setupMetadata.masterHash");
  }
  if (!isNonEmptyString(setup.recoveryKeyHash)) {
    return failure("missing-setup-metadata", "setupMetadata.recoveryKeyHash");
  }
  if (!Number.isSafeInteger(setup.securityProfile) || setup.securityProfile <= 0) {
    return failure("invalid-security-profile", "setupMetadata.securityProfile");
  }
  if (!isValidKdfMetadata(setup.kdfMetadata)) {
    return failure("invalid-kdf-metadata", "setupMetadata.kdfMetadata");
  }
  if (input.initializedMarkerValue && input.initializedMarkerValue !== "1") {
    return failure("invalid-initialized-marker", "initializedMarkerValue");
  }
  if (input.includeCachedMasterKey && !isNonEmptyString(input.cachedMasterKeyReference)) {
    return failure("missing-cached-master-key-reference", "cachedMasterKeyReference");
  }

  const entryIds = new Set<string>();
  for (const [index, entry] of (input.entries ?? []).entries()) {
    if (!isValidRecordId(entry.id)) {
      return failure("invalid-entry-id", `entries[${index}].id`);
    }
    if (entryIds.has(entry.id)) {
      return failure("duplicate-entry-id", `entries[${index}].id`);
    }
    entryIds.add(entry.id);
  }

  const noteIds = new Set<string>();
  for (const [index, note] of (input.secureNotes ?? []).entries()) {
    if (!isValidRecordId(note.id)) {
      return failure("invalid-note-id", `secureNotes[${index}].id`);
    }
    if (noteIds.has(note.id)) {
      return failure("duplicate-note-id", `secureNotes[${index}].id`);
    }
    noteIds.add(note.id);
  }

  return null;
}

function pushWrite(
  operations: SetupImportCommitOperation[],
  key: string,
  category: Exclude<SetupImportCommitCategory, "cached-master-key">,
  value: string,
  safeDescription: string,
): void {
  operations.push({ type: "write", key, category, value, safeDescription });
}

function buildRollbackManifest(
  operations: SetupImportCommitOperation[],
): SetupImportRollbackManifest {
  const targets = operations.map((operation) => ({
    key: operation.key,
    category: operation.category,
    restorePolicy: "restore-previous-or-delete-new" as const,
    safeDescription: `rollback ${operation.category}`,
  }));
  const keys = targets.map((target) => target.key);

  return {
    targets,
    keysToSnapshot: keys,
    keysToDeleteIfNew: keys,
    initializedMarkerKey: SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
  };
}

function failure(
  code: SetupImportCommitPlanErrorCode,
  path: string,
): Extract<SetupImportCommitPlanResult, { ok: false }> {
  return {
    ok: false,
    error: {
      code,
      path,
      message: "Setup/import commit plan input is invalid",
    },
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isValidRecordId(value: unknown): value is string {
  return isNonEmptyString(value) && value.length <= 256;
}

function vaultEntryKey(id: string): string {
  return `${VAULT_ENTRY_PREFIX}${id}`;
}

function secureNoteKey(id: string): string {
  return `${SECURE_NOTE_PREFIX}${id}`;
}
