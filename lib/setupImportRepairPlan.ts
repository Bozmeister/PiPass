import { SETUP_IMPORT_STORAGE_KEYS } from "./setupImportCommitPlan";

const VAULT_ENTRY_PREFIX = "pipass_vault_";
const SECURE_NOTE_PREFIX = "pipass_note_";

const SETUP_IMPORT_BASE_KEYS = [
  SETUP_IMPORT_STORAGE_KEYS.masterSalt,
  SETUP_IMPORT_STORAGE_KEYS.masterHash,
  SETUP_IMPORT_STORAGE_KEYS.securityProfile,
  SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
  SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
  SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
  SETUP_IMPORT_STORAGE_KEYS.notesIndex,
  SETUP_IMPORT_STORAGE_KEYS.sharedVault,
  SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey,
  SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
] as const;

const CRITICAL_SETUP_KEYS = [
  SETUP_IMPORT_STORAGE_KEYS.masterSalt,
  SETUP_IMPORT_STORAGE_KEYS.masterHash,
  SETUP_IMPORT_STORAGE_KEYS.securityProfile,
  SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
  SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
] as const;

export type SetupImportLocalStateClassification =
  | "clean-uninitialized"
  | "initialized"
  | "partial-setup"
  | "partial-import"
  | "inconsistent-initialized"
  | "unknown-inconsistent";

export type SetupImportRepairAction =
  | "none"
  | "clear-local-setup-import-state"
  | "manual-repair-required";

export interface SetupImportLocalStateResult {
  classification: SetupImportLocalStateClassification;
  initialized: boolean;
  setupMetadataPresent: boolean;
  importDataPresent: boolean;
  inconsistent: boolean;
  reasons: string[];
  relevantKeys: string[];
}

export interface SetupImportRepairPlan {
  action: SetupImportRepairAction;
  classification: SetupImportLocalStateClassification;
  keysToDelete: string[];
  reason: string;
  userMessage: string;
}

export type SetupImportLocalStorageSnapshot = Record<string, string | null | undefined>;

export function classifySetupImportLocalState(
  snapshot: SetupImportLocalStorageSnapshot,
): SetupImportLocalStateResult {
  const keys = getRelevantPresentKeys(snapshot);
  const initialized = snapshot[SETUP_IMPORT_STORAGE_KEYS.vaultInitialized] === "1";
  const presentSetupKeys = CRITICAL_SETUP_KEYS.filter((key) => hasValue(snapshot[key]));
  const setupMetadataPresent = presentSetupKeys.length > 0;
  const criticalSetupComplete = presentSetupKeys.length === CRITICAL_SETUP_KEYS.length;
  const importDataPresent = keys.some(isImportDataKey);
  const reasons: string[] = [];

  if (hasMalformedIndex(snapshot[SETUP_IMPORT_STORAGE_KEYS.vaultIndex])) {
    reasons.push("malformed-vault-index");
  }
  if (hasMalformedIndex(snapshot[SETUP_IMPORT_STORAGE_KEYS.notesIndex])) {
    reasons.push("malformed-notes-index");
  }

  const danglingEntryKeys = getDanglingRecordKeys(
    snapshot,
    VAULT_ENTRY_PREFIX,
    SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
  );
  if (danglingEntryKeys.length > 0) {
    reasons.push("dangling-vault-entry");
  }

  const danglingNoteKeys = getDanglingRecordKeys(
    snapshot,
    SECURE_NOTE_PREFIX,
    SETUP_IMPORT_STORAGE_KEYS.notesIndex,
  );
  if (danglingNoteKeys.length > 0) {
    reasons.push("dangling-secure-note");
  }

  const inconsistent = reasons.length > 0;

  if (initialized) {
    if (!criticalSetupComplete || inconsistent) {
      return result("inconsistent-initialized", initialized, setupMetadataPresent, importDataPresent, true, reasons, keys);
    }
    return result("initialized", initialized, setupMetadataPresent, importDataPresent, false, reasons, keys);
  }

  if (inconsistent) {
    return result("unknown-inconsistent", initialized, setupMetadataPresent, importDataPresent, true, reasons, keys);
  }

  if (importDataPresent) {
    return result("partial-import", initialized, setupMetadataPresent, importDataPresent, false, reasons, keys);
  }

  if (setupMetadataPresent) {
    return result("partial-setup", initialized, setupMetadataPresent, importDataPresent, false, reasons, keys);
  }

  return result("clean-uninitialized", initialized, setupMetadataPresent, importDataPresent, false, reasons, keys);
}

export function buildSetupImportRepairPlan(
  snapshot: SetupImportLocalStorageSnapshot,
): SetupImportRepairPlan {
  const state = classifySetupImportLocalState(snapshot);

  if (state.classification === "clean-uninitialized" || state.classification === "initialized") {
    return {
      action: "none",
      classification: state.classification,
      keysToDelete: [],
      reason: state.classification,
      userMessage: "No unfinished local setup or import state was found.",
    };
  }

  if (state.classification === "inconsistent-initialized") {
    return {
      action: "manual-repair-required",
      classification: state.classification,
      keysToDelete: [],
      reason: "initialized-vault-state-is-inconsistent",
      userMessage: "PiPass found inconsistent local vault state. Manual repair is required before changing setup or import data.",
    };
  }

  return {
    action: "clear-local-setup-import-state",
    classification: state.classification,
    keysToDelete: state.relevantKeys,
    reason: state.classification,
    userMessage: "PiPass found an unfinished setup or import. Clear unfinished local setup data before creating a vault.",
  };
}

function result(
  classification: SetupImportLocalStateClassification,
  initialized: boolean,
  setupMetadataPresent: boolean,
  importDataPresent: boolean,
  inconsistent: boolean,
  reasons: string[],
  relevantKeys: string[],
): SetupImportLocalStateResult {
  return {
    classification,
    initialized,
    setupMetadataPresent,
    importDataPresent,
    inconsistent,
    reasons: [...reasons].sort(),
    relevantKeys: [...relevantKeys].sort(),
  };
}

function getRelevantPresentKeys(snapshot: SetupImportLocalStorageSnapshot): string[] {
  const keys = new Set<string>();

  for (const key of SETUP_IMPORT_BASE_KEYS) {
    if (hasValue(snapshot[key])) keys.add(key);
  }

  for (const key of Object.keys(snapshot)) {
    if (hasValue(snapshot[key]) && (isVaultEntryRecordKey(key) || isSecureNoteRecordKey(key))) {
      keys.add(key);
    }
  }

  return [...keys].sort();
}

function hasValue(value: string | null | undefined): value is string {
  return typeof value === "string";
}

function isImportDataKey(key: string): boolean {
  return (
    key === SETUP_IMPORT_STORAGE_KEYS.vaultIndex ||
    key === SETUP_IMPORT_STORAGE_KEYS.notesIndex ||
    key === SETUP_IMPORT_STORAGE_KEYS.sharedVault ||
    isVaultEntryRecordKey(key) ||
    isSecureNoteRecordKey(key)
  );
}

function hasMalformedIndex(value: string | null | undefined): boolean {
  if (!hasValue(value)) return false;
  try {
    const parsed = JSON.parse(value);
    return !Array.isArray(parsed) || !parsed.every((id) => typeof id === "string" && id.length > 0);
  } catch {
    return true;
  }
}

function getDanglingRecordKeys(
  snapshot: SetupImportLocalStorageSnapshot,
  prefix: string,
  indexKey: string,
): string[] {
  const recordKeys = Object.keys(snapshot).filter(
    (key) =>
      hasValue(snapshot[key]) &&
      (prefix === VAULT_ENTRY_PREFIX ? isVaultEntryRecordKey(key) : isSecureNoteRecordKey(key)),
  );
  if (recordKeys.length === 0) return [];

  const indexedIds = parseIndex(snapshot[indexKey]);
  if (indexedIds === null) return [];

  return recordKeys.filter((key) => {
    const id = key.slice(prefix.length);
    return !indexedIds.has(id);
  });
}

function isVaultEntryRecordKey(key: string): boolean {
  return (
    key.startsWith(VAULT_ENTRY_PREFIX) &&
    key !== SETUP_IMPORT_STORAGE_KEYS.vaultIndex &&
    key !== SETUP_IMPORT_STORAGE_KEYS.vaultInitialized
  );
}

function isSecureNoteRecordKey(key: string): boolean {
  return key.startsWith(SECURE_NOTE_PREFIX) && key !== SETUP_IMPORT_STORAGE_KEYS.notesIndex;
}

function parseIndex(value: string | null | undefined): Set<string> | null {
  if (!hasValue(value)) return new Set();
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || !parsed.every((id) => typeof id === "string" && id.length > 0)) {
      return null;
    }
    return new Set(parsed);
  } catch {
    return null;
  }
}
