import {
  type SetupImportRepairAction,
  type SetupImportRepairPlan,
} from "./setupImportRepairPlan";
import { SETUP_IMPORT_STORAGE_KEYS } from "./setupImportCommitPlan";

const VAULT_ENTRY_PREFIX = "pipass_vault_";
const SECURE_NOTE_PREFIX = "pipass_note_";

const OWNED_REPAIR_KEYS = new Set<string>([
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
]);

export interface SetupImportRepairStorageDriver {
  deleteItem(key: string): Promise<void>;
}

export type SetupImportRepairExecutionResult =
  | {
      success: true;
      action: "none" | "clear-local-setup-import-state";
      deletedKeys: string[];
      failedKeys: [];
      message: string;
    }
  | {
      success: false;
      action: SetupImportRepairAction | "unknown";
      deletedKeys: string[];
      failedKeys: string[];
      reason:
        | "manual-repair-required"
        | "invalid-action"
        | "unsafe-key"
        | "delete-failed";
      message: string;
    };

export async function executeSetupImportRepairPlan(
  plan: SetupImportRepairPlan,
  storage: SetupImportRepairStorageDriver,
): Promise<SetupImportRepairExecutionResult> {
  if (plan.action === "none") {
    return {
      success: true,
      action: "none",
      deletedKeys: [],
      failedKeys: [],
      message: "No setup/import repair action was needed",
    };
  }

  if (plan.action === "manual-repair-required") {
    return {
      success: false,
      action: "manual-repair-required",
      deletedKeys: [],
      failedKeys: [],
      reason: "manual-repair-required",
      message: "Manual setup/import repair is required",
    };
  }

  if (plan.action !== "clear-local-setup-import-state") {
    return {
      success: false,
      action: "unknown",
      deletedKeys: [],
      failedKeys: [],
      reason: "invalid-action",
      message: "Setup/import repair action is invalid",
    };
  }

  const keysToDelete = [...new Set(plan.keysToDelete)];
  const unsafeKey = keysToDelete.find((key) => !isSafeSetupImportRepairKey(key));
  if (unsafeKey !== undefined) {
    return {
      success: false,
      action: "clear-local-setup-import-state",
      deletedKeys: [],
      failedKeys: [],
      reason: "unsafe-key",
      message: "Setup/import repair plan contains an unsafe key",
    };
  }

  const deletedKeys: string[] = [];
  const failedKeys: string[] = [];

  for (const key of keysToDelete) {
    try {
      await storage.deleteItem(key);
      deletedKeys.push(key);
    } catch {
      failedKeys.push(key);
    }
  }

  if (failedKeys.length > 0) {
    return {
      success: false,
      action: "clear-local-setup-import-state",
      deletedKeys,
      failedKeys,
      reason: "delete-failed",
      message: "Setup/import repair could not delete every planned key",
    };
  }

  return {
    success: true,
    action: "clear-local-setup-import-state",
    deletedKeys,
    failedKeys: [],
    message: "Setup/import repair deleted planned keys",
  };
}

function isSafeSetupImportRepairKey(key: string): boolean {
  if (typeof key !== "string" || key.length === 0 || key.length > 512) return false;
  if (key.trim() !== key) return false;
  if (key.includes("..") || key.includes("/") || key.includes("\\")) return false;
  if (/[\u0000-\u001f\s]/.test(key)) return false;
  if (key.startsWith("pipass.auth.") || key === "pipass.installId" || key === "deviceUUID") {
    return false;
  }
  if (OWNED_REPAIR_KEYS.has(key)) return true;
  return isRecordKey(key, VAULT_ENTRY_PREFIX) || isRecordKey(key, SECURE_NOTE_PREFIX);
}

function isRecordKey(key: string, prefix: string): boolean {
  if (!key.startsWith(prefix)) return false;
  if (key === SETUP_IMPORT_STORAGE_KEYS.vaultIndex) return false;
  if (key === SETUP_IMPORT_STORAGE_KEYS.vaultInitialized) return false;
  if (key === SETUP_IMPORT_STORAGE_KEYS.notesIndex) return false;

  const suffix = key.slice(prefix.length);
  return suffix.length > 0 && suffix.trim() === suffix;
}
