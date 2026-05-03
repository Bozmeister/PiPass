import {
  buildSetupImportRepairPlan,
  classifySetupImportLocalState,
  type SetupImportLocalStateClassification,
  type SetupImportLocalStateResult,
  type SetupImportLocalStorageSnapshot,
  type SetupImportRepairPlan,
} from "./setupImportRepairPlan";
import { SETUP_IMPORT_STORAGE_KEYS } from "./setupImportCommitPlan";
import {
  executeSetupImportRepairPlan,
  type SetupImportRepairExecutionResult,
  type SetupImportRepairStorageDriver,
} from "./setupImportRepairExecutor";

const VAULT_ENTRY_PREFIX = "pipass_vault_";
const SECURE_NOTE_PREFIX = "pipass_note_";

const DIRECT_SNAPSHOT_KEYS = [
  SETUP_IMPORT_STORAGE_KEYS.vaultInitialized,
  SETUP_IMPORT_STORAGE_KEYS.masterSalt,
  SETUP_IMPORT_STORAGE_KEYS.masterHash,
  SETUP_IMPORT_STORAGE_KEYS.securityProfile,
  SETUP_IMPORT_STORAGE_KEYS.kdfMetadata,
  SETUP_IMPORT_STORAGE_KEYS.recoveryKeyHash,
  SETUP_IMPORT_STORAGE_KEYS.vaultIndex,
  SETUP_IMPORT_STORAGE_KEYS.notesIndex,
  SETUP_IMPORT_STORAGE_KEYS.sharedVault,
  SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey,
] as const;

export interface SetupImportSnapshotReadDriver {
  getItem(key: string): Promise<string | null>;
}

export type SetupImportSnapshotReadResult =
  | {
      ok: true;
      snapshot: SetupImportLocalStorageSnapshot;
      keysRead: string[];
    }
  | {
      ok: false;
      reason: "read-failed";
      failedKey: string;
      message: string;
    };

export type StartupRepairRoute =
  | "setup"
  | "unlock"
  | "repair-prompt"
  | "manual-repair"
  | "safe-error";

export type StartupRepairDecision =
  | {
      route: Exclude<StartupRepairRoute, "safe-error">;
      classification: SetupImportLocalStateClassification;
      repairPlan: SetupImportRepairPlan;
      state: SetupImportLocalStateResult;
      message: string;
    }
  | {
      route: "safe-error";
      classification: "read-failed";
      repairPlan: null;
      state: null;
      message: string;
      reason: "snapshot-read-failed";
      failedKey: string;
    };

export type StartupRepairConfirmationResult =
  | {
      success: true;
      repairResult: SetupImportRepairExecutionResult;
      message: string;
    }
  | {
      success: false;
      repairResult: SetupImportRepairExecutionResult | null;
      reason: "not-repairable" | "repair-failed";
      message: string;
    };

export async function readSetupImportStateSnapshot(
  driver: SetupImportSnapshotReadDriver,
): Promise<SetupImportSnapshotReadResult> {
  const snapshot: SetupImportLocalStorageSnapshot = {};
  const keysRead: string[] = [];

  for (const key of DIRECT_SNAPSHOT_KEYS) {
    const readResult = await readSnapshotKey(driver, key, snapshot, keysRead);
    if (!readResult.ok) return readResult;
  }

  const vaultIds = parseIndex(snapshot[SETUP_IMPORT_STORAGE_KEYS.vaultIndex]);
  if (vaultIds) {
    for (const id of vaultIds) {
      const readResult = await readSnapshotKey(
        driver,
        `${VAULT_ENTRY_PREFIX}${id}`,
        snapshot,
        keysRead,
      );
      if (!readResult.ok) return readResult;
    }
  }

  const noteIds = parseIndex(snapshot[SETUP_IMPORT_STORAGE_KEYS.notesIndex]);
  if (noteIds) {
    for (const id of noteIds) {
      const readResult = await readSnapshotKey(
        driver,
        `${SECURE_NOTE_PREFIX}${id}`,
        snapshot,
        keysRead,
      );
      if (!readResult.ok) return readResult;
    }
  }

  return { ok: true, snapshot, keysRead };
}

export async function readAndDecideStartupRepairState(
  driver: SetupImportSnapshotReadDriver,
): Promise<StartupRepairDecision> {
  const snapshotResult = await readSetupImportStateSnapshot(driver);
  return decideStartupRepairState(snapshotResult);
}

export function decideStartupRepairState(
  input: SetupImportLocalStorageSnapshot | SetupImportSnapshotReadResult,
): StartupRepairDecision {
  if (isSnapshotReadResult(input)) {
    if (!input.ok) {
      return {
        route: "safe-error",
        classification: "read-failed",
        repairPlan: null,
        state: null,
        message: "PiPass could not inspect local setup state safely.",
        reason: "snapshot-read-failed",
        failedKey: input.failedKey,
      };
    }
    return decideStartupRepairState(input.snapshot);
  }

  const state = classifySetupImportLocalState(input);
  const repairPlan = buildSetupImportRepairPlan(input);

  if (state.classification === "clean-uninitialized") {
    return {
      route: "setup",
      classification: state.classification,
      repairPlan,
      state,
      message: "Continue to setup",
    };
  }

  if (state.classification === "initialized") {
    return {
      route: "unlock",
      classification: state.classification,
      repairPlan,
      state,
      message: "Continue to unlock",
    };
  }

  if (repairPlan.action === "clear-local-setup-import-state") {
    return {
      route: "repair-prompt",
      classification: state.classification,
      repairPlan,
      state,
      message: "PiPass found an unfinished setup or restore.",
    };
  }

  return {
    route: "manual-repair",
    classification: state.classification,
    repairPlan,
    state,
    message: "PiPass found inconsistent local vault state.",
  };
}

export async function confirmStartupRepairDecision(
  decision: StartupRepairDecision,
  storage: SetupImportRepairStorageDriver,
): Promise<StartupRepairConfirmationResult> {
  if (decision.route !== "repair-prompt") {
    return {
      success: false,
      repairResult: null,
      reason: "not-repairable",
      message: "Startup repair is not available for this local state",
    };
  }

  const repairResult = await executeSetupImportRepairPlan(decision.repairPlan, storage);
  if (!repairResult.success) {
    return {
      success: false,
      repairResult,
      reason: "repair-failed",
      message: "Startup repair could not clear every planned key",
    };
  }

  return {
    success: true,
    repairResult,
    message: "Startup repair cleared incomplete setup state",
  };
}

async function readSnapshotKey(
  driver: SetupImportSnapshotReadDriver,
  key: string,
  snapshot: SetupImportLocalStorageSnapshot,
  keysRead: string[],
): Promise<SetupImportSnapshotReadResult> {
  try {
    snapshot[key] = await driver.getItem(key);
    keysRead.push(key);
    return { ok: true, snapshot, keysRead };
  } catch {
    return {
      ok: false,
      reason: "read-failed",
      failedKey: key,
      message: "Could not read setup/import state",
    };
  }
}

function parseIndex(value: string | null | undefined): string[] | null {
  if (typeof value !== "string") return [];

  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return null;
    if (!parsed.every((id) => typeof id === "string" && id.length > 0)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function isSnapshotReadResult(value: unknown): value is SetupImportSnapshotReadResult {
  return (
    typeof value === "object" &&
    value !== null &&
    "ok" in value &&
    typeof (value as { ok?: unknown }).ok === "boolean"
  );
}
