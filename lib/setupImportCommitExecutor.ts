import {
  SETUP_IMPORT_STORAGE_KEYS,
  type SetupImportCommitOperation,
  type SetupImportCommitPlan,
} from "./setupImportCommitPlan";

export interface SetupImportStorageDriver {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  deleteItem(key: string): Promise<void>;
}

export type SetupImportRollbackStatus = "not-needed" | "completed" | "failed";

export interface SetupImportSafeOperationDetail {
  key: string;
  type: string;
  category: string;
}

export interface SetupImportRollbackFailure {
  key: string;
  action: "restore" | "delete";
}

export type SetupImportCommitResult =
  | {
      success: true;
      operationsApplied: number;
      rollbackStatus: "not-needed";
    }
  | {
      success: false;
      reason: "invalid-plan" | "write-failed";
      message: string;
      operationsApplied: number;
      rollbackStatus: SetupImportRollbackStatus;
      failedOperation?: SetupImportSafeOperationDetail;
      validationError?: string;
      rollbackFailures?: SetupImportRollbackFailure[];
    };

export interface SetupImportRollbackSnapshot {
  key: string;
  existed: boolean;
  value?: string;
}

export interface RollbackSetupImportCommitInput {
  storage: SetupImportStorageDriver;
  completedOperations: SetupImportCommitOperation[];
  snapshots: SetupImportRollbackSnapshot[];
}

export type SetupImportRollbackResult =
  | { rollbackStatus: "not-needed" | "completed"; rollbackFailures: [] }
  | { rollbackStatus: "failed"; rollbackFailures: SetupImportRollbackFailure[] };

export async function executeSetupImportCommitPlan(
  plan: SetupImportCommitPlan,
  storage: SetupImportStorageDriver,
): Promise<SetupImportCommitResult> {
  const validationError = validatePlan(plan);
  if (validationError) {
    return {
      success: false,
      reason: "invalid-plan",
      message: "Setup/import commit plan is invalid",
      operationsApplied: 0,
      rollbackStatus: "not-needed",
      validationError,
    };
  }

  const completedOperations: SetupImportCommitOperation[] = [];
  const snapshots: SetupImportRollbackSnapshot[] = [];

  for (const operation of plan.operations) {
    try {
      const previousValue = await storage.getItem(operation.key);
      snapshots.push({
        key: operation.key,
        existed: previousValue !== null,
        value: previousValue ?? undefined,
      });
      await applyOperation(operation, storage);
      completedOperations.push(operation);
    } catch {
      const rollbackResult = await rollbackSetupImportCommit({
        storage,
        completedOperations,
        snapshots,
      });

      return {
        success: false,
        reason: "write-failed",
        message: "Setup/import commit write failed",
        operationsApplied: completedOperations.length,
        rollbackStatus: rollbackResult.rollbackStatus,
        failedOperation: safeOperationDetail(operation),
        rollbackFailures: rollbackResult.rollbackFailures,
      };
    }
  }

  return {
    success: true,
    operationsApplied: completedOperations.length,
    rollbackStatus: "not-needed",
  };
}

export async function rollbackSetupImportCommit(
  input: RollbackSetupImportCommitInput,
): Promise<SetupImportRollbackResult> {
  if (input.completedOperations.length === 0) {
    return { rollbackStatus: "not-needed", rollbackFailures: [] };
  }

  const snapshotByKey = new Map(input.snapshots.map((snapshot) => [snapshot.key, snapshot]));
  const rollbackFailures: SetupImportRollbackFailure[] = [];

  for (const operation of [...input.completedOperations].reverse()) {
    const snapshot = snapshotByKey.get(operation.key);
    if (!snapshot) {
      rollbackFailures.push({ key: operation.key, action: "delete" });
      continue;
    }

    try {
      if (snapshot.existed) {
        await input.storage.setItem(operation.key, snapshot.value as string);
      } else {
        await input.storage.deleteItem(operation.key);
      }
    } catch {
      rollbackFailures.push({
        key: operation.key,
        action: snapshot.existed ? "restore" : "delete",
      });
    }
  }

  if (rollbackFailures.length > 0) {
    return { rollbackStatus: "failed", rollbackFailures };
  }

  return { rollbackStatus: "completed", rollbackFailures: [] };
}

function validatePlan(plan: SetupImportCommitPlan): string | null {
  if (!plan || !Array.isArray(plan.operations) || plan.operations.length === 0) {
    return "missing-operations";
  }

  const lastOperation = plan.operations[plan.operations.length - 1];
  if (
    lastOperation.key !== SETUP_IMPORT_STORAGE_KEYS.vaultInitialized ||
    lastOperation.category !== "initialized-marker"
  ) {
    return "initialized-marker-not-last";
  }

  const keys = new Set<string>();
  for (const operation of plan.operations) {
    if (!isKnownOperation(operation)) {
      return "unknown-operation-type";
    }
    if (keys.has(operation.key)) {
      return "duplicate-write-key";
    }
    keys.add(operation.key);
  }

  return null;
}

function isKnownOperation(operation: SetupImportCommitOperation): boolean {
  if (!operation || typeof operation !== "object") return false;
  if (operation.type === "write") {
    return (
      typeof operation.key === "string" &&
      typeof operation.value === "string" &&
      typeof operation.category === "string"
    );
  }
  if (operation.type === "write-cached-master-key") {
    return (
      typeof operation.key === "string" &&
      typeof operation.valueReference === "string" &&
      operation.category === "cached-master-key"
    );
  }
  return false;
}

async function applyOperation(
  operation: SetupImportCommitOperation,
  storage: SetupImportStorageDriver,
): Promise<void> {
  if (operation.type === "write") {
    await storage.setItem(operation.key, operation.value);
    return;
  }
  if (operation.type === "write-cached-master-key") {
    await storage.setItem(operation.key, operation.valueReference);
    return;
  }
  throw new Error("Unknown setup/import commit operation");
}

function safeOperationDetail(
  operation: SetupImportCommitOperation,
): SetupImportSafeOperationDetail {
  return {
    key: operation.key,
    type: operation.type,
    category: operation.category,
  };
}
