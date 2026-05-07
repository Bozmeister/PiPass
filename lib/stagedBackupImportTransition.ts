import type { StagedBackupCommitGateDecision } from "./stagedBackupCommitGate";

export type StagedBackupImportTransitionStatus =
  | "no-backup"
  | "checked-only"
  | "ready-to-import"
  | "blocked-import"
  | "setup-only-dismissed"
  | "import-committed";

export interface StagedBackupImportTransitionInput {
  stagedBackupPresent: boolean;
  importCommitEnabled: boolean;
  gateDecision: StagedBackupCommitGateDecision | null;
  userDismissedImport?: boolean;
  importCommitted?: boolean;
}

export interface StagedBackupImportTransitionResult {
  status: StagedBackupImportTransitionStatus;
  canContinueSetup: boolean;
  canAttemptImport: boolean;
  requiresClearOrDismiss: boolean;
  safeTitle: string;
  safeMessage: string;
  warnings: string[];
}

const SAFE_WARNING_HONEYTOKEN =
  "Backup contains decoy trigger metadata that may need review after import.";
const SAFE_WARNING_GENERIC =
  "Backup has a non-blocking warning that should be reviewed before import.";
const SAFE_WARNING_REVIEW =
  "Backup has a warning that should be reviewed before record commit.";

export function determineStagedBackupImportTransition(
  input: StagedBackupImportTransitionInput,
): StagedBackupImportTransitionResult {
  const warnings = sanitizeWarnings(input.gateDecision?.warnings ?? []);

  if (input.importCommitted) {
    return result(
      "import-committed",
      true,
      false,
      false,
      "Backup imported",
      "Backup records were added only after setup/import commit completed.",
      warnings,
    );
  }

  if (!input.stagedBackupPresent) {
    return result(
      "no-backup",
      true,
      false,
      false,
      "No backup selected",
      "Setup can continue without backup records.",
      [],
    );
  }

  if (!input.importCommitEnabled) {
    return result(
      "checked-only",
      true,
      false,
      false,
      "Backup checked only",
      "Backup records are staged in memory only. No backup records have been written.",
      warnings,
    );
  }

  if (isGateReadyToImport(input.gateDecision)) {
    return result(
      "ready-to-import",
      true,
      true,
      false,
      "Backup ready for commit",
      "Backup records are ready for recovery-confirmed commit. No backup records have been written.",
      warnings,
    );
  }

  if (input.userDismissedImport) {
    return result(
      "setup-only-dismissed",
      true,
      false,
      false,
      "Setup without backup",
      "Backup import was dismissed. Setup can continue without backup records.",
      warnings,
    );
  }

  return result(
    "blocked-import",
    false,
    false,
    true,
    "Backup cannot be committed",
    "This backup is not ready for vault commit. Clear or dismiss it to continue setup without backup records.",
    warnings,
  );
}

function isGateReadyToImport(
  gateDecision: StagedBackupCommitGateDecision | null,
): boolean {
  return (
    gateDecision?.allowed === true &&
    gateDecision.mode === "commit-staged-backup" &&
    gateDecision.reason === "allowed"
  );
}

function result(
  status: StagedBackupImportTransitionStatus,
  canContinueSetup: boolean,
  canAttemptImport: boolean,
  requiresClearOrDismiss: boolean,
  safeTitle: string,
  safeMessage: string,
  warnings: string[],
): StagedBackupImportTransitionResult {
  return {
    status,
    canContinueSetup,
    canAttemptImport,
    requiresClearOrDismiss,
    safeTitle,
    safeMessage,
    warnings,
  };
}

function sanitizeWarnings(warnings: string[]): string[] {
  const safeWarnings = new Set<string>();
  for (const warning of warnings) {
    if (typeof warning !== "string" || warning.length === 0) continue;
    if (warning === SAFE_WARNING_HONEYTOKEN || warning === SAFE_WARNING_GENERIC) {
      safeWarnings.add(warning);
    } else {
      safeWarnings.add(SAFE_WARNING_REVIEW);
    }
  }
  return [...safeWarnings];
}
