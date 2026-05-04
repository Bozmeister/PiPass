import type { BackupStageResult } from "./backupSchema";
import {
  decideStagedBackupCommitGate,
  type StagedBackupCommitGateDecision,
  type StagedBackupCommitGateInput,
  type StagedBackupCommitGateReason,
} from "./stagedBackupCommitGate";

export type RuntimeStagedBackupBridgeStatusKind =
  | "no-backup"
  | "checked-only-not-imported-yet"
  | "gate-blocked-setup-only"
  | "gate-blocked-clear-required";

export interface RuntimeStagedBackupBridgeStatusInput {
  stagedBackup?: BackupStageResult | null;
  gateInput?: Omit<StagedBackupCommitGateInput, "stagedBackupPresent" | "format">;
  decideGate?: (
    input: StagedBackupCommitGateInput,
  ) => StagedBackupCommitGateDecision;
  blockSetupWhenGateBlocked?: boolean;
}

export interface RuntimeStagedBackupBridgeStatus {
  kind: RuntimeStagedBackupBridgeStatusKind;
  stagedBackupPresent: boolean;
  setupAllowed: boolean;
  recordsWillBeCommitted: false;
  gateAllowed: boolean;
  gateReason: StagedBackupCommitGateReason;
  warnings: string[];
  safeMessage: string;
}

const CHECKED_ONLY_MESSAGE =
  "Backup checked only. Backup records are staged in memory and will not be added to this vault in this setup step.";

const GATE_BLOCKED_SETUP_ONLY_MESSAGE =
  "Backup checked only. This backup is not ready to add to the vault, and setup will continue without backup records.";

const GATE_BLOCKED_CLEAR_REQUIRED_MESSAGE =
  "Backup checked only. Clear the selected backup before continuing setup.";

export function computeStagedBackupPreflightStatus(
  input: RuntimeStagedBackupBridgeStatusInput = {},
): RuntimeStagedBackupBridgeStatus {
  const stagedBackup = input.stagedBackup ?? null;
  const decideGate = input.decideGate ?? decideStagedBackupCommitGate;

  if (!stagedBackup) {
    const gateDecision = decideGate({ stagedBackupPresent: false });
    return {
      kind: "no-backup",
      stagedBackupPresent: false,
      setupAllowed: true,
      recordsWillBeCommitted: false,
      gateAllowed: gateDecision.allowed,
      gateReason: gateDecision.reason,
      warnings: sanitizeWarnings(gateDecision.warnings),
      safeMessage: "No backup is selected. Setup will continue without backup records.",
    };
  }

  const gateDecision = decideGate({
    stagedBackupPresent: true,
    format: stagedBackup.format,
    ...input.gateInput,
  });
  const warnings = sanitizeWarnings([
    ...stagedBackup.warnings,
    ...gateDecision.warnings,
  ]);

  if (gateDecision.allowed) {
    return {
      kind: "checked-only-not-imported-yet",
      stagedBackupPresent: true,
      setupAllowed: true,
      recordsWillBeCommitted: false,
      gateAllowed: true,
      gateReason: gateDecision.reason,
      warnings,
      safeMessage: CHECKED_ONLY_MESSAGE,
    };
  }

  const setupAllowed = !input.blockSetupWhenGateBlocked;
  return {
    kind: setupAllowed ? "gate-blocked-setup-only" : "gate-blocked-clear-required",
    stagedBackupPresent: true,
    setupAllowed,
    recordsWillBeCommitted: false,
    gateAllowed: false,
    gateReason: gateDecision.reason,
    warnings,
    safeMessage: setupAllowed
      ? GATE_BLOCKED_SETUP_ONLY_MESSAGE
      : GATE_BLOCKED_CLEAR_REQUIRED_MESSAGE,
  };
}

function sanitizeWarnings(warnings: string[]): string[] {
  const safeWarnings = new Set<string>();
  for (const warning of warnings) {
    if (typeof warning !== "string" || warning.length === 0) continue;
    if (isKnownSafeParserWarning(warning) || isKnownSafeGateWarning(warning)) {
      safeWarnings.add(warning);
      continue;
    }
    safeWarnings.add("Backup has a warning that should be reviewed before records can be added.");
  }
  return [...safeWarnings];
}

function isKnownSafeParserWarning(warning: string): boolean {
  return (
    warning ===
    "encrypted-local-records backups are staged only and require a future compatibility or rekey flow before commit"
  );
}

function isKnownSafeGateWarning(warning: string): boolean {
  return (
    warning ===
      "Backup contains decoy trigger metadata that may need review after import." ||
    warning ===
      "Backup has a non-blocking warning that should be reviewed before import."
  );
}
