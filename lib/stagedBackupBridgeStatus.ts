import type { BackupStageResult } from "./backupSchema";
import {
  decideStagedBackupCommitGate,
  type StagedBackupCommitGateDecision,
  type StagedBackupCommitGateInput,
  type StagedBackupCommitGateReason,
} from "./stagedBackupCommitGate";
import {
  determineStagedBackupImportTransition,
  type StagedBackupImportTransitionStatus,
} from "./stagedBackupImportTransition";

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
  importCommitEnabled?: boolean;
  userDismissedImport?: boolean;
}

export interface RuntimeStagedBackupBridgeStatus {
  kind: RuntimeStagedBackupBridgeStatusKind;
  transitionStatus: StagedBackupImportTransitionStatus;
  stagedBackupPresent: boolean;
  setupAllowed: boolean;
  recordsWillBeCommitted: false;
  gateAllowed: boolean;
  gateReason: StagedBackupCommitGateReason;
  warnings: string[];
  safeMessage: string;
}

export function computeStagedBackupPreflightStatus(
  input: RuntimeStagedBackupBridgeStatusInput = {},
): RuntimeStagedBackupBridgeStatus {
  const stagedBackup = input.stagedBackup ?? null;
  const decideGate = input.decideGate ?? decideStagedBackupCommitGate;
  const importCommitEnabled = input.importCommitEnabled ?? false;

  if (!stagedBackup) {
    const gateDecision = decideGate({ stagedBackupPresent: false });
    const transition = determineStagedBackupImportTransition({
      stagedBackupPresent: false,
      importCommitEnabled,
      gateDecision,
    });

    return {
      kind: "no-backup",
      transitionStatus: transition.status,
      stagedBackupPresent: false,
      setupAllowed: transition.canContinueSetup,
      recordsWillBeCommitted: false,
      gateAllowed: gateDecision.allowed,
      gateReason: gateDecision.reason,
      warnings: transition.warnings,
      safeMessage: transition.safeMessage,
    };
  }

  const gateDecision = decideGate({
    stagedBackupPresent: true,
    format: stagedBackup.format,
    ...input.gateInput,
  });
  const transitionGateDecision = {
    ...gateDecision,
    warnings: [...stagedBackup.warnings, ...gateDecision.warnings],
  };
  const transition = determineStagedBackupImportTransition({
    stagedBackupPresent: true,
    importCommitEnabled,
    gateDecision: transitionGateDecision,
    userDismissedImport: input.userDismissedImport,
  });

  return {
    kind: bridgeKindForTransition(transition.status, input.blockSetupWhenGateBlocked),
    transitionStatus: transition.status,
    stagedBackupPresent: true,
    setupAllowed: setupAllowedForTransition(
      transition.status,
      transition.canContinueSetup,
      input.blockSetupWhenGateBlocked,
    ),
    recordsWillBeCommitted: false,
    gateAllowed: gateDecision.allowed,
    gateReason: gateDecision.reason,
    warnings: transition.warnings,
    safeMessage: transition.safeMessage,
  };
}

function bridgeKindForTransition(
  transitionStatus: StagedBackupImportTransitionStatus,
  blockSetupWhenGateBlocked: boolean | undefined,
): RuntimeStagedBackupBridgeStatusKind {
  if (transitionStatus === "no-backup") {
    return "no-backup";
  }

  if (transitionStatus === "blocked-import") {
    return blockSetupWhenGateBlocked
      ? "gate-blocked-clear-required"
      : "gate-blocked-setup-only";
  }

  if (transitionStatus === "setup-only-dismissed") {
    return "gate-blocked-setup-only";
  }

  return "checked-only-not-imported-yet";
}

function setupAllowedForTransition(
  transitionStatus: StagedBackupImportTransitionStatus,
  canContinueSetup: boolean,
  blockSetupWhenGateBlocked: boolean | undefined,
): boolean {
  if (transitionStatus === "blocked-import") {
    return blockSetupWhenGateBlocked ? false : true;
  }

  return canContinueSetup;
}
