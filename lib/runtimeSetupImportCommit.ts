import type { BackupStageResult } from "./backupSchema";
import type { BackupVerifier } from "./backupVerifier";
import {
  type SetupImportCommitOrchestrationDependencies,
  type SetupImportCommitOrchestrationInput,
  type SetupImportCommitOrchestrationResult,
  prepareAndExecuteSetupImportCommit,
} from "./setupImportCommitOrchestrator";
import type { SetupImportCommitResult } from "./setupImportCommitExecutor";
import type { SetupImportSetupMetadata } from "./setupImportCommitPlan";
import type { SharedVaultBlob } from "../workers/sharedVaultStorage";
import {
  determineStagedBackupImportCommitEligibility,
  type StagedBackupImportCommitEligibilityInput,
  type StagedBackupImportCommitEligibilityResult,
} from "./stagedBackupImportEligibility";

export type RuntimeSetupImportCommitStage =
  | "eligibility"
  | SetupImportCommitOrchestrationResult["stage"];

export interface RuntimeSetupImportCommitInput {
  setupMetadata: SetupImportSetupMetadata;
  stagedBackup?: BackupStageResult | null;
  backupVerifier?: BackupVerifier | null;
  eligibilityInput: StagedBackupImportCommitEligibilityInput;
  sharedVaultBlob?: SharedVaultBlob | null;
  includeCachedMasterKey?: boolean;
  cachedMasterKeyReference?: string;
  initializedMarkerValue?: "1";
  allowUnknownCompatibility?: boolean;
  requireBackupVerifier?: boolean;
  allowHoneytokenWarnings?: boolean;
  dependencies: SetupImportCommitOrchestrationDependencies;
  determineEligibility?: (
    input: StagedBackupImportCommitEligibilityInput,
  ) => StagedBackupImportCommitEligibilityResult;
  executeSetupImportCommit?: (
    input: SetupImportCommitOrchestrationInput,
  ) => Promise<SetupImportCommitOrchestrationResult>;
}

export type RuntimeSetupImportCommitResult =
  | {
      ok: true;
      stage: RuntimeSetupImportCommitStage;
      eligibility: StagedBackupImportCommitEligibilityResult;
      recordsIncluded: boolean;
      activeSharesPublished: false;
      warnings: string[];
      commitResult: SetupImportCommitResult;
    }
  | {
      ok: false;
      stage: RuntimeSetupImportCommitStage;
      reason: string;
      eligibility: StagedBackupImportCommitEligibilityResult;
      recordsIncluded: boolean;
      activeSharesPublished: false;
      warnings: string[];
      commitResult?: SetupImportCommitResult;
    };

export async function prepareSetupImportCommitFromRuntimeState(
  input: RuntimeSetupImportCommitInput,
): Promise<RuntimeSetupImportCommitResult> {
  const determineEligibility =
    input.determineEligibility ?? determineStagedBackupImportCommitEligibility;
  const eligibility = determineEligibility(input.eligibilityInput);

  if (!eligibility.importCommitEnabled && !eligibility.setupOnlyAllowed) {
    return {
      ok: false,
      stage: "eligibility",
      reason: eligibility.reason,
      eligibility,
      recordsIncluded: false,
      activeSharesPublished: false,
      warnings: sanitizeWarnings(eligibility.warnings),
    };
  }

  const shouldIncludeStagedRecords =
    eligibility.importCommitEnabled && input.stagedBackup !== null && input.stagedBackup !== undefined;
  const executeSetupImportCommit =
    input.executeSetupImportCommit ?? prepareAndExecuteSetupImportCommit;
  const orchestrationResult = await executeSetupImportCommit({
    setupMetadata: input.setupMetadata,
    stagedBackup: shouldIncludeStagedRecords ? input.stagedBackup : null,
    backupVerifier: shouldIncludeStagedRecords ? input.backupVerifier : null,
    sharedVaultBlob: shouldIncludeStagedRecords ? input.sharedVaultBlob : undefined,
    includeCachedMasterKey: input.includeCachedMasterKey,
    cachedMasterKeyReference: input.cachedMasterKeyReference,
    initializedMarkerValue: input.initializedMarkerValue,
    allowUnknownCompatibility: input.allowUnknownCompatibility,
    requireBackupVerifier: input.requireBackupVerifier,
    allowHoneytokenWarnings: input.allowHoneytokenWarnings,
    dependencies: input.dependencies,
  });

  const warnings = sanitizeWarnings([
    ...eligibility.warnings,
    ...orchestrationResult.warnings,
  ]);

  if (!orchestrationResult.ok) {
    return {
      ok: false,
      stage: orchestrationResult.stage,
      reason: orchestrationResult.reason,
      eligibility,
      recordsIncluded: false,
      activeSharesPublished: false,
      warnings,
      commitResult: orchestrationResult.commitResult,
    };
  }

  return {
    ok: true,
    stage: orchestrationResult.stage,
    eligibility,
    recordsIncluded: shouldIncludeStagedRecords && orchestrationResult.stage === "commit",
    activeSharesPublished: false,
    warnings,
    commitResult: orchestrationResult.commitResult,
  };
}

function sanitizeWarnings(warnings: string[]): string[] {
  const safeWarnings = new Set<string>();
  for (const warning of warnings) {
    if (typeof warning !== "string" || warning.length === 0) continue;
    if (isKnownSafeWarning(warning)) {
      safeWarnings.add(warning);
      continue;
    }
    safeWarnings.add("Setup/import has a warning that must be reviewed before records can be added.");
  }
  return [...safeWarnings];
}

function isKnownSafeWarning(warning: string): boolean {
  return (
    warning === "Backup contains decoy trigger metadata that must be reviewed before import." ||
    warning === "Backup has a warning that must be reviewed before records can be added." ||
    warning === "Backup contains decoy trigger metadata that may need review after import." ||
    warning === "Backup has a non-blocking warning that should be reviewed before import." ||
    warning ===
      "encrypted-local-records backups are staged only and require a future compatibility or rekey flow before commit"
  );
}
