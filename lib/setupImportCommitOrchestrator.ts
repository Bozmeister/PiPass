import type {
  BackupCompatibilityResult,
  BackupStageResult,
} from "./backupSchema";
import type { BackupDecryptVerificationResult } from "./backupDecryptVerification";
import type {
  BackupSentinelVerificationResult,
  BackupVerifier,
} from "./backupVerifier";
import type { SetupImportCommitResult } from "./setupImportCommitExecutor";
import type {
  BuildSetupImportCommitPlanInput,
  SetupImportCommitPlan,
  SetupImportCommitPlanResult,
  SetupImportSetupMetadata,
} from "./setupImportCommitPlan";
import {
  decideStagedBackupCommitGate,
  type StagedBackupCommitGateDecision,
  type StagedBackupCommitGateInput,
} from "./stagedBackupCommitGate";
import type { SharedVaultBlob } from "../workers/sharedVaultStorage";
import type { VaultEntry } from "../workers/vaultWorker";

export type SetupImportCommitOrchestrationStage =
  | "setup-only"
  | "compatibility"
  | "sentinel"
  | "decryptability"
  | "gate"
  | "shared-vault"
  | "plan"
  | "commit";

export interface SetupImportCommitOrchestrationDependencies {
  classifyCompatibility: (
    stagedBackup: BackupStageResult,
  ) => BackupCompatibilityResult | Promise<BackupCompatibilityResult>;
  verifySentinel?: (
    verifier: BackupVerifier,
  ) => BackupSentinelVerificationResult | Promise<BackupSentinelVerificationResult>;
  verifyDecryptability: (
    stagedBackup: BackupStageResult,
  ) => BackupDecryptVerificationResult | Promise<BackupDecryptVerificationResult>;
  decideCommitGate?: (
    input: StagedBackupCommitGateInput,
  ) => StagedBackupCommitGateDecision | Promise<StagedBackupCommitGateDecision>;
  buildSharedVaultBlob?: (
    entries: VaultEntry[],
  ) => SharedVaultBlob | null | Promise<SharedVaultBlob | null>;
  buildPlan: (input: BuildSetupImportCommitPlanInput) => SetupImportCommitPlanResult;
  executePlan: (plan: SetupImportCommitPlan) => SetupImportCommitResult | Promise<SetupImportCommitResult>;
}

export interface SetupImportCommitOrchestrationInput {
  setupMetadata: SetupImportSetupMetadata;
  stagedBackup?: BackupStageResult | null;
  backupVerifier?: BackupVerifier | null;
  sharedVaultBlob?: SharedVaultBlob | null;
  includeCachedMasterKey?: boolean;
  cachedMasterKeyReference?: string;
  initializedMarkerValue?: "1";
  allowUnknownCompatibility?: boolean;
  requireBackupVerifier?: boolean;
  allowHoneytokenWarnings?: boolean;
  dependencies: SetupImportCommitOrchestrationDependencies;
}

export type SetupImportCommitOrchestrationResult =
  | {
      ok: true;
      stage: SetupImportCommitOrchestrationStage;
      warnings: string[];
      commitResult: SetupImportCommitResult;
    }
  | {
      ok: false;
      stage: SetupImportCommitOrchestrationStage;
      reason: string;
      warnings: string[];
      commitResult?: SetupImportCommitResult;
    };

export async function prepareAndExecuteSetupImportCommit(
  input: SetupImportCommitOrchestrationInput,
): Promise<SetupImportCommitOrchestrationResult> {
  const stagedBackup = input.stagedBackup ?? null;
  const warnings = collectWarnings(stagedBackup?.warnings);

  if (!stagedBackup) {
    const gateDecision = await resolveGateDecision(input, {
      stagedBackupPresent: false,
    });
    const gateWarnings = mergeWarnings(warnings, gateDecision.warnings);
    if (!gateDecision.allowed) {
      return failure("gate", gateDecision.reason, gateWarnings);
    }
    return buildAndExecutePlan(input, gateWarnings, "setup-only", undefined);
  }

  const compatibility = await input.dependencies.classifyCompatibility(stagedBackup);

  if (compatibility.status === "incompatible") {
    return gateFailure(input, stagedBackup, compatibility, null, null, null, warnings);
  }

  if (compatibility.status === "unknown" && !input.allowUnknownCompatibility) {
    return gateFailure(input, stagedBackup, compatibility, null, null, null, warnings);
  }

  let sentinelResult: BackupSentinelVerificationResult | null = null;
  if (input.backupVerifier) {
    if (!input.dependencies.verifySentinel) {
      sentinelResult = {
        ok: false,
        reason: "missing-decryptor",
        message: "Backup verifier decryptor is unavailable.",
      };
    } else {
      sentinelResult = await input.dependencies.verifySentinel(input.backupVerifier);
    }
    if (!sentinelResult.ok) {
      return gateFailure(
        input,
        stagedBackup,
        compatibility,
        { ok: true, verifier: input.backupVerifier },
        sentinelResult,
        null,
        warnings,
      );
    }
  }

  const decryptability = await input.dependencies.verifyDecryptability(stagedBackup);
  if (!decryptability.ok) {
    return gateFailure(input, stagedBackup, compatibility, null, sentinelResult, decryptability, warnings);
  }

  const gateDecision = await resolveGateDecision(input, {
    stagedBackupPresent: true,
    format: stagedBackup.format,
    compatibility,
    verifier: input.backupVerifier
      ? { ok: true, verifier: input.backupVerifier }
      : null,
    sentinelVerification: sentinelResult,
    decryptability,
    options: {
      allowUnknownCompatibility: input.allowUnknownCompatibility,
      requireVerifier: input.requireBackupVerifier,
      allowHoneytokenWarnings: input.allowHoneytokenWarnings,
    },
  });

  const gateWarnings = mergeWarnings(warnings, gateDecision.warnings);
  if (!gateDecision.allowed) {
    return failure("gate", gateDecision.reason, gateWarnings);
  }

  if (gateDecision.mode !== "commit-staged-backup") {
    return buildAndExecutePlan(input, gateWarnings, "setup-only", undefined);
  }

  const sharedVaultResult = await resolveSharedVaultBlob(input, stagedBackup, gateWarnings);
  if (!sharedVaultResult.ok) {
    return sharedVaultResult;
  }

  return buildAndExecutePlan(input, gateWarnings, "commit", {
    entries: stagedBackup.entries,
    secureNotes: stagedBackup.secureNotes,
    sharedVaultBlob: sharedVaultResult.sharedVaultBlob,
  });
}

async function gateFailure(
  input: SetupImportCommitOrchestrationInput,
  stagedBackup: BackupStageResult,
  compatibility: BackupCompatibilityResult,
  verifier: StagedBackupCommitGateInput["verifier"],
  sentinelVerification: BackupSentinelVerificationResult | null,
  decryptability: BackupDecryptVerificationResult | null,
  warnings: string[],
): Promise<Extract<SetupImportCommitOrchestrationResult, { ok: false }>> {
  const gateDecision = await resolveGateDecision(input, {
    stagedBackupPresent: true,
    format: stagedBackup.format,
    compatibility,
    verifier,
    sentinelVerification,
    decryptability,
    options: {
      allowUnknownCompatibility: input.allowUnknownCompatibility,
      requireVerifier: input.requireBackupVerifier,
      allowHoneytokenWarnings: input.allowHoneytokenWarnings,
    },
  });

  return failure("gate", gateDecision.reason, mergeWarnings(warnings, gateDecision.warnings));
}

function resolveGateDecision(
  input: SetupImportCommitOrchestrationInput,
  gateInput: StagedBackupCommitGateInput,
): StagedBackupCommitGateDecision | Promise<StagedBackupCommitGateDecision> {
  return (input.dependencies.decideCommitGate ?? decideStagedBackupCommitGate)(gateInput);
}

async function resolveSharedVaultBlob(
  input: SetupImportCommitOrchestrationInput,
  stagedBackup: BackupStageResult,
  warnings: string[],
): Promise<
  | { ok: true; sharedVaultBlob: SharedVaultBlob | null }
  | Extract<SetupImportCommitOrchestrationResult, { ok: false }>
> {
  if (input.sharedVaultBlob !== undefined) {
    return { ok: true, sharedVaultBlob: input.sharedVaultBlob };
  }

  if (stagedBackup.entries.length === 0) {
    return { ok: true, sharedVaultBlob: null };
  }

  if (!input.dependencies.buildSharedVaultBlob) {
    return failure("shared-vault", "missing-shared-vault-builder", warnings);
  }

  try {
    const sharedVaultBlob = await input.dependencies.buildSharedVaultBlob(stagedBackup.entries);
    return { ok: true, sharedVaultBlob };
  } catch {
    return failure("shared-vault", "shared-vault-build-failed", warnings);
  }
}

async function buildAndExecutePlan(
  input: SetupImportCommitOrchestrationInput,
  warnings: string[],
  successStage: Extract<SetupImportCommitOrchestrationStage, "setup-only" | "commit">,
  backupInput:
    | {
        entries: BackupStageResult["entries"];
        secureNotes: BackupStageResult["secureNotes"];
        sharedVaultBlob: SharedVaultBlob | null;
      }
    | undefined,
): Promise<SetupImportCommitOrchestrationResult> {
  const planResult = input.dependencies.buildPlan({
    setupMetadata: input.setupMetadata,
    entries: backupInput?.entries,
    secureNotes: backupInput?.secureNotes,
    sharedVaultBlob: backupInput?.sharedVaultBlob,
    includeCachedMasterKey: input.includeCachedMasterKey,
    cachedMasterKeyReference: input.cachedMasterKeyReference,
    initializedMarkerValue: input.initializedMarkerValue,
  });

  if (!planResult.ok) {
    return failure("plan", planResult.error.code, warnings);
  }

  const commitResult = await input.dependencies.executePlan(planResult.plan);
  if (!commitResult.success) {
    return {
      ok: false,
      stage: "commit",
      reason: commitResult.reason,
      warnings,
      commitResult,
    };
  }

  return {
    ok: true,
    stage: successStage,
    warnings,
    commitResult,
  };
}

function failure(
  stage: SetupImportCommitOrchestrationStage,
  reason: string,
  warnings: string[],
): Extract<SetupImportCommitOrchestrationResult, { ok: false }> {
  return {
    ok: false,
    stage,
    reason,
    warnings,
  };
}

function collectWarnings(warnings: string[] | undefined): string[] {
  if (!warnings) return [];
  return warnings.filter((warning) => typeof warning === "string" && warning.length > 0);
}

function mergeWarnings(...warningGroups: Array<string[] | undefined>): string[] {
  const merged = new Set<string>();
  for (const warnings of warningGroups) {
    for (const warning of collectWarnings(warnings)) {
      merged.add(warning);
    }
  }
  return [...merged];
}
