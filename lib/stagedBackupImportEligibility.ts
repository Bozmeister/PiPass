import { PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS } from "./backupSchema";

export type StagedBackupImportCommitEligibilityStatus =
  | "not-selected"
  | "eligible"
  | "blocked"
  | "requires-clear-or-dismiss"
  | "not-yet-enabled";

export type StagedBackupImportCommitEligibilityReason =
  | "no-backup"
  | "feature-disabled"
  | "unsupported-format"
  | "incompatible"
  | "unknown-compatibility"
  | "missing-compatibility"
  | "missing-verifier"
  | "invalid-verifier"
  | "sentinel-not-run"
  | "sentinel-failed"
  | "decryptability-not-run"
  | "decryptability-failed"
  | "warnings-blocked"
  | "import-intent-required"
  | "eligible";

export type StagedBackupImportCompatibilityStatus =
  | "compatible"
  | "incompatible"
  | "unknown"
  | "missing";

export type StagedBackupImportVerifierStatus =
  | "missing"
  | "valid"
  | "invalid";

export type StagedBackupImportSentinelStatus =
  | "not-needed"
  | "passed"
  | "failed"
  | "not-run";

export type StagedBackupImportDecryptabilityStatus =
  | "passed"
  | "failed"
  | "not-run";

export interface StagedBackupImportCommitEligibilityOptions {
  requireExplicitImportIntent?: boolean;
  requireVerifier?: boolean;
  blockHoneytokenWarnings?: boolean;
}

export interface StagedBackupImportCommitEligibilityInput {
  stagedBackupPresent: boolean;
  stagedBackupFormat?: string;
  compatibilityStatus?: StagedBackupImportCompatibilityStatus;
  verifierStatus?: StagedBackupImportVerifierStatus;
  sentinelStatus?: StagedBackupImportSentinelStatus;
  decryptabilityStatus?: StagedBackupImportDecryptabilityStatus;
  warningKinds?: string[];
  userConfirmedImportIntent?: boolean;
  userDismissedImport?: boolean;
  featureFlagEnabled?: boolean;
  options?: StagedBackupImportCommitEligibilityOptions;
}

export interface StagedBackupImportCommitEligibilityResult {
  status: StagedBackupImportCommitEligibilityStatus;
  reason: StagedBackupImportCommitEligibilityReason;
  importCommitEnabled: boolean;
  setupOnlyAllowed: boolean;
  canAttemptImport: boolean;
  requiresClearOrDismiss: boolean;
  safeTitle: string;
  safeMessage: string;
  warnings: string[];
}

const SAFE_WARNING_HONEYTOKEN =
  "Backup contains decoy trigger metadata that must be reviewed before import.";
const SAFE_WARNING_GENERIC =
  "Backup has a warning that must be reviewed before record commit.";

export function determineStagedBackupImportCommitEligibility(
  input: StagedBackupImportCommitEligibilityInput,
): StagedBackupImportCommitEligibilityResult {
  const warnings = sanitizeWarnings(input.warningKinds ?? []);

  if (!input.stagedBackupPresent) {
    return result(
      "not-selected",
      "no-backup",
      false,
      true,
      false,
      false,
      "No backup selected",
      "Setup can continue without backup records.",
      [],
    );
  }

  if (!input.featureFlagEnabled) {
    return result(
      "not-yet-enabled",
      "feature-disabled",
      false,
      true,
      false,
      false,
      "Backup checked only",
      "Backup records are staged in memory only. No backup records have been written.",
      warnings,
    );
  }

  const blockingReason = findBlockingReason(input);
  if (blockingReason) {
    return blockedResult(blockingReason, warnings, input.userDismissedImport);
  }

  if (
    input.options?.requireExplicitImportIntent &&
    !input.userConfirmedImportIntent
  ) {
    return result(
      "requires-clear-or-dismiss",
      "import-intent-required",
      false,
      input.userDismissedImport === true,
      false,
      input.userDismissedImport !== true,
      input.userDismissedImport ? "Setup without backup" : "Confirm backup import",
      input.userDismissedImport
        ? "Backup import was dismissed. Setup can continue without backup records."
        : "Confirm importing this backup, or clear it to continue setup without backup records.",
      warnings,
    );
  }

  return result(
    "eligible",
    "eligible",
    true,
    true,
    true,
    false,
    "Backup ready for commit",
    "Backup records are ready for recovery-confirmed commit. No backup records have been written.",
    warnings,
  );
}

function findBlockingReason(
  input: StagedBackupImportCommitEligibilityInput,
): StagedBackupImportCommitEligibilityReason | null {
  if (input.stagedBackupFormat !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS) {
    return "unsupported-format";
  }

  if (!input.compatibilityStatus || input.compatibilityStatus === "missing") {
    return "missing-compatibility";
  }

  if (input.compatibilityStatus === "unknown") {
    return "unknown-compatibility";
  }

  if (input.compatibilityStatus === "incompatible") {
    return "incompatible";
  }

  if (!input.verifierStatus || input.verifierStatus === "missing") {
    if (input.options?.requireVerifier) {
      return "missing-verifier";
    }
  } else if (input.verifierStatus === "invalid") {
    return "invalid-verifier";
  } else if (input.sentinelStatus !== "passed") {
    return input.sentinelStatus === "failed"
      ? "sentinel-failed"
      : "sentinel-not-run";
  }

  if (input.decryptabilityStatus !== "passed") {
    return input.decryptabilityStatus === "failed"
      ? "decryptability-failed"
      : "decryptability-not-run";
  }

  if (
    input.options?.blockHoneytokenWarnings !== false &&
    hasHoneytokenWarning(input.warningKinds ?? [])
  ) {
    return "warnings-blocked";
  }

  return null;
}

function blockedResult(
  reason: StagedBackupImportCommitEligibilityReason,
  warnings: string[],
  userDismissedImport: boolean | undefined,
): StagedBackupImportCommitEligibilityResult {
  if (userDismissedImport) {
    return result(
      "requires-clear-or-dismiss",
      reason,
      false,
      true,
      false,
      false,
      "Setup without backup",
      "Backup import was dismissed. Setup can continue without backup records.",
      warnings,
    );
  }

  return result(
    "blocked",
    reason,
    false,
    false,
    false,
    true,
    "Backup cannot be committed",
    "This backup is not ready for vault commit. Clear or dismiss it to continue setup without backup records.",
    warnings,
  );
}

function result(
  status: StagedBackupImportCommitEligibilityStatus,
  reason: StagedBackupImportCommitEligibilityReason,
  importCommitEnabled: boolean,
  setupOnlyAllowed: boolean,
  canAttemptImport: boolean,
  requiresClearOrDismiss: boolean,
  safeTitle: string,
  safeMessage: string,
  warnings: string[],
): StagedBackupImportCommitEligibilityResult {
  return {
    status,
    reason,
    importCommitEnabled,
    setupOnlyAllowed,
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
    if (hasHoneytokenWarning([warning])) {
      safeWarnings.add(SAFE_WARNING_HONEYTOKEN);
    } else {
      safeWarnings.add(SAFE_WARNING_GENERIC);
    }
  }
  return [...safeWarnings];
}

function hasHoneytokenWarning(warnings: string[]): boolean {
  return warnings.some((warning) => {
    const normalized = warning.toLowerCase();
    return (
      normalized.includes("honeytoken") ||
      normalized.includes("encryptedaux") ||
      normalized.includes("encrypted aux") ||
      normalized.includes("decoy")
    );
  });
}
