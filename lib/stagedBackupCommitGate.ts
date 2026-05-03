import {
  PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS,
  type BackupCompatibilityResult,
} from "./backupSchema";
import type { BackupDecryptVerificationResult } from "./backupDecryptVerification";
import type {
  BackupSentinelVerificationResult,
  BackupVerifierParseResult,
} from "./backupVerifier";

export type StagedBackupCommitGateMode =
  | "no-backup"
  | "setup-only"
  | "commit-staged-backup";

export type StagedBackupCommitGateReason =
  | "no-backup"
  | "unsupported-format"
  | "incompatible"
  | "unknown-compatibility"
  | "missing-verifier"
  | "invalid-verifier"
  | "sentinel-failed"
  | "decryptability-not-run"
  | "decryptability-failed"
  | "warnings-blocked"
  | "allowed";

export interface StagedBackupCommitGateOptions {
  allowUnknownCompatibility?: boolean;
  requireVerifier?: boolean;
  allowHoneytokenWarnings?: boolean;
}

export interface StagedBackupCommitGateInput {
  stagedBackupPresent: boolean;
  format?: string;
  compatibility?: BackupCompatibilityResult;
  verifier?: BackupVerifierParseResult | null;
  sentinelVerification?: BackupSentinelVerificationResult | null;
  decryptability?: BackupDecryptVerificationResult | null;
  options?: StagedBackupCommitGateOptions;
}

export interface StagedBackupCommitGateDecision {
  allowed: boolean;
  mode: StagedBackupCommitGateMode;
  reason: StagedBackupCommitGateReason;
  warnings: string[];
  safeMessage: string;
}

const SAFE_WARNING_HONEYTOKEN =
  "Backup contains decoy trigger metadata that may need review after import.";
const SAFE_WARNING_GENERIC =
  "Backup has a non-blocking warning that should be reviewed before import.";

export function decideStagedBackupCommitGate(
  input: StagedBackupCommitGateInput,
): StagedBackupCommitGateDecision {
  const warnings = sanitizeWarnings(input.compatibility?.warnings ?? []);

  if (!input.stagedBackupPresent) {
    return decision(true, "setup-only", "no-backup", [], "No staged backup is attached. Setup can continue without importing backup records.");
  }

  if (input.format !== PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS) {
    return decision(false, "setup-only", "unsupported-format", warnings, "This backup format is not supported for staged import.");
  }

  if (!input.compatibility || input.compatibility.status === "unknown") {
    if (!input.options?.allowUnknownCompatibility) {
      return decision(false, "setup-only", "unknown-compatibility", warnings, "PiPass cannot prove this backup is compatible yet.");
    }
  } else if (input.compatibility.status === "incompatible") {
    return decision(false, "setup-only", "incompatible", warnings, "This backup does not match the current local vault setup.");
  }

  const verifierDecision = evaluateVerifier(input);
  if (verifierDecision) {
    return { ...verifierDecision, warnings };
  }

  if (!input.decryptability) {
    return decision(false, "setup-only", "decryptability-not-run", warnings, "PiPass has not verified every staged backup record.");
  }

  if (!input.decryptability.ok) {
    return decision(false, "setup-only", "decryptability-failed", warnings, "PiPass could not verify every staged backup record.");
  }

  if (!input.options?.allowHoneytokenWarnings && hasHoneytokenWarning(input.compatibility?.warnings ?? [])) {
    return decision(false, "setup-only", "warnings-blocked", warnings, "This backup has decoy trigger metadata that needs review before import.");
  }

  return decision(true, "commit-staged-backup", "allowed", warnings, "This staged backup passed the required import gates.");
}

function evaluateVerifier(
  input: StagedBackupCommitGateInput,
): Omit<StagedBackupCommitGateDecision, "warnings"> | null {
  if (!input.verifier || (!input.verifier.ok && input.verifier.error.code === "missing-verifier")) {
    if (input.options?.requireVerifier) {
      return decision(false, "setup-only", "missing-verifier", [], "This backup is missing a required verifier.");
    }
    return null;
  }

  if (!input.verifier.ok) {
    return decision(false, "setup-only", "invalid-verifier", [], "This backup verifier is not valid.");
  }

  if (!input.sentinelVerification?.ok) {
    return decision(false, "setup-only", "sentinel-failed", [], "PiPass could not verify the backup sentinel.");
  }

  return null;
}

function decision(
  allowed: boolean,
  mode: StagedBackupCommitGateMode,
  reason: StagedBackupCommitGateReason,
  warnings: string[],
  safeMessage: string,
): StagedBackupCommitGateDecision {
  return {
    allowed,
    mode,
    reason,
    warnings,
    safeMessage,
  };
}

function sanitizeWarnings(warnings: string[]): string[] {
  const safeWarnings = new Set<string>();
  for (const warning of warnings) {
    if (hasHoneytokenWarning([warning])) {
      safeWarnings.add(SAFE_WARNING_HONEYTOKEN);
    } else if (typeof warning === "string" && warning.length > 0) {
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
