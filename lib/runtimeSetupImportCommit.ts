import type { BackupStageResult } from "./backupSchema";
import {
  buildBackupCompatibilityContextFromSetup,
  classifyBackupCompatibility,
  PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS,
} from "./backupSchema";
import { verifyStagedBackupDecryptability } from "./backupDecryptVerification";
import type { BackupVerifier } from "./backupVerifier";
import {
  extractBackupVerifierFromStagedBackup,
  verifyBackupSentinel,
} from "./backupVerifier";
import { decryptData } from "../crypto/encryption";
import { deriveEntryKey } from "../crypto/hkdf";
import type { KeyShares } from "../crypto/secureMemory";
import { combineShares, hexToBytes, wipeBuffer } from "../crypto/secureMemory";
import {
  type SetupImportCommitOrchestrationDependencies,
  type SetupImportCommitOrchestrationInput,
  type SetupImportCommitOrchestrationResult,
  prepareAndExecuteSetupImportCommit,
} from "./setupImportCommitOrchestrator";
import type { SetupImportCommitResult } from "./setupImportCommitExecutor";
import type { SetupImportSetupMetadata } from "./setupImportCommitPlan";
import type { SharedVaultBlob } from "../workers/sharedVaultStorage";
import type { SecureNote, VaultEntry } from "../workers/vaultWorker";
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
      commitResult: sanitizeCommitResult(orchestrationResult.commitResult),
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
    safeWarnings.add("Setup/import has a warning that must be reviewed before record commit.");
  }
  return [...safeWarnings];
}

function isKnownSafeWarning(warning: string): boolean {
  return (
    warning === "Backup contains decoy trigger metadata that must be reviewed before import." ||
    warning === "Backup has a warning that must be reviewed before record commit." ||
    warning === "Backup contains decoy trigger metadata that may need review after import." ||
    warning === "Backup has a non-blocking warning that should be reviewed before import." ||
    warning ===
      "encrypted-local-records backups are staged only and require a future compatibility or rekey flow before commit"
  );
}

export interface PrepareStagedBackupEligibilityInput {
  stagedBackup?: BackupStageResult | null;
  compatibilityStatus?: "compatible" | "incompatible" | "unknown" | "missing";
  verifierStatus?: "missing" | "valid" | "invalid";
  sentinelStatus?: "not-needed" | "passed" | "failed" | "not-run";
  decryptabilityStatus?: "passed" | "failed" | "not-run";
  warningKinds?: string[];
  userConfirmedImportIntent?: boolean;
  userDismissedImport?: boolean;
  enableFeatureFlagForSameInstall?: boolean;
}

export function prepareStagedBackupImportEligibilityInput(
  input: PrepareStagedBackupEligibilityInput,
): StagedBackupImportCommitEligibilityInput {
  const stagedBackupPresent = !!input.stagedBackup;
  const stagedBackupFormat = stagedBackupPresent ? input.stagedBackup!.format : undefined;

  return {
    stagedBackupPresent,
    stagedBackupFormat,
    compatibilityStatus: input.compatibilityStatus ?? "missing",
    verifierStatus: input.verifierStatus ?? "missing",
    sentinelStatus: input.sentinelStatus ?? "not-needed",
    decryptabilityStatus: input.decryptabilityStatus ?? "not-run",
    warningKinds: input.warningKinds,
    userConfirmedImportIntent: input.userConfirmedImportIntent,
    userDismissedImport: input.userDismissedImport,
    featureFlagEnabled: input.enableFeatureFlagForSameInstall ?? false,
    options: {
      blockHoneytokenWarnings: true,
      requireVerifier: false,
      requireExplicitImportIntent: false,
    },
  };
}

function sanitizeCommitResult(
  commitResult: SetupImportCommitResult | undefined,
): SetupImportCommitResult | undefined {
  if (!commitResult?.success && commitResult) {
    return {
      ...commitResult,
      failedOperation: commitResult.failedOperation
        ? {
            ...commitResult.failedOperation,
            key: "setup-import-operation",
          }
        : undefined,
      rollbackFailures: commitResult.rollbackFailures?.map((failure) => ({
        ...failure,
        key: "setup-import-operation",
      })),
    };
  }

  return commitResult;
}

export interface RuntimeStagedBackupCommitContextInput {
  setupMetadata: SetupImportSetupMetadata;
  stagedBackup?: BackupStageResult | null;
  keyShares: KeyShares;
  masterKeyHex?: string;
  deviceUUID?: string | null;
  deviceUUIDPresent?: boolean;
  now?: () => number;
}

export interface RuntimeStagedBackupCommitContext {
  eligibilityInput: StagedBackupImportCommitEligibilityInput;
  classifyCompatibility: SetupImportCommitOrchestrationDependencies["classifyCompatibility"];
  verifySentinel: NonNullable<SetupImportCommitOrchestrationDependencies["verifySentinel"]>;
  verifyDecryptability: SetupImportCommitOrchestrationDependencies["verifyDecryptability"];
  backupVerifier: BackupVerifier | null;
  sharedVaultBlob: SharedVaultBlob | null;
  warnings: string[];
}

export async function prepareRuntimeStagedBackupCommitContext(
  input: RuntimeStagedBackupCommitContextInput,
): Promise<RuntimeStagedBackupCommitContext> {
  const stagedBackup = input.stagedBackup ?? null;
  if (!stagedBackup) {
    return {
      eligibilityInput: prepareStagedBackupImportEligibilityInput({
        stagedBackup: null,
      }),
      classifyCompatibility: () => ({
        status: "incompatible",
        reason: "no-staged-backup",
        warnings: [],
      }),
      verifySentinel: async () => ({
        ok: false,
        reason: "missing-decryptor",
        message: "Backup verifier decryptor is unavailable.",
      }),
      verifyDecryptability: async () => ({
        ok: false,
        counts: {
          entriesChecked: 0,
          notesChecked: 0,
          entriesFailed: 0,
          notesFailed: 0,
        },
        failures: [],
      }),
      backupVerifier: null,
      sharedVaultBlob: null,
      warnings: [],
    };
  }

  const masterKeyHex = input.masterKeyHex ?? combineShares(input.keyShares);
  try {
    const compatibility = classifyBackupCompatibility(
      stagedBackup,
      buildBackupCompatibilityContextFromSetup({
        setupMetadata: {
          masterSalt: input.setupMetadata.masterSalt,
          kdfMetadata: input.setupMetadata.kdfMetadata,
        },
        deviceUUID: input.deviceUUID,
        deviceUUIDPresent: input.deviceUUIDPresent,
      }),
    );
    const verifier = extractBackupVerifierFromStagedBackup(stagedBackup);
    const sentinel =
      verifier.ok
        ? await verifyBackupSentinel({
            verifier: verifier.verifier,
            masterKeyHex,
            deriveAndDecryptEntrySentinel: ({ recordId, salt, ciphertext }) =>
              decryptData(ciphertext, deriveEntryKey(masterKeyHex, recordId, salt)),
            deriveAndDecryptNoteSentinel: ({ recordId, salt, ciphertext }) =>
              decryptData(ciphertext, deriveEntryKey(masterKeyHex, recordId, salt)),
          })
        : null;
    const decryptability = await verifyStagedBackupDecryptability({
      stagedBackup,
      keyShares: input.keyShares,
      masterKeyHex,
      decryptEntry: ({ entry, keyShares }) => {
        if (!keyShares) throw new Error("missing key shares");
        return verifyEncryptedEntryWithShares(entry, keyShares);
      },
      decryptSecureNote: ({ note, keyShares }) => {
        if (!keyShares) throw new Error("missing key shares");
        return verifyEncryptedSecureNoteWithShares(note, keyShares);
      },
    });
    const warnings = [...stagedBackup.warnings, ...compatibility.warnings];

    return {
      eligibilityInput: prepareStagedBackupImportEligibilityInput({
        stagedBackup,
        compatibilityStatus: compatibility.status,
        verifierStatus: verifier.ok
          ? "valid"
          : verifier.error.code === "missing-verifier"
            ? "missing"
            : "invalid",
        sentinelStatus: verifier.ok
          ? sentinel?.ok
            ? "passed"
            : "failed"
          : "not-needed",
        decryptabilityStatus: decryptability.ok ? "passed" : "failed",
        warningKinds: warnings,
        enableFeatureFlagForSameInstall: isFirstSupportedBackupShape(stagedBackup),
      }),
      classifyCompatibility: () => compatibility,
      verifySentinel: async () =>
        sentinel ?? {
          ok: false,
          reason: "missing-decryptor",
          message: "Backup verifier decryptor is unavailable.",
        },
      verifyDecryptability: async () => decryptability,
      backupVerifier: verifier.ok ? verifier.verifier : null,
      sharedVaultBlob: buildRuntimeSharedVaultBlob(
        stagedBackup.entries,
        input.now ?? Date.now,
      ),
      warnings,
    };
  } finally {
    if (input.masterKeyHex === undefined) {
      const keyBytes = hexToBytes(masterKeyHex);
      wipeBuffer(keyBytes);
    }
  }
}

function verifyEncryptedEntryWithShares(entry: VaultEntry, keyShares: KeyShares): true {
  const masterKeyHex = combineShares(keyShares);
  try {
    const entryKey = entry.salt
      ? deriveEntryKey(masterKeyHex, entry.id, entry.salt)
      : masterKeyHex;
    decryptData(entry.encryptedPassword, entryKey);
    decryptOptional(entry.encryptedTitle, entryKey);
    decryptOptional(entry.encryptedUsername, entryKey);
    decryptOptional(entry.encryptedUrl, entryKey);
    decryptOptional(entry.notes, entryKey);
    decryptOptional(entry.encryptedAux, entryKey);
    return true;
  } finally {
    const keyBytes = hexToBytes(masterKeyHex);
    wipeBuffer(keyBytes);
  }
}

function verifyEncryptedSecureNoteWithShares(note: SecureNote, keyShares: KeyShares): true {
  const masterKeyHex = combineShares(keyShares);
  try {
    const noteKey = note.salt
      ? deriveEntryKey(masterKeyHex, note.id, note.salt)
      : masterKeyHex;
    decryptData(note.encryptedContent, noteKey);
    decryptData(note.encryptedLabel, noteKey);
    return true;
  } finally {
    const keyBytes = hexToBytes(masterKeyHex);
    wipeBuffer(keyBytes);
  }
}

function decryptOptional(value: string | undefined, keyHex: string): void {
  if (typeof value === "string" && value.length > 0) {
    decryptData(value, keyHex);
  }
}

function isFirstSupportedBackupShape(stagedBackup: BackupStageResult): boolean {
  return (
    stagedBackup.schema === "pipass-backup" &&
    stagedBackup.version === 1 &&
    stagedBackup.format === PIPASS_BACKUP_FORMAT_ENCRYPTED_LOCAL_RECORDS
  );
}

function buildRuntimeSharedVaultBlob(
  entries: VaultEntry[],
  now: () => number,
): SharedVaultBlob | null {
  if (entries.length === 0) return null;
  return {
    encryptedBlob: JSON.stringify(entries),
    version: 1,
    updatedAt: now(),
  };
}
