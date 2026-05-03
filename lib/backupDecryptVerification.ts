import type { KeyShares } from "../crypto/secureMemory";
import type { BackupStageResult } from "./backupSchema";
import type { SecureNote, VaultEntry } from "../workers/vaultWorker";

export type BackupDecryptFailureKind = "entry" | "secure-note";
export type BackupDecryptFailureReason = "decrypt-failed" | "invalid-shape" | "missing-decryptor";

export interface BackupDecryptFailure {
  kind: BackupDecryptFailureKind;
  id?: string;
  index: number;
  reason: BackupDecryptFailureReason;
}

export interface BackupDecryptVerificationCounts {
  entriesChecked: number;
  notesChecked: number;
  entriesFailed: number;
  notesFailed: number;
}

export type BackupDecryptVerificationResult =
  | {
      ok: true;
      counts: BackupDecryptVerificationCounts;
      failures: [];
    }
  | {
      ok: false;
      counts: BackupDecryptVerificationCounts;
      failures: BackupDecryptFailure[];
    };

export interface BackupEntryDecryptInput {
  entry: VaultEntry;
  index: number;
  masterKeyHex?: string;
  keyShares?: KeyShares;
}

export interface BackupSecureNoteDecryptInput {
  note: SecureNote;
  index: number;
  masterKeyHex?: string;
  keyShares?: KeyShares;
}

export interface VerifyStagedBackupDecryptabilityInput {
  stagedBackup: BackupStageResult;
  masterKeyHex?: string;
  keyShares?: KeyShares;
  decryptEntry?: (input: BackupEntryDecryptInput) => unknown | Promise<unknown>;
  decryptSecureNote?: (input: BackupSecureNoteDecryptInput) => unknown | Promise<unknown>;
}

export async function verifyStagedBackupDecryptability(
  input: VerifyStagedBackupDecryptabilityInput,
): Promise<BackupDecryptVerificationResult> {
  const failures: BackupDecryptFailure[] = [];
  const counts: BackupDecryptVerificationCounts = {
    entriesChecked: input.stagedBackup.entries.length,
    notesChecked: input.stagedBackup.secureNotes.length,
    entriesFailed: 0,
    notesFailed: 0,
  };

  for (let index = 0; index < input.stagedBackup.entries.length; index++) {
    const entry = input.stagedBackup.entries[index];
    const failure = await verifyEntry(entry, index, input);
    if (failure) {
      counts.entriesFailed++;
      failures.push(failure);
    }
  }

  for (let index = 0; index < input.stagedBackup.secureNotes.length; index++) {
    const note = input.stagedBackup.secureNotes[index];
    const failure = await verifySecureNote(note, index, input);
    if (failure) {
      counts.notesFailed++;
      failures.push(failure);
    }
  }

  if (failures.length > 0) {
    return { ok: false, counts, failures };
  }

  return { ok: true, counts, failures: [] };
}

async function verifyEntry(
  entry: VaultEntry,
  index: number,
  input: VerifyStagedBackupDecryptabilityInput,
): Promise<BackupDecryptFailure | null> {
  if (!isDecryptableEntryShape(entry)) {
    return { kind: "entry", id: safeId(entry), index, reason: "invalid-shape" };
  }

  if (!input.decryptEntry) {
    return { kind: "entry", id: entry.id, index, reason: "missing-decryptor" };
  }

  try {
    await input.decryptEntry({
      entry,
      index,
      masterKeyHex: input.masterKeyHex,
      keyShares: input.keyShares,
    });
    return null;
  } catch {
    return { kind: "entry", id: entry.id, index, reason: "decrypt-failed" };
  }
}

async function verifySecureNote(
  note: SecureNote,
  index: number,
  input: VerifyStagedBackupDecryptabilityInput,
): Promise<BackupDecryptFailure | null> {
  if (!isDecryptableSecureNoteShape(note)) {
    return { kind: "secure-note", id: safeId(note), index, reason: "invalid-shape" };
  }

  if (!input.decryptSecureNote) {
    return { kind: "secure-note", id: note.id, index, reason: "missing-decryptor" };
  }

  try {
    await input.decryptSecureNote({
      note,
      index,
      masterKeyHex: input.masterKeyHex,
      keyShares: input.keyShares,
    });
    return null;
  } catch {
    return { kind: "secure-note", id: note.id, index, reason: "decrypt-failed" };
  }
}

function isDecryptableEntryShape(entry: VaultEntry): boolean {
  return (
    typeof entry === "object" &&
    entry !== null &&
    typeof entry.id === "string" &&
    entry.id.length > 0 &&
    typeof entry.encryptedPassword === "string" &&
    entry.encryptedPassword.length > 0
  );
}

function isDecryptableSecureNoteShape(note: SecureNote): boolean {
  return (
    typeof note === "object" &&
    note !== null &&
    typeof note.id === "string" &&
    note.id.length > 0 &&
    typeof note.encryptedContent === "string" &&
    note.encryptedContent.length > 0
  );
}

function safeId(value: unknown): string | undefined {
  if (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof value.id === "string" &&
    value.id.length > 0
  ) {
    return value.id;
  }
  return undefined;
}
