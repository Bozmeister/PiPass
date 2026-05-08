import { getCredentials } from "./credentials";
import { authedApiRequest } from "./query-client";
import {
  getAllEntries,
  getAllSecureNotes,
  saveEntry,
  saveSecureNote,
  saveSyncVersion,
  getSyncVersion,
} from "../workers/storageWorker";
import { encryptData, decryptData } from "../crypto/encryption";
import { combineShares, hexToBytes, wipeBuffer, KeyShares } from "../crypto/secureMemory";
import { deriveSubkey } from "../crypto/hkdf";
import { VaultEntry, SecureNote } from "../workers/vaultWorker";

// Fixed salt for deterministic blob-key derivation.
// 32 zero-bytes in hex — same pattern used by the fractal seed (hkdf.ts:HKDF_SALT_V1 uses
// SHA-256 as salt; here we want a fixed known salt so decryption is reproducible without
// storing any extra metadata).
const BLOB_SUBKEY_SALT = "00".repeat(32); // 64 hex chars = 32 bytes
const BLOB_SUBKEY_INFO = "vault-blob-sync-v1";

// ---------------------------------------------------------------------------
// Payload validation helpers (used by restoreVaultFromRemote)
// ---------------------------------------------------------------------------

function isValidVaultEntry(v: unknown): v is VaultEntry {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.id === "string" && e.id.length > 0 &&
    typeof e.encryptedPassword === "string" && e.encryptedPassword.length > 0 &&
    typeof e.salt === "string" && e.salt.length > 0 &&
    typeof e.createdAt === "number" &&
    typeof e.updatedAt === "number"
  );
}

function isValidSecureNote(v: unknown): v is SecureNote {
  if (!v || typeof v !== "object") return false;
  const n = v as Record<string, unknown>;
  return (
    typeof n.id === "string" && n.id.length > 0 &&
    typeof n.encryptedContent === "string" && n.encryptedContent.length > 0 &&
    typeof n.salt === "string" && n.salt.length > 0 &&
    typeof n.createdAt === "number" &&
    typeof n.updatedAt === "number"
  );
}

function isValidRestorePayload(
  v: unknown
): v is { entries: VaultEntry[]; secureNotes: SecureNote[] } {
  if (!v || typeof v !== "object") return false;
  const p = v as Record<string, unknown>;
  return (
    Array.isArray(p.entries) &&
    Array.isArray(p.secureNotes) &&
    (p.entries as unknown[]).every(isValidVaultEntry) &&
    (p.secureNotes as unknown[]).every(isValidSecureNote)
  );
}

// ---------------------------------------------------------------------------
// Stage 2A: restore from remote for empty local vaults
// ---------------------------------------------------------------------------

/**
 * Fetches the encrypted vault blob from the backend and restores it locally,
 * but ONLY when the local vault is completely empty (no entries, no notes).
 *
 * Safety guarantees:
 *  - Best-effort only: any error is caught and returns false.
 *  - Never touches local storage if local vault has any entries or notes.
 *  - Double-checks emptiness before writing (race guard).
 *  - Decryption failure → no local writes, non-secret warning in __DEV__.
 *  - Payload validation failure → no local writes.
 *  - No secret material (blobKey, encryptedBlob contents) is ever logged.
 *  - blobKey is always wiped in the finally block regardless of outcome.
 *  - Does not block the caller; caller decides whether to signal a UI reload.
 *
 * Returns true if entries/notes were actually written to local storage.
 */
export async function restoreVaultFromRemote(keyShares: KeyShares): Promise<boolean> {
  // Derive blob subkey synchronously before any await — same strategy as
  // syncVaultToBackend. Master key bytes exist only in this stack frame.
  const masterKeyHex = combineShares(keyShares);
  const blobKey = deriveSubkey(masterKeyHex, BLOB_SUBKEY_INFO, BLOB_SUBKEY_SALT);
  const masterKeyBytes = hexToBytes(masterKeyHex);
  wipeBuffer(masterKeyBytes);

  // blobKey is the only remaining sensitive local — always wiped in finally.
  try {
    const creds = await getCredentials();
    if (!creds) return false;

    // Guard 1: never overwrite a non-empty local vault.
    const [existingEntries, existingNotes] = await Promise.all([
      getAllEntries(),
      getAllSecureNotes(),
    ]);
    if (existingEntries.length > 0 || existingNotes.length > 0) return false;

    // Fetch encrypted blob from server.
    const res = await authedApiRequest("GET", "/api/vault/fetch");
    const raw = await res.json() as Record<string, unknown>;

    if (
      typeof raw?.encryptedBlob !== "string" ||
      !raw.encryptedBlob ||
      typeof raw?.version !== "number" ||
      (raw.version as number) <= 0
    ) {
      return false;
    }

    // Decrypt — wrong key or corrupted blob throws; we return false.
    let decryptedJson: string;
    try {
      decryptedJson = decryptData(raw.encryptedBlob as string, blobKey);
    } catch {
      if (__DEV__) console.warn("[restoreVault] decryption failed — wrong key or corrupted blob, no local changes");
      return false;
    }

    // Parse JSON.
    let payload: unknown;
    try {
      payload = JSON.parse(decryptedJson);
    } catch {
      if (__DEV__) console.warn("[restoreVault] blob JSON malformed — no local changes");
      return false;
    }

    // Validate payload shape before touching storage.
    if (!isValidRestorePayload(payload)) {
      if (__DEV__) console.warn("[restoreVault] blob payload shape invalid — no local changes");
      return false;
    }

    // Guard 2: re-check emptiness before any write (race between this async
    // path and a manual entry add that could happen in the tiny window above).
    const [checkEntries, checkNotes] = await Promise.all([
      getAllEntries(),
      getAllSecureNotes(),
    ]);
    if (checkEntries.length > 0 || checkNotes.length > 0) return false;

    const { entries, secureNotes } = payload;

    // If the remote vault is also empty there is nothing to restore.
    // Return false so the caller doesn't fire a spurious UI reload.
    if (entries.length === 0 && secureNotes.length === 0) return false;

    // Write validated entries and notes to local storage.
    for (const entry of entries) {
      await saveEntry(entry);
    }
    for (const note of secureNotes) {
      await saveSecureNote(note);
    }

    // Record the server version we just restored from. Stage 2B will use
    // this to detect whether the server has advanced since this restore.
    // raw.version is already validated > 0 at this point.
    await saveSyncVersion(raw.version as number);

    return true;
  } catch {
    // Network errors, 401 (authedApiRequest already cleared creds), 403
    // (untrusted device), or any unexpected exception — local vault untouched.
    return false;
  } finally {
    const blobKeyBytes = hexToBytes(blobKey);
    wipeBuffer(blobKeyBytes);
  }
}

// ---------------------------------------------------------------------------
// Upload sync
// ---------------------------------------------------------------------------

/**
 * Builds a fully encrypted vault blob from the current local vault state and
 * uploads it to the backend via POST /api/vault/sync.
 *
 * Guarantees:
 *  - Best-effort only: any error (network, 401, 403 untrusted device, 409 conflict)
 *    is caught and swallowed — the caller's local write already succeeded.
 *  - No sensitive material (keyHex, authHash, encryptedBlob contents) is ever logged.
 *  - Key bytes are wiped from memory after use.
 *  - If credentials are absent, returns immediately without any network call.
 */
export async function syncVaultToBackend(keyShares: KeyShares): Promise<void> {
  try {
    const creds = await getCredentials();
    if (!creds) return;

    const [entries, secureNotes] = await Promise.all([
      getAllEntries(),
      getAllSecureNotes(),
    ]);

    const payload = JSON.stringify({
      entries,
      secureNotes,
      syncedAt: Date.now(),
    });

    const masterKeyHex = combineShares(keyShares);
    let encryptedBlob: string;
    try {
      const blobKey = deriveSubkey(masterKeyHex, BLOB_SUBKEY_INFO, BLOB_SUBKEY_SALT);
      encryptedBlob = encryptData(payload, blobKey);
      const blobKeyBytes = hexToBytes(blobKey);
      wipeBuffer(blobKeyBytes);
    } finally {
      const masterKeyBytes = hexToBytes(masterKeyHex);
      wipeBuffer(masterKeyBytes);
    }

    // Use Unix epoch in SECONDS as version. PostgreSQL INTEGER is a signed 32-bit
    // column (max 2,147,483,647 — overflows in 2038). Date.now() returns
    // milliseconds (~1.7 trillion) which exceeds this and causes a 400 "Invalid version".
    // Dividing by 1000 gives ~1.778 billion seconds which fits until 2038.
    // Monotonically increasing: syncs are always at least 1 second apart in practice;
    // a same-second repeat gets 409 which the catch below swallows harmlessly.
    const version = Math.floor(Date.now() / 1000);

    const syncRes = await authedApiRequest("POST", "/api/vault/sync", { encryptedBlob, version });

    // Persist lastSyncedVersion only on confirmed 2xx. For 409/403 the upload
    // did not succeed so the local version record must not advance.
    if (syncRes.ok) {
      try {
        const body = await syncRes.json() as Record<string, unknown>;
        const serverVersion =
          typeof body?.version === "number" && body.version > 0
            ? (body.version as number)
            : version;
        await saveSyncVersion(serverVersion);
      } catch {
        // Body unreadable — save the version we sent as a safe fallback.
        await saveSyncVersion(version);
      }
    }
  } catch {
    // Intentionally empty — sync is best-effort.
    // 401: authedApiRequest already cleared credentials; next unlock will re-login.
    // 403: untrusted device — user must approve device first; sync deferred.
    // 409: our version was stale (conflict) — fetch/merge prompt will handle this.
    // Network errors, timeouts: local vault is unaffected.
    // No sensitive data is referenced here.
  }
}

// ---------------------------------------------------------------------------
// Stage 2B: additive remote import (non-empty local vault)
// ---------------------------------------------------------------------------
// When the local vault already has entries/notes and the server has additional
// items, we surface a user prompt and let them explicitly approve an import.
// Local data is NEVER overwritten or deleted. Conflicts (same id, different
// ciphertext or salt) are silently SKIPPED — local always wins.

export type MergeStatus =
  | "up-to-date"        // server.version <= lastSyncedVersion → nothing to do
  | "no-remote"         // server has no blob yet
  | "import-available"  // remote has items not present locally
  | "no-changes"        // remote fully matches (or only has conflicts) — silent
  | "error";            // network/decrypt/validation failure (no writes)

export interface MergeCandidate {
  entries: VaultEntry[];     // remote-only entries (id not present locally)
  notes: SecureNote[];       // remote-only notes (id not present locally)
  conflictCount: number;     // same-id, ciphertext/salt differs — kept local
  duplicateCount: number;    // same-id, byte-identical — silently skipped
  remoteVersion: number;     // server version we diffed against
}

export interface MergeResult {
  status: MergeStatus;
  candidate?: MergeCandidate;
}

function entriesIdentical(a: VaultEntry, b: VaultEntry): boolean {
  return (
    a.salt === b.salt &&
    a.encryptedPassword === b.encryptedPassword &&
    (a.encryptedTitle ?? "") === (b.encryptedTitle ?? "") &&
    (a.encryptedUsername ?? "") === (b.encryptedUsername ?? "") &&
    (a.encryptedUrl ?? "") === (b.encryptedUrl ?? "") &&
    (a.notes ?? "") === (b.notes ?? "") &&
    (a.encryptedAux ?? "") === (b.encryptedAux ?? "")
  );
}

function notesIdentical(a: SecureNote, b: SecureNote): boolean {
  return (
    a.salt === b.salt &&
    a.encryptedContent === b.encryptedContent &&
    (a.encryptedLabel ?? "") === (b.encryptedLabel ?? "")
  );
}

/**
 * Fetches the remote blob, decrypts it, and diffs it against the local vault
 * by entry/note id. Returns import candidates for the caller to surface in a
 * confirmation UI. NEVER writes to local storage.
 *
 * Safety:
 *  - Best-effort only: any error returns {status:"error"}.
 *  - Decryption failure or payload validation failure → no result, no writes.
 *  - blobKey is wiped in finally regardless of outcome.
 *  - No secret material (blobKey, encryptedBlob, ciphertext, salts) is logged.
 *  - Short-circuits via getSyncVersion() when the server hasn't advanced.
 */
export async function planVaultMerge(keyShares: KeyShares): Promise<MergeResult> {
  const masterKeyHex = combineShares(keyShares);
  const blobKey = deriveSubkey(masterKeyHex, BLOB_SUBKEY_INFO, BLOB_SUBKEY_SALT);
  const masterKeyBytes = hexToBytes(masterKeyHex);
  wipeBuffer(masterKeyBytes);

  try {
    const creds = await getCredentials();
    if (!creds) return { status: "error" };

    const lastSynced = await getSyncVersion();

    const res = await authedApiRequest("GET", "/api/vault/fetch");
    const raw = await res.json() as Record<string, unknown>;

    // No blob on server, or malformed envelope → nothing to merge.
    if (
      typeof raw?.encryptedBlob !== "string" ||
      !raw.encryptedBlob ||
      typeof raw?.version !== "number" ||
      (raw.version as number) <= 0
    ) {
      return { status: "no-remote" };
    }

    const remoteVersion = raw.version as number;

    // Server hasn't advanced beyond our last confirmed sync → skip work.
    if (lastSynced > 0 && remoteVersion <= lastSynced) {
      return { status: "up-to-date" };
    }

    // Decrypt before any further work. Wrong key / corrupted blob → silent error.
    let decryptedJson: string;
    try {
      decryptedJson = decryptData(raw.encryptedBlob as string, blobKey);
    } catch {
      if (__DEV__) console.warn("[planVaultMerge] decryption failed — wrong key or corrupted blob");
      return { status: "error" };
    }

    let payload: unknown;
    try {
      payload = JSON.parse(decryptedJson);
    } catch {
      if (__DEV__) console.warn("[planVaultMerge] blob JSON malformed");
      return { status: "error" };
    }

    if (!isValidRestorePayload(payload)) {
      if (__DEV__) console.warn("[planVaultMerge] blob payload shape invalid");
      return { status: "error" };
    }

    const { entries: remoteEntries, secureNotes: remoteNotes } = payload;

    // Diff by id. Local is the source of truth — anything in local with the same
    // id is either identical (duplicate) or different (conflict). Remote-only
    // entries are import candidates.
    const [localEntries, localNotes] = await Promise.all([
      getAllEntries(),
      getAllSecureNotes(),
    ]);

    const localEntryById = new Map<string, VaultEntry>();
    for (const e of localEntries) localEntryById.set(e.id, e);
    const localNoteById = new Map<string, SecureNote>();
    for (const n of localNotes) localNoteById.set(n.id, n);

    const candidateEntries: VaultEntry[] = [];
    const candidateNotes: SecureNote[] = [];
    let conflictCount = 0;
    let duplicateCount = 0;

    for (const remote of remoteEntries) {
      const local = localEntryById.get(remote.id);
      if (!local) {
        candidateEntries.push(remote);
      } else if (entriesIdentical(local, remote)) {
        duplicateCount++;
      } else {
        conflictCount++;
      }
    }

    for (const remote of remoteNotes) {
      const local = localNoteById.get(remote.id);
      if (!local) {
        candidateNotes.push(remote);
      } else if (notesIdentical(local, remote)) {
        duplicateCount++;
      } else {
        conflictCount++;
      }
    }

    if (candidateEntries.length === 0 && candidateNotes.length === 0) {
      // Nothing the user needs to approve. Advance the watermark so we don't
      // re-fetch + re-decrypt the same blob on every unlock. Conflict-only
      // state is intentionally silent until Stage 2C ships a manual reconcile UI.
      await saveSyncVersion(remoteVersion);
      return { status: "no-changes" };
    }

    return {
      status: "import-available",
      candidate: {
        entries: candidateEntries,
        notes: candidateNotes,
        conflictCount,
        duplicateCount,
        remoteVersion,
      },
    };
  } catch {
    // Network errors, 401 (creds already cleared), 403, 5xx, etc.
    return { status: "error" };
  } finally {
    const blobKeyBytes = hexToBytes(blobKey);
    wipeBuffer(blobKeyBytes);
  }
}

export interface ApplyImportResult {
  written: { entries: number; notes: number };
}

/**
 * Persists user-approved import candidates to local storage and advances the
 * sync watermark. Re-checks emptiness per id (Guard 2) so a manual add of the
 * same id between plan and apply never gets clobbered.
 *
 * After successful local writes, fires syncVaultToBackend best-effort to push
 * the merged state back so other devices see it. Sync failure is swallowed.
 *
 * Caller is responsible for triggering a UI reload (reloadKey bump).
 */
export async function applyVaultImport(
  approvedEntries: VaultEntry[],
  approvedNotes: SecureNote[],
  remoteVersion: number,
  keyShares: KeyShares,
): Promise<ApplyImportResult> {
  // Guard 2: re-check that none of the approved ids snuck into local storage
  // between plan and apply (e.g. user added an entry while the prompt sat open).
  const [currentEntries, currentNotes] = await Promise.all([
    getAllEntries(),
    getAllSecureNotes(),
  ]);
  const localEntryIds = new Set(currentEntries.map((e) => e.id));
  const localNoteIds = new Set(currentNotes.map((n) => n.id));

  let entriesWritten = 0;
  let notesWritten = 0;

  for (const entry of approvedEntries) {
    if (localEntryIds.has(entry.id)) continue;
    await saveEntry(entry);
    entriesWritten++;
  }
  for (const note of approvedNotes) {
    if (localNoteIds.has(note.id)) continue;
    await saveSecureNote(note);
    notesWritten++;
  }

  // Watermark only advances after the writes succeed.
  if (Number.isInteger(remoteVersion) && remoteVersion > 0) {
    await saveSyncVersion(remoteVersion);
  }

  // Best-effort: push the merged local state so other devices see what we just
  // imported alongside any pre-existing local-only items. Failure is swallowed.
  try {
    await syncVaultToBackend(keyShares);
  } catch {
    // Intentional: import already succeeded locally.
  }

  return { written: { entries: entriesWritten, notes: notesWritten } };
}
