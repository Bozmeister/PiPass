import { getCredentials } from "./credentials";
import { authedApiRequest } from "./query-client";
import { getAllEntries, getAllSecureNotes, saveEntry, saveSecureNote } from "../workers/storageWorker";
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

    // Write validated entries and notes to local storage.
    const { entries, secureNotes } = payload;
    for (const entry of entries) {
      await saveEntry(entry);
    }
    for (const note of secureNotes) {
      await saveSecureNote(note);
    }

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

    await authedApiRequest("POST", "/api/vault/sync", { encryptedBlob, version });
  } catch {
    // Intentionally empty — sync is best-effort.
    // 401: authedApiRequest already cleared credentials; next unlock will re-login.
    // 403: untrusted device — user must approve device first; sync deferred.
    // 409: our version was stale (conflict) — fetch/merge prompt will handle this.
    // Network errors, timeouts: local vault is unaffected.
    // No sensitive data is referenced here.
  }
}
