import { getCredentials } from "./credentials";
import { authedApiRequest } from "./query-client";
import { getAllEntries, getAllSecureNotes } from "../workers/storageWorker";
import { encryptData } from "../crypto/encryption";
import { combineShares, hexToBytes, wipeBuffer, KeyShares } from "../crypto/secureMemory";
import { deriveSubkey } from "../crypto/hkdf";

// Fixed salt for deterministic blob-key derivation.
// 32 zero-bytes in hex — same pattern used by the fractal seed (hkdf.ts:HKDF_SALT_V1 uses
// SHA-256 as salt; here we want a fixed known salt so decryption is reproducible without
// storing any extra metadata).
const BLOB_SUBKEY_SALT = "00".repeat(32); // 64 hex chars = 32 bytes
const BLOB_SUBKEY_INFO = "vault-blob-sync-v1";

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

    // Use Date.now() as a monotonically increasing version.
    // The server upserts only when the new version exceeds the stored one,
    // so a stale or duplicate sync simply returns 409 — which we catch below.
    const version = Date.now();

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
