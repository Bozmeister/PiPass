import type { VaultEntry, SecureNote } from "./vaultWorker";
import { saveSharedVaultBlob, getSharedVaultBlob, clearSharedVault } from "./sharedVaultStorage";
// Phase 1 IntentDB outbox. Append-only local ciphertext log. It does not
// replace SecureStore vault records or the shared autofill blob.
import {
  clearIntentdbOutbox,
  recordSecureNoteDeleted,
  recordSecureNoteSaved,
  recordVaultEntryDeleted,
  recordVaultEntrySaved,
} from "./intentdbOutbox";
import { clearDeviceUUID } from "../crypto/deviceUUIDStorage";
import {
  isValidKdfMetadata as isValidStoredKdfMetadata,
  type KdfMetadata,
} from "../crypto/kdfMetadata";
import { clearCredentials } from "../lib/credentials";
import { clearInstallId } from "../lib/install-id";
import {
  deletePlatformItem,
  isWebStoragePlatform,
  readPlatformItem,
  writePlatformItem,
} from "../lib/platformStorage";
import { clearChunkedCiphertext } from "../lib/vaultSearchChunks";

const VAULT_KEY_PREFIX = "pipass_vault_";
const VAULT_INDEX_KEY = "pipass_vault_index";
const MASTER_KEY_HASH_KEY = "pipass_master_hash";
const MASTER_SALT_KEY = "pipass_master_salt";
const NOTES_KEY_PREFIX = "pipass_note_";
const NOTES_INDEX_KEY = "pipass_notes_index";
const SECURITY_PROFILE_KEY = "pipass_security_profile";
const KDF_METADATA_KEY = "pipass_kdf_metadata";
const SHOW_KEYPRINTS_KEY = "pipass_show_keyprints";
const VAULT_INITIALIZED_KEY = "pipass_vault_initialized";
const FRACTAL_FINGERPRINT_KEY = "pipass_fractal_fingerprint";
const RECOVERY_KEY_HASH_KEY = "pipass_recovery_key_hash";
const MIGRATION_DONE_KEY = "pipass_shared_migration_done";

export {
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  isValidKdfMetadata,
  KDF_DEVICE_BINDING_NONE,
  KDF_DEVICE_BINDING_UUID_V1,
  type Argon2idKdfMetadata,
  type Argon2idKdfParameters,
  type KdfDeviceBinding,
  type KdfMetadata,
  type KdfMetadataAlgorithm,
  type KdfMetadataSource,
  type Pbkdf2KdfMetadata,
  type Pbkdf2KdfParameters,
} from "../crypto/kdfMetadata";

async function getItem(key: string): Promise<string | null> {
  return await readPlatformItem(key);
}

async function setItem(key: string, value: string): Promise<void> {
  await writePlatformItem(key, value);
}

async function deleteItem(key: string): Promise<void> {
  await deletePlatformItem(key);
}

export async function getKdfMetadata(): Promise<KdfMetadata | null> {
  const raw = await getItem(KDF_METADATA_KEY);
  if (raw === null) return null;

  try {
    const parsed = JSON.parse(raw);
    return isValidStoredKdfMetadata(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export type KdfMetadataState =
  | { status: "valid"; metadata: KdfMetadata }
  | { status: "missing"; metadata: null }
  | { status: "invalid"; metadata: null };

export async function getKdfMetadataState(): Promise<KdfMetadataState> {
  const raw = await getItem(KDF_METADATA_KEY);
  if (raw === null) return { status: "missing", metadata: null };

  try {
    const parsed = JSON.parse(raw);
    if (isValidStoredKdfMetadata(parsed)) {
      return { status: "valid", metadata: parsed };
    }
  } catch {}

  return { status: "invalid", metadata: null };
}

export async function saveKdfMetadata(metadata: KdfMetadata): Promise<void> {
  if (!isValidStoredKdfMetadata(metadata)) {
    throw new Error("Invalid KDF metadata");
  }

  await setItem(KDF_METADATA_KEY, JSON.stringify(metadata));
}

export async function clearKdfMetadata(): Promise<void> {
  await deleteItem(KDF_METADATA_KEY);
}

async function getVaultIndex(): Promise<string[]> {
  const indexStr = await getItem(VAULT_INDEX_KEY);
  if (!indexStr) return [];
  try {
    return JSON.parse(indexStr);
  } catch {
    return [];
  }
}

async function setVaultIndex(ids: string[]): Promise<void> {
  await setItem(VAULT_INDEX_KEY, JSON.stringify(ids));
}

async function syncSharedVaultBlob(): Promise<void> {
  const entries = await getAllEntries();
  await saveSharedVaultBlob({
    encryptedBlob: JSON.stringify(entries),
    version: 1,
    updatedAt: Date.now(),
  });
}

export async function migrateToSharedStorage(): Promise<void> {
  const migrated = await getItem(MIGRATION_DONE_KEY);
  if (migrated === "1") return;

  const entries = await getAllEntries();
  if (entries.length > 0) {
    const existing = await getSharedVaultBlob();
    const now = Date.now();
    if (!existing || existing.updatedAt < now) {
      await saveSharedVaultBlob({
        encryptedBlob: JSON.stringify(entries),
        version: 1,
        updatedAt: now,
      });
    }
  }

  await setItem(MIGRATION_DONE_KEY, "1");
}

export async function saveEntry(entry: VaultEntry): Promise<void> {
  const entryKey = VAULT_KEY_PREFIX + entry.id;
  await setItem(entryKey, JSON.stringify(entry));

  const index = await getVaultIndex();
  if (!index.includes(entry.id)) {
    index.push(entry.id);
    await setVaultIndex(index);
  }
  await syncSharedVaultBlob();
  // Phase 1: stage a ciphertext manifest after the local save commits.
  // Refused (non-v4) records are skipped. The shared autofill blob above
  // is unchanged by the outbox.
  await recordVaultEntrySaved(entry);
}

export async function getEntry(id: string): Promise<VaultEntry | null> {
  const entryKey = VAULT_KEY_PREFIX + id;
  const entryStr = await getItem(entryKey);
  if (!entryStr) return null;
  try {
    return JSON.parse(entryStr);
  } catch {
    return null;
  }
}

export async function getAllEntries(): Promise<VaultEntry[]> {
  const index = await getVaultIndex();
  const entries: VaultEntry[] = [];
  for (const id of index) {
    const entry = await getEntry(id);
    if (entry) entries.push(entry);
  }
  return entries;
}

export async function deleteEntry(id: string): Promise<void> {
  const existing = await getEntry(id);
  const entryKey = VAULT_KEY_PREFIX + id;
  await deleteItem(entryKey);
  const index = await getVaultIndex();
  const newIndex = index.filter((i) => i !== id);
  await setVaultIndex(newIndex);
  await syncSharedVaultBlob();
  // Phase 1: tombstone after the local delete commits. Hash is taken from
  // the pre-delete record when that record is authenticated v4.
  await recordVaultEntryDeleted(id, existing);
}

export async function updateEntry(entry: VaultEntry): Promise<void> {
  const entryKey = VAULT_KEY_PREFIX + entry.id;
  await setItem(entryKey, JSON.stringify(entry));
  await syncSharedVaultBlob();
}

export async function saveMasterKeyHash(hash: string): Promise<void> {
  await setItem(MASTER_KEY_HASH_KEY, hash);
}

export async function getMasterKeyHash(): Promise<string | null> {
  return await getItem(MASTER_KEY_HASH_KEY);
}

export async function saveMasterSalt(salt: string): Promise<void> {
  await setItem(MASTER_SALT_KEY, salt);
}

export async function getMasterSalt(): Promise<string | null> {
  return await getItem(MASTER_SALT_KEY);
}

export async function setVaultInitialized(initialized: boolean): Promise<void> {
  await setItem(VAULT_INITIALIZED_KEY, initialized ? "1" : "0");
}

export async function isVaultInitialized(): Promise<boolean> {
  const val = await getItem(VAULT_INITIALIZED_KEY);
  return val === "1";
}

export async function clearVault(): Promise<void> {
  const index = await getVaultIndex();
  for (const id of index) {
    await deleteItem(VAULT_KEY_PREFIX + id);
  }
  await deleteItem(VAULT_INDEX_KEY);
  await deleteItem(MASTER_KEY_HASH_KEY);
  await clearSharedVault();
  await clearChunkedCiphertext();
}

/** Legacy key only: recovery-key feature removed. Kept for destroy/wipe of old installs. */
export async function getRecoveryKeyHash(): Promise<string | null> {
  return await getItem(RECOVERY_KEY_HASH_KEY);
}

export async function destroyAllData(): Promise<void> {
  await clearVault();
  await clearAllNotes();
  await deleteItem(MASTER_SALT_KEY);
  await deleteItem(SECURITY_PROFILE_KEY);
  await clearKdfMetadata();
  await deleteItem(SHOW_KEYPRINTS_KEY);
  await deleteItem(VAULT_INITIALIZED_KEY);
  await deleteItem(FRACTAL_FINGERPRINT_KEY);
  await deleteItem(RECOVERY_KEY_HASH_KEY);
  await deleteItem(MIGRATION_DONE_KEY);
  await clearMasterKeySecurely();
  // Phase 1 IntentDB outbox holds a second copy of ciphertext manifests.
  // Nuclear reset removes it. Lock and logout do not.
  await clearIntentdbOutbox();
  // Nuclear reset is the "fresh install" boundary for local state. Ordinary
  // lock/logout/password-rotation flows must not clear these identifiers.
  await clearCredentials();
  await clearInstallId();
  await clearDeviceUUID();
}

async function getNotesIndex(): Promise<string[]> {
  const indexStr = await getItem(NOTES_INDEX_KEY);
  if (!indexStr) return [];
  try {
    return JSON.parse(indexStr);
  } catch {
    return [];
  }
}

async function setNotesIndex(ids: string[]): Promise<void> {
  await setItem(NOTES_INDEX_KEY, JSON.stringify(ids));
}

export async function hasLocalEncryptedVaultData(): Promise<boolean> {
  const entryIds = await getVaultIndex();
  if (entryIds.length > 0) return true;

  const noteIds = await getNotesIndex();
  return noteIds.length > 0;
}

export async function saveSecureNote(note: SecureNote): Promise<void> {
  // Never persist plaintext label — storage confidentiality for note titles.
  const stored: SecureNote = {
    id: note.id,
    encryptedLabel: note.encryptedLabel,
    encryptedContent: note.encryptedContent,
    salt: note.salt,
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
  };
  await setItem(NOTES_KEY_PREFIX + note.id, JSON.stringify(stored));
  const index = await getNotesIndex();
  if (!index.includes(note.id)) {
    index.push(note.id);
    await setNotesIndex(index);
  }
  // Phase 1: stage the stripped ciphertext note. Legacy plaintext labels
  // are not written to the note row or the outbox.
  await recordSecureNoteSaved(stored);
}

export async function getSecureNote(id: string): Promise<SecureNote | null> {
  const str = await getItem(NOTES_KEY_PREFIX + id);
  if (!str) return null;
  try {
    const parsed = JSON.parse(str) as SecureNote;
    // Surface whatever is on disk (including legacy plaintext label) so
    // decrypt/migration paths can handle it; do not strip on read without
    // re-save so we do not discard the only label copy if encryptedLabel is bad.
    return parsed;
  } catch {
    return null;
  }
}

export async function getAllSecureNotes(): Promise<SecureNote[]> {
  const index = await getNotesIndex();
  const notes: SecureNote[] = [];
  for (const id of index) {
    const note = await getSecureNote(id);
    if (note) notes.push(note);
  }
  return notes;
}

export async function deleteSecureNote(id: string): Promise<void> {
  const existing = await getSecureNote(id);
  await deleteItem(NOTES_KEY_PREFIX + id);
  const index = await getNotesIndex();
  await setNotesIndex(index.filter((i) => i !== id));
  await recordSecureNoteDeleted(id, existing);
}

export async function clearAllNotes(): Promise<void> {
  const index = await getNotesIndex();
  for (const id of index) {
    await deleteItem(NOTES_KEY_PREFIX + id);
  }
  await deleteItem(NOTES_INDEX_KEY);
}

export async function saveSecurityProfile(iterations: number): Promise<void> {
  await setItem(SECURITY_PROFILE_KEY, iterations.toString());
}

export async function getSecurityProfile(): Promise<number> {
  const val = await getItem(SECURITY_PROFILE_KEY);
  if (val === null) return 100000;
  const num = parseInt(val, 10);
  return isNaN(num) || num <= 0 ? 100000 : num;
}

export async function saveShowKeyprints(show: boolean): Promise<void> {
  await setItem(SHOW_KEYPRINTS_KEY, show ? "1" : "0");
}

export async function getShowKeyprints(): Promise<boolean> {
  const val = await getItem(SHOW_KEYPRINTS_KEY);
  return val !== "0";
}

export interface FractalFingerprintRecord {
  fingerprint: string;
  iterations: number;
  /** Algorithm used when the fingerprint was bound (informational metadata only). */
  kdf: "argon2id" | "pbkdf2-sha256";
  version: 1;
}

export async function saveFractalFingerprint(record: FractalFingerprintRecord): Promise<void> {
  await setItem(FRACTAL_FINGERPRINT_KEY, JSON.stringify(record));
}

export async function getFractalFingerprint(): Promise<FractalFingerprintRecord | string | null> {
  const raw = await getItem(FRACTAL_FINGERPRINT_KEY);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && typeof parsed.fingerprint === "string") {
      return parsed as FractalFingerprintRecord;
    }
  } catch {}
  return raw;
}

const KEYCHAIN_KEY = "pipass_master_key";
const KEYCHAIN_SERVICE = "group.com.pipass.shared";

let cachedBiometricAvailable: boolean | null = null;

async function isAuthenticatedKeyStorageAvailable(): Promise<boolean> {
  if (await isWebStoragePlatform()) return false;
  if (cachedBiometricAvailable !== null) return cachedBiometricAvailable;
  try {
    const LocalAuthentication = await import("expo-local-authentication");
    const Device = await import("expo-device");
    const enrolledLevel = await LocalAuthentication.getEnrolledLevelAsync();
    cachedBiometricAvailable =
      Device.isDevice &&
      enrolledLevel >= LocalAuthentication.SecurityLevel.SECRET;
  } catch (err) {
    if (__DEV__) console.warn("[storageWorker] biometric probe failed:", err);
    cachedBiometricAvailable = false;
  }
  return cachedBiometricAvailable;
}

export async function storeMasterKeySecurely(keyHex: string): Promise<void> {
  if (await isWebStoragePlatform()) return;

  const useAuthentication = await isAuthenticatedKeyStorageAvailable();
  if (!useAuthentication) {
    // The cached master key is an unlock accelerator, not required vault
    // state. In production we fail closed by refusing to persist it unless
    // the platform can protect it with device authentication.
    await clearMasterKeySecurely();
    if (__DEV__) {
      console.warn(
        "[storageWorker] biometric auth unavailable - master key cache disabled (production will never store without strong auth)"
      );
    }
    return;
  }

  try {
    await writePlatformItem(KEYCHAIN_KEY, keyHex, {
      keychainService: KEYCHAIN_SERVICE,
      requireAuthentication: true,
    });
  } catch (err) {
    if (__DEV__) {
      console.warn(
        "[storageWorker] storeMasterKeySecurely with requireAuthentication=true failed:",
        err
      );
    }
    await clearMasterKeySecurely();
    // No fallback store in any environment. Production must never persist
    // the master key cache without biometric/device auth protection.
  }
}

export async function getMasterKeySecurely(): Promise<string | null> {
  if (await isWebStoragePlatform()) return null;

  const useAuthentication = await isAuthenticatedKeyStorageAvailable();
  if (!useAuthentication) {
    if (!__DEV__) return null;
    try {
      return await readPlatformItem(KEYCHAIN_KEY, {
        keychainService: KEYCHAIN_SERVICE,
        requireAuthentication: false,
      });
    } catch {
      return null;
    }
  }

  try {
    return await readPlatformItem(KEYCHAIN_KEY, {
      keychainService: KEYCHAIN_SERVICE,
      requireAuthentication: true,
    });
  } catch (err) {
    if (__DEV__) {
      console.warn(
        "[storageWorker] getMasterKeySecurely failed (will fall back to master password):",
        err
      );
    }
    return null;
  }
}

export async function clearMasterKeySecurely(): Promise<void> {
  if (await isWebStoragePlatform()) return;
  try {
    await deletePlatformItem(KEYCHAIN_KEY, {
      keychainService: KEYCHAIN_SERVICE,
    });
  } catch (err) {
    if (__DEV__) console.warn("[storageWorker] clearMasterKeySecurely failed:", err);
  }
}
