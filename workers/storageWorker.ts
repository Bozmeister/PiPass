import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";
import { VaultEntry, SecureNote } from "./vaultWorker";

const VAULT_KEY_PREFIX = "pipass_vault_";
const VAULT_INDEX_KEY = "pipass_vault_index";
const MASTER_KEY_HASH_KEY = "pipass_master_hash";
const MASTER_SALT_KEY = "pipass_master_salt";
const NOTES_KEY_PREFIX = "pipass_note_";
const NOTES_INDEX_KEY = "pipass_notes_index";
const SECURITY_PROFILE_KEY = "pipass_security_profile";
const SHOW_KEYPRINTS_KEY = "pipass_show_keyprints";
const VAULT_INITIALIZED_KEY = "pipass_vault_initialized";
const FRACTAL_FINGERPRINT_KEY = "pipass_fractal_fingerprint";
const RECOVERY_KEY_HASH_KEY = "pipass_recovery_key_hash";

async function getItem(key: string): Promise<string | null> {
  if (Platform.OS === "web") {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }
  return await SecureStore.getItemAsync(key);
}

async function setItem(key: string, value: string): Promise<void> {
  if (Platform.OS === "web") {
    localStorage.setItem(key, value);
    return;
  }
  await SecureStore.setItemAsync(key, value);
}

async function deleteItem(key: string): Promise<void> {
  if (Platform.OS === "web") {
    localStorage.removeItem(key);
    return;
  }
  await SecureStore.deleteItemAsync(key);
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

export async function saveEntry(entry: VaultEntry): Promise<void> {
  const entryKey = VAULT_KEY_PREFIX + entry.id;
  await setItem(entryKey, JSON.stringify(entry));

  const index = await getVaultIndex();
  if (!index.includes(entry.id)) {
    index.push(entry.id);
    await setVaultIndex(index);
  }
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
  const entryKey = VAULT_KEY_PREFIX + id;
  await deleteItem(entryKey);
  const index = await getVaultIndex();
  const newIndex = index.filter((i) => i !== id);
  await setVaultIndex(newIndex);
}

export async function updateEntry(entry: VaultEntry): Promise<void> {
  const entryKey = VAULT_KEY_PREFIX + entry.id;
  await setItem(entryKey, JSON.stringify(entry));
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
}

export async function saveRecoveryKeyHash(hash: string): Promise<void> {
  await setItem(RECOVERY_KEY_HASH_KEY, hash);
}

export async function getRecoveryKeyHash(): Promise<string | null> {
  return await getItem(RECOVERY_KEY_HASH_KEY);
}

export async function destroyAllData(): Promise<void> {
  try {
    await clearVault();
    await clearAllNotes();
    await deleteItem(MASTER_SALT_KEY);
    await deleteItem(SECURITY_PROFILE_KEY);
    await deleteItem(SHOW_KEYPRINTS_KEY);
    await deleteItem(VAULT_INITIALIZED_KEY);
    await deleteItem(FRACTAL_FINGERPRINT_KEY);
    await deleteItem(RECOVERY_KEY_HASH_KEY);
  } catch (err) {
    console.error("Purge failed", err);
  }
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

export async function saveSecureNote(note: SecureNote): Promise<void> {
  await setItem(NOTES_KEY_PREFIX + note.id, JSON.stringify(note));
  const index = await getNotesIndex();
  if (!index.includes(note.id)) {
    index.push(note.id);
    await setNotesIndex(index);
  }
}

export async function getSecureNote(id: string): Promise<SecureNote | null> {
  const str = await getItem(NOTES_KEY_PREFIX + id);
  if (!str) return null;
  try {
    return JSON.parse(str);
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
  await deleteItem(NOTES_KEY_PREFIX + id);
  const index = await getNotesIndex();
  await setNotesIndex(index.filter((i) => i !== id));
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
  kdf: "argon2id";
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
