import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";
import { VaultEntry } from "./vaultWorker";

const VAULT_KEY_PREFIX = "pipass_vault_";
const VAULT_INDEX_KEY = "pipass_vault_index";
const MASTER_KEY_HASH_KEY = "pipass_master_hash";
const PI_SEED_KEY = "pipass_pi_seed";

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
    if (entry) {
      entries.push(entry);
    }
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

export async function clearVault(): Promise<void> {
  const index = await getVaultIndex();
  for (const id of index) {
    await deleteItem(VAULT_KEY_PREFIX + id);
  }
  await deleteItem(VAULT_INDEX_KEY);
  await deleteItem(MASTER_KEY_HASH_KEY);
}

export async function savePiSeed(seed: number): Promise<void> {
  await setItem(PI_SEED_KEY, seed.toString());
}

export async function getPiSeed(): Promise<number | null> {
  const val = await getItem(PI_SEED_KEY);
  if (val === null) return null;
  const num = parseInt(val, 10);
  return isNaN(num) ? null : num;
}
