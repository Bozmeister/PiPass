import * as SecureStore from "expo-secure-store";
import { VaultEntry } from "./vaultWorker";

const VAULT_KEY_PREFIX = "pipass_vault_";
const VAULT_INDEX_KEY = "pipass_vault_index";
const MASTER_KEY_HASH_KEY = "pipass_master_hash";

async function getVaultIndex(): Promise<string[]> {
  const indexStr = await SecureStore.getItemAsync(VAULT_INDEX_KEY);
  if (!indexStr) return [];
  try {
    return JSON.parse(indexStr);
  } catch {
    return [];
  }
}

async function setVaultIndex(ids: string[]): Promise<void> {
  await SecureStore.setItemAsync(VAULT_INDEX_KEY, JSON.stringify(ids));
}

export async function saveEntry(entry: VaultEntry): Promise<void> {
  const entryKey = VAULT_KEY_PREFIX + entry.id;
  await SecureStore.setItemAsync(entryKey, JSON.stringify(entry));

  const index = await getVaultIndex();
  if (!index.includes(entry.id)) {
    index.push(entry.id);
    await setVaultIndex(index);
  }
}

export async function getEntry(id: string): Promise<VaultEntry | null> {
  const entryKey = VAULT_KEY_PREFIX + id;
  const entryStr = await SecureStore.getItemAsync(entryKey);
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
  await SecureStore.deleteItemAsync(entryKey);

  const index = await getVaultIndex();
  const newIndex = index.filter((i) => i !== id);
  await setVaultIndex(newIndex);
}

export async function updateEntry(entry: VaultEntry): Promise<void> {
  const entryKey = VAULT_KEY_PREFIX + entry.id;
  await SecureStore.setItemAsync(entryKey, JSON.stringify(entry));
}

export async function saveMasterKeyHash(hash: string): Promise<void> {
  await SecureStore.setItemAsync(MASTER_KEY_HASH_KEY, hash);
}

export async function getMasterKeyHash(): Promise<string | null> {
  return await SecureStore.getItemAsync(MASTER_KEY_HASH_KEY);
}

export async function clearVault(): Promise<void> {
  const index = await getVaultIndex();
  for (const id of index) {
    await SecureStore.deleteItemAsync(VAULT_KEY_PREFIX + id);
  }
  await SecureStore.deleteItemAsync(VAULT_INDEX_KEY);
  await SecureStore.deleteItemAsync(MASTER_KEY_HASH_KEY);
}
