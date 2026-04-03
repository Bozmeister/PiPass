import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";

const SHARED_VAULT_KEY = "pipass_shared_vault";

const KEYCHAIN_SERVICE = "group.com.pipass.shared";

export interface SharedVaultBlob {
  encryptedBlob: string;
  version: number;
  updatedAt: number;
}

async function getSharedItem(key: string): Promise<string | null> {
  if (Platform.OS === "web") {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }
  return await SecureStore.getItemAsync(key, {
    keychainService: KEYCHAIN_SERVICE,
  });
}

async function setSharedItem(key: string, value: string): Promise<void> {
  if (Platform.OS === "web") {
    localStorage.setItem(key, value);
    return;
  }
  await SecureStore.setItemAsync(key, value, {
    keychainService: KEYCHAIN_SERVICE,
  });
}

async function deleteSharedItem(key: string): Promise<void> {
  if (Platform.OS === "web") {
    localStorage.removeItem(key);
    return;
  }
  await SecureStore.deleteItemAsync(key, {
    keychainService: KEYCHAIN_SERVICE,
  });
}

export async function saveSharedVaultBlob(blob: SharedVaultBlob): Promise<void> {
  await setSharedItem(SHARED_VAULT_KEY, JSON.stringify(blob));
}

export async function getSharedVaultBlob(): Promise<SharedVaultBlob | null> {
  const raw = await getSharedItem(SHARED_VAULT_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof parsed.encryptedBlob === "string" &&
      typeof parsed.version === "number" &&
      parsed.version === 1 &&
      typeof parsed.updatedAt === "number" &&
      Number.isFinite(parsed.updatedAt) &&
      parsed.updatedAt > 0
    ) {
      return parsed as SharedVaultBlob;
    }
    return null;
  } catch {
    return null;
  }
}

export async function clearSharedVault(): Promise<void> {
  await deleteSharedItem(SHARED_VAULT_KEY);
}
