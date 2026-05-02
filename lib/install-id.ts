import { Platform } from "react-native";
import * as ExpoCrypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";

const INSTALL_ID_KEY = "pipass.installId";
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function readItem(key: string): Promise<string | null> {
  try {
    if (Platform.OS === "web") {
      return localStorage.getItem(key);
    }
    return await SecureStore.getItemAsync(key);
  } catch {
    return null;
  }
}

async function writeItem(key: string, value: string): Promise<void> {
  try {
    if (Platform.OS === "web") {
      localStorage.setItem(key, value);
      return;
    }
    await SecureStore.setItemAsync(key, value);
  } catch {
    // installId is a non-secret label. Storage failure must never block auth,
    // crypto, vault access, or any protected request.
  }
}

async function deleteItem(key: string): Promise<void> {
  try {
    if (Platform.OS === "web") {
      localStorage.removeItem(key);
      return;
    }
    await SecureStore.deleteItemAsync(key);
  } catch {
    // installId is non-secret metadata. Reset should try to remove it, but a
    // platform storage failure must not strand the user in a half-reset flow.
  }
}

export function isValidInstallId(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export async function getInstallId(): Promise<string> {
  const existing = await readItem(INSTALL_ID_KEY);
  if (isValidInstallId(existing)) {
    return existing.toLowerCase();
  }

  const installId = ExpoCrypto.randomUUID().toLowerCase();
  await writeItem(INSTALL_ID_KEY, installId);
  return installId;
}

export async function clearInstallId(): Promise<void> {
  await deleteItem(INSTALL_ID_KEY);
}
