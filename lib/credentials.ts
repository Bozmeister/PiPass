import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";

const USER_ID_KEY = "pipass.auth.userId";
const AUTH_HASH_KEY = "pipass.auth.authHash";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const AUTH_HASH_RE = /^[0-9a-fA-F]{64,128}$/;

export type Credentials = { userId: string; authHash: string };

async function readItem(key: string): Promise<string | null> {
  if (Platform.OS === "web") {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }
  return await SecureStore.getItemAsync(key);
}

async function writeItem(key: string, value: string): Promise<void> {
  if (Platform.OS === "web") {
    try {
      localStorage.setItem(key, value);
    } catch {
      // localStorage unavailable (private mode, quota) — fail silently per
      // the credentials contract: caller cannot rely on persistence.
    }
    return;
  }
  await SecureStore.setItemAsync(key, value);
}

async function deleteItem(key: string): Promise<void> {
  if (Platform.OS === "web") {
    try {
      localStorage.removeItem(key);
    } catch {}
    return;
  }
  await SecureStore.deleteItemAsync(key);
}

export function isValidUserId(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export function isValidAuthHash(value: unknown): value is string {
  return typeof value === "string" && AUTH_HASH_RE.test(value);
}

export async function getCredentials(): Promise<Credentials | null> {
  const userId = await readItem(USER_ID_KEY);
  const authHash = await readItem(AUTH_HASH_KEY);
  if (userId === null || authHash === null) {
    return null;
  }
  if (!isValidUserId(userId) || !isValidAuthHash(authHash)) {
    await clearCredentials();
    return null;
  }
  return { userId, authHash };
}

export async function setCredentials(creds: Credentials): Promise<void> {
  if (!isValidUserId(creds?.userId)) {
    throw new Error("setCredentials: invalid userId (must be a UUID)");
  }
  if (!isValidAuthHash(creds?.authHash)) {
    throw new Error(
      "setCredentials: invalid authHash (must be 64-128 hex chars)",
    );
  }
  await writeItem(USER_ID_KEY, creds.userId);
  await writeItem(AUTH_HASH_KEY, creds.authHash);
}

export async function clearCredentials(): Promise<void> {
  await deleteItem(USER_ID_KEY);
  await deleteItem(AUTH_HASH_KEY);
}

export async function hasCredentials(): Promise<boolean> {
  return (await getCredentials()) !== null;
}
