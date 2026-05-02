import {
  deletePlatformItem,
  readPlatformItem,
  writePlatformItem,
} from "./platformStorage";

const INSTALL_ID_KEY = "pipass.installId";
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function readItem(key: string): Promise<string | null> {
  try {
    return await readPlatformItem(key);
  } catch {
    return null;
  }
}

async function writeItem(key: string, value: string): Promise<void> {
  try {
    await writePlatformItem(key, value);
  } catch {
    // installId is a non-secret label. Storage failure must never block auth,
    // crypto, vault access, or any protected request.
  }
}

async function deleteItem(key: string): Promise<void> {
  try {
    await deletePlatformItem(key);
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

  const ExpoCrypto = await import("expo-crypto");
  const installId = ExpoCrypto.randomUUID().toLowerCase();
  await writeItem(INSTALL_ID_KEY, installId);
  return installId;
}

export async function clearInstallId(): Promise<void> {
  await deleteItem(INSTALL_ID_KEY);
}
