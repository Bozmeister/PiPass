import {
  deletePlatformItem,
  readPlatformItem,
  writePlatformItem,
} from "../lib/platformStorage";

const DEVICE_UUID_KEY = "deviceUUID";

async function randomUUID(): Promise<string> {
  const ExpoCrypto = await import("expo-crypto");
  return ExpoCrypto.randomUUID();
}

export async function getDeviceUUID(): Promise<string> {
  let uuid = await readPlatformItem(DEVICE_UUID_KEY);
  if (!uuid) {
    uuid = await randomUUID();
    await writePlatformItem(DEVICE_UUID_KEY, uuid);
  }
  return uuid;
}

export async function clearDeviceUUID(): Promise<void> {
  await deletePlatformItem(DEVICE_UUID_KEY);
}
