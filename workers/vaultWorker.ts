import * as ExpoCrypto from "expo-crypto";
import { deriveClusterKey } from "../crypto/keyDerivation";
import { encryptData, decryptData } from "../crypto/encryption";
import {
  splitKeyIntoShares,
  combineShares,
  wipeShares,
  wipeBuffer,
  hexToBytes,
  KeyShares,
} from "../crypto/secureMemory";
import { argon2id } from "hash-wasm";
import * as SecureStore from "expo-secure-store";

export interface VaultEntry {
  id: string;
  title: string;
  username: string;
  encryptedPassword: string;
  encryptedTitle?: string;
  encryptedUsername?: string;
  encryptedUrl?: string;
  url?: string;
  notes?: string;
  createdAt: number;
  updatedAt: number;
}

export interface DecryptedVaultEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  createdAt: number;
  updatedAt: number;
}

export async function deriveMasterKeyShares(
  userPiSeed: number,
  iterations: number = 100000
): Promise<KeyShares> {
  const safeIterations = Math.max(iterations || 100000, 3);
  console.log("Argon2id hydration guard: iterations resolved to", safeIterations);

  const rawKey = deriveClusterKey(userPiSeed, safeIterations);
  const deviceUUID = await getDeviceUUID();
  const rawMaterial = rawKey + deviceUUID + userPiSeed.toString();

  const salt = new TextEncoder().encode(deviceUUID + userPiSeed.toString().slice(0, 16));

  // Guard: force positive params
  let timeCost = safeIterations === 25000 ? 3 : safeIterations === 100000 ? 4 : 6;
  let memorySize = safeIterations === 25000 ? 65536 : safeIterations === 100000 ? 131072 : 262144;
  if (timeCost <= 0) timeCost = 3;
  if (memorySize <= 0) memorySize = 65536;

  console.log("Argon2id params:", { iterations: timeCost, memorySize });

  const argonKeyBytes = await argon2id({
    password: new TextEncoder().encode(rawMaterial),
    salt,
    iterations: timeCost,  // FIXED PARAM NAME
    memorySize,            // FIXED PARAM NAME
    parallelism: 4,
    hashLength: 32,
    outputType: "binary" as const,
  });

  const masterKeyHex = Array.from(argonKeyBytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const shares = splitKeyIntoShares(masterKeyHex);

  const rawBytes = hexToBytes(masterKeyHex);
  wipeBuffer(rawBytes);

  return shares;
}

// DEVICE UUID HELPER
async function getDeviceUUID(): Promise<string> {
  let uuid = await SecureStore.getItemAsync("deviceUUID");
  if (!uuid) {
    uuid = ExpoCrypto.randomUUID();
    await SecureStore.setItemAsync("deviceUUID", uuid);
  }
  return uuid;
}

// REST OF THE FILE UNCHANGED
export function encryptVaultEntry(
  entry: Omit<DecryptedVaultEntry, "id" | "createdAt" | "updatedAt">,
  shares: KeyShares,
  id?: string
): VaultEntry {
  const keyHex = combineShares(shares);
  try {
    const now = Date.now();
    return {
      id: id || generateId(),
      title: entry.title,
      username: entry.username,
      encryptedPassword: encryptData(entry.password, keyHex),
      encryptedTitle: encryptData(entry.title, keyHex),
      encryptedUsername: encryptData(entry.username, keyHex),
      encryptedUrl: entry.url ? encryptData(entry.url, keyHex) : undefined,
      url: entry.url,
      notes: entry.notes ? encryptData(entry.notes, keyHex) : undefined,
      createdAt: now,
      updatedAt: now,
    };
  } finally {
    const wipeBuf = hexToBytes(keyHex);
    wipeBuffer(wipeBuf);
  }
}

export function decryptVaultEntry(
  entry: VaultEntry,
  shares: KeyShares
): DecryptedVaultEntry {
  const keyHex = combineShares(shares);
  try {
    const title = entry.encryptedTitle
      ? decryptData(entry.encryptedTitle, keyHex)
      : entry.title;
    const username = entry.encryptedUsername
      ? decryptData(entry.encryptedUsername, keyHex)
      : entry.username;
    const url = entry.encryptedUrl
      ? decryptData(entry.encryptedUrl, keyHex)
      : entry.url;

    return {
      id: entry.id,
      title,
      username,
      password: decryptData(entry.encryptedPassword, keyHex),
      url,
      notes: entry.notes ? decryptData(entry.notes, keyHex) : undefined,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    };
  } finally {
    const wipeBuf = hexToBytes(keyHex);
    wipeBuffer(wipeBuf);
  }
}

export function reEncryptEntry(
  entry: VaultEntry,
  oldShares: KeyShares,
  newShares: KeyShares
): VaultEntry {
  const decrypted = decryptVaultEntry(entry, oldShares);
  const newKeyHex = combineShares(newShares);
  try {
    return {
      id: entry.id,
      title: decrypted.title,
      username: decrypted.username,
      encryptedPassword: encryptData(decrypted.password, newKeyHex),
      encryptedTitle: encryptData(decrypted.title, newKeyHex),
      encryptedUsername: encryptData(decrypted.username, newKeyHex),
      encryptedUrl: decrypted.url ? encryptData(decrypted.url, newKeyHex) : undefined,
      url: decrypted.url,
      notes: decrypted.notes ? encryptData(decrypted.notes, newKeyHex) : undefined,
      createdAt: entry.createdAt,
      updatedAt: Date.now(),
    };
  } finally {
    const wipeBuf = hexToBytes(newKeyHex);
    wipeBuffer(wipeBuf);
  }
}

export interface SecureNote {
  id: string;
  encryptedLabel: string;
  encryptedContent: string;
  label: string;
  createdAt: number;
  updatedAt: number;
}

export interface DecryptedSecureNote {
  id: string;
  label: string;
  content: string;
  createdAt: number;
  updatedAt: number;
}

export function encryptSecureNote(
  note: { label: string; content: string },
  shares: KeyShares,
  id?: string
): SecureNote {
  const keyHex = combineShares(shares);
  try {
    const now = Date.now();
    return {
      id: id || generateId(),
      label: note.label,
      encryptedLabel: encryptData(note.label, keyHex),
      encryptedContent: encryptData(note.content, keyHex),
      createdAt: now,
      updatedAt: now,
    };
  } finally {
    const wipeBuf = hexToBytes(keyHex);
    wipeBuffer(wipeBuf);
  }
}

export function decryptSecureNote(
  note: SecureNote,
  shares: KeyShares
): DecryptedSecureNote {
  const keyHex = combineShares(shares);
  try {
    return {
      id: note.id,
      label: note.encryptedLabel ? decryptData(note.encryptedLabel, keyHex) : note.label,
      content: decryptData(note.encryptedContent, keyHex),
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    };
  } finally {
    const wipeBuf = hexToBytes(keyHex);
    wipeBuffer(wipeBuf);
  }
}

export function reEncryptSecureNote(
  note: SecureNote,
  oldShares: KeyShares,
  newShares: KeyShares
): SecureNote {
  const decrypted = decryptSecureNote(note, oldShares);
  const newKeyHex = combineShares(newShares);
  try {
    return {
      id: note.id,
      label: decrypted.label,
      encryptedLabel: encryptData(decrypted.label, newKeyHex),
      encryptedContent: encryptData(decrypted.content, newKeyHex),
      createdAt: note.createdAt,
      updatedAt: Date.now(),
    };
  } finally {
    const wipeBuf = hexToBytes(newKeyHex);
    wipeBuffer(wipeBuf);
  }
}

function generateId(): string {
  const bytes = ExpoCrypto.getRandomBytes(15);
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 15; i++) {
    result += chars.charAt(bytes[i] % chars.length);
  }
  return result;
}