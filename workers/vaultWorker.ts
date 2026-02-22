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

export function deriveMasterKeyShares(userPiSeed: number, iterations: number = 100000): KeyShares {
  const rawKey = deriveClusterKey(userPiSeed, iterations);
  const shares = splitKeyIntoShares(rawKey);
  const rawBytes = hexToBytes(rawKey);
  wipeBuffer(rawBytes);
  return shares;
}

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

function generateId(): string {
  const bytes = ExpoCrypto.getRandomBytes(15);
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 15; i++) {
    result += chars.charAt(bytes[i] % chars.length);
  }
  return result;
}
