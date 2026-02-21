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

export function deriveMasterKeyShares(userPiSeed: number): KeyShares {
  const rawKey = deriveClusterKey(userPiSeed);
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
    return {
      id: entry.id,
      title: entry.title,
      username: entry.username,
      password: decryptData(entry.encryptedPassword, keyHex),
      url: entry.url,
      notes: entry.notes ? decryptData(entry.notes, keyHex) : undefined,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    };
  } finally {
    const wipeBuf = hexToBytes(keyHex);
    wipeBuffer(wipeBuf);
  }
}

function generateId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 20; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
