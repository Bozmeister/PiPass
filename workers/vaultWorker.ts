import { deriveKeyWithRounds } from "../crypto/keyDerivation";
import { encryptData, decryptData } from "../crypto/encryption";

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

export function encryptVaultEntry(
  entry: Omit<DecryptedVaultEntry, "id" | "createdAt" | "updatedAt">,
  masterKey: string,
  id?: string
): VaultEntry {
  const now = Date.now();
  return {
    id: id || generateId(),
    title: entry.title,
    username: entry.username,
    encryptedPassword: encryptData(entry.password, masterKey),
    url: entry.url,
    notes: entry.notes ? encryptData(entry.notes, masterKey) : undefined,
    createdAt: now,
    updatedAt: now,
  };
}

export function decryptVaultEntry(
  entry: VaultEntry,
  masterKey: string
): DecryptedVaultEntry {
  return {
    id: entry.id,
    title: entry.title,
    username: entry.username,
    password: decryptData(entry.encryptedPassword, masterKey),
    url: entry.url,
    notes: entry.notes ? decryptData(entry.notes, masterKey) : undefined,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
  };
}

export function deriveMasterKey(masterPassword: string): string {
  return deriveKeyWithRounds(masterPassword, "pipass-vault-salt", 3);
}

function generateId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 20; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
