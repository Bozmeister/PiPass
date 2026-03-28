import * as ExpoCrypto from "expo-crypto";
import { deriveMasterKey, generateMasterSalt, hashMasterKey } from "../crypto/keyDerivation";
import { encryptData, decryptData } from "../crypto/encryption";
import { deriveEntryKey, generateSaltHex } from "../crypto/hkdf";
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
  salt: string; // Per-entry salt for HKDF subkey derivation
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

// Derives master key from password and returns XOR-split shares.
// The raw key only exists briefly during derivation.
export async function deriveMasterKeyShares(
  password: string,
  saltHex: string,
  iterations: number = 100000
): Promise<KeyShares> {
  const safeIterations = Math.max(iterations || 100000, 3);
  const masterKeyHex = await deriveMasterKey(password, saltHex, safeIterations);

  const shares = splitKeyIntoShares(masterKeyHex);

  const rawBytes = hexToBytes(masterKeyHex);
  wipeBuffer(rawBytes);

  return shares;
}

export { generateMasterSalt, hashMasterKey };

// Encrypts a vault entry using a per-entry subkey derived via HKDF.
export function encryptVaultEntry(
  entry: Omit<DecryptedVaultEntry, "id" | "createdAt" | "updatedAt">,
  shares: KeyShares,
  id?: string
): VaultEntry {
  const masterKeyHex = combineShares(shares);
  const entryId = id || generateId();
  const entrySalt = generateSaltHex();

  try {
    const entryKey = deriveEntryKey(masterKeyHex, entryId, entrySalt);
    const now = Date.now();

    const result: VaultEntry = {
      id: entryId,
      title: entry.title,
      username: entry.username,
      encryptedPassword: encryptData(entry.password, entryKey),
      encryptedTitle: encryptData(entry.title, entryKey),
      encryptedUsername: encryptData(entry.username, entryKey),
      encryptedUrl: entry.url ? encryptData(entry.url, entryKey) : undefined,
      url: entry.url,
      notes: entry.notes ? encryptData(entry.notes, entryKey) : undefined,
      salt: entrySalt,
      createdAt: now,
      updatedAt: now,
    };

    const entryKeyBytes = hexToBytes(entryKey);
    wipeBuffer(entryKeyBytes);

    return result;
  } finally {
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

// Decrypts a vault entry using its per-entry subkey.
export function decryptVaultEntry(
  entry: VaultEntry,
  shares: KeyShares
): DecryptedVaultEntry {
  const masterKeyHex = combineShares(shares);

  try {
    // For entries with per-entry salt, derive subkey via HKDF
    // For legacy entries without salt, use master key directly
    const entryKey = entry.salt
      ? deriveEntryKey(masterKeyHex, entry.id, entry.salt)
      : masterKeyHex;

    const title = entry.encryptedTitle
      ? decryptData(entry.encryptedTitle, entryKey)
      : entry.title;
    const username = entry.encryptedUsername
      ? decryptData(entry.encryptedUsername, entryKey)
      : entry.username;
    const url = entry.encryptedUrl
      ? decryptData(entry.encryptedUrl, entryKey)
      : entry.url;

    const result: DecryptedVaultEntry = {
      id: entry.id,
      title,
      username,
      password: decryptData(entry.encryptedPassword, entryKey),
      url,
      notes: entry.notes ? decryptData(entry.notes, entryKey) : undefined,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    };

    if (entry.salt) {
      const entryKeyBytes = hexToBytes(entryKey);
      wipeBuffer(entryKeyBytes);
    }

    return result;
  } finally {
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

export function reEncryptEntry(
  entry: VaultEntry,
  oldShares: KeyShares,
  newShares: KeyShares
): VaultEntry {
  const decrypted = decryptVaultEntry(entry, oldShares);
  return encryptVaultEntry(
    {
      title: decrypted.title,
      username: decrypted.username,
      password: decrypted.password,
      url: decrypted.url,
      notes: decrypted.notes,
    },
    newShares,
    entry.id
  );
}

export interface SecureNote {
  id: string;
  encryptedLabel: string;
  encryptedContent: string;
  label: string;
  salt: string;
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
  const masterKeyHex = combineShares(shares);
  const noteId = id || generateId();
  const noteSalt = generateSaltHex();

  try {
    const noteKey = deriveEntryKey(masterKeyHex, noteId, noteSalt);
    const now = Date.now();

    const result: SecureNote = {
      id: noteId,
      label: note.label,
      encryptedLabel: encryptData(note.label, noteKey),
      encryptedContent: encryptData(note.content, noteKey),
      salt: noteSalt,
      createdAt: now,
      updatedAt: now,
    };

    const noteKeyBytes = hexToBytes(noteKey);
    wipeBuffer(noteKeyBytes);

    return result;
  } finally {
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

export function decryptSecureNote(
  note: SecureNote,
  shares: KeyShares
): DecryptedSecureNote {
  const masterKeyHex = combineShares(shares);

  try {
    const noteKey = note.salt
      ? deriveEntryKey(masterKeyHex, note.id, note.salt)
      : masterKeyHex;

    const result: DecryptedSecureNote = {
      id: note.id,
      label: note.encryptedLabel ? decryptData(note.encryptedLabel, noteKey) : note.label,
      content: decryptData(note.encryptedContent, noteKey),
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    };

    if (note.salt) {
      const noteKeyBytes = hexToBytes(noteKey);
      wipeBuffer(noteKeyBytes);
    }

    return result;
  } finally {
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

export function reEncryptSecureNote(
  note: SecureNote,
  oldShares: KeyShares,
  newShares: KeyShares
): SecureNote {
  const decrypted = decryptSecureNote(note, oldShares);
  return encryptSecureNote(
    { label: decrypted.label, content: decrypted.content },
    newShares,
    note.id
  );
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
