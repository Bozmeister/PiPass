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
  // T001 — Encrypted auxiliary blob (decoy / honeytoken metadata).
  //
  // ZERO-KNOWLEDGE INDISTINGUISHABILITY: a thief who decrypts a
  // single entry must NOT be able to tell whether it's a real
  // credential or a decoy without actually using it. Earlier
  // revisions of this code stored `isHoneytoken: boolean` and
  // `honeytokenId: string` as plaintext outer fields, which made
  // every decoy obvious to anyone reading SecureStore — defeating
  // the entire honeytoken concept. We now bundle ALL decoy
  // metadata (server row id + 256-bit marker) into a single
  // encrypted blob and give it a deliberately neutral name
  // (`encryptedAux`) so the field's mere presence carries no
  // semantic signal.
  //
  // Plaintext shape inside the blob (kept short to minimise
  // ciphertext-length variation across decoys):
  //   { "h": 1, "i": <honeytokenId>, "m": <markerHex> }
  //
  // Encrypted with the same per-entry HKDF subkey as the password,
  // so it inherits the same key separation / rotation properties.
  // The plaintext marker NEVER touches storage; only the in-memory
  // DecryptedVaultEntry.honeytokenMarker holds it while unlocked.
  encryptedAux?: string;
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
  // T001 — Decrypted honeytoken fields. Present iff the source
  // VaultEntry is a decoy. Consumers (EntryDetailModal, trigger
  // hooks) check `isHoneytoken && honeytokenMarker` before firing
  // the trigger.
  isHoneytoken?: boolean;
  honeytokenId?: string;
  honeytokenMarker?: string;
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

    // T001 — Bundle decoy metadata into a single encrypted blob
    // (see `encryptedAux` field comment). We require BOTH a marker
    // and a honeytokenId before persisting any aux data; mismatched
    // state silently coerces to "not a decoy" rather than crashing.
    const encryptedAux: string | undefined =
      entry.isHoneytoken && entry.honeytokenMarker && entry.honeytokenId
        ? encryptData(
            JSON.stringify({ h: 1, i: entry.honeytokenId, m: entry.honeytokenMarker }),
            entryKey,
          )
        : undefined;

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
      encryptedAux,
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

    // T001 — Decrypt the auxiliary blob if present and recover
    // honeytoken metadata. Decoy state is derived ENTIRELY from
    // successful decryption + JSON shape validation — there is no
    // plaintext flag to consult. Defensive about every step:
    //   - decryptData may throw on key mismatch (post-rotation
    //     marker would be encrypted with the OLD per-entry key);
    //     we swallow and degrade to "not a decoy".
    //   - JSON.parse may throw on garbage; swallow same.
    //   - Shape validation: must be `{ h: 1, i: <string>, m: <hex> }`.
    //     Any deviation is treated as "not a decoy" — same calm
    //     degradation. The trigger hook also checks that
    //     honeytokenMarker is a non-empty string before firing.
    let isHoneytoken: boolean | undefined;
    let honeytokenMarker: string | undefined;
    let honeytokenId: string | undefined;
    if (entry.encryptedAux) {
      try {
        const decryptedAux = decryptData(entry.encryptedAux, entryKey);
        if (typeof decryptedAux === "string" && decryptedAux.length > 0) {
          const parsed = JSON.parse(decryptedAux) as {
            h?: number;
            i?: string;
            m?: string;
          };
          if (
            parsed &&
            parsed.h === 1 &&
            typeof parsed.i === "string" &&
            parsed.i.length > 0 &&
            typeof parsed.m === "string" &&
            parsed.m.length > 0
          ) {
            isHoneytoken = true;
            honeytokenId = parsed.i;
            honeytokenMarker = parsed.m;
          }
        }
      } catch {
        // Silent — see comment above.
      }
    }

    const result: DecryptedVaultEntry = {
      id: entry.id,
      title,
      username,
      password: decryptData(entry.encryptedPassword, entryKey),
      url,
      notes: entry.notes ? decryptData(entry.notes, entryKey) : undefined,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      isHoneytoken,
      honeytokenId,
      honeytokenMarker,
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
      // T001 — Preserve honeytoken status across master-key rotation.
      // Without this, password changes would silently disarm every
      // decoy in the user's vault.
      isHoneytoken: decrypted.isHoneytoken,
      honeytokenId: decrypted.honeytokenId,
      honeytokenMarker: decrypted.honeytokenMarker,
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
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const maxValid = 256 - (256 % chars.length);
  let result = "";
  while (result.length < 15) {
    const bytes = ExpoCrypto.getRandomBytes(20);
    for (let i = 0; i < bytes.length && result.length < 15; i++) {
      if (bytes[i] < maxValid) {
        result += chars.charAt(bytes[i] % chars.length);
      }
    }
  }
  return result;
}
