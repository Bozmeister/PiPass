import * as ExpoCrypto from "expo-crypto";
import { deriveMasterKey, generateMasterSalt, hashMasterKey } from "../crypto/keyDerivation";
import { encryptData, decryptData, type FieldAad } from "../crypto/encryption";
import { deriveEntryKey, generateSaltHex } from "../crypto/hkdf";
import {
  envelopeMigrationAllowed,
  generateItemKeyHex,
  intentdbEnvelopeEnabled,
  recordHasWrappedItemKey,
  resolveFieldKey,
  rewrapItemKey,
  wrapItemKey,
  type EnvelopeMigrationOptions,
} from "../crypto/itemEnvelope";
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
  // Legacy plaintext fields kept as optional for migration / old entries.
  // New entries (post plaintext-dup removal) only populate the encrypted* fields.
  // decryptVaultEntry() falls back to these when encrypted* are absent.
  title?: string;
  username?: string;
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
  // Encrypted with the same field key as the password (derived entry
  // key, or the unwrapped item key when encryptedItemKey is set).
  // The plaintext marker NEVER touches storage; only the in-memory
  // DecryptedVaultEntry.honeytokenMarker holds it while unlocked.
  encryptedAux?: string;
  /**
   * Wrapped 32-byte item key (v4, AAD field "itemKey").
   * Absent on items that still use the HKDF entry key.
   */
  encryptedItemKey?: string;
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

/**
 * Derives master key shares via Argon2id profile params only (no silent PBKDF2).
 *
 * Unlock / password verification MUST use planUnlockKdfDerivation (or
 * performCurrentUnlockVerification) so stored KDF metadata is respected.
 * This helper is for callers that intentionally use the current profile's
 * Argon2id parameters (e.g. empty-vault profile rekey after password verify).
 */
export async function deriveMasterKeyShares(
  password: string,
  saltHex: string,
  iterations: number = 100000
): Promise<KeyShares> {
  const safeIterations = Math.max(iterations || 100000, 3);
  // Uses keyDerivation.deriveMasterKey → Argon2id only; throws if unavailable.
  const masterKeyHex = await deriveMasterKey(password, saltHex, safeIterations);

  const shares = splitKeyIntoShares(masterKeyHex);

  const rawBytes = hexToBytes(masterKeyHex);
  wipeBuffer(rawBytes);

  return shares;
}

export { generateMasterSalt, hashMasterKey };

/** Field AAD for a vault entry ciphertext (binds MAC to entryId + field name). */
function entryFieldAad(entryId: string, field: FieldAad["field"]): FieldAad {
  return { recordId: entryId, field };
}

function wipeResolvedFieldKey(
  fieldKey: string,
  masterKeyHex: string,
  record: { salt: string; encryptedItemKey?: string },
): void {
  if (!record.salt && !recordHasWrappedItemKey(record)) return;
  if (!fieldKey || fieldKey === masterKeyHex) return;
  const fieldKeyBytes = hexToBytes(fieldKey);
  wipeBuffer(fieldKeyBytes);
}

// Encrypts a vault entry.
// Envelope off: fields use the HKDF entry key and no wrapped key is stored.
// Envelope on: fields use a random 32-byte item key stored as encryptedItemKey.
// `envelope` overrides EXPO_PUBLIC_INTENTDB_ENVELOPE. Omitted reads that flag.
export function encryptVaultEntry(
  entry: Omit<DecryptedVaultEntry, "id" | "createdAt" | "updatedAt">,
  shares: KeyShares,
  id?: string,
  envelope?: boolean,
): VaultEntry {
  const masterKeyHex = combineShares(shares);
  const entryId = id || generateId();
  const entrySalt = generateSaltHex();
  const useEnvelope = intentdbEnvelopeEnabled(envelope);
  let fieldKey = "";

  try {
    fieldKey = useEnvelope
      ? generateItemKeyHex()
      : deriveEntryKey(masterKeyHex, entryId, entrySalt);
    const now = Date.now();
    const aad = (field: FieldAad["field"]) => entryFieldAad(entryId, field);

    // T001 — Bundle decoy metadata into a single encrypted blob
    // (see `encryptedAux` field comment). We require BOTH a marker
    // and a honeytokenId before persisting any aux data; mismatched
    // state silently coerces to "not a decoy" rather than crashing.
    const encryptedAux: string | undefined =
      entry.isHoneytoken && entry.honeytokenMarker && entry.honeytokenId
        ? encryptData(
            JSON.stringify({ h: 1, i: entry.honeytokenId, m: entry.honeytokenMarker }),
            fieldKey,
            aad("aux"),
          )
        : undefined;

    const result: VaultEntry = {
      id: entryId,
      // NOTE: Plaintext title/username/url intentionally no longer stored for new entries.
      // Only encrypted* variants are persisted. This removes metadata duplication/leakage
      // in the encrypted blob on disk and during any future sync.
      //
      // SAFE MIGRATION:
      // - Legacy entries (pre-this change) may still contain plain title/username/url.
      // - decryptVaultEntry() already falls back to plain fields when encrypted* are absent.
      // - Re-encrypt (password change / recovery) will produce clean entries without plain fields.
      // - A one-time migration pass can be added later to strip remaining plain fields from old entries.
      encryptedPassword: encryptData(entry.password, fieldKey, aad("password")),
      encryptedTitle: encryptData(entry.title, fieldKey, aad("title")),
      encryptedUsername: encryptData(entry.username, fieldKey, aad("username")),
      encryptedUrl: entry.url ? encryptData(entry.url, fieldKey, aad("url")) : undefined,
      // Do not store plaintext url
      notes: entry.notes ? encryptData(entry.notes, fieldKey, aad("notes")) : undefined,
      salt: entrySalt,
      createdAt: now,
      updatedAt: now,
      encryptedAux,
    };
    if (useEnvelope) {
      result.encryptedItemKey = wrapItemKey(fieldKey, masterKeyHex, entrySalt, entryId);
    }

    return result;
  } finally {
    if (fieldKey) {
      const fieldKeyBytes = hexToBytes(fieldKey);
      wipeBuffer(fieldKeyBytes);
    }
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
    // Wrapped item key when present. Otherwise the HKDF entry key,
    // or the master key for legacy entries that have no salt.
    const entryKey = resolveFieldKey(entry, masterKeyHex);
    const aad = (field: FieldAad["field"]) => entryFieldAad(entry.id, field);

    // v3 requires field AAD; v1/v2 ignore AAD (backward compatible).
    const title = entry.encryptedTitle
      ? decryptData(entry.encryptedTitle, entryKey, aad("title"))
      : (entry.title ?? "");
    const username = entry.encryptedUsername
      ? decryptData(entry.encryptedUsername, entryKey, aad("username"))
      : (entry.username ?? "");
    const url = entry.encryptedUrl
      ? decryptData(entry.encryptedUrl, entryKey, aad("url"))
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
        const decryptedAux = decryptData(entry.encryptedAux, entryKey, aad("aux"));
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
      password: decryptData(entry.encryptedPassword, entryKey, aad("password")),
      url,
      notes: entry.notes ? decryptData(entry.notes, entryKey, aad("notes")) : undefined,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      isHoneytoken,
      honeytokenId,
      honeytokenMarker,
    };

    wipeResolvedFieldKey(entryKey, masterKeyHex, entry);

    return result;
  } finally {
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

function rewrapVaultEntryKey(
  entry: VaultEntry,
  oldShares: KeyShares,
  newShares: KeyShares,
): VaultEntry {
  if (!entry.encryptedItemKey || !entry.salt) {
    throw new Error("Cannot rewrap an item key without a salt");
  }
  const oldMaster = combineShares(oldShares);
  const newMaster = combineShares(newShares);
  try {
    return {
      id: entry.id,
      encryptedPassword: entry.encryptedPassword,
      encryptedTitle: entry.encryptedTitle,
      encryptedUsername: entry.encryptedUsername,
      encryptedUrl: entry.encryptedUrl,
      notes: entry.notes,
      salt: entry.salt,
      createdAt: entry.createdAt,
      updatedAt: Date.now(),
      encryptedAux: entry.encryptedAux,
      encryptedItemKey: rewrapItemKey(
        entry.encryptedItemKey,
        oldMaster,
        newMaster,
        entry.salt,
        entry.id,
      ),
    };
  } finally {
    wipeBuffer(hexToBytes(oldMaster));
    wipeBuffer(hexToBytes(newMaster));
  }
}

export function reEncryptEntry(
  entry: VaultEntry,
  oldShares: KeyShares,
  newShares: KeyShares
): VaultEntry {
  if (recordHasWrappedItemKey(entry)) {
    return rewrapVaultEntryKey(entry, oldShares, newShares);
  }
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
    entry.id,
    false,
  );
}

/**
 * Store the existing derived entry key as encryptedItemKey.
 * Other field ciphertext is left as stored. Already-wrapped items are unchanged.
 * Runs only when the envelope flag is on and the caller reports the vault unlocked.
 */
export function migrateVaultEntryEnvelope(
  entry: VaultEntry,
  shares: KeyShares,
  options?: EnvelopeMigrationOptions,
): VaultEntry {
  if (recordHasWrappedItemKey(entry)) return entry;
  if (!envelopeMigrationAllowed(options)) return entry;
  if (!entry.salt) return entry;
  const masterKeyHex = combineShares(shares);
  let derived = "";
  try {
    derived = deriveEntryKey(masterKeyHex, entry.id, entry.salt);
    return {
      ...entry,
      encryptedItemKey: wrapItemKey(derived, masterKeyHex, entry.salt, entry.id),
    };
  } finally {
    if (derived) wipeBuffer(hexToBytes(derived));
    wipeBuffer(hexToBytes(masterKeyHex));
  }
}

/**
 * At-rest secure note record.
 *
 * Labels are stored ONLY as encryptedLabel. The optional `label` field is a
 * legacy plaintext hangover: never written by new code; stripped on save;
 * still accepted on decrypt for one-time migration of older records.
 */
export interface SecureNote {
  id: string;
  encryptedLabel: string;
  encryptedContent: string;
  /** @deprecated Legacy plaintext label — do not write; stripped on save. */
  label?: string;
  salt: string;
  createdAt: number;
  updatedAt: number;
  /**
   * Wrapped 32-byte item key (v4, AAD field "itemKey").
   * Absent on notes that still use the HKDF entry key.
   */
  encryptedItemKey?: string;
}

export interface DecryptedSecureNote {
  id: string;
  label: string;
  content: string;
  createdAt: number;
  updatedAt: number;
}

/** True if the stored record still carries a legacy plaintext label. */
export function secureNoteHasLegacyPlaintextLabel(note: SecureNote): boolean {
  return typeof note.label === "string" && note.label.length > 0;
}

/**
 * Build a storage-safe note object: encrypted fields only, no plaintext label.
 * Does not re-encrypt; only strips legacy `label` if present.
 */
export function toStoredSecureNote(note: SecureNote): SecureNote {
  const stored: SecureNote = {
    id: note.id,
    encryptedLabel: note.encryptedLabel,
    encryptedContent: note.encryptedContent,
    salt: note.salt,
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
  };
  if (recordHasWrappedItemKey(note)) {
    stored.encryptedItemKey = note.encryptedItemKey;
  }
  return stored;
}

export function encryptSecureNote(
  note: { label: string; content: string },
  shares: KeyShares,
  id?: string,
  envelope?: boolean,
): SecureNote {
  const masterKeyHex = combineShares(shares);
  const noteId = id || generateId();
  const noteSalt = generateSaltHex();
  const useEnvelope = intentdbEnvelopeEnabled(envelope);
  let fieldKey = "";

  try {
    fieldKey = useEnvelope
      ? generateItemKeyHex()
      : deriveEntryKey(masterKeyHex, noteId, noteSalt);
    const now = Date.now();
    const aad = (field: FieldAad["field"]) => entryFieldAad(noteId, field);

    // Never persist plaintext label — only encryptedLabel + encryptedContent.
    const result: SecureNote = {
      id: noteId,
      encryptedLabel: encryptData(note.label, fieldKey, aad("label")),
      encryptedContent: encryptData(note.content, fieldKey, aad("content")),
      salt: noteSalt,
      createdAt: now,
      updatedAt: now,
    };
    if (useEnvelope) {
      result.encryptedItemKey = wrapItemKey(fieldKey, masterKeyHex, noteSalt, noteId);
    }

    return result;
  } finally {
    if (fieldKey) {
      const fieldKeyBytes = hexToBytes(fieldKey);
      wipeBuffer(fieldKeyBytes);
    }
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

/**
 * Decrypt only the note label (list UI). Prefer encryptedLabel; fall back to
 * legacy plaintext label when encryptedLabel is missing (pre-encryption records).
 */
export function decryptSecureNoteLabel(note: SecureNote, shares: KeyShares): string {
  const masterKeyHex = combineShares(shares);
  try {
    const noteKey = resolveFieldKey(note, masterKeyHex);
    try {
      if (typeof note.encryptedLabel === "string" && note.encryptedLabel.length > 0) {
        return decryptData(
          note.encryptedLabel,
          noteKey,
          entryFieldAad(note.id, "label"),
        );
      }
      if (typeof note.label === "string" && note.label.length > 0) {
        return note.label;
      }
      throw new Error("Secure note has no label material");
    } finally {
      wipeResolvedFieldKey(noteKey, masterKeyHex, note);
    }
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
    const noteKey = resolveFieldKey(note, masterKeyHex);
    const aad = (field: FieldAad["field"]) => entryFieldAad(note.id, field);

    let label: string;
    if (typeof note.encryptedLabel === "string" && note.encryptedLabel.length > 0) {
      label = decryptData(note.encryptedLabel, noteKey, aad("label"));
    } else if (typeof note.label === "string" && note.label.length > 0) {
      // Legacy plaintext-only label (should not exist for modern notes).
      label = note.label;
    } else {
      throw new Error("Secure note label is missing");
    }

    const result: DecryptedSecureNote = {
      id: note.id,
      label,
      content: decryptData(note.encryptedContent, noteKey, aad("content")),
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    };

    wipeResolvedFieldKey(noteKey, masterKeyHex, note);

    return result;
  } finally {
    const wipeBuf = hexToBytes(masterKeyHex);
    wipeBuffer(wipeBuf);
  }
}

/**
 * Upgrade a legacy note that still has plaintext label (and/or missing
 * encryptedLabel) into a clean encrypt-only record under the same shares.
 * Always produces a note without a plaintext `label` field.
 */
export function migrateSecureNoteToEncryptedLabel(
  note: SecureNote,
  shares: KeyShares,
): SecureNote {
  // If encryptedLabel already present and we only need to drop plaintext,
  // avoid re-deriving salt/key — just strip the plaintext field.
  if (
    typeof note.encryptedLabel === "string" &&
    note.encryptedLabel.length > 0 &&
    secureNoteHasLegacyPlaintextLabel(note)
  ) {
    // Verify encrypted label still decrypts before discarding plaintext backup.
    decryptSecureNoteLabel(note, shares);
    return toStoredSecureNote(note);
  }

  const decrypted = decryptSecureNote(note, shares);
  return encryptSecureNote(
    { label: decrypted.label, content: decrypted.content },
    shares,
    note.id,
  );
}

function rewrapSecureNoteKey(
  note: SecureNote,
  oldShares: KeyShares,
  newShares: KeyShares,
): SecureNote {
  if (!note.encryptedItemKey || !note.salt) {
    throw new Error("Cannot rewrap an item key without a salt");
  }
  const oldMaster = combineShares(oldShares);
  const newMaster = combineShares(newShares);
  try {
    return {
      id: note.id,
      encryptedLabel: note.encryptedLabel,
      encryptedContent: note.encryptedContent,
      salt: note.salt,
      createdAt: note.createdAt,
      updatedAt: Date.now(),
      encryptedItemKey: rewrapItemKey(
        note.encryptedItemKey,
        oldMaster,
        newMaster,
        note.salt,
        note.id,
      ),
    };
  } finally {
    wipeBuffer(hexToBytes(oldMaster));
    wipeBuffer(hexToBytes(newMaster));
  }
}

export function reEncryptSecureNote(
  note: SecureNote,
  oldShares: KeyShares,
  newShares: KeyShares
): SecureNote {
  if (recordHasWrappedItemKey(note)) {
    return rewrapSecureNoteKey(note, oldShares, newShares);
  }
  const decrypted = decryptSecureNote(note, oldShares);
  return encryptSecureNote(
    { label: decrypted.label, content: decrypted.content },
    newShares,
    note.id,
    false,
  );
}

/**
 * Store the existing derived note key as encryptedItemKey.
 * Label and content ciphertext stay as stored. Already-wrapped notes are unchanged.
 * Runs only when the envelope flag is on and the caller reports the vault unlocked.
 */
export function migrateSecureNoteEnvelope(
  note: SecureNote,
  shares: KeyShares,
  options?: EnvelopeMigrationOptions,
): SecureNote {
  if (recordHasWrappedItemKey(note)) return note;
  if (!envelopeMigrationAllowed(options)) return note;
  if (!note.salt) return note;
  const masterKeyHex = combineShares(shares);
  let derived = "";
  try {
    derived = deriveEntryKey(masterKeyHex, note.id, note.salt);
    return {
      ...note,
      encryptedItemKey: wrapItemKey(derived, masterKeyHex, note.salt, note.id),
    };
  } finally {
    if (derived) wipeBuffer(hexToBytes(derived));
    wipeBuffer(hexToBytes(masterKeyHex));
  }
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
