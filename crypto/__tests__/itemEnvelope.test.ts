/**
 * Optional item-key envelope.
 *
 * New items wrap a random key only when asked. Old items keep the derived
 * entry key. Password change rewraps only when a wrapped key is already
 * stored. Migration wraps that derived key once and leaves field ciphertext.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Module from "node:module";
import { after, before, test } from "node:test";
import { decryptData, isAuthenticatedCiphertext } from "../encryption";
import { deriveEntryKey } from "../hkdf";
import {
  INTENTDB_ENVELOPE_ENV,
  ITEM_KEY_FIELD,
  ITEM_WRAP_HKDF_INFO,
  intentdbEnvelopeEnabled,
  unwrapItemKey,
} from "../itemEnvelope";
import { splitKeyIntoShares, wipeShares, type KeyShares } from "../secureMemory";
import {
  buildSecureNoteManifest,
  buildVaultEntryManifest,
  verifyItemManifest,
} from "../../lib/intentdb/itemManifest";
import {
  buildReceipt,
  createHmacSha256ReceiptCrypto,
  verifyReceipt,
} from "../../lib/intentdb/receipt";
import {
  acceptOpaqueItemManifest,
  itemContentSha256,
} from "../../server/itemManifestProof";
import type * as VaultWorker from "../../workers/vaultWorker";

function installExpoCryptoStub(): () => void {
  const moduleLoader = Module as unknown as {
    _load: (request: string, parent: unknown, isMain: boolean) => unknown;
  };
  const originalLoad = moduleLoader._load;
  let counter = 0;
  moduleLoader._load = function patchedLoad(
    request: string,
    parent: unknown,
    isMain: boolean,
  ) {
    if (request === "expo-crypto") {
      return {
        getRandomBytes: (length: number) => {
          const bytes = new Uint8Array(length);
          for (let i = 0; i < length; i++) {
            bytes[i] = (counter + i * 17) & 0xff;
          }
          counter += 1;
          return bytes;
        },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  return () => {
    moduleLoader._load = originalLoad;
  };
}

let restoreExpo: () => void = () => {};
let vault: typeof VaultWorker;

before(async () => {
  restoreExpo = installExpoCryptoStub();
  vault = await import("../../workers/vaultWorker");
});

after(() => {
  restoreExpo();
});

const OLD_MASTER = "11".repeat(32);
const NEW_MASTER = "22".repeat(32);
const PASSWORD = "Envelope-Password-Secret!";
const TITLE = "Envelope Title";
const USERNAME = "ada@example.com";
const URL = "https://bank.example/login";
const NOTES = "Envelope-Note-Secret";
const LABEL = "Envelope-Label-Secret";
const CONTENT = "Envelope-Content-Secret";

function sharesFor(master: string): KeyShares {
  return splitKeyIntoShares(master);
}

function restoreEnv(previous: string | undefined): void {
  if (previous === undefined) delete process.env[INTENTDB_ENVELOPE_ENV];
  else process.env[INTENTDB_ENVELOPE_ENV] = previous;
}

function entryPlain() {
  return {
    title: TITLE,
    username: USERNAME,
    password: PASSWORD,
    url: URL,
    notes: NOTES,
  };
}

test("envelope flag defaults off", () => {
  const previous = process.env[INTENTDB_ENVELOPE_ENV];
  delete process.env[INTENTDB_ENVELOPE_ENV];
  try {
    assert.equal(intentdbEnvelopeEnabled(), false);
    assert.equal(intentdbEnvelopeEnabled(false), false);
    assert.equal(intentdbEnvelopeEnabled(true), true);
    assert.equal(ITEM_WRAP_HKDF_INFO, "pipass-item-wrap-v1");
    assert.equal(ITEM_KEY_FIELD, "itemKey");
  } finally {
    restoreEnv(previous);
  }
});

test("flag default off leaves encrypt and migration unchanged", () => {
  const previous = process.env[INTENTDB_ENVELOPE_ENV];
  delete process.env[INTENTDB_ENVELOPE_ENV];
  const shares = sharesFor(OLD_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), shares);
    assert.equal(entry.encryptedItemKey, undefined);
    assert.equal(vault.decryptVaultEntry(entry, shares).password, PASSWORD);
    const derived = deriveEntryKey(OLD_MASTER, entry.id, entry.salt);
    assert.equal(
      decryptData(entry.encryptedPassword, derived, { recordId: entry.id, field: "password" }),
      PASSWORD,
    );
    const migrated = vault.migrateVaultEntryEnvelope(entry, shares, { unlocked: true });
    assert.equal(migrated, entry);
    assert.equal(migrated.encryptedItemKey, undefined);

    const note = vault.encryptSecureNote({ label: LABEL, content: CONTENT }, shares);
    assert.equal(note.encryptedItemKey, undefined);
    assert.equal(vault.decryptSecureNote(note, shares).content, CONTENT);
    assert.equal(vault.migrateSecureNoteEnvelope(note, shares, { unlocked: true }), note);
  } finally {
    wipeShares(shares);
    restoreEnv(previous);
  }
});

test("new item uses a wrapped item key when the envelope override is on", () => {
  const previous = process.env[INTENTDB_ENVELOPE_ENV];
  delete process.env[INTENTDB_ENVELOPE_ENV];
  const shares = sharesFor(OLD_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), shares, undefined, true);
    assert.equal(isAuthenticatedCiphertext(entry.encryptedItemKey ?? ""), true);
    assert.match(entry.encryptedItemKey ?? "", /^v4:/);

    const itemKey = unwrapItemKey(entry.encryptedItemKey ?? "", OLD_MASTER, entry.salt, entry.id);
    assert.match(itemKey, /^[0-9a-f]{64}$/);
    assert.equal(
      decryptData(entry.encryptedPassword, itemKey, { recordId: entry.id, field: "password" }),
      PASSWORD,
    );
    assert.equal(JSON.stringify(entry).includes(itemKey), false);

    const derived = deriveEntryKey(OLD_MASTER, entry.id, entry.salt);
    assert.throws(
      () => decryptData(entry.encryptedPassword, derived, { recordId: entry.id, field: "password" }),
      /Authentication failed/,
    );
    assert.equal(vault.decryptVaultEntry(entry, shares).password, PASSWORD);
    assert.equal(JSON.stringify(entry).includes(PASSWORD), false);
    assert.equal(JSON.stringify(entry).includes(OLD_MASTER), false);

    const manifest = buildVaultEntryManifest(entry);
    const wrappedField = manifest.fields.find((field) => field.name === "itemKey");
    assert.equal(wrappedField?.ciphertext, entry.encryptedItemKey);
    assert.equal(verifyItemManifest(manifest), true);
    assert.equal(JSON.stringify(manifest).includes(PASSWORD), false);
    assert.equal(JSON.stringify(manifest).includes(itemKey), false);

    const accepted = acceptOpaqueItemManifest({
      ...manifest,
      locator: "phone",
      tombstone: false,
      vaultKeyProof: "ab".repeat(32),
    });
    assert.equal(accepted.ok, true);
    assert.equal(
      itemContentSha256({
        schema: manifest.schema,
        itemId: manifest.itemId,
        kind: manifest.kind,
        version: manifest.version,
        salt: manifest.salt,
        createdAt: manifest.createdAt,
        updatedAt: manifest.updatedAt,
        fields: manifest.fields,
      }),
      manifest.contentSha256,
    );

    const receiptCrypto = createHmacSha256ReceiptCrypto(new Uint8Array(32).fill(7));
    const receipt = buildReceipt(
      {
        op: "put",
        itemId: manifest.itemId,
        itemVersion: manifest.version,
        contentSha256: manifest.contentSha256,
        fromLocator: "client",
        toLocator: "phone",
        botId: "pipass-server",
        issuedAt: 1_700_000_000_000,
      },
      receiptCrypto,
    );
    assert.equal(verifyReceipt(receipt, receiptCrypto).ok, true);
    assert.equal(JSON.stringify(receipt).includes(PASSWORD), false);
    assert.equal(JSON.stringify(receipt).includes(itemKey), false);
    assert.equal(receipt.contentSha256, manifest.contentSha256);
  } finally {
    wipeShares(shares);
    restoreEnv(previous);
  }
});

test("EXPO_PUBLIC_INTENTDB_ENVELOPE=1 wraps a new item", () => {
  const previous = process.env[INTENTDB_ENVELOPE_ENV];
  process.env[INTENTDB_ENVELOPE_ENV] = "1";
  const shares = sharesFor(OLD_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), shares);
    assert.equal(isAuthenticatedCiphertext(entry.encryptedItemKey ?? ""), true);
    assert.equal(vault.decryptVaultEntry(entry, shares).title, TITLE);
    const forcedOff = vault.encryptVaultEntry(entryPlain(), shares, undefined, false);
    assert.equal(forcedOff.encryptedItemKey, undefined);
  } finally {
    wipeShares(shares);
    restoreEnv(previous);
  }
});

test("old item still decrypts with the derived entry key", () => {
  const shares = sharesFor(OLD_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), shares, undefined, false);
    assert.equal(entry.encryptedItemKey, undefined);
    const derived = deriveEntryKey(OLD_MASTER, entry.id, entry.salt);
    assert.equal(
      decryptData(entry.encryptedPassword, derived, { recordId: entry.id, field: "password" }),
      PASSWORD,
    );
    assert.equal(vault.decryptVaultEntry(entry, shares).username, USERNAME);
    const manifest = buildVaultEntryManifest(entry);
    assert.equal(manifest.fields.some((field) => field.name === "itemKey"), false);
    const accepted = acceptOpaqueItemManifest({
      ...manifest,
      locator: "phone",
      tombstone: false,
      vaultKeyProof: "cd".repeat(32),
    });
    assert.equal(accepted.ok, true);
  } finally {
    wipeShares(shares);
  }
});

test("password change rewraps only the item key when one is present", () => {
  const previous = process.env[INTENTDB_ENVELOPE_ENV];
  delete process.env[INTENTDB_ENVELOPE_ENV];
  const oldShares = sharesFor(OLD_MASTER);
  const newShares = sharesFor(NEW_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), oldShares, undefined, true);
    const changed = vault.reEncryptEntry(entry, oldShares, newShares);
    assert.equal(changed.id, entry.id);
    assert.equal(changed.salt, entry.salt);
    assert.equal(changed.createdAt, entry.createdAt);
    assert.equal(changed.encryptedPassword, entry.encryptedPassword);
    assert.equal(changed.encryptedTitle, entry.encryptedTitle);
    assert.equal(changed.encryptedUsername, entry.encryptedUsername);
    assert.equal(changed.encryptedUrl, entry.encryptedUrl);
    assert.equal(changed.notes, entry.notes);
    assert.notEqual(changed.encryptedItemKey, entry.encryptedItemKey);
    assert.equal(isAuthenticatedCiphertext(changed.encryptedItemKey ?? ""), true);
    assert.equal(vault.decryptVaultEntry(changed, newShares).password, PASSWORD);
    assert.equal(vault.decryptVaultEntry(changed, newShares).notes, NOTES);
    assert.throws(
      () => vault.decryptVaultEntry(changed, oldShares),
      /Authentication failed/,
    );

    const note = vault.encryptSecureNote({ label: LABEL, content: CONTENT }, oldShares, undefined, true);
    const changedNote = vault.reEncryptSecureNote(note, oldShares, newShares);
    assert.equal(changedNote.encryptedLabel, note.encryptedLabel);
    assert.equal(changedNote.encryptedContent, note.encryptedContent);
    assert.equal(changedNote.salt, note.salt);
    assert.notEqual(changedNote.encryptedItemKey, note.encryptedItemKey);
    assert.equal(vault.decryptSecureNote(changedNote, newShares).content, CONTENT);
    assert.throws(() => vault.decryptSecureNote(changedNote, oldShares), /Authentication failed/);
  } finally {
    wipeShares(oldShares);
    wipeShares(newShares);
    restoreEnv(previous);
  }
});

test("password change of an unmigrated item still re-encrypts every field", () => {
  const previous = process.env[INTENTDB_ENVELOPE_ENV];
  process.env[INTENTDB_ENVELOPE_ENV] = "1";
  const oldShares = sharesFor(OLD_MASTER);
  const newShares = sharesFor(NEW_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), oldShares, undefined, false);
    assert.equal(entry.encryptedItemKey, undefined);
    const changed = vault.reEncryptEntry(entry, oldShares, newShares);
    assert.equal(changed.encryptedItemKey, undefined);
    assert.notEqual(changed.salt, entry.salt);
    assert.notEqual(changed.encryptedPassword, entry.encryptedPassword);
    assert.notEqual(changed.encryptedTitle, entry.encryptedTitle);
    assert.notEqual(changed.encryptedUsername, entry.encryptedUsername);
    assert.equal(vault.decryptVaultEntry(changed, newShares).password, PASSWORD);
    assert.throws(() => vault.decryptVaultEntry(changed, oldShares), /Authentication failed/);

    const note = vault.encryptSecureNote({ label: LABEL, content: CONTENT }, oldShares, undefined, false);
    const changedNote = vault.reEncryptSecureNote(note, oldShares, newShares);
    assert.equal(changedNote.encryptedItemKey, undefined);
    assert.notEqual(changedNote.encryptedContent, note.encryptedContent);
    assert.equal(vault.decryptSecureNote(changedNote, newShares).label, LABEL);
  } finally {
    wipeShares(oldShares);
    wipeShares(newShares);
    restoreEnv(previous);
  }
});

test("migration wraps the derived key once and is idempotent", () => {
  const shares = sharesFor(OLD_MASTER);
  try {
    const entry = vault.encryptVaultEntry(entryPlain(), shares, undefined, false);
    const once = vault.migrateVaultEntryEnvelope(entry, shares, { enabled: true, unlocked: true });
    const twice = vault.migrateVaultEntryEnvelope(once, shares, { enabled: true, unlocked: true });
    assert.equal(twice, once);
    assert.deepEqual(twice, once);
    assert.equal(once.encryptedPassword, entry.encryptedPassword);
    assert.equal(once.encryptedTitle, entry.encryptedTitle);
    assert.equal(once.encryptedUsername, entry.encryptedUsername);
    assert.equal(once.encryptedUrl, entry.encryptedUrl);
    assert.equal(once.notes, entry.notes);
    assert.equal(once.salt, entry.salt);
    assert.equal(once.updatedAt, entry.updatedAt);
    assert.equal(isAuthenticatedCiphertext(once.encryptedItemKey ?? ""), true);
    const derived = deriveEntryKey(OLD_MASTER, once.id, once.salt);
    assert.equal(
      decryptData(once.encryptedPassword, derived, { recordId: once.id, field: "password" }),
      PASSWORD,
    );
    assert.equal(vault.decryptVaultEntry(once, shares).password, PASSWORD);

    const manifest = buildVaultEntryManifest(once);
    assert.equal(
      manifest.fields.find((field) => field.name === "itemKey")?.ciphertext,
      once.encryptedItemKey,
    );
    const accepted = acceptOpaqueItemManifest({
      ...manifest,
      locator: "phone",
      tombstone: false,
      vaultKeyProof: "ef".repeat(32),
    });
    assert.equal(accepted.ok, true);

    const locked = vault.migrateVaultEntryEnvelope(entry, shares, { enabled: true, unlocked: false });
    assert.equal(locked, entry);
    const disabled = vault.migrateVaultEntryEnvelope(entry, shares, { enabled: false, unlocked: true });
    assert.equal(disabled, entry);

    const note = vault.encryptSecureNote({ label: LABEL, content: CONTENT }, shares, undefined, false);
    const noteOnce = vault.migrateSecureNoteEnvelope(note, shares, { enabled: true, unlocked: true });
    const noteTwice = vault.migrateSecureNoteEnvelope(noteOnce, shares, { enabled: true, unlocked: true });
    assert.equal(noteTwice, noteOnce);
    assert.equal(noteOnce.encryptedLabel, note.encryptedLabel);
    assert.equal(noteOnce.encryptedContent, note.encryptedContent);
    assert.equal(vault.decryptSecureNote(noteOnce, shares).label, LABEL);
    const noteManifest = buildSecureNoteManifest(noteOnce);
    assert.equal(
      noteManifest.fields.find((field) => field.name === "itemKey")?.ciphertext,
      noteOnce.encryptedItemKey,
    );
    const noteAccepted = acceptOpaqueItemManifest({
      ...noteManifest,
      locator: "phone",
      tombstone: false,
      vaultKeyProof: "ab".repeat(32),
    });
    assert.equal(noteAccepted.ok, true);
  } finally {
    wipeShares(shares);
  }
});

test("envelope helpers do not read vault shares and the server does not import them", () => {
  const envelope = readFileSync("crypto/itemEnvelope.ts", "utf8");
  const proof = readFileSync("server/itemManifestProof.ts", "utf8");
  const routes = readFileSync("server/routes.ts", "utf8");
  const proofImports = proof.split("\n").filter((line) => line.startsWith("import "));
  assert.equal(envelope.includes("vaultSession"), false);
  assert.equal(envelope.includes("getActiveKeyShares"), false);
  assert.equal(envelope.includes("pipass-entry-key"), false);
  assert.equal(envelope.includes("pipass-aes-gcm-v1"), false);
  assert.equal(proof.includes('"itemKey"'), true);
  assert.equal(proofImports.some((line) => line.includes("itemEnvelope")), false);
  assert.equal(proofImports.some((line) => line.includes("encryption")), false);
  assert.equal(proofImports.some((line) => line.includes("intentdb")), false);
  assert.equal(routes.includes("itemEnvelope"), false);
  assert.equal(routes.includes("encryptedItemKey"), false);
});
