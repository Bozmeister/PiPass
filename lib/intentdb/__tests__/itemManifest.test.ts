/**
 * Phase 1 IntentDB item manifests.
 * Encrypt with the current vault worker, hash ciphertext only, and refuse
 * records that are not authenticated v4.
 */
import assert from "node:assert/strict";
import Module from "node:module";
import test from "node:test";
import { decryptData, encryptData } from "../../../crypto/encryption";
import { deriveEntryKey } from "../../../crypto/hkdf";
import { splitKeyIntoShares, wipeShares } from "../../../crypto/secureMemory";
import {
  buildSecureNoteManifest,
  buildVaultEntryManifest,
  canonicalManifestBody,
  ItemManifestError,
  sha256Utf8Hex,
  verifyItemManifest,
  type ItemManifest,
} from "../itemManifest";
import type { SecureNote, VaultEntry } from "../../../workers/vaultWorker";

const MASTER_KEY = "c3".repeat(32);
const ENTRY_KEY = "a1".repeat(32);
const RECORD_ID = "entryid1234567";
const SALT = "ab".repeat(16);

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
    if (request === "react-native") {
      return {
        Platform: { OS: "web", select: (spec: { web?: unknown; default?: unknown }) => spec.web ?? spec.default },
        NativeModules: {},
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  return () => {
    moduleLoader._load = originalLoad;
  };
}

function fieldCiphertext(field: ItemManifest["fields"][number]["name"], plaintext: string): string {
  return encryptData(plaintext, ENTRY_KEY, { recordId: RECORD_ID, field });
}

function baseEntry(overrides: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id: RECORD_ID,
    salt: SALT,
    encryptedPassword: fieldCiphertext("password", "Plaintext-Password!"),
    encryptedTitle: fieldCiphertext("title", "Work Email"),
    encryptedUsername: fieldCiphertext("username", "ada@example.com"),
    createdAt: 10,
    updatedAt: 20,
    ...overrides,
  };
}

test("sha256Utf8Hex matches the known SHA-256 of abc", () => {
  assert.equal(
    sha256Utf8Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("vault entry manifest strips legacy plaintext and keeps v4 ciphertext", () => {
  const entry = baseEntry({
    title: "LEAKED TITLE",
    username: "leaked-user",
    url: "https://leak.example/secret",
    encryptedUrl: fieldCiphertext("url", "https://bank.example/login"),
    notes: fieldCiphertext("notes", "mother's maiden name"),
  });
  const manifest = buildVaultEntryManifest(entry);
  const encoded = JSON.stringify(manifest);

  assert.equal(manifest.schema, "pipass-item-v1");
  assert.equal(manifest.kind, "vault-entry");
  assert.equal(manifest.version, 20);
  assert.equal(verifyItemManifest(manifest), true);
  assert.equal(encoded.includes("LEAKED TITLE"), false);
  assert.equal(encoded.includes("leaked-user"), false);
  assert.equal(encoded.includes("https://leak.example/secret"), false);
  assert.equal(encoded.includes("Plaintext-Password!"), false);
  assert.equal(encoded.includes("Work Email"), false);
  assert.equal(encoded.includes("ada@example.com"), false);
  assert.equal(encoded.includes("https://bank.example/login"), false);
  assert.equal(encoded.includes("mother's maiden name"), false);
  assert.equal(encoded.includes("wrappedItemKey"), false);
  assert.equal(
    manifest.fields.find((field) => field.name === "password")?.ciphertext,
    entry.encryptedPassword,
  );
  assert.deepEqual(
    manifest.fields.map((field) => field.name),
    ["notes", "password", "title", "url", "username"],
  );
});

test("canonical manifest hash ignores field order", () => {
  const manifest = buildVaultEntryManifest(baseEntry());
  const reversed = canonicalManifestBody({
    schema: manifest.schema,
    itemId: manifest.itemId,
    kind: manifest.kind,
    version: manifest.version,
    salt: manifest.salt,
    createdAt: manifest.createdAt,
    updatedAt: manifest.updatedAt,
    fields: [...manifest.fields].reverse(),
  });
  assert.equal(sha256Utf8Hex(reversed), manifest.contentSha256);
});

test("tampered manifest ciphertext fails verification", () => {
  const manifest = buildVaultEntryManifest(baseEntry());
  const password = manifest.fields.find((field) => field.name === "password");
  assert.ok(password);
  password.ciphertext = `${password.ciphertext.slice(0, -1)}${password.ciphertext.endsWith("a") ? "b" : "a"}`;
  assert.equal(verifyItemManifest(manifest), false);
});

test("legacy and missing ciphertext are refused", () => {
  assert.throws(
    () =>
      buildVaultEntryManifest(
        baseEntry({
          encryptedPassword: "aabbcc:ddeeff",
        }),
      ),
    (err: unknown) => err instanceof ItemManifestError && err.code === "unauthenticated-ciphertext",
  );
  assert.throws(
    () =>
      buildVaultEntryManifest(
        baseEntry({
          encryptedTitle: undefined,
          title: "only plaintext",
        }),
      ),
    (err: unknown) => err instanceof ItemManifestError && err.code === "missing-ciphertext",
  );
  assert.throws(
    () =>
      buildVaultEntryManifest(
        baseEntry({
          notes: "plaintext note",
        }),
      ),
    (err: unknown) => err instanceof ItemManifestError && err.code === "unauthenticated-ciphertext",
  );
  assert.throws(
    () => buildVaultEntryManifest(baseEntry({ salt: "not-hex" })),
    (err: unknown) => err instanceof ItemManifestError && err.code === "invalid-salt",
  );
});

test("secure note manifest strips a legacy label", () => {
  const note: SecureNote = {
    id: "noteid123456789",
    salt: SALT,
    encryptedLabel: encryptData("Tax Folder", ENTRY_KEY, {
      recordId: "noteid123456789",
      field: "label",
    }),
    encryptedContent: encryptData("Note-Content-Secret!", ENTRY_KEY, {
      recordId: "noteid123456789",
      field: "content",
    }),
    label: "Tax Folder",
    createdAt: 1,
    updatedAt: 2,
  };
  const manifest = buildSecureNoteManifest(note);
  const encoded = JSON.stringify(manifest);
  assert.equal(manifest.kind, "secure-note");
  assert.equal(verifyItemManifest(manifest), true);
  assert.equal(encoded.includes("Tax Folder"), false);
  assert.equal(encoded.includes("Note-Content-Secret!"), false);
  assert.equal(encoded.includes('"label":"Tax Folder"'), false);
});

test("encrypt with vaultWorker round-trips through the manifest", async () => {
  const restore = installExpoCryptoStub();
  try {
    const vault = await import("../../../workers/vaultWorker");
    const shares = splitKeyIntoShares(MASTER_KEY);
    try {
      const password = "Plaintext-Password!";
      const title = "Work Email";
      const username = "ada@example.com";
      const url = "https://bank.example/login";
      const notes = "mother's maiden name";
      const marker = "MARKER-not-hex";
      const entry = vault.encryptVaultEntry(
        {
          title,
          username,
          password,
          url,
          notes,
          isHoneytoken: true,
          honeytokenId: "honeytoken-1",
          honeytokenMarker: marker,
        },
        shares,
      );
      const leaked: VaultEntry = {
        ...entry,
        title: "LEAKED TITLE",
        username: "leaked-user",
        url: "https://leak.example",
      };
      const manifest = buildVaultEntryManifest(leaked);
      const encoded = JSON.stringify(manifest);

      const decrypted = vault.decryptVaultEntry(entry, shares);
      assert.equal(decrypted.password, password);
      assert.equal(decrypted.title, title);
      assert.equal(decrypted.username, username);
      assert.equal(decrypted.url, url);
      assert.equal(decrypted.notes, notes);
      assert.equal(decrypted.honeytokenMarker, marker);

      assert.equal(encoded.includes(password), false);
      assert.equal(encoded.includes(title), false);
      assert.equal(encoded.includes(username), false);
      assert.equal(encoded.includes(url), false);
      assert.equal(encoded.includes(notes), false);
      assert.equal(encoded.includes(marker), false);
      assert.equal(encoded.includes("LEAKED TITLE"), false);
      assert.equal(encoded.includes(MASTER_KEY), false);

      const entryKey = deriveEntryKey(MASTER_KEY, entry.id, entry.salt);
      for (const field of manifest.fields) {
        const source = field.name === "password"
          ? entry.encryptedPassword
          : field.name === "title"
            ? entry.encryptedTitle
            : field.name === "username"
              ? entry.encryptedUsername
              : field.name === "url"
                ? entry.encryptedUrl
                : field.name === "notes"
                  ? entry.notes
                  : entry.encryptedAux;
        assert.equal(field.ciphertext, source);
        const plain = decryptData(field.ciphertext, entryKey, {
          recordId: entry.id,
          field: field.name,
        });
        if (field.name === "aux") {
          assert.equal(plain.includes(marker), true);
          assert.equal(encoded.includes(marker), false);
        }
      }
    } finally {
      wipeShares(shares);
    }
  } finally {
    restore();
  }
});
