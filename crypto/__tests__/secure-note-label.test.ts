/**
 * Secure note label confidentiality (C13 / V9).
 * Labels must not be stored in plaintext; only after decryption while unlocked.
 */
import assert from "node:assert/strict";
import Module from "node:module";
import test from "node:test";

const MASTER_KEY = "c3".repeat(32);

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

async function loadVaultCrypto() {
  const restore = installExpoCryptoStub();
  try {
    // Dynamic import after expo-crypto stub so vaultWorker's static import resolves.
    const vault = await import("../../workers/vaultWorker");
    const secure = await import("../secureMemory");
    return { vault, secure, restore };
  } catch (err) {
    restore();
    throw err;
  }
}

test("encryptSecureNote does not store plaintext label", async () => {
  const { vault, secure, restore } = await loadVaultCrypto();
  try {
    const shares = secure.splitKeyIntoShares(MASTER_KEY);
    try {
      const stored = vault.encryptSecureNote(
        { label: "Bank PIN sheet", content: "1234-seed-phrase" },
        shares,
      );
      assert.equal(stored.label, undefined);
      assert.equal(typeof stored.encryptedLabel, "string");
      assert.ok(stored.encryptedLabel.length > 0);
      assert.notEqual(stored.encryptedLabel, "Bank PIN sheet");
      assert.equal(JSON.stringify(stored).includes("Bank PIN sheet"), false);
      assert.equal(JSON.stringify(stored).includes("1234-seed-phrase"), false);
    } finally {
      secure.wipeShares(shares);
    }
  } finally {
    restore();
  }
});

test("decryptSecureNote recovers label only via decryption", async () => {
  const { vault, secure, restore } = await loadVaultCrypto();
  try {
    const shares = secure.splitKeyIntoShares(MASTER_KEY);
    try {
      const stored = vault.encryptSecureNote(
        { label: "Wi-Fi key", content: "super-secret" },
        shares,
      );
      const decrypted = vault.decryptSecureNote(stored, shares);
      assert.equal(decrypted.label, "Wi-Fi key");
      assert.equal(decrypted.content, "super-secret");
      assert.equal(vault.decryptSecureNoteLabel(stored, shares), "Wi-Fi key");
    } finally {
      secure.wipeShares(shares);
    }
  } finally {
    restore();
  }
});

test("legacy plaintext label still decrypts and migrates cleanly", async () => {
  const { vault, secure, restore } = await loadVaultCrypto();
  try {
    const shares = secure.splitKeyIntoShares(MASTER_KEY);
    try {
      const modern = vault.encryptSecureNote(
        { label: "Legacy title", content: "body" },
        shares,
      );
      const legacy = {
        ...modern,
        label: "Legacy title",
      };
      assert.equal(vault.secureNoteHasLegacyPlaintextLabel(legacy), true);
      assert.equal(vault.decryptSecureNoteLabel(legacy, shares), "Legacy title");

      const migrated = vault.migrateSecureNoteToEncryptedLabel(legacy, shares);
      assert.equal(vault.secureNoteHasLegacyPlaintextLabel(migrated), false);
      assert.equal(migrated.label, undefined);
      assert.equal(vault.decryptSecureNote(migrated, shares).label, "Legacy title");
      assert.equal(vault.decryptSecureNote(migrated, shares).content, "body");
    } finally {
      secure.wipeShares(shares);
    }
  } finally {
    restore();
  }
});

test("toStoredSecureNote strips plaintext label", async () => {
  const { vault, restore } = await loadVaultCrypto();
  try {
    const dirty = {
      id: "abc",
      label: "LEAKED",
      encryptedLabel: "v3:aa:bb:cc",
      encryptedContent: "v3:dd:ee:ff",
      salt: "11".repeat(16),
      createdAt: 1,
      updatedAt: 2,
    };
    const clean = vault.toStoredSecureNote(dirty);
    assert.equal(clean.label, undefined);
    assert.equal(JSON.stringify(clean).includes("LEAKED"), false);
    assert.equal(clean.encryptedLabel, dirty.encryptedLabel);
  } finally {
    restore();
  }
});
