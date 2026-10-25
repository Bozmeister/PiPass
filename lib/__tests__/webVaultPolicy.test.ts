/**
 * Web vault disablement (V3): no localStorage vault, fail-closed writes.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  deleteLegacyWebStorageKey,
  isPiPassStorageKey,
  isWebVaultDisabled,
  purgeLegacyWebVaultStorage,
  WEB_VAULT_DISABLED_MESSAGE,
  WEB_VAULT_DISABLED_TITLE,
  WebVaultStorageError,
} from "../webVaultPolicy";
import {
  deletePlatformItem,
  isWebStoragePlatform,
  readPlatformItem,
  setPlatformStorageDriverForTests,
  writePlatformItem,
} from "../platformStorage";

type FakeStorage = Storage & { _data: Record<string, string> };

function installFakeLocalStorage(initial: Record<string, string> = {}): {
  storage: FakeStorage;
  restore: () => void;
} {
  const data: Record<string, string> = { ...initial };
  const storage = {
    _data: data,
    getItem(key: string) {
      return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null;
    },
    setItem(key: string, value: string) {
      data[key] = String(value);
    },
    removeItem(key: string) {
      delete data[key];
    },
    key(index: number) {
      return Object.keys(data)[index] ?? null;
    },
    clear() {
      for (const key of Object.keys(data)) delete data[key];
    },
    get length() {
      return Object.keys(data).length;
    },
  } as FakeStorage;

  const previousDescriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", {
    value: storage,
    configurable: true,
    writable: true,
  });

  return {
    storage,
    restore() {
      if (previousDescriptor) {
        Object.defineProperty(globalThis, "localStorage", previousDescriptor);
      } else {
        Reflect.deleteProperty(globalThis, "localStorage");
      }
    },
  };
}

test("isWebVaultDisabled is true in the Node/web test environment", () => {
  assert.equal(isWebVaultDisabled(), true);
});

test("isPiPassStorageKey matches vault, auth, and device UUID keys only", () => {
  assert.equal(isPiPassStorageKey("pipass_vault_index"), true);
  assert.equal(isPiPassStorageKey("pipass_master_salt"), true);
  assert.equal(isPiPassStorageKey("pipass_kdf_metadata"), true);
  assert.equal(isPiPassStorageKey("pipass.auth.authHash"), true);
  assert.equal(isPiPassStorageKey("pipass.installId"), true);
  assert.equal(isPiPassStorageKey("deviceUUID"), true);
  assert.equal(isPiPassStorageKey("theme"), false);
  assert.equal(isPiPassStorageKey("unrelated"), false);
});

test("purgeLegacyWebVaultStorage removes PiPass keys and leaves other keys", () => {
  const { storage, restore } = installFakeLocalStorage({
    pipass_vault_index: '["abc"]',
    pipass_master_salt: "aa".repeat(16),
    pipass_kdf_metadata: "{}",
    "pipass.auth.authHash": "ff".repeat(32),
    deviceUUID: "uuid-1",
    theme: "dark",
  });
  try {
    const removed = purgeLegacyWebVaultStorage();
    assert.equal(removed, 5);
    assert.equal(storage.getItem("theme"), "dark");
    assert.equal(storage.getItem("pipass_vault_index"), null);
    assert.equal(storage.getItem("deviceUUID"), null);
    assert.equal(storage.getItem("pipass.auth.authHash"), null);
  } finally {
    restore();
  }
});

test("disabled-screen copy is honest that the vault is native-only", () => {
  assert.match(WEB_VAULT_DISABLED_TITLE, /native mobile app/i);
  assert.match(WEB_VAULT_DISABLED_MESSAGE, /not available in a web browser/i);
});

test("web platform storage never reads leftover localStorage vault data", async () => {
  setPlatformStorageDriverForTests(null);
  const { storage, restore } = installFakeLocalStorage({
    pipass_vault_index: '["abc"]',
    pipass_master_hash: "deadbeef",
  });
  try {
    assert.equal(await isWebStoragePlatform(), true);
    const value = await readPlatformItem("pipass_vault_index");
    assert.equal(value, null);
    assert.equal(storage.getItem("pipass_vault_index"), null);
    assert.equal(storage.getItem("pipass_master_hash"), null);
  } finally {
    restore();
    setPlatformStorageDriverForTests(null);
  }
});

test("web platform storage refuses writes and does not persist", async () => {
  setPlatformStorageDriverForTests(null);
  const { storage, restore } = installFakeLocalStorage();
  try {
    await assert.rejects(
      () => writePlatformItem("pipass_master_salt", "aa".repeat(16)),
      (err: unknown) => {
        assert.ok(err instanceof WebVaultStorageError);
        return true;
      },
    );
    assert.equal(storage.getItem("pipass_master_salt"), null);
    assert.equal(storage.length, 0);
  } finally {
    restore();
    setPlatformStorageDriverForTests(null);
  }
});

test("web platform storage delete only removes leftover keys", async () => {
  setPlatformStorageDriverForTests(null);
  const { storage, restore } = installFakeLocalStorage({
    pipass_notes_index: "[]",
    theme: "dark",
  });
  try {
    await deletePlatformItem("pipass_notes_index");
    assert.equal(storage.getItem("pipass_notes_index"), null);
    assert.equal(storage.getItem("theme"), "dark");
    deleteLegacyWebStorageKey("theme");
    assert.equal(storage.getItem("theme"), null);
  } finally {
    restore();
    setPlatformStorageDriverForTests(null);
  }
});

test("injected native test driver is not treated as web storage", async () => {
  const mem = new Map<string, string>();
  setPlatformStorageDriverForTests({
    getItem: (key) => mem.get(key) ?? null,
    setItem: (key, value) => {
      mem.set(key, value);
    },
    deleteItem: (key) => {
      mem.delete(key);
    },
    isWeb: () => false,
  });
  try {
    assert.equal(await isWebStoragePlatform(), false);
    await writePlatformItem("pipass_master_salt", "native-ok");
    assert.equal(await readPlatformItem("pipass_master_salt"), "native-ok");
  } finally {
    setPlatformStorageDriverForTests(null);
  }
});
