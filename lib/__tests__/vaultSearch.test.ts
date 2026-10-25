/**
 * Local encrypted search index.
 * Round-trip, id search for derived and wrapped keys, sort, and locked read.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Module from "node:module";
import { after, before, test } from "node:test";
import { splitKeyIntoShares, wipeShares, type KeyShares } from "../../crypto/secureMemory";
import { setPlatformStorageDriverForTests } from "../platformStorage";
import {
  SEARCH_HKDF_INFO,
  deriveSearchKey,
  openSearchIndex,
  querySearchIndex,
  sealSearchIndex,
  visibleVaultEntries,
  type SearchIndexPlain,
  type SearchRecord,
} from "../vaultSearch";
import { SEARCH_INDEX_STORAGE_KEY } from "../vaultSearchKey";
import type * as VaultSearchStore from "../vaultSearchStore";
import type * as VaultWorker from "../../workers/vaultWorker";

const MASTER = "ab".repeat(32);
const OTHER = "cd".repeat(32);
const DERIVED_TITLE = "Derived-Bank-Title";
const WRAPPED_TITLE = "Wrapped-Bank-Title";
const NOTE_LABEL = "Wifi-Note-Label";
const SECRET_NOTES = "Entry-Notes-Secret";

function installExpoCryptoStub(): () => void {
  const moduleLoader = Module as unknown as {
    _load: (request: string, parent: unknown, isMain: boolean) => unknown;
  };
  const originalLoad = moduleLoader._load;
  let counter = 0;
  moduleLoader._load = function patchedLoad(request: string, parent: unknown, isMain: boolean) {
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

function memoryDriver() {
  const items = new Map<string, string>();
  let reads = 0;
  setPlatformStorageDriverForTests({
    getItem: async (key) => {
      reads += 1;
      return items.get(key) ?? null;
    },
    setItem: async (key, value) => {
      items.set(key, value);
    },
    deleteItem: async (key) => {
      items.delete(key);
    },
    isWeb: () => false,
  });
  return {
    items,
    reads: () => reads,
    resetReads: () => {
      reads = 0;
    },
  };
}

let restoreExpo: () => void = () => {};
let store: typeof VaultSearchStore;
let vault: typeof VaultWorker;

before(async () => {
  restoreExpo = installExpoCryptoStub();
  store = await import("../vaultSearchStore");
  vault = await import("../../workers/vaultWorker");
});

after(() => {
  restoreExpo();
  setPlatformStorageDriverForTests(null);
});

function sharesFor(master: string): KeyShares {
  return splitKeyIntoShares(master);
}

function record(partial: Partial<SearchRecord> & Pick<SearchRecord, "id" | "kind" | "title">): SearchRecord {
  return {
    username: "",
    url: "",
    notes: "",
    label: "",
    ...partial,
  };
}

test("search key info is pipass-search-v1 and the sealed index round-trips", () => {
  const shares = sharesFor(MASTER);
  try {
    assert.equal(SEARCH_HKDF_INFO, "pipass-search-v1");
    assert.equal(deriveSearchKey(MASTER), deriveSearchKey(MASTER));
    assert.notEqual(deriveSearchKey(MASTER), deriveSearchKey(OTHER));
    const index: SearchIndexPlain = {
      v: 1,
      records: [
        record({
          id: "e1",
          kind: "vault-entry",
          title: DERIVED_TITLE,
          username: "ada",
          url: "https://derived.example",
          notes: SECRET_NOTES,
        }),
      ],
    };
    const sealed = sealSearchIndex(index, shares);
    assert.match(sealed, /^v4:/);
    assert.equal(sealed.includes(DERIVED_TITLE), false);
    assert.equal(sealed.includes(SECRET_NOTES), false);
    assert.equal(sealed.includes(MASTER), false);
    const opened = openSearchIndex(sealed, shares);
    assert.equal(opened.ok, true);
    if (opened.ok) assert.deepEqual(opened.index, index);
    const other = sharesFor(OTHER);
    try {
      assert.deepEqual(openSearchIndex(sealed, other), { ok: false, reason: "unreadable" });
    } finally {
      wipeShares(other);
    }
  } finally {
    wipeShares(shares);
  }
});

test("locked open does not decrypt and a locked load does not read storage", async () => {
  const shares = sharesFor(MASTER);
  const driver = memoryDriver();
  try {
    const index: SearchIndexPlain = {
      v: 1,
      records: [record({ id: "e1", kind: "vault-entry", title: DERIVED_TITLE, notes: SECRET_NOTES })],
    };
    assert.deepEqual(openSearchIndex(sealSearchIndex(index, shares), null), { ok: false, reason: "locked" });
    await store.persistSearchIndex(index, shares);
    const stored = [...driver.items.values()].join("\n");
    assert.equal(stored.includes(DERIVED_TITLE), false);
    assert.equal(stored.includes(SECRET_NOTES), false);
    assert.equal(stored.includes(MASTER), false);
    driver.resetReads();
    assert.deepEqual(await store.loadSearchIndex(null), { ok: false, reason: "locked" });
    assert.equal(driver.reads(), 0);
    const loaded = await store.loadSearchIndex(shares);
    assert.equal(loaded.ok, true);
    if (loaded.ok) assert.equal(loaded.index.records[0]?.title, DERIVED_TITLE);
  } finally {
    wipeShares(shares);
    setPlatformStorageDriverForTests(null);
  }
});

test("search returns ids for derived and wrapped keys, including notes labels", () => {
  const shares = sharesFor(MASTER);
  try {
    const derived = vault.encryptVaultEntry(
      {
        title: DERIVED_TITLE,
        username: "derived-user",
        password: "pw-derived",
        url: "https://derived.example/login",
        notes: SECRET_NOTES,
      },
      shares,
      undefined,
      false,
    );
    const wrapped = vault.encryptVaultEntry(
      {
        title: WRAPPED_TITLE,
        username: "wrapped-user",
        password: "pw-wrapped",
        url: "https://wrapped.example/login",
        notes: "wrapped-notes",
      },
      shares,
      undefined,
      true,
    );
    const note = vault.encryptSecureNote({ label: NOTE_LABEL, content: "note-body" }, shares, undefined, true);
    assert.equal(derived.encryptedItemKey, undefined);
    assert.equal(typeof wrapped.encryptedItemKey, "string");
    const index = store.buildSearchIndex([derived, wrapped], [note], shares);
    assert.deepEqual(querySearchIndex(index, "derived-user", "none"), [derived.id]);
    assert.deepEqual(querySearchIndex(index, "wrapped.example", "none"), [wrapped.id]);
    assert.deepEqual(querySearchIndex(index, SECRET_NOTES, "none"), [derived.id]);
    assert.deepEqual(querySearchIndex(index, NOTE_LABEL, "none"), [note.id]);
    assert.deepEqual(querySearchIndex(index, "bank-title", "none").sort(), [derived.id, wrapped.id].sort());
    const sealed = sealSearchIndex(index, shares);
    assert.equal(sealed.includes(DERIVED_TITLE), false);
    assert.equal(sealed.includes(WRAPPED_TITLE), false);
    assert.equal(sealed.includes(NOTE_LABEL), false);
    assert.equal(sealed.includes("pw-derived"), false);
    assert.equal(sealed.includes("pw-wrapped"), false);
  } finally {
    wipeShares(shares);
  }
});

test("sort order is none, A-Z, then Z-A, and the list filter uses the index", () => {
  const index: SearchIndexPlain = {
    v: 1,
    records: [
      record({ id: "c", kind: "vault-entry", title: "citrus" }),
      record({ id: "a", kind: "vault-entry", title: "Apple" }),
      record({ id: "b", kind: "vault-entry", title: "banana" }),
    ],
  };
  assert.deepEqual(querySearchIndex(index, "", "none"), ["c", "a", "b"]);
  assert.deepEqual(querySearchIndex(index, "", "az"), ["a", "b", "c"]);
  assert.deepEqual(querySearchIndex(index, "", "za"), ["c", "b", "a"]);

  const entries = [
    { id: "c", encryptedPassword: "v4:cipher", salt: "00", createdAt: 3, updatedAt: 3, title: "LEAKED-C" },
    { id: "a", encryptedPassword: "v4:cipher", salt: "00", createdAt: 1, updatedAt: 1, title: "LEAKED-A" },
    { id: "b", encryptedPassword: "v4:cipher", salt: "00", createdAt: 2, updatedAt: 2, title: "LEAKED-B" },
  ];
  const visible = visibleVaultEntries(entries, index, "app", "az");
  assert.deepEqual(visible.map((entry) => entry.id), ["a"]);
  assert.equal(visible[0]?.title, "Apple");
  assert.equal(JSON.stringify(visible).includes("LEAKED-A"), false);
  const unsorted = visibleVaultEntries(entries, index, "", "none");
  assert.deepEqual(unsorted.map((entry) => entry.id), ["c", "a", "b"]);
  assert.equal(visibleVaultEntries(entries, null, "app", "az"), entries);
});

test("stored index chunks stay ciphertext and clearVault removes them", async () => {
  const shares = sharesFor(MASTER);
  const driver = memoryDriver();
  try {
    const entry = vault.encryptVaultEntry(
      {
        title: DERIVED_TITLE,
        username: "ada",
        password: "pw",
        url: "https://bank.example",
        notes: "n".repeat(4000),
      },
      shares,
      undefined,
      false,
    );
    const index = store.buildSearchIndex([entry], [], shares);
    await store.persistSearchIndex(index, shares);
    assert.equal(driver.items.has(SEARCH_INDEX_STORAGE_KEY), true);
    assert.ok([...driver.items.keys()].some((key) => key.startsWith(`${SEARCH_INDEX_STORAGE_KEY}_`)));
    for (const value of driver.items.values()) {
      assert.equal(value.includes(DERIVED_TITLE), false);
      assert.equal(value.includes("n".repeat(80)), false);
    }
    const loaded = await store.loadSearchIndex(shares);
    assert.equal(loaded.ok, true);
    if (loaded.ok) {
      assert.equal(loaded.index.records[0]?.title, DERIVED_TITLE);
      assert.equal(loaded.index.records[0]?.notes.length, 4000);
    }
    const storage = await import("../../workers/storageWorker");
    await storage.clearVault();
    assert.equal(driver.items.has(SEARCH_INDEX_STORAGE_KEY), false);
    assert.equal([...driver.items.keys()].some((key) => key.startsWith(SEARCH_INDEX_STORAGE_KEY)), false);
  } finally {
    wipeShares(shares);
    setPlatformStorageDriverForTests(null);
  }
});

test("search helpers do not read vault shares or call the server", () => {
  const source = readFileSync("lib/vaultSearch.ts", "utf8");
  const storeSource = readFileSync("lib/vaultSearchStore.ts", "utf8");
  assert.equal(source.includes("vaultSession"), false);
  assert.equal(source.includes("getActiveKeyShares"), false);
  assert.equal(source.includes("/api/"), false);
  assert.equal(source.includes("pipass-entry-key"), false);
  assert.equal(source.includes("pipass-item-wrap-v1"), false);
  assert.equal(storeSource.includes("vaultSession"), false);
  assert.equal(storeSource.includes("getActiveKeyShares"), false);
  assert.equal(readFileSync("screens/VaultScreen.tsx", "utf8").includes("visibleVaultEntries"), true);
});
