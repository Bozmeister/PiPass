/**
 * Secret clipboard policy (P11 / V11).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  SECRET_CLIPBOARD_TTL_MS,
  clipboardDigest,
  copyPlain,
  copySecret,
  __flushPendingSecretWipeForTests,
  __resetSecureClipboardForTests,
  __setClipboardBridgeForTests,
  type ClipboardBridge,
} from "../secureClipboard";

function makeFakeClipboard(initial = ""): ClipboardBridge & { store: { text: string; options?: Record<string, unknown> } } {
  const store: { text: string; options?: Record<string, unknown> } = { text: initial };
  return {
    store,
    async setStringAsync(text: string, options?: Record<string, unknown>) {
      store.text = text;
      store.options = options;
      return true;
    },
    async getStringAsync() {
      return store.text;
    },
  };
}

test("clipboardDigest is stable and distinguishes values", () => {
  assert.equal(clipboardDigest("secret"), clipboardDigest("secret"));
  assert.notEqual(clipboardDigest("secret"), clipboardDigest("other"));
});

test("copySecret marks the clip sensitive and sets OS expiration", async () => {
  const fake = makeFakeClipboard();
  __setClipboardBridgeForTests(fake);
  __resetSecureClipboardForTests();
  try {
    await copySecret("hunter2");
    assert.equal(fake.store.text, "hunter2");
    assert.equal(fake.store.options?.isSensitive, true);
    assert.equal(fake.store.options?.expirationMs, SECRET_CLIPBOARD_TTL_MS);
  } finally {
    __resetSecureClipboardForTests();
    __setClipboardBridgeForTests(null);
  }
});

test("copySecret wipes the clipboard if it still holds the secret", async () => {
  const fake = makeFakeClipboard();
  __setClipboardBridgeForTests(fake);
  __resetSecureClipboardForTests();
  try {
    await copySecret("vault-password");
    await __flushPendingSecretWipeForTests();
    assert.equal(fake.store.text, "");
  } finally {
    __resetSecureClipboardForTests();
    __setClipboardBridgeForTests(null);
  }
});

test("copySecret does not wipe if the user copied something else", async () => {
  const fake = makeFakeClipboard();
  __setClipboardBridgeForTests(fake);
  __resetSecureClipboardForTests();
  try {
    await copySecret("vault-password");
    fake.store.text = "unrelated";
    await __flushPendingSecretWipeForTests();
    assert.equal(fake.store.text, "unrelated");
  } finally {
    __resetSecureClipboardForTests();
    __setClipboardBridgeForTests(null);
  }
});

test("copyPlain does not mark sensitive and is not auto-cleared", async () => {
  const fake = makeFakeClipboard();
  __setClipboardBridgeForTests(fake);
  __resetSecureClipboardForTests();
  try {
    await copyPlain("alice@example.com");
    assert.equal(fake.store.text, "alice@example.com");
    assert.equal(fake.store.options, undefined);
    await __flushPendingSecretWipeForTests();
    assert.equal(fake.store.text, "alice@example.com");
  } finally {
    __resetSecureClipboardForTests();
    __setClipboardBridgeForTests(null);
  }
});

test("copyPlain after copySecret cancels the pending secret wipe", async () => {
  const fake = makeFakeClipboard();
  __setClipboardBridgeForTests(fake);
  __resetSecureClipboardForTests();
  try {
    await copySecret("vault-password");
    await copyPlain("https://example.com");
    await __flushPendingSecretWipeForTests();
    assert.equal(fake.store.text, "https://example.com");
    assert.equal(fake.store.options, undefined);
  } finally {
    __resetSecureClipboardForTests();
    __setClipboardBridgeForTests(null);
  }
});
