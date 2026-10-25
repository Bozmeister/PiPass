/**
 * Clipboard writes for vault data.
 *
 * Secrets (passwords, secure notes) are marked sensitive where the OS
 * supports it (Android ClipDescription.EXTRA_IS_SENSITIVE; iOS
 * UIPasteboard localOnly + expiration). A module-level timer then
 * wipes the clip after SECRET_CLIPBOARD_TTL_MS if it still holds our
 * value. The timer is not owned by a React component so unmount cannot
 * cancel the wipe.
 *
 * Non-secrets (username, URL) use a plain write with no flag and no TTL.
 */

import { AppState } from "react-native";

export const SECRET_CLIPBOARD_TTL_MS = 30_000;

export type ClipboardBridge = {
  setStringAsync: (text: string, options?: Record<string, unknown>) => Promise<boolean | void>;
  getStringAsync: () => Promise<string>;
};

let injectedBridge: ClipboardBridge | null = null;
let nativeBridge: ClipboardBridge | null | undefined;
let clearTimer: ReturnType<typeof setTimeout> | null = null;
let pendingDigest: string | null = null;
let writeGeneration = 0;
let appStateSub: { remove: () => void } | null = null;

function loadNativeBridge(): ClipboardBridge {
  if (nativeBridge !== undefined) {
    if (!nativeBridge) {
      throw new Error("expo-clipboard unavailable");
    }
    return nativeBridge;
  }
  try {
    // Lazy require keeps Node tests from loading the native module.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    nativeBridge = require("expo-clipboard") as ClipboardBridge;
  } catch {
    nativeBridge = null;
    throw new Error("expo-clipboard unavailable");
  }
  return nativeBridge;
}

function getBridge(): ClipboardBridge {
  return injectedBridge ?? loadNativeBridge();
}

/** Equality token only — not a cryptographic boundary. */
export function clipboardDigest(value: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

function cancelScheduledClear(): void {
  if (clearTimer) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
  pendingDigest = null;
}

function ensureAppStateListener(): void {
  if (appStateSub) return;
  const add = AppState?.addEventListener;
  if (typeof add !== "function") return;
  appStateSub = add("change", (next) => {
    if (next === "active" && pendingDigest && !clearTimer) {
      void wipeIfStillOurs(writeGeneration);
    }
  });
}

async function wipeIfStillOurs(generation: number): Promise<void> {
  if (generation !== writeGeneration) return;
  const expected = pendingDigest;
  if (expected == null) return;

  let current: string;
  try {
    current = await getBridge().getStringAsync();
  } catch {
    // Android 10+ may refuse clipboard reads in the background.
    // Keep pendingDigest so a later foreground retry can finish the wipe.
    return;
  }

  if (generation !== writeGeneration || pendingDigest !== expected) return;
  if (clipboardDigest(current) !== expected) {
    pendingDigest = null;
    return;
  }

  try {
    await getBridge().setStringAsync("");
  } catch {
    return;
  }

  if (generation === writeGeneration) {
    pendingDigest = null;
  }
}

function scheduleSecretWipe(value: string): void {
  cancelScheduledClear();
  const generation = ++writeGeneration;
  pendingDigest = clipboardDigest(value);
  ensureAppStateListener();
  clearTimer = setTimeout(() => {
    clearTimer = null;
    void wipeIfStillOurs(generation);
  }, SECRET_CLIPBOARD_TTL_MS);
}

/**
 * Copy a password, secure note, or other secret.
 * Marks the clip sensitive when native support is present, then auto-clears.
 */
export async function copySecret(value: string): Promise<void> {
  await getBridge().setStringAsync(value, {
    isSensitive: true,
    expirationMs: SECRET_CLIPBOARD_TTL_MS,
  });
  scheduleSecretWipe(value);
}

/**
 * Copy a non-secret field (username, URL). No sensitive flag, no auto-clear.
 * Cancels a pending secret wipe so we do not erase the user's new clip.
 */
export async function copyPlain(value: string): Promise<void> {
  cancelScheduledClear();
  writeGeneration += 1;
  await getBridge().setStringAsync(value);
}

/** Test seam. Pass null to restore the real expo-clipboard module. */
export function __setClipboardBridgeForTests(bridge: ClipboardBridge | null): void {
  injectedBridge = bridge;
}

/** Test seam — drop timers and pending wipe state. */
export function __resetSecureClipboardForTests(): void {
  if (clearTimer) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
  pendingDigest = null;
  writeGeneration += 1;
}

/** Test seam — run the pending wipe immediately (does not wait for TTL). */
export async function __flushPendingSecretWipeForTests(): Promise<void> {
  if (clearTimer) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
  await wipeIfStillOurs(writeGeneration);
}
