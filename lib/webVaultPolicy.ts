/**
 * Web vault policy (V3).
 *
 * PiPass is a native mobile password manager. Browsers have no
 * SecureStore/Keychain equivalent: localStorage is readable by XSS,
 * extensions, DevTools, and anyone with the profile. Do not store
 * vault material there, and do not offer setup/unlock on web.
 */

import { Platform } from "react-native";

export const WEB_VAULT_DISABLED_TITLE = "PiPass is a native mobile app";

export const WEB_VAULT_DISABLED_MESSAGE =
  "The password vault is not available in a web browser. Browsers cannot protect vault data the way iOS and Android can.";

export const WEB_VAULT_DISABLED_DETAIL =
  "Page scripts, extensions, and anyone with access to this browser could copy a web-stored vault. Use the PiPass iOS or Android app. Nothing is stored in this browser.";

const EXACT_PURGE_KEYS = ["deviceUUID"];

export class WebVaultStorageError extends Error {
  constructor(operation: string) {
    super(
      `PiPass vault storage is disabled on web (${operation}). Use the iOS or Android app.`,
    );
    this.name = "WebVaultStorageError";
  }
}

/** True on the Expo web runtime. Native iOS/Android are unaffected. */
export function isWebVaultDisabled(): boolean {
  return Platform.OS === "web";
}

export function isPiPassStorageKey(key: string): boolean {
  return (
    key.startsWith("pipass_") ||
    key.startsWith("pipass.") ||
    EXACT_PURGE_KEYS.includes(key)
  );
}

function getBrowserLocalStorage(): Storage | null {
  try {
    if (typeof localStorage === "undefined" || !localStorage) return null;
    return localStorage;
  } catch {
    return null;
  }
}

/**
 * Remove leftover PiPass keys from browser localStorage.
 * The only allowed web storage mutation — cleanup, never persist.
 */
export function purgeLegacyWebVaultStorage(): number {
  const store = getBrowserLocalStorage();
  if (!store) return 0;

  const toRemove: string[] = [];
  try {
    for (let i = 0; i < store.length; i++) {
      const key = store.key(i);
      if (key && isPiPassStorageKey(key)) {
        toRemove.push(key);
      }
    }
  } catch {
    return 0;
  }

  let removed = 0;
  for (const key of toRemove) {
    try {
      store.removeItem(key);
      removed += 1;
    } catch {
      // Best-effort wipe.
    }
  }
  return removed;
}

/** Delete one leftover key if the browser still has it. */
export function deleteLegacyWebStorageKey(key: string): void {
  const store = getBrowserLocalStorage();
  if (!store) return;
  try {
    store.removeItem(key);
  } catch {
    // Best-effort wipe.
  }
}
