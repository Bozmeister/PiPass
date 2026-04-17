import { NativeModules, Platform } from "react-native";

/**
 * JS bridge for the Android Autofill native module
 * (`com.pipass.app.autofill.PiPassAutofillModule`).
 *
 * This is plumbing only — the underlying Kotlin module currently returns
 * stub values ("[]" / false). Once the vault integration lands, the same
 * surface will return real entries.
 *
 * Calling these on iOS or web is a no-op: `getVaultEntriesForAutofill`
 * resolves to "[]" and `isVaultUnlocked` returns `false`.
 */

export interface AutofillVaultEntry {
  id: string;
  name: string;
  username: string;
  password: string;
  url: string;
}

interface PiPassAutofillModuleSpec {
  getVaultEntriesForAutofill(): Promise<string>;
  isVaultUnlocked(): boolean;
}

const NativeAutofill: PiPassAutofillModuleSpec | undefined =
  Platform.OS === "android"
    ? (NativeModules.PiPassAutofillModule as PiPassAutofillModuleSpec | undefined)
    : undefined;

function warnUnavailable(method: string): void {
  if (__DEV__) {
    // eslint-disable-next-line no-console
    console.warn(
      `[AutofillBridge] PiPassAutofillModule not available on ${Platform.OS}; ` +
        `${method} is a no-op stub.`,
    );
  }
}

/**
 * Returns the raw JSON string from the native module. Useful when forwarding
 * to other native code without paying the parse/serialize cost.
 */
export async function getVaultEntriesJsonForAutofill(): Promise<string> {
  if (!NativeAutofill) {
    warnUnavailable("getVaultEntriesForAutofill");
    return "[]";
  }
  try {
    return await NativeAutofill.getVaultEntriesForAutofill();
  } catch (err) {
    if (__DEV__) {
      // eslint-disable-next-line no-console
      console.warn("[AutofillBridge] getVaultEntriesForAutofill failed", err);
    }
    return "[]";
  }
}

/**
 * Convenience wrapper that parses the JSON returned by the native module
 * into typed entries. Returns an empty array on parse failure.
 */
export async function getVaultEntriesForAutofill(): Promise<AutofillVaultEntry[]> {
  const json = await getVaultEntriesJsonForAutofill();
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? (parsed as AutofillVaultEntry[]) : [];
  } catch (err) {
    if (__DEV__) {
      // eslint-disable-next-line no-console
      console.warn("[AutofillBridge] failed to parse vault JSON", err);
    }
    return [];
  }
}

/**
 * Synchronous check of vault lock state. Always `false` on iOS/web.
 */
export function isVaultUnlocked(): boolean {
  if (!NativeAutofill) {
    warnUnavailable("isVaultUnlocked");
    return false;
  }
  try {
    return NativeAutofill.isVaultUnlocked();
  } catch (err) {
    if (__DEV__) {
      // eslint-disable-next-line no-console
      console.warn("[AutofillBridge] isVaultUnlocked failed", err);
    }
    return false;
  }
}

export const AutofillBridge = {
  getVaultEntriesForAutofill,
  getVaultEntriesJsonForAutofill,
  isVaultUnlocked,
};

export default AutofillBridge;
