import { NativeModules, Platform } from "react-native";
import {
  decryptVaultEntry,
  deriveMasterKeyShares,
  type VaultEntry,
} from "../workers/vaultWorker";
import {
  wipeShares,
  type KeyShares,
} from "../crypto/secureMemory";
import { requireFreshBiometric } from "../crypto/biometricGate";

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

/* -------------------------------------------------------------------------- */
/* JS-side vault integration                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Minimal payload returned to the autofill layer. Intentionally narrow:
 * no titles, no notes, no timestamps — only what's needed to fill a form.
 */
export interface AutofillPayloadEntry {
  id: string;
  domain: string;
  username: string;
  password: string;
}

export interface PrepareAutofillPayloadOptions {
  /** Encrypted vault entries (typically loaded via storageWorker). */
  entries: VaultEntry[];
  /**
   * Pre-derived key shares from an active vault session. Preferred path:
   * the unlocked vault already holds these in memory and passes them in.
   *
   * Ownership: caller-provided shares are NOT wiped by this function —
   * the caller retains ownership and must wipe them via `wipeShares` in
   * its own `finally` block, even if this function throws (e.g. on a
   * cancelled biometric prompt).
   */
  shares?: KeyShares;
  /**
   * Fallback derivation inputs. Used only when `shares` is not provided
   * (e.g. background autofill flow with no live session). The derived
   * shares are wiped before this function returns.
   */
  password?: string;
  salt?: string;
  iterations?: number;
  /**
   * Whether to require a fresh biometric before decrypting. Defaults to
   * true; pass false only when the caller has *just* completed a fresh
   * biometric gate itself (e.g. inside biometricDecryptGuard).
   */
  requireBiometric?: boolean;
}

function extractDomain(value: string | undefined | null): string {
  if (!value) return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const u = new URL(withProto);
    return u.hostname.replace(/^www\./i, "").toLowerCase();
  } catch {
    return trimmed
      .toLowerCase()
      .replace(/^https?:\/\//i, "")
      .replace(/^www\./i, "")
      .split("/")[0]
      .split("?")[0];
  }
}

/**
 * Decrypts the given vault entries in memory and returns the minimal
 * autofill payload. The decrypted password strings live only inside the
 * returned array; callers are responsible for forwarding them to the
 * native layer and discarding the array immediately after.
 *
 * Security guarantees provided here:
 *  - Biometric freshness gate (unless explicitly disabled by the caller)
 *  - Master-key bytes are wiped inside `decryptVaultEntry` (per-entry HKDF)
 *  - Shares derived inside this function are wiped via `wipeShares` in
 *    a `finally` block — even on partial decryption failure
 *  - Per-entry decrypt failures are skipped, never thrown, so a single
 *    corrupt entry can't poison the whole autofill response
 *
 * Caveat: JS strings are immutable. The returned `password`/`username`
 * strings cannot be zeroed; minimise their lifetime by serialising and
 * dropping the array as soon as the native push completes.
 */
export async function prepareAutofillPayload(
  opts: PrepareAutofillPayloadOptions,
): Promise<AutofillPayloadEntry[]> {
  const {
    entries,
    shares: providedShares,
    password,
    salt,
    iterations,
    requireBiometric = true,
  } = opts;

  if (!Array.isArray(entries) || entries.length === 0) {
    return [];
  }

  if (requireBiometric) {
    const ok = await requireFreshBiometric();
    if (!ok) {
      throw new Error("Biometric authentication required for autofill");
    }
  }

  let shares: KeyShares | undefined = providedShares;
  let ownsShares = false;

  if (!shares) {
    if (!password || !salt) {
      throw new Error(
        "prepareAutofillPayload: either `shares` or `password` + `salt` is required",
      );
    }
    shares = await deriveMasterKeyShares(password, salt, iterations ?? 100000);
    ownsShares = true;
  }

  const payload: AutofillPayloadEntry[] = [];

  try {
    for (const entry of entries) {
      try {
        const decrypted = decryptVaultEntry(entry, shares);
        const domain = extractDomain(decrypted.url ?? entry.url);

        payload.push({
          id: decrypted.id,
          domain,
          username: decrypted.username,
          password: decrypted.password,
        });
      } catch (err) {
        if (__DEV__) {
          // eslint-disable-next-line no-console
          console.warn(
            `[AutofillBridge] skipped entry ${entry.id}: decrypt failed`,
            err,
          );
        }
      }
    }
    return payload;
  } finally {
    if (ownsShares && shares) {
      wipeShares(shares);
    }
  }
}

/**
 * Best-effort wipe for a payload array produced by `prepareAutofillPayload`.
 * JS strings are immutable, so this empties the array and overwrites each
 * entry's fields with empty strings — it cannot guarantee removal of the
 * original password bytes from the JS heap, but it removes references and
 * helps the GC reclaim them sooner.
 *
 * Always call this in a `finally` after forwarding the payload to native.
 */
export function wipeAutofillPayload(payload: AutofillPayloadEntry[]): void {
  for (let i = 0; i < payload.length; i++) {
    const entry = payload[i];
    entry.id = "";
    entry.domain = "";
    entry.username = "";
    entry.password = "";
  }
  payload.length = 0;
}

export const AutofillBridge = {
  getVaultEntriesForAutofill,
  getVaultEntriesJsonForAutofill,
  isVaultUnlocked,
  prepareAutofillPayload,
  wipeAutofillPayload,
};

export default AutofillBridge;
