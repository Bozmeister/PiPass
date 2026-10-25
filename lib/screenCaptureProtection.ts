/**
 * Screenshot / screen-recording protection for sensitive vault UI.
 *
 * Android release: FLAG_SECURE is also applied natively via plugins/withFlagSecure.js.
 * iOS / JS: expo-screen-capture preventScreenCaptureAsync.
 *
 * Design:
 * - Enable for the process lifetime on native production builds (not web, not __DEV__).
 * - Never call allowScreenCaptureAsync on cleanup of a single screen — that previously
 *   re-enabled capture when leaving VaultScreen and undid Android FLAG_SECURE.
 * - Re-apply when the app returns to foreground (OEM / OS may clear window flags).
 */

import { useEffect } from "react";
import { AppState, type AppStateStatus, Platform } from "react-native";

type ScreenCaptureModule = {
  preventScreenCaptureAsync: () => Promise<void>;
  allowScreenCaptureAsync: () => Promise<void>;
};

let protectionDesired = false;
let appStateSubscription: { remove: () => void } | null = null;
let screenCaptureModule: ScreenCaptureModule | null | undefined;

function isNativeMobile(): boolean {
  return Platform.OS === "ios" || Platform.OS === "android";
}

/**
 * Production native builds only. Debug/dev may allow screenshots for QA —
 * never use those builds with a real vault (see SECURITY_AUDIT P3/P8).
 */
export function shouldBlockScreenCapture(): boolean {
  if (!isNativeMobile()) return false;
  if (typeof __DEV__ !== "undefined" && __DEV__) return false;
  return true;
}

function loadScreenCapture(): ScreenCaptureModule | null {
  if (screenCaptureModule !== undefined) return screenCaptureModule;
  try {
    // Lazy require keeps web / Node tests from loading native modules eagerly.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    screenCaptureModule = require("expo-screen-capture") as ScreenCaptureModule;
  } catch {
    screenCaptureModule = null;
  }
  return screenCaptureModule;
}

async function applyPrevent(): Promise<void> {
  if (!shouldBlockScreenCapture()) return;
  const mod = loadScreenCapture();
  if (!mod) return;
  try {
    await mod.preventScreenCaptureAsync();
  } catch {
    // Best-effort: never throw into UI / startup paths.
  }
}

function onAppStateChange(next: AppStateStatus): void {
  if (next === "active" && protectionDesired) {
    void applyPrevent();
  }
}

/**
 * Enable screenshot/recording protection for the rest of the process life.
 * Safe to call multiple times. Does not re-enable capture on "disable".
 */
export async function enableScreenCaptureProtection(): Promise<void> {
  if (!shouldBlockScreenCapture()) return;
  protectionDesired = true;
  await applyPrevent();
  if (!appStateSubscription) {
    appStateSubscription = AppState.addEventListener("change", onAppStateChange);
  }
}

/**
 * Intentionally a no-op for production password-manager UX.
 * Capture stays blocked once enabled so navigation cannot open a capture window.
 */
export async function disableScreenCaptureProtection(): Promise<void> {
  // Do not call allowScreenCaptureAsync here.
  // Process-lifetime protection is required for unlock → vault navigation.
}

/**
 * React hook: enable protection while any sensitive tree is mounted.
 * Call from root layout so unlock, setup, vault, notes, and settings are covered.
 */
export function useScreenCaptureProtection(): void {
  useEffect(() => {
    void enableScreenCaptureProtection();
    // Do not disable on unmount — root stays mounted; even if it remounted,
    // we never re-allow capture for this process in production.
  }, []);
}
