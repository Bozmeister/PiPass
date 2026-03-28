import { Platform } from "react-native";
import * as Device from "expo-device";
import * as ExpoCrypto from "expo-crypto";
import CryptoJS from "crypto-js";

export type TamperReason =
  | "debugger_attached"
  | "emulator_detected"
  | "crypto_self_test_failed"
  | "timing_anomaly"
  | "hook_detected";

export interface IntegrityReport {
  tampered: boolean;
  reasons: TamperReason[];
}

let _onTamperCallback: (() => void) | null = null;
let _guardIntervalId: ReturnType<typeof setInterval> | null = null;

export function setTamperCallback(cb: () => void): void {
  _onTamperCallback = cb;
}

function fireTamper(reasons: TamperReason[]): void {
  if (__DEV__) return;
  if (_onTamperCallback) _onTamperCallback();
}

export function detectDebugger(): boolean {
  if (Platform.OS === "web") {
    try {
      const start = performance.now();
      // eslint-disable-next-line no-debugger
      const dummy = new Function("return 1+1")();
      const elapsed = performance.now() - start;
      if (elapsed > 100) return true;
    } catch {
      return true;
    }
    return false;
  }

  if ((global as any).__REACT_DEVTOOLS_GLOBAL_HOOK__) return true;

  try {
    const before = Date.now();
    for (let i = 0; i < 10000; i++) { /* calibration loop */ }
    const after = Date.now();
    if (after - before > 500) return true;
  } catch {
    // ignore
  }

  return false;
}

export function detectEmulator(): boolean {
  if (Platform.OS === "web") return false;

  if (!Device.isDevice) return true;

  const brand = (Device.brand || "").toLowerCase();
  const modelName = (Device.modelName || "").toLowerCase();
  const deviceName = (Device.deviceName || "").toLowerCase();

  const emulatorIndicators = [
    "sdk", "emulator", "simulator", "genymotion",
    "bluestacks", "nox", "andy", "memu", "ldplayer",
    "google_sdk", "droid4x", "windroye",
  ];

  const combined = `${brand} ${modelName} ${deviceName}`;
  for (const indicator of emulatorIndicators) {
    if (combined.includes(indicator)) return true;
  }

  if (Platform.OS === "android") {
    const manufacturer = (Device.manufacturer || "").toLowerCase();
    if (manufacturer.includes("unknown") || manufacturer.includes("genymotion")) return true;
    if (modelName.includes("sdk") || modelName.includes("android sdk")) return true;
  }

  return false;
}

export function cryptoSelfTest(): boolean {
  try {
    const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const testPlain = "PiPass-integrity-check";

    const iv = CryptoJS.enc.Hex.parse("00112233445566778899aabbccddeeff");
    const key = CryptoJS.enc.Hex.parse(testKey);

    const encrypted = CryptoJS.AES.encrypt(testPlain, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const decrypted = CryptoJS.AES.decrypt(encrypted, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const result = decrypted.toString(CryptoJS.enc.Utf8);
    if (result !== testPlain) return false;

    const hmac = CryptoJS.HmacSHA256("test-message", testKey).toString(CryptoJS.enc.Hex);
    if (!hmac || hmac.length !== 64) return false;

    const hash = CryptoJS.SHA256("test").toString(CryptoJS.enc.Hex);
    if (!hash || hash.length !== 64) return false;

    const rng = ExpoCrypto.getRandomBytes(32);
    if (!rng || rng.length !== 32) return false;
    let allZero = true;
    for (let i = 0; i < rng.length; i++) {
      if (rng[i] !== 0) { allZero = false; break; }
    }
    if (allZero) return false;

    return true;
  } catch {
    return false;
  }
}

export function detectFunctionHooks(): boolean {
  try {
    const fnStr = CryptoJS.AES.encrypt.toString();
    if (fnStr.includes("Proxy") || fnStr.includes("native code") === false && fnStr.length < 20) {
      return true;
    }

    if (typeof (Array.prototype as any).__original_map !== "undefined") return true;

    return false;
  } catch {
    return true;
  }
}

export function runIntegrityCheck(): IntegrityReport {
  const reasons: TamperReason[] = [];

  if (!__DEV__) {
    if (detectDebugger()) reasons.push("debugger_attached");
    if (detectEmulator()) reasons.push("emulator_detected");
    if (detectFunctionHooks()) reasons.push("hook_detected");
  }

  if (!cryptoSelfTest()) reasons.push("crypto_self_test_failed");

  const tampered = reasons.length > 0;
  if (tampered) fireTamper(reasons);

  return { tampered, reasons };
}

export function startPeriodicGuard(intervalMs: number = 30000): void {
  stopPeriodicGuard();

  _guardIntervalId = setInterval(() => {
    const report = runIntegrityCheck();
    if (report.tampered) {
      fireTamper(report.reasons);
    }
  }, intervalMs);
}

export function stopPeriodicGuard(): void {
  if (_guardIntervalId) {
    clearInterval(_guardIntervalId);
    _guardIntervalId = null;
  }
}
