/**
 * Null-safe native Argon2id bridge.
 *
 * JS never `require()`s @sphereon/react-native-argon2 (its index.js
 * crashes when NativeModules.RNArgon2 is null). We talk to the
 * first-party Android module (modules/pipass-argon2) via
 * NativeModules.RNArgon2 only.
 *
 * Native is used on Android only. iOS Sphereon/CatCrypto treats the
 * salt string as UTF-8, which would not match hash-wasm / Android hex
 * decode — so iOS stays on hash-wasm.
 */

export type Argon2BinaryParams = {
  password: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  memorySize: number;
  parallelism: number;
  hashLength: number;
};

export type NativeArgon2Bridge = (
  password: string,
  saltHex: string,
  config: Record<string, unknown>,
) => Promise<{ rawHash?: string }>;

function getPlatformOS(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const rn = require("react-native");
    const os = rn?.Platform?.OS;
    if (typeof os === "string") return os;
  } catch {
    // Node / web
  }
  return "web";
}

export function isAndroidNativeArgon2Platform(): boolean {
  return getPlatformOS() === "android";
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b: number) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function diagnoseNativeArgon2(): {
  ok: boolean;
  reason: string;
  platform: string;
  moduleKeysMatchingArgon: string[];
  hasRNArgon2: boolean;
  argon2MethodType: string;
} {
  const empty = {
    ok: false,
    reason: "unknown",
    platform: "unknown",
    moduleKeysMatchingArgon: [] as string[],
    hasRNArgon2: false,
    argon2MethodType: "none",
  };
  try {
    const platform = getPlatformOS();
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const rn = require("react-native");
    if (rn == null || typeof rn !== "object") {
      return { ...empty, platform, reason: "react-native require returned null/non-object" };
    }
    const modules = rn["NativeModules"];
    if (modules == null || typeof modules !== "object") {
      return { ...empty, platform, reason: "NativeModules is null/non-object" };
    }
    let keys: string[] = [];
    try {
      keys = Object.keys(modules).filter(
        (k) => /argon/i.test(k) || /RNArgon/i.test(k) || /pipass/i.test(k),
      );
    } catch {
      keys = [];
    }
    const mod = modules["RNArgon2"];
    if (mod == null) {
      return {
        ...empty,
        platform,
        moduleKeysMatchingArgon: keys,
        hasRNArgon2: false,
        reason:
          "NativeModules.RNArgon2 is null — first-party pipass-argon2 is not registered " +
          "(check MainApplication add(PipassArgon2Package()) and ProGuard keep rules)",
      };
    }
    if (typeof mod !== "object" && typeof mod !== "function") {
      return {
        ...empty,
        platform,
        moduleKeysMatchingArgon: keys,
        hasRNArgon2: true,
        argon2MethodType: typeof mod,
        reason: `NativeModules.RNArgon2 has unexpected type=${typeof mod}`,
      };
    }
    const method = mod["argon2"];
    const methodType = typeof method;
    if (methodType !== "function") {
      return {
        ...empty,
        platform,
        moduleKeysMatchingArgon: keys,
        hasRNArgon2: true,
        argon2MethodType: methodType,
        reason: `NativeModules.RNArgon2.argon2 is not callable (type=${methodType})`,
      };
    }
    return {
      ok: true,
      platform,
      moduleKeysMatchingArgon: keys,
      reason: "NativeModules.RNArgon2.argon2 is present and callable",
      hasRNArgon2: true,
      argon2MethodType: methodType,
    };
  } catch {
    return { ...empty, reason: "diagnoseNativeArgon2 threw" };
  }
}

export function isNativeArgon2Confirmed(): boolean {
  try {
    return isAndroidNativeArgon2Platform() && diagnoseNativeArgon2().ok;
  } catch {
    return false;
  }
}

export function tryResolveNativeArgon2Fn(): NativeArgon2Bridge | null {
  try {
    if (!isAndroidNativeArgon2Platform()) return null;
    const diag = diagnoseNativeArgon2();
    if (!diag.ok) return null;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const rn = require("react-native");
    const mod = rn["NativeModules"]["RNArgon2"];
    const argon2Method = mod["argon2"];
    return (password, saltHex, config) => {
      try {
        if (typeof mod.argon2 === "function") {
          return Promise.resolve(mod.argon2(password, saltHex, config));
        }
        return Promise.resolve(argon2Method(password, saltHex, config));
      } catch (callErr: unknown) {
        return Promise.reject(callErr);
      }
    };
  } catch {
    return null;
  }
}

export function adaptNativeArgon2(
  nativeArgon: NativeArgon2Bridge,
): (params: Argon2BinaryParams) => Promise<Uint8Array> {
  return async (params: Argon2BinaryParams): Promise<Uint8Array> => {
    let pwStr: string;
    try {
      pwStr = new TextDecoder("utf-8").decode(params.password);
    } catch {
      pwStr = Array.from(params.password)
        .map((b) => String.fromCharCode(b))
        .join("");
    }

    if (!params.salt || params.salt.length !== 32) {
      throw new Error(
        `Native argon2 requires exactly 32-byte salt, got length=${params.salt?.length ?? "null"}`,
      );
    }
    const saltHexForNative = bytesToHex(params.salt).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(saltHexForNative)) {
      throw new Error(
        `Native argon2 salt hex invalid (len=${saltHexForNative.length}, expected 64 hex chars)`,
      );
    }

    const config = {
      iterations: Math.max(1, params.iterations | 0),
      memory: Math.max(8, params.memorySize | 0),
      parallelism: Math.max(1, params.parallelism | 0),
      hashLength: Math.max(16, Math.min(64, params.hashLength | 0 || 32)),
      mode: "argon2id",
    };
    const res = await nativeArgon(pwStr, saltHexForNative, config);
    const raw =
      res != null && typeof res === "object" && typeof res.rawHash === "string"
        ? res.rawHash
        : null;
    if (!raw || raw.length < 32 || raw.length % 2 !== 0) {
      throw new Error(
        `Native argon2 did not return valid rawHash (type=${typeof raw}, len=${raw?.length ?? 0})`,
      );
    }
    const out = new Uint8Array(raw.length / 2);
    for (let i = 0; i < out.length; i++) {
      const byte = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(byte)) {
        throw new Error(`Native argon2 rawHash has invalid hex at offset ${i}`);
      }
      out[i] = byte;
    }
    return out;
  };
}
