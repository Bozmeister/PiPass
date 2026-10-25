/**
 * AES-256-GCM via native OpenSSL.
 *
 *   - Node (tests, CI): node:crypto
 *   - iOS / Android:    react-native-quick-crypto 0.7 (JSI, old + new arch)
 *
 * 1.x of quick-crypto requires New Architecture / Nitro; this app still
 * has newArchEnabled=false, so 0.7 is the correct native binding.
 * encrypt/decrypt stay synchronous to match vaultWorker call sites.
 */

type CipherLike = {
  setAAD(data: Uint8Array): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
  getAuthTag(): Uint8Array;
};

type DecipherLike = {
  setAAD(data: Uint8Array): unknown;
  setAuthTag(tag: Uint8Array): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
};

type AesGcmBackend = {
  createCipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options: { authTagLength: number },
  ): CipherLike;
  createDecipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options: { authTagLength: number },
  ): DecipherLike;
  randomBytes(size: number): Uint8Array;
};

const ALGORITHM = "aes-256-gcm";
const AUTH_TAG_LENGTH = 16;

let cached: AesGcmBackend | null = null;

function isNativeMobile(): boolean {
  try {
    const { Platform } = require("react-native") as {
      Platform?: { OS?: string };
    };
    return Platform?.OS === "ios" || Platform?.OS === "android";
  } catch {
    return false;
  }
}

function asUint8Array(value: Uint8Array | ArrayBuffer | number[]): Uint8Array {
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(value);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function loadBackend(): AesGcmBackend {
  if (cached) return cached;

  if (!isNativeMobile()) {
    try {
      const node = require("node:crypto") as typeof import("node:crypto");
      if (typeof node.createCipheriv === "function") {
        cached = {
          createCipheriv: node.createCipheriv.bind(node) as AesGcmBackend["createCipheriv"],
          createDecipheriv: node.createDecipheriv.bind(
            node,
          ) as AesGcmBackend["createDecipheriv"],
          randomBytes: (size) => asUint8Array(node.randomBytes(size)),
        };
        return cached;
      }
    } catch {
      // Not Node — try the native RN binding.
    }
  }

  try {
    const qcMod = require("react-native-quick-crypto") as {
      default?: AesGcmBackend;
    } & Partial<AesGcmBackend>;
    const qc = (qcMod.default ?? qcMod) as AesGcmBackend;
    if (typeof qc.createCipheriv === "function") {
      cached = {
        createCipheriv: qc.createCipheriv.bind(qc),
        createDecipheriv: qc.createDecipheriv.bind(qc),
        randomBytes: (size) => asUint8Array(qc.randomBytes(size)),
      };
      return cached;
    }
  } catch {
    // Fall through to the fail-closed error.
  }

  throw new Error(
    "AES-256-GCM is unavailable. Native builds require react-native-quick-crypto; Node uses node:crypto.",
  );
}

export function randomNonce(bytes: number): Uint8Array {
  return loadBackend().randomBytes(bytes);
}

export function aesGcmEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const cipher = loadBackend().createCipheriv(ALGORITHM, key, nonce, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  cipher.setAAD(aad);
  const ciphertext = concatBytes([
    asUint8Array(cipher.update(plaintext)),
    asUint8Array(cipher.final()),
  ]);
  const tag = asUint8Array(cipher.getAuthTag());
  return { ciphertext, tag };
}

export function aesGcmDecrypt(
  ciphertext: Uint8Array,
  tag: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const decipher = loadBackend().createDecipheriv(ALGORITHM, key, nonce, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return concatBytes([
    asUint8Array(decipher.update(ciphertext)),
    asUint8Array(decipher.final()),
  ]);
}
