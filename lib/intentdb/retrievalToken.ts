/**
 * Mint a short-lived retrieval token and register the device public key
 * on the login session.
 *
 * The signing key is an Ed25519 pair generated on the device. Register the
 * public key with the session token returned at login. The private key
 * stays on the device. This module does not derive the key from the vault
 * master key, and it does not use the entry-key HKDF info strings.
 *
 * Default lifetime is 90 seconds. The server accepts at most 120 seconds.
 */

import { getApiUrl } from "../api-url";
import type { JsonWebKey } from "node:crypto";

export const RETRIEVAL_AUD = "intentdb";
export const RETRIEVAL_OP = "read";
export const RETRIEVAL_TTL_DEFAULT_MS = 90_000;
export const RETRIEVAL_TTL_MAX_MS = 120_000;

export type RetrievalClaims = {
  aud: string;
  sub: string;
  op: string;
  exp: number;
  nonce: string;
  itemIds?: string[];
  prefix?: string;
};

export type RetrievalDeviceKey = {
  publicKeyHex: string;
  privateKeyHex: string;
};

export type RetrievalRegisterResult =
  | { registered: true }
  | { registered: false; reason: "network" | "rejected"; status?: number };

type NodeCrypto = typeof import("node:crypto");

type FetchResponse = { ok: boolean; status: number; text: () => Promise<string> };

export function canonicalRetrievalClaims(claims: RetrievalClaims): string {
  const parts = [
    `"aud":${JSON.stringify(claims.aud)}`,
    `"exp":${claims.exp}`,
  ];
  if (claims.itemIds !== undefined) {
    const itemIds = [...new Set(claims.itemIds)].sort();
    parts.push(`"itemIds":${JSON.stringify(itemIds)}`);
  }
  parts.push(`"nonce":${JSON.stringify(claims.nonce)}`);
  parts.push(`"op":${JSON.stringify(claims.op)}`);
  if (claims.prefix !== undefined) {
    parts.push(`"prefix":${JSON.stringify(claims.prefix)}`);
  }
  parts.push(`"sub":${JSON.stringify(claims.sub)}`);
  return `{${parts.join(",")}}`;
}

export function generateRetrievalDeviceKey(): RetrievalDeviceKey {
  const crypto = loadEd25519();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubJwk = publicKey.export({ format: "jwk" }) as { x?: string };
  const privJwk = privateKey.export({ format: "jwk" }) as { d?: string };
  if (!pubJwk.x || !privJwk.d) {
    throw new Error("Ed25519 device key is unavailable");
  }
  return {
    publicKeyHex: b64urlDecode(pubJwk.x).toString("hex"),
    privateKeyHex: b64urlDecode(privJwk.d).toString("hex"),
  };
}

export function mintRetrievalToken(input: {
  privateKeyHex: string;
  publicKeyHex: string;
  userId: string;
  nowMs?: number;
  ttlMs?: number;
  itemIds?: string[];
  prefix?: string;
  nonceHex?: string;
}): string {
  const ttl = input.ttlMs ?? RETRIEVAL_TTL_DEFAULT_MS;
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > RETRIEVAL_TTL_MAX_MS) {
    throw new Error("Invalid retrieval token lifetime");
  }
  const now = input.nowMs ?? Date.now();
  if (!Number.isSafeInteger(now)) {
    throw new Error("Invalid retrieval token lifetime");
  }
  const nonce = input.nonceHex ?? loadEd25519().randomBytes(32).toString("hex");
  if (!/^[0-9a-f]{64}$/.test(nonce)) {
    throw new Error("Invalid retrieval nonce");
  }
  const claims: RetrievalClaims = {
    aud: RETRIEVAL_AUD,
    sub: input.userId,
    op: RETRIEVAL_OP,
    exp: now + ttl,
    nonce,
  };
  if (input.itemIds !== undefined) {
    if (input.itemIds.length < 1 || input.itemIds.length > 32) {
      throw new Error("Invalid retrieval item scope");
    }
    claims.itemIds = [...input.itemIds];
  }
  if (input.prefix !== undefined) {
    if (input.prefix.length < 1 || input.prefix.length > 128 || /[\0\n\r]/.test(input.prefix)) {
      throw new Error("Invalid retrieval item scope");
    }
    claims.prefix = input.prefix;
  }
  return signRetrievalToken(claims, input.privateKeyHex, input.publicKeyHex);
}

/** Sign claims as-is. Used when a test needs an audience the minter will not produce. */
export function signRetrievalToken(
  claims: RetrievalClaims,
  privateKeyHex: string,
  publicKeyHex: string,
): string {
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex) || !/^[0-9a-f]{64}$/.test(privateKeyHex)) {
    throw new Error("Invalid retrieval device key");
  }
  if (!Number.isSafeInteger(claims.exp)) {
    throw new Error("Invalid retrieval expiry");
  }
  const payload = canonicalRetrievalClaims(claims);
  const payloadBytes = Buffer.from(payload, "utf8");
  const crypto = loadEd25519();
  const key = crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: b64urlEncode(Buffer.from(publicKeyHex, "hex")),
      d: b64urlEncode(Buffer.from(privateKeyHex, "hex")),
    } as JsonWebKey,
    format: "jwk",
  });
  const signature = crypto.sign(null, payloadBytes, key);
  return `v1.${publicKeyHex}.${b64urlEncode(payloadBytes)}.${b64urlEncode(signature)}`;
}

/**
 * Register the device public key on the session that login just issued.
 * Sends the public key and x-session-token. Does not send the private key.
 */
export async function registerRetrievalDeviceKey(input: {
  sessionToken: string;
  publicKeyHex: string;
  apiBaseUrl?: string;
  fetchImpl?: (
    url: string,
    init: { method: string; headers: Record<string, string>; body: string },
  ) => Promise<FetchResponse>;
}): Promise<RetrievalRegisterResult> {
  if (typeof input.sessionToken !== "string" || input.sessionToken.length === 0) {
    return { registered: false, reason: "rejected" };
  }
  if (!/^[0-9a-f]{64}$/.test(input.publicKeyHex)) {
    return { registered: false, reason: "rejected" };
  }
  try {
    const base = input.apiBaseUrl ?? getApiUrl();
    const url = new URL("/api/auth/retrieval-device", base);
    const request = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-session-token": input.sessionToken,
      },
      body: JSON.stringify({ publicKey: input.publicKeyHex }),
    };
    const response = input.fetchImpl
      ? await input.fetchImpl(url.toString(), request)
      : await fetch(url.toString(), request);
    const text = await response.text().catch(() => "");
    if (response.status !== 200) {
      return { registered: false, reason: "rejected", status: response.status };
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return { registered: false, reason: "rejected", status: response.status };
    }
    if (
      !body ||
      typeof body !== "object" ||
      (body as { registered?: unknown }).registered !== true
    ) {
      return { registered: false, reason: "rejected", status: response.status };
    }
    return { registered: true };
  } catch {
    return { registered: false, reason: "network" };
  }
}

function loadEd25519(): NodeCrypto {
  if (!isNativeMobile()) {
    try {
      const node = require("node:crypto") as NodeCrypto;
      if (typeof node.generateKeyPairSync === "function" && typeof node.sign === "function") {
        return node;
      }
    } catch {
      // Native builds use the quick-crypto binding below.
    }
  }
  try {
    const qcMod = require("react-native-quick-crypto") as { default?: NodeCrypto } & Partial<NodeCrypto>;
    const qc = (qcMod.default ?? qcMod) as NodeCrypto;
    if (typeof qc.generateKeyPairSync === "function" && typeof qc.sign === "function") {
      return qc;
    }
  } catch {
    // Fall through to the fail-closed error.
  }
  throw new Error(
    "Ed25519 is unavailable. Native builds require react-native-quick-crypto; Node uses node:crypto.",
  );
}

function isNativeMobile(): boolean {
  try {
    const { Platform } = require("react-native") as { Platform?: { OS?: string } };
    return Platform?.OS === "ios" || Platform?.OS === "android";
  } catch {
    return false;
  }
}

function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlDecode(value: string): Buffer {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}
