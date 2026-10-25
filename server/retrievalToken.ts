/**
 * Short-lived IntentDB retrieval tokens.
 *
 * The device holds an Ed25519 private key. Login registers the raw public
 * key on that session. This module checks the signature, expiry, audience,
 * operation, and item scope. Vault fields stay ciphertext. The private
 * key is never read here.
 *
 * Claims are aud, sub, op, exp, nonce, and optional itemIds or prefix.
 * The public key travels in the token envelope so the server can load the
 * login session that registered it. The envelope is not a claim.
 */

import { createPublicKey, timingSafeEqual, verify, type JsonWebKey } from "node:crypto";

export const RETRIEVAL_AUD = "intentdb";
export const RETRIEVAL_OP = "read";
export const RETRIEVAL_TTL_MAX_MS = 120_000;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type RetrievalClaims = {
  aud: string;
  sub: string;
  op: string;
  exp: number;
  nonce: string;
  itemIds?: string[];
  prefix?: string;
};

export type RetrievalVerdict =
  | { ok: true; userId: string }
  | { ok: false };

export type AuthorizationBearer =
  | { present: false }
  | { present: true; token: string | null };

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

export function readAuthorizationBearer(header: string | undefined): AuthorizationBearer {
  if (header === undefined) return { present: false };
  const match = /^Bearer ([A-Za-z0-9._-]+)$/i.exec(header.trim());
  return { present: true, token: match ? match[1] : null };
}

export function retrievalTokenPublicKey(token: string): string | null {
  return parseEnvelope(token)?.publicKeyHex ?? null;
}

export function verifyRetrievalToken(input: {
  token: string;
  itemId: string;
  nowMs: number;
  registeredUserIds: readonly string[];
}): RetrievalVerdict {
  const envelope = parseEnvelope(input.token);
  if (!envelope) return { ok: false };
  const claims = claimsFromPayload(envelope.payload, envelope.payloadBytes);
  if (!claims) return { ok: false };
  if (!verifySignature(envelope.publicKeyHex, envelope.payloadBytes, envelope.signature)) {
    return { ok: false };
  }
  if (claims.aud !== RETRIEVAL_AUD || claims.op !== RETRIEVAL_OP) return { ok: false };
  if (!Number.isSafeInteger(input.nowMs)) return { ok: false };
  if (claims.exp <= input.nowMs || claims.exp > input.nowMs + RETRIEVAL_TTL_MAX_MS) {
    return { ok: false };
  }
  if (!scopeAllows(claims, input.itemId)) return { ok: false };
  if (!input.registeredUserIds.some((userId) => sameUtf8(userId, claims.sub))) {
    return { ok: false };
  }
  return { ok: true, userId: claims.sub };
}

function scopeAllows(claims: RetrievalClaims, itemId: string): boolean {
  if (claims.itemIds !== undefined && !claims.itemIds.includes(itemId)) return false;
  if (claims.prefix !== undefined && !itemId.startsWith(claims.prefix)) return false;
  return true;
}

function sameUtf8(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

type Envelope = {
  publicKeyHex: string;
  payload: string;
  payloadBytes: Buffer;
  signature: Buffer;
};

function parseEnvelope(token: string): Envelope | null {
  if (typeof token !== "string" || token.length < 1 || token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return null;
  if (!/^[0-9a-f]{64}$/.test(parts[1])) return null;
  const payloadBytes = b64urlDecode(parts[2]);
  const signature = b64urlDecode(parts[3]);
  if (!payloadBytes || !signature || signature.length !== 64) return null;
  if (payloadBytes.length < 2 || payloadBytes.length > 2048) return null;
  const payload = payloadBytes.toString("utf8");
  if (!payloadBytes.equals(Buffer.from(payload, "utf8"))) return null;
  return { publicKeyHex: parts[1], payload, payloadBytes, signature };
}

function claimsFromPayload(raw: string, payloadBytes: Buffer): RetrievalClaims | null {
  if (!payloadBytes.equals(Buffer.from(raw, "utf8"))) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (
      key !== "aud" &&
      key !== "exp" &&
      key !== "itemIds" &&
      key !== "nonce" &&
      key !== "op" &&
      key !== "prefix" &&
      key !== "sub"
    ) {
      return null;
    }
  }
  if (typeof obj.aud !== "string" || obj.aud.length < 1 || obj.aud.length > 64) return null;
  if (typeof obj.op !== "string" || obj.op.length < 1 || obj.op.length > 32) return null;
  if (typeof obj.sub !== "string" || !UUID_RE.test(obj.sub)) return null;
  if (typeof obj.nonce !== "string" || !/^[0-9a-f]{64}$/.test(obj.nonce)) return null;
  if (typeof obj.exp !== "number" || !Number.isSafeInteger(obj.exp)) return null;

  const claims: RetrievalClaims = {
    aud: obj.aud,
    sub: obj.sub,
    op: obj.op,
    exp: obj.exp,
    nonce: obj.nonce,
  };
  if ("itemIds" in obj) {
    if (!Array.isArray(obj.itemIds) || obj.itemIds.length < 1 || obj.itemIds.length > 32) {
      return null;
    }
    const itemIds: string[] = [];
    for (const id of obj.itemIds) {
      if (typeof id !== "string" || id.length < 1 || id.length > 128) return null;
      itemIds.push(id);
    }
    claims.itemIds = itemIds;
  }
  if ("prefix" in obj) {
    if (typeof obj.prefix !== "string" || obj.prefix.length < 1 || obj.prefix.length > 128) {
      return null;
    }
    if (/[\0\n\r]/.test(obj.prefix)) return null;
    claims.prefix = obj.prefix;
  }
  if (canonicalRetrievalClaims(claims) !== raw) return null;
  return claims;
}

function verifySignature(publicKeyHex: string, payload: Buffer, signature: Buffer): boolean {
  try {
    const key = createPublicKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: b64urlEncode(Buffer.from(publicKeyHex, "hex")),
      } as JsonWebKey,
      format: "jwk",
    });
    return verify(null, payload, key, signature);
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

function b64urlDecode(value: string): Buffer | null {
  if (value.length === 0 || value.length > 4096) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  const decoded = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
  if (b64urlEncode(decoded) !== value) return null;
  return decoded;
}
