/**
 * Check a fetched item receipt before any local vault write.
 *
 * Uses verifyReceipt from the Phase 1 receipt module. The Ed25519 public
 * key is the caller's pin, or EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY.
 * A failed check is logged. This module does not write vault data.
 */

import type { JsonWebKey } from "node:crypto";
import {
  TOMBSTONE_LOCATOR,
  verifyReceipt,
  type MovementReceipt,
  type ReceiptCrypto,
  type ReceiptVerifyFailure,
} from "./receipt";

export const INTENTDB_RECEIPT_PUBLIC_KEY_ENV = "EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY";

export type FetchedItemReceiptView = {
  itemId: string;
  version: number;
  contentSha256: string;
  tombstone: boolean;
};

export type FetchReceiptFailure =
  | "missing"
  | "unpinned-key"
  | "hash-mismatch"
  | "item-mismatch"
  | ReceiptVerifyFailure;

export type FetchReceiptDecision =
  | { accepted: true }
  | { accepted: false; reason: FetchReceiptFailure };

export type VerifyFetchedItemInput = {
  item: FetchedItemReceiptView;
  receipt: MovementReceipt | null;
  /** Pin. Omit it to read EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY. */
  publicKeyHex?: string;
  log?: (message: string) => void;
  /** Called only after the signature and the content hash both check out. */
  commit?: (item: FetchedItemReceiptView) => void;
};

export function verifyFetchedItemReceipt(input: VerifyFetchedItemInput): FetchReceiptDecision {
  const itemId = safeItemId(input.item?.itemId);
  if (!input.receipt) {
    safeLog(input.log, `intentdb receipt verification failed itemId=${itemId} reason=missing`);
    return { accepted: false, reason: "missing" };
  }
  const publicKeyHex = resolvePublicKey(input.publicKeyHex);
  if (!publicKeyHex) {
    safeLog(input.log, `intentdb receipt verification failed itemId=${itemId} reason=unpinned-key`);
    return { accepted: false, reason: "unpinned-key" };
  }

  let crypto: ReceiptCrypto;
  try {
    crypto = ed25519ReceiptVerifier(publicKeyHex);
  } catch {
    safeLog(input.log, `intentdb receipt verification failed itemId=${itemId} reason=bad-signature`);
    return { accepted: false, reason: "bad-signature" };
  }

  const verified = verifyReceipt(input.receipt, crypto);
  if (!verified.ok) {
    safeLog(
      input.log,
      `intentdb receipt verification failed itemId=${itemId} reason=${verified.reason}`,
    );
    return { accepted: false, reason: verified.reason };
  }
  if (input.receipt.contentSha256 !== input.item.contentSha256) {
    safeLog(input.log, `intentdb receipt verification failed itemId=${itemId} reason=hash-mismatch`);
    return { accepted: false, reason: "hash-mismatch" };
  }
  if (!bindingOk(input.item, input.receipt)) {
    safeLog(input.log, `intentdb receipt verification failed itemId=${itemId} reason=item-mismatch`);
    return { accepted: false, reason: "item-mismatch" };
  }
  if (input.commit) input.commit(input.item);
  return { accepted: true };
}

function bindingOk(item: FetchedItemReceiptView, receipt: MovementReceipt): boolean {
  if (receipt.itemId !== item.itemId || receipt.itemVersion !== item.version) return false;
  if (item.tombstone) {
    return receipt.op === "delete" && receipt.toLocator === TOMBSTONE_LOCATOR;
  }
  return receipt.op !== "delete" && receipt.toLocator !== TOMBSTONE_LOCATOR;
}

function resolvePublicKey(override: string | undefined): string | null {
  if (typeof override === "string" && /^[0-9a-f]{64}$/.test(override)) return override;
  const env = process.env[INTENTDB_RECEIPT_PUBLIC_KEY_ENV];
  if (typeof env === "string" && /^[0-9a-f]{64}$/.test(env.trim())) return env.trim();
  return null;
}

function safeItemId(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001F\u007F]/g, "").slice(0, 128);
}

function safeLog(log: VerifyFetchedItemInput["log"], message: string): void {
  try {
    (log ?? defaultLog)(message);
  } catch {
    // A logger must not turn a rejected receipt into a vault write.
  }
}

function defaultLog(message: string): void {
  console.warn(message);
}

function ed25519ReceiptVerifier(publicKeyHex: string): ReceiptCrypto {
  const node = loadEd25519();
  const key = node.createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: b64urlEncode(Buffer.from(publicKeyHex, "hex")),
    } as JsonWebKey,
    format: "jwk",
  });
  return {
    alg: "ed25519",
    sign() {
      throw new Error("Receipt verification does not sign");
    },
    verify(payload, signature) {
      return node.verify(null, Buffer.from(payload), key, Buffer.from(signature));
    },
  };
}

function loadEd25519(): typeof import("node:crypto") {
  if (!isNativeMobile()) {
    try {
      const node = require("node:crypto") as typeof import("node:crypto");
      if (typeof node.verify === "function" && typeof node.createPublicKey === "function") {
        return node;
      }
    } catch {
      // Native builds use the quick-crypto binding below.
    }
  }
  const qcMod = require("react-native-quick-crypto") as {
    default?: typeof import("node:crypto");
  } & Partial<typeof import("node:crypto")>;
  const qc = (qcMod.default ?? qcMod) as typeof import("node:crypto");
  if (typeof qc.verify === "function" && typeof qc.createPublicKey === "function") return qc;
  throw new Error("Ed25519 is unavailable");
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
