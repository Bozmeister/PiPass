/**
 * Server-signed item receipt.
 *
 * After a manifest or tombstone write, PiPass mints one Ed25519 receipt
 * and stores it. The canonical body matches the client receipt module.
 * Vault fields stay ciphertext. The signing seed is never returned.
 *
 * Set INTENTDB_RECEIPT_SIGNING_SEED to 64 lowercase hex to pin the key
 * across process restarts. When it is unset, the process keeps one
 * ephemeral key in memory.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import type { VaultItemReceiptRecord } from "./storage";

export const ITEM_RECEIPT_VERSION = 1;
export const ITEM_RECEIPT_GENESIS_HASH = "0".repeat(64);
export const ITEM_RECEIPT_BOT_ID = "pipass-server";
export const ITEM_RECEIPT_BOT_PROPOSER_ID = "intentdb-bot-v1";
export const ITEM_RECEIPT_CLIENT_LOCATOR = "client";
export const ITEM_RECEIPT_TOMBSTONE_LOCATOR = "tombstone";
export const ITEM_RECEIPT_SIG_ALG = "ed25519" as const;

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export type PublicItemReceipt = {
  v: number;
  op: string;
  itemId: string;
  itemVersion: number;
  contentSha256: string;
  fromLocator: string;
  toLocator: string;
  botId: string;
  issuedAt: number;
  prevReceiptHash: string;
  sigAlg: typeof ITEM_RECEIPT_SIG_ALG;
  signature: string;
};

type SigningKey = { publicKeyHex: string; privateKey: KeyObject };

let signingKey: SigningKey | null = null;

export function canonicalItemReceiptBody(body: {
  v: number;
  op: string;
  itemId: string;
  itemVersion: number;
  contentSha256: string;
  fromLocator: string;
  toLocator: string;
  botId: string;
  issuedAt: number;
  prevReceiptHash: string;
}): string {
  return `{${[
    `"botId":${JSON.stringify(body.botId)}`,
    `"contentSha256":${JSON.stringify(body.contentSha256)}`,
    `"fromLocator":${JSON.stringify(body.fromLocator)}`,
    `"issuedAt":${body.issuedAt}`,
    `"itemId":${JSON.stringify(body.itemId)}`,
    `"itemVersion":${body.itemVersion}`,
    `"op":${JSON.stringify(body.op)}`,
    `"prevReceiptHash":${JSON.stringify(body.prevReceiptHash)}`,
    `"toLocator":${JSON.stringify(body.toLocator)}`,
    `"v":${body.v}`,
  ].join(",")}}`;
}

export function itemReceiptChainHash(receipt: {
  canonical: string;
  sigAlg: string;
  signature: string;
}): string {
  return createHash("sha256")
    .update(`${receipt.canonical}.${receipt.sigAlg}.${receipt.signature}`, "utf8")
    .digest("hex");
}

export function getItemReceiptPublicKey(): string {
  return loadSigningKey().publicKeyHex;
}

export function toPublicItemReceipt(record: VaultItemReceiptRecord): PublicItemReceipt {
  return {
    v: record.v,
    op: record.op,
    itemId: record.itemId,
    itemVersion: record.itemVersion,
    contentSha256: record.contentSha256,
    fromLocator: record.fromLocator,
    toLocator: record.toLocator,
    botId: record.botId,
    issuedAt: record.issuedAt,
    prevReceiptHash: record.prevReceiptHash,
    sigAlg: ITEM_RECEIPT_SIG_ALG,
    signature: record.signature,
  };
}

export function createSignedItemReceipt(input: {
  previous: VaultItemReceiptRecord | undefined;
  op: "put" | "copy" | "move" | "delete";
  itemId: string;
  itemVersion: number;
  contentSha256: string;
  fromLocator: string;
  toLocator: string;
  issuedAt: number;
  /** Omit for the server bot. The only other accepted id is the proposer. */
  botId?: string;
}): VaultItemReceiptRecord {
  if (
    input.op !== "put" &&
    input.op !== "copy" &&
    input.op !== "move" &&
    input.op !== "delete"
  ) {
    throw new Error("Invalid item receipt");
  }
  if (input.op === "delete" && input.toLocator !== ITEM_RECEIPT_TOMBSTONE_LOCATOR) {
    throw new Error("Invalid item receipt");
  }
  if (input.op !== "delete" && input.toLocator === ITEM_RECEIPT_TOMBSTONE_LOCATOR) {
    throw new Error("Invalid item receipt");
  }
  if (!locatorOk(input.fromLocator) || !locatorOk(input.toLocator)) {
    throw new Error("Invalid item receipt");
  }
  if (!/^[0-9a-f]{64}$/.test(input.contentSha256)) {
    throw new Error("Invalid item receipt");
  }
  if (!Number.isSafeInteger(input.itemVersion) || input.itemVersion < 0) {
    throw new Error("Invalid item receipt");
  }
  if (!Number.isSafeInteger(input.issuedAt) || input.issuedAt <= 0) {
    throw new Error("Invalid item receipt");
  }
  const botId = receiptBotId(input.botId);
  const prevReceiptHash = input.previous
    ? itemReceiptChainHash(input.previous)
    : ITEM_RECEIPT_GENESIS_HASH;
  const body = {
    v: ITEM_RECEIPT_VERSION,
    op: input.op,
    itemId: input.itemId,
    itemVersion: input.itemVersion,
    contentSha256: input.contentSha256,
    fromLocator: input.fromLocator,
    toLocator: input.toLocator,
    botId,
    issuedAt: input.issuedAt,
    prevReceiptHash,
  };
  const canonical = canonicalItemReceiptBody(body);
  const signature = sign(null, Buffer.from(canonical, "utf8"), loadSigningKey().privateKey).toString(
    "hex",
  );
  if (!/^[0-9a-f]{128}$/.test(signature)) {
    throw new Error("Invalid item receipt");
  }
  return { ...body, sigAlg: ITEM_RECEIPT_SIG_ALG, signature, canonical };
}

export function itemReadBody<T extends object>(
  item: T,
  receipt: VaultItemReceiptRecord | undefined,
): T & { receipt: PublicItemReceipt | null; receiptPublicKey: string } {
  return {
    ...item,
    receipt: receipt ? toPublicItemReceipt(receipt) : null,
    receiptPublicKey: getItemReceiptPublicKey(),
  };
}

function receiptBotId(value: string | undefined): string {
  const botId = value ?? ITEM_RECEIPT_BOT_ID;
  if (botId !== ITEM_RECEIPT_BOT_ID && botId !== ITEM_RECEIPT_BOT_PROPOSER_ID) {
    throw new Error("Invalid item receipt");
  }
  return botId;
}

function locatorOk(value: string): boolean {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 256 &&
    !/[\0-\x1f\x7f]/.test(value)
  );
}

function loadSigningKey(): SigningKey {
  if (signingKey) return signingKey;
  const seed = process.env.INTENTDB_RECEIPT_SIGNING_SEED?.trim();
  if (seed) {
    if (!/^[0-9a-f]{64}$/.test(seed)) {
      throw new Error("Invalid receipt signing seed");
    }
    const der = Buffer.concat([PKCS8_PREFIX, Buffer.from(seed, "hex")]);
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    signingKey = { publicKeyHex: rawPublicKeyHex(createPublicKey(privateKey)), privateKey };
    return signingKey;
  }
  const generated = generateKeyPairSync("ed25519");
  signingKey = {
    publicKeyHex: rawPublicKeyHex(generated.publicKey),
    privateKey: generated.privateKey,
  };
  return signingKey;
}

function rawPublicKeyHex(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new Error("Invalid receipt signing key");
  const raw = b64urlDecode(jwk.x);
  const hex = raw.toString("hex");
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("Invalid receipt signing key");
  return hex;
}

function b64urlDecode(value: string): Buffer {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}
