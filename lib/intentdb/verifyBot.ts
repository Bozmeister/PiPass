/**
 * Re-check one stored item and its latest receipt.
 *
 * botId is intentdb-verifier-v1. The helper GETs the existing item route,
 * then calls verifyFetchedItemReceipt. The pin is the caller argument or
 * EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY. A key returned beside the
 * receipt is not the pin.
 *
 * Default is off. Set EXPO_PUBLIC_INTENTDB_VERIFY=1, or pass enabled: true.
 * Pass unlocked: true only while the vault is unlocked. This helper does
 * not read vault key shares.
 *
 * A mismatch is logged as itemId, op, and reason. The item, locator, and
 * phone vault are left unchanged. Vault fields are not opened. The request
 * sends x-session-token and does not send a vault key proof.
 */

import { getApiUrl } from "../api-url";
import type { MovementReceipt } from "./receipt";
import {
  verifyFetchedItemReceipt,
  type FetchReceiptFailure,
  type FetchedItemReceiptView,
} from "./verifyItemReceipt";

export const INTENTDB_VERIFIER_BOT_ID = "intentdb-verifier-v1";
export const INTENTDB_VERIFY_ENV = "EXPO_PUBLIC_INTENTDB_VERIFY";

export type VerifyIntentFailure =
  | "disabled"
  | "locked"
  | "network"
  | "rejected"
  | FetchReceiptFailure;

export type VerifyIntentItemResult =
  | { verified: false; reason: VerifyIntentFailure; status?: number }
  | {
      verified: true;
      itemId: string;
      op: string;
      contentSha256: string;
      botId: typeof INTENTDB_VERIFIER_BOT_ID;
    };

export type VerifyIntentItemInput = {
  itemId: string;
  sessionToken: string;
  unlocked: boolean;
  /** Pin for the receipt signature. A key in the response is not used. */
  publicKeyHex?: string;
  /** Overrides EXPO_PUBLIC_INTENTDB_VERIFY. Omit it to read the env flag. */
  enabled?: boolean;
  apiBaseUrl?: string;
  log?: (message: string) => void;
  fetchImpl?: (
    url: string,
    init: { method: string; headers: Record<string, string>; body?: string },
  ) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;
};

export function intentdbVerifyEnabled(override: boolean | undefined): boolean {
  if (typeof override === "boolean") return override;
  return process.env[INTENTDB_VERIFY_ENV] === "1";
}

/**
 * Load one item and its latest receipt and check the signature and content hash.
 * Failure leaves the caller's item untouched.
 */
export async function verifyIntentItem(
  input: VerifyIntentItemInput,
): Promise<VerifyIntentItemResult> {
  if (!intentdbVerifyEnabled(input.enabled)) {
    return { verified: false, reason: "disabled" };
  }
  if (input.unlocked !== true) {
    return { verified: false, reason: "locked" };
  }
  const itemId = canonicalItemId(input.itemId);
  if (!itemId || !sessionOk(input.sessionToken)) {
    return { verified: false, reason: "rejected" };
  }

  try {
    const base = input.apiBaseUrl ?? getApiUrl();
    const url = new URL(`/api/vault/items/${encodeURIComponent(itemId)}`, base);
    const request = {
      method: "GET",
      headers: { "x-session-token": input.sessionToken },
    };
    const response = input.fetchImpl
      ? await input.fetchImpl(url.toString(), request)
      : await fetch(url.toString(), request);
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      return { verified: false, reason: "rejected", status: response.status };
    }
    const view = viewFromPayload(itemId, text);
    if (!view) return { verified: false, reason: "rejected" };
    const receipt = receiptFromPayload(text);
    const decision = verifyFetchedItemReceipt({
      item: view.item,
      receipt,
      publicKeyHex: input.publicKeyHex,
      log: input.log,
    });
    if (!decision.accepted) {
      audit(input.log, view.item.itemId, safeOp(receipt), decision.reason);
      return { verified: false, reason: decision.reason };
    }
    const op = safeOp(receipt);
    if (!op) return { verified: false, reason: "rejected" };
    return {
      verified: true,
      itemId: view.item.itemId,
      op,
      contentSha256: view.item.contentSha256,
      botId: INTENTDB_VERIFIER_BOT_ID,
    };
  } catch {
    return { verified: false, reason: "network" };
  }
}

function viewFromPayload(
  itemId: string,
  text: string,
): { item: FetchedItemReceiptView } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const body = parsed as Record<string, unknown>;
  if (body.itemId !== itemId) return null;
  if (typeof body.version !== "number" || !Number.isSafeInteger(body.version) || body.version < 0) {
    return null;
  }
  if (typeof body.contentSha256 !== "string" || !/^[0-9a-f]{64}$/.test(body.contentSha256)) {
    return null;
  }
  if (typeof body.tombstone !== "boolean") return null;
  return {
    item: {
      itemId,
      version: body.version,
      contentSha256: body.contentSha256,
      tombstone: body.tombstone,
    },
  };
}

function receiptFromPayload(text: string): MovementReceipt | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const receipt = (parsed as { receipt?: unknown }).receipt;
  if (receipt === null || receipt === undefined) return null;
  if (typeof receipt !== "object") return null;
  return receipt as MovementReceipt;
}

function canonicalItemId(value: string): string | null {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || /[\0\n\r:]/.test(value)) {
    return null;
  }
  return value;
}

function sessionOk(value: string): boolean {
  return typeof value === "string" && /^[0-9a-fA-F]{64}$/.test(value);
}

function safeOp(receipt: MovementReceipt | null): string {
  if (!receipt || typeof receipt.op !== "string") return "";
  return /^[a-z]{1,16}$/.test(receipt.op) ? receipt.op : "";
}

function audit(
  log: VerifyIntentItemInput["log"],
  itemId: string,
  op: string,
  reason: FetchReceiptFailure,
): void {
  const safeId = itemId.replace(/[\u0000-\u001F\u007F]/g, "").slice(0, 128);
  safeLog(log, `intentdb verifier audit itemId=${safeId} op=${op} reason=${reason}`);
}

function safeLog(log: VerifyIntentItemInput["log"], message: string): void {
  try {
    (log ?? defaultLog)(message);
  } catch {
    // A logger must not turn a rejected receipt into an item write.
  }
}

function defaultLog(message: string): void {
  console.warn(message);
}
