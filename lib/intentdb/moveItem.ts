/**
 * Request a locator move and adopt it only when the receipt checks out.
 *
 * The phone vault stays authoritative. This helper does not write the
 * vault itself. applyLocator runs only after verifyFetchedItemReceipt
 * accepts a move receipt whose content hash matches the caller's hash.
 * A failed check is logged and local data is left alone.
 *
 * Default is off. Set EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1, or pass
 * enabled: true, before any request is made.
 *
 * The request uses x-session-token plus vaultKeyProof.
 */

import { getApiUrl } from "../api-url";
import { TOMBSTONE_LOCATOR, type MovementReceipt } from "./receipt";
import { intentdbItemUploadEnabled } from "./uploadItem";
import { verifyFetchedItemReceipt } from "./verifyItemReceipt";

/** Proposer id the move route will stamp onto a receipt. */
export const INTENTDB_BOT_ID = "intentdb-bot-v1";

export type ItemMoveResult =
  | { moved: false; reason: "disabled" | "network" | "rejected" | "unverified"; status?: number }
  | { moved: true; itemId: string; locator: string; contentSha256: string };

export type ItemMoveRequest = {
  itemId: string;
  newLocator: string;
  version: number;
  contentSha256: string;
  sessionToken: string;
  vaultKeyProof: string;
  /** When set, the move is proposed as this bot and the receipt must match. */
  botId?: typeof INTENTDB_BOT_ID;
  /** When set, the receipt fromLocator must match before a local apply. */
  fromLocator?: string;
  /** Pin for the receipt signature. A key in the response is not used. */
  publicKeyHex?: string;
  /** Overrides EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD. Omit it to read the env flag. */
  enabled?: boolean;
  apiBaseUrl?: string;
  log?: (message: string) => void;
  /**
   * move posts to /move and expects op move.
   * copy posts to /replicate, expects op copy, and keeps the original locator.
   */
  operation?: "move" | "copy";
  /** Called only after a move receipt is accepted. */
  applyLocator?: (update: { itemId: string; locator: string }) => void;
  /** Called only after a copy receipt is accepted. Both locators are kept. */
  applyLocators?: (update: { itemId: string; locators: string[] }) => void;
  fetchImpl?: (
    url: string,
    init: { method: string; headers: Record<string, string>; body: string },
  ) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;
};

type MoveBody = {
  itemId?: unknown;
  version?: unknown;
  contentSha256?: unknown;
  locator?: unknown;
  tombstone?: unknown;
  receipt?: unknown;
};

/**
 * POST one locator move when the feature flag is on.
 * Failure leaves the caller's local record untouched.
 */
export async function requestItemLocatorMove(input: ItemMoveRequest): Promise<ItemMoveResult> {
  if (!intentdbItemUploadEnabled(input.enabled)) {
    return { moved: false, reason: "disabled" };
  }
  if (!requestOk(input)) {
    return { moved: false, reason: "rejected" };
  }

  let response: { ok: boolean; status: number; text: () => Promise<string> };
  try {
    const base = input.apiBaseUrl ?? getApiUrl();
    const action = input.operation === "copy" ? "replicate" : "move";
    const url = new URL(
      `/api/vault/items/${encodeURIComponent(input.itemId)}/${action}`,
      base,
    );
    const request = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-session-token": input.sessionToken,
      },
      body: JSON.stringify(movePayload(input)),
    };
    response = input.fetchImpl
      ? await input.fetchImpl(url.toString(), request)
      : await fetch(url.toString(), request);
  } catch {
    return { moved: false, reason: "network" };
  }

  let text = "";
  try {
    text = await response.text();
  } catch {
    return { moved: false, reason: "network" };
  }
  if (!response.ok) {
    return { moved: false, reason: "rejected", status: response.status };
  }

  const body = readMoveBody(text);
  if (!body) {
    return { moved: false, reason: "rejected" };
  }
  return adoptMove(input, body);
}

function adoptMove(input: ItemMoveRequest, body: MoveBody): ItemMoveResult {
  const itemId = input.itemId;
  if (body.contentSha256 !== input.contentSha256) {
    logFailure(input.log, itemId, "hash-mismatch");
    return { moved: false, reason: "unverified" };
  }
  const receipt = body.receipt;
  if (isReceiptRecord(receipt) && receipt.contentSha256 !== input.contentSha256) {
    logFailure(input.log, itemId, "hash-mismatch");
    return { moved: false, reason: "unverified" };
  }
  if (!isExpectedMove(input, body, receipt)) {
    if (!receipt) {
      verifyFetchedItemReceipt({
        item: expectedItem(input),
        receipt: null,
        publicKeyHex: input.publicKeyHex,
        log: input.log,
      });
    } else {
      logFailure(input.log, itemId, "item-mismatch");
    }
    return { moved: false, reason: "unverified" };
  }

  const decision = verifyFetchedItemReceipt({
    item: expectedItem(input),
    receipt,
    publicKeyHex: input.publicKeyHex,
    log: input.log,
    commit: () => {
      if (input.operation === "copy" && input.fromLocator) {
        input.applyLocators?.({
          itemId,
          locators: [input.fromLocator, input.newLocator],
        });
        return;
      }
      input.applyLocator?.({ itemId, locator: input.newLocator });
    },
  });
  if (!decision.accepted) {
    return { moved: false, reason: "unverified" };
  }
  return {
    moved: true,
    itemId,
    locator: input.newLocator,
    contentSha256: input.contentSha256,
  };
}

function expectedItem(input: ItemMoveRequest) {
  return {
    itemId: input.itemId,
    version: input.version,
    contentSha256: input.contentSha256,
    tombstone: false,
  };
}

function isExpectedMove(
  input: ItemMoveRequest,
  body: MoveBody,
  receipt: unknown,
): receipt is MovementReceipt {
  return (
    body.itemId === input.itemId &&
    body.version === input.version &&
    body.locator === (input.operation === "copy" ? input.fromLocator : input.newLocator) &&
    body.tombstone === false &&
    isReceiptRecord(receipt) &&
    receipt.op === (input.operation === "copy" ? "copy" : "move") &&
    receipt.itemId === input.itemId &&
    receipt.itemVersion === input.version &&
    receipt.toLocator === input.newLocator &&
    receipt.contentSha256 === input.contentSha256 &&
    receipt.toLocator !== TOMBSTONE_LOCATOR &&
    (input.botId === undefined || receipt.botId === input.botId) &&
    (input.fromLocator === undefined || receipt.fromLocator === input.fromLocator)
  );
}

function isReceiptRecord(value: unknown): value is MovementReceipt {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function requestOk(input: ItemMoveRequest): boolean {
  return (
    itemIdOk(input.itemId) &&
    locatorOk(input.newLocator) &&
    typeof input.version === "number" &&
    Number.isSafeInteger(input.version) &&
    input.version >= 0 &&
    typeof input.contentSha256 === "string" &&
    /^[0-9a-f]{64}$/.test(input.contentSha256) &&
    typeof input.sessionToken === "string" &&
    input.sessionToken.length > 0 &&
    typeof input.vaultKeyProof === "string" &&
    /^[0-9a-f]{64}$/.test(input.vaultKeyProof) &&
    (input.botId === undefined || input.botId === INTENTDB_BOT_ID) &&
    (input.fromLocator === undefined || locatorOk(input.fromLocator)) &&
    (input.operation === undefined || input.operation === "move" || input.operation === "copy") &&
    (input.operation !== "copy" || locatorOk(input.fromLocator ?? ""))
  );
}

function movePayload(input: ItemMoveRequest): {
  newLocator: string;
  vaultKeyProof: string;
  botId?: typeof INTENTDB_BOT_ID;
} {
  const payload: {
    newLocator: string;
    vaultKeyProof: string;
    botId?: typeof INTENTDB_BOT_ID;
  } = {
    newLocator: input.newLocator,
    vaultKeyProof: input.vaultKeyProof,
  };
  if (input.botId) payload.botId = input.botId;
  return payload;
}

function itemIdOk(value: string): boolean {
  return typeof value === "string" && value.length >= 1 && value.length <= 128 && !/[\0\n\r:]/.test(value);
}

function locatorOk(value: string): boolean {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 200 &&
    value !== TOMBSTONE_LOCATOR &&
    !/[\u0000-\u001F\u007F]/.test(value)
  );
}

function readMoveBody(text: string): MoveBody | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as MoveBody;
  } catch {
    return null;
  }
}

function logFailure(
  log: ItemMoveRequest["log"],
  itemId: string,
  reason: string,
): void {
  const safeId = itemId.replace(/[\u0000-\u001F\u007F]/g, "").slice(0, 128);
  try {
    (log ?? ((message: string) => console.warn(message)))(
      `intentdb receipt verification failed itemId=${safeId} reason=${reason}`,
    );
  } catch {
    // A logger must not turn a rejected move into a local write.
  }
}
