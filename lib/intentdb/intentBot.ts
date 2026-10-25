/**
 * Propose one locator move as the IntentDB bot.
 *
 * The bot calls the existing move request, which posts to
 * POST /api/vault/items/:itemId/move and checks the receipt with
 * verifyFetchedItemReceipt. The phone vault stays authoritative.
 * applyLocator runs only after that check accepts a move whose botId
 * is intentdb-bot-v1 and whose content hash is unchanged.
 *
 * Default is off. Set EXPO_PUBLIC_INTENTDB_BOT_MOVE=1, or pass
 * enabled: true. Pass unlocked: true only while the vault is unlocked.
 * This helper does not read vault key shares.
 *
 * The request uses x-session-token plus vaultKeyProof.
 */

import {
  INTENTDB_BOT_ID,
  requestItemLocatorMove,
  type ItemMoveRequest,
} from "./moveItem";

export { INTENTDB_BOT_ID };

export const INTENTDB_BOT_MOVE_ENV = "EXPO_PUBLIC_INTENTDB_BOT_MOVE";
export const INTENTDB_BOT_TIER_LOCATOR = "tier-1";
export const INTENTDB_BOT_REPLICA_LOCATOR = "tier-1-replica";

export type IntentBotMoveResult =
  | {
      proposed: false;
      reason: "disabled" | "locked" | "rejected" | "network" | "unverified";
      status?: number;
    }
  | {
      proposed: true;
      itemId: string;
      locator: string;
      contentSha256: string;
      botId: typeof INTENTDB_BOT_ID;
    };

export type IntentBotMoveInput = {
  itemId: string;
  fromLocator: string;
  /** Defaults to tier-1. */
  toLocator?: string;
  version: number;
  contentSha256: string;
  sessionToken: string;
  vaultKeyProof: string;
  unlocked: boolean;
  /** Pin for the receipt signature. A key in the response is not used. */
  publicKeyHex?: string;
  /** Overrides EXPO_PUBLIC_INTENTDB_BOT_MOVE. Omit it to read the env flag. */
  enabled?: boolean;
  apiBaseUrl?: string;
  log?: (message: string) => void;
  /** Called only after the bot move receipt is accepted. */
  applyLocator?: (update: { itemId: string; locator: string }) => void;
  /** Called only after a replicate receipt is accepted. Both locators are kept. */
  applyLocators?: (update: { itemId: string; locators: string[] }) => void;
  fetchImpl?: ItemMoveRequest["fetchImpl"];
};

export type IntentBotReplicateResult =
  | {
      proposed: false;
      reason: "disabled" | "locked" | "rejected" | "network" | "unverified";
      status?: number;
    }
  | {
      proposed: true;
      itemId: string;
      fromLocator: string;
      toLocator: string;
      locators: [string, string];
      contentSha256: string;
      botId: typeof INTENTDB_BOT_ID;
    };

export function intentdbBotMoveEnabled(override: boolean | undefined): boolean {
  if (typeof override === "boolean") return override;
  return process.env[INTENTDB_BOT_MOVE_ENV] === "1";
}

/**
 * Propose and execute one bot locator move when the flag is on and the
 * vault is unlocked. Failure leaves the caller's local record untouched.
 */
export async function proposeIntentBotMove(input: IntentBotMoveInput): Promise<IntentBotMoveResult> {
  if (!intentdbBotMoveEnabled(input.enabled)) {
    return { proposed: false, reason: "disabled" };
  }
  if (input.unlocked !== true) {
    return { proposed: false, reason: "locked" };
  }
  const toLocator = input.toLocator ?? INTENTDB_BOT_TIER_LOCATOR;
  if (typeof input.fromLocator !== "string" || input.fromLocator === toLocator) {
    return { proposed: false, reason: "rejected" };
  }

  const result = await requestItemLocatorMove({
    itemId: input.itemId,
    newLocator: toLocator,
    fromLocator: input.fromLocator,
    version: input.version,
    contentSha256: input.contentSha256,
    sessionToken: input.sessionToken,
    vaultKeyProof: input.vaultKeyProof,
    botId: INTENTDB_BOT_ID,
    publicKeyHex: input.publicKeyHex,
    enabled: true,
    apiBaseUrl: input.apiBaseUrl,
    log: input.log,
    applyLocator: input.applyLocator,
    fetchImpl: input.fetchImpl,
  });
  if (!result.moved) {
    return result.status === undefined
      ? { proposed: false, reason: result.reason }
      : { proposed: false, reason: result.reason, status: result.status };
  }
  return {
    proposed: true,
    itemId: result.itemId,
    locator: result.locator,
    contentSha256: result.contentSha256,
    botId: INTENTDB_BOT_ID,
  };
}

/**
 * Propose a replica. The receipt op is copy. The original locator stays.
 * applyLocators runs only after the receipt checks out.
 */
export async function proposeIntentBotReplicate(
  input: IntentBotMoveInput,
): Promise<IntentBotReplicateResult> {
  if (!intentdbBotMoveEnabled(input.enabled)) {
    return { proposed: false, reason: "disabled" };
  }
  if (input.unlocked !== true) {
    return { proposed: false, reason: "locked" };
  }
  const toLocator = input.toLocator ?? INTENTDB_BOT_REPLICA_LOCATOR;
  if (typeof input.fromLocator !== "string" || input.fromLocator === toLocator) {
    return { proposed: false, reason: "rejected" };
  }

  const result = await requestItemLocatorMove({
    itemId: input.itemId,
    newLocator: toLocator,
    fromLocator: input.fromLocator,
    version: input.version,
    contentSha256: input.contentSha256,
    sessionToken: input.sessionToken,
    vaultKeyProof: input.vaultKeyProof,
    botId: INTENTDB_BOT_ID,
    operation: "copy",
    publicKeyHex: input.publicKeyHex,
    enabled: true,
    apiBaseUrl: input.apiBaseUrl,
    log: input.log,
    applyLocators: input.applyLocators,
    fetchImpl: input.fetchImpl,
  });
  if (!result.moved) {
    return result.status === undefined
      ? { proposed: false, reason: result.reason }
      : { proposed: false, reason: result.reason, status: result.status };
  }
  const locators: [string, string] = [input.fromLocator, toLocator];
  return {
    proposed: true,
    itemId: result.itemId,
    fromLocator: input.fromLocator,
    toLocator,
    locators,
    contentSha256: result.contentSha256,
    botId: INTENTDB_BOT_ID,
  };
}
