/**
 * Report which IntentDB flags are on, and whether the local search index
 * ciphertext is stored. The report is booleans and a single status line.
 * It does not open vault fields and does not include pins, tokens, or keys.
 */

import { INTENTDB_ENVELOPE_ENV, intentdbEnvelopeEnabled } from "../../crypto/itemEnvelope";
import { readPlatformItem } from "../platformStorage";
import { SEARCH_INDEX_STORAGE_KEY } from "../vaultSearchKey";
import { PIPASS_ACCOUNT_DELETE_ENV, pipassAccountDeleteEnabled } from "./deleteAccount";
import { INTENTDB_BOT_MOVE_ENV, intentdbBotMoveEnabled } from "./intentBot";
import { INTENTDB_ITEM_UPLOAD_ENV, intentdbItemUploadEnabled } from "./uploadItem";
import { INTENTDB_VERIFY_ENV, intentdbVerifyEnabled } from "./verifyBot";

export {
  INTENTDB_BOT_MOVE_ENV,
  INTENTDB_ENVELOPE_ENV,
  INTENTDB_ITEM_UPLOAD_ENV,
  INTENTDB_VERIFY_ENV,
  PIPASS_ACCOUNT_DELETE_ENV,
};

export type IntentdbFeatureStatus = {
  itemUpload: boolean;
  accountDelete: boolean;
  botMove: boolean;
  envelope: boolean;
  verify: boolean;
  searchIndexPresent: boolean;
};

export type FeatureStatusReader = (key: string) => Promise<string | null>;

export async function reportFeatureStatus(
  readStorage?: FeatureStatusReader,
): Promise<IntentdbFeatureStatus> {
  return {
    itemUpload: intentdbItemUploadEnabled(undefined),
    accountDelete: pipassAccountDeleteEnabled(undefined),
    botMove: intentdbBotMoveEnabled(undefined),
    envelope: intentdbEnvelopeEnabled(),
    verify: intentdbVerifyEnabled(undefined),
    searchIndexPresent: await searchIndexPresent(readStorage ?? readPlatformItem),
  };
}

export function formatFeatureStatus(report: IntentdbFeatureStatus): string {
  const bit = (value: boolean) => (value === true ? "1" : "0");
  return `intentdb status upload=${bit(report.itemUpload)} delete=${bit(report.accountDelete)} bot=${bit(report.botMove)} envelope=${bit(report.envelope)} verify=${bit(report.verify)} searchIndex=${bit(report.searchIndexPresent)}`;
}

async function searchIndexPresent(readStorage: FeatureStatusReader): Promise<boolean> {
  try {
    const raw = await readStorage(SEARCH_INDEX_STORAGE_KEY);
    if (typeof raw !== "string" || raw.length === 0 || raw.length > 256) return false;
    const parsed = JSON.parse(raw) as { v?: unknown; chunks?: unknown };
    return (
      parsed?.v === 1 &&
      typeof parsed.chunks === "number" &&
      Number.isSafeInteger(parsed.chunks) &&
      parsed.chunks >= 1 &&
      parsed.chunks <= 10_000
    );
  } catch {
    return false;
  }
}
