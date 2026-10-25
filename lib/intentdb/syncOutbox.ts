/**
 * Walk the local IntentDB outbox and upload staged manifests and tombstones.
 *
 * Call this after a successful local save or delete, or start the timer
 * while the vault is unlocked. The phone vault and the outbox stay
 * authoritative. A failed upload is logged and leaves both untouched.
 *
 * Default is off. Set EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1, or pass
 * enabled: true. Pass unlocked: true only while the vault key shares
 * are active. This helper does not read or wipe those shares.
 *
 * When EXPO_PUBLIC_INTENTDB_BOT_MOVE=1 as well, a manifest that uploads
 * at the phone locator can propose a bot move. A failed proposal is
 * logged. The outbox record stays.
 *
 * When EXPO_PUBLIC_INTENTDB_VERIFY=1 as well, a successful manifest upload
 * can re-check the latest receipt. A failed check is logged. The outbox
 * record and the phone vault stay.
 */

import type { OutboxRecord } from "../../workers/intentdbOutbox";
import { listIntentdbOutbox } from "../../workers/intentdbOutbox";
import {
  intentdbBotMoveEnabled,
  proposeIntentBotMove,
  type IntentBotMoveResult,
} from "./intentBot";
import {
  DEFAULT_ITEM_LOCATOR,
  intentdbItemUploadEnabled,
  uploadStagedOutboxItem,
  type ItemUploadRequest,
  type ItemUploadResult,
} from "./uploadItem";
import {
  intentdbVerifyEnabled,
  verifyIntentItem,
  type VerifyIntentItemResult,
} from "./verifyBot";

export type IntentdbSyncLogger = (message: string) => void;

export type IntentdbSyncInput = {
  unlocked: boolean;
  /** Overrides EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD. Omit it to read the env flag. */
  enabled?: boolean;
  sessionToken: string;
  vaultKeyProof: string;
  records?: OutboxRecord[];
  listRecords?: () => Promise<OutboxRecord[]>;
  upload?: (record: OutboxRecord) => Promise<ItemUploadResult>;
  log?: IntentdbSyncLogger;
  apiBaseUrl?: string;
  fetchImpl?: ItemUploadRequest["fetchImpl"];
  locator?: string;
  /** Overrides EXPO_PUBLIC_INTENTDB_BOT_MOVE. Omit it to read the env flag. */
  botMove?: boolean;
  /** Pin for a bot move receipt. A key in the response is not used. */
  receiptPublicKey?: string;
  /** Called only after a bot move receipt is accepted. */
  applyLocator?: (update: { itemId: string; locator: string }) => void;
  proposeMove?: (item: {
    itemId: string;
    fromLocator: string;
    version: number;
    contentSha256: string;
  }) => Promise<IntentBotMoveResult>;
  /** Overrides EXPO_PUBLIC_INTENTDB_VERIFY. Omit it to read the env flag. */
  verify?: boolean;
  verifyItem?: (item: { itemId: string }) => Promise<VerifyIntentItemResult>;
};

export type IntentdbSyncResult = {
  ran: boolean;
  attempted: number;
  uploaded: number;
  failed: number;
};

const IDLE: IntentdbSyncResult = { ran: false, attempted: 0, uploaded: 0, failed: 0 };

export async function syncIntentdbOutbox(input: IntentdbSyncInput): Promise<IntentdbSyncResult> {
  if (!intentdbItemUploadEnabled(input.enabled) || input.unlocked !== true) {
    return IDLE;
  }

  let records: OutboxRecord[];
  try {
    records = input.records ?? (await (input.listRecords ?? listIntentdbOutbox)());
  } catch {
    safeLog(input.log, "intentdb outbox sync failed reason=network");
    return { ran: true, attempted: 0, uploaded: 0, failed: 1 };
  }

  const uploadLocator = input.locator ?? DEFAULT_ITEM_LOCATOR;
  let uploaded = 0;
  let failed = 0;
  for (const record of records) {
    const itemId = record.kind === "manifest" ? record.manifest.itemId : record.tombstone.itemId;
    try {
      const result = input.upload
        ? await input.upload(record)
        : await uploadStagedOutboxItem({
            record,
            sessionToken: input.sessionToken,
            vaultKeyProof: input.vaultKeyProof,
            enabled: input.enabled ?? true,
            apiBaseUrl: input.apiBaseUrl,
            fetchImpl: input.fetchImpl,
            locator: input.locator,
          });
      if (result.uploaded) {
        uploaded += 1;
        if (
          record.kind === "manifest" &&
          uploadLocator === DEFAULT_ITEM_LOCATOR &&
          intentdbBotMoveEnabled(input.botMove)
        ) {
          await proposePhoneMove(input, record.manifest, uploadLocator);
        }
        if (record.kind === "manifest" && intentdbVerifyEnabled(input.verify)) {
          await verifyUploadedItem(input, record.manifest.itemId);
        }
      } else {
        failed += 1;
        safeLog(input.log, `intentdb outbox upload failed itemId=${itemId} reason=${result.reason}`);
      }
    } catch {
      failed += 1;
      safeLog(input.log, `intentdb outbox upload failed itemId=${itemId} reason=network`);
    }
  }
  return { ran: true, attempted: records.length, uploaded, failed };
}

async function verifyUploadedItem(input: IntentdbSyncInput, itemId: string): Promise<void> {
  try {
    const checked = input.verifyItem
      ? await input.verifyItem({ itemId })
      : await verifyIntentItem({
          itemId,
          sessionToken: input.sessionToken,
          unlocked: true,
          enabled: true,
          publicKeyHex: input.receiptPublicKey,
          apiBaseUrl: input.apiBaseUrl,
          log: input.log,
          fetchImpl: input.fetchImpl,
        });
    if (!checked.verified) {
      safeLog(input.log, `intentdb verifier failed itemId=${itemId} reason=${checked.reason}`);
    }
  } catch {
    safeLog(input.log, `intentdb verifier failed itemId=${itemId} reason=network`);
  }
}

async function proposePhoneMove(
  input: IntentdbSyncInput,
  manifest: { itemId: string; version: number; contentSha256: string },
  fromLocator: string,
): Promise<void> {
  try {
    const proposed = input.proposeMove
      ? await input.proposeMove({
          itemId: manifest.itemId,
          fromLocator,
          version: manifest.version,
          contentSha256: manifest.contentSha256,
        })
      : await proposeIntentBotMove({
          itemId: manifest.itemId,
          fromLocator,
          version: manifest.version,
          contentSha256: manifest.contentSha256,
          sessionToken: input.sessionToken,
          vaultKeyProof: input.vaultKeyProof,
          unlocked: true,
          enabled: true,
          publicKeyHex: input.receiptPublicKey,
          apiBaseUrl: input.apiBaseUrl,
          log: input.log,
          applyLocator: input.applyLocator,
          fetchImpl: input.fetchImpl,
        });
    if (!proposed.proposed) {
      safeLog(
        input.log,
        `intentdb bot move failed itemId=${manifest.itemId} reason=${proposed.reason}`,
      );
    }
  } catch {
    safeLog(input.log, `intentdb bot move failed itemId=${manifest.itemId} reason=network`);
  }
}

/**
 * Repeat syncIntentdbOutbox on a timer. Stop it on lock. The first pass
 * waits for the interval; call syncIntentdbOutbox directly after a local
 * save or delete when that pass should happen immediately.
 */
export function startIntentdbOutboxSync(
  input: IntentdbSyncInput,
  intervalMs: number,
): { stop: () => void } {
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000) {
    throw new Error("Invalid IntentDB sync interval");
  }
  const timer = setInterval(() => {
    void syncIntentdbOutbox(input).catch(() => {
      safeLog(input.log, "intentdb outbox sync failed reason=network");
    });
  }, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  return {
    stop() {
      clearInterval(timer);
    },
  };
}

function safeLog(log: IntentdbSyncLogger | undefined, message: string): void {
  try {
    (log ?? defaultLog)(message);
  } catch {
    // A local logger must not change the outbox walk.
  }
}

function defaultLog(message: string): void {
  console.warn(message);
}
