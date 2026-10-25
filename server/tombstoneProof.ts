/**
 * Server check for a pipass-tombstone-v1 document.
 *
 * node:crypto only. Does not decrypt. The canonical JSON matches
 * canonicalTombstoneBody in lib/intentdb/tombstone.ts.
 * contentSha256 is the deleted item hash and stays inside the body.
 * tombstoneSha256 is SHA-256 of that body.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import type { VaultItemTombstonePutInput } from "../shared/schema";

export const TOMBSTONE_DOCUMENT_SCHEMA = "pipass-tombstone-v1" as const;

export type TombstoneDocument = {
  schema: typeof TOMBSTONE_DOCUMENT_SCHEMA;
  itemId: string;
  kind: "vault-entry" | "secure-note";
  itemVersion: number;
  contentSha256: string;
  contentBound: boolean;
  deletedAt: number;
};

export type AcceptedTombstone = {
  itemId: string;
  kind: "vault-entry" | "secure-note";
  version: number;
  contentSha256: string;
  deletedAt: number;
};

export function canonicalTombstoneBody(body: TombstoneDocument): string {
  return `{${[
    `"contentBound":${body.contentBound}`,
    `"contentSha256":${JSON.stringify(body.contentSha256)}`,
    `"deletedAt":${body.deletedAt}`,
    `"itemId":${JSON.stringify(body.itemId)}`,
    `"itemVersion":${body.itemVersion}`,
    `"kind":${JSON.stringify(body.kind)}`,
    `"schema":${JSON.stringify(body.schema)}`,
  ].join(",")}}`;
}

export function tombstoneDocumentSha256(body: TombstoneDocument): string {
  return createHash("sha256").update(canonicalTombstoneBody(body), "utf8").digest("hex");
}

function hashesMatch(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  const leftBuf = Buffer.from(left, "utf8");
  const rightBuf = Buffer.from(right, "utf8");
  if (leftBuf.length !== rightBuf.length) return false;
  return timingSafeEqual(leftBuf, rightBuf);
}

export function acceptOpaqueItemTombstone(
  input: VaultItemTombstonePutInput,
): { ok: true; tombstone: AcceptedTombstone } | { ok: false; error: "Hash mismatch" } {
  const document: TombstoneDocument = {
    schema: TOMBSTONE_DOCUMENT_SCHEMA,
    itemId: input.itemId,
    kind: input.kind,
    itemVersion: input.itemVersion,
    contentSha256: input.contentSha256,
    contentBound: input.contentBound,
    deletedAt: input.deletedAt,
  };
  const expected = tombstoneDocumentSha256(document);
  if (!hashesMatch(expected, input.tombstoneSha256)) {
    return { ok: false, error: "Hash mismatch" };
  }
  return {
    ok: true,
    tombstone: {
      itemId: input.itemId,
      kind: input.kind,
      version: input.itemVersion,
      contentSha256: input.contentSha256,
      deletedAt: input.deletedAt,
    },
  };
}
