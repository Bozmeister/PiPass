/**
 * Canonical encoding of a pipass-tombstone-v1 outbox record.
 *
 * contentSha256 inside the document is the deleted item's content hash
 * (or the unbound delete hash). It is part of the body. tombstoneDocumentSha256
 * is SHA-256 of this encoding and is not part of the body.
 * The server recomputes that document hash before storing a tombstone.
 */

import { sha256Utf8Hex } from "./itemManifest";

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

/** Fixed key order. Matches the server copy in server/tombstoneProof.ts. */
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
  return sha256Utf8Hex(canonicalTombstoneBody(body));
}
