/**
 * Server-side check for a pipass-item-v1 ciphertext manifest.
 *
 * Uses node:crypto only. Do not import lib/intentdb or crypto/encryption:
 * those modules load the client AES-GCM path. This file does not decrypt.
 * The canonical JSON matches canonicalManifestBody in lib/intentdb/itemManifest.ts.
 * contentSha256 is SHA-256 of that JSON and is not part of the body.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import type { VaultItemPutInput } from "../shared/schema";

export const OPAQUE_ITEM_SCHEMA = "pipass-item-v1" as const;

const V4_CIPHERTEXT =
  /^v4:[0-9a-fA-F]{24}:(?:[0-9a-fA-F]{2})*:[0-9a-fA-F]{32}$/;

const ENTRY_REQUIRED = ["password", "title", "username"] as const;
const ENTRY_ALLOWED = new Set<string>([
  ...ENTRY_REQUIRED,
  "url",
  "notes",
  "aux",
  "itemKey",
]);
const NOTE_REQUIRED = ["label", "content"] as const;
const NOTE_ALLOWED = new Set<string>([...NOTE_REQUIRED, "itemKey"]);

export type OpaqueItemField = {
  name: string;
  ciphertext: string;
};

export type AcceptedOpaqueItem = {
  schema: typeof OPAQUE_ITEM_SCHEMA;
  itemId: string;
  kind: "vault-entry" | "secure-note";
  version: number;
  salt: string;
  createdAt: number;
  updatedAt: number;
  fields: OpaqueItemField[];
  contentSha256: string;
  locator: string;
  tombstone: boolean;
};

export type ItemManifestProofResult =
  | { ok: true; item: AcceptedOpaqueItem }
  | { ok: false; error: "Invalid fields" | "Invalid version" | "Hash mismatch" };

export function isOpaqueItemId(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 128 &&
    !/[\0\n\r:]/.test(value)
  );
}

/** Canonical UTF-8 JSON. Key order matches the client manifest hash. */
export function canonicalItemBody(body: {
  schema: typeof OPAQUE_ITEM_SCHEMA;
  itemId: string;
  kind: "vault-entry" | "secure-note";
  version: number;
  salt: string;
  createdAt: number;
  updatedAt: number;
  fields: OpaqueItemField[];
}): string {
  const fields = [...body.fields].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
  const fieldJson = fields
    .map(
      (field) =>
        `{"ciphertext":${JSON.stringify(field.ciphertext)},"name":${JSON.stringify(field.name)}}`,
    )
    .join(",");
  return `{${[
    `"createdAt":${body.createdAt}`,
    `"fields":[${fieldJson}]`,
    `"itemId":${JSON.stringify(body.itemId)}`,
    `"kind":${JSON.stringify(body.kind)}`,
    `"salt":${JSON.stringify(body.salt)}`,
    `"schema":${JSON.stringify(body.schema)}`,
    `"updatedAt":${body.updatedAt}`,
    `"version":${body.version}`,
  ].join(",")}}`;
}

export function itemContentSha256(body: {
  schema: typeof OPAQUE_ITEM_SCHEMA;
  itemId: string;
  kind: "vault-entry" | "secure-note";
  version: number;
  salt: string;
  createdAt: number;
  updatedAt: number;
  fields: OpaqueItemField[];
}): string {
  return createHash("sha256").update(canonicalItemBody(body), "utf8").digest("hex");
}

function fieldsAreAuthenticated(
  kind: "vault-entry" | "secure-note",
  fields: OpaqueItemField[],
): boolean {
  const allowed = kind === "vault-entry" ? ENTRY_ALLOWED : NOTE_ALLOWED;
  const required = kind === "vault-entry" ? ENTRY_REQUIRED : NOTE_REQUIRED;
  const seen = new Set<string>();
  for (const field of fields) {
    if (seen.has(field.name) || !allowed.has(field.name)) return false;
    if (!V4_CIPHERTEXT.test(field.ciphertext)) return false;
    seen.add(field.name);
  }
  for (const name of required) {
    if (!seen.has(name)) return false;
  }
  return true;
}

function hashesMatch(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  const leftBuf = Buffer.from(left, "utf8");
  const rightBuf = Buffer.from(right, "utf8");
  if (leftBuf.length !== rightBuf.length) return false;
  return timingSafeEqual(leftBuf, rightBuf);
}

/**
 * Accept a parsed put body only when the field set is v4 ciphertext and
 * contentSha256 equals the canonical manifest hash.
 */
export function acceptOpaqueItemManifest(
  input: VaultItemPutInput,
): ItemManifestProofResult {
  if (!fieldsAreAuthenticated(input.kind, input.fields)) {
    return { ok: false, error: "Invalid fields" };
  }
  if (input.version !== input.updatedAt) {
    return { ok: false, error: "Invalid version" };
  }
  const fields = [...input.fields]
    .map((field) => ({ name: field.name, ciphertext: field.ciphertext }))
    .sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    );
  const expected = itemContentSha256({
    schema: OPAQUE_ITEM_SCHEMA,
    itemId: input.itemId,
    kind: input.kind,
    version: input.version,
    salt: input.salt,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    fields,
  });
  if (!hashesMatch(expected, input.contentSha256)) {
    return { ok: false, error: "Hash mismatch" };
  }
  return {
    ok: true,
    item: {
      schema: OPAQUE_ITEM_SCHEMA,
      itemId: input.itemId,
      kind: input.kind,
      version: input.version,
      salt: input.salt,
      createdAt: input.createdAt,
      updatedAt: input.updatedAt,
      fields,
      contentSha256: input.contentSha256,
      locator: input.locator,
      tombstone: input.tombstone,
    },
  };
}
