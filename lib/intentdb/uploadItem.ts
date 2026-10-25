/**
 * Optional upload of one staged outbox manifest.
 *
 * The phone vault and the local outbox stay authoritative. This helper
 * never writes SecureStore, never deletes an outbox record, and never
 * throws if the network or the server rejects the upload.
 *
 * Default is off. Set EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1, or pass
 * enabled: true, before any request is made.
 *
 * Manifest records go to PUT /api/vault/items. Tombstone records go to
 * PUT /api/vault/items/:itemId/tombstone. A tombstone upload does not
 * write the local vault and does not recreate a deleted entry.
 *
 * The request uses x-session-token plus vaultKeyProof. It does not send
 * the long-lived auth hash.
 */

import { getApiUrl } from "../api-url";
import type { ItemTombstone, OutboxRecord } from "../../workers/intentdbOutbox";
import type { ItemManifest } from "./itemManifest";
import { tombstoneDocumentSha256 } from "./tombstone";

export const INTENTDB_ITEM_UPLOAD_ENV = "EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD";
export const DEFAULT_ITEM_LOCATOR = "phone";

export type ItemUploadResult =
  | { uploaded: false; reason: "disabled" | "network" | "rejected"; status?: number }
  | { uploaded: true; itemId: string; contentSha256: string };

export type ItemUploadRequest = {
  record: OutboxRecord;
  sessionToken: string;
  vaultKeyProof: string;
  locator?: string;
  /** Overrides the env flag. Omit it to read EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD. */
  enabled?: boolean;
  apiBaseUrl?: string;
  fetchImpl?: (
    url: string,
    init: { method: string; headers: Record<string, string>; body?: string },
  ) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;
};

export function intentdbItemUploadEnabled(override: boolean | undefined): boolean {
  if (typeof override === "boolean") return override;
  return process.env[INTENTDB_ITEM_UPLOAD_ENV] === "1";
}

function credentialsOk(sessionToken: string, vaultKeyProof: string): boolean {
  return (
    typeof sessionToken === "string" &&
    sessionToken.length > 0 &&
    typeof vaultKeyProof === "string" &&
    /^[0-9a-f]{64}$/.test(vaultKeyProof)
  );
}

function manifestBody(manifest: ItemManifest, locator: string, vaultKeyProof: string) {
  return {
    schema: manifest.schema,
    itemId: manifest.itemId,
    kind: manifest.kind,
    version: manifest.version,
    salt: manifest.salt,
    createdAt: manifest.createdAt,
    updatedAt: manifest.updatedAt,
    fields: manifest.fields.map((field) => ({
      name: field.name,
      ciphertext: field.ciphertext,
    })),
    contentSha256: manifest.contentSha256,
    locator,
    tombstone: false,
    vaultKeyProof,
  };
}

function tombstoneBody(tombstone: ItemTombstone, vaultKeyProof: string) {
  const document = {
    schema: tombstone.schema,
    itemId: tombstone.itemId,
    kind: tombstone.kind,
    itemVersion: tombstone.itemVersion,
    contentSha256: tombstone.contentSha256,
    contentBound: tombstone.contentBound,
    deletedAt: tombstone.deletedAt,
  };
  return {
    ...document,
    tombstoneSha256: tombstoneDocumentSha256(document),
    vaultKeyProof,
  };
}

/**
 * Upload one staged manifest when the feature flag is on.
 * Failure leaves the caller's record and any local vault data untouched.
 */
export async function uploadStagedOutboxItem(
  input: ItemUploadRequest,
): Promise<ItemUploadResult> {
  if (!intentdbItemUploadEnabled(input.enabled)) {
    return { uploaded: false, reason: "disabled" };
  }
  if (!credentialsOk(input.sessionToken, input.vaultKeyProof)) {
    return { uploaded: false, reason: "rejected" };
  }

  try {
    const base = input.apiBaseUrl ?? getApiUrl();
    if (input.record.kind === "manifest") {
      const locator = input.locator ?? DEFAULT_ITEM_LOCATOR;
      if (
        locator.length < 1 ||
        locator.length > 200 ||
        /[\u0000-\u001F\u007F]/.test(locator)
      ) {
        return { uploaded: false, reason: "rejected" };
      }
      const url = new URL("/api/vault/items", base);
      const request = {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          "x-session-token": input.sessionToken,
        },
        body: JSON.stringify(
          manifestBody(input.record.manifest, locator, input.vaultKeyProof),
        ),
      };
      const response = input.fetchImpl
        ? await input.fetchImpl(url.toString(), request)
        : await fetch(url.toString(), request);
      await response.text().catch(() => "");
      if (!response.ok) {
        return { uploaded: false, reason: "rejected", status: response.status };
      }
      return {
        uploaded: true,
        itemId: input.record.manifest.itemId,
        contentSha256: input.record.manifest.contentSha256,
      };
    }

    const tombstone = input.record.tombstone;
    const url = new URL(
      `/api/vault/items/${encodeURIComponent(tombstone.itemId)}/tombstone`,
      base,
    );
    const request = {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "x-session-token": input.sessionToken,
      },
      body: JSON.stringify(tombstoneBody(tombstone, input.vaultKeyProof)),
    };
    const response = input.fetchImpl
      ? await input.fetchImpl(url.toString(), request)
      : await fetch(url.toString(), request);
    await response.text().catch(() => "");
    if (!response.ok) {
      return { uploaded: false, reason: "rejected", status: response.status };
    }
    return {
      uploaded: true,
      itemId: tombstone.itemId,
      contentSha256: tombstone.contentSha256,
    };
  } catch {
    return { uploaded: false, reason: "network" };
  }
}
