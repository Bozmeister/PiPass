/**
 * Retrieval token minting and device-key registration.
 *
 * Run:
 *   node --env-file-if-exists=.env --env-file-if-exists=.env.test --import ./server/__tests__/setup-env.js --import tsx --test --test-force-exit lib/intentdb/__tests__/retrievalToken.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  RETRIEVAL_AUD,
  RETRIEVAL_TTL_MAX_MS,
  canonicalRetrievalClaims,
  generateRetrievalDeviceKey,
  mintRetrievalToken,
  registerRetrievalDeviceKey,
  signRetrievalToken,
} from "../retrievalToken";
import {
  RETRIEVAL_AUD as SERVER_AUD,
  RETRIEVAL_TTL_MAX_MS as SERVER_TTL_MAX_MS,
  canonicalRetrievalClaims as serverCanonicalRetrievalClaims,
  verifyRetrievalToken,
} from "../../../server/retrievalToken";

const USER_ID = "11111111-1111-4111-8111-111111111111";
const ITEM_ID = "retrieval-item-1";

test("client and server sign the same retrieval claims", () => {
  const claims = {
    aud: RETRIEVAL_AUD,
    sub: USER_ID,
    op: "read" as const,
    exp: 1_700_000_090_000,
    nonce: "ab".repeat(32),
    itemIds: ["b-item", "a-item"],
    prefix: "a-",
  };
  assert.equal(RETRIEVAL_AUD, SERVER_AUD);
  assert.equal(RETRIEVAL_TTL_MAX_MS, SERVER_TTL_MAX_MS);
  const clientBody = canonicalRetrievalClaims(claims);
  const serverBody = serverCanonicalRetrievalClaims(claims);
  assert.equal(clientBody, serverBody);
  assert.equal(clientBody.includes(`"itemIds":["a-item","b-item"]`), true);
  assert.equal(clientBody.indexOf('"aud"'), 1);
  assert.equal(clientBody.indexOf('"prefix"') < clientBody.indexOf('"sub"'), true);
});

test("a minted token verifies and does not carry the private key", () => {
  const key = generateRetrievalDeviceKey();
  assert.equal(key.publicKeyHex.length, 64);
  assert.equal(key.privateKeyHex.length, 64);
  const now = 1_700_000_000_000;
  const token = mintRetrievalToken({
    privateKeyHex: key.privateKeyHex,
    publicKeyHex: key.publicKeyHex,
    userId: USER_ID,
    nowMs: now,
    ttlMs: 90_000,
    itemIds: [ITEM_ID],
    nonceHex: "cd".repeat(32),
  });
  const payload = token.split(".")[2];
  assert.equal(payload.includes(key.privateKeyHex), false);
  assert.equal(token.includes(key.privateKeyHex), false);
  assert.equal(token.startsWith(`v1.${key.publicKeyHex}.`), true);

  const accepted = verifyRetrievalToken({
    token,
    itemId: ITEM_ID,
    nowMs: now + 1_000,
    registeredUserIds: [USER_ID],
  });
  assert.equal(accepted.ok, true);
  if (accepted.ok) assert.equal(accepted.userId, USER_ID);

  const expired = verifyRetrievalToken({
    token,
    itemId: ITEM_ID,
    nowMs: now + 90_000,
    registeredUserIds: [USER_ID],
  });
  assert.equal(expired.ok, false);

  const wrongItem = verifyRetrievalToken({
    token,
    itemId: "other-item",
    nowMs: now + 1_000,
    registeredUserIds: [USER_ID],
  });
  assert.equal(wrongItem.ok, false);

  const unregistered = verifyRetrievalToken({
    token,
    itemId: ITEM_ID,
    nowMs: now + 1_000,
    registeredUserIds: [],
  });
  assert.equal(unregistered.ok, false);

  const otherKey = generateRetrievalDeviceKey();
  const swapped = token.replace(key.publicKeyHex, otherKey.publicKeyHex);
  const swappedResult = verifyRetrievalToken({
    token: swapped,
    itemId: ITEM_ID,
    nowMs: now + 1_000,
    registeredUserIds: [USER_ID],
  });
  assert.equal(swappedResult.ok, false);

  const wrongAudience = signRetrievalToken(
    {
      aud: "elsewhere",
      sub: USER_ID,
      op: "read",
      exp: now + 60_000,
      nonce: "ef".repeat(32),
      itemIds: [ITEM_ID],
    },
    key.privateKeyHex,
    key.publicKeyHex,
  );
  assert.equal(
    verifyRetrievalToken({
      token: wrongAudience,
      itemId: ITEM_ID,
      nowMs: now,
      registeredUserIds: [USER_ID],
    }).ok,
    false,
  );
});

test("device registration sends the public key and the session token", async () => {
  const key = generateRetrievalDeviceKey();
  let captured: { url: string; method: string; headers: Record<string, string>; body: string } | null =
    null;
  const result = await registerRetrievalDeviceKey({
    sessionToken: "ab".repeat(32),
    publicKeyHex: key.publicKeyHex,
    apiBaseUrl: "https://items.example",
    fetchImpl: async (url, init) => {
      captured = { url, method: init.method, headers: init.headers, body: init.body };
      return { ok: true, status: 200, text: async () => JSON.stringify({ registered: true }) };
    },
  });
  assert.equal(result.registered, true);
  assert.ok(captured);
  const request = captured as {
    url: string;
    method: string;
    headers: Record<string, string>;
    body: string;
  };
  assert.equal(request.method, "POST");
  assert.equal(request.url, "https://items.example/api/auth/retrieval-device");
  assert.equal(request.headers["x-session-token"], "ab".repeat(32));
  assert.equal(request.headers["x-auth-hash"], undefined);
  assert.equal(request.body, JSON.stringify({ publicKey: key.publicKeyHex }));
  assert.equal(request.body.includes(key.privateKeyHex), false);
});

test("retrieval token source does not send the auth hash or the private key", () => {
  const source = readFileSync("lib/intentdb/retrievalToken.ts", "utf8");
  assert.equal(source.includes("x-auth-hash"), false);
  assert.equal(source.includes("privateKey"), true);
  assert.equal(source.includes("vault_blobs"), false);
  assert.equal(source.includes("pipass-entry-key"), false);
  const server = readFileSync("server/retrievalToken.ts", "utf8");
  assert.equal(server.includes("lib/intentdb"), false);
  assert.equal(server.includes("vault_blobs"), false);
  assert.equal(server.includes("decrypt"), false);
});
