import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  PIPASS_ACCOUNT_DELETE_ENV,
  deleteAccountAndResetLocal,
} from "../deleteAccount";

const TOKEN = "ab".repeat(32);

test("account delete stays off unless the feature flag is enabled", async () => {
  const previous = process.env[PIPASS_ACCOUNT_DELETE_ENV];
  delete process.env[PIPASS_ACCOUNT_DELETE_ENV];
  let fetches = 0;
  let resets = 0;
  try {
    const result = await deleteAccountAndResetLocal({
      sessionToken: TOKEN,
      fetchImpl: async () => {
        fetches += 1;
        throw new Error("network must not run");
      },
      resetLocal: async () => {
        resets += 1;
      },
    });
    assert.equal(result.deleted, false);
    if (!result.deleted) assert.equal(result.reason, "disabled");
    assert.equal(fetches, 0);
    assert.equal(resets, 0);
  } finally {
    if (previous === undefined) delete process.env[PIPASS_ACCOUNT_DELETE_ENV];
    else process.env[PIPASS_ACCOUNT_DELETE_ENV] = previous;
  }
});

test("account delete resets local data only after the server returns 204", async () => {
  let captured: { url: string; method: string; headers: Record<string, string> } | null = null;
  let resets = 0;
  const result = await deleteAccountAndResetLocal({
    sessionToken: TOKEN,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async (url, init) => {
      captured = { url, method: init.method, headers: init.headers };
      return { ok: true, status: 204, text: async () => "" };
    },
    resetLocal: async () => {
      resets += 1;
    },
  });
  assert.equal(result.deleted, true);
  assert.equal(resets, 1);
  assert.ok(captured);
  const request = captured as { url: string; method: string; headers: Record<string, string> };
  assert.equal(request.method, "DELETE");
  assert.equal(request.url, "https://items.example/api/account");
  assert.equal(request.headers["x-session-token"], TOKEN);
  assert.equal(request.headers["x-auth-hash"], undefined);
  assert.equal(request.headers["x-user-id"], undefined);
});

test("a failed account delete does not run the local nuclear reset", async () => {
  let resets = 0;
  const rejected = await deleteAccountAndResetLocal({
    sessionToken: TOKEN,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async () => ({ ok: false, status: 500, text: async () => "" }),
    resetLocal: async () => {
      resets += 1;
    },
  });
  assert.equal(rejected.deleted, false);
  if (!rejected.deleted) {
    assert.equal(rejected.reason, "rejected");
    assert.equal(rejected.status, 500);
  }
  assert.equal(resets, 0);

  const offline = await deleteAccountAndResetLocal({
    sessionToken: TOKEN,
    enabled: true,
    apiBaseUrl: "https://items.example",
    fetchImpl: async () => {
      throw new Error("offline");
    },
    resetLocal: async () => {
      resets += 1;
    },
  });
  assert.equal(offline.deleted, false);
  if (!offline.deleted) assert.equal(offline.reason, "network");
  assert.equal(resets, 0);
});

test("account delete helper sends no auth hash and uses the nuclear reset", () => {
  const source = readFileSync("lib/intentdb/deleteAccount.ts", "utf8");
  assert.equal(source.includes("x-auth-hash"), false);
  assert.equal(source.includes("vaultKeyProof"), false);
  assert.equal(source.includes("destroyAllData"), true);
});
