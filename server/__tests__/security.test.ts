// Regression + security tests covering T001–T010 of the auth +
// device-trust surface.
//
// Run:
//   npx tsx --test --test-force-exit server/__tests__/security.test.ts
//
// Why node:test (and not jest)?
//   The project ships no test framework. Node 22 has a built-in test
//   runner that is stable, ESM-native, and zero new dependencies — a
//   better fit for a TypeScript-only server module than pulling in
//   the jest/babel/ts-jest toolchain. The spec said "jest OR existing
//   test framework"; node:test is the existing framework Node itself
//   provides.
//
// Strategy
//   Spin up the real Express app + DatabaseStorage against the dev
//   DATABASE_URL on an ephemeral port, then exercise it via fetch.
//   Each test creates a uniquely-named user so concurrent or repeat
//   runs don't collide and we never need a shared cleanup phase.
//
//   A handful of cases poke storage methods directly. That's
//   intentional: the tests where the route layer's correctness IS
//   the storage layer's correctness (revoked-credential lookup,
//   counter-replay) are clearer and more deterministic when we drop
//   the HTTP layer than when we try to drive WebAuthn end-to-end.
//   Those exceptions are flagged with a comment.
//
// Known limitations
//   - T003: a full passkey replay test would need a virtual
//     authenticator (no @simplewebauthn helper accepts a synthetic
//     signature without a real key pair). We assert the storage-
//     level guarantees the route depends on instead — those ARE
//     the underlying anti-replay primitive.
//   - T009: a true cross-process restart can't be simulated from a
//     single test process (the route module's in-memory Maps stay
//     loaded). We exercise the equivalent path: a fresh user with
//     no in-memory state pre-seeded with an anomaly audit row,
//     then a real authenticated request that must repopulate
//     state from the audit log on its way through. That IS the
//     hydration code-path.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";

import { registerRoutes } from "../routes";
import { DatabaseStorage, type AuditLogItem } from "../storage";
import {
  encryptTotpSecret,
  generateTotpSecret,
  generateTotpToken,
} from "../totp";

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

const storage = new DatabaseStorage();
let server: Server;
let baseUrl: string;

before(async () => {
  const app = express();
  // Honor X-Forwarded-For so getClientIp() (which reads req.ip) can be
  // driven from tests. Without this, every connection looks like
  // 127.0.0.1 and the IP-binding test (T004) becomes a no-op.
  app.set("trust proxy", true);
  // No global json parser here: the route module now mounts a
  // per-route jsonBody(AUTH_BODY_LIMIT) on every endpoint that
  // reads req.body (the previous "implicit upstream parser"
  // assumption was a bug — see prior task fix). Tests therefore
  // exercise the SAME parser chain production runs, with the
  // SAME stricter per-route limits in force.
  server = await registerRoutes(app, storage);
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  // The route module spawns rate-limit + audit-dedupe GC intervals
  // that keep Node alive past test completion. The recommended runner
  // command above passes --test-force-exit which terminates the
  // process; this hook just shuts the listener cleanly.
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function uniqueUsername(prefix = "u"): string {
  // Stay inside registerSchema's 3..64-char + standard-charset window.
  return `${prefix}_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
}

function hex64(seed = ""): string {
  return createHash("sha256")
    .update(seed)
    .update(randomBytes(16))
    .digest("hex");
}

function validEncryptedBlob(seed = "vault"): string {
  return `${hex64(`${seed}:iv`).slice(0, 32)}:${hex64(`${seed}:cipher`)}:${hex64(`${seed}:mac`)}`;
}

async function expectInvalidVaultBlob(encryptedBlob: string): Promise<void> {
  const res = await fetch(`${baseUrl}/api/vault/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ encryptedBlob, expectedPrevVersion: 0 }),
  });
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "Invalid blob" });
}

async function expectInvalidVaultSyncBody(body: object): Promise<void> {
  const res = await fetch(`${baseUrl}/api/vault/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(res.status, 400);
  const payload = (await res.json()) as { error?: unknown };
  assert.equal(typeof payload.error, "string");
}

// Random 10.x.y.z address. The route module rate-limits register/login
// per-IP, so reusing 127.0.0.1 across the suite trips the budget after
// a handful of tests. Each register/login call gets its own bucket by
// default; tests that need a stable IP (T001 trust-device, T010 shared
// bucket) pass one explicitly.
function randomIp(): string {
  return `10.${randomBytes(1)[0]}.${randomBytes(1)[0]}.${randomBytes(1)[0]}`;
}

type Registered = {
  userId: string;
  username: string;
  authHash: string;
  salt: string;
  iterations: number;
};

async function registerUser(
  opts: { username?: string; authHash?: string; ip?: string } = {},
): Promise<Registered> {
  const username = opts.username ?? uniqueUsername();
  const authHash = opts.authHash ?? hex64("ah");
  const salt = hex64("salt");
  const iterations = 100_000;
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": opts.ip ?? randomIp(),
    },
    body: JSON.stringify({ username, authHash, salt, iterations }),
  });
  if (res.status !== 201) {
    // Read the body ONLY on the failure path. assert.equal eagerly
    // evaluates its message argument, so doing this inline (with
    // template-literal `await res.text()`) consumes the body even on
    // the success path and breaks the subsequent .json() read.
    const text = await res.text();
    assert.fail(`register failed: ${res.status} ${text}`);
  }
  const body = (await res.json()) as { id: string };
  return { userId: body.id, username, authHash, salt, iterations };
}

async function expectStatus(
  res: Response,
  expectedStatus: number,
  message: string,
): Promise<void> {
  if (res.status !== expectedStatus) {
    assert.fail(`${message}; got ${res.status} ${await res.text()}`);
  }
}

async function legacyVaultSync(
  user: Registered,
  encryptedBlob: string,
  expectedPrevVersion: number,
  opts: { ip?: string } = {},
): Promise<Response> {
  return fetch(`${baseUrl}/api/vault/sync`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-user-id": user.userId,
      "x-auth-hash": user.authHash,
      "x-forwarded-for": opts.ip ?? randomIp(),
    },
    body: JSON.stringify({ encryptedBlob, expectedPrevVersion }),
  });
}

async function legacyVaultFetch(
  user: Registered,
  opts: { ip?: string } = {},
): Promise<Response> {
  return fetch(`${baseUrl}/api/vault/fetch`, {
    headers: {
      "x-user-id": user.userId,
      "x-auth-hash": user.authHash,
      "x-forwarded-for": opts.ip ?? randomIp(),
    },
  });
}

async function legacyVaultRestore(
  user: Registered,
  version: number,
  opts: { ip?: string } = {},
): Promise<Response> {
  return fetch(`${baseUrl}/api/vault/restore`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-user-id": user.userId,
      "x-auth-hash": user.authHash,
      "x-forwarded-for": opts.ip ?? randomIp(),
    },
    body: JSON.stringify({ version }),
  });
}

function assertAuditRowSafe(
  row: AuditLogItem,
  forbiddenValues: readonly string[] = [],
): void {
  const text = JSON.stringify(row);
  for (const field of [
    "encryptedBlob",
    "authHash",
    "credentialId",
    "credential_id",
    "publicKey",
    "public_key",
    "headers",
    "body",
  ]) {
    assert.ok(!text.includes(field), `audit row leaked forbidden field ${field}`);
  }
  for (const value of forbiddenValues) {
    assert.ok(!text.includes(value), "audit row leaked forbidden value");
  }
}

async function waitForAuditEvent(
  userId: string,
  predicate: (entry: AuditLogItem) => boolean,
  label: string,
): Promise<AuditLogItem> {
  for (let i = 0; i < 20; i++) {
    const entries = await storage.getAuditLog(userId, 100);
    const found = entries.find(predicate);
    if (found) return found;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail(`timed out waiting for ${label}`);
}

async function expectRateLimitResponse(
  res: Response,
  forbiddenValues: readonly string[] = [],
): Promise<void> {
  await expectStatus(res, 429, "request should be rate-limited");
  const text = await res.text();
  const payload = JSON.parse(text) as Record<string, unknown>;
  assert.deepEqual(payload, { error: "Too many requests" });

  for (const field of [
    "encryptedBlob",
    "authHash",
    "credentialId",
    "credential_id",
    "publicKey",
    "public_key",
    "headers",
    "body",
  ]) {
    assert.ok(
      !text.includes(field),
      "rate-limit response leaked forbidden field",
    );
  }

  for (const value of forbiddenValues) {
    assert.ok(!text.includes(value), "rate-limit response leaked forbidden value");
  }
}

async function expectVersionConflict(
  res: Response,
  serverVersion: number,
  forbiddenValues: readonly string[] = [],
): Promise<void> {
  await expectStatus(res, 409, "sync should return a version conflict");
  const text = await res.text();
  const payload = JSON.parse(text) as Record<string, unknown>;
  assert.deepEqual(Object.keys(payload).sort(), ["error", "serverVersion"]);
  assert.equal(payload.error, "Version conflict");
  assert.equal(payload.serverVersion, serverVersion);

  for (const field of [
    "encryptedBlob",
    "authHash",
    "credentialId",
    "credential_id",
    "publicKey",
    "public_key",
    "headers",
    "body",
  ]) {
    assert.ok(!text.includes(field), "conflict response leaked forbidden field");
  }

  for (const value of forbiddenValues) {
    assert.ok(!text.includes(value), "conflict response leaked forbidden value");
  }
}

type LoginOpts = { ua?: string; ip?: string; platform?: string };

async function loginUser(
  username: string,
  authHash: string,
  opts: LoginOpts = {},
): Promise<{ status: number; body: any; sessionToken: string | null }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-forwarded-for": opts.ip ?? randomIp(),
  };
  if (opts.ua) headers["user-agent"] = opts.ua;
  if (opts.platform) headers["x-platform"] = opts.platform;
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers,
    body: JSON.stringify({ username, authHash }),
  });
  const body: any = await res.json();
  return { status: res.status, body, sessionToken: body?.sessionToken ?? null };
}

async function authedFetch(
  path: string,
  sessionToken: string,
  init: RequestInit & LoginOpts = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) ?? {}),
    "x-session-token": sessionToken,
  };
  if (init.body && !headers["content-type"]) {
    headers["content-type"] = "application/json";
  }
  if (init.ua) headers["user-agent"] = init.ua;
  if (init.ip) headers["x-forwarded-for"] = init.ip;
  if (init.platform) headers["x-platform"] = init.platform;
  return fetch(`${baseUrl}${path}`, { ...init, headers });
}

// Plant a TOTP secret on a user without going through the setup HTTP
// dance. Returns the raw secret so the test can derive valid step-up
// codes from it.
async function enableTotp(userId: string): Promise<string> {
  const secret = generateTotpSecret();
  await storage.setTotpEnabled(userId, encryptTotpSecret(secret));
  return secret;
}

// Run the TOTP step-up against a fresh session, returning the new
// sessionToken (the verifiedUntil column is on the same row, so the
// SAME token is now step-up-fresh for STEP_UP_TTL_MS).
async function stepUp(sessionToken: string, secret: string): Promise<void> {
  const code = generateTotpToken(secret);
  const res = await authedFetch("/api/auth/totp/step-up", sessionToken, {
    method: "POST",
    body: JSON.stringify({ token: code }),
  });
  assert.equal(
    res.status,
    200,
    `step-up failed: ${res.status} ${await res.text()}`,
  );
}

// SHA-256(lowercase(trim(ua)) || \0 || ip) — mirrors the server's
// deriveDeviceFingerprint(ip, ua), which is the formula used for
// the trusted_devices table (NOT the 3-part getDeviceFingerprint
// that the sessions table uses). Lets a test predict the row a
// /api/security/devices listing will contain.
function predictFingerprint(opts: LoginOpts): string {
  const ua = (opts.ua ?? "").toLowerCase().trim();
  return createHash("sha256")
    .update(ua)
    .update("\u0000")
    .update(opts.ip ?? "127.0.0.1")
    .digest("hex");
}

// ---------------------------------------------------------------------------
// T001 — Device Trust
// ---------------------------------------------------------------------------

test("T001.a — a fresh login surfaces the device as untrusted", async () => {
  const u = await registerUser();
  const ua = "T001a-Agent/1.0";
  const login = await loginUser(u.username, u.authHash, { ua, ip: "10.0.0.1" });
  assert.equal(login.status, 200);
  assert.ok(login.sessionToken, "expected sessionToken on first login");

  const res = await authedFetch("/api/security/devices", login.sessionToken!, {
    ua,
    ip: "10.0.0.1",
  });
  assert.equal(res.status, 200);
  const { devices } = (await res.json()) as {
    devices: Array<{ fingerprint: string; trusted: boolean }>;
  };
  const fp = predictFingerprint({ ua, ip: "10.0.0.1" });
  const me = devices.find((d) => d.fingerprint === fp);
  assert.ok(me, "expected the just-logged-in device to appear in /devices");
  assert.equal(me!.trusted, false, "first-time devices must not be trusted");
});

test("T001.b — POST /api/security/device/trust persists trusted=true", async () => {
  const u = await registerUser();
  const ua = "T001b-Agent/1.0";
  const ip = "10.0.0.2";
  const login = await loginUser(u.username, u.authHash, { ua, ip });
  const fp = predictFingerprint({ ua, ip });

  const trustRes = await authedFetch(
    "/api/security/device/trust",
    login.sessionToken!,
    { method: "POST", body: JSON.stringify({ fingerprint: fp }), ua, ip },
  );
  assert.equal(trustRes.status, 200);
  const trustBody = (await trustRes.json()) as { changed: boolean };
  assert.equal(trustBody.changed, true);

  // Read-back via storage, NOT just /devices, so the assertion is on
  // persistence — a route that swallowed the write but lied with a
  // 200 would pass an HTTP-only check.
  const persisted = await storage.getDevicesForUser(u.userId);
  const row = persisted.find((d) => d.fingerprint === fp);
  assert.ok(row, "device must exist after trust");
  assert.equal(row!.trusted, true);
});

test("T001.c — POST /api/security/device/revoke persists trusted=false", async () => {
  const u = await registerUser();
  const ua = "T001c-Agent/1.0";
  const ip = "10.0.0.3";
  const login = await loginUser(u.username, u.authHash, { ua, ip });
  const fp = predictFingerprint({ ua, ip });

  // First trust it so revoke has something to flip.
  await authedFetch("/api/security/device/trust", login.sessionToken!, {
    method: "POST",
    body: JSON.stringify({ fingerprint: fp }),
    ua,
    ip,
  });
  const revokeRes = await authedFetch(
    "/api/security/device/revoke",
    login.sessionToken!,
    { method: "POST", body: JSON.stringify({ fingerprint: fp }), ua, ip },
  );
  assert.equal(revokeRes.status, 200);
  const revokeBody = (await revokeRes.json()) as { changed: boolean };
  assert.equal(revokeBody.changed, true);

  const persisted = await storage.getDevicesForUser(u.userId);
  const row = persisted.find((d) => d.fingerprint === fp);
  assert.equal(row?.trusted, false);
});

// ---------------------------------------------------------------------------
// T002 — Step-Up Enforcement
// ---------------------------------------------------------------------------

test("T002.a — TOTP-enabled user cannot trust a device without step-up", async () => {
  const u = await registerUser();
  await enableTotp(u.userId);
  // Re-login AFTER enabling TOTP. The first login predates the flag
  // so its session row would not be subject to the step-up gate.
  // Login post-enable goes through the temp-token path.
  const initial = await loginUser(u.username, u.authHash);
  assert.equal(
    initial.body?.requiresTOTP,
    true,
    "TOTP-enabled login should issue a temp token, not a session",
  );
  // Drive the TOTP login flow to actually get a session token.
  const code = generateTotpToken((await currentSecretFor(u.userId))!);
  const totpLogin = await fetch(`${baseUrl}/api/auth/totp/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tempToken: initial.body.tempToken, token: code }),
  });
  assert.equal(totpLogin.status, 200);
  const tlBody = (await totpLogin.json()) as { sessionToken: string };
  assert.ok(tlBody.sessionToken, "TOTP login must mint a session token");

  // The session is freshly minted but NOT step-up-fresh — there's a
  // distinction between "user passed 2FA at login" and "user just
  // proved 2FA for THIS write" (the second is what /trust requires).
  const fp = hex64("fp"); // any valid 64-hex value; trust path enforces step-up before lookup
  const trustRes = await authedFetch(
    "/api/security/device/trust",
    tlBody.sessionToken,
    { method: "POST", body: JSON.stringify({ fingerprint: fp }) },
  );
  assert.equal(
    trustRes.status,
    401,
    "TOTP-enabled trust attempt without step-up must be rejected",
  );
  const body = (await trustRes.json()) as { reason?: string };
  assert.equal(body.reason, "totp", "401 should identify TOTP as the gate");
});

test("T002.b — TOTP-enabled user CAN trust after a successful step-up", async () => {
  const u = await registerUser();
  const secret = await enableTotp(u.userId);

  // Get a real session token via the TOTP login path.
  const initial = await loginUser(u.username, u.authHash);
  const totpLogin = await fetch(`${baseUrl}/api/auth/totp/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      tempToken: initial.body.tempToken,
      token: generateTotpToken(secret),
    }),
  });
  const tlBody = (await totpLogin.json()) as { sessionToken: string };

  // Step up. Same secret, fresh code (TOTP rotates every 30s but
  // generateTotpToken uses the current window).
  await stepUp(tlBody.sessionToken, secret);

  // Now the trust call should succeed. Use the actual device fingerprint
  // for the headers we send so the underlying row exists to flip.
  const fp = predictFingerprint({});
  const trustRes = await authedFetch(
    "/api/security/device/trust",
    tlBody.sessionToken,
    { method: "POST", body: JSON.stringify({ fingerprint: fp }) },
  );
  assert.equal(
    trustRes.status,
    200,
    `trust after step-up must succeed; got ${trustRes.status} ${await trustRes.text()}`,
  );
});

// Pull the encrypted secret back off the user row and decrypt it. Used
// by T002 only — the step-up tests need to derive codes from the SAME
// secret enableTotp() planted, which we threw away at the helper call.
async function currentSecretFor(userId: string): Promise<string | null> {
  const user = await storage.getUser(userId);
  if (!user?.totpSecretEncrypted) return null;
  const { decryptTotpSecret } = await import("../totp");
  return decryptTotpSecret(user.totpSecretEncrypted);
}

// ---------------------------------------------------------------------------
// T003 — Passkey Security
// ---------------------------------------------------------------------------
//
// Full WebAuthn replay needs a virtual authenticator (none of
// @simplewebauthn/server's verifiers accept a synthetic assertion
// without a real key pair). We instead pin the storage-layer
// guarantees the route relies on — those primitives ARE the
// anti-replay machinery.

test("T003.a — getCredentialById excludes revoked rows", async () => {
  const u = await registerUser();
  const credentialId = `cred_${randomBytes(16).toString("hex")}`;
  const created = await storage.createWebAuthnCredential({
    userId: u.userId,
    credentialId,
    publicKey: "00".repeat(32),
    counter: 0,
    deviceName: "T003a-device",
    transports: "internal",
  });
  assert.ok(created, "createWebAuthnCredential should return a row");

  // Pre-revocation: lookup hits.
  const before = await storage.getCredentialById(credentialId);
  assert.ok(before, "pre-revoke lookup must return the row");

  // Revoke and confirm the lookup now misses (same shape as a bogus
  // credentialId — the route layer uses this single read to decide
  // "should I authenticate this assertion?").
  const revoked = await storage.revokeCredential(credentialId);
  assert.equal(revoked, true);

  const after = await storage.getCredentialById(credentialId);
  assert.equal(
    after,
    undefined,
    "revoked credentials must not be returned to the auth path",
  );
});

test("T003.b — updateCredentialCounter rejects equal-or-stale counter (replay)", async () => {
  const u = await registerUser();
  const credentialId = `cred_${randomBytes(16).toString("hex")}`;
  await storage.createWebAuthnCredential({
    userId: u.userId,
    credentialId,
    publicKey: "00".repeat(32),
    counter: 5,
    deviceName: "T003b-device",
    transports: "internal",
  });

  // Advancing the counter is fine.
  const advance = await storage.updateCredentialCounter(credentialId, 10);
  assert.equal(advance, true, "monotonic advance must succeed");

  // A REPLAYED assertion would land here with newCounter == stored.
  // The conditional UPDATE must refuse, returning false so the route
  // can audit + revoke (see comment on updateCredentialCounter in
  // server/storage.ts).
  const replay = await storage.updateCredentialCounter(credentialId, 10);
  assert.equal(replay, false, "equal-counter write must be refused");

  // Same for a stale (lower) counter.
  const stale = await storage.updateCredentialCounter(credentialId, 9);
  assert.equal(stale, false, "stale-counter write must be refused");
});

// ---------------------------------------------------------------------------
// T004 — Session Binding
// ---------------------------------------------------------------------------

test("T004.a — same session token from a new IP is recorded as a device-mismatch signal", async () => {
  const u = await registerUser();
  const ua = "T004-Agent/1.0";
  const login = await loginUser(u.username, u.authHash, {
    ua,
    ip: "10.0.4.1",
  });
  assert.ok(login.sessionToken);

  // Pre-fetch the baseline audit log from the original IP so we can
  // diff against it. `new_device_detected` fires on first login and
  // would otherwise let the test pass even if IP-change detection is
  // completely broken — so we anchor on rows that appear ONLY after
  // the IP swap.
  const baselineRes = await authedFetch(
    "/api/vault/audit",
    login.sessionToken!,
    { ua, ip: "10.0.4.1" },
  );
  assert.equal(baselineRes.status, 200);
  const baseline = (await baselineRes.json()) as {
    entries: Array<{ action: string; createdAt: number }>;
  };
  const baselineKeys = new Set(
    baseline.entries.map((e) => `${e.action}@${e.createdAt}`),
  );

  // Subsequent request from a DIFFERENT IP using the SAME session
  // token. The IP change drives authenticate() into the device-
  // mismatch / ip-change signal path.
  const res = await authedFetch("/api/vault/audit", login.sessionToken!, {
    ua,
    ip: "10.0.99.99",
  });
  assert.equal(res.status, 200);

  // The mismatch signal is recorded fire-and-forget — poll briefly so
  // we don't race the DB insert. We only count rows that are NEW
  // relative to the baseline, and that name a post-IP-change action
  // (`device_mismatch` or `ip_change_detected`). `new_device_detected`
  // is intentionally NOT accepted: it fires on first login and would
  // mask a regression where the IP-change branch never runs.
  let flagged = false;
  const POST_CHANGE_ACTIONS = new Set([
    "device_mismatch",
    "ip_change_detected",
  ]);
  for (let i = 0; i < 20 && !flagged; i++) {
    const poll = await authedFetch(
      "/api/vault/audit",
      login.sessionToken!,
      { ua, ip: "10.0.99.99" },
    );
    if (poll.status !== 200) {
      // If polling itself starts failing, surface it rather than time
      // out into a misleading "no signal recorded" message.
      assert.fail(
        `audit poll returned ${poll.status} mid-test; cannot validate signal`,
      );
    }
    const { entries } = (await poll.json()) as {
      entries: Array<{ action: string; createdAt: number }>;
    };
    flagged = entries.some(
      (e) =>
        POST_CHANGE_ACTIONS.has(e.action) &&
        !baselineKeys.has(`${e.action}@${e.createdAt}`),
    );
    if (!flagged) await new Promise((r) => setTimeout(r, 50));
  }
  assert.ok(
    flagged,
    "expected a NEW device_mismatch or ip_change_detected audit row (relative to pre-swap baseline) after the same session token is used from a different IP",
  );
});

test("T004.b — sync from an untrusted device is blocked (step-up required)", async () => {
  const u = await registerUser();
  const login = await loginUser(u.username, u.authHash, {
    ua: "T004b-Agent/1.0",
    ip: "10.0.4.10",
  });
  assert.ok(login.sessionToken);

  // The brand-new device is untrusted; sync hits the device-untrust
  // gate and returns 403 (or 401 for step-up-required users). Either
  // status proves the binding gate fired — what matters is "writes
  // do NOT silently succeed from an unapproved device".
  const sync = await authedFetch("/api/vault/sync", login.sessionToken!, {
    method: "POST",
    body: JSON.stringify({
      encryptedBlob: validEncryptedBlob("t004b"),
      expectedPrevVersion: 0,
    }),
    ua: "T004b-Agent/1.0",
    ip: "10.0.4.10",
  });
  assert.notEqual(
    sync.status,
    200,
    "sync from a brand-new untrusted device must not return 200",
  );
  assert.ok(
    [401, 403].includes(sync.status),
    `expected 401/403 from sync on untrusted device; got ${sync.status}`,
  );
});

test("T004.c — vault sync rejects legacy client-chosen version", async () => {
  await expectInvalidVaultSyncBody({
    encryptedBlob: validEncryptedBlob("legacy-version"),
    version: 1,
  });
});

test("T004.d — vault sync rejects huge legacy client-chosen version", async () => {
  await expectInvalidVaultSyncBody({
    encryptedBlob: validEncryptedBlob("huge-legacy-version"),
    version: 2_147_483_647,
  });
});

test("T004.e — vault sync rejects both version and expectedPrevVersion", async () => {
  await expectInvalidVaultSyncBody({
    encryptedBlob: validEncryptedBlob("both-version-fields"),
    version: 1,
    expectedPrevVersion: 0,
  });
});

test("T004.f — vault sync rejects an empty encryptedBlob", async () => {
  await expectInvalidVaultBlob("");
});

test("T004.g — vault sync rejects a single-space encryptedBlob", async () => {
  await expectInvalidVaultBlob(" ");
});

test("T004.h — vault sync rejects whitespace-only encryptedBlob text", async () => {
  await expectInvalidVaultBlob("     ");
});

test("T004.i — vault sync rejects null placeholder encryptedBlob text", async () => {
  await expectInvalidVaultBlob("null");
});

test("T004.j — vault sync rejects empty-array placeholder encryptedBlob text", async () => {
  await expectInvalidVaultBlob("[]");
});

test("T004.k — vault sync rejects a trimmed encryptedBlob shorter than 64 characters", async () => {
  await expectInvalidVaultBlob(`  ${"a".repeat(63)}  `);
});

test("T004.l — first vault sync conflict reports serverVersion 0 without writing", async () => {
  const u = await registerUser();
  const attemptedBlob = validEncryptedBlob("t004l:conflict");

  const conflict = await legacyVaultSync(u, attemptedBlob, 999);
  await expectVersionConflict(conflict, 0, [
    attemptedBlob,
    u.authHash,
    u.userId,
  ]);

  const fetchRes = await legacyVaultFetch(u);
  await expectStatus(fetchRes, 200, "fetch after first-sync conflict should succeed");
  const fetched = (await fetchRes.json()) as {
    encryptedBlob: string | null;
    version: number;
  };
  assert.equal(fetched.version, 0);
  assert.equal(fetched.encryptedBlob, null);
});

test("T004.m — first vault sync with expectedPrevVersion 0 stores version 1", async () => {
  const u = await registerUser();
  const blob = validEncryptedBlob("t004m");
  const res = await legacyVaultSync(u, blob, 0);
  await expectStatus(res, 200, "first sync should succeed");
  const body = (await res.json()) as { version: number; updatedAt: number };
  assert.equal(body.version, 1);

  const fetchRes = await legacyVaultFetch(u);
  await expectStatus(fetchRes, 200, "fetch after first sync should succeed");
  const fetched = (await fetchRes.json()) as {
    encryptedBlob: string | null;
    version: number;
  };
  assert.equal(fetched.version, 1);
  assert.equal(fetched.encryptedBlob, blob);
});

test("T004.n — second vault sync with expectedPrevVersion 1 stores version 2", async () => {
  const u = await registerUser();
  await expectStatus(
    await legacyVaultSync(u, validEncryptedBlob("t004n:first"), 0),
    200,
    "first sync should succeed",
  );

  const blob = validEncryptedBlob("t004n:second");
  const res = await legacyVaultSync(u, blob, 1);
  await expectStatus(res, 200, "second sync should succeed");
  const body = (await res.json()) as { version: number; updatedAt: number };
  assert.equal(body.version, 2);

  const fetchRes = await legacyVaultFetch(u);
  await expectStatus(fetchRes, 200, "fetch after second sync should succeed");
  const fetched = (await fetchRes.json()) as {
    encryptedBlob: string | null;
    version: number;
  };
  assert.equal(fetched.version, 2);
  assert.equal(fetched.encryptedBlob, blob);
});

test("T004.o — stale expectedPrevVersion returns safe conflict without changing vault", async () => {
  const u = await registerUser();
  const blob = validEncryptedBlob("t004o:first");
  await expectStatus(
    await legacyVaultSync(u, blob, 0),
    200,
    "first sync should succeed",
  );

  const staleBlob = validEncryptedBlob("t004o:stale");
  const stale = await legacyVaultSync(u, staleBlob, 0);
  await expectVersionConflict(stale, 1, [
    blob,
    staleBlob,
    u.authHash,
    u.userId,
  ]);

  const fetchRes = await legacyVaultFetch(u);
  await expectStatus(fetchRes, 200, "fetch after stale conflict should succeed");
  const fetched = (await fetchRes.json()) as {
    encryptedBlob: string | null;
    version: number;
  };
  assert.equal(fetched.version, 1);
  assert.equal(fetched.encryptedBlob, blob);
});

test("T004.p — huge expectedPrevVersion conflicts and cannot force huge stored version", async () => {
  const u = await registerUser();
  const blob = validEncryptedBlob("t004p:first");
  await expectStatus(
    await legacyVaultSync(u, blob, 0),
    200,
    "first sync should succeed",
  );

  const hugeBlob = validEncryptedBlob("t004p:huge");
  const huge = await legacyVaultSync(
    u,
    hugeBlob,
    2_147_483_647,
  );
  await expectVersionConflict(huge, 1, [
    blob,
    hugeBlob,
    u.authHash,
    u.userId,
  ]);

  const fetchRes = await legacyVaultFetch(u);
  await expectStatus(fetchRes, 200, "fetch after huge conflict should succeed");
  const fetched = (await fetchRes.json()) as {
    encryptedBlob: string | null;
    version: number;
  };
  assert.equal(fetched.version, 1);
  assert.equal(fetched.encryptedBlob, blob);
});

// ---------------------------------------------------------------------------
// T005 — Recovery Mode
// ---------------------------------------------------------------------------

test("T005.a — recovery acknowledge without step-up is rejected (TOTP user)", async () => {
  const u = await registerUser();
  const secret = await enableTotp(u.userId);

  // Get a real session via the TOTP login path.
  const initial = await loginUser(u.username, u.authHash);
  const totpLogin = await fetch(`${baseUrl}/api/auth/totp/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      tempToken: initial.body.tempToken,
      token: generateTotpToken(secret),
    }),
  });
  const tlBody = (await totpLogin.json()) as { sessionToken: string };

  // Acknowledge BEFORE stepping up. Should be rejected — a stolen
  // session shouldn't be able to silently dismiss the recovery banner.
  const ack = await authedFetch(
    "/api/vault/recovery/acknowledge",
    tlBody.sessionToken,
    { method: "POST", body: JSON.stringify({}) },
  );
  assert.equal(ack.status, 401, "recovery ack without step-up must 401");
});

test("T005.b — recovery acknowledge succeeds after step-up", async () => {
  const u = await registerUser();
  const secret = await enableTotp(u.userId);
  const initial = await loginUser(u.username, u.authHash);
  const totpLogin = await fetch(`${baseUrl}/api/auth/totp/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      tempToken: initial.body.tempToken,
      token: generateTotpToken(secret),
    }),
  });
  const tlBody = (await totpLogin.json()) as { sessionToken: string };

  await stepUp(tlBody.sessionToken, secret);

  const ack = await authedFetch(
    "/api/vault/recovery/acknowledge",
    tlBody.sessionToken,
    { method: "POST", body: JSON.stringify({}) },
  );
  assert.equal(
    ack.status,
    200,
    `recovery ack after step-up must succeed; got ${ack.status} ${await ack.text()}`,
  );
});

test("T005.c — anomaly audit row visibly elevates the security signal", async () => {
  const u = await registerUser();
  const login = await loginUser(u.username, u.authHash);
  assert.ok(login.sessionToken);

  // Plant an anomaly directly. This is what the live signal hooks
  // would persist on a real anomaly fire — by writing it out-of-band
  // we prove that the read path SURFACES it (rather than only
  // surfacing the in-memory live state).
  await storage.logAuditEvent({
    userId: u.userId,
    action: "anomaly_detected",
    ipAddress: "10.0.5.99",
    userAgent: "reason=test_seed",
  });

  const res = await authedFetch("/api/vault/audit", login.sessionToken!);
  assert.equal(res.status, 200);
  const body = (await res.json()) as {
    hasRecentAnomalies: boolean;
    securityLevel: string;
    threatLevel: number;
  };
  assert.equal(
    body.hasRecentAnomalies,
    true,
    "anomaly audit row must surface as hasRecentAnomalies=true",
  );
  // Level may be elevated/high/critical depending on configuration —
  // any non-normal value satisfies the "anomaly raises the signal"
  // contract.
  assert.notEqual(
    body.securityLevel,
    "normal",
    `expected non-normal securityLevel after anomaly; got ${body.securityLevel}`,
  );
});

// ---------------------------------------------------------------------------
// T006 — Audit Integrity
// ---------------------------------------------------------------------------

test("T006 — /api/vault/audit response leaks no credential / public-key fields", async () => {
  const u = await registerUser();
  const login = await loginUser(u.username, u.authHash);
  assert.ok(login.sessionToken);

  // Stash a passkey row so the audit response has SOMETHING that
  // could leak — without it the test could pass trivially on an
  // empty audit table.
  const credentialId = `cred_${randomBytes(16).toString("hex")}`;
  await storage.createWebAuthnCredential({
    userId: u.userId,
    credentialId,
    publicKey: "DEADBEEF".repeat(8),
    counter: 0,
    deviceName: "T006-device",
    transports: "internal",
  });
  await storage.logAuditEvent({
    userId: u.userId,
    action: "passkey_registered",
    ipAddress: null,
    userAgent: null,
  });

  const res = await authedFetch("/api/vault/audit", login.sessionToken!);
  assert.equal(res.status, 200);
  const text = await res.text();

  // String-search the raw response. False-positive risk is low — these
  // names are camelCase / snake_case identifiers, not English words.
  for (const banned of [
    "authHash",
    "auth_hash",
    "encryptedBlob",
    "encrypted_blob",
    "credentialId",
    "credential_id",
    "publicKey",
    "public_key",
    "counter",
    "headers",
    "body",
    "DEADBEEF", // the actual leaked-key string we just persisted
  ]) {
    assert.ok(
      !text.includes(banned),
      `audit response must not include ${banned}; sample: ${text.slice(0, 200)}`,
    );
  }
  assert.ok(!text.includes(u.authHash), "audit response must not echo authHash");
});

test("T006.b — vault sync and fetch emit safe audit rows", async () => {
  const u = await registerUser();
  const blob = validEncryptedBlob("t006b:sync");

  const sync = await legacyVaultSync(u, blob, 0);
  await expectStatus(sync, 200, "vault sync should succeed");
  const syncAudit = await waitForAuditEvent(
    u.userId,
    (entry) =>
      entry.action === "vault_sync" &&
      entry.versionBefore === 0 &&
      entry.versionAfter === 1,
    "vault_sync audit row",
  );
  assert.equal(syncAudit.blobSize, Buffer.byteLength(blob, "utf8"));
  assertAuditRowSafe(syncAudit, [blob, u.authHash, u.userId]);

  const fetchRes = await legacyVaultFetch(u);
  await expectStatus(fetchRes, 200, "vault fetch should succeed");
  const fetchAudit = await waitForAuditEvent(
    u.userId,
    (entry) => entry.action === "vault_fetch",
    "vault_fetch audit row",
  );
  assert.equal(fetchAudit.versionBefore, null);
  assert.equal(fetchAudit.versionAfter, null);
  assert.equal(fetchAudit.blobSize, null);
  assertAuditRowSafe(fetchAudit, [blob, u.authHash, u.userId]);
});

test("T006.c — vault sync version conflict does not create a success audit row", async () => {
  const u = await registerUser();
  const blob = validEncryptedBlob("t006c:first");
  await expectStatus(
    await legacyVaultSync(u, blob, 0),
    200,
    "initial sync should succeed",
  );
  await waitForAuditEvent(
    u.userId,
    (entry) => entry.action === "vault_sync" && entry.versionAfter === 1,
    "initial vault_sync audit row",
  );
  const before = (await storage.getAuditLog(u.userId, 100)).filter(
    (entry) => entry.action === "vault_sync",
  ).length;

  const conflictBlob = validEncryptedBlob("t006c:conflict");
  await expectVersionConflict(
    await legacyVaultSync(u, conflictBlob, 0),
    1,
    [blob, conflictBlob, u.authHash, u.userId],
  );
  await new Promise((resolve) => setTimeout(resolve, 100));
  const after = (await storage.getAuditLog(u.userId, 100)).filter(
    (entry) => entry.action === "vault_sync",
  ).length;
  assert.equal(after, before, "version conflict must not add vault_sync audit rows");
});

test("T006.d — successful vault restore emits safe audit metadata", async () => {
  const u = await registerUser();
  const firstBlob = validEncryptedBlob("t006d:first");
  const secondBlob = validEncryptedBlob("t006d:second");

  await expectStatus(
    await legacyVaultSync(u, firstBlob, 0),
    200,
    "first sync should succeed",
  );
  await expectStatus(
    await legacyVaultSync(u, secondBlob, 1),
    200,
    "second sync should succeed",
  );

  const restore = await legacyVaultRestore(u, 1);
  await expectStatus(restore, 200, "restore should succeed");
  const restoreBody = (await restore.json()) as { version: number };
  assert.equal(restoreBody.version, 3);

  const restoreAudit = await waitForAuditEvent(
    u.userId,
    (entry) =>
      entry.action === "vault_restore" &&
      entry.versionBefore === 2 &&
      entry.versionAfter === 3,
    "vault_restore audit row",
  );
  assert.equal(restoreAudit.blobSize, null);
  assertAuditRowSafe(restoreAudit, [firstBlob, secondBlob, u.authHash, u.userId]);

  const before = (await storage.getAuditLog(u.userId, 100)).filter(
    (entry) => entry.action === "vault_restore",
  ).length;
  await expectStatus(
    await legacyVaultRestore(u, 999),
    404,
    "missing restore target should 404",
  );
  await new Promise((resolve) => setTimeout(resolve, 100));
  const after = (await storage.getAuditLog(u.userId, 100)).filter(
    (entry) => entry.action === "vault_restore",
  ).length;
  assert.equal(after, before, "failed restore must not add vault_restore audit rows");
});

test("T006.e — untrusted-device sync block emits a safe audit row", async () => {
  const u = await registerUser();
  const ua = "T006e-Agent/1.0";
  const ip = "10.6.0.5";
  const login = await loginUser(u.username, u.authHash, { ua, ip });
  assert.ok(login.sessionToken);

  const blob = validEncryptedBlob("t006e:blocked");
  const sync = await authedFetch("/api/vault/sync", login.sessionToken!, {
    method: "POST",
    body: JSON.stringify({ encryptedBlob: blob, expectedPrevVersion: 0 }),
    ua,
    ip,
  });
  assert.equal(sync.status, 403);

  const blockedAudit = await waitForAuditEvent(
    u.userId,
    (entry) =>
      entry.action === "untrusted_device_blocked" &&
      entry.userAgent === "attemptedAction=sync",
    "untrusted_device_blocked audit row",
  );
  assertAuditRowSafe(blockedAudit, [
    blob,
    u.authHash,
    login.sessionToken ?? "",
    u.userId,
  ]);
});

test("T006.f — login and device trust changes emit safe audit rows", async () => {
  const u = await registerUser();
  const ua = "T006f-Agent/1.0";
  const ip = "10.6.0.6";
  const login = await loginUser(u.username, u.authHash, { ua, ip });
  assert.equal(login.status, 200);
  assert.ok(login.sessionToken);

  for (const action of ["login_success", "session_created", "new_device_detected"]) {
    const row = await waitForAuditEvent(
      u.userId,
      (entry) => entry.action === action,
      `${action} audit row`,
    );
    assertAuditRowSafe(row, [u.authHash, login.sessionToken ?? "", u.userId]);
  }

  const fingerprint = predictFingerprint({ ua, ip });
  const trustRes = await authedFetch(
    "/api/security/device/trust",
    login.sessionToken,
    { method: "POST", body: JSON.stringify({ fingerprint }), ua, ip },
  );
  await expectStatus(trustRes, 200, "device trust should succeed");
  const trusted = await waitForAuditEvent(
    u.userId,
    (entry) =>
      entry.action === "device_trusted" &&
      entry.userAgent === `fingerprint=${fingerprint.slice(0, 16)}`,
    "device_trusted audit row",
  );
  assertAuditRowSafe(trusted, [u.authHash, login.sessionToken, u.userId]);

  const revokeRes = await authedFetch(
    "/api/security/device/revoke",
    login.sessionToken,
    { method: "POST", body: JSON.stringify({ fingerprint }), ua, ip },
  );
  await expectStatus(revokeRes, 200, "device revoke should succeed");
  const revoked = await waitForAuditEvent(
    u.userId,
    (entry) =>
      entry.action === "device_untrusted" &&
      entry.userAgent === `fingerprint=${fingerprint.slice(0, 16)}`,
    "device_untrusted audit row",
  );
  assertAuditRowSafe(revoked, [u.authHash, login.sessionToken, u.userId]);
});

// ---------------------------------------------------------------------------
// T007 — Timing Attack Protection
// ---------------------------------------------------------------------------
//
// The login route inserts a 50-120ms uniform random delay that swamps
// the sub-millisecond differences between "user not found" and "wrong
// password". Two checks:
//   1. Mean delta between valid and invalid usernames is bounded.
//   2. Both means are at least the floor of the delay (≥ ~40ms).
// Both bounds are deliberately wide so transient CI noise doesn't
// flake the suite — a true regression (delay removed entirely) would
// blow past either trivially.

test("T007 — login response time variance is dominated by the noise floor", async () => {
  const u = await registerUser();
  const N = 8;

  async function timeIt(username: string): Promise<number> {
    const t0 = performance.now();
    await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, authHash: u.authHash }),
    });
    return performance.now() - t0;
  }

  const valid: number[] = [];
  const invalid: number[] = [];
  for (let i = 0; i < N; i++) {
    valid.push(await timeIt(u.username));
    invalid.push(await timeIt(uniqueUsername("nope")));
  }
  const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
  const meanValid = mean(valid);
  const meanInvalid = mean(invalid);

  // Floor: the uniform delay alone forces every response to take at
  // least ~40ms (50ms minimum minus generous slack for an unloaded
  // local-loopback fetch).
  assert.ok(
    meanValid >= 40 && meanInvalid >= 40,
    `expected both means ≥ 40ms (delay floor); got valid=${meanValid.toFixed(1)} invalid=${meanInvalid.toFixed(1)}`,
  );

  // Delta bound: with a 70ms-wide uniform random delay and N=8, the
  // expected |Δmean| from random alone is ~10ms. 200ms is the
  // regression-not-noise threshold — much wider than the natural
  // variance, much narrower than the gap that would exist if the
  // delay were removed and the DB-round-trip showed through.
  assert.ok(
    Math.abs(meanValid - meanInvalid) < 200,
    `valid vs invalid mean delta too large: |${meanValid.toFixed(1)} - ${meanInvalid.toFixed(1)}| = ${Math.abs(meanValid - meanInvalid).toFixed(1)}ms`,
  );
});

// ---------------------------------------------------------------------------
// T008 — Failure Streak
// ---------------------------------------------------------------------------

test("T008 — repeated failed logins from one IP are eventually rate-limited (failure streak protection)", async () => {
  const u = await registerUser();
  const wrongHash = hex64("wrong");
  // Use a dedicated IP so other tests' 200/401 responses can't have
  // already filled this bucket, and so the rate-limit assertion
  // doesn't depend on global ordering.
  const ip = `10.${randomBytes(1)[0]}.${randomBytes(1)[0]}.${randomBytes(1)[0]}`;

  // Hammer the login endpoint with the right username + WRONG hash.
  // The per-IP `login:` bucket increments on every request regardless
  // of outcome, so a sustained brute-force burst trips into 429
  // before the attacker can grind through the password space. We
  // walk the budget and assert it eventually closes.
  let observed429 = false;
  for (let i = 0; i < 60; i++) {
    const res = await loginUser(u.username, wrongHash, { ip });
    if (res.status === 429) {
      observed429 = true;
      break;
    }
    // Sanity: every non-429 attempt should be a 401. A 200 here would
    // mean the wrong hash got accepted — that's a different bug, but
    // we want to surface it rather than silently loop.
    assert.equal(
      res.status,
      401,
      `expected 401 on wrong-password attempt; got ${res.status}`,
    );
  }
  assert.ok(
    observed429,
    "expected 60 consecutive failed-login attempts from one IP to trip the per-IP rate limit",
  );

  // The same IP, even with the CORRECT password, must now also be
  // throttled — that's the "shared bucket" property: the bucket
  // closes against the IP, not against an outcome. (This is the
  // tradeoff: a brute-forcer locks out a legitimate user behind the
  // same NAT for the rate-limit window. Documented; tested here so
  // the tradeoff is visible if anyone tries to "fix" it by keying
  // failures separately from successes.)
  const sameIpGood = await loginUser(u.username, u.authHash, { ip });
  assert.equal(
    sameIpGood.status,
    429,
    "after exhausting the per-IP login bucket, even a correct password from that IP must 429",
  );
});

// ---------------------------------------------------------------------------
// T009 — Restart Hydration
// ---------------------------------------------------------------------------
//
// A real cross-process restart can't be simulated from a single test
// process — the route module's in-memory Maps stay loaded for the
// whole test run. What we CAN do is exercise the equivalent path:
// a fresh user (one that has never been seen by this process's
// in-memory state) gets pre-seeded with an anomaly audit row, then
// makes its first authenticated request. The lazy-hydration code in
// authenticate() must reconstruct the security level from the audit
// log on the way through.

test("T009 — fresh-user lazy hydration reconstructs elevated state from audit log", async () => {
  const u = await registerUser();

  // Plant a recent anomaly row BEFORE any authenticated request from
  // this user. Hydration only runs once per (process, user); since
  // this user has never been authenticated yet, in-memory state for
  // them is empty.
  await storage.logAuditEvent({
    userId: u.userId,
    action: "anomaly_detected",
    ipAddress: "10.0.9.1",
    userAgent: "reason=t009_seed",
  });

  // Now authenticate — this is the first request that will trigger
  // hydration for this user.
  const login = await loginUser(u.username, u.authHash);
  assert.ok(login.sessionToken);
  const res = await authedFetch("/api/vault/audit", login.sessionToken!);
  assert.equal(res.status, 200);
  const body = (await res.json()) as {
    securityLevel: string;
    hasRecentAnomalies: boolean;
  };

  assert.equal(
    body.hasRecentAnomalies,
    true,
    "hydration must surface the pre-existing anomaly as hasRecentAnomalies",
  );
  assert.notEqual(
    body.securityLevel,
    "normal",
    `securityLevel must reflect hydrated anomaly; got ${body.securityLevel}`,
  );
});

// ---------------------------------------------------------------------------
// T010 — Rate Limits
// ---------------------------------------------------------------------------
//
// /api/passkeys/login/start and /api/auth/login share the per-IP
// `login:` bucket. Hammering one until 429 must NOT leave the other
// bucket fresh — that's what "cannot bypass via endpoint switching"
// means. We assert both halves: passkey-login eventually 429s, and
// the next password-login request from the same IP also 429s.

test("T010 — passkey login rate-limit cannot be bypassed by switching to password login", async () => {
  const ip = "10.0.10.42"; // Unique IP so this test owns its own bucket.
  let observedPasskey429 = false;

  // Spam passkey login/start until we see a 429 (or give up).
  for (let i = 0; i < 60; i++) {
    const res = await fetch(`${baseUrl}/api/passkeys/login/start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": ip,
      },
      body: JSON.stringify({ username: `nobody_${i}` }),
    });
    if (res.status === 429) {
      observedPasskey429 = true;
      break;
    }
  }
  assert.ok(
    observedPasskey429,
    "expected passkey login/start to 429 within 60 attempts",
  );

  // Now the bucket is exhausted. Password login from the SAME IP must
  // also 429 — they share the per-IP `login:` bucket by design.
  const pwLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": ip,
    },
    body: JSON.stringify({
      username: uniqueUsername("xx"),
      authHash: hex64("x"),
    }),
  });
  assert.equal(
    pwLogin.status,
    429,
    "password login from the same exhausted IP must also 429 (shared bucket)",
  );
});

test("T010.vault_sync — repeated vault sync attempts are rate-limited safely", async () => {
  const u = await registerUser();
  const ip = randomIp();
  const attemptedBlob = validEncryptedBlob("t010:rate-sync");
  let limited: Response | null = null;

  for (let i = 0; i < 40; i++) {
    const res = await legacyVaultSync(u, attemptedBlob, 999, { ip });
    if (res.status === 429) {
      limited = res;
      break;
    }
    if (res.status !== 409) {
      assert.fail(`expected pre-limit sync attempts to 409; got ${res.status} ${await res.text()}`);
    }
  }

  assert.ok(limited, "expected repeated vault sync attempts to hit 429");
  await expectRateLimitResponse(limited, [attemptedBlob, u.authHash, u.userId]);
});

test("T010.vault_fetch — repeated vault fetch requests are rate-limited safely", async () => {
  const u = await registerUser();
  const ip = randomIp();
  let limited: Response | null = null;

  for (let i = 0; i < 70; i++) {
    const res = await legacyVaultFetch(u, { ip });
    if (res.status === 429) {
      limited = res;
      break;
    }
    if (res.status !== 200) {
      assert.fail(`expected pre-limit fetch requests to 200; got ${res.status} ${await res.text()}`);
    }
  }

  assert.ok(limited, "expected repeated vault fetch requests to hit 429");
  await expectRateLimitResponse(limited, [u.authHash, u.userId]);
});

test("T010.vault_audit — per-user bucket trips even when IP changes", async () => {
  const u = await registerUser();
  let limited: Response | null = null;

  for (let i = 0; i < 15; i++) {
    const res = await fetch(`${baseUrl}/api/vault/audit`, {
      headers: {
        "x-user-id": u.userId,
        "x-auth-hash": u.authHash,
        "x-forwarded-for": `10.13.${i}.1`,
      },
    });
    if (res.status === 429) {
      limited = res;
      break;
    }
    if (res.status !== 200) {
      assert.fail(`expected pre-limit audit requests to 200; got ${res.status} ${await res.text()}`);
    }
  }

  assert.ok(limited, "expected same-user audit requests across IPs to hit 429");
  await expectRateLimitResponse(limited, [u.authHash, u.userId]);
});

test("T010.vault_audit — unknown userId stays on collapsed auth error, not 429", async () => {
  const missingUserId = randomUUID();
  const authHash = hex64("missing-user-auth");

  for (let i = 0; i < 15; i++) {
    const res = await fetch(`${baseUrl}/api/vault/audit`, {
      headers: {
        "x-user-id": missingUserId,
        "x-auth-hash": authHash,
        "x-forwarded-for": `10.14.${i}.1`,
      },
    });
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: "Invalid credentials" });
  }
});

// T011 — audit visibility: a failed password login (known user, wrong
// authHash) must leave a `login_failed` row in the audit log keyed
// under the real userId. The user-not-found branch deliberately
// writes nothing (no userId to attach + would become a username-
// enumeration oracle), but once the username is real the row IS
// emitted so the legitimate user sees the probe in their activity
// log. Dedup is per (user, ip, minute), so multiple attempts from
// the same IP in the same minute collapse to a single row — that's
// the spec's required behaviour, not a regression.
test("T011 — failed password login emits a login_failed audit row keyed under the real userId", async () => {
  const u = await registerUser();
  const probeIp = "10.0.11.7"; // unique IP so the dedup bucket is owned by this test

  // Wrong authHash → 401, but should leave an audit row.
  const wrongAttempt = await loginUser(u.username, hex64("z"), { ip: probeIp });
  assert.equal(wrongAttempt.status, 401, "wrong authHash must 401");

  // Audit fire-and-forget needs the event-loop tick to flush.
  await new Promise<void>((resolve) => setTimeout(resolve, 50));

  const audit = await storage.getAuditLog(u.userId, 50);
  const loginFailedRow = audit.find((r) => r.action === "login_failed");
  assert.ok(
    loginFailedRow,
    "expected a login_failed audit row after wrong-password attempt",
  );
  assert.equal(loginFailedRow!.ipAddress, probeIp);
  // userAgent metadata must carry the safe reason enum and MUST NOT
  // contain the password / authHash material.
  assert.ok(
    /reason=invalid_credentials/.test(loginFailedRow!.userAgent ?? ""),
    "userAgent metadata must include reason=invalid_credentials",
  );
  assert.ok(
    !/[a-f0-9]{64}/i.test(loginFailedRow!.userAgent ?? ""),
    "userAgent metadata must NOT echo the 64-hex authHash",
  );

  // A second wrong attempt from the SAME IP within the same minute
  // is suppressed by the (user, ip, minute) dedup — confirming the
  // dedup contract works as designed (one row, not two).
  await loginUser(u.username, hex64("y"), { ip: probeIp });
  await new Promise<void>((resolve) => setTimeout(resolve, 50));
  const audit2 = await storage.getAuditLog(u.userId, 50);
  const loginFailedRows = audit2.filter((r) => r.action === "login_failed");
  assert.equal(
    loginFailedRows.length,
    1,
    "second failure from same IP within the minute must dedup to one row",
  );

  // A failure from a DIFFERENT IP within the same minute MUST leave a
  // distinct row — distributed brute-force from many IPs cannot
  // collapse all attempts into a single row (preserves the signal
  // a per-user-only dedup would erase).
  await loginUser(u.username, hex64("y"), { ip: "10.0.11.8" });
  await new Promise<void>((resolve) => setTimeout(resolve, 50));
  const audit3 = await storage.getAuditLog(u.userId, 50);
  const loginFailedRows2 = audit3.filter((r) => r.action === "login_failed");
  assert.ok(
    loginFailedRows2.length >= 2,
    `expected ≥2 login_failed rows once a second IP attempted (got ${loginFailedRows2.length}) — IP-aware dedup must NOT collapse across IPs`,
  );
});
