import express, { type Express, type Request, type Response } from "express";
import { createServer, type Server } from "node:http";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
import { z } from "zod";
import {
  SESSION_LIFETIME_MS,
  AUDIT_LOG_LIMIT,
  HoneytokenMarkerConflictError,
  type AuditEventInput,
  type IStorage,
} from "./storage";
import {
  createHoneytokenSchema,
  disableHoneytokenSchema,
  triggerHoneytokenSchema,
} from "../shared/schema";
import {
  validateRegister,
  validateLogin,
  validateVaultSync,
  validateVaultRestore,
  validateUsernameParam,
  validateAuthHeaders,
  validateSessionTokenHeader,
  validateNoQueryParams,
  validateTotpVerify,
  validateTotpLogin,
  validatePasskeyRegisterStart,
  validatePasskeyRegisterFinish,
  validatePasskeyLoginStart,
  validatePasskeyLoginFinish,
  getOptionalInstallId,
} from "./validation";
import {
  generateTotpSecret,
  verifyTotp,
  buildOtpauthUrl,
  encryptTotpSecret,
  decryptTotpSecret,
} from "./totp";
import {
  generateRegistrationOptionsFor,
  verifyRegistrationResponseFor,
  generateAuthenticationOptionsFor,
  verifyAuthenticationResponseFor,
} from "./webauthn";

// Per-route JSON parsers with explicit, route-appropriate size limits.
// Auth bodies are small (~500 bytes max — see registerSchema/loginSchema bounds);
// vault sync must accept up to a 10 MiB encryptedBlob (see vaultSyncSchema cap)
// plus a few dozen bytes of JSON envelope. We mount per-route rather than
// globally so an auth endpoint cannot be DoS'd by an 11 MiB payload that the
// validator would have rejected anyway.
function jsonBody(limit: string) {
  return express.json({
    limit,
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  });
}
const AUTH_BODY_LIMIT = "4kb";
const VAULT_SYNC_BODY_LIMIT = "11mb";
// POST /api/passkeys/register/finish — the request body wraps a
// WebAuthn RegistrationResponseJSON whose attestationObject can be
// several kilobytes for authenticators with cert chains. The inner
// zod cap allows attestationObject up to 100_000 chars; pick a
// body-parser cap comfortably above the largest plausible real
// payload (~16-32 KiB) so a legitimately-large authenticator
// doesn't hit a 413 before it reaches the strict validator. 64 KiB
// is well below the vault sync ceiling and well above any real
// attestation size we expect to see in practice.
const PASSKEY_FINISH_BODY_LIMIT = "64kb";

function hashForComparison(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 10;

// Per-user request budgets for the authenticated endpoints. These are the
// values from the spec — change any single number here and the cap moves
// without touching any route handler. Values are deliberately tight on
// destructive operations (logout-all = 5/min) and generous on read paths
// (vault/fetch = 60/min, ~one per second of normal client polling).
const PER_USER_RATE_LIMITS = {
  vault_fetch: 60,
  vault_sync: 30,
  vault_history: 30,
  vault_restore: 10,
  auth_sessions: 10,
  logout_all: 5,
  // GET /api/vault/audit — comparable in nature to auth_sessions
  // (read-only listing of per-user metadata). Same 10/min cap so an
  // attacker who briefly has a session can't scrape audit history at
  // unbounded rates. The spec doesn't mandate a limit here, but
  // matching the existing pattern is the conservative default.
  vault_audit: 10,
  // POST /api/vault/recovery/acknowledge — user-initiated exit from
  // recovery mode. Tighter than reads (this mutates security state)
  // but loose enough that a user mashing the button while panicking
  // doesn't lock themselves out. 10/min matches restore/sessions —
  // any single user trying to acknowledge faster than once every
  // 6 seconds is almost certainly a script, not a person.
  recovery_ack: 10,
  // POST /api/auth/trust-device — user-initiated approval of a new
  // device. Tighter than the read endpoints (this mutates session
  // state and could be abused to silently elevate privileges) but
  // not so tight that a user re-trusting after a typo'd request
  // gets locked out. 5/min matches logout_all (the other "I'm
  // taking charge of my account" mutation).
  trust_device: 5,
  // TOTP setup / verify / step-up — all are state-mutating user
  // actions. 5/min matches trust_device: a user fat-fingering a
  // 6-digit code 5 times in a minute is plausible; beyond that we
  // assume someone (or something) is brute-forcing. The window
  // and the otplib `window: 1` (90 sec total skew) together cap
  // the attacker's per-minute guess budget to 5 — well below the
  // 1-in-1000000 / 5 ≈ 1 in 200,000 success probability per minute.
  totp_setup: 5,
  totp_verify: 5,
  // POST /api/auth/totp/step-up — slightly looser (10/min) so a
  // legitimate user pushing through several sensitive actions in a
  // row (sync several blobs, then restore a version) doesn't keep
  // hitting 429 on the gate itself. The verify cap above is the
  // real brute-force defense; step-up reuses the same audit/lockout
  // signals so abuse still surfaces.
  totp_step_up: 10,
  // Passkey registration flow. Two-step ceremony: /start mints a
  // challenge + options, /finish verifies the authenticator's
  // attestation. We cap each at 5/min — the same shape as
  // totp_setup / totp_verify, since the underlying brute-force
  // surface is similar (a user clicking through a registration UI
  // 5 times a minute is plausible; beyond that we assume something
  // is automated). The challenge itself is single-use (consumed by
  // /finish) so even at the cap a successful /start cannot be
  // replayed against /finish more than once.
  passkey_register_start: 5,
  passkey_register_finish: 5,
  // Device management (T005, T008): READ endpoints. 10/min mirrors
  // auth_sessions / vault_audit — same shape (per-user listing of
  // metadata rows) and same brute-force surface (an attacker briefly
  // holding a session has no incentive to scrape these faster than a
  // legitimate user inspecting their own account).
  security_devices: 10,
  passkeys_list: 10,
  // Device label (T010): MUTATE, but the surface area is just renaming
  // a row the user already owns. 10/min matches recovery_ack — loose
  // enough that a user fixing a typo doesn't 429 themselves, tight
  // enough that a script flipping labels at unbounded rates trips.
  device_label: 10,
  // Device trust toggles (T006) and passkey revoke (T009): step-up-
  // gated mutations of authoritative security state. 5/min matches
  // trust_device / logout_all — these are deliberate user actions, not
  // hot-path operations, and the step-up requirement already provides
  // the brute-force defense; the rate limit here is purely a per-user
  // abuse cap.
  security_device_trust: 5,
  passkey_revoke: 5,
  // Passkey step-up: same shape as totp_step_up. Slightly looser
  // than register/* because a real user pushing through several
  // sensitive actions in a row can legitimately re-prove on each
  // one. /finish is what brute-forcers care about (it's the
  // signature-verifying endpoint), and it is still capped at the
  // same 10/min ceiling — the underlying anti-replay is the
  // single-use challenge consumed inside server/webauthn.ts.
  passkey_step_up_start: 10,
  passkey_step_up_finish: 10,
  // Honeytokens / deception layer (T001-T010).
  //
  // Reads (list) mirror security_devices / passkeys_list at 10/min — same
  // shape (per-user listing of metadata rows).
  //
  // Create is a benign user-initiated mutation (no security state flips,
  // just a row insert). 10/min is generous enough that a user setting up
  // multiple decoys in one sitting doesn't 429, tight enough that a
  // script flooding the table at unbounded rates trips.
  //
  // Disable is step-up-gated (mirrors security_device_trust / passkey_revoke)
  // because retiring a honeytoken WEAKENS the user's deception posture —
  // an attacker holding a stolen session shouldn't be able to silently
  // shut down the user's traps. 5/min matches the trust-toggle pattern.
  //
  // Trigger is the hottest path here — a panicking client can fire it
  // multiple times in a burst when several decoy entries are accessed in
  // quick succession (e.g. decryption-loop attack). 30/min gives ample
  // headroom for legitimate burst-trigger scenarios while still bounding
  // a compromised client that loops on POST /trigger to spam audit rows.
  // The audit row itself is NOT in DEDUPABLE_AUDIT_ACTIONS — every
  // trigger writes — so the rate limit is the primary cap on row growth.
  honeytoken_list: 10,
  honeytoken_create: 10,
  honeytoken_disable: 5,
  honeytoken_trigger: 30,
} as const;
type RateLimitedEndpoint = keyof typeof PER_USER_RATE_LIMITS;

// IP-bucket cap for the authenticated endpoints. Set higher than the per-
// user cap so several authenticated users sharing one egress IP (corporate
// NAT, mobile carrier-grade NAT, household router) can each hit their full
// per-user quota without blocking each other. A single source still gets a
// hard cap if it spreads abuse across many user accounts. The 10x factor
// was picked as the "fits a small office" headroom — reasonable shared-IP
// scenarios stay well under it; spam-from-one-IP across many accounts is
// still bounded at a predictable rate.
const PER_IP_LIMIT_MULTIPLIER = 10;

// Rate limiting can be disabled via DISABLE_RATE_LIMIT=true for local
// integration testing where bursts of requests are expected. The flag is
// IGNORED whenever NODE_ENV === "production" so a misconfigured deploy can
// never silently turn off the auth-endpoint protection.
const RATE_LIMIT_DISABLED =
  process.env.NODE_ENV !== "production" &&
  process.env.DISABLE_RATE_LIMIT === "true";

if (RATE_LIMIT_DISABLED) {
  console.warn(
    "[rate-limit] DISABLED via DISABLE_RATE_LIMIT=true " +
      "(non-production environment). Do not use this setting in production.",
  );
} else if (process.env.DISABLE_RATE_LIMIT === "true") {
  console.warn(
    "[rate-limit] DISABLE_RATE_LIMIT=true was set but is being IGNORED " +
      "because NODE_ENV=production. Rate limiting remains active.",
  );
}

// Generic fixed-window counter. The `limit` parameter defaults to
// RATE_LIMIT_MAX so the existing per-IP buckets on register/login/salt
// keep their original 10/min cap untouched; the new per-endpoint buckets
// pass an explicit cap derived from PER_USER_RATE_LIMITS.
function isRateLimited(key: string, limit: number = RATE_LIMIT_MAX): boolean {
  if (RATE_LIMIT_DISABLED) return false;
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count++;
  return entry.count > limit;
}

// Per-endpoint rate limiter for AUTHENTICATED routes. Always called
// AFTER authenticate() so the userId is real (a probe with bad creds
// gets a 401 from authenticate and never poisons either bucket here).
//
// Checks two buckets with one shared cap each:
//   - `endpoint:uid:<userId>` capped at PER_USER_RATE_LIMITS[endpoint] —
//     the primary defense against a single account's abuse.
//   - `endpoint:ip:<ip>`     capped at the user cap × MULTIPLIER —
//     a softer ceiling that lets shared-NAT users coexist while still
//     stopping a single source from spraying across many accounts.
//
// Returns true the moment EITHER bucket is over budget. The 429 response
// at the call site is single-shape; callers must NOT distinguish "user
// vs IP triggered" or report time-to-reset (per spec — leaking that lets
// an attacker tune their pacing).
function checkUserRateLimit(
  endpoint: RateLimitedEndpoint,
  ip: string,
  userId: string,
): boolean {
  const userCap = PER_USER_RATE_LIMITS[endpoint];
  const ipCap = userCap * PER_IP_LIMIT_MULTIPLIER;
  // User bucket FIRST: if a single account is already over its own cap,
  // its denied requests must not keep charging the shared IP bucket.
  // Without this, a single over-quota account on a NAT could eventually
  // drag the IP cap over the line and throttle unrelated, well-behaved
  // users sharing that egress IP.
  if (isRateLimited(`${endpoint}:uid:${userId}`, userCap)) return true;
  // IP bucket only fires when a request was about to be honored. The
  // cross-account abuse case ("one IP spraying via many user accounts")
  // is still caught: each spreader account's request increments IP
  // because it's individually within its per-user cap, so the IP bucket
  // accumulates the spread and saturates at the IP cap.
  if (isRateLimited(`${endpoint}:ip:${ip}`, ipCap)) return true;
  return false;
}

function getClientIp(req: Request): string {
  return req.ip || req.socket.remoteAddress || "unknown";
}

// Stable per-device hash. SHA-256(user-agent || \0 || ip || \0 || x-platform).
// Three notes:
//
//   - We use NUL bytes between fields rather than a printable separator so a
//     pathological user-agent like `"foo\u0000bar"` cannot collide with a
//     different (UA, IP) pair under string concatenation.
//   - x-platform is a soft hint sent by the Expo client (e.g. "ios" / "web").
//     Missing → empty string. We deliberately tolerate its absence: even
//     without it the (UA, IP) pair already gives us a usable fingerprint,
//     and refusing logins from clients that don't send the header would
//     break legacy callers.
//   - The fingerprint is INTENTIONALLY coarse — moving between Wi-Fi and
//     cellular changes the IP and re-trips "new device". That's the
//     correct security tradeoff: better to ask for trust again than to
//     silently accept a session from a network the user has never used.
function getDeviceFingerprint(req: Request): string {
  const ua = captureUserAgent(req) ?? "";
  const ip = getClientIp(req);
  const platformRaw = req.headers["x-platform"];
  const platform = typeof platformRaw === "string" ? platformRaw : "";
  return createHash("sha256")
    .update(ua)
    .update("\u0000")
    .update(ip)
    .update("\u0000")
    .update(platform)
    .digest("hex");
}

// T003 — Pure helper for the trusted_devices table fingerprint.
// DELIBERATELY DIFFERENT from getDeviceFingerprint above:
//   - Two inputs only (ip, ua) — no x-platform header dependency,
//     so the same logical device produces a stable fingerprint across
//     web / mobile contexts that may or may not send the header.
//   - UA is normalized (lowercase + trim) so trivial whitespace /
//     casing differences (some clients send "Mozilla/5.0..." others
//     "mozilla/5.0...") collapse to the same row.
//
// Both fingerprints are SHA-256 hex (irreversible by construction).
// We deliberately do NOT store raw IP+UA anywhere; only the hash is
// persisted (sessions.deviceFingerprint and trusted_devices.deviceFingerprint).
//
// `userAgent` is typed `string | null` to mirror captureUserAgent —
// a request with no UA header still produces a stable hash (the empty
// string after the null-coalesce). This keeps the auth hot path total:
// every request must yield a fingerprint, even ones from misbehaving
// clients.
function deriveDeviceFingerprint(
  ip: string,
  userAgent: string | null,
): string {
  const ua = (userAgent ?? "").toLowerCase().trim();
  return createHash("sha256")
    .update(ua)
    .update("\u0000")
    .update(ip)
    .digest("hex");
}

const DUMMY_SECRET = randomBytes(32);
const DUMMY_ITERATIONS = 100000;

function deterministicDummySalt(username: string): string {
  return createHash("sha256").update(DUMMY_SECRET).update(username).digest("hex");
}

if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitMap) {
      if (now > entry.resetAt) rateLimitMap.delete(key);
    }
  }, 5 * 60_000);
}

// ---------------------------------------------------------------------------
// Anomaly detection (in-memory, best-effort)
// ---------------------------------------------------------------------------
//
// Lightweight inline detection of two patterns, both fire-and-forget into
// the audit log. Neither blocks or rejects requests — that's the rate
// limiter's job. This is *observability* on top of the hard rate caps.
//
//   1. Rate spike:  > ANOMALY_FETCH_THRESHOLD vault_fetch in 60s, or
//                   > ANOMALY_SYNC_THRESHOLD vault_sync in 60s.
//      Triggers ONCE per user per window so a single burst does not
//      flood the audit log with N redundant anomaly rows.
//
//   2. IP change:   the per-user lastIp differs from the request IP.
//      Useful signal for "session token used from two countries" but
//      noisy on roaming users — the spec lists this as OPTIONAL.
//
// Thresholds are deliberately BELOW the rate-limit caps (fetch=60,
// sync=30 per minute) so an anomaly fires before the rate limiter
// kicks in. That gives operators visibility into "this account is
// approaching abuse" without waiting for a hard 429.
//
// State is per-process and resets on restart. Multi-instance deploys
// would need to share state via Redis to detect anomalies that span
// instances — out of scope for this task; in-memory is the spec.
const ANOMALY_FETCH_THRESHOLD = 30;
const ANOMALY_SYNC_THRESHOLD = 15;
const ANOMALY_WINDOW_MS = 60_000;
// Drop entries that haven't been touched in 1h. Bounds memory growth
// for long-tail inactive users while keeping anomaly state alive
// across short pauses (typical user session).
const ANOMALY_STATE_TTL_MS = 60 * 60_000;

type AnomalyState = {
  windowStart: number;
  fetchCount: number;
  syncCount: number;
  // Dedup flags so the threshold only logs ONCE per window per action,
  // not every additional request after crossing the line.
  fetchAnomalyLogged: boolean;
  syncAnomalyLogged: boolean;
  // Same dedup discipline for ip_change_detected: emit at most one
  // ip_change event per user per window. Without this, a flaky NAT
  // or mobile/wifi handoff that flips A→B→A→B every few seconds would
  // spam the audit log with a row per flip — drowning the signal that
  // a real IP change actually means something. Resets on window roll
  // (see new-entry init below).
  ipChangeAnomalyLogged: boolean;
  // Last observed IP — used purely for ip_change_detected. Persists
  // across window rolls so a 61s gap between requests doesn't reset
  // the IP comparison.
  lastIp?: string;
  // For TTL-based cleanup; updated on every recordAnomaly() call.
  lastTouchedAt: number;
};
const anomalyState = new Map<string, AnomalyState>();

type AnomalySignal = {
  rateAnomalyMeta?: string;
  ipChangeFromIp?: string;
};

// Increment the in-memory counters for `userId`+`action`, roll the
// window if expired, and return any anomalies that just crossed their
// threshold. PURE: never logs anything itself — the caller decides
// whether/how to surface the signals (typically: fire-and-forget audit
// rows). Always cheap (one Map lookup, no I/O).
function recordAnomaly(
  userId: string,
  action: "vault_fetch" | "vault_sync",
  ip: string,
): AnomalySignal {
  const now = Date.now();
  let entry = anomalyState.get(userId);
  if (!entry || now - entry.windowStart > ANOMALY_WINDOW_MS) {
    entry = {
      windowStart: now,
      fetchCount: 0,
      syncCount: 0,
      fetchAnomalyLogged: false,
      syncAnomalyLogged: false,
      ipChangeAnomalyLogged: false,
      // Preserve lastIp across window rolls so an IP change is still
      // detectable even if it happens at the boundary.
      lastIp: entry?.lastIp,
      lastTouchedAt: now,
    };
    anomalyState.set(userId, entry);
  }

  let rateAnomalyMeta: string | undefined;
  if (action === "vault_fetch") {
    entry.fetchCount++;
    if (
      entry.fetchCount > ANOMALY_FETCH_THRESHOLD &&
      !entry.fetchAnomalyLogged
    ) {
      entry.fetchAnomalyLogged = true;
      rateAnomalyMeta = `vault_fetch threshold exceeded (${entry.fetchCount} in ${ANOMALY_WINDOW_MS / 1000}s)`;
    }
  } else {
    entry.syncCount++;
    if (
      entry.syncCount > ANOMALY_SYNC_THRESHOLD &&
      !entry.syncAnomalyLogged
    ) {
      entry.syncAnomalyLogged = true;
      rateAnomalyMeta = `vault_sync threshold exceeded (${entry.syncCount} in ${ANOMALY_WINDOW_MS / 1000}s)`;
    }
  }

  let ipChangeFromIp: string | undefined;
  if (entry.lastIp && entry.lastIp !== ip && !entry.ipChangeAnomalyLogged) {
    // First IP change of this window → emit. Subsequent flips within
    // the same window are intentionally suppressed (NAT/cell-handoff
    // noise). entry.lastIp is still updated below so the comparison
    // baseline keeps moving forward.
    ipChangeFromIp = entry.lastIp;
    entry.ipChangeAnomalyLogged = true;
  }
  entry.lastIp = ip;
  entry.lastTouchedAt = now;

  return { rateAnomalyMeta, ipChangeFromIp };
}

if (!RATE_LIMIT_DISABLED) {
  // Periodic GC for anomaly state. Same cadence as the rate-limit map
  // GC above. Without this, a server that has seen N distinct users
  // over its lifetime keeps O(N) anomaly entries in memory forever.
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of anomalyState) {
      if (now - v.lastTouchedAt > ANOMALY_STATE_TTL_MS) {
        anomalyState.delete(k);
      }
    }
  }, 5 * 60_000);
}

// ---------------------------------------------------------------------------
// Passkey failure-burst tracker (in-memory)
// ---------------------------------------------------------------------------
//
// EXTENDS the security model — does NOT replace or modify the existing
// recordAnomaly machinery above. Counts CONSECUTIVE failed passkey
// attempts (login/finish + step-up/finish + login/start with no
// registered credentials) per user inside a sliding window. When the
// burst threshold is crossed the caller escalates via
// escalatePasskeyAnomaly below. A single successful passkey assertion
// decays the counter (decayPasskeyFailures) so a legitimate user who
// fumbled a few attempts before getting it right doesn't carry a
// suspicion tail.
//
// Threshold + window are deliberately tighter than the vault rate
// anomaly: passkey traffic is far lower volume, so MORE THAN 5
// failures in 5min is genuinely unusual (a real user re-tapping
// their YubiKey or re-trying biometrics typically converges in
// 1–3 attempts and finishes inside the window). The trigger uses
// strict `>` against the threshold (i.e. fires on the 6th failure),
// matching the existing `>` semantic in recordAnomaly above for
// consistency — an attacker who stops at exactly 5 failures per
// window stays under the radar for THIS hook, but the per-IP
// `login:` rate limiter still caps total attempts. Counter-replay
// is NOT counted here — that is its own single-event signal and is
// escalated unconditionally at the call site (see
// passkey_counter_replay_detected paths).
const PASSKEY_FAILURE_THRESHOLD = 5;
const PASSKEY_FAILURE_WINDOW_MS = 5 * 60_000;
const PASSKEY_FAILURE_STATE_TTL_MS = 60 * 60_000;

type PasskeyFailureState = {
  windowStart: number;
  count: number;
  // Dedup so the burst escalation fires AT MOST once per window —
  // additional failures past the threshold inside the same window
  // are still counted (so the next window starts from a clean slate
  // only after PASSKEY_FAILURE_WINDOW_MS elapses) but they don't
  // emit additional anomaly_detected rows.
  burstLogged: boolean;
  lastTouchedAt: number;
};
const passkeyFailureState = new Map<string, PasskeyFailureState>();

function recordPasskeyFailure(userId: string): { burstMeta?: string } {
  const now = Date.now();
  let entry = passkeyFailureState.get(userId);
  if (!entry || now - entry.windowStart > PASSKEY_FAILURE_WINDOW_MS) {
    entry = {
      windowStart: now,
      count: 0,
      burstLogged: false,
      lastTouchedAt: now,
    };
    passkeyFailureState.set(userId, entry);
  }
  entry.count++;
  entry.lastTouchedAt = now;
  let burstMeta: string | undefined;
  if (entry.count > PASSKEY_FAILURE_THRESHOLD && !entry.burstLogged) {
    entry.burstLogged = true;
    burstMeta = `passkey failure threshold exceeded (${entry.count} in ${PASSKEY_FAILURE_WINDOW_MS / 1000}s)`;
  }
  return { burstMeta };
}

// T006 hardening: DECAY (not full-reset) the failure streak on a
// successful passkey authentication. The previous behaviour
// (delete-the-entry) let an attacker run an alternating fail/succeed
// pattern indefinitely without ever crossing the burst threshold —
// each clean assertion would erase all of the failures that came
// before it. Decaying by one preserves the ATTACKER's running cost:
// to KEEP the streak below threshold they would have to interleave
// roughly one success for every failure, and that requires actually
// possessing a credential — a bot blasting failures still trips the
// burst the same way it did before.
//
// Successful auth still IMPROVES the user's posture (the count goes
// down by one each time and the entry is dropped at zero), but it
// does not silently launder a long streak in a single tap. The
// burstLogged flag survives within the SAME 5-min window — we don't
// want to re-emit the burst audit on a count that re-crosses
// threshold within the same window — but a fresh window naturally
// resets it via the windowStart check in recordPasskeyFailure.
function decayPasskeyFailures(userId: string): void {
  const entry = passkeyFailureState.get(userId);
  if (!entry) return;
  entry.count = Math.max(0, entry.count - 1);
  entry.lastTouchedAt = Date.now();
  if (entry.count === 0) {
    passkeyFailureState.delete(userId);
  }
}

// Login-failure burst tracker (in-memory)
// ---------------------------------------------------------------------------
//
// Mirrors the passkey-failure tracker above but counts CONSECUTIVE
// non-passkey login failures (password mismatch, TOTP code wrong)
// per user inside the same 5-min sliding window. Kept as a separate
// state map so the passkey decay semantics (a successful passkey tap
// decays the streak) don't accidentally launder password-side bursts
// and vice-versa.
//
// On burst the caller escalates via the EXISTING escalatePasskeyAnomaly
// helper (the function is generic — it writes anomaly_detected +
// recordSecuritySignalHit + optional triggerSoftLock; only the name
// has "Passkey" in it). Uses hardLock=false on the unauth login path
// for the same DoS-protection reason as the passkey burst: an
// attacker who knows a victim username + can rotate IPs could
// otherwise soft-lock the legitimate user's writes.
//
// Threshold + window match the passkey side deliberately (>5 in 5min)
// — a real user who fat-fingers their password or TOTP code converges
// in 1–3 attempts, so the 6th failure is the right escalation point.
const LOGIN_FAILURE_THRESHOLD = 5;
const LOGIN_FAILURE_WINDOW_MS = 5 * 60_000;
const LOGIN_FAILURE_STATE_TTL_MS = 60 * 60_000;

type LoginFailureState = {
  windowStart: number;
  count: number;
  burstLogged: boolean;
  lastTouchedAt: number;
};
const loginFailureState = new Map<string, LoginFailureState>();

function recordLoginFailure(userId: string): { burstMeta?: string } {
  const now = Date.now();
  let entry = loginFailureState.get(userId);
  if (!entry || now - entry.windowStart > LOGIN_FAILURE_WINDOW_MS) {
    entry = {
      windowStart: now,
      count: 0,
      burstLogged: false,
      lastTouchedAt: now,
    };
    loginFailureState.set(userId, entry);
  }
  entry.count++;
  entry.lastTouchedAt = now;
  let burstMeta: string | undefined;
  if (entry.count > LOGIN_FAILURE_THRESHOLD && !entry.burstLogged) {
    entry.burstLogged = true;
    burstMeta = `login failure threshold exceeded (${entry.count} in ${LOGIN_FAILURE_WINDOW_MS / 1000}s)`;
  }
  return { burstMeta };
}

// Decay (not full-reset) on a successful login. Same reasoning as
// decayPasskeyFailures: an attacker shouldn't be able to launder a
// long failure streak with a single successful guess. The streak
// only fully clears when count reaches zero or the 5-min window
// rolls.
function decayLoginFailures(userId: string): void {
  const entry = loginFailureState.get(userId);
  if (!entry) return;
  entry.count = Math.max(0, entry.count - 1);
  entry.lastTouchedAt = Date.now();
  if (entry.count === 0) {
    loginFailureState.delete(userId);
  }
}

// =====================================================================
// Adaptive IP Threat Intelligence (T001-T010)
// =====================================================================
//
// Per-IP behavioural tracking that turns "many failures from one
// source" into a concrete soft-block + adaptive friction. All state
// is process-local in-memory (a restart wipes it — fail-open, per
// T010). No schema or crypto changes; every signal feeds the
// EXISTING anomaly + security-level pipeline (recordSecuritySignalHit
// + triggerSoftLock + an `ip_threat_detected` audit row).
//
// Detected threat types:
//   1. brute_force        — single user, ≥10 failures in 5 min from
//                           one IP.
//   2. credential_stuffing — ≥5 DISTINCT user/username probes from
//                           one IP in 10 min (real userIds and
//                           hashed not-found-username probes both
//                           contribute to cardinality).
//
// On detection:
//   - 5-minute soft IP block (`blockedUntil`) → 429 on subsequent
//     login attempts at any of the 4 login entry points
//     (/api/auth/login, /api/auth/totp/login, /api/passkeys/login/start,
//     /api/passkeys/login/finish). The 429 uses the same single-shape
//     "Too many attempts" wording the IP-rate-limiter already uses,
//     per T005 (no leak of "you specifically are blocked").
//   - `ip_threat_detected` audit row for each REAL targeted user
//     (anyone reading their own activity log learns "an IP probing
//     multiple accounts/many passwords just hit me"). Rows are
//     attached to the user's `userId` because AuditEventInput.userId
//     is NOT NULL — there is no global / unattributed audit shape.
//   - `recordSecuritySignalHit` for each real targeted user with
//     hardLock=(type === credential_stuffing). Brute_force keeps
//     hardLock=false to avoid DoS-amplification on a single account
//     (an attacker who knows just one username could otherwise
//     soft-lock the legitimate user's writes); credential_stuffing
//     against ≥5 distinct accounts is too high-confidence to skip
//     the lock.
//   - For credential_stuffing: explicit triggerSoftLock(userId) on
//     each targeted user. Feeds the existing write-block enforcement
//     so a successful guess in the middle of an attack still hits
//     the soft-lock gate when it tries to write.
//
// Memory safety:
//   - Targeted-user Sets are capped at IP_THREAT_TARGETS_CAP entries
//     per IP. Once an attacker has probed that many distinct users
//     we already know it's an attack and don't need finer cardinality.
//   - Entries inactive >IP_THREAT_INACTIVITY_TTL_MS are GC'd in the
//     existing 5-min sweep below.
//   - Failure count decays by IP_THREAT_DECAY_PER_SUCCESS on every
//     successful login from that IP (T008); when it reaches zero
//     and no block is active, the entry is dropped immediately so
//     a long-running process doesn't hoard memory for IPs that
//     turned out to be benign (e.g. shared NAT where someone
//     fat-fingered once then logged in cleanly).
//
// Username privacy:
//   - We never store raw usernames in memory. The not-found branch
//     stores SHA-256(username) prefixed with "u:" as the target
//     key — this preserves the "5 distinct probes" cardinality
//     measure without holding usernames in process memory. Real
//     users (verified via getUserByUsername) contribute their
//     opaque userId. Audit rows are only emitted for real userIds
//     (a row keyed by hash would have nothing to attach it to).
const IP_THREAT_INACTIVITY_TTL_MS = 30 * 60_000;
const IP_THREAT_BRUTE_THRESHOLD = 10;
const IP_THREAT_BRUTE_WINDOW_MS = 5 * 60_000;
const IP_THREAT_STUFFING_THRESHOLD = 5;
const IP_THREAT_STUFFING_WINDOW_MS = 10 * 60_000;
const IP_THREAT_BLOCK_MS = 5 * 60_000;
const IP_THREAT_TARGETS_CAP = 1000;
const IP_THREAT_DECAY_PER_SUCCESS = 2;
// Bound on the rolling per-IP failure-timestamp queue. Well above
// the brute threshold (10) and decay step (2) so detection is not
// lost even if an attacker hammers faster than the prune cadence;
// existing only to keep the per-IP queue size constant under
// sustained sub-threshold abuse that never trips the block.
const IP_THREAT_FAILURE_QUEUE_CAP = 200;

// Adaptive delay parameters: base preserves the existing 50-120ms
// uniform anti-timing baseline (so legitimate users on a clean IP
// are not slowed down) and adds 50ms per accumulated failure on
// top, capped at 2s total. A first-time visitor with failures=0
// gets the same 50-120ms they always did; an IP with 30+ failures
// faces ~2s per attempt, multiplying the wall-clock cost of a
// brute force by ~10-20x without breaking legitimate retry UX.
const IP_THREAT_DELAY_BASE_MIN_MS = 50;
const IP_THREAT_DELAY_BASE_RANGE_MS = 71; // → uniform(50, 120)
const IP_THREAT_DELAY_PER_FAILURE_MS = 50;
const IP_THREAT_DELAY_CAP_MS = 2000;

type IpThreatEntry = {
  // Rolling queue of failure timestamps. Push on every recorded
  // failure; prune timestamps older than the LONGER of the two
  // detection windows (10 min stuffing) on every read so the queue
  // is naturally self-trimming. Capped at IP_THREAT_FAILURE_QUEUE_CAP
  // to bound memory under sustained sub-threshold abuse — when the
  // cap is hit we drop the oldest (sliding-window semantics).
  //
  // Brute count = number of timestamps inside the 5-min brute window.
  // Stuffing count = distinct targets in targetTimestamps inside the
  // 10-min stuffing window (independent measure).
  failureTimestamps: number[];
  // Per-target last-seen timestamp. Key is either a real userId
  // (UUID string) or a hashUsernameForIpThreat() result ("u:"-prefixed).
  // isReal=true means the key is a real userId and contributes to
  // audit emission; isReal=false means a hashed-username probe (still
  // counts toward stuffing cardinality, but no audit row to emit).
  // Capped at IP_THREAT_TARGETS_CAP distinct entries.
  targetTimestamps: Map<string, { lastSeen: number; isReal: boolean }>;
  lastSeenAt: number;
  blockedUntil?: number;
  // Per-active-block dedup: the audit + security-signal hit for each
  // threat type fires AT MOST ONCE per active block. CRUCIALLY both
  // flags clear inside isIpBlocked() the moment the block is observed
  // to have lapsed — so an attacker who continues hammering after
  // their 5-min cool-off can be re-blocked and re-alerted on the very
  // next threshold breach. Rolling-window detection makes this safe:
  // there is no per-entry-lifetime cap on detections, only "once per
  // active block window".
  bruteAlerted: boolean;
  stuffingAlerted: boolean;
};

const ipThreatState = new Map<string, IpThreatEntry>();

function hashUsernameForIpThreat(username: string): string {
  // SHA-256, truncated to 32 hex chars (128 bits) — collision-resistant
  // enough for cardinality measurement, short enough to cap memory
  // even at IP_THREAT_TARGETS_CAP entries per IP. The "u:" prefix
  // distinguishes hashed-username probes from real userIds (UUID
  // strings) when reading the targetTimestamps map.
  return (
    "u:" +
    createHash("sha256").update(username).digest("hex").slice(0, 32)
  );
}

// Drop entries (failure timestamps + per-target last-seen) older
// than the LONGER of the two detection windows. Keeps both rolling
// counts (brute and stuffing) accurate without O(n) scans on the
// hot path: timestamps are pushed monotonically, so the prune is a
// single-pointer slice from the front.
function pruneIpThreatEntry(entry: IpThreatEntry, now: number): void {
  const longerWindow = Math.max(
    IP_THREAT_BRUTE_WINDOW_MS,
    IP_THREAT_STUFFING_WINDOW_MS,
  );
  const cutoff = now - longerWindow;
  const ts = entry.failureTimestamps;
  let drop = 0;
  while (drop < ts.length && ts[drop] < cutoff) drop++;
  if (drop > 0) ts.splice(0, drop);
  for (const [key, val] of entry.targetTimestamps) {
    if (val.lastSeen < cutoff) entry.targetTimestamps.delete(key);
  }
}

// Number of failures inside the rolling 5-min brute window.
// Timestamps are monotonically increasing (push-only at request
// time), so we scan from the tail and break at the first miss.
function ipThreatBruteCount(entry: IpThreatEntry, now: number): number {
  const cutoff = now - IP_THREAT_BRUTE_WINDOW_MS;
  const ts = entry.failureTimestamps;
  let n = 0;
  for (let i = ts.length - 1; i >= 0; i--) {
    if (ts[i] >= cutoff) n++;
    else break;
  }
  return n;
}

// Distinct-target count inside the rolling 10-min stuffing window.
function ipThreatStuffingCount(
  entry: IpThreatEntry,
  now: number,
): number {
  const cutoff = now - IP_THREAT_STUFFING_WINDOW_MS;
  let n = 0;
  for (const v of entry.targetTimestamps.values()) {
    if (v.lastSeen >= cutoff) n++;
  }
  return n;
}

// Real userIds touched within the LONGER detection window — used
// when emitting per-user audit rows on a fresh block. Hashed-username
// probes are excluded (no userId to attach a row to).
function ipThreatRecentRealUserIds(
  entry: IpThreatEntry,
  now: number,
): string[] {
  const cutoff =
    now - Math.max(IP_THREAT_BRUTE_WINDOW_MS, IP_THREAT_STUFFING_WINDOW_MS);
  const out: string[] = [];
  for (const [key, val] of entry.targetTimestamps) {
    if (val.isReal && val.lastSeen >= cutoff) out.push(key);
  }
  return out;
}

function isIpBlocked(ip: string): boolean {
  if (!ip) return false;
  try {
    const entry = ipThreatState.get(ip);
    if (!entry?.blockedUntil) return false;
    if (entry.blockedUntil > Date.now()) return true;
    // Lazy expire. Drop the blockedUntil field AND clear the
    // per-block dedup flags so a still-attacking IP can be
    // re-blocked + re-alerted on the next threshold breach. Keep
    // the rolling failure history (it self-prunes by window) so
    // adaptive delay still applies until the 30-min GC sweep
    // removes the entry — and so a freshly-unblocked attacker who
    // resumes hammering re-trips the brute window almost
    // immediately.
    delete entry.blockedUntil;
    entry.bruteAlerted = false;
    entry.stuffingAlerted = false;
    return false;
  } catch {
    // Fail-open per T010: anything unexpected here means we
    // treat the IP as un-blocked rather than 500'ing the request.
    return false;
  }
}

function ipThreatDelayMs(ip: string): number {
  const base =
    IP_THREAT_DELAY_BASE_MIN_MS +
    Math.floor(Math.random() * IP_THREAT_DELAY_BASE_RANGE_MS);
  if (!ip) return base;
  try {
    const entry = ipThreatState.get(ip);
    if (!entry) return base;
    // Use the rolling count (timestamps still inside the longer
    // window) rather than a raw counter — decay-on-success and
    // window-prune both shrink this naturally, so a clean IP that
    // had a burst 30 min ago doesn't keep paying the delay tax.
    const extra =
      entry.failureTimestamps.length * IP_THREAT_DELAY_PER_FAILURE_MS;
    return Math.min(base + extra, IP_THREAT_DELAY_CAP_MS);
  } catch {
    return base;
  }
}

// Adaptive replacement for uniformLoginDelay() at login failure
// paths. Preserves the 50-120ms anti-timing-leak baseline (so a
// fresh IP with no history is delayed identically to today) while
// making sustained brute force from a known-bad IP wall-clock
// expensive. The success path continues to call uniformLoginDelay()
// directly so legitimate logins from a shared-NAT IP are not
// penalised by an attacker that recently used the same IP.
async function adaptiveLoginDelay(ip: string): Promise<void> {
  const ms = ipThreatDelayMs(ip);
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}

// Append a failure timestamp WITHOUT triggering threshold
// evaluation — used from ipBlockResponse so attempts that arrive
// while the IP is already blocked still accrue toward the rolling
// brute-force count. CRITICAL for re-block-on-continued-attack
// semantics: when the block lapses 5 min after the original
// trigger, those original failures have aged out of the window —
// but the during-block failures remain, so a single post-unblock
// failure re-trips detection. Conversely, an attacker who pauses
// for the full block duration accrues no timestamps and gets a
// clean window back (intended: the block achieved its goal).
function recordIpBlockedAttempt(ip: string): void {
  if (!ip) return;
  try {
    const now = Date.now();
    const entry = ipThreatState.get(ip);
    if (!entry) return;
    pruneIpThreatEntry(entry, now);
    if (entry.failureTimestamps.length >= IP_THREAT_FAILURE_QUEUE_CAP) {
      entry.failureTimestamps.shift();
    }
    entry.failureTimestamps.push(now);
    entry.lastSeenAt = now;
    // Deliberately do NOT touch targetTimestamps (we have no target
    // at the block-check point — it's before body parsing) and do
    // NOT call evaluateIpThreat (the IP is already blocked; there
    // is nothing to escalate beyond the existing block).
  } catch {
    // Fail-open per T010.
  }
}

// Single-shape 429 response for all four login entry points when
// the IP is currently soft-blocked. Wraps the adaptive delay so an
// attacker can't distinguish the block-response from a regular
// auth-failure response by latency. The wording matches the IP
// rate-limiter exactly so a caller can't tell which gate fired.
//
// Also accrues a failure timestamp via recordIpBlockedAttempt so
// continued hammering during the block keeps the rolling brute
// queue populated — guaranteeing immediate re-block on the next
// failure after the block lapses (rather than requiring a fresh
// 10-failure threshold reload).
async function ipBlockResponse(
  res: Response,
  ip: string,
): Promise<Response> {
  recordIpBlockedAttempt(ip);
  await adaptiveLoginDelay(ip);
  return res
    .status(429)
    .json({ error: "Too many attempts. Please try again later." });
}

function recordIpFailure(
  storage: IStorage,
  ip: string,
  // Either a real userId (uuid) or a hashUsernameForIpThreat()
  // result. Both contribute to the credential-stuffing cardinality
  // threshold; only the real userId variant produces audit rows.
  targetKey: string,
  realUserId: string | null,
): void {
  if (!ip) return;
  // Outer try/catch is the LAST line of fail-open defense — any
  // mutation, evaluator, or audit failure must NOT propagate up
  // into the auth response. The route-level handlers above also
  // call this fire-and-forget (no return value to depend on).
  try {
    const now = Date.now();
    let entry = ipThreatState.get(ip);
    if (!entry) {
      entry = {
        failureTimestamps: [],
        targetTimestamps: new Map(),
        lastSeenAt: now,
        bruteAlerted: false,
        stuffingAlerted: false,
      };
      ipThreatState.set(ip, entry);
    }
    pruneIpThreatEntry(entry, now);
    if (entry.failureTimestamps.length >= IP_THREAT_FAILURE_QUEUE_CAP) {
      // Cap reached — drop oldest, keep newest. Sliding-window
      // semantics under sustained burst; threshold detection is
      // unaffected because the cap is far above the brute threshold.
      entry.failureTimestamps.shift();
    }
    entry.failureTimestamps.push(now);
    // Upsert: a repeat probe of the same target refreshes its
    // lastSeen so the rolling stuffing window correctly excludes
    // it once activity stops. Cap distinct entries to bound memory.
    if (
      entry.targetTimestamps.has(targetKey) ||
      entry.targetTimestamps.size < IP_THREAT_TARGETS_CAP
    ) {
      entry.targetTimestamps.set(targetKey, {
        lastSeen: now,
        isReal: realUserId !== null,
      });
    }
    entry.lastSeenAt = now;
    evaluateIpThreat(storage, ip, entry);
  } catch {
    // Fail-open per T010.
  }
}

function evaluateIpThreat(
  storage: IStorage,
  ip: string,
  entry: IpThreatEntry,
): void {
  try {
    const now = Date.now();
    // Brute force: ≥THRESHOLD failures inside the rolling 5-min
    // window. Independent of stuffing — both can fire on the same
    // entry (each at most once per active block, flags reset on
    // unblock so re-blocking is permitted on continued attack).
    const bruteCount = ipThreatBruteCount(entry, now);
    if (
      !entry.bruteAlerted &&
      bruteCount >= IP_THREAT_BRUTE_THRESHOLD
    ) {
      entry.bruteAlerted = true;
      entry.blockedUntil = now + IP_THREAT_BLOCK_MS;
      fireIpThreatDetected(
        storage,
        ip,
        "brute_force",
        bruteCount,
        ipThreatRecentRealUserIds(entry, now),
      );
    }
    // Credential stuffing: ≥THRESHOLD DISTINCT targets inside the
    // rolling 10-min window. Mix of real userIds + hashed-username
    // probes both count toward cardinality; audit rows only fire
    // for real userIds.
    const stuffingCount = ipThreatStuffingCount(entry, now);
    if (
      !entry.stuffingAlerted &&
      stuffingCount >= IP_THREAT_STUFFING_THRESHOLD
    ) {
      entry.stuffingAlerted = true;
      entry.blockedUntil = now + IP_THREAT_BLOCK_MS;
      fireIpThreatDetected(
        storage,
        ip,
        "credential_stuffing",
        bruteCount, // count = brute window count for consistency
        ipThreatRecentRealUserIds(entry, now),
      );
    }
  } catch {
    // Fail-open per T010.
  }
}

function fireIpThreatDetected(
  storage: IStorage,
  ip: string,
  type: "brute_force" | "credential_stuffing",
  count: number,
  realUserIds: string[],
): void {
  // Per T009: log type, ip, count. NEVER raw usernames or the
  // targeted-user set. Each affected REAL user gets ONE row
  // attached to their account so it surfaces in their security
  // activity log. (Hashed-username probes against non-existent
  // accounts contribute to detection but produce no audit rows —
  // there's no userId to attach them to and a row keyed by hash
  // would be operationally useless.)
  for (const userId of realUserIds) {
    try {
      recordAudit(storage, {
        userId,
        action: "ip_threat_detected",
        ipAddress: ip,
        userAgent: `type=${type}; count=${count}`,
      });
    } catch {
      // Fail-open: audit-write failure must not block the next
      // user in the list nor propagate up to the auth response.
    }
    try {
      // Feed the existing security model. recordSecuritySignalHit
      // paints elevated/high so deriveSecurityLevel sees the IP
      // threat synchronously on the user's next request.
      //
      // hardLock policy:
      //   - credential_stuffing → true. ≥5 distinct accounts probed
      //     from one IP is ~never benign. The triggerSoftLock below
      //     blocks writes for 5 min while the user reviews the
      //     activity log entry.
      //   - brute_force → false. A single-account brute force from
      //     one IP COULD be the legitimate owner fat-fingering — we
      //     paint the security signal (elevated) but don't lock
      //     writes, because an attacker who knows a victim username
      //     could otherwise turn this into a remote DoS on the
      //     legitimate user's vault.
      const hardLock = type === "credential_stuffing";
      recordSecuritySignalHit(userId, null, hardLock);
      if (hardLock) {
        triggerSoftLock(userId);
      }
    } catch {
      // Fail-open per T010: in-memory security model errors MUST
      // NOT propagate up into the auth response.
    }
  }
}

function recordIpSuccess(ip: string): void {
  if (!ip) return;
  try {
    const entry = ipThreatState.get(ip);
    if (!entry) return;
    // Decay by popping the MOST RECENT failures from the rolling
    // queue. Pop-from-tail (vs shift-from-head) means the oldest
    // failures stay in the window — so a clean success after a
    // recent fat-finger streak relieves the user, but an attacker
    // who somehow guesses correctly in the middle of a 9-failure
    // burst still leaves 7 in the window for the next 2 failures
    // to re-trip detection. Decay step is bounded so a single
    // success cannot fully erase a sustained attack pattern.
    for (
      let i = 0;
      i < IP_THREAT_DECAY_PER_SUCCESS && entry.failureTimestamps.length > 0;
      i++
    ) {
      entry.failureTimestamps.pop();
    }
    entry.lastSeenAt = Date.now();
    if (entry.failureTimestamps.length === 0 && !entry.blockedUntil) {
      // Fully decayed and no active block — drop the entry now
      // rather than waiting for the 30-min TTL. Frees memory for
      // IPs that turned out to be benign and lets the next attack
      // burst from this IP re-alert from a clean slate.
      ipThreatState.delete(ip);
    }
  } catch {
    // Fail-open per T010.
  }
}

// T003 hardening: per-(sessionId, ip, ua) dedup so the binding-drift
// audit + security-signal hit fires AT MOST once per unique tuple
// per dedup TTL. Without this, every authenticated request from a
// drifted-binding session would re-emit ip_change_detected /
// device_mismatch and re-mark the session suspicious — pure noise
// and a soft DoS on the audit table.
//
// Key shape: `${sessionId}|${currentIp}|${currentUa}`. The TTL is
// long (1h) because a stolen session that keeps using the same
// (ip, ua) tuple is a SINGLE event from a security-signal
// perspective; we don't need to re-flag every minute. A session
// that legitimately roams (mobile carrier IP rotation, captive
// portal swap) emits one event per new tuple — also fine.
const SESSION_BINDING_DEDUP_TTL_MS = 60 * 60_000;
const sessionBindingDriftDedup = new Map<string, number>();

if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of passkeyFailureState) {
      if (now - v.lastTouchedAt > PASSKEY_FAILURE_STATE_TTL_MS) {
        passkeyFailureState.delete(k);
      }
    }
    // Same 5-min sweep also GCs the login-failure tracker — entries
    // not touched in an hour can't be part of any active 5-min burst
    // window and serve no further purpose.
    for (const [k, v] of loginFailureState) {
      if (now - v.lastTouchedAt > LOGIN_FAILURE_STATE_TTL_MS) {
        loginFailureState.delete(k);
      }
    }
    // T003 hardening: piggyback on the same 5-min sweep to GC the
    // session-binding-drift dedup map. Entries older than the dedup
    // TTL are safe to evict — the next drifted request from the
    // same tuple will simply re-fire one event, which is the
    // intended cadence anyway.
    for (const [k, ts] of sessionBindingDriftDedup) {
      if (now - ts > SESSION_BINDING_DEDUP_TTL_MS) {
        sessionBindingDriftDedup.delete(k);
      }
    }
    // Adaptive IP threat sweep: drop entries that haven't seen a
    // login attempt in IP_THREAT_INACTIVITY_TTL_MS (30 min). The
    // entry's failures + targetedUsers history can't contribute to
    // any active 5-min brute-force or 10-min stuffing window after
    // that long, so it's safe to evict — a returning attacker
    // starts fresh and re-trips the thresholds normally.
    for (const [k, v] of ipThreatState) {
      if (now - v.lastSeenAt > IP_THREAT_INACTIVITY_TTL_MS) {
        ipThreatState.delete(k);
      }
    }
  }, 5 * 60_000);
}

// T003 hardening: detect when an active session's current request
// arrives from a different (ip, ua) than the session row was
// originally minted with. Mark the session suspicious + paint the
// security-signal + emit a dedup-aware audit row. Does NOT kill
// the session — per spec, the existing step-up + write-block gates
// already restrict what a drifted-binding session can DO; this
// hook only ensures the user's session-list UI surfaces "this
// device looks suspicious" and that subsequent context-evaluation
// (deriveSecurityLevel) sees the elevated state.
//
// Conservative comparisons:
//   - ip:    skip when stored or current is empty/unknown — the
//            request might have arrived through a different proxy
//            chain on first contact post-deploy and we'd rather
//            under-flag than spam.
//   - ua:    skip when stored or current is empty — legacy rows
//            pre-feature have a NULL user_agent and we treat that
//            as "no signal". Substring exact compare is fine for
//            our purposes (a real UA change is a different string
//            top-to-bottom, not a tweak).
function checkSessionBindingDrift(
  storage: IStorage,
  session: {
    id: string;
    userId: string;
    ipAddress: string | null;
    userAgent: string | null;
  },
  currentIp: string | null,
  currentUa: string | null,
): void {
  // Coerce nulls up-front so the rest of the function can compare
  // strings without a type pivot. captureUserAgent returns `string |
  // null` (legitimately, when the request omits the header) and
  // getClientIp can also return an empty string under proxy edge
  // cases — both must be treated as "no signal" rather than crashing
  // .length lookups, which would have been swallowed by the outer
  // try/catch and silently SUPPRESSED the drift signal entirely. The
  // empty-string sentinel below then naturally short-circuits the
  // drift compare (a stored value cannot drift from "absent").
  const storedIp = session.ipAddress ?? "";
  const storedUa = session.userAgent ?? "";
  const curIp = currentIp ?? "";
  const curUa = currentUa ?? "";
  const ipDrift =
    storedIp.length > 0 && curIp.length > 0 && storedIp !== curIp;
  const uaDrift =
    storedUa.length > 0 && curUa.length > 0 && storedUa !== curUa;
  if (!ipDrift && !uaDrift) return;

  // Dedup BEFORE any side effect so a drifted session that keeps
  // hitting endpoints doesn't re-mark / re-audit / re-flag. The
  // 5-min audit-level dedup in recordAudit is per-(user, action,
  // minute) and would still let one row per minute through, which
  // is too noisy for this signal — the session-tuple dedup here
  // is the right granularity.
  const key = `${session.id}|${currentIp}|${currentUa}`;
  const now = Date.now();
  const seenAt = sessionBindingDriftDedup.get(key);
  if (seenAt !== undefined && now - seenAt < SESSION_BINDING_DEDUP_TTL_MS) {
    return;
  }
  sessionBindingDriftDedup.set(key, now);

  // Mark + signal. markSessionSuspicious is fail-open inside
  // storage; recordSecuritySignalHit is sync in-memory. Emit the
  // ip_change_detected row only on actual IP drift (so a UA-only
  // change doesn't claim an IP changed); device_mismatch only on
  // UA drift. Both can fire if both drifted. flagSession=false
  // because markSessionSuspicious already records the per-session
  // flag durably — the in-memory suspicious-set is a write-side
  // optimisation we don't need to also touch from the read path.
  void storage.markSessionSuspicious(session.id);
  recordSecuritySignalHit(session.userId, session.id, false);
  if (ipDrift) {
    recordAudit(storage, {
      userId: session.userId,
      action: "ip_change_detected",
      ipAddress: currentIp,
      userAgent: `previous=${storedIp}; sessionId=${session.id.slice(0, 8)}; source=session_binding`,
    });
  }
  if (uaDrift) {
    recordAudit(storage, {
      userId: session.userId,
      action: "device_mismatch",
      ipAddress: currentIp,
      // Truncate both UAs to 80 bytes each so a malicious caller
      // with a giant UA can't bloat the audit row past sensible
      // bounds. captureUserAgent already caps at 512; this is a
      // tighter limit specifically for the metadata field.
      userAgent: `previous=${storedUa.slice(0, 80)}; current=${curUa.slice(0, 80)}; sessionId=${session.id.slice(0, 8)}`,
    });
  }
}

// Single chokepoint that EXTENDS the existing security model with a
// passkey-side anomaly. Mirrors the rate-spike escalation block in
// /api/vault/sync (anomaly_detected audit + recordSecuritySignalHit
// + markSessionSuspicious + optionally triggerSoftLock) using the
// same hooks — does NOT introduce a parallel security state machine
// and does NOT mutate the existing recordAnomaly counters.
//
// hardLock semantics:
//
//   - true  → also call triggerSoftLock(userId). Used for replay
//             detection (always — that's a near-zero-false-positive
//             signal) and for AUTHENTICATED step-up failure bursts
//             (the caller already proved session ownership).
//
//   - false → skip triggerSoftLock; still record anomaly_detected
//             + recordSecuritySignalHit (paints securityLevel
//             "elevated", increases threatLevel via the existing
//             unified ladder). Used for UNAUTHENTICATED passkey
//             login failure bursts where soft-locking on a known
//             username + many attacker IPs would be a remote DoS
//             vector against the legitimate user's writes. The
//             elevated level + audit row still surface in the
//             owner's activity log, and the per-IP login rate
//             limit (already in place upstream) is the primary
//             defense against the brute-force burst itself.
//
// sessionId may be null for unauthenticated paths (login/start,
// login/finish). markSessionSuspicious + the suspicious-session set
// are both gated on a non-null sessionId.
function escalatePasskeyAnomaly(
  storage: IStorage,
  userId: string,
  sessionId: string | null,
  ip: string,
  meta: string,
  opts: { hardLock: boolean },
): void {
  recordAudit(storage, {
    userId,
    action: "anomaly_detected",
    ipAddress: ip,
    userAgent: meta,
  });
  if (opts.hardLock) {
    triggerSoftLock(userId);
  }
  if (sessionId) {
    void storage.markSessionSuspicious(sessionId);
  }
  recordSecuritySignalHit(userId, sessionId, true);
}

// ---------------------------------------------------------------------------
// Soft-lock + IP-burst response system (in-memory, fail-open)
// ---------------------------------------------------------------------------
//
// LAYERED on top of anomaly detection. Anomaly detection observes; this
// layer RESPONDS:
//
//   - Rate-spike anomaly (existing rateAnomalyMeta from recordAnomaly)
//     → soft-lock the user for SOFT_LOCK_DURATION_MS.
//   - IP-flip burst: more than IP_CHANGE_THRESHOLD distinct sequential
//     IPs in IP_CHANGE_WINDOW_MS → soft-lock.
//
// Soft lock semantics (per spec, deliberately conservative):
//   - Returns 423 from POST /api/vault/sync and POST /api/vault/restore
//     ONLY. Reads (fetch, history, audit, sessions) keep working — the
//     user must always be able to see what's happening on their account
//     during a lock.
//   - Always auto-expires (Date.now() comparison, no admin override
//     needed). There is no code path that creates a permanent lock.
//   - Fail-open: if the in-memory state is somehow lost (server
//     restart, GC eviction), all writes succeed. This is INTENTIONAL.
//     Locking out a legitimate user because the lock-state Map crashed
//     would be worse than a brief detection gap.
//   - Triggered by the anomaly detector but NEVER by the rate-limiter:
//     hitting a rate cap (429) is normal client misbehavior; tripping
//     an anomaly threshold is the genuinely-suspicious signal.
//
// IP-burst tracking is separate from the existing single-flip
// ip_change_detected event. A single flip is logged but does NOT lock
// (per spec's "light touch"). Locking only happens after enough flips
// pile up in the window — this catches "session token in use from many
// places" without punishing road-warrior / mobile-roaming users.
const SOFT_LOCK_DURATION_MS = 5 * 60_000;
const IP_CHANGE_WINDOW_MS = 10 * 60_000;
// Spec wording: "more than 3 IP changes within 10 minutes". A "change"
// is a transition (A→B), not an entry. With N entries in the buffer,
// transitions = N - 1. "More than 3" → transitions ≥ 4 → entries ≥ 5.
const IP_CHANGE_THRESHOLD = 3;
// Cap the buffer slightly above what the threshold needs so the
// trim-to-window step has room to detect the most recent burst even
// if old entries haven't been GC'd yet.
const IP_HISTORY_MAX = IP_CHANGE_THRESHOLD + 3;

type UserSecurityState = {
  // Wall-clock epoch-ms after which the lock no longer applies. Absent
  // / undefined → no lock. Compared with Date.now() on every check;
  // there is no separate "lock expired" event — the absence of a
  // future timestamp IS the unlock.
  softLockedUntil?: number;
  // Ring buffer of recent (ip, when) entries for burst detection.
  // Pruned to entries within IP_CHANGE_WINDOW_MS on every push.
  // Bounded length IP_HISTORY_MAX so a long-running attacker cannot
  // grow this unbounded for one user.
  ipHistory: Array<{ ip: string; at: number }>;
  // For TTL-based GC of inactive users.
  lastTouchedAt: number;
  // Wall-clock epoch-ms of the most recent anomaly_detected OR
  // write_blocked_soft_lock event. Mirrors the signal that GET
  // /api/vault/audit's hasRecentAnomalies derives from the audit log,
  // kept in memory so deriveSecurityLevel can compute "elevated"
  // without a DB hit on the hot path. Considered "recent" while
  // (now - recentAnomalyAt) <= ANOMALY_RECENT_WINDOW_MS. Lost on
  // process restart — fail-open by design.
  recentAnomalyAt?: number;
  // In-memory mirror of session ids whose sessions.suspicious column
  // has been set TRUE during this process's lifetime. Used by
  // deriveSecurityLevel to detect "high" synchronously, without a
  // per-request DB lookup. The DB column remains the durable source
  // of truth and is what GET /api/auth/sessions actually surfaces;
  // this Set is purely a hot-path cache. Lost on restart but
  // hydrated lazily from the audit log — see hydrateSecurityStateFromAudit.
  suspiciousSessions: Set<string>;
  // In-memory mirror of session ids whose sessions.trusted column is
  // FALSE in the DB (i.e. a new device that has not yet been approved
  // for sync/restore). Populated lazily by `authenticate` whenever it
  // resolves a session — DB column is the source of truth, this Set is
  // a hot-path cache for deriveSecurityLevel and the sync/restore 403
  // gate. Removed from the set when the device is trusted (login on a
  // known device, or POST /api/auth/trust-device). Lost on restart but
  // that's fail-OPEN by design: a forgotten "untrusted" entry only
  // matters until the next authenticate() call rebuilds it from the DB
  // row, and the sync/restore endpoints re-check the in-memory set
  // populated by their own authenticate() call this same request.
  untrustedSessions: Set<string>;
  // T007 — In-memory mirror of session ids whose CURRENT REQUEST's
  // device-fingerprint matched a trusted_devices row with trusted=false
  // (i.e. the device the user is on right now is not yet user-approved).
  // Populated by authenticate() after the createOrUpdateDevice call;
  // cleared by POST /api/security/device/trust on a successful flip.
  // SEPARATE from `untrustedSessions` (which mirrors the per-SESSION
  // sessions.trusted column): a device the user has globally trusted
  // can still mint a fresh untrusted session, and an untrusted device
  // can still hold a session the user previously trusted on a
  // different device. Both signals contribute "elevated" via
  // deriveSecurityLevel — neither overrides the other.
  deviceUntrustedSessions: Set<string>;
  // Wall-clock epoch-ms of the last successful hydration from the
  // audit log. Set by hydrateSecurityStateFromAudit. Its mere
  // presence (alongside the entry being in userSecurityState at all)
  // is what causes future hydrateIfNeeded calls to skip — see the
  // race-protection comment on hydrateIfNeeded for why a placeholder
  // gets stamped BEFORE the audit query, not after.
  hydratedAt?: number;
};
const userSecurityState = new Map<string, UserSecurityState>();

// Same TTL as anomaly state. A user inactive for >1h drops out of the
// in-memory tracker entirely (next request rebuilds state from scratch
// — fail-open by design). EXCEPT: an active soft lock keeps the entry
// alive past its TTL so a user who triggers a lock and then disappears
// can't dodge the lock by waiting an hour.
const SECURITY_STATE_TTL_MS = 60 * 60_000;
if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of userSecurityState) {
      const stillLocked =
        v.softLockedUntil !== undefined && v.softLockedUntil > now;
      if (!stillLocked && now - v.lastTouchedAt > SECURITY_STATE_TTL_MS) {
        userSecurityState.delete(k);
      }
    }
  }, 5 * 60_000);
}

function getOrInitSecurityState(userId: string): UserSecurityState {
  let s = userSecurityState.get(userId);
  if (!s) {
    s = {
      ipHistory: [],
      lastTouchedAt: Date.now(),
      suspiciousSessions: new Set(),
      untrustedSessions: new Set(),
      deviceUntrustedSessions: new Set(),
    };
    userSecurityState.set(userId, s);
  }
  // Backward-compat: existing UserSecurityState entries created by
  // earlier process versions don't have the new field. Heal lazily so
  // the very first hydrate after a deploy doesn't NPE on Set ops.
  if (!s.deviceUntrustedSessions) {
    s.deviceUntrustedSessions = new Set();
  }
  return s;
}

// T007 — In-memory write helpers for the device-trust signal. Mirror
// the recordUntrustedSession / clearUntrustedSession pair above. Both
// are pure in-memory mutations — the DB row in trusted_devices is the
// durable source of truth and is written by the storage layer; these
// helpers just keep the synchronous hot-path check (deriveSecurityLevel)
// in lock-step with what the most recent authenticate() call observed.
function recordDeviceUntrustedSession(
  userId: string,
  sessionId: string,
): void {
  const s = getOrInitSecurityState(userId);
  s.deviceUntrustedSessions.add(sessionId);
  s.lastTouchedAt = Date.now();
}

function clearDeviceUntrustedSession(
  userId: string,
  sessionId: string,
): void {
  const s = userSecurityState.get(userId);
  if (!s) return;
  s.deviceUntrustedSessions?.delete(sessionId);
  s.lastTouchedAt = Date.now();
}

// Mark a session as untrusted in the in-memory cache. Called by
// `authenticate` whenever the resolved session row has trusted=false
// (i.e. the user is on a device they have not yet approved). Idempotent
// — re-marking is a no-op Set.add. We deliberately do NOT touch the DB
// here: the DB column is the durable source of truth and was set at
// session-creation time; this Set just lets the hot-path checks (sync /
// restore 403, deriveSecurityLevel) avoid a DB hit.
function recordUntrustedSession(userId: string, sessionId: string): void {
  const s = getOrInitSecurityState(userId);
  s.untrustedSessions.add(sessionId);
  s.lastTouchedAt = Date.now();
}

// Inverse of recordUntrustedSession — called when a session becomes
// trusted (POST /api/auth/trust-device, or `authenticate` resolving a
// session row where trusted=true). No DB write here either; the route
// that owns the trust transition is responsible for the DB UPDATE.
function clearUntrustedSession(userId: string, sessionId: string): void {
  const s = userSecurityState.get(userId);
  if (!s) return;
  s.untrustedSessions.delete(sessionId);
  s.lastTouchedAt = Date.now();
}

// Synchronous hot-path check for "is this session currently flagged as
// untrusted?". Returns false on any missing-state path so an empty
// in-memory cache (e.g. right after restart) is treated as trusted —
// authenticate() will repopulate from the DB on the next request,
// which is the only place the cache mismatch could leak through.
function isSessionUntrusted(
  userId: string,
  sessionId: string | null,
): boolean {
  if (!sessionId) return false;
  const s = userSecurityState.get(userId);
  if (!s) return false;
  return s.untrustedSessions.has(sessionId);
}

// Stamp the in-memory "recent anomaly" timestamp and optionally mirror
// the suspicious-session flag. Called from the SAME paths that log
// anomaly_detected and write_blocked_soft_lock so the in-memory signal
// stays in lock-step with the audit-log signal — that lets
// deriveSecurityLevel project "elevated"/"high" without re-reading the
// audit table on every request. flagSession=false on plain
// write_blocked_soft_lock paths (the lock alone doesn't escalate the
// SESSION; the session is only flagged when an actual anomaly fires).
function recordSecuritySignalHit(
  userId: string,
  sessionId: string | null,
  flagSession: boolean,
): void {
  const s = getOrInitSecurityState(userId);
  s.recentAnomalyAt = Date.now();
  s.lastTouchedAt = s.recentAnomalyAt;
  if (flagSession && sessionId) {
    s.suspiciousSessions.add(sessionId);
  }
}

// Returns the lock-until timestamp if the user is currently soft-locked,
// otherwise undefined. ALSO opportunistically clears expired locks so the
// in-memory state doesn't accumulate stale `softLockedUntil` values past
// their expiry — important for the auto-expire UX (user makes a request
// after the 5min lock has elapsed, this returns undefined, write proceeds).
function getActiveSoftLock(userId: string): number | undefined {
  const s = userSecurityState.get(userId);
  if (!s || s.softLockedUntil === undefined) return undefined;
  const now = Date.now();
  if (s.softLockedUntil > now) return s.softLockedUntil;
  s.softLockedUntil = undefined;
  return undefined;
}

// Idempotent. Multiple anomalies in quick succession do NOT extend an
// already-longer lock — Math.max keeps the latest expiry, never shortens.
// Returns the lock-until timestamp so callers can include it in the
// audit log payload.
function triggerSoftLock(userId: string): number {
  const s = getOrInitSecurityState(userId);
  const now = Date.now();
  const candidate = now + SOFT_LOCK_DURATION_MS;
  s.softLockedUntil = Math.max(s.softLockedUntil ?? 0, candidate);
  s.lastTouchedAt = now;
  return s.softLockedUntil;
}

// Push the current IP onto the per-user history (only if it differs
// from the most recent entry — repeated requests from the same IP do
// not count as "changes"), prune to window + max-length, and report
// whether the user JUST CROSSED the IP_CHANGE_THRESHOLD on this call.
//
// Edge-detected on purpose: a still-bursty user already past the
// threshold returns FALSE here (the soft lock is already active and
// triggerSoftLock is idempotent, but recomputing it on every
// subsequent request was wasteful and made auditing the trigger point
// harder). When the window expires and entries drop back below the
// threshold, the next crossing fires fresh — no permanent suppression.
function trackIpAndCheckBurst(userId: string, ip: string): boolean {
  const s = getOrInitSecurityState(userId);
  const now = Date.now();
  s.lastTouchedAt = now;
  // Prune stale entries FIRST so transitionsBefore reflects only the
  // current 10-min window. Otherwise a 2-hour-old entry would inflate
  // the pre-push count and prevent the edge detector from firing the
  // current window's first crossing.
  s.ipHistory = s.ipHistory.filter((e) => now - e.at <= IP_CHANGE_WINDOW_MS);
  const transitionsBefore = Math.max(0, s.ipHistory.length - 1);

  const last = s.ipHistory[s.ipHistory.length - 1];
  if (!last || last.ip !== ip) {
    s.ipHistory.push({ ip, at: now });
  }
  // Hard cap on buffer length to bound per-user memory.
  if (s.ipHistory.length > IP_HISTORY_MAX) {
    s.ipHistory = s.ipHistory.slice(-IP_HISTORY_MAX);
  }
  const transitionsAfter = s.ipHistory.length - 1;
  // Edge: must have just crossed from "at-or-below threshold" to
  // "above threshold". Threshold check uses ">" to match spec wording
  // "more than 3".
  return (
    transitionsAfter > IP_CHANGE_THRESHOLD &&
    transitionsBefore <= IP_CHANGE_THRESHOLD
  );
}

// ---------------------------------------------------------------------------
// Unified security level system
// ---------------------------------------------------------------------------
//
// One single backend-derived signal that the frontend can render directly
// (fractal renderer + UI messaging). Rather than asking the client to
// inspect a half-dozen flags (suspicious, hasRecentAnomalies, soft lock,
// IP-burst, ...), the server projects everything onto a 4-state ladder:
//
//   normal   — no active signals
//   elevated — anomaly_detected or write_blocked_soft_lock in the last
//              ANOMALY_RECENT_WINDOW_MS, but no other elevation
//   high     — the authenticating session is flagged suspicious
//   critical — user is currently soft-locked
//
// Levels are RANKED (normal=0..critical=3) so transitions can be split
// into "any change" vs "escalation only" — see evaluateSecurityLevel.
//
// HOT PATH discipline: deriveSecurityLevel is FULLY SYNCHRONOUS and
// only reads in-memory state set by the existing anomaly/soft-lock
// hooks. NO DB I/O. This satisfies the "do NOT query DB repeatedly"
// constraint and keeps per-request cost effectively zero.
type SecurityLevel = "normal" | "elevated" | "high" | "critical";
const LEVEL_RANK: Record<SecurityLevel, number> = {
  normal: 0,
  elevated: 1,
  high: 2,
  critical: 3,
};
const ANOMALY_RECENT_WINDOW_MS = 10 * 60_000;

// Per-user "last observed level" so we can detect transitions and log
// only on change (not on every request). Mutating this Map and emitting
// the audit row both happen in the same synchronous tick — concurrent
// requests within that tick will all observe the post-update value, so
// duplicate transition rows can't be produced for one event.
const userSecurityLevelState = new Map<
  string,
  { currentLevel: SecurityLevel; lastChangedAt: number }
>();

if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of userSecurityLevelState) {
      if (now - v.lastChangedAt > SECURITY_STATE_TTL_MS) {
        userSecurityLevelState.delete(k);
      }
    }
  }, 5 * 60_000);
}

// ---------------------------------------------------------------------------
// Recovery Mode + Visual Canary (Threat Level)
// ---------------------------------------------------------------------------
//
// Recovery Mode is an in-memory "circuit breaker" the server flips when a
// user's security level escalates to "critical". While active it:
//   - Blocks all WRITES (vault/sync, vault/restore) with 423 — protecting
//     the vault from further damage during a suspected compromise.
//   - Leaves READS available so the user can still inspect their vault,
//     audit log, sessions, and (out-of-band) recover from a backup.
//   - Forces threatLevel=100 in the response so the UI can paint the
//     "panic" canary regardless of the underlying numeric level.
//
// Fail-open guarantees (T7):
//   1. The user can ALWAYS escape via POST /api/vault/recovery/acknowledge.
//   2. If the user just stops poking the server, recovery mode auto-exits
//      after either (a) 10 min with no recent anomaly + no active lock
//      (the "clean" path) or (b) RECOVERY_MAX_AGE_MS regardless of state
//      (the "backstop" path that prevents a sustained false-positive
//      from permanently locking a legitimate user out).
//   3. Process restart never traps a user in recovery mode: the state is
//      in-memory only. Hydration MAY re-enter recovery mode if and only
//      if the audit log shows actual anomalies in the recent window AND
//      the reconstructed level is "critical" (T7 wording: "must NOT
//      re-trigger ... unless anomalies exist") — and even then the
//      acknowledge + auto-expire escape hatches still apply.
//
// All recovery actions audit-log via recordAudit (fire-and-forget,
// never throws).

type RecoveryModeState = {
  enteredAt: number;
  reason: string;
  // Soft flag rather than Map.delete() so we keep the timestamps for
  // a short window after exit (useful for diagnosing back-to-back
  // re-entries). The GC sweep below drops fully-inactive entries.
  active: boolean;
};

// Per-user recovery mode state. Lost on restart by design — see
// hydration hook in hydrateIfNeeded for the deliberate, conditional
// re-entry pathway.
const recoveryState = new Map<string, RecoveryModeState>();

// ---------------------------------------------------------------------------
// TOTP step-up: in-memory state
// ---------------------------------------------------------------------------
//
// Two ephemeral maps backing the TOTP flow. Both are deliberately
// in-memory only:
//
//   - tempLoginTokens: short-lived token issued by /api/auth/login when
//     a user with TOTP enabled passes the password phase. The client
//     redeems it (with the 6-digit code) at /api/auth/totp/login to
//     obtain a real session. NOT a session token: it cannot
//     authenticate any other endpoint, is single-use, and expires
//     after TEMP_LOGIN_TTL_MS regardless. Process restart invalidates
//     all in-flight 2FA logins — the user just retypes their password,
//     which is a 5-second annoyance, not a security regression.
//
//   - pendingTotpSetups: secret generated by /api/auth/totp/setup but
//     not yet confirmed by /api/auth/totp/verify. Stored in memory
//     only so a half-finished setup can never reach the DB and
//     accidentally enable 2FA without the user proving they hold the
//     secret. Bounded TTL keeps the map small even if a user opens
//     the setup screen repeatedly.
//
// Both maps are GC'd by a periodic sweep that runs alongside the
// existing rate-limit GC (5 min cadence). Per-user write replaces any
// existing entry — the most recent setup attempt wins, so a user who
// re-opens the setup screen after losing their first QR code is not
// trapped by a stale pending entry.

const TEMP_LOGIN_TTL_MS = 5 * 60_000;
const SETUP_PENDING_TTL_MS = 10 * 60_000;
// Step-up validity window. After a successful POST /api/auth/totp/step-up,
// the session is treated as 2FA-verified for this long. Matches the
// spec's "5 minute" guidance and is short enough that a stolen
// session token can only abuse the elevated state for a brief
// window before having to re-prompt for the code.
const STEP_UP_TTL_MS = 5 * 60_000;

type TempLoginToken = {
  // Hash of the random token, NOT the raw value. Same discipline as
  // sessions.tokenHash — a leak of this map cannot impersonate the
  // user even before TTL expiry.
  tokenHash: string;
  userId: string;
  expiresAt: number;
};
// Keyed by tokenHash for O(1) redemption lookup. Single entry per
// hash; the random bytes make collisions astronomically unlikely.
const tempLoginTokens = new Map<string, TempLoginToken>();

type PendingTotpSetup = {
  secret: string;
  expiresAt: number;
};
// Keyed by userId — only one in-flight setup per user at a time. A
// new POST /api/auth/totp/setup overwrites the previous entry.
const pendingTotpSetups = new Map<string, PendingTotpSetup>();

if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of tempLoginTokens) {
      if (now > v.expiresAt) tempLoginTokens.delete(k);
    }
    for (const [k, v] of pendingTotpSetups) {
      if (now > v.expiresAt) pendingTotpSetups.delete(k);
    }
  }, 5 * 60_000);
}

// Hard upper bound on recovery mode lifetime regardless of subsequent
// signals. Required by the T7 fail-open guarantee — even if anomalies
// keep firing, recovery mode auto-exits after this much time so a
// legitimate user cannot be permanently locked out by a sustained
// false-positive escalation. Distinct from the "clean" 10-min auto-
// exit which only fires when the underlying signals have settled.
const RECOVERY_MAX_AGE_MS = 15 * 60_000;

// GC TTL for inactive recovery state entries. Same TTL we use for the
// other in-memory security maps, so memory growth stays bounded for
// long-tail inactive users.
const RECOVERY_TTL_MS = SECURITY_STATE_TTL_MS;

if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of recoveryState) {
      // Only sweep entries that have already exited (active=false) —
      // an active recovery state is meaningful even if it's old; the
      // RECOVERY_MAX_AGE_MS backstop inside isRecoveryModeActive will
      // exit it lazily on the next request.
      if (!v.active && now - v.enteredAt > RECOVERY_TTL_MS) {
        recoveryState.delete(k);
      }
    }
  }, 5 * 60_000);
}

// Idempotent enter. Re-entering an already-active recovery state is a
// no-op (no duplicate audit row). The transition reason is recorded
// in the audit metadata so operators can distinguish "live escalation"
// from "post-restart hydration" entries.
function enterRecoveryMode(
  userId: string,
  reason: string,
  fromLevel: SecurityLevel,
  toLevel: SecurityLevel,
  storage: IStorage,
): void {
  const existing = recoveryState.get(userId);
  if (existing?.active) return;
  recoveryState.set(userId, {
    enteredAt: Date.now(),
    reason,
    active: true,
  });
  recordAudit(storage, {
    userId,
    action: "recovery_mode_entered",
    ipAddress: null,
    // Stash structured context in user_agent following the existing
    // anomaly_detected / write_blocked_soft_lock convention. Keeps
    // the audit schema unchanged.
    userAgent: `reason=${reason}; from=${fromLevel}; to=${toLevel}`,
  });
}

// Idempotent exit. Distinct exit reasons ("user_acknowledged",
// "auto_expired_clean", "auto_expired_max_age") are surfaced in the
// audit metadata so operators can distinguish manual dismissal from
// automatic recovery. NOTE: the user-acknowledged path emits a
// recovery_acknowledged event INSTEAD of recovery_mode_exited (see
// the acknowledge endpoint) — this function is only used for the
// auto-exit paths.
function exitRecoveryMode(
  userId: string,
  reason: string,
  currentLevel: SecurityLevel,
  storage: IStorage,
): void {
  const existing = recoveryState.get(userId);
  if (!existing?.active) return;
  existing.active = false;
  recordAudit(storage, {
    userId,
    action: "recovery_mode_exited",
    ipAddress: null,
    userAgent: `reason=${reason}; level=${currentLevel}`,
  });
}

// Single source of truth consulted by both the response builders
// (fetch/audit/sessions) and the write blockers (sync/restore).
// LAZY auto-exit: every call evaluates the exit conditions and
// transitions to inactive if either condition holds. This keeps the
// state machine self-healing — no setInterval needed to drive exit.
//
// Auto-exit conditions (either triggers exit):
//   (a) "Clean" path — no recent anomaly within ANOMALY_RECENT_WINDOW_MS
//       AND no active soft lock. This is the T1 wording.
//   (b) "Backstop" path — recovery mode entered more than
//       RECOVERY_MAX_AGE_MS ago, regardless of state. This is the T7
//       fail-open guarantee that prevents sustained false-positives
//       from permanently locking a user out.
function isRecoveryModeActive(userId: string, storage: IStorage): boolean {
  const r = recoveryState.get(userId);
  if (!r?.active) return false;
  const now = Date.now();
  // Backstop FIRST so a stuck/looping signal can never defeat the
  // hard upper bound. If we evaluated the clean condition first and
  // an anomaly fired exactly at the backstop boundary, the backstop
  // would never apply.
  if (now - r.enteredAt > RECOVERY_MAX_AGE_MS) {
    exitRecoveryMode(
      userId,
      "auto_expired_max_age",
      deriveSecurityLevel(userId, null),
      storage,
    );
    return false;
  }
  const sec = userSecurityState.get(userId);
  const recentAnomaly =
    sec?.recentAnomalyAt !== undefined &&
    now - sec.recentAnomalyAt <= ANOMALY_RECENT_WINDOW_MS;
  const lockActive = getActiveSoftLock(userId) !== undefined;
  if (!recentAnomaly && !lockActive) {
    exitRecoveryMode(
      userId,
      "auto_expired_clean",
      deriveSecurityLevel(userId, null),
      storage,
    );
    return false;
  }
  return true;
}

// Visual canary signal for the frontend. 0–100 scale so the client can
// drive a single hue/animation parameter without having to translate
// our enum to a color ramp. Mapping per spec:
//   normal=0, elevated=30, high=60, critical=90; recoveryMode forces 100.
// Pure derivation from existing in-memory state — NO DB I/O on the
// hot path. Fail-open returns 0 (least alarming) if anything throws.
function getThreatLevel(
  userId: string,
  sessionId: string | null,
  storage: IStorage,
): number {
  try {
    if (isRecoveryModeActive(userId, storage)) return 100;
    const level = deriveSecurityLevel(userId, sessionId);
    switch (level) {
      case "normal":
        return 0;
      case "elevated":
        return 30;
      case "high":
        return 60;
      case "critical":
        return 90;
    }
  } catch {
    return 0;
  }
}

// Pure synchronous derivation. ALL inputs come from the in-memory
// userSecurityState Map populated by anomaly/soft-lock hooks. NO DB
// access, NO awaits — safe to call on the hot path. Fail-open: any
// error returns "normal" (the most permissive level).
function deriveSecurityLevel(
  userId: string,
  sessionId: string | null,
): SecurityLevel {
  try {
    // Order matters: highest-rank check FIRST so a soft-locked user
    // who is also flagged suspicious surfaces as "critical" (worst
    // case wins).
    if (getActiveSoftLock(userId) !== undefined) return "critical";
    const s = userSecurityState.get(userId);
    if (s && sessionId && s.suspiciousSessions.has(sessionId)) return "high";
    const recentAnomaly =
      s?.recentAnomalyAt !== undefined &&
      Date.now() - s.recentAnomalyAt <= ANOMALY_RECENT_WINDOW_MS;
    if (recentAnomaly) return "elevated";
    // Untrusted device → minimum "elevated". Stacks BELOW the
    // recentAnomaly check (same level) but ABOVE "normal" so a
    // freshly-logged-in unknown device shows up as elevated even
    // without any other signal. Per spec: untrusted should never
    // surface as "normal" — the user-facing client uses this to
    // gate the "trust this device?" prompt.
    if (s && sessionId && s.untrustedSessions.has(sessionId)) return "elevated";
    // T007 — Device-table untrusted (parallel signal to the per-
    // session sessions.trusted check above). Same "elevated" bump,
    // for the same reason: the user-facing client uses this to gate
    // the "trust this device?" prompt. Extends the anomaly logic;
    // does NOT override soft-lock / suspicious-session checks above
    // (worst-case-wins ordering is preserved by the early returns).
    if (
      s &&
      sessionId &&
      s.deviceUntrustedSessions?.has(sessionId)
    ) {
      return "elevated";
    }
    return "normal";
  } catch {
    return "normal";
  }
}

// Derive level, log transitions if any, return level for response.
// Transition logging is fire-and-forget through recordAudit (which
// already swallows errors) so it can never fail the request. Two
// audit events on a transition:
//
//   1. security_level_changed — fires on EVERY change (up or down) so
//      operators have a complete history. Reason field is fixed
//      "derived_state_change" since this is the only way levels move.
//   2. user_notified_security_state — fires ONLY on escalation
//      (rank increased). Skipped on downgrades to keep the audit log
//      readable: a soft-lock that expires triggers critical→normal,
//      which is good news the user doesn't need a banner for.
function evaluateSecurityLevel(
  userId: string,
  sessionId: string | null,
  ipAddress: string,
  storage: IStorage,
): SecurityLevel {
  const newLevel = deriveSecurityLevel(userId, sessionId);
  try {
    const stored = userSecurityLevelState.get(userId);
    const prev = stored?.currentLevel ?? "normal";
    if (prev !== newLevel) {
      userSecurityLevelState.set(userId, {
        currentLevel: newLevel,
        lastChangedAt: Date.now(),
      });
      recordAudit(storage, {
        userId,
        action: "security_level_changed",
        ipAddress,
        // Metadata stuffed in user_agent following the existing
        // anomaly_detected / write_blocked_soft_lock convention. Keeps
        // the audit schema unchanged.
        userAgent: `from=${prev}; to=${newLevel}; reason=derived_state_change`,
      });
      if (LEVEL_RANK[newLevel] > LEVEL_RANK[prev]) {
        recordAudit(storage, {
          userId,
          action: "user_notified_security_state",
          ipAddress,
          userAgent: `level=${newLevel}`,
        });
      }
      // Recovery Mode entry trigger (T1): enter when the level
      // TRANSITIONS to "critical" — i.e. fires once on the rising
      // edge, not on every subsequent critical-level request.
      // enterRecoveryMode is itself idempotent so a stray double-call
      // is harmless. We deliberately gate this on the prev !== newLevel
      // branch so a normal "still critical" request doesn't keep
      // reawakening recovery mode after the user acknowledged.
      if (newLevel === "critical" && prev !== "critical") {
        enterRecoveryMode(
          userId,
          "transition_to_critical",
          prev,
          newLevel,
          storage,
        );
      }
    }
  } catch {
    // Transition logging is purely diagnostic. A failure here must
    // NOT block the response — newLevel was already computed above.
  }
  return newLevel;
}

// ---------------------------------------------------------------------------
// Lazy hydration of in-memory security state from the audit log
// ---------------------------------------------------------------------------
//
// Problem: all the security state (recentAnomalyAt, softLockedUntil,
// suspiciousSessions, currentLevel) lives ONLY in memory. A server
// restart wipes it, which would let an attacker downgrade their
// securityLevel ("critical" → "normal") simply by waiting for / causing
// a process bounce. Spec requires the level to remain consistent
// across restarts.
//
// Solution: on the first authenticated request per user after a fresh
// process start, reconstruct what we can from the audit log (last 10
// minutes only — beyond that the signal naturally decays anyway). This
// is LAZY: only active users pay the cost; cold-start does not scan
// every user.
//
// All hot-path constraints still hold:
//   - Hydration is gated on "is this user's in-memory state empty?";
//     a single check on the userSecurityState Map. Once populated,
//     no further DB I/O for the lifetime of that process's entry.
//   - The hydration query is bounded (limit 100, indexed by user_id +
//     created_at) and runs at most ONCE per user per process.
//   - Live signals (real-time anomaly hooks) ALWAYS win — hydration
//     never overwrites a field that was set by a live event.
//   - Wrapped in try/catch with fail-open semantics — any error
//     (DB unreachable, malformed metadata, etc.) silently leaves the
//     state empty rather than blocking authentication.

// Maximum age of audit entries used to reconstruct state. Matches the
// existing ANOMALY_RECENT_WINDOW_MS so a hydrated state cannot
// surface as "elevated" longer than a live state could have.
const HYDRATION_LOOKBACK_MS = ANOMALY_RECENT_WINDOW_MS;

// Parse "blockedUntil=<epoch-ms>" out of a userAgent-stuffed audit
// metadata string. Returns undefined on any parse failure (the loose
// metadata format is best-effort by design — see write_blocked_soft_lock
// recordAudit calls). Strict numeric parse: must be a finite number.
function parseBlockedUntilFromMetadata(meta: string | null): number | undefined {
  if (!meta) return undefined;
  try {
    const m = meta.match(/blockedUntil=(\d+)/);
    if (!m) return undefined;
    const n = Number(m[1]);
    return Number.isFinite(n) ? n : undefined;
  } catch {
    return undefined;
  }
}

// Reconstruct the recent-window security signals for one user from
// the audit log. Returns a tagged result the caller MERGES into live
// state (never overwriting fields that already have live values).
//
// Failure mode: any error (DB unreachable, schema drift, parse error)
// returns an empty result. The caller continues without hydration —
// the user simply starts at "normal" and live signals will populate
// state from the next anomaly forward.
async function hydrateSecurityStateFromAudit(
  userId: string,
  storage: IStorage,
): Promise<{
  recentAnomalyAt?: number;
  softLockedUntil?: number;
  hadAnomaly: boolean;
}> {
  try {
    // getAuditLog already returns newest-first. The DB-side index is
    // (user_id, created_at desc), so this is a single index scan
    // returning at most 100 rows.
    const rows = await storage.getAuditLog(userId, 100);
    const cutoff = Date.now() - HYDRATION_LOOKBACK_MS;
    let recentAnomalyAt: number | undefined;
    let softLockedUntil: number | undefined;
    let hadAnomaly = false;
    // T004 hardening: also re-derive the passkey-failure streak so
    // the burst escalation survives a process restart. Without
    // this, an attacker could drop a few failures right before a
    // restart and have the in-memory counter wiped, getting an
    // extra full window's worth of attempts before the burst
    // threshold trips.
    let passkeyFailuresInWindow = 0;
    let oldestPasskeyFailureInWindowAt: number | undefined;
    const passkeyFailureCutoff = Date.now() - PASSKEY_FAILURE_WINDOW_MS;
    for (const r of rows) {
      // Newest-first traversal — we can stop the moment we leave the
      // 10-min window (rows are strictly ordered by createdAt desc).
      if (r.createdAt < cutoff) break;
      if (
        r.action === "anomaly_detected" ||
        r.action === "write_blocked_soft_lock"
      ) {
        // Take the FIRST (= newest) timestamp we see — preserves the
        // "most recent anomaly" semantics that recentAnomalyAt has on
        // the live path.
        if (recentAnomalyAt === undefined) recentAnomalyAt = r.createdAt;
      }
      if (r.action === "anomaly_detected") {
        hadAnomaly = true;
      }
      if (r.action === "write_blocked_soft_lock") {
        // Prefer the explicit blockedUntil timestamp from metadata
        // (always present on entries created by recordSecuritySignalHit
        // since the prior task). If missing or unparseable, fall back
        // to event_time + SOFT_LOCK_DURATION_MS — the 5-min lock is
        // fixed so this approximation matches what the live path
        // would have computed at the time of the event.
        const fromMeta = parseBlockedUntilFromMetadata(r.userAgent);
        const candidate = fromMeta ?? r.createdAt + SOFT_LOCK_DURATION_MS;
        // Take the LATEST candidate — if multiple lock events, the
        // newest is the one that's still relevant.
        softLockedUntil = Math.max(softLockedUntil ?? 0, candidate);
      }
      // T004 hardening: passkey-side failure rows in the streak
      // window. Counts ONLY actual failure events (not _success
      // or _required_for_write); newest-first so the OLDEST in-
      // window failure timestamp is the LAST one we see in this
      // branch — used as the reconstructed windowStart.
      if (
        (r.action === "passkey_login_failure" ||
          r.action === "passkey_step_up_failure") &&
        r.createdAt >= passkeyFailureCutoff
      ) {
        passkeyFailuresInWindow++;
        oldestPasskeyFailureInWindowAt = r.createdAt;
      }
    }
    // T004 hardening: seed the in-memory passkey failure streak
    // ONLY if the live path hasn't already populated it during the
    // restart-grace window. Live state is always more authoritative
    // (per project rule) — the audit-derived value is a
    // best-effort restoration of state that would otherwise be
    // entirely lost. burstLogged is reconstructed strictly from
    // count-vs-threshold so a streak that already crossed the
    // burst line stays "burst-acknowledged" and doesn't re-fire
    // an anomaly_detected the moment a sixth failure arrives.
    if (
      passkeyFailuresInWindow > 0 &&
      oldestPasskeyFailureInWindowAt !== undefined &&
      !passkeyFailureState.has(userId)
    ) {
      passkeyFailureState.set(userId, {
        windowStart: oldestPasskeyFailureInWindowAt,
        count: passkeyFailuresInWindow,
        burstLogged: passkeyFailuresInWindow > PASSKEY_FAILURE_THRESHOLD,
        lastTouchedAt: Date.now(),
      });
    }
    return { recentAnomalyAt, softLockedUntil, hadAnomaly };
  } catch {
    return { hadAnomaly: false };
  }
}

// In-flight hydration promises, keyed by userId. Concurrent auths for
// the same user post-restart all AWAIT THE SAME PROMISE so every one
// of them observes the post-hydration state — preventing a transient
// "normal" response from a request that arrived during another
// request's audit query. The promise is removed from this map in a
// .finally() once it settles (success OR failure), so subsequent
// requests can re-attempt only if hydratedAt is still unset (e.g.
// the previous attempt failed and the slot is still empty).
const inflightHydrations = new Map<string, Promise<void>>();

// Idempotent gate around hydrateSecurityStateFromAudit. Called from
// authenticate() after a successful auth. The gate has THREE purposes:
//
//   1. Steady-state short-circuit: once hydratedAt is stamped on the
//      slot, NEVER hydrate again for the lifetime of this Map entry
//      (per spec: "Live signals are always more accurate than
//      reconstructed ones — DO NOT rehydrate"). One Map lookup; zero
//      DB I/O. This is the hot path after the first auth per user.
//
//   2. Race protection (single-shot): concurrent auths for the same
//      user could both observe "state missing" and both kick off a
//      hydration query. inflightHydrations[userId] holds the pending
//      promise so concurrent callers AWAIT THE SAME hydration —
//      every concurrent first-after-restart auth gets the
//      post-hydration state, not a transient "normal" view.
//
//   3. Bounded retry: if a hydration attempt FAILS (DB unreachable,
//      etc.), the slot stays without hydratedAt and the in-flight
//      entry is cleared via .finally(). The NEXT auth gets to retry
//      hydration. Each successful hydration runs at most once per
//      Map-entry lifetime (Map entry is GC'd after 1h inactivity, at
//      which point a future auth re-hydrates from scratch — the only
//      way the hydration count exceeds 1 per user per process).
//
// Fail-open: the inner async fn itself catches all errors and
// resolves successfully. authenticate() additionally wraps this call
// in its own try/catch as belt-and-suspenders.
async function hydrateIfNeeded(
  userId: string,
  sessionId: string | null,
  storage: IStorage,
): Promise<void> {
  // Fast path: already hydrated for this user (and the slot hasn't
  // been GC'd). The TTL GC runs on inactivity, so this short-circuit
  // covers the vast majority of post-first-auth requests with a
  // single Map lookup.
  if (userSecurityState.get(userId)?.hydratedAt !== undefined) return;
  // If a hydration is already in flight for this user, await it —
  // every concurrent first-auth observes the same outcome.
  let p = inflightHydrations.get(userId);
  if (!p) {
    p = (async () => {
      // Reserve the slot synchronously inside the promise body so
      // live events that fire during the audit query mutate THIS
      // entry; the merge below preserves any live writes by only
      // populating still-undefined fields.
      const slot = getOrInitSecurityState(userId);
      try {
        const result = await hydrateSecurityStateFromAudit(userId, storage);
        // Merge with "live wins" semantics. Each field is only written
        // when the live path hasn't already populated it during the
        // await window above.
        if (
          slot.recentAnomalyAt === undefined &&
          result.recentAnomalyAt !== undefined
        ) {
          slot.recentAnomalyAt = result.recentAnomalyAt;
        }
        if (
          slot.softLockedUntil === undefined &&
          result.softLockedUntil !== undefined
        ) {
          // Note: getActiveSoftLock auto-clears expired locks on read,
          // so setting a past-expired value here is harmless — it
          // just gets cleared on the next access.
          slot.softLockedUntil = result.softLockedUntil;
        }
        if (result.hadAnomaly && sessionId) {
          // Per spec: "if any anomaly_detected exists → treat as true
          // (fail-open safe assumption)". We don't know which session
          // was suspicious before the restart, so we conservatively
          // flag the CURRENT authenticating session. Worst case: a
          // user who logged in fresh just after a restart sees one
          // elevated request and can rotate the session; better than
          // missing a real attacker who reauthenticated after restart.
          slot.suspiciousSessions.add(sessionId);
        }
        // Stamp hydratedAt LAST — its presence is the marker that
        // future hydrateIfNeeded calls use to fast-path. Setting it
        // only on the success path means a failed hydration leaves
        // hydratedAt undefined and the next auth retries.
        slot.hydratedAt = Date.now();
        // Seed userSecurityLevelState with the derived level so the
        // first evaluateSecurityLevel call after this hydration does
        // NOT emit a misleading "from=normal; to=critical" transition
        // row (the user was already critical before the restart).
        // Only seed if a level isn't already recorded — a live
        // transition that happened during the await window must not
        // be clobbered.
        if (!userSecurityLevelState.has(userId)) {
          const derived = deriveSecurityLevel(userId, sessionId);
          userSecurityLevelState.set(userId, {
            currentLevel: derived,
            lastChangedAt: Date.now(),
          });
          // Recovery Mode hydration hook (T7): re-enter recovery
          // mode if-and-only-if the audit log showed a real anomaly
          // AND the reconstructed level lands at "critical". This is
          // the deliberate, conditional re-entry pathway documented
          // in the recovery-mode header — without it an attacker
          // could downgrade out of recovery just by waiting for /
          // causing a process restart. The acknowledge endpoint and
          // 15-min auto-expire backstop still apply, so the user is
          // never permanently trapped (T7 fail-open).
          //
          // We seed the userSecurityLevelState above with `derived`,
          // which means the FIRST evaluateSecurityLevel call after
          // hydration sees prev===newLevel===critical and DOES NOT
          // fire enterRecoveryMode via the transition path — so this
          // is the only place hydration-driven recovery entry can
          // happen. (Without this branch, post-restart users would
          // see securityLevel=critical but recoveryMode=false, which
          // is the regression the spec is closing.)
          if (result.hadAnomaly && derived === "critical") {
            enterRecoveryMode(
              userId,
              "hydrated_after_restart",
              "normal",
              derived,
              storage,
            );
          }
        }
      } catch {
        // Fail-open: hydration is purely diagnostic. The slot stays
        // (mostly) empty; live events from here forward populate it
        // correctly. hydratedAt stays undefined so a future auth can
        // retry hydration if the underlying issue clears.
      }
    })().finally(() => {
      // Whether success or failure, drop the in-flight entry so
      // future auths can retry (success path's hydratedAt stamp
      // already short-circuits, so retry only fires on failure).
      inflightHydrations.delete(userId);
    });
    inflightHydrations.set(userId, p);
  }
  await p;
}

// ---------------------------------------------------------------------------
// Audit log fire-and-forget wrapper
// ---------------------------------------------------------------------------
//
// All audit-log writes go through this helper. Two reasons to wrap it
// rather than calling storage.logAuditEvent directly:
//   1. The .catch() is belt-and-suspenders — storage.logAuditEvent
//      already swallows its own errors, but if a future refactor
//      removes that try/catch we don't want a stray rejection to
//      crash the request handler.
//   2. The helper is synchronous from the caller's perspective: it
//      kicks off the async insert and returns immediately. Callers
//      can do `recordAudit(...); return res.json(...);` and not
//      worry about awaiting the audit insert before responding.
//
// Critical: never put encrypted blob contents, auth_hash, session
// token, or any other secret into `input`. The audit log is read
// back wholesale by GET /api/vault/audit, so anything that lands
// here becomes user-visible.
// T009 hardening: opt-in dedupe for HIGH-VOLUME PROBE actions only.
// An attacker can otherwise spam the audit_log table by repeatedly
// firing the same failure path (e.g. /api/passkeys/login/start with a
// known username from a botnet) — within a single minute that becomes
// thousands of identical rows that drown out other security signals.
//
// Per-(user, action, minute) bucket: the FIRST event in a minute is
// always written; subsequent events with the same key inside the
// SAME minute are dropped at the recordAudit boundary. The minute
// boundary is wall-clock floor(Date.now()/60_000) so the bucket
// rolls over naturally with no extra timer.
//
// Opt-IN by allowlist (not opt-out) so any new audit action added in
// future MUST be explicitly added to this set to be dedupable. This
// is deliberate: silently suppressing security events is more
// dangerous than a few duplicates in the table. Critical actions
// (security_level_changed, recovery_*, session_created, vault_sync,
// vault_restore, passkey_registered, passkey_revoked,
// passkey_counter_replay_detected, anomaly_detected, etc.) are NOT
// in this set and continue to write every time.
const DEDUPABLE_AUDIT_ACTIONS: ReadonlySet<string> = new Set([
  "passkey_login_failure",
  "passkey_step_up_failure",
  "totp_required",
  "totp_required_for_write",
  "passkey_required_for_write",
  "write_blocked_soft_lock",
  "ip_change_detected",
  "device_mismatch",
  "untrusted_device_blocked",
  "new_device_detected",
  // login_failed is dedupable but uses an IP-aware key (see
  // shouldRecordAuditEvent below) so an attacker who rotates
  // through many IPs against the same victim still leaves a
  // distinct row per (user, ip, minute) — preserving the signal
  // a per-user-only dedup would erase. Spec requirement: dedupe
  // per (userId OR username) + IP + 60-second window.
  "login_failed",
]);

const auditDedupeBuckets = new Map<string, number>();
const AUDIT_DEDUPE_GC_INTERVAL_MS = 5 * 60_000;
const AUDIT_DEDUPE_MAX_AGE_MINUTES = 5;

if (!RATE_LIMIT_DISABLED) {
  setInterval(() => {
    const cutoff = Math.floor(Date.now() / 60_000) - AUDIT_DEDUPE_MAX_AGE_MINUTES;
    for (const [k, minute] of auditDedupeBuckets) {
      if (minute < cutoff) auditDedupeBuckets.delete(k);
    }
  }, AUDIT_DEDUPE_GC_INTERVAL_MS);
}

function shouldRecordAuditEvent(input: AuditEventInput): boolean {
  if (!DEDUPABLE_AUDIT_ACTIONS.has(input.action)) return true;
  // userId may be optional for some event shapes; treat absence as
  // "always record" to avoid coalescing distinct anonymous events.
  const userKey = input.userId ?? "_";
  const minute = Math.floor(Date.now() / 60_000);
  // login_failed dedup is per-(user, ip, minute) so a distributed
  // brute-force from many IPs against the same account still yields
  // a row per attacker-IP per minute. All other dedupable actions
  // collapse to a single row per (user, action, minute), which is
  // the right granularity for those signals (a UA flap or device-
  // mismatch flap should not flood the table).
  const key =
    input.action === "login_failed"
      ? `${userKey}:login_failed:${input.ipAddress ?? "_"}:${minute}`
      : `${userKey}:${input.action}:${minute}`;
  if (auditDedupeBuckets.has(key)) return false;
  auditDedupeBuckets.set(key, minute);
  return true;
}

function recordAudit(storage: IStorage, input: AuditEventInput): void {
  if (!shouldRecordAuditEvent(input)) {
    // Suppressed by dedupe; intentional no-op. The first event in
    // this (user, action, minute) bucket already wrote, so an
    // operator reading the audit log still sees the signal.
    return;
  }
  storage.logAuditEvent(input).catch(() => {
    // Errors are already logged inside storage.logAuditEvent. The
    // additional .catch() here is just to absorb any rejection so it
    // can't surface as an unhandled promise rejection.
  });
}

// T007 hardening: uniform random delay before LOGIN responses (both
// success and failure, both password and passkey paths). Defends
// against timing oracles that could otherwise distinguish:
//   - "user exists vs not" (DB lookup latency, dummy-salt latency)
//   - "credential valid vs not" (verifier latency, counter-update
//      DB latency)
// The existing dummy-PBKDF2 (hashForComparison on the not-found
// branch) equalizes the heavy-crypto cost; this delay further
// drowns out the lighter timing differences left over.
//
// 50-120ms is a small enough range to be invisible to a real user
// but large enough to swamp typical inter-branch nanosecond
// differences. Math.random is fine here — this is anti-timing
// noise, not a security secret.
async function uniformLoginDelay(): Promise<void> {
  const ms = 50 + Math.floor(Math.random() * 71);
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}

// Result of authenticating a request via either session token (preferred)
// or legacy x-auth-hash. `sessionId` is populated only when the request
// authenticated via a session token — a logout endpoint can use this to
// know which session row to delete. The "401 vs 400" split lives here so
// every authenticated route returns consistent responses; see comments
// inside authenticate() for why.
type AuthResult =
  | {
      ok: true;
      userId: string;
      sessionId: string | null;
      // Mirror of sessions.totpVerifiedUntil for the authenticated session,
      // so write-path step-up gates can decide "is this session 2FA-fresh?"
      // without re-querying the DB. NULL on the legacy auth-hash path
      // (no session row) and on a session that has never stepped up.
      totpVerifiedUntil: number | null;
    }
  | { ok: false; status: 400 | 401; error: string };

// Single source of truth for vault-endpoint authentication. Combines:
//   - Header shape validation (400 on malformed headers — same single
//     "Invalid authentication headers" message regardless of which header
//     went wrong, so a probe cannot fingerprint the missing piece).
//   - Session-token lookup (preferred path): hashes the token, looks up
//     a non-expired row, and touches last_seen_at. Invalid OR expired
//     tokens collapse to a single 401 — never tell the attacker which.
//   - Legacy auth-hash lookup: timing-safe compare against stored hash;
//     unknown user collapses to the same 401 as wrong password.
//
// On success, the route handler gets a verified userId and (for the
// session path) the sessionId so it can pass it to logout endpoints.
async function authenticate(
  req: Request,
  storage: IStorage,
): Promise<AuthResult> {
  const headers = validateAuthHeaders(req);
  if (!headers.ok) return { ok: false, status: 400, error: headers.error };

  if (headers.data.kind === "session") {
    // SHA-256 the raw token before any DB I/O. The DB only ever sees the
    // hash; the raw token never touches the storage layer.
    const tokenHash = createHash("sha256")
      .update(headers.data.token)
      .digest("hex");
    const session = await storage.getActiveSessionByTokenHash(tokenHash);
    if (!session) {
      // Per spec: invalid and expired must be indistinguishable. The
      // active-only filter inside getActiveSessionByTokenHash already
      // collapses both branches into a single "no row" result.
      return { ok: false, status: 401, error: "Invalid credentials" };
    }
    // Best-effort touch — failing this should NOT fail the request.
    // If the DB is briefly unavailable for the UPDATE we still want the
    // user to be able to read their vault. Caught locally and logged.
    try {
      await storage.touchSession(session.id, Date.now());
    } catch (err) {
      console.error("touchSession failed");
    }
    // T003 hardening: compare the current request's (ip, ua) to the
    // values the session row was minted with. On drift, mark the
    // session suspicious + paint the security signal + emit a
    // dedup-aware audit row. Wrapped in try/catch so a failure here
    // (e.g. transient DB issue inside markSessionSuspicious)
    // CANNOT block the user's request — fail-open per the project's
    // standing rule for system errors on the auth hot path.
    try {
      checkSessionBindingDrift(
        storage,
        session,
        getClientIp(req),
        captureUserAgent(req),
      );
    } catch (err) {
      console.error("checkSessionBindingDrift failed");
    }
    // Lazy hydration of security state from audit log. Only fires
    // ONCE per user per process — subsequent auths short-circuit on
    // the in-memory map check. Wrapped in try/catch on top of the
    // function's own fail-open guarantee (belt + suspenders) so a
    // hydration failure can never block auth.
    try {
      await hydrateIfNeeded(session.userId, session.id, storage);
    } catch {
      // Already swallowed inside hydrateIfNeeded; this is defense in depth.
    }
    // Populate the in-memory untrusted-session cache from the DB row.
    // The DB column is the source of truth (set at session-creation
    // time, flipped only by /api/auth/trust-device); we mirror it into
    // the Set here so the synchronous hot-path checks (sync/restore
    // 403, deriveSecurityLevel) don't need an extra DB read. Both
    // branches must run on every authenticate so a session that gets
    // trusted between requests transitions correctly without waiting
    // for the next process restart to clear stale state.
    if (session.trusted === true) {
      clearUntrustedSession(session.userId, session.id);
    } else {
      recordUntrustedSession(session.userId, session.id);
    }
    // T004 — trusted_devices ledger upsert. Runs AFTER session
    // validation + binding-drift check so the device-fingerprint we
    // commit reflects this REQUEST (not the session's birth context),
    // which is the right behavior for a "where has this user been
    // signing in from?" management view. Wrapped in try/catch:
    // device tracking is observability + a soft input to the security
    // level, NEVER load-bearing for auth correctness — a transient
    // DB error MUST NOT block the user's actual request.
    try {
      const fp = deriveDeviceFingerprint(
        getClientIp(req),
        captureUserAgent(req),
      );
      const upsert = await storage.createOrUpdateDevice({
        userId: session.userId,
        deviceFingerprint: fp,
        now: Date.now(),
      });
      // Device-table trust signal mirrored into the in-memory cache so
      // deriveSecurityLevel can consult it synchronously. Both
      // branches run on every authenticate so a device freshly
      // trusted via /api/security/device/trust is reflected on the
      // very next request without waiting for process restart.
      if (upsert.row.trusted === true) {
        clearDeviceUntrustedSession(session.userId, session.id);
      } else {
        recordDeviceUntrustedSession(session.userId, session.id);
      }
      // First-sighting audit. The new_device_detected action is
      // already in DEDUPABLE_AUDIT_ACTIONS so a flapping client can't
      // flood the log; we still gate on `upsert.created` here so a
      // steady-state ping doesn't even attempt to log.
      if (upsert.created) {
        recordAudit(storage, {
          userId: session.userId,
          action: "new_device_detected",
          ipAddress: getClientIp(req),
          // Truncated fingerprint for cross-referencing with
          // /api/security/devices entries — same convention as the
          // existing trust-device / login paths.
          userAgent: appendInstallIdMetadata(
            req,
            `fingerprint=${fp.slice(0, 16)}`,
          ),
        });
      }
    } catch (err) {
      console.error("createOrUpdateDevice failed");
    }
    return {
      ok: true,
      userId: session.userId,
      sessionId: session.id,
      totpVerifiedUntil: session.totpVerifiedUntil ?? null,
    };
  }

  const { userId, authHash } = headers.data;
  const user = await storage.getUser(userId);
  if (!user) {
    // Same defense-in-depth collapse as the existing legacy code path.
    return { ok: false, status: 401, error: "Invalid credentials" };
  }
  const providedHash = hashForComparison(authHash);
  const storedHash = Buffer.from(user.authHash, "hex");
  if (
    providedHash.length !== storedHash.length ||
    !timingSafeEqual(providedHash, storedHash)
  ) {
    return { ok: false, status: 401, error: "Invalid credentials" };
  }
  // Same lazy hydration on the legacy auth-hash path. sessionId is
  // null here so suspicious-session reconstruction is skipped, but
  // the user-level signals (recentAnomalyAt, softLockedUntil) still
  // get rebuilt — the legacy path can still surface "elevated" or
  // "critical" after restart from those signals alone.
  try {
    await hydrateIfNeeded(userId, null, storage);
  } catch {
    // Already swallowed inside hydrateIfNeeded.
  }
  return { ok: true, userId, sessionId: null, totpVerifiedUntil: null };
}

// Truncate user-agent so a malicious or misbehaving client cannot bloat
// the sessions table by sending a multi-megabyte UA string. 512 bytes is
// well above any real browser/native UA (~200 bytes typical).
const USER_AGENT_MAX_BYTES = 512;
function captureUserAgent(req: Request): string | null {
  const raw = req.headers["user-agent"];
  if (typeof raw !== "string") return null;
  if (raw.length === 0) return null;
  return raw.length > USER_AGENT_MAX_BYTES
    ? raw.slice(0, USER_AGENT_MAX_BYTES)
    : raw;
}

function appendInstallIdMetadata(
  req: Request,
  metadata: string | null,
): string | null {
  const installId = getOptionalInstallId(req);
  if (!installId) return metadata;

  const installMeta = `installId=${installId}`;
  if (!metadata) return installMeta;

  const separator = "; ";
  const maxMetadataLength =
    USER_AGENT_MAX_BYTES - separator.length - installMeta.length;
  const safeMetadata =
    metadata.length > maxMetadataLength
      ? metadata.slice(0, maxMetadataLength)
      : metadata;
  return `${safeMetadata}${separator}${installMeta}`;
}

function captureAuditUserAgent(req: Request): string | null {
  return appendInstallIdMetadata(req, captureUserAgent(req));
}

type VersionConflictResponse = {
  error: "Version conflict";
  serverVersion: number;
};

function versionConflictResponse(serverVersion: number): VersionConflictResponse {
  return { error: "Version conflict", serverVersion };
}

export async function registerRoutes(app: Express, storage: IStorage): Promise<Server> {

  app.post("/api/auth/register", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const clientIp = getClientIp(req);
      if (isRateLimited(`register:${clientIp}`)) {
        return res.status(429).json({ error: "Too many attempts. Please try again later." });
      }

      const parsed = validateRegister(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const { username, authHash, salt, iterations } = parsed.data;

      const existing = await storage.getUserByUsername(username);
      if (existing) {
        return res.status(409).json({ error: "Username already taken" });
      }

      const storedAuthHash = createHash("sha256").update(authHash).digest("hex");
      const user = await storage.createUser({ username, authHash: storedAuthHash, salt, iterations });

      return res.status(201).json({
        id: user.id,
        username: user.username,
        salt: user.salt,
        iterations: user.iterations,
      });
    } catch (err) {
      const e = err as { code?: string; constraint?: string };
      if (e?.code === "23505") {
        return res.status(409).json({ error: "Username already taken" });
      }
      console.error("Register error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/auth/login", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const clientIp = getClientIp(req);
      if (isRateLimited(`login:${clientIp}`)) {
        return res.status(429).json({ error: "Too many attempts. Please try again later." });
      }
      // Adaptive IP threat block: if recent failures from this IP
      // crossed the brute-force or credential-stuffing threshold,
      // refuse further attempts for IP_THREAT_BLOCK_MS regardless
      // of which login endpoint they target. Single-shape 429 with
      // the same wording the rate-limiter above uses, so an
      // attacker can't tell which gate fired. Adaptive delay before
      // the response keeps the timing oracle closed.
      if (isIpBlocked(clientIp)) {
        return await ipBlockResponse(res, clientIp);
      }

      const parsed = validateLogin(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      // T007 hardening: uniform random delay BEFORE the auth-result
      // work. Every subsequent return path (not-found 401, wrong-hash
      // 401, TOTP-required 200, success 200) inherits the same
      // 50-120ms baseline noise, which swamps the sub-millisecond
      // branch-time differences (DB lookup vs cached miss, dummy
      // hash vs real compare) that could otherwise be measured by a
      // username-enumeration probe. The 429 + 400 paths above are
      // intentionally NOT delayed — they don't leak user existence.
      // Failure paths additionally apply adaptiveLoginDelay(clientIp)
      // before responding, which adds per-failure-count friction.
      await uniformLoginDelay();

      const { username, authHash } = parsed.data;

      const user = await storage.getUserByUsername(username);
      if (!user) {
        hashForComparison(authHash);
        // Adaptive IP threat: count this not-found probe toward the
        // credential-stuffing cardinality (distinct usernames probed
        // from one IP). We hash the username before storing — raw
        // usernames never enter process memory. No userId to attach
        // an audit row to (and a not-found audit would itself be a
        // username-enumeration oracle), so realUserId=null.
        recordIpFailure(
          storage,
          clientIp,
          hashUsernameForIpThreat(username),
          null,
        );
        await adaptiveLoginDelay(clientIp);
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = Buffer.from(user.authHash, "hex");

      if (providedHash.length !== storedHash.length || !timingSafeEqual(providedHash, storedHash)) {
        // Audit visibility: emit a generic login_failed row so the
        // legitimate user sees the probe in their activity log,
        // even though the response is the same generic 401 the
        // not-found branch returns. The audit row is keyed under
        // the REAL userId (we just confirmed the username exists
        // and the password didn't match) — anyone reading their
        // own log learns "someone tried my account from <ip>".
        // Dedup is per (user, ip, minute) via shouldRecordAuditEvent
        // so a high-volume guess from one IP is one row per minute,
        // while a distributed attempt across many IPs leaves a
        // distinct row per attacker.
        recordAudit(storage, {
          userId: user.id,
          action: "login_failed",
          ipAddress: clientIp,
          userAgent: `reason=invalid_credentials; ua=${(captureUserAgent(req) ?? "").slice(0, 200)}`,
        });
        // Burst tracker: 6th failure inside a 5-min window escalates
        // via the existing security-signal pipeline (anomaly_detected
        // audit + recordSecuritySignalHit). hardLock=false because
        // this is the unauthenticated path — an attacker who knows
        // a victim username + can rotate IPs could otherwise soft-
        // lock the legitimate user's writes (DoS vector).
        const burst = recordLoginFailure(user.id);
        if (burst.burstMeta) {
          escalatePasskeyAnomaly(
            storage,
            user.id,
            null,
            clientIp,
            `${burst.burstMeta}; source=password_login`,
            { hardLock: false },
          );
        }
        // Adaptive IP threat: count this real-user wrong-password
        // failure toward both the brute-force threshold (≥10
        // failures from this IP) and the credential-stuffing
        // cardinality (this user contributes 1 distinct target).
        // Real userId so the ip_threat_detected audit row, if it
        // fires here, is attached to this user.
        recordIpFailure(storage, clientIp, user.id, user.id);
        await adaptiveLoginDelay(clientIp);
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // TOTP gate: if 2FA is enabled, the password phase is NOT
      // sufficient to mint a session. Issue a short-lived temp token
      // instead and require the client to call /api/auth/totp/login
      // with the current 6-digit code. We deliberately do NOT create
      // a session row here — a half-authenticated session would be
      // indistinguishable from a real one once persisted, which would
      // defeat 2FA. The temp token is held only in memory.
      //
      // We DO emit an audit row so a user reading their activity log
      // sees "someone passed my password and was prompted for 2FA" —
      // useful as a credential-leak early warning even on the path
      // where the attacker has the password but not the second factor.
      if (user.totpEnabled === true) {
        const rawTempToken = randomBytes(32).toString("hex");
        const tempTokenHash = createHash("sha256")
          .update(rawTempToken)
          .digest("hex");
        tempLoginTokens.set(tempTokenHash, {
          tokenHash: tempTokenHash,
          userId: user.id,
          expiresAt: Date.now() + TEMP_LOGIN_TTL_MS,
        });
        recordAudit(storage, {
          userId: user.id,
          action: "totp_required",
          ipAddress: getClientIp(req),
          userAgent: captureUserAgent(req),
        });
        // Existing fields (id/username/salt/iterations) are preserved so
        // a client doing client-side KDF derivation can still proceed
        // (the same data was already public via /api/auth/salt). The
        // ABSENCE of sessionToken is the signal to the client that 2FA
        // is required — alongside the explicit requiresTOTP flag.
        return res.status(200).json({
          id: user.id,
          username: user.username,
          salt: user.salt,
          iterations: user.iterations,
          requiresTOTP: true,
          tempToken: rawTempToken,
          tempTokenExpiresAt: Date.now() + TEMP_LOGIN_TTL_MS,
        });
      }

      // Issue a fresh session: 32 random bytes (256 bits of entropy) hex-
      // encoded for transport. We persist ONLY the SHA-256 hash so a
      // database leak cannot impersonate the user — the raw token is shown
      // to the client exactly once, in this response, and never again.
      const rawToken = randomBytes(32).toString("hex");
      const tokenHash = createHash("sha256").update(rawToken).digest("hex");
      // Device-trust decision happens HERE, BEFORE createSession, so the
      // resulting row is correctly stamped trusted=true|false at insert
      // time. We look the fingerprint up against this user's existing
      // sessions: if we've ever seen this device for this account, it's
      // trusted automatically; otherwise it lands as untrusted and the
      // user has to approve it via POST /api/auth/trust-device before
      // sync/restore unlock.
      const deviceFingerprint = getDeviceFingerprint(req);
      const isKnownDevice = await storage.hasDeviceFingerprintForUser(
        user.id,
        deviceFingerprint,
      );
      const session = await storage.createSession({
        userId: user.id,
        tokenHash,
        expiresAt: Date.now() + SESSION_LIFETIME_MS,
        userAgent: captureUserAgent(req),
        ipAddress: getClientIp(req),
        deviceFingerprint,
        trusted: isKnownDevice,
      });

      // Audit hooks AFTER successful auth + session creation. Two
      // separate events per spec: login_success (the credential
      // exchange) and session_created (a new server-side session row).
      // Both fire-and-forget — the response is sent regardless.
      const ip = getClientIp(req);
      const userAgent = captureAuditUserAgent(req);
      recordAudit(storage, {
        userId: user.id,
        action: "login_success",
        ipAddress: ip,
        userAgent,
      });
      recordAudit(storage, {
        userId: user.id,
        action: "session_created",
        ipAddress: ip,
        userAgent,
      });
      // Decay (not full-reset) the login-failure burst counter on a
      // clean success — same reasoning as decayPasskeyFailures: a
      // single successful login should NOT erase a 5-attempt streak
      // that came before it (an attacker who stumbles on the right
      // password after 4 wrong guesses still leaves a partial trail).
      decayLoginFailures(user.id);
      // Adaptive IP threat decay (T008): a clean success from this
      // IP knocks IP_THREAT_DECAY_PER_SUCCESS off its accumulated
      // failure count. If the count reaches zero and there's no
      // active block, the entry is dropped entirely so a one-off
      // fat-finger streak followed by a real login doesn't leave
      // adaptive friction lingering on a benign IP.
      recordIpSuccess(ip);
      // New-device path: log the event AND raise the in-memory threat
      // signal so the very first request after login (the client's
      // initial /api/vault/fetch) already sees securityLevel=elevated.
      // We deliberately do NOT call triggerSoftLock — a brand-new
      // device is not necessarily an attack, and locking writes for
      // the legitimate user installing on a second phone would be
      // user-hostile. The 403 on sync/restore (gated below) is the
      // proper enforcement; recordSecuritySignalHit just paints the
      // UI banner. flagSession=false on purpose: untrusted is a
      // PER-DEVICE signal, not a per-session anomaly flag.
      if (!isKnownDevice) {
        recordAudit(storage, {
          userId: user.id,
          action: "new_device_detected",
          ipAddress: ip,
          // Stash the fingerprint hash in user_agent (same convention
          // as anomaly_detected) so an operator reading the audit log
          // can correlate this row with the specific session row by
          // joining on sessions.device_fingerprint.
          userAgent: appendInstallIdMetadata(
            req,
            `fingerprint=${deviceFingerprint.slice(0, 16)}`,
          ),
        });
        recordSecuritySignalHit(user.id, session.id, false);
        recordUntrustedSession(user.id, session.id);
      }

      // Existing fields are preserved for backward compatibility — clients
      // that have not yet adopted session tokens continue to receive
      // id/username/salt/iterations exactly as before. New clients pick up
      // sessionToken + sessionExpiresAt and switch to the token-based
      // header (x-session-token) on subsequent requests.
      return res.status(200).json({
        id: user.id,
        username: user.username,
        salt: user.salt,
        iterations: user.iterations,
        sessionToken: rawToken,
        sessionExpiresAt: session.expiresAt,
      });
    } catch (err) {
      console.error("Login error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/auth/salt/:username", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const clientIp = getClientIp(req);
      if (isRateLimited(`salt:${clientIp}`)) {
        return res.status(429).json({ error: "Too many attempts. Please try again later." });
      }

      const validated = validateUsernameParam(req.params.username);
      if (!validated.ok) {
        return res.status(400).json({ error: validated.error });
      }
      const username = validated.data;

      const user = await storage.getUserByUsername(username);

      return res.status(200).json({
        salt: user ? user.salt : deterministicDummySalt(username),
        iterations: user ? user.iterations : DUMMY_ITERATIONS,
      });
    } catch (err) {
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/vault/sync", jsonBody(VAULT_SYNC_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      // Validate body shape BEFORE the auth DB lookup — same ordering
      // rationale as the original implementation: a malformed body should
      // never trigger a wasted getUser/getActiveSessionByTokenHash round
      // trip. Header shape is checked inside authenticate() below.
      const parsed = validateVaultSync(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId } = auth;

      // Rate limit AFTER authenticate so the userId is real and unauth
      // probes can never poison either bucket. Single-shape 429 — see
      // checkUserRateLimit doc for why we don't distinguish IP vs user.
      if (checkUserRateLimit("vault_sync", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      // Recovery Mode write block (T3): runs BEFORE the soft-lock
      // check so the message is consistent ("recovery mode active")
      // and so a user whose lock has technically expired but who
      // hasn't acknowledged recovery mode is still blocked from
      // further writes. isRecoveryModeActive itself runs the lazy
      // auto-exit checks (clean + 15-min backstop), so a user whose
      // signals have settled passes through here without any audit
      // noise from this code path.
      if (isRecoveryModeActive(userId, storage)) {
        return res
          .status(423)
          .json({ error: "Vault locked - recovery mode active" });
      }

      // Soft-lock check sits BETWEEN rate limit and the storage call:
      //   - Rate-limit hits (429) come first because they are the
      //     cheaper, lower-noise defense; we don't want a 423 to mask a
      //     legitimate "you are spamming" 429.
      //   - It runs BEFORE storage.syncVault so a locked user doesn't
      //     hit the DB at all — the lock is the whole point.
      // 423 (Locked) is the closest standard HTTP status; the response
      // body is a single-shape error so a probe can't distinguish 423
      // from any other rejection without parsing.
      const lockedUntil = getActiveSoftLock(userId);
      if (lockedUntil !== undefined) {
        recordAudit(storage, {
          userId,
          action: "write_blocked_soft_lock",
          ipAddress: getClientIp(req),
          // Stash structured metadata in user_agent (same convention
          // as anomaly_detected / ip_change_detected — see
          // recordAnomaly callsites). attemptedAction lets a user
          // reading their audit log see "I tried to sync at T and got
          // blocked"; blockedUntil lets the UI show a countdown.
          userAgent: `attemptedAction=sync; blockedUntil=${lockedUntil}`,
        });
        // Mirror to in-memory anomaly signal so deriveSecurityLevel
        // can surface "elevated" for ANOMALY_RECENT_WINDOW_MS after
        // the lock expires — matches the hasRecentAnomalies semantics
        // exposed by GET /api/vault/audit.
        recordSecuritySignalHit(userId, auth.sessionId, false);
        return res
          .status(423)
          .json({ error: "Vault temporarily locked due to suspicious activity" });
      }

      // TOTP step-up gate. Sits BELOW recovery mode (423) and soft-
      // lock (423) — same rationale as the untrusted-device block
      // below — but ABOVE the untrusted-device 403 because TOTP
      // step-up is meant to SUBSTITUTE for device trust on the write
      // path. A user with TOTP enabled who has freshly stepped up
      // can write from an untrusted device; without TOTP we fall
      // through to the existing 403.
      //
      // For sync, the gate fires only when the request context is
      // already elevated (securityLevel === "high" OR untrusted
      // device). A normal-context sync is NOT gated even with TOTP
      // enabled — that would be needlessly user-hostile.
      const syncIsUntrusted = isSessionUntrusted(userId, auth.sessionId);
      const syncSecurityLevel = deriveSecurityLevel(userId, auth.sessionId);
      const syncStepUp = await evaluateTotpStepUp({
        userId,
        sessionId: auth.sessionId,
        sessionTotpVerifiedUntil: auth.totpVerifiedUntil,
        securityLevel: syncSecurityLevel,
        isUntrusted: syncIsUntrusted,
        requireAlways: false,
      });
      if (syncStepUp.required && !syncStepUp.satisfied) {
        recordAudit(storage, {
          userId,
          action: "totp_required_for_write",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=sync; level=${syncSecurityLevel}; untrusted=${syncIsUntrusted}`,
        });
        return res.status(401).json({ error: "TOTP required" });
      }

      // Passkey step-up gate. Mirrors the TOTP gate above for users
      // whose second factor is a passkey instead of TOTP. Sits BELOW
      // the TOTP gate (which short-circuits for TOTP-enabled users)
      // and ABOVE the untrusted-device 403 (so a passkey-fresh user
      // can write from an untrusted device, same SUBSTITUTE-for-trust
      // semantics the TOTP path already has).
      const syncStepUpPasskey = await evaluatePasskeyStepUp({
        userId,
        sessionId: auth.sessionId,
        sessionTotpVerifiedUntil: auth.totpVerifiedUntil,
        securityLevel: syncSecurityLevel,
        isUntrusted: syncIsUntrusted,
        requireAlways: false,
        totpEnabled: syncStepUp.totpEnabled,
      });
      if (syncStepUpPasskey.required && !syncStepUpPasskey.satisfied) {
        recordAudit(storage, {
          userId,
          action: "passkey_required_for_write",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=sync; level=${syncSecurityLevel}; untrusted=${syncIsUntrusted}`,
        });
        return res.status(401).json({ error: "Step-up required" });
      }

      // Untrusted-device write block. Sits BELOW recovery mode (423)
      // and soft-lock (423) because those are stronger account-wide
      // states — surfacing 403 first would mislead the user into
      // believing trust-device would unblock them when actually their
      // account is in a deeper lockdown. 403 (Forbidden) is the right
      // status: this is an authorization decision (the request is
      // well-formed and the credentials valid; the server is refusing
      // to act on this device specifically). The audit row gives the
      // user a paper trail in their own audit log so they can see
      // "I tried to sync from a new device and was blocked".
      //
      // SUPPRESSED when ANY step-up factor is currently satisfied for
      // this session (read directly off the totpVerifiedUntil column,
      // which is written by both TOTP step-up AND passkey step-up).
      // A 2FA-fresh user has already proven identity and is not
      // subject to the per-device trust gate. Users with no second
      // factor enabled continue to see the 403 exactly as before.
      const syncStepUpFresh =
        auth.totpVerifiedUntil !== null &&
        auth.totpVerifiedUntil > Date.now();
      if (syncIsUntrusted && !syncStepUpFresh) {
        recordAudit(storage, {
          userId,
          action: "untrusted_device_blocked",
          ipAddress: getClientIp(req),
          userAgent: appendInstallIdMetadata(req, "attemptedAction=sync"),
        });
        return res
          .status(403)
          .json({ error: "Untrusted device - approval required" });
      }

      // T008 hardening: re-check step-up freshness immediately
      // before the storage write to close the TOCTOU window between
      // the gate evaluation above and the actual write. Captured
      // syncStepUpWasRequired off the gate decision — so this
      // re-check fires ONLY for users who actually had to step up
      // (TOTP-enabled OR passkey-enabled in an elevated context).
      // Users with no second factor enabled keep the existing
      // behaviour (no step-up was required at the gate, no re-check
      // here). totpVerifiedUntil is the snapshot loaded by
      // authenticate(); Date.now() advances during the awaits
      // between authenticate and here — so a long-running auth +
      // anomaly evaluation could cross the expiry boundary even
      // though the gate above passed. Failing CLOSED on expiry
      // (401, same shape as the gate above) is the correct posture.
      const syncStepUpWasRequired =
        syncStepUp.required || syncStepUpPasskey.required;
      if (
        syncStepUpWasRequired &&
        !(auth.totpVerifiedUntil !== null && auth.totpVerifiedUntil > Date.now())
      ) {
        recordAudit(storage, {
          userId,
          action: "totp_required_for_write",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=sync; reason=step_up_expired_pre_write`,
        });
        return res.status(401).json({ error: "Step-up expired" });
      }

      // syncVault verifies expectedPrevVersion and mints the next stored
      // version inside its transaction. The client never chooses version.
      const result = await storage.syncVault(
        userId,
        parsed.data.encryptedBlob,
        parsed.data.expectedPrevVersion,
      );
      if (!result.ok) {
        // Version conflict is NOT a successful sync — do not audit-log
        // it. Per spec we only log AFTER success to avoid noise and to
        // prevent enumeration via repeated failed attempts.
        return res.status(409).json(versionConflictResponse(result.serverVersion));
      }

      // Audit + anomaly hooks AFTER success. blobSize is the actual
      // byte length of the encrypted blob the client just stored
      // (NOT the blob contents themselves — we never log those, that
      // would break zero-knowledge). versionBefore is captured inside
      // syncVault's transaction so it's race-free.
      const ip = getClientIp(req);
      const userAgent = captureAuditUserAgent(req);
      recordAudit(storage, {
        userId,
        action: "vault_sync",
        versionBefore: result.previousVersion,
        versionAfter: result.blob.version,
        blobSize: Buffer.byteLength(parsed.data.encryptedBlob, "utf8"),
        ipAddress: ip,
        userAgent,
      });
      const signal = recordAnomaly(userId, "vault_sync", ip);
      if (signal.rateAnomalyMeta) {
        // Stash anomaly context in user_agent (per spec: "include
        // metadata in user_agent or a new field"). Keeps the schema
        // unchanged while preserving the human-readable detail.
        recordAudit(storage, {
          userId,
          action: "anomaly_detected",
          ipAddress: ip,
          userAgent: signal.rateAnomalyMeta,
        });
        // ESCALATE: a rate-spike anomaly is a high-signal event.
        // Trigger the soft lock so the NEXT write attempt gets 423.
        // (The current request already passed validation and the
        // storage write succeeded; spec is "block writes during the
        // lock window", not "retroactively reject this one".)
        triggerSoftLock(userId);
        // Mark the authenticating session as suspicious so the user's
        // session-list UI can flag the device. No-op if the request
        // came in via legacy auth-hash (auth.sessionId === null) —
        // there is no session row to mark.
        if (auth.sessionId) {
          void storage.markSessionSuspicious(auth.sessionId);
        }
        // In-memory mirror for the security-level system. flagSession
        // = true so deriveSecurityLevel can surface "high" without a
        // DB lookup for the rest of this session's life.
        recordSecuritySignalHit(userId, auth.sessionId, true);
      }
      if (signal.ipChangeFromIp) {
        recordAudit(storage, {
          userId,
          action: "ip_change_detected",
          ipAddress: ip,
          userAgent: `previous: ${signal.ipChangeFromIp}`,
        });
      }
      // IP-burst hardening: track on every authenticated write. Locks
      // the user when the per-account ring buffer shows more than
      // IP_CHANGE_THRESHOLD transitions in the window. Independent of
      // the single-flip ip_change_detected event above (which only
      // fires once per anomaly window and never locks).
      if (trackIpAndCheckBurst(userId, ip)) {
        triggerSoftLock(userId);
      }

      return res.status(200).json({
        version: result.blob.version,
        updatedAt: result.blob.updatedAt,
      });
    } catch (err) {
      console.error("Vault sync error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/vault/fetch", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId } = auth;

      if (checkUserRateLimit("vault_fetch", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      const blob = await storage.getVaultBlob(userId);
      // A fetch with no current vault row is still a SUCCESSFUL fetch
      // (the user simply has no vault yet) — log it. Spec says log
      // every successful fetch; doesn't carve out the empty case.
      const ip = getClientIp(req);
      const userAgent = captureAuditUserAgent(req);
      recordAudit(storage, {
        userId,
        action: "vault_fetch",
        ipAddress: ip,
        userAgent,
      });
      const signal = recordAnomaly(userId, "vault_fetch", ip);
      if (signal.rateAnomalyMeta) {
        recordAudit(storage, {
          userId,
          action: "anomaly_detected",
          ipAddress: ip,
          userAgent: signal.rateAnomalyMeta,
        });
        // Same escalation as /api/vault/sync. Even though fetch is a
        // READ and the soft lock only blocks WRITES, we still trigger
        // the lock here: an attacker who can spam fetches has likely
        // also stolen a session token, and we want their next write
        // attempt to be blocked. Reads remain available throughout
        // (per spec — user must always be able to see their data).
        triggerSoftLock(userId);
        if (auth.sessionId) {
          void storage.markSessionSuspicious(auth.sessionId);
        }
        recordSecuritySignalHit(userId, auth.sessionId, true);
      }
      if (signal.ipChangeFromIp) {
        recordAudit(storage, {
          userId,
          action: "ip_change_detected",
          ipAddress: ip,
          userAgent: `previous: ${signal.ipChangeFromIp}`,
        });
      }
      // IP-burst tracking on reads too — fetches are far more frequent
      // than writes and give us a denser signal of session-token reuse
      // across geographies. The lock it triggers still only blocks
      // WRITES; the fetch in flight here completes normally.
      if (trackIpAndCheckBurst(userId, ip)) {
        triggerSoftLock(userId);
      }

      // Compute + log security level transition just before the
      // response. Done AFTER all the anomaly hooks above so the level
      // reflects the state INCLUDING any escalation this request just
      // caused (e.g. a fetch that crossed the rate-spike threshold
      // returns securityLevel="critical" right away).
      const securityLevel = evaluateSecurityLevel(
        userId,
        auth.sessionId,
        ip,
        storage,
      );
      // Recovery mode + threat level (T2/T6). isRecoveryModeActive
      // also drives the lazy auto-exit, so calling it here keeps the
      // self-healing path warm even on read-only traffic. Cheap (one
      // Map lookup + a couple of timestamp comparisons).
      const recoveryMode = isRecoveryModeActive(userId, storage);
      const threatLevel = getThreatLevel(userId, auth.sessionId, storage);

      // Surface the per-session device-trust state on every fetch so
      // the client can show the "trust this device?" prompt without an
      // extra round-trip. Computed from the in-memory cache populated
      // by authenticate() on this same request — no DB hit. Legacy
      // auth-hash callers (sessionId === null) always see true: they
      // have no session row to gate, and the device-trust gate only
      // applies to session-token auth.
      const deviceTrusted = !isSessionUntrusted(userId, auth.sessionId);

      if (!blob) {
        return res.status(200).json({
          encryptedBlob: null,
          version: 0,
          securityLevel,
          recoveryMode,
          threatLevel,
          deviceTrusted,
        });
      }

      return res.status(200).json({
        encryptedBlob: blob.encryptedBlob,
        version: blob.version,
        updatedAt: blob.updatedAt,
        securityLevel,
        recoveryMode,
        threatLevel,
        deviceTrusted,
      });
    } catch (err) {
      console.error("Vault fetch error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/vault/history", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId } = auth;

      if (checkUserRateLimit("vault_history", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      // Returns metadata only — `version`, `archivedAt`, `blobSize`. We do
      // NOT return encrypted blobs here. Reasons:
      //   (a) the blob can be up to 10 MiB; sending up to 10 of them per
      //       request would be a DoS amplification vector, and
      //   (b) only the user already has the master key, so seeing N
      //       encrypted blobs without metadata wastes bandwidth — they have
      //       to GET /api/vault/restore (or in a future API, GET a specific
      //       historical blob) to actually use one.
      const entries = await storage.getVaultHistory(userId);
      return res.status(200).json(entries);
    } catch (err) {
      console.error("Vault history error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/vault/restore", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      // Body validation BEFORE the DB auth check, mirroring /api/vault/sync.
      // Restore body is tiny ({ version: number }) so the AUTH_BODY_LIMIT
      // (4kb) JSON parser is the right size — a fat body is a 413 by
      // express.json before this handler even runs.
      const parsed = validateVaultRestore(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId } = auth;

      if (checkUserRateLimit("vault_restore", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      // Recovery Mode write block (T3): same placement/rationale as
      // /api/vault/sync — restore IS a write so it must be blocked
      // while recovery mode is active. Runs BEFORE the soft-lock
      // check for consistency.
      if (isRecoveryModeActive(userId, storage)) {
        return res
          .status(423)
          .json({ error: "Vault locked - recovery mode active" });
      }

      // Soft-lock check — same placement and rationale as
      // /api/vault/sync. Restore IS a write (it archives the current
      // blob and replaces it with a historical version), so it must
      // be blocked during a lock too.
      const restoreLockedUntil = getActiveSoftLock(userId);
      if (restoreLockedUntil !== undefined) {
        recordAudit(storage, {
          userId,
          action: "write_blocked_soft_lock",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=restore; blockedUntil=${restoreLockedUntil}`,
        });
        recordSecuritySignalHit(userId, auth.sessionId, false);
        return res
          .status(423)
          .json({ error: "Vault temporarily locked due to suspicious activity" });
      }

      // TOTP step-up gate. ALWAYS required for restore when TOTP is
      // enabled (per spec) — restore is the most destructive write
      // (it can wind the vault back to any historical version) so
      // every restore re-prompts for the second factor regardless of
      // securityLevel or device trust. Same suppression-of-403
      // semantics as sync: if step-up is satisfied, the untrusted-
      // device 403 below is bypassed too.
      const restoreIsUntrusted = isSessionUntrusted(userId, auth.sessionId);
      const restoreSecurityLevel = deriveSecurityLevel(userId, auth.sessionId);
      const restoreStepUp = await evaluateTotpStepUp({
        userId,
        sessionId: auth.sessionId,
        sessionTotpVerifiedUntil: auth.totpVerifiedUntil,
        securityLevel: restoreSecurityLevel,
        isUntrusted: restoreIsUntrusted,
        requireAlways: true,
      });
      if (restoreStepUp.required && !restoreStepUp.satisfied) {
        recordAudit(storage, {
          userId,
          action: "totp_required_for_write",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=restore; level=${restoreSecurityLevel}; untrusted=${restoreIsUntrusted}`,
        });
        return res.status(401).json({ error: "TOTP required" });
      }

      // Passkey step-up gate. ALWAYS required for restore when the
      // user has a passkey enabled (mirrors the TOTP gate's
      // requireAlways:true above) — restore is the most destructive
      // write so every restore re-prompts for the second factor
      // regardless of context.
      const restoreStepUpPasskey = await evaluatePasskeyStepUp({
        userId,
        sessionId: auth.sessionId,
        sessionTotpVerifiedUntil: auth.totpVerifiedUntil,
        securityLevel: restoreSecurityLevel,
        isUntrusted: restoreIsUntrusted,
        requireAlways: true,
        totpEnabled: restoreStepUp.totpEnabled,
      });
      if (restoreStepUpPasskey.required && !restoreStepUpPasskey.satisfied) {
        recordAudit(storage, {
          userId,
          action: "passkey_required_for_write",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=restore; level=${restoreSecurityLevel}; untrusted=${restoreIsUntrusted}`,
        });
        return res.status(401).json({ error: "Step-up required" });
      }

      // Untrusted-device write block — same placement / rationale as
      // /api/vault/sync. Restore IS a write (it archives the current
      // blob and replaces it with a historical version), so it must
      // be blocked from untrusted devices for the same reason sync is.
      // Suppressed when ANY step-up factor is satisfied (read off the
      // shared totpVerifiedUntil column written by both TOTP and
      // passkey step-up paths — mirror of sync).
      const restoreStepUpFresh =
        auth.totpVerifiedUntil !== null &&
        auth.totpVerifiedUntil > Date.now();
      if (restoreIsUntrusted && !restoreStepUpFresh) {
        recordAudit(storage, {
          userId,
          action: "untrusted_device_blocked",
          ipAddress: getClientIp(req),
          userAgent: appendInstallIdMetadata(req, "attemptedAction=restore"),
        });
        return res
          .status(403)
          .json({ error: "Untrusted device - approval required" });
      }

      // T008 hardening: re-check step-up freshness immediately
      // before the storage write — same TOCTOU rationale as the
      // sync handler. For restore the gate uses requireAlways:true,
      // so step-up is required for ANY second-factor-enabled user
      // regardless of context; the re-check therefore fires for
      // every TOTP-or-passkey user. Fails closed on expiry.
      const restoreStepUpWasRequired =
        restoreStepUp.required || restoreStepUpPasskey.required;
      if (
        restoreStepUpWasRequired &&
        !(auth.totpVerifiedUntil !== null && auth.totpVerifiedUntil > Date.now())
      ) {
        recordAudit(storage, {
          userId,
          action: "totp_required_for_write",
          ipAddress: getClientIp(req),
          userAgent: `attemptedAction=restore; reason=step_up_expired_pre_write`,
        });
        return res.status(401).json({ error: "Step-up expired" });
      }

      // restoreVault is itself transactional and idempotent: it picks the
      // new vault version as max(currentVersion, targetVersion) + 1 so the
      // restore can never violate version monotonicity, archives the
      // displaced current blob first (a restore IS a write, so it must
      // itself be reversible), and prunes history. The historical entry
      // is looked up by (userId, targetVersion); if absent → 404.
      const result = await storage.restoreVault(userId, parsed.data.version);
      if (!result.ok) {
        // Failed restores (version_conflict, not_found) are NOT
        // audit-logged per the "only log AFTER success" rule.
        if (result.code === "version_conflict") {
          // A concurrent sync/restore raced this restore. The historical
          // entry exists; the client should re-fetch and retry.
          return res.status(409).json(versionConflictResponse(result.serverVersion));
        }
        return res.status(404).json({ error: "Version not found in history" });
      }

      // versionBefore captured race-free inside restoreVault's
      // transaction. versionAfter is the new live version (max of
      // current+1 and target+1, see restoreVault doc).
      const restoreIp = getClientIp(req);
      recordAudit(storage, {
        userId,
        action: "vault_restore",
        versionBefore: result.previousVersion,
        versionAfter: result.blob.version,
        ipAddress: restoreIp,
        userAgent: captureAuditUserAgent(req),
      });
      // IP-burst tracking on restore too — restore is a write endpoint
      // and an attacker spamming restores from rotating IPs should be
      // caught the same way as someone spamming sync. We deliberately
      // do NOT call recordAnomaly() here: restore has its own much
      // tighter rate cap (10/min, well below the 15/min anomaly
      // threshold), so a rate-spike anomaly bucket would never fire.
      if (trackIpAndCheckBurst(userId, restoreIp)) {
        triggerSoftLock(userId);
      }

      return res.status(200).json({
        version: result.blob.version,
        updatedAt: result.blob.updatedAt,
        restoredFromVersion: result.restoredFromVersion,
      });
    } catch (err) {
      console.error("Vault restore error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/auth/logout — revoke the current session.
  // Requires x-session-token specifically (not a legacy auth-hash) because
  // there is nothing to delete in the legacy path: a vault user without a
  // session has nothing to "log out". 400 if the header is missing or
  // malformed; 401 if the token is unknown OR expired (single response so
  // an attacker cannot probe for valid tokens via this endpoint); 200 on
  // success. The response includes no body fields the caller doesn't
  // already know — the client knows it just logged out.
  app.post("/api/auth/logout", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const tokenHeader = validateSessionTokenHeader(req);
      if (!tokenHeader.ok) {
        return res.status(400).json({ error: tokenHeader.error });
      }

      const tokenHash = createHash("sha256")
        .update(tokenHeader.data)
        .digest("hex");
      const session = await storage.getActiveSessionByTokenHash(tokenHash);
      if (!session) {
        // Treat unknown / expired the same. We do NOT reveal whether the
        // token "used to be" valid — that is information leakage.
        return res.status(401).json({ error: "Invalid credentials" });
      }

      await storage.deleteSessionById(session.id);
      // Audit AFTER deletion succeeds. We treat "session was already
      // gone" the same as "we just deleted it" (deleteSessionById
      // returns false in the former case, true in the latter), but
      // either way the user reached this branch with a valid token,
      // so the logout intent succeeded. Logging it gives users a
      // record of "I was logged out at this time from this device".
      recordAudit(storage, {
        userId: session.userId,
        action: "logout",
        ipAddress: getClientIp(req),
        userAgent: captureUserAgent(req),
      });
      return res.status(200).json({ ok: true });
    } catch (err) {
      console.error("Logout error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/auth/logout-all — revoke EVERY session for the user.
  // Accepts either auth scheme so a user who lost access to a session
  // (e.g. stolen device) but still remembers their password can still
  // panic-revoke. Returns the count of revoked sessions purely as a
  // confirmation signal for the client UI ("Logged out of N devices").
  app.post("/api/auth/logout-all", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }

      // Tightest cap of any endpoint (5/min). The whole point of
      // logout-all is "panic button"; that only happens a handful of
      // times in a user's lifetime. Capping it tightly stops an
      // attacker who briefly grabs a session from spamming this to
      // disrupt the legitimate user's other sessions repeatedly.
      if (checkUserRateLimit("logout_all", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      const revoked = await storage.deleteAllSessionsForUser(auth.userId);
      // Audit AFTER the delete succeeds. Spec doesn't ask for a
      // "count revoked" metadata field for logout_all, so we don't
      // stash it — the count is already in the API response and the
      // user can see it there. Logging it here too would be redundant
      // and would awkwardly overload one of the version_* columns.
      recordAudit(storage, {
        userId: auth.userId,
        action: "logout_all",
        ipAddress: getClientIp(req),
        userAgent: captureUserAgent(req),
      });
      return res.status(200).json({ ok: true, revoked });
    } catch (err) {
      console.error("Logout-all error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // GET /api/auth/sessions — list active sessions for the user.
  // Powers a "where am I logged in?" UI. Only non-expired sessions are
  // returned. Token hashes are deliberately omitted from the response
  // (see SessionListItem doc) — an attacker who steals a session for a
  // moment cannot use this endpoint to enumerate the user's other
  // sessions' token hashes. The current session id is exposed via the
  // `id` field so the UI can highlight it.
  app.get("/api/auth/sessions", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }

      if (checkUserRateLimit("auth_sessions", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      const list = await storage.listActiveSessionsForUser(auth.userId);
      // Compute + log security level transition. Sessions endpoint is
      // a natural place to surface this because the UI typically reads
      // it on app open / "security center" view.
      //
      // RESPONSE SHAPE CHANGE: previously this endpoint returned the
      // sessions array directly; spec mandates wrapping in
      // { sessions, securityLevel }. Documented in commit message —
      // this is the only spec-mandated breaking change in this task.
      const securityLevel = evaluateSecurityLevel(
        auth.userId,
        auth.sessionId,
        getClientIp(req),
        storage,
      );
      // Recovery mode + threat level (T2/T6) — same additive pattern
      // as /api/vault/fetch. Existing fields untouched.
      const recoveryMode = isRecoveryModeActive(auth.userId, storage);
      const threatLevel = getThreatLevel(auth.userId, auth.sessionId, storage);
      // Tag the requesting session with `current: true` so the UI can
      // highlight "this device" without having to round-trip the session
      // id separately. SessionListItem already includes `trusted` (set
      // by the storage layer); we only need to layer `current` on top.
      // For legacy auth-hash callers (sessionId === null) every row
      // surfaces as current=false — they have no session row to match.
      const sessionsWithCurrent = list.map((s) => ({
        ...s,
        current: auth.sessionId !== null && s.id === auth.sessionId,
      }));
      return res.status(200).json({
        sessions: sessionsWithCurrent,
        securityLevel,
        recoveryMode,
        threatLevel,
      });
    } catch (err) {
      console.error("List-sessions error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // GET /api/vault/audit — return the latest AUDIT_LOG_LIMIT (100)
  // audit entries for the authenticated user, newest first. Powers a
  // user-facing "vault activity" view so the user can see when their
  // vault was read/written, from where, and detect anything unfamiliar.
  //
  // Privacy contract:
  //   - The internal row id is NEVER exposed (see AuditLogItem doc).
  //   - The endpoint is per-user — the WHERE userId = auth.userId
  //     filter in storage.getAuditLog ensures one user can never see
  //     another's history even via a forged request.
  //   - Encrypted blobs / auth hashes / tokens are not in this table
  //     by construction (see vaultAuditLog schema doc), so there is
  //     nothing sensitive to redact at the API layer.
  //
  // No pagination by spec. The fixed 100-row cap is also a DoS bound
  // — even a user with millions of audit rows pays only for a single
  // index-backed LIMIT 100 lookup per request.
  app.get("/api/vault/audit", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }

      // Rate limit AFTER authenticate so the userId is real and unauth
      // probes never poison the user/IP buckets — same pattern as the
      // other authenticated endpoints. See checkUserRateLimit doc.
      if (checkUserRateLimit("vault_audit", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      const entries = await storage.getAuditLog(auth.userId, AUDIT_LOG_LIMIT);
      // hasRecentAnomalies is a derived signal computed from the same
      // page of entries we are about to return — no extra DB query.
      // True iff there is at least one anomaly_detected OR
      // write_blocked_soft_lock event in the last 10 minutes. The
      // client uses this as a one-bit "show a security banner" hint
      // without having to scan the entries array itself.
      //
      // RESPONSE SHAPE CHANGE: this endpoint previously returned the
      // raw `entries` array. Wrapping it in `{ entries, hasRecentAnomalies }`
      // is required by spec ("add optional field at top-level") and
      // is the only spec-mandated breaking response change in this
      // task. Documented in commit message.
      const tenMinAgo = Date.now() - 10 * 60_000;
      const hasRecentAnomalies = entries.some(
        (e) =>
          (e.action === "anomaly_detected" ||
            e.action === "write_blocked_soft_lock") &&
          e.createdAt >= tenMinAgo,
      );
      // Append the unified securityLevel signal. Additive only — does
      // not affect entries[] or hasRecentAnomalies fields.
      const securityLevel = evaluateSecurityLevel(
        auth.userId,
        auth.sessionId,
        getClientIp(req),
        storage,
      );
      // Recovery mode + threat level (T2/T6) — same additive pattern
      // as /api/vault/fetch and /api/auth/sessions. Existing fields
      // (entries, hasRecentAnomalies) are untouched.
      const recoveryMode = isRecoveryModeActive(auth.userId, storage);
      const threatLevel = getThreatLevel(auth.userId, auth.sessionId, storage);
      return res.status(200).json({
        entries,
        hasRecentAnomalies,
        securityLevel,
        recoveryMode,
        threatLevel,
      });
    } catch (err) {
      console.error("Vault audit error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // ---------------------------------------------------------------------
  // TOTP step-up gate helper
  // ---------------------------------------------------------------------
  //
  // Decides whether a sensitive write needs to be blocked because the
  // user has TOTP enabled but hasn't recently proven possession of the
  // second factor on this session.
  //
  // Returns:
  //   { satisfied: true,  required: bool } — caller may proceed.
  //   { satisfied: false, required: true } — caller MUST 401 with
  //                                          "TOTP required".
  //   { satisfied: false, required: false } — TOTP not enabled / not
  //                                            applicable; caller falls
  //                                            through to the existing
  //                                            untrusted-device gate.
  //
  // `requireAlways` is set by /api/vault/restore (every restore is
  // sensitive); otherwise the gate fires only when securityLevel >= "high"
  // OR the device is untrusted. Lookup of users.totpEnabled costs one
  // indexed PK SELECT — tolerable on the write path because both
  // sync and restore are already DB-bound. If this becomes a hotspot
  // a small in-memory cache (60s TTL) can be added without changing
  // the call sites.
  async function evaluateTotpStepUp(input: {
    userId: string;
    sessionId: string | null;
    sessionTotpVerifiedUntil: number | null;
    securityLevel: SecurityLevel;
    isUntrusted: boolean;
    requireAlways: boolean;
  }): Promise<{ required: boolean; satisfied: boolean; totpEnabled: boolean }> {
    const user = await storage.getUser(input.userId);
    const totpEnabled = user?.totpEnabled === true;
    if (!totpEnabled) {
      return { required: false, satisfied: false, totpEnabled: false };
    }
    const required =
      input.requireAlways ||
      input.securityLevel === "high" ||
      input.isUntrusted ||
      // Legacy auth-hash callers (sessionId === null) cannot step up:
      // there is no session row to mark as TOTP-verified. For TOTP-
      // enabled accounts that means writes MUST be denied here, so we
      // mark step-up "required" knowing it can never be satisfied
      // through this auth path. Net effect: legacy auth becomes
      // read-only for TOTP-enabled users — they have to log in
      // through the password+TOTP flow to mint a real session before
      // they can sync or restore.
      input.sessionId === null;
    if (!required) {
      // Step-up not needed for this action even though TOTP is on — a
      // normal-context sync should not be gated.
      return { required: false, satisfied: false, totpEnabled: true };
    }
    const now = Date.now();
    const satisfied =
      input.sessionTotpVerifiedUntil !== null &&
      input.sessionTotpVerifiedUntil > now;
    return { required: true, satisfied, totpEnabled: true };
  }

  // ---------------------------------------------------------------------
  // Passkey step-up gate helper
  // ---------------------------------------------------------------------
  //
  // Mirror of evaluateTotpStepUp for accounts whose second factor is a
  // passkey rather than TOTP. A successful passkey step-up writes the
  // same sessions.totp_verified_until column (legacy column name —
  // semantically it represents "this session has step-up verified by
  // ANY accepted second factor", not specifically TOTP), so the
  // satisfaction check here is identical to the TOTP helper.
  //
  // The gate runs ONLY when TOTP is disabled. If a user has BOTH
  // factors enabled, evaluateTotpStepUp already fired and the
  // resulting "step-up required" error message routes the user
  // through the TOTP path; either factor satisfies the same column,
  // so a TOTP-and-passkey user can still complete via passkey if
  // they prefer (the route just doesn't surface "use passkey" as a
  // first-class option in that combined case).
  //
  // The "do they actually have a passkey" lookup happens AFTER the
  // cheap context checks short-circuit, so a normal-context sync on
  // a passkey-less account costs zero extra DB hits.
  async function evaluatePasskeyStepUp(input: {
    userId: string;
    sessionId: string | null;
    sessionTotpVerifiedUntil: number | null;
    securityLevel: SecurityLevel;
    isUntrusted: boolean;
    requireAlways: boolean;
    totpEnabled: boolean;
  }): Promise<{ required: boolean; satisfied: boolean }> {
    if (input.totpEnabled) {
      // TOTP gate already handled this user; do nothing here so we
      // don't double-gate. (Either factor's step-up writes the same
      // column, so a TOTP-stepped-up user is also passkey-fresh
      // from the column's perspective.)
      return { required: false, satisfied: false };
    }
    const required =
      input.requireAlways ||
      input.securityLevel === "high" ||
      input.isUntrusted ||
      // Legacy auth-hash callers (sessionId === null) cannot step
      // up: there is no session row to mark. Same rationale as
      // the TOTP helper — passkey-enabled users on the legacy
      // auth path become read-only on sync/restore until they
      // log in via the session-token path.
      input.sessionId === null;
    if (!required) {
      return { required: false, satisfied: false };
    }
    // Only when the gate WOULD fire do we hit the DB to confirm
    // the user actually has a usable passkey. listCredentialsForUser
    // already filters out revoked rows, so empty list = "no
    // active passkey" and the gate is a no-op for this account.
    const credentials = await storage.listCredentialsForUser(input.userId);
    if (credentials.length === 0) {
      return { required: false, satisfied: false };
    }
    const now = Date.now();
    const satisfied =
      input.sessionTotpVerifiedUntil !== null &&
      input.sessionTotpVerifiedUntil > now;
    return { required: true, satisfied };
  }

  // POST /api/vault/recovery/acknowledge — user-initiated exit from
  // recovery mode (T4). Auth required (header path: x-session-token
  // OR legacy x-user-id+x-auth-hash, same as every other authenticated
  // endpoint). Idempotent: calling it when recovery mode is NOT active
  // is a successful no-op (200) so a client retry on a flaky network
  // can't surface a confusing failure.
  //
  // What this endpoint clears: ONLY the in-memory recovery flag.
  // What it intentionally does NOT clear:
  //   - softLockedUntil — if the user is still soft-locked, writes
  //     stay blocked by the existing soft-lock guard. Acknowledging
  //     recovery mode says "I see this", not "you were wrong".
  //   - recentAnomalyAt — anomaly memory persists for the normal
  //     ANOMALY_RECENT_WINDOW_MS so deriveSecurityLevel still
  //     surfaces "elevated" until that window naturally expires.
  //   - suspiciousSessions — the per-session suspicious flag remains
  //     so the user can independently rotate the affected session via
  //     the existing logout-all flow.
  // The user is therefore never trapped, but is also never falsely
  // told the underlying signals have all cleared.
  app.post("/api/vault/recovery/acknowledge", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId } = auth;

      // Rate-limit AFTER authenticate (real userId only). recovery_ack
      // bucket: 10/min — see PER_USER_RATE_LIMITS comment for the
      // rationale on why we don't lock this down further.
      if (checkUserRateLimit("recovery_ack", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      // T005 hardening: an attacker holding a stolen session token
      // would otherwise be able to silently dismiss recovery mode
      // (clearing the in-memory critical-state flag and re-enabling
      // a normal-context UI) without proving they hold the user's
      // SECOND factor. For accounts with TOTP enabled OR an active
      // passkey, require the same step-up posture the sync/restore
      // path requires (auth.totpVerifiedUntil > now — both factors
      // write that column, so either satisfies). Accounts with no
      // second factor at all retain the existing single-factor
      // behaviour — there is nothing to step up to. Failure here
      // emits the same totp_required_for_write audit shape as the
      // write-path gates so an operator reading the log sees a
      // unified "step-up was needed" event regardless of the
      // attempted action.
      const recUser = await storage.getUser(userId);
      const recPasskeys = await storage.listCredentialsForUser(userId);
      const recHasSecondFactor =
        recUser?.totpEnabled === true || recPasskeys.length > 0;
      if (recHasSecondFactor) {
        const recStepUpFresh =
          auth.totpVerifiedUntil !== null &&
          auth.totpVerifiedUntil > Date.now();
        if (!recStepUpFresh) {
          recordAudit(storage, {
            userId,
            action: "totp_required_for_write",
            ipAddress: getClientIp(req),
            userAgent: `attemptedAction=recovery_ack; totpEnabled=${recUser?.totpEnabled === true}; passkeys=${recPasskeys.length}`,
          });
          return res.status(401).json({ error: "Step-up required" });
        }
      }

      const r = recoveryState.get(userId);
      if (r?.active) {
        // Flip the flag synchronously so a parallel write-blocker
        // check (sync/restore) immediately observes the cleared
        // state — no need to wait on the audit insert.
        r.active = false;
        const currentLevel = deriveSecurityLevel(userId, auth.sessionId);
        // Single audit row per spec — recovery_acknowledged is
        // distinct from recovery_mode_exited (the auto-exit event)
        // so operators can distinguish manual user dismissal from
        // automatic recovery without parsing metadata.
        recordAudit(storage, {
          userId,
          action: "recovery_acknowledged",
          ipAddress: getClientIp(req),
          // previous: critical (recovery mode entry implies critical
          // at the time of entry); current: derived NOW (may have
          // already drifted down to elevated/normal as the underlying
          // signals decayed). Keeping both gives operators the full
          // before/after picture.
          userAgent: appendInstallIdMetadata(
            req,
            `previous=critical; current=${currentLevel}`,
          ),
        });
      }
      // Idempotent success — same response shape whether we cleared
      // a state or there was nothing to clear. Clients can retry
      // freely without surfacing a spurious failure.
      return res.status(200).json({ success: true });
    } catch (err) {
      console.error("Recovery acknowledge error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/auth/trust-device — user-initiated approval of the CURRENT
  // session/device for sensitive actions. Idempotent: trusting an
  // already-trusted session returns 200 without surfacing an error
  // (clients can retry freely on transient failures). Returns 400 for
  // legacy auth-hash callers — they have no session row to mark, and
  // silently succeeding would mislead the client into thinking they
  // had unblocked sync/restore when in fact the next request would
  // still trip the 403 (auth-hash callers are exempt from the device-
  // trust gate, but they're also incapable of toggling the flag).
  app.post("/api/auth/trust-device", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId, sessionId } = auth;

      // Rate-limit AFTER authenticate (real userId only). 5/min — see
      // PER_USER_RATE_LIMITS comment for rationale.
      if (checkUserRateLimit("trust_device", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      // Legacy auth-hash callers have no session row to update. Reject
      // explicitly rather than silently succeeding — see endpoint doc
      // comment above for why.
      if (sessionId === null) {
        return res
          .status(400)
          .json({ error: "Session token required to trust device" });
      }

      // DB UPDATE first (fail-open per IStorage contract — does not
      // throw), then in-memory cache, then audit. Order matters:
      //   - DB before cache so the durable state is correct even if
      //     the process crashes between the two writes;
      //   - Cache before audit so the next request from this same
      //     session in the same window sees the cleared state even if
      //     the audit insert is slow.
      await storage.markSessionTrusted(sessionId);
      clearUntrustedSession(userId, sessionId);
      recordAudit(storage, {
        userId,
        action: "device_trusted",
        ipAddress: getClientIp(req),
        // Stash the (truncated) fingerprint for cross-referencing with
        // the corresponding new_device_detected entry — same convention
        // as the login path.
        userAgent: appendInstallIdMetadata(
          req,
          `fingerprint=${getDeviceFingerprint(req).slice(0, 16)}`,
        ),
      });

      return res.status(200).json({ success: true });
    } catch (err) {
      console.error("Trust-device error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // -------------------------------------------------------------------------
  // Device + passkey management (T005-T010)
  // -------------------------------------------------------------------------
  //
  // Five endpoints, all session-token-authenticated:
  //   - GET  /api/security/devices        — list known devices (T005)
  //   - POST /api/security/device/trust   — flip trusted=true (T006)
  //   - POST /api/security/device/revoke  — flip trusted=false (T006)
  //   - POST /api/security/device/label   — set user label (T010)
  //   - GET  /api/passkeys                — list passkeys (T008)
  //   - POST /api/passkeys/revoke         — revoke passkey (T009)
  //
  // Trust-toggle + passkey-revoke require step-up (TOTP OR passkey,
  // requireAlways:true) so an attacker holding only a stolen session
  // token cannot self-elevate trust or wipe the legitimate user's
  // passkeys. Reads (devices list, passkeys list) require auth only —
  // the projections are public-safe (no IP/UA/credential-id/public-key).

  // Inline helper: enforce the step-up posture used by the three
  // sensitive mutations below. Returns null on success, or an
  // {status, body} pair the caller passes straight to res.status().json().
  // Mirrors the inlined gate in /api/vault/restore.
  async function enforceStepUpRequired(
    auth: { userId: string; sessionId: string | null; totpVerifiedUntil: number | null },
  ): Promise<{ status: number; body: { error: string; reason?: string } } | null> {
    const sec = deriveSecurityLevel(auth.userId, auth.sessionId);
    const isUntrusted = isSessionUntrusted(auth.userId, auth.sessionId);
    const totpStepUp = await evaluateTotpStepUp({
      userId: auth.userId,
      sessionId: auth.sessionId,
      sessionTotpVerifiedUntil: auth.totpVerifiedUntil,
      securityLevel: sec,
      isUntrusted,
      requireAlways: true,
    });
    if (totpStepUp.required && !totpStepUp.satisfied) {
      return {
        status: 401,
        body: { error: "Step-up authentication required", reason: "totp" },
      };
    }
    const passkeyStepUp = await evaluatePasskeyStepUp({
      userId: auth.userId,
      sessionId: auth.sessionId,
      sessionTotpVerifiedUntil: auth.totpVerifiedUntil,
      securityLevel: sec,
      isUntrusted,
      requireAlways: true,
      totpEnabled: totpStepUp.totpEnabled,
    });
    if (passkeyStepUp.required && !passkeyStepUp.satisfied) {
      return {
        status: 401,
        body: { error: "Step-up authentication required", reason: "passkey" },
      };
    }
    return null;
  }

  // T005 — GET /api/security/devices
  // Returns the per-user trusted_devices ledger as a public-safe
  // projection (fingerprint + label + trusted + first/lastSeenAt).
  // Drives the management UI's "your devices" list. NEVER includes
  // raw IP / UA — only the irreversible fingerprint hash.
  app.get("/api/security/devices", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (checkUserRateLimit("security_devices", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const devices = await storage.getDevicesForUser(auth.userId);
      return res.status(200).json({ devices });
    } catch (err) {
      console.error("List-devices error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // Strict body schema for the trust / revoke endpoints. Fingerprint
  // must be the 64-char SHA-256 hex deriveDeviceFingerprint produces;
  // anything else is a client bug or a malformed probe. .strict() so
  // unknown fields are rejected with 400 (same pattern as register/
  // login/sync schemas in shared/schema.ts).
  const deviceFingerprintSchema = z
    .object({
      fingerprint: z
        .string()
        .regex(/^[a-f0-9]{64}$/, "fingerprint must be 64 lowercase hex chars"),
    })
    .strict();

  // T006 — POST /api/security/device/trust
  // Flip trusted=true on a (user, fingerprint) row. Step-up required
  // so a stolen session cannot self-elevate. Audit on success
  // (device_trusted is NOT in DEDUPABLE — every user-initiated trust
  // toggle is recorded distinctly).
  app.post("/api/security/device/trust", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (
        checkUserRateLimit("security_device_trust", getClientIp(req), auth.userId)
      ) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const parsed = deviceFingerprintSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body" });
      }
      const gate = await enforceStepUpRequired(auth);
      if (gate) return res.status(gate.status).json(gate.body);

      const flipped = await storage.markDeviceTrusted(
        auth.userId,
        parsed.data.fingerprint,
      );
      if (!flipped) {
        // Either the device doesn't exist for this user OR it was
        // already trusted (idempotent). 404 in the not-found case
        // would leak existence; we return 200 with a flag so a
        // client retry on a flaky network is forgiving and a
        // probe gets no signal about which fingerprints exist.
        return res.status(200).json({ success: true, changed: false });
      }
      // Clear the in-memory device-untrusted signal for this session
      // immediately so the very next /api/auth/security-state call
      // surfaces the new posture without waiting for the next
      // authenticate() round-trip to repopulate from the DB.
      if (auth.sessionId !== null) {
        clearDeviceUntrustedSession(auth.userId, auth.sessionId);
      }
      recordAudit(storage, {
        userId: auth.userId,
        action: "device_trusted",
        ipAddress: getClientIp(req),
        userAgent: appendInstallIdMetadata(
          req,
          `fingerprint=${parsed.data.fingerprint.slice(0, 16)}`,
        ),
      });
      return res.status(200).json({ success: true, changed: true });
    } catch (err) {
      console.error("Device-trust error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // T006 — POST /api/security/device/revoke
  // Inverse of /trust. Same step-up gate, same audit shape. Does NOT
  // log the user out of any session on that device — revoking trust
  // re-elevates the security posture (sync/restore will require
  // step-up again) without forcing a re-login, which matches the
  // existing trust-device / untrust-session UX.
  app.post("/api/security/device/revoke", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (
        checkUserRateLimit("security_device_trust", getClientIp(req), auth.userId)
      ) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const parsed = deviceFingerprintSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body" });
      }
      const gate = await enforceStepUpRequired(auth);
      if (gate) return res.status(gate.status).json(gate.body);

      const flipped = await storage.revokeDeviceTrust(
        auth.userId,
        parsed.data.fingerprint,
      );
      if (!flipped) {
        return res.status(200).json({ success: true, changed: false });
      }
      // If the user just untrusted the CURRENT device, immediately
      // mark this session's device-untrusted signal so the very next
      // request surfaces "elevated" without waiting for an authenticate
      // round-trip.
      if (auth.sessionId !== null) {
        const currentFp = deriveDeviceFingerprint(
          getClientIp(req),
          captureUserAgent(req),
        );
        if (currentFp === parsed.data.fingerprint) {
          recordDeviceUntrustedSession(auth.userId, auth.sessionId);
        }
      }
      recordAudit(storage, {
        userId: auth.userId,
        action: "device_untrusted",
        ipAddress: getClientIp(req),
        userAgent: appendInstallIdMetadata(
          req,
          `fingerprint=${parsed.data.fingerprint.slice(0, 16)}`,
        ),
      });
      return res.status(200).json({ success: true, changed: true });
    } catch (err) {
      console.error("Device-revoke error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // T010 — POST /api/security/device/label
  // Lightweight metadata write: rename a device the user already owns.
  // No step-up required (renaming is not a security-state mutation;
  // the worst-case abuse — stolen session relabels the user's device
  // — is annoying but not exploitable). Validation enforces the spec's
  // ≤64-char limit and rejects control characters so a malicious label
  // can't break management-UI rendering.
  const deviceLabelSchema = z
    .object({
      fingerprint: z
        .string()
        .regex(/^[a-f0-9]{64}$/, "fingerprint must be 64 lowercase hex chars"),
      label: z
        .string()
        .min(1)
        .max(64)
        // Reject \x00-\x1F and \x7F (control chars); allow everything
        // else (unicode letters / emoji are fine — the column is
        // unrestricted text and the UI handles its own escaping).
        .regex(/^[^\x00-\x1F\x7F]+$/, "label contains control characters"),
    })
    .strict();

  app.post("/api/security/device/label", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (checkUserRateLimit("device_label", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const parsed = deviceLabelSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body" });
      }
      // Trim AFTER schema validation so leading/trailing whitespace
      // doesn't smuggle empty labels past the .min(1) check.
      const cleanLabel = parsed.data.label.trim();
      if (cleanLabel.length === 0 || cleanLabel.length > 64) {
        return res.status(400).json({ error: "Invalid label" });
      }
      const updated = await storage.relabelDevice(
        auth.userId,
        parsed.data.fingerprint,
        cleanLabel,
      );
      if (!updated) {
        return res.status(200).json({ success: true, changed: false });
      }
      recordAudit(storage, {
        userId: auth.userId,
        action: "device_relabeled",
        ipAddress: getClientIp(req),
        userAgent: `fingerprint=${parsed.data.fingerprint.slice(0, 16)}`,
      });
      return res.status(200).json({ success: true, changed: true });
    } catch (err) {
      console.error("Device-label error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // ---------------------------------------------------------------------------
  // Honeytokens / deception layer (T001-T010)
  // ---------------------------------------------------------------------------
  //
  // Endpoints (all under /api/security/honeytokens):
  //   - GET    /                  — list this user's honeytokens (no markerHash)
  //   - POST   /                  — create a new honeytoken
  //   - POST   /disable           — soft-disable by id (step-up gated)
  //   - POST   /trigger           — record an access; escalate security state
  //
  // Disable requires step-up so a stolen session cannot silently retire
  // the user's traps. Create + trigger + list are auth-only — creating a
  // honeytoken doesn't change anything sensitive (the row just sits there
  // until something probes it), and trigger is the panic-button path
  // where an additional gate would defeat the purpose.
  //
  // Trigger integrates with the EXISTING security model:
  //   recordAudit(honeytoken_triggered)
  //     + recordSecuritySignalHit (paints elevated, marks suspicious)
  //     + markSessionSuspicious (DB-side flag)
  //     + on triggerCount >= 2: triggerSoftLock (5-min write lock)
  //
  // This deliberately uses the same hooks as escalatePasskeyAnomaly above
  // — no parallel state machine, no new severity ladder. The unified
  // security level system in /api/auth/security-state surfaces the
  // posture change to the client without any new wire-format work.

  // GET /api/security/honeytokens — list. Read-only, no step-up.
  // Returns the public projection (NEVER includes markerHash). Bounded
  // by the per-user list cap inherent to the table — a user has at
  // most a handful of decoys, and the per-user rate limit caps abuse.
  app.get("/api/security/honeytokens", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (
        checkUserRateLimit("honeytoken_list", getClientIp(req), auth.userId)
      ) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const honeytokens = await storage.listHoneytokens(auth.userId);
      return res.status(200).json({ honeytokens });
    } catch (err) {
      console.error("List-honeytokens error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/security/honeytokens — create. Auth-only (no step-up:
  // adding a decoy doesn't weaken anything). Body validated by the
  // shared createHoneytokenSchema (label/tokenType enum/markerHash hex).
  // Returns the public projection of the new row so the UI can render
  // immediately without a follow-up GET. UNIQUE(user, marker) violations
  // surface as 409 — the client should rotate its marker and retry.
  app.post(
    "/api/security/honeytokens",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }
        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        if (
          checkUserRateLimit(
            "honeytoken_create",
            getClientIp(req),
            auth.userId,
          )
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }
        const parsed = createHoneytokenSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ error: "Invalid request body" });
        }
        // Trim AFTER schema validation so trailing whitespace can't smuggle
        // an empty label past the .min(1) check (mirror of the device_label
        // route's defense above).
        const cleanLabel = parsed.data.label.trim();
        if (cleanLabel.length === 0 || cleanLabel.length > 64) {
          return res.status(400).json({ error: "Invalid label" });
        }
        let row;
        try {
          row = await storage.createHoneytoken({
            userId: auth.userId,
            label: cleanLabel,
            tokenType: parsed.data.tokenType,
            markerHash: parsed.data.markerHash,
          });
        } catch (err) {
          if (err instanceof HoneytokenMarkerConflictError) {
            // Unique-violation. Distinguishable from generic 500 so the
            // client can take a different recovery path (regenerate
            // marker, prompt user, ...) rather than blindly retrying.
            return res
              .status(409)
              .json({ error: "Honeytoken with this marker already exists" });
          }
          throw err;
        }
        // Audit. NEVER include the markerHash in the audit row — only
        // label + tokenType. The 16-char id prefix mirrors the audit
        // shape used by device_trusted / device_relabeled above.
        recordAudit(storage, {
          userId: auth.userId,
          action: "honeytoken_created",
          ipAddress: getClientIp(req),
          userAgent: `id=${row.id.slice(0, 16)}; type=${row.tokenType}; label=${cleanLabel.slice(0, 32)}`,
        });
        return res.status(201).json({ honeytoken: row });
      } catch (err) {
        console.error("Create-honeytoken error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/security/honeytokens/disable — step-up gated. Soft-disable
  // by row id (NOT by markerHash — see disableHoneytokenSchema doc for
  // why). Idempotent: a disable on an already-disabled or non-existent
  // row returns 200 with changed:false (no leak about which ids exist).
  app.post(
    "/api/security/honeytokens/disable",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }
        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        if (
          checkUserRateLimit(
            "honeytoken_disable",
            getClientIp(req),
            auth.userId,
          )
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }
        const parsed = disableHoneytokenSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ error: "Invalid request body" });
        }
        // Step-up REQUIRED — disabling weakens the user's deception
        // posture, so an attacker holding only a stolen session token
        // must NOT be able to wipe the traps. Mirrors the device-trust
        // and passkey-revoke gates.
        const gate = await enforceStepUpRequired(auth);
        if (gate) return res.status(gate.status).json(gate.body);

        const result = await storage.disableHoneytoken(
          auth.userId,
          parsed.data.id,
        );
        if (!result) {
          // Either the id doesn't belong to this user, the id doesn't
          // exist, or it was already disabled. 404 in any of those
          // would leak existence; 200 with changed:false is the same
          // pattern device-trust uses for the analogous case.
          return res.status(200).json({ success: true, changed: false });
        }
        recordAudit(storage, {
          userId: auth.userId,
          action: "honeytoken_disabled",
          ipAddress: getClientIp(req),
          userAgent: `id=${parsed.data.id.slice(0, 16)}; type=${result.tokenType}; label=${result.label.slice(0, 32)}`,
        });
        return res.status(200).json({ success: true, changed: true });
      } catch (err) {
        console.error("Disable-honeytoken error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/security/honeytokens/trigger — the deception-layer
  // panic-button. Auth-only (no step-up — a panicking client must be
  // able to fire this before any further interaction). Validates the
  // marker hash format, then delegates to the storage atomic trigger.
  //
  // Behavior on a confirmed match:
  //   1. Fire honeytoken_triggered audit (NEVER includes markerHash).
  //   2. recordSecuritySignalHit — paints elevated, marks session
  //      suspicious (in-memory).
  //   3. markSessionSuspicious — persists the suspicious flag to the
  //      sessions row (fire-and-forget per IStorage contract).
  //   4. If triggerCount >= 2 on the returned row: triggerSoftLock
  //      so further vault writes return 423 for SOFT_LOCK_DURATION_MS.
  //      Single-trigger is "elevated"; repeat trigger is "actively
  //      under attack" — the soft lock buys the user time to react
  //      while still allowing READS (per spec: never break the user
  //      out of their own vault).
  //
  // No-match (unknown marker, wrong user, or already disabled): 200
  // with triggered:false. Same posture as the analogous device routes
  // above — the wire surface area gives an attacker no signal about
  // which markers exist.
  app.post(
    "/api/security/honeytokens/trigger",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }
        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        if (
          checkUserRateLimit(
            "honeytoken_trigger",
            getClientIp(req),
            auth.userId,
          )
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }
        const parsed = triggerHoneytokenSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ error: "Invalid request body" });
        }

        const result = await storage.triggerHoneytoken(
          auth.userId,
          parsed.data.markerHash,
        );
        if (!result) {
          // No active row matched. Returning a successful 200 (rather
          // than 404) ensures an attacker probing markers cannot map
          // out which hashes correspond to real honeytokens. Note we
          // intentionally DO NOT record any audit row here — a probe
          // miss is not a security event, and surfacing one would
          // create a bottomless audit-log spam vector.
          return res
            .status(200)
            .json({ success: true, triggered: false });
        }

        // Match. Build the audit metadata WITHOUT the markerHash —
        // only label + tokenType + (optional) context + the post-update
        // counter. The 32-char label slice mirrors the discipline used
        // by honeytoken_created above; the optional context is bounded
        // to 128 chars by the request schema.
        const contextSuffix = parsed.data.context
          ? `; context=${parsed.data.context}`
          : "";
        recordAudit(storage, {
          userId: auth.userId,
          action: "honeytoken_triggered",
          ipAddress: getClientIp(req),
          userAgent: `id=${result.honeytokenId.slice(0, 16)}; type=${result.tokenType}; label=${result.label.slice(0, 32)}; count=${result.triggerCount}${contextSuffix}`,
        });

        // Fan-out into the existing security model. recordSecuritySignalHit
        // paints elevated + flags the session in the in-memory
        // suspicious-session set. markSessionSuspicious is the DB-side
        // mirror — fire-and-forget per IStorage contract. Both are safe
        // when sessionId is null (legacy auth-hash path); the helpers
        // already guard internally.
        recordSecuritySignalHit(auth.userId, auth.sessionId, true);
        if (auth.sessionId !== null) {
          void storage.markSessionSuspicious(auth.sessionId);
        }

        // Repeat trigger → soft-lock writes. Using the per-row counter
        // (rather than a separate window structure) keeps the policy
        // dead-simple and self-documenting: the same honeytoken being
        // probed twice is an unambiguous attack signal. triggerSoftLock
        // is idempotent — multiple repeats in quick succession do NOT
        // extend an already-active lock past its natural expiry.
        let softLockedUntil: number | undefined;
        if (result.triggerCount >= 2) {
          softLockedUntil = triggerSoftLock(auth.userId);
        }

        return res.status(200).json({
          success: true,
          triggered: true,
          triggerCount: result.triggerCount,
          softLockedUntil: softLockedUntil ?? null,
        });
      } catch (err) {
        console.error("Trigger-honeytoken error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // T008 — GET /api/passkeys
  // Per-spec safe projection: id + deviceName + createdAt + lastUsedAt.
  // EXPLICITLY EXCLUDES credentialId, publicKey, counter, transports.
  // The internal id is the handle the client uses to address /revoke
  // (mapped server-side back to credentialId for the storage call —
  // the wire surface area never exposes the WebAuthn credentialId).
  app.get("/api/passkeys", async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (checkUserRateLimit("passkeys_list", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const credentials = await storage.listCredentialsForUser(auth.userId);
      const passkeys = credentials.map((c) => ({
        id: c.id,
        deviceName: c.deviceName,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      }));
      return res.status(200).json({ passkeys });
    } catch (err) {
      console.error("List-passkeys error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // T009 — POST /api/passkeys/revoke
  // Step-up required so a stolen session cannot wipe the user's
  // passkeys (which would lock them out if the password was lost
  // and passkey was the only path back in).
  //
  // Body { passkeyId } where passkeyId is the INTERNAL uuid (id) the
  // /api/passkeys list returned. We resolve it to credentialId via a
  // user-scoped lookup — a request whose passkeyId belongs to a
  // different user returns 404 indistinguishably from "not found",
  // matching the project's invalid-vs-not-exist convention.
  const passkeyRevokeSchema = z
    .object({
      passkeyId: z.string().uuid(),
    })
    .strict();

  app.post("/api/passkeys/revoke", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }
      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      if (checkUserRateLimit("passkey_revoke", getClientIp(req), auth.userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }
      const parsed = passkeyRevokeSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body" });
      }
      const gate = await enforceStepUpRequired(auth);
      if (gate) return res.status(gate.status).json(gate.body);

      // User-scoped resolve: only this user's NON-REVOKED credentials
      // are eligible. Cross-tenant passkeyId returns the same 404 a
      // bogus uuid would.
      const credentials = await storage.listCredentialsForUser(auth.userId);
      const target = credentials.find((c) => c.id === parsed.data.passkeyId);
      if (!target) {
        return res.status(404).json({ error: "Passkey not found" });
      }
      const revoked = await storage.revokeCredential(target.credentialId);
      if (!revoked) {
        // Concurrent revoke races (two tabs, both clicking revoke on
        // the same passkey) — the second observes the row already
        // soft-deleted. Treat as success-no-op so the UX is forgiving.
        return res.status(200).json({ success: true, changed: false });
      }
      recordAudit(storage, {
        userId: auth.userId,
        action: "passkey_revoked",
        ipAddress: getClientIp(req),
        userAgent: `passkey_id=${target.id}`,
      });
      return res.status(200).json({ success: true, changed: true });
    } catch (err) {
      console.error("Passkey-revoke error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // -------------------------------------------------------------------------
  // TOTP step-up authentication
  // -------------------------------------------------------------------------
  //
  // Four endpoints make up the 2FA surface area:
  //   - POST /api/auth/totp/setup   — generate a fresh secret, return
  //                                    it (+ otpauth URL) so the user
  //                                    can scan it into their app.
  //                                    Does NOT enable TOTP yet.
  //   - POST /api/auth/totp/verify  — confirm the user holds the secret
  //                                    by submitting a valid 6-digit
  //                                    code. Atomically persists the
  //                                    secret + flips totpEnabled.
  //   - POST /api/auth/totp/login   — second factor for the password
  //                                    flow. Redeems the temp token
  //                                    issued by /api/auth/login and
  //                                    creates a real session.
  //   - POST /api/auth/totp/step-up — re-prove 2FA for sensitive
  //                                    actions (restore, sync from a
  //                                    suspicious context). Marks the
  //                                    session 2FA-verified for
  //                                    STEP_UP_TTL_MS.

  // POST /api/auth/totp/setup — auth required (session token preferred;
  // legacy auth-hash also accepted). Generates a fresh shared secret
  // and returns it ALONGSIDE the canonical otpauth URL so the client
  // can either show the raw secret (manual entry) or render a QR code
  // (camera scan). The secret is held only in memory under
  // pendingTotpSetups[userId] until /verify confirms it — a half-
  // finished setup that the user abandons simply expires after
  // SETUP_PENDING_TTL_MS without ever touching the DB.
  //
  // Idempotent for in-flight setups: calling setup twice in a row
  // overwrites the pending entry, so a user who lost their first
  // QR code can simply re-trigger the flow.
  app.post("/api/auth/totp/setup", jsonBody(AUTH_BODY_LIMIT), async (req: Request, res: Response) => {
    try {
      const queryCheck = validateNoQueryParams(req);
      if (!queryCheck.ok) {
        return res.status(400).json({ error: queryCheck.error });
      }

      const auth = await authenticate(req, storage);
      if (!auth.ok) {
        return res.status(auth.status).json({ error: auth.error });
      }
      const { userId } = auth;

      if (checkUserRateLimit("totp_setup", getClientIp(req), userId)) {
        return res.status(429).json({ error: "Too many requests" });
      }

      // Refuse setup if TOTP is already enabled. Re-running setup
      // without first calling a (future) /disable endpoint would
      // silently rotate the secret, which is a footgun: the user's
      // current authenticator-app entry would silently stop working
      // on the next /verify. 409 Conflict is the right status — the
      // request is well-formed but the resource is in an
      // incompatible state.
      const user = await storage.getUser(userId);
      if (!user) {
        // Should never happen: authenticate already verified the user
        // exists. Defense in depth.
        return res.status(401).json({ error: "Invalid credentials" });
      }
      if (user.totpEnabled === true) {
        return res
          .status(409)
          .json({ error: "TOTP is already enabled for this account" });
      }

      const secret = generateTotpSecret();
      pendingTotpSetups.set(userId, {
        secret,
        expiresAt: Date.now() + SETUP_PENDING_TTL_MS,
      });
      const otpauth = buildOtpauthUrl({ secret, username: user.username });

      // Audit the setup INITIATION (not the secret itself — never
      // log the secret or the otpauth URL). Distinct from
      // totp_enabled so an operator can see a user who repeatedly
      // started but never finished setup as a separate signal.
      recordAudit(storage, {
        userId,
        action: "totp_setup_initiated",
        ipAddress: getClientIp(req),
        userAgent: captureUserAgent(req),
      });

      return res.status(200).json({
        secret,
        otpauth,
        expiresAt: Date.now() + SETUP_PENDING_TTL_MS,
      });
    } catch (err) {
      console.error("TOTP setup error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/auth/totp/verify — auth required. Body: { token }. Looks
  // up the user's pending setup secret, runs the TOTP check (with the
  // configured ±1 step skew window), and on success atomically
  // encrypts + persists the secret AND flips users.totp_enabled.
  // Clears the pending entry so it can't be replayed. From this point
  // forward the user's password phase will issue a temp token, and
  // they will need a code to finish login.
  app.post(
    "/api/auth/totp/verify",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const parsed = validateTotpVerify(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        const { userId } = auth;

        if (checkUserRateLimit("totp_verify", getClientIp(req), userId)) {
          return res.status(429).json({ error: "Too many requests" });
        }

        const pending = pendingTotpSetups.get(userId);
        if (!pending || pending.expiresAt < Date.now()) {
          // Lazy expire so a stale entry never accidentally enables
          // TOTP. 400 (not 404) because the client clearly didn't
          // call setup recently enough — distinguishable from the
          // verify code being wrong (which is 401).
          pendingTotpSetups.delete(userId);
          return res
            .status(400)
            .json({ error: "No pending TOTP setup; call /setup first" });
        }

        if (!verifyTotp(pending.secret, parsed.data.token)) {
          // We deliberately do NOT delete the pending entry on a
          // failed code: a user fat-fingering once shouldn't have to
          // restart the QR scan. The rate limit (5/min) bounds
          // brute force; the SETUP_PENDING_TTL_MS bounds it across
          // restarts.
          recordAudit(storage, {
            userId,
            action: "totp_setup_failed",
            ipAddress: getClientIp(req),
            userAgent: captureUserAgent(req),
          });
          return res.status(401).json({ error: "Invalid TOTP code" });
        }

        // Encrypt + persist + flip the flag. setTotpEnabled does both
        // writes in a single UPDATE so the row is never observed
        // half-enabled. Encryption errors throw — they should be
        // surfaced as 500 so the user can retry rather than silently
        // succeeding on a half-stored secret.
        const encrypted = encryptTotpSecret(pending.secret);
        await storage.setTotpEnabled(userId, encrypted);
        pendingTotpSetups.delete(userId);

        recordAudit(storage, {
          userId,
          action: "totp_enabled",
          ipAddress: getClientIp(req),
          userAgent: captureUserAgent(req),
        });

        return res.status(200).json({ success: true });
      } catch (err) {
        console.error("TOTP verify error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/auth/totp/login — second factor for the password flow.
  // No auth required (the temp token IS the auth, single-use). On
  // success creates a real session — the same machinery as the
  // ordinary /api/auth/login response, including device-trust
  // decisioning and the new_device_detected audit row when this
  // device hasn't been seen before for this user.
  //
  // Failure modes:
  //   - Bad temp token shape   → 400
  //   - Unknown / expired temp → 401 (collapsed into "Invalid 2FA")
  //   - Wrong code             → 401 (collapsed into "Invalid 2FA")
  // We deliberately collapse "wrong token" and "wrong code" into the
  // same response so an attacker who has the password (and therefore
  // a valid temp token) can't distinguish "I have a real temp token
  // but wrong code" from "my temp token already expired".
  app.post(
    "/api/auth/totp/login",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const clientIp = getClientIp(req);
        // Per-IP rate limit (NOT per-user — we don't have a userId yet
        // and also don't want to leak which usernames have TOTP via
        // diff-rate behaviour). 5/min keyed on IP, same shape as the
        // login + register IP buckets.
        if (isRateLimited(`totp_login:${clientIp}`)) {
          return res
            .status(429)
            .json({ error: "Too many attempts. Please try again later." });
        }
        // Adaptive IP threat block — same shape as /api/auth/login.
        // The TOTP phase is the second half of the password+TOTP flow,
        // so we share the IP block bucket with the password phase.
        if (isIpBlocked(clientIp)) {
          return await ipBlockResponse(res, clientIp);
        }

        const parsed = validateTotpLogin(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        // T007 hardening: uniform random delay before any auth-result
        // branch. Equalises timing across "unknown temp token",
        // "user gone / TOTP disabled mid-flow", "wrong code", and
        // "success" — none of which should be distinguishable
        // through latency. 429 + 400 above are not delayed. Failure
        // paths additionally apply adaptiveLoginDelay(clientIp)
        // before responding for per-failure-count friction.
        await uniformLoginDelay();

        const tempTokenHash = createHash("sha256")
          .update(parsed.data.tempToken)
          .digest("hex");
        const entry = tempLoginTokens.get(tempTokenHash);
        const now = Date.now();
        if (!entry || entry.expiresAt < now) {
          // Lazy expire (and collapse with "no such entry") so the
          // response is single-shape: an attacker probing temp tokens
          // can't measure the difference between unknown and expired.
          tempLoginTokens.delete(tempTokenHash);
          return res
            .status(401)
            .json({ error: "Invalid credentials" });
        }

        // ATOMIC CLAIM: delete BEFORE any await so two concurrent
        // requests using the same tempToken cannot both pass this
        // gate and both mint sessions. JavaScript is single-threaded
        // up to the next await point, so the get-then-delete pair
        // above completes atomically from the perspective of any
        // other request that arrives during the awaits below.
        //
        // We re-insert the entry on a code-verification FAILURE (see
        // below) so a fat-finger retry within the 5-minute TTL still
        // works — but we hold no entry across the in-flight verify,
        // which is the window where the race would otherwise occur.
        tempLoginTokens.delete(tempTokenHash);

        const user = await storage.getUser(entry.userId);
        if (!user || user.totpEnabled !== true || !user.totpSecretEncrypted) {
          // User row was deleted, or TOTP got disabled between
          // password phase and code phase. The temp token is already
          // claimed (deleted above) — the user must re-do the
          // password phase. Same single-shape 401.
          return res
            .status(401)
            .json({ error: "Invalid credentials" });
        }

        const secret = decryptTotpSecret(user.totpSecretEncrypted);
        if (secret === null) {
          // Decryption failure is a server-side problem, not a user
          // error. Re-insert the claimed entry so a transient
          // key-config issue doesn't lock the user out of all retries
          // within the 5 min window — but only if the token would
          // still be live. Race-safe because we hold no overlap
          // window: the caller must retry as a separate request, by
          // which point the re-inserted entry is back in the map.
          if (entry.expiresAt > Date.now()) {
            tempLoginTokens.set(tempTokenHash, entry);
          }
          console.error("TOTP secret decryption failed during login");
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }

        if (!verifyTotp(secret, parsed.data.token)) {
          // Audit the FAILURE — distinct event so a user with their
          // own audit log can see "someone tried to use my password
          // but didn't have my code" as a clear credential-leak
          // signal. Re-insert the temp token so a fat-finger retry
          // works (same UX as /verify): we already claim-and-deleted
          // above, so the brief window where the entry is missing
          // closes BEFORE this re-insert, preserving single-use on
          // the success path while allowing retries on failure.
          if (entry.expiresAt > Date.now()) {
            tempLoginTokens.set(tempTokenHash, entry);
          }
          recordAudit(storage, {
            userId: user.id,
            action: "totp_login_failure",
            ipAddress: clientIp,
            userAgent: captureUserAgent(req),
          });
          // Audit visibility: also emit the unified login_failed
          // event so a client (or operator) reading the audit log can
          // count "failed login attempts of any kind" with a single
          // action filter, instead of OR'ing across totp_login_failure
          // / passkey_login_failure / etc. Dedup is per (user, ip,
          // minute) — a fat-fingered code retry from the same IP
          // collapses to one row per minute.
          recordAudit(storage, {
            userId: user.id,
            action: "login_failed",
            ipAddress: clientIp,
            userAgent: `reason=invalid_credentials; ua=${(captureUserAgent(req) ?? "").slice(0, 200)}`,
          });
          // Burst tracker: TOTP failures count toward the same
          // login-failure window as password failures (they're two
          // halves of the same auth flow). 6th failure inside 5 min
          // escalates via the existing security-signal pipeline.
          // hardLock=false: this is the unauth (pre-session) path.
          const burst = recordLoginFailure(user.id);
          if (burst.burstMeta) {
            escalatePasskeyAnomaly(
              storage,
              user.id,
              null,
              clientIp,
              `${burst.burstMeta}; source=totp_login`,
              { hardLock: false },
            );
          }
          // Adaptive IP threat: TOTP wrong-code = same severity as a
          // password failure for IP-block purposes. Real userId so an
          // ip_threat_detected row, if it fires, attaches here.
          recordIpFailure(storage, clientIp, user.id, user.id);
          await adaptiveLoginDelay(clientIp);
          return res
            .status(401)
            .json({ error: "Invalid credentials" });
        }

        // SUCCESS: temp token already burned at the top of this
        // handler (atomic claim). Create the real session — from
        // here we mirror the post-password code path of
        // /api/auth/login one-for-one: device fingerprint, trusted
        // decision, new_device_detected audit, etc. Keeping the two
        // paths in sync ensures 2FA users get the same device-trust
        // UX as non-2FA users.

        const rawToken = randomBytes(32).toString("hex");
        const sessionTokenHash = createHash("sha256")
          .update(rawToken)
          .digest("hex");
        const deviceFingerprint = getDeviceFingerprint(req);
        const isKnownDevice = await storage.hasDeviceFingerprintForUser(
          user.id,
          deviceFingerprint,
        );
        const session = await storage.createSession({
          userId: user.id,
          tokenHash: sessionTokenHash,
          expiresAt: Date.now() + SESSION_LIFETIME_MS,
          userAgent: captureUserAgent(req),
          ipAddress: clientIp,
          deviceFingerprint,
          trusted: isKnownDevice,
        });

        const userAgent = captureAuditUserAgent(req);
        recordAudit(storage, {
          userId: user.id,
          action: "totp_login_success",
          ipAddress: clientIp,
          userAgent,
        });
        recordAudit(storage, {
          userId: user.id,
          action: "session_created",
          ipAddress: clientIp,
          userAgent,
        });
        // Decay (not full-reset) the login-failure burst counter on
        // a clean TOTP success — same reasoning as the password
        // login success path. Mirrors decayPasskeyFailures.
        decayLoginFailures(user.id);
        // Adaptive IP threat decay (T008) — see /api/auth/login.
        recordIpSuccess(clientIp);
        if (!isKnownDevice) {
          recordAudit(storage, {
            userId: user.id,
            action: "new_device_detected",
            ipAddress: clientIp,
            userAgent: appendInstallIdMetadata(
              req,
              `fingerprint=${deviceFingerprint.slice(0, 16)}`,
            ),
          });
          recordSecuritySignalHit(user.id, session.id, false);
          recordUntrustedSession(user.id, session.id);
        }

        return res.status(200).json({
          id: user.id,
          username: user.username,
          salt: user.salt,
          iterations: user.iterations,
          sessionToken: rawToken,
          sessionExpiresAt: session.expiresAt,
        });
      } catch (err) {
        console.error("TOTP login error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/auth/totp/step-up — re-prove 2FA for the next sensitive
  // action. Auth required (session token only — legacy auth-hash
  // callers cannot step up because there is no session row to mark).
  // On success, sessions.totpVerifiedUntil is set to now + STEP_UP_TTL_MS
  // and the next sync/restore from this session will pass the gate
  // without re-prompting.
  app.post(
    "/api/auth/totp/step-up",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const parsed = validateTotpVerify(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        const { userId, sessionId } = auth;

        if (checkUserRateLimit("totp_step_up", getClientIp(req), userId)) {
          return res.status(429).json({ error: "Too many requests" });
        }

        // Legacy auth-hash callers can't step up: there is no session
        // row whose totpVerifiedUntil column we could write. Fail
        // explicitly rather than silently returning 200 — same
        // rationale as /trust-device.
        if (sessionId === null) {
          return res
            .status(400)
            .json({ error: "Session token required to step up" });
        }

        const user = await storage.getUser(userId);
        if (!user || user.totpEnabled !== true || !user.totpSecretEncrypted) {
          // Step-up only makes sense for users who have TOTP enabled.
          // 400 (not 404) — the request itself is invalid for this
          // account state.
          return res
            .status(400)
            .json({ error: "TOTP is not enabled for this account" });
        }

        const secret = decryptTotpSecret(user.totpSecretEncrypted);
        if (secret === null) {
          console.error("TOTP secret decryption failed during step-up");
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }

        if (!verifyTotp(secret, parsed.data.token)) {
          recordAudit(storage, {
            userId,
            action: "totp_step_up_failure",
            ipAddress: getClientIp(req),
            userAgent: captureUserAgent(req),
          });
          return res.status(401).json({ error: "Invalid TOTP code" });
        }

        const verifiedUntil = Date.now() + STEP_UP_TTL_MS;
        // Step-up persistence is load-bearing: if the column is not
        // written, the very next sync/restore on this session 401s
        // on the gate. markSessionTotpVerified returns false on DB
        // failure (errors swallowed + logged inside) — surface that
        // as 500 so the user can retry rather than discovering the
        // failure on their next sensitive action. The audit row
        // below is still emitted for the SUCCESS path only, so an
        // operator can distinguish "user attempted step-up but DB
        // dropped it" from "user successfully stepped up".
        const persisted = await storage.markSessionTotpVerified(
          sessionId,
          verifiedUntil,
        );
        if (!persisted) {
          recordAudit(storage, {
            userId,
            action: "totp_step_up_failure",
            ipAddress: getClientIp(req),
            userAgent: `reason=persist_failed`,
          });
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }
        recordAudit(storage, {
          userId,
          action: "totp_step_up_success",
          ipAddress: getClientIp(req),
          userAgent: captureUserAgent(req),
        });

        return res.status(200).json({
          success: true,
          verifiedUntil,
        });
      } catch (err) {
        console.error("TOTP step-up error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/passkeys/step-up/start — auth required. Mints a fresh
  // WebAuthn AUTHENTICATION challenge (single-use, in-process, 5 min
  // TTL) bound to the current session's userId, and returns
  // PublicKeyCredentialRequestOptions for the client to hand to
  // navigator.credentials.get(). Mirror of the TOTP step-up start
  // path conceptually, except the second factor is a passkey
  // assertion rather than a TOTP code.
  //
  // Body: empty object — strict-validated via the existing
  // validatePasskeyRegisterStart (same shape: an empty .strict()).
  // No body fields are needed; the user is identified entirely by
  // the session token on the request.
  //
  // Legacy auth-hash callers cannot step up (no session row to mark
  // on /finish) — rejected with 400 same as the TOTP path.
  app.post(
    "/api/passkeys/step-up/start",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const parsed = validatePasskeyRegisterStart(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        const { userId, sessionId } = auth;

        if (
          checkUserRateLimit("passkey_step_up_start", getClientIp(req), userId)
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }

        if (sessionId === null) {
          return res
            .status(400)
            .json({ error: "Session token required to step up" });
        }

        // Need at least one usable passkey to even start. listCredentials
        // already filters revoked rows; an empty list means the user has
        // no passkey to assert with. 400 (not 404) — the request itself
        // is invalid for this account state, same shape the TOTP path
        // returns when TOTP is not enabled.
        const credentials = await storage.listCredentialsForUser(userId);
        if (credentials.length === 0) {
          return res
            .status(400)
            .json({ error: "No passkeys registered for this account" });
        }

        const options = await generateAuthenticationOptionsFor({
          userId,
          request: req,
          allowCredentialIds: credentials.map((c) => ({
            id: c.credentialId,
            transports: c.transports,
          })),
        });
        if (!options.ok) {
          // generateAuthenticationOptionsFor only fails on internal
          // errors (challenge store failure, etc.). Surface 500.
          console.error(
            `Passkey step-up options generation failed: code=${options.code}`,
          );
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }
        return res.status(200).json(options.options);
      } catch (err) {
        console.error("Passkey step-up start error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/passkeys/step-up/finish — auth required. Verifies the
  // assertion against the challenge issued by /step-up/start, then
  // marks sessions.totpVerifiedUntil so the next sync/restore on
  // this session bypasses the step-up gate for STEP_UP_TTL_MS.
  //
  // Body: { response: <WebAuthn assertion> } — strict-validated via
  // the existing validatePasskeyLoginFinish (identical body shape).
  //
  // Critical security check: the credential must belong to the
  // session's user. Without this, an attacker who controls both an
  // active session for user X AND a passkey-bound authenticator
  // belonging to user Z could:
  //   1. POST /step-up/start with X's session → challenge bound to X
  //   2. Have Z sign that challenge
  //   3. POST /step-up/finish with Z's assertion under X's session
  //   4. The verifier would consume X's challenge and validate the
  //      signature against Z's stored public key (looked up by
  //      credential id) — succeeding because the signature is
  //      cryptographically valid for that key
  //   5. We would then mark X's session as step-up verified
  // Cross-user assertions MUST be rejected before the verifier is
  // called.
  //
  // Failure modes collapse to a generic 401 the same way passkey
  // login does, so no information about WHY the step-up failed
  // leaks (unknown credential vs. wrong user vs. bad signature
  // vs. expired challenge are all "Step-up failed" to the client).
  // counter_replay still gets the special revoke+replay-detected path.
  app.post(
    "/api/passkeys/step-up/finish",
    jsonBody(PASSKEY_FINISH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const parsed = validatePasskeyLoginFinish(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        const { userId, sessionId } = auth;
        const clientIp = getClientIp(req);
        const userAgent = captureUserAgent(req);

        if (
          checkUserRateLimit("passkey_step_up_finish", clientIp, userId)
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }

        if (sessionId === null) {
          return res
            .status(400)
            .json({ error: "Session token required to step up" });
        }

        const stored = await storage.getCredentialById(parsed.data.response.id);
        // Credential lookup failures collapse to the same generic 401
        // as a verification failure. The user-mismatch branch is the
        // load-bearing security check (see endpoint comment above):
        // a valid assertion from credential C bound to user Z must
        // NOT satisfy step-up for an attacker session bound to user X.
        if (!stored || stored.userId !== userId) {
          recordAudit(storage, {
            userId,
            action: "passkey_step_up_failure",
            ipAddress: clientIp,
            userAgent,
          });
          // Extends the security model: count this attempt toward the
          // passkey-failure burst tracker. Step-up runs under an
          // authenticated session, so escalating with hardLock=true is
          // appropriate when the burst threshold is crossed (matches
          // the existing rate-spike escalation pattern in vault/sync).
          const burst = recordPasskeyFailure(userId);
          if (burst.burstMeta) {
            escalatePasskeyAnomaly(
              storage,
              userId,
              sessionId,
              clientIp,
              `${burst.burstMeta}; source=step_up`,
              { hardLock: true },
            );
          }
          return res.status(401).json({ error: "Step-up failed" });
        }

        const verified = await verifyAuthenticationResponseFor({
          userId,
          // Same passthrough/strict mismatch as the login verify
          // call: the validator's inner response uses .passthrough()
          // so authenticator extras survive, but SimpleWebAuthn's
          // AuthenticationResponseJSON narrows to known fields. The
          // runtime contract is unchanged — the verifier rejects
          // anything it doesn't understand.
          response: parsed.data.response as Parameters<
            typeof verifyAuthenticationResponseFor
          >[0]["response"],
          request: req,
          storedCredential: {
            credentialId: stored.credentialId,
            publicKey: stored.publicKey,
            counter: stored.counter,
            transports: stored.transports,
          },
        });

        if (!verified.ok) {
          if (verified.code === "counter_replay") {
            // Counter regression / replay — same severity here as on
            // /api/passkeys/login/finish. Revoke the credential
            // (best-effort; swallow storage errors so a DB hiccup
            // can't be used to KEEP a compromised credential alive)
            // and emit the anomaly, the revocation, and the
            // step-up failure events so the audit log shows what
            // happened and that the step-up itself was denied.
            //
            // Audit metadata is intentionally MINIMAL: no
            // credentialId and no public key — those are sensitive
            // attributes of the credential and have no business in
            // an audit row. `source=step_up` is enough context for
            // an operator to tell which flow triggered it.
            let revoked = false;
            try {
              revoked = await storage.revokeCredential(stored.credentialId);
            } catch (revokeErr) {
              console.error(
                "Failed to revoke credential after counter replay during step-up",
              );
            }
            recordAudit(storage, {
              userId,
              action: "passkey_counter_replay_detected",
              ipAddress: clientIp,
              userAgent: `source=step_up`,
            });
            if (revoked) {
              recordAudit(storage, {
                userId,
                action: "passkey_revoked",
                ipAddress: clientIp,
                userAgent: `reason=counter_replay; source=step_up`,
              });
            }
            recordAudit(storage, {
              userId,
              action: "passkey_step_up_failure",
              ipAddress: clientIp,
              userAgent,
            });
            // Replay detection is a single-event signal — escalate
            // unconditionally with the hard soft-lock. The credential
            // is already revoked above, so this lock primarily
            // protects the user's WRITE surface for 5 min while they
            // notice the activity-log entry and react.
            escalatePasskeyAnomaly(
              storage,
              userId,
              sessionId,
              clientIp,
              `passkey replay detected; source=step_up`,
              { hardLock: true },
            );
            return res.status(401).json({ error: "Step-up failed" });
          }
          if (verified.code === "internal_error") {
            console.error("Passkey step-up verify internal_error");
          }
          recordAudit(storage, {
            userId,
            action: "passkey_step_up_failure",
            ipAddress: clientIp,
            userAgent,
          });
          // Same failure-burst tracking as the credential-mismatch
          // branch above. Verifier failures (no_challenge,
          // challenge_expired, verification_failed, internal_error)
          // are still ATTEMPTS from the user's perspective and count
          // the same. counter_replay is handled separately above and
          // does NOT count here (it has its own single-event escalation).
          const burst = recordPasskeyFailure(userId);
          if (burst.burstMeta) {
            escalatePasskeyAnomaly(
              storage,
              userId,
              sessionId,
              clientIp,
              `${burst.burstMeta}; source=step_up`,
              { hardLock: true },
            );
          }
          return res.status(401).json({ error: "Step-up failed" });
        }

        // Persist the new signCount BEFORE marking the session.
        // Same reasoning as /api/passkeys/login/finish: if we mark
        // the session step-up-verified but fail to advance the
        // counter, the same assertion could be replayed against a
        // future step-up on this same credential. Counter
        // persistence is therefore on the critical path; a write
        // failure is a real 500, not the generic 401.
        let counterAdvancedStepUp = false;
        try {
          counterAdvancedStepUp = await storage.updateCredentialCounter(
            stored.credentialId,
            verified.newCounter,
          );
        } catch (counterErr) {
          console.error(
            "Failed to persist new signCount after passkey step-up verify",
          );
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }
        if (!counterAdvancedStepUp) {
          // T002 hardening: the conditional UPDATE matched zero rows
          // — a concurrent assertion for the same credential won
          // the race and already wrote the new counter. From the
          // server's perspective THIS step-up assertion is a replay
          // (the counter we'd write is no longer ahead of stored),
          // even though the SimpleWebAuthn verifier individually
          // accepted both. Treat it the same as the explicit
          // counter_replay branch above: revoke the credential,
          // emit replay + revoked + step_up_failure audits, and
          // escalate with a hard soft-lock. Best-effort revoke —
          // a DB hiccup must not let us KEEP a compromised
          // credential alive.
          let raceRevoked = false;
          try {
            raceRevoked = await storage.revokeCredential(stored.credentialId);
          } catch (revokeErr) {
            console.error(
              "Failed to revoke credential after T002 race during step-up",
            );
          }
          recordAudit(storage, {
            userId,
            action: "passkey_counter_replay_detected",
            ipAddress: clientIp,
            userAgent: `source=step_up; reason=race`,
          });
          if (raceRevoked) {
            recordAudit(storage, {
              userId,
              action: "passkey_revoked",
              ipAddress: clientIp,
              userAgent: `reason=counter_replay; source=step_up; race=true`,
            });
          }
          recordAudit(storage, {
            userId,
            action: "passkey_step_up_failure",
            ipAddress: clientIp,
            userAgent,
          });
          escalatePasskeyAnomaly(
            storage,
            userId,
            sessionId,
            clientIp,
            `passkey replay race detected; source=step_up`,
            { hardLock: true },
          );
          return res.status(401).json({ error: "Step-up failed" });
        }

        const verifiedUntil = Date.now() + STEP_UP_TTL_MS;
        // markSessionTotpVerified writes the same column whose
        // legacy name suggests TOTP — we reuse it deliberately so
        // both factors satisfy the same downstream gates without
        // any schema change. Returns false on DB error (errors
        // swallowed inside the storage layer); surface that as 500
        // so the user can retry rather than discovering the failure
        // on their next sensitive write. The success-only audit
        // pattern matches the TOTP step-up endpoint: an operator
        // can distinguish "user attempted step-up but DB dropped
        // it" from "user successfully stepped up".
        const persisted = await storage.markSessionTotpVerified(
          sessionId,
          verifiedUntil,
        );
        if (!persisted) {
          recordAudit(storage, {
            userId,
            action: "passkey_step_up_failure",
            ipAddress: clientIp,
            userAgent: `reason=persist_failed`,
          });
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }
        recordAudit(storage, {
          userId,
          action: "passkey_step_up_success",
          ipAddress: clientIp,
          userAgent,
        });
        // Successful step-up = clean possession proof. T006 hardening:
        // DECAY (not full-reset) the failure-burst counter so an
        // attacker can't launder a long streak with a single
        // successful tap. See decayPasskeyFailures for rationale.
        decayPasskeyFailures(userId);

        return res.status(200).json({
          success: true,
          verifiedUntil,
        });
      } catch (err) {
        console.error("Passkey step-up finish error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/passkeys/register/start — auth required. Mints a fresh
  // WebAuthn registration challenge for the current user and returns
  // the PublicKeyCredentialCreationOptions JSON for the client to
  // hand to navigator.credentials.create(). The challenge is held
  // in process memory (5 min TTL, single-use) — see server/webauthn.ts.
  //
  // Body: empty object. Strict-validated so a stray field is a 400.
  //
  // The response includes the user's existing credentialIds in
  // excludeCredentials so the authenticator refuses to create a
  // duplicate passkey on the same device — a real WebAuthn UX
  // defense, not just a server-side check. We pull that list from
  // listCredentialsForUser (which already filters out revoked rows).
  app.post(
    "/api/passkeys/register/start",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const parsed = validatePasskeyRegisterStart(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        const { userId } = auth;

        if (
          checkUserRateLimit(
            "passkey_register_start",
            getClientIp(req),
            userId,
          )
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }

        const user = await storage.getUser(userId);
        if (!user) {
          // Session was valid at authenticate() time but the user row
          // is gone now (concurrent account deletion). Same single-
          // shape 401 the rest of the auth-required endpoints emit.
          return res.status(401).json({ error: "Invalid credentials" });
        }

        const existing = await storage.listCredentialsForUser(userId);
        const excludeCredentialIds = existing.map((c) => c.credentialId);

        const result = await generateRegistrationOptionsFor({
          userId,
          username: user.username,
          request: req,
          excludeCredentialIds,
        });
        if (!result.ok) {
          // generateRegistrationOptionsFor returns a structured error
          // rather than throwing. The reason is logged inside
          // server/webauthn.ts; surface a single-shape 500 to the
          // client.
          console.error(
            `passkey register/start failed: code=${result.code}`,
          );
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }

        return res.status(200).json(result.options);
      } catch (err) {
        console.error("Passkey register/start error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/passkeys/register/finish — auth required. Verifies the
  // attestation the client got back from navigator.credentials.create()
  // against the challenge stored at /start, then persists the new
  // credential row. The challenge is single-use: a successful verify
  // (or any verify attempt — see consumeChallenge in webauthn.ts)
  // deletes it so the same /start cannot be replayed against /finish.
  //
  // Body: { response: <RegistrationResponseJSON>, deviceName?: string }.
  // The deviceName is the user-supplied label that will appear in the
  // passkeys management screen (e.g. "iPhone 15", "YubiKey"); optional,
  // bounded 1-128 chars.
  //
  // Failure modes:
  //   - Malformed body                                → 400
  //   - No matching challenge (expired or never set) → 400
  //   - Verifier rejected the attestation             → 400
  //   - Origin / RP id mismatch                       → 400
  //   - Internal verifier error                       → 500
  //   - Credential already registered (race)          → 409
  //
  // Per spec / task: the publicKey is NEVER echoed back in the
  // response — only the credentialId and the user-visible deviceName.
  app.post(
    "/api/passkeys/register/finish",
    jsonBody(PASSKEY_FINISH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const parsed = validatePasskeyRegisterFinish(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        const auth = await authenticate(req, storage);
        if (!auth.ok) {
          return res.status(auth.status).json({ error: auth.error });
        }
        const { userId } = auth;

        if (
          checkUserRateLimit(
            "passkey_register_finish",
            getClientIp(req),
            userId,
          )
        ) {
          return res.status(429).json({ error: "Too many requests" });
        }

        const verified = await verifyRegistrationResponseFor({
          userId,
          // Cast: the validator strict-checks the outer envelope and
          // requires non-empty clientDataJSON / attestationObject in
          // the inner response, but uses .passthrough() on the inner
          // object so authenticator-specific extensions survive.
          // SimpleWebAuthn's RegistrationResponseJSON narrows to
          // exact known fields, so TS can't see the extra-keys case.
          // The verifier itself rejects anything that isn't a valid
          // attestation, so the runtime contract is preserved.
          response: parsed.data.response as Parameters<
            typeof verifyRegistrationResponseFor
          >[0]["response"],
          request: req,
        });

        if (!verified.ok) {
          // Map verifier outcomes to HTTP status. We deliberately
          // collapse "no challenge" / "verification_failed" /
          // "origin_mismatch" / "rp_mismatch" into a single 400 with
          // a generic error so an attacker probing the endpoint can't
          // distinguish "I sent a bogus response" from "the challenge
          // expired" — both reduce to "this attempt didn't work, do
          // /start again". Internal errors (library/runtime) surface
          // as 500 so the client knows a retry is appropriate.
          if (verified.code === "internal_error") {
            console.error(
              `passkey register/finish internal error: ${verified.reason ?? "unknown"}`,
            );
            return res
              .status(500)
              .json({ error: "Internal server error" });
          }
          return res
            .status(400)
            .json({ error: "Passkey registration failed" });
        }

        // Persist. The unique constraint on credential_id will reject
        // a duplicate at the DB level — surface as 409 so the client
        // can present a meaningful "this passkey is already
        // registered" instead of a misleading 500. Any other DB error
        // is a real internal failure.
        try {
          await storage.createWebAuthnCredential({
            userId,
            credentialId: verified.credential.credentialId,
            publicKey: verified.credential.publicKey,
            counter: verified.credential.counter,
            deviceName: parsed.data.deviceName ?? null,
            transports: verified.credential.transports,
          });
        } catch (err) {
          const e = err as { code?: string };
          if (e?.code === "23505") {
            return res
              .status(409)
              .json({ error: "Passkey already registered" });
          }
          throw err;
        }

        // Audit AFTER the persist succeeds — a credential row that
        // exists must always be paired with a passkey_registered
        // event. recordAudit is fire-and-forget (errors swallowed
        // inside) so it never blocks the 200.
        recordAudit(storage, {
          userId,
          action: "passkey_registered",
          ipAddress: getClientIp(req),
          userAgent: captureUserAgent(req),
        });

        // DO NOT return the publicKey or counter — both are internal
        // state. The credentialId is fine (the client already saw it
        // when the authenticator returned the assertion) and the
        // deviceName is the label the user themselves supplied.
        return res.status(201).json({
          success: true,
          credentialId: verified.credential.credentialId,
          deviceName: parsed.data.deviceName ?? null,
        });
      } catch (err) {
        console.error("Passkey register/finish error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/passkeys/login/start — UNAUTHENTICATED. The whole point
  // of passkey login is that the client doesn't have a session yet;
  // they're trying to mint one via the assertion. Body carries just
  // the username (so we can scope the challenge + load the user's
  // allowed credential ids for the authenticator allowlist).
  //
  // Failure shape is generic by design (everything that goes wrong
  // here — unknown user, no passkeys registered, internal options
  // generation error — collapses into the same 401 the password
  // login flow uses) so an attacker probing usernames cannot tell
  // "this user doesn't exist" from "this user exists but has no
  // passkey configured". The username enumeration surface is no
  // worse than the existing /api/auth/login (which already returns
  // 401 on unknown user); keeping the shape identical means a
  // probe of one is indistinguishable from a probe of the other.
  app.post(
    "/api/passkeys/login/start",
    jsonBody(AUTH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const clientIp = getClientIp(req);
        // Reuse the existing per-IP `login:` bucket — passkey login
        // and password login are two paths to the same outcome
        // (a fresh session for the same user), so a single bucket
        // prevents an attacker from doubling their guess budget by
        // alternating between the two endpoints.
        if (isRateLimited(`login:${clientIp}`)) {
          return res
            .status(429)
            .json({ error: "Too many attempts. Please try again later." });
        }
        // Adaptive IP threat block — same shape as /api/auth/login.
        // Shared block bucket across all 4 login entry points so an
        // attacker can't bypass via endpoint switching.
        if (isIpBlocked(clientIp)) {
          return await ipBlockResponse(res, clientIp);
        }

        const parsed = validatePasskeyLoginStart(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        // T007 hardening: uniform random delay before the user
        // lookup. Equalises timing for "unknown user", "user with
        // no passkeys", and "valid user with credentials" so a
        // probe can't tell them apart by latency. 429 + 400 above
        // are not delayed — they don't leak user existence. Failure
        // paths additionally apply adaptiveLoginDelay(clientIp)
        // before responding for per-failure-count friction.
        await uniformLoginDelay();

        const { username } = parsed.data;

        const user = await storage.getUserByUsername(username);
        if (!user) {
          // No audit event here: we have no userId to attach it to
          // and an audit row keyed off "the username an attacker
          // guessed" would itself become a username-enumeration
          // oracle (visible to anyone with admin DB access).
          // Adaptive IP threat: hashed-username probe still counts
          // toward the credential-stuffing cardinality threshold —
          // an attacker spraying random usernames at the passkey
          // start endpoint is the textbook stuffing pattern.
          recordIpFailure(
            storage,
            clientIp,
            hashUsernameForIpThreat(username),
            null,
          );
          await adaptiveLoginDelay(clientIp);
          return res.status(401).json({ error: "Invalid credentials" });
        }

        const credentials = await storage.listCredentialsForUser(user.id);
        if (credentials.length === 0) {
          // User exists but has no usable passkeys. We DO audit this
          // (under the real userId) so the legitimate user sees the
          // probe in their activity log, but the client response is
          // the same generic 401 — never leak "this account has no
          // passkey configured".
          recordAudit(storage, {
            userId: user.id,
            action: "passkey_login_failure",
            ipAddress: clientIp,
            userAgent: captureUserAgent(req),
          });
          // Unified login_failed companion event — see the password
          // login failure path for the full rationale. Both rows
          // are emitted so a client filtering on either action sees
          // the probe; both share the same (user, ip, minute)
          // dedup window via shouldRecordAuditEvent.
          recordAudit(storage, {
            userId: user.id,
            action: "login_failed",
            ipAddress: clientIp,
            userAgent: `reason=invalid_credentials; ua=${(captureUserAgent(req) ?? "").slice(0, 200)}`,
          });
          // Failure-burst tracking with hardLock=false. This is the
          // unauthenticated path: an attacker who knows a victim
          // username + can rotate IPs could otherwise trigger a
          // soft-lock against the legitimate user's writes — a
          // remote DoS vector. Painting securityLevel "elevated" +
          // emitting anomaly_detected still surfaces the burst in
          // the user's activity log; the per-IP `login:` rate limit
          // upstream is the primary defense against the brute force
          // itself.
          const burst = recordPasskeyFailure(user.id);
          if (burst.burstMeta) {
            escalatePasskeyAnomaly(
              storage,
              user.id,
              null,
              clientIp,
              `${burst.burstMeta}; source=login_start`,
              { hardLock: false },
            );
          }
          // Adaptive IP threat: real userId so an ip_threat_detected
          // row attaches here. Note: a user with no passkeys is a
          // valid login_failed signal — distinct from "user not
          // found" — and contributes one distinct target to this
          // IP's stuffing cardinality.
          recordIpFailure(storage, clientIp, user.id, user.id);
          await adaptiveLoginDelay(clientIp);
          return res.status(401).json({ error: "Invalid credentials" });
        }

        const result = await generateAuthenticationOptionsFor({
          userId: user.id,
          request: req,
          allowCredentialIds: credentials.map((c) => ({
            id: c.credentialId,
            transports: c.transports,
          })),
        });
        if (!result.ok) {
          // Internal failure inside the helper. Surface as 500 (this
          // is a real server problem, not a credential failure) but
          // don't echo the underlying reason to the client.
          console.error(
            `passkey login/start failed: code=${result.code}`,
          );
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }

        return res.status(200).json(result.options);
      } catch (err) {
        console.error("Passkey login/start error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  // POST /api/passkeys/login/finish — UNAUTHENTICATED. The assertion
  // IS the auth: the client posts what `navigator.credentials.get()`
  // returned and we verify the signature against the stored public
  // key + active challenge. On success we mint a regular session row
  // (same shape as /api/auth/login) and return the session token.
  //
  // Failure handling is deliberately uniform: every failure path
  // — unknown credential, expired/missing challenge, signature
  // verification failed, counter replay, internal verifier error —
  // returns the same 401 with a single generic error string. The
  // detail goes to the audit log (under the credential's owner)
  // and the server console, never to the client.
  //
  // Counter-replay is special-cased BEFORE the generic failure
  // bucket: a counter that didn't advance is the WebAuthn anti-
  // replay signal, and the credential is immediately revoked +
  // an anomaly is audited. The client still gets the same 401.
  //
  // Note on TOTP: a successful passkey assertion is itself a
  // multi-factor proof (the credential is something-you-have, the
  // authenticator's UV is something-you-are/know), so this path
  // does NOT gate on user.totpEnabled the way /api/auth/login
  // does. The session it creates is fully authenticated.
  app.post(
    "/api/passkeys/login/finish",
    jsonBody(PASSKEY_FINISH_BODY_LIMIT),
    async (req: Request, res: Response) => {
      try {
        const queryCheck = validateNoQueryParams(req);
        if (!queryCheck.ok) {
          return res.status(400).json({ error: queryCheck.error });
        }

        const clientIp = getClientIp(req);
        if (isRateLimited(`login:${clientIp}`)) {
          return res
            .status(429)
            .json({ error: "Too many attempts. Please try again later." });
        }
        // Adaptive IP threat block — same shape as /api/auth/login.
        // Shared block bucket across all 4 login entry points so an
        // attacker can't bypass via endpoint switching.
        if (isIpBlocked(clientIp)) {
          return await ipBlockResponse(res, clientIp);
        }

        const parsed = validatePasskeyLoginFinish(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ error: parsed.error });
        }

        // T007 hardening: uniform random delay before the credential
        // lookup. Equalises timing for "unknown credential id",
        // "user mismatch", "verifier failure", "counter replay",
        // "TOTP gate", and "success". 429 + 400 above are not
        // delayed. Failure paths additionally apply
        // adaptiveLoginDelay(clientIp) before responding for
        // per-failure-count friction.
        await uniformLoginDelay();

        // The browser hands us back the credential id it used. Look
        // it up — getCredentialById already filters out revoked
        // rows, so a previously-revoked credential reads as
        // "unknown" with no special-case branch needed.
        const stored = await storage.getCredentialById(
          parsed.data.response.id,
        );
        if (!stored) {
          // No audit row: we have no userId to attach it to (the
          // credential is unknown). Generic 401.
          return res.status(401).json({ error: "Invalid credentials" });
        }

        const userAgent = captureUserAgent(req);
        const auditUserAgent = captureAuditUserAgent(req);

        const verified = await verifyAuthenticationResponseFor({
          userId: stored.userId,
          // Same passthrough/strict mismatch as the registration
          // verify call: the validator's inner response uses
          // .passthrough() so authenticator extras survive, but
          // SimpleWebAuthn's AuthenticationResponseJSON type
          // narrows to known fields. The runtime contract is
          // unchanged — the verifier rejects anything it doesn't
          // understand.
          response: parsed.data.response as Parameters<
            typeof verifyAuthenticationResponseFor
          >[0]["response"],
          request: req,
          storedCredential: {
            credentialId: stored.credentialId,
            publicKey: stored.publicKey,
            counter: stored.counter,
            transports: stored.transports,
          },
        });

        if (!verified.ok) {
          // Counter replay: the WebAuthn library raised the
          // signCount-didn't-advance signal. This is a strong
          // indicator the credential has been cloned (or replayed
          // from a captured assertion). Revoke it immediately so
          // it cannot authenticate again, and audit a distinct
          // anomaly event so the user can see what happened.
          // The credential's owner sees both the anomaly and the
          // generic failure rows in their activity log.
          if (verified.code === "counter_replay") {
            // Same minimal-metadata rule as the step-up flow:
            // never log credentialId or public key in the audit
            // userAgent field. The client UA captured at the
            // request boundary is fine — that's not a sensitive
            // credential attribute.
            let revoked = false;
            try {
              revoked = await storage.revokeCredential(stored.credentialId);
            } catch (revokeErr) {
              // Revoke is best-effort here — even if it fails the
              // client still sees a 401 and we still emit the audit
              // row. A second clone-replay attempt would simply hit
              // the same revoke path.
              console.error(
                "Failed to revoke credential after counter replay",
              );
            }
            recordAudit(storage, {
              userId: stored.userId,
              action: "passkey_counter_replay_detected",
              ipAddress: clientIp,
              userAgent,
            });
            if (revoked) {
              recordAudit(storage, {
                userId: stored.userId,
                action: "passkey_revoked",
                ipAddress: clientIp,
                userAgent: `reason=counter_replay; source=login`,
              });
            }
            recordAudit(storage, {
              userId: stored.userId,
              action: "passkey_login_failure",
              ipAddress: clientIp,
              userAgent,
            });
            // Unified login_failed companion event — see the password
            // login failure path for the full rationale.
            recordAudit(storage, {
              userId: stored.userId,
              action: "login_failed",
              ipAddress: clientIp,
              userAgent: `reason=invalid_credentials; ua=${(userAgent ?? "").slice(0, 200)}`,
            });
            // Replay = single-event high-confidence signal. Escalate
            // with hardLock=true even though this is the unauth path:
            // counter_replay is essentially never benign (a cloned or
            // captured-then-replayed assertion), the credential is
            // already revoked above, and the soft-lock guards the
            // owner's WRITE surface for 5 min while they read the
            // activity log entry. sessionId is null here — login
            // mints a new session on success, never on failure.
            escalatePasskeyAnomaly(
              storage,
              stored.userId,
              null,
              clientIp,
              `passkey replay detected; source=login`,
              { hardLock: true },
            );
            // Adaptive IP threat: explicit counter_replay = same
            // severity as a verifier failure for IP-block purposes.
            recordIpFailure(storage, clientIp, stored.userId, stored.userId);
            await adaptiveLoginDelay(clientIp);
            return res
              .status(401)
              .json({ error: "Invalid credentials" });
          }

          // All other verifier failures (no_challenge,
          // challenge_expired, verification_failed, internal_error)
          // collapse into the same 401. We DO emit the failure
          // audit so the legitimate owner sees probe attempts.
          recordAudit(storage, {
            userId: stored.userId,
            action: "passkey_login_failure",
            ipAddress: clientIp,
            userAgent,
          });
          // Unified login_failed companion event — see the password
          // login failure path for the full rationale.
          recordAudit(storage, {
            userId: stored.userId,
            action: "login_failed",
            ipAddress: clientIp,
            userAgent: `reason=invalid_credentials; ua=${(userAgent ?? "").slice(0, 200)}`,
          });
          if (verified.code === "internal_error") {
            console.error(
              `passkey login/finish internal error: ${verified.reason ?? "unknown"}`,
            );
          }
          // Same failure-burst tracking + hardLock=false reasoning as
          // the login/start no-credentials branch above. counter_replay
          // is handled separately and does NOT count here.
          const burst = recordPasskeyFailure(stored.userId);
          if (burst.burstMeta) {
            escalatePasskeyAnomaly(
              storage,
              stored.userId,
              null,
              clientIp,
              `${burst.burstMeta}; source=login_finish`,
              { hardLock: false },
            );
          }
          // Adaptive IP threat: verifier failure attaches to the
          // credential's owner. Real userId so an ip_threat_detected
          // row can fire here.
          recordIpFailure(storage, clientIp, stored.userId, stored.userId);
          await adaptiveLoginDelay(clientIp);
          return res.status(401).json({ error: "Invalid credentials" });
        }

        // Verified. Persist the new signCount BEFORE issuing the
        // session OR the temp token — if the counter update fails
        // we MUST NOT advance the flow, because the next assertion
        // attempt would let the same counter value through again
        // (replay vector). If the update throws we surface a 500
        // (real server failure) rather than the generic 401: the
        // credential is valid, the storage layer just couldn't
        // write.
        let counterAdvancedLogin = false;
        try {
          counterAdvancedLogin = await storage.updateCredentialCounter(
            stored.credentialId,
            verified.newCounter,
          );
        } catch (counterErr) {
          console.error(
            "Failed to persist new signCount after passkey verify",
          );
          return res
            .status(500)
            .json({ error: "Internal server error" });
        }
        if (!counterAdvancedLogin) {
          // T002 hardening: conditional UPDATE matched zero rows —
          // a concurrent login-assertion for the same credential
          // won the race. Treat THIS attempt as replay, even though
          // the verifier accepted it independently (same rationale
          // as the step-up handler). Revoke + audit + escalate.
          // sessionId is null on the unauth login path; hardLock=true
          // matches the explicit counter_replay branch above —
          // counter_replay is essentially never benign and the
          // credential is already revoked here.
          let raceRevoked = false;
          try {
            raceRevoked = await storage.revokeCredential(stored.credentialId);
          } catch (revokeErr) {
            console.error(
              "Failed to revoke credential after T002 race during login",
            );
          }
          recordAudit(storage, {
            userId: stored.userId,
            action: "passkey_counter_replay_detected",
            ipAddress: clientIp,
            userAgent: `source=login; reason=race`,
          });
          if (raceRevoked) {
            recordAudit(storage, {
              userId: stored.userId,
              action: "passkey_revoked",
              ipAddress: clientIp,
              userAgent: `reason=counter_replay; source=login; race=true`,
            });
          }
          recordAudit(storage, {
            userId: stored.userId,
            action: "passkey_login_failure",
            ipAddress: clientIp,
            userAgent,
          });
          // Unified login_failed companion event — see the password
          // login failure path for the full rationale.
          recordAudit(storage, {
            userId: stored.userId,
            action: "login_failed",
            ipAddress: clientIp,
            userAgent: `reason=invalid_credentials; ua=${(userAgent ?? "").slice(0, 200)}`,
          });
          escalatePasskeyAnomaly(
            storage,
            stored.userId,
            null,
            clientIp,
            `passkey replay race detected; source=login`,
            { hardLock: true },
          );
          // Adaptive IP threat: race-replay is a counter_replay
          // variant, same severity for IP-block purposes. Swap the
          // pre-existing uniformLoginDelay (added by T007) for
          // adaptiveLoginDelay so the per-failure friction also
          // attaches to this branch.
          recordIpFailure(storage, clientIp, stored.userId, stored.userId);
          await adaptiveLoginDelay(clientIp);
          return res.status(401).json({ error: "Invalid credentials" });
        }

        // TOTP gate. The verifier currently runs with
        // requireUserVerification: false, which means an assertion
        // may have been satisfied by user-presence alone (e.g. a
        // YubiKey touch with no PIN configured) rather than a true
        // user-verification (biometric/PIN). In that case the
        // assertion is single-factor — possession only. If the
        // user has explicitly enabled TOTP, we MUST NOT downgrade
        // their security posture by issuing a session on a
        // single-factor proof: surface the same tempToken /
        // requiresTOTP flow the password login uses. The client
        // then completes the second factor via
        // /api/auth/totp/login. We DO emit the success audit so
        // the activity log records "the passkey check passed";
        // the totp_required event is added for parity with the
        // password path so a reader of the audit log can see
        // which gate the user is sitting at.
        const owner = await storage.getUser(stored.userId);
        if (owner?.totpEnabled === true) {
          const rawTempToken = randomBytes(32).toString("hex");
          const tempTokenHash = createHash("sha256")
            .update(rawTempToken)
            .digest("hex");
          tempLoginTokens.set(tempTokenHash, {
            tokenHash: tempTokenHash,
            userId: stored.userId,
            expiresAt: Date.now() + TEMP_LOGIN_TTL_MS,
          });
          recordAudit(storage, {
            userId: stored.userId,
            action: "passkey_login_success",
            ipAddress: clientIp,
            userAgent,
          });
          recordAudit(storage, {
            userId: stored.userId,
            action: "totp_required",
            ipAddress: clientIp,
            userAgent,
          });
          // Passkey assertion verified — decay the failure-burst
          // counter (T006: not a full reset) even though TOTP is
          // still pending. The passkey half is proven; the streak
          // budget is reduced by one so an alternating fail/succeed
          // pattern still trips the burst eventually.
          decayPasskeyFailures(stored.userId);
          // The ABSENCE of sessionToken is the signal that more
          // factors are needed. requiresTOTP + tempToken matches
          // /api/auth/login's 2FA-required response shape exactly.
          return res.status(200).json({
            requiresTOTP: true,
            tempToken: rawTempToken,
            tempTokenExpiresAt: Date.now() + TEMP_LOGIN_TTL_MS,
          });
        }

        // No TOTP gate. Mint a session: same shape as /api/auth/login. Token is
        // 32 random bytes hex; we persist only the SHA-256 hash so
        // a DB leak cannot impersonate the user. Device-trust
        // decision happens here, BEFORE createSession, so the row
        // is correctly stamped trusted=true|false at insert time.
        const rawToken = randomBytes(32).toString("hex");
        const tokenHash = createHash("sha256")
          .update(rawToken)
          .digest("hex");
        const deviceFingerprint = getDeviceFingerprint(req);
        const isKnownDevice = await storage.hasDeviceFingerprintForUser(
          stored.userId,
          deviceFingerprint,
        );
        const session = await storage.createSession({
          userId: stored.userId,
          tokenHash,
          expiresAt: Date.now() + SESSION_LIFETIME_MS,
          userAgent,
          ipAddress: clientIp,
          deviceFingerprint,
          trusted: isKnownDevice,
        });

        // Audit AFTER the session is persisted: passkey_login_success
        // is the credential-exchange event, session_created is the
        // session-row event (matching the password login pattern).
        // Both fire-and-forget.
        recordAudit(storage, {
          userId: stored.userId,
          action: "passkey_login_success",
          ipAddress: clientIp,
          userAgent: auditUserAgent,
        });
        recordAudit(storage, {
          userId: stored.userId,
          action: "session_created",
          ipAddress: clientIp,
          userAgent: auditUserAgent,
        });
        // Successful full-session passkey login = clean possession
        // proof. T006: decay (not full-reset) the failure-burst
        // counter so an attacker can't launder a long streak with
        // a single tap.
        decayPasskeyFailures(stored.userId);
        // Adaptive IP threat decay (T008) — see /api/auth/login.
        // Only the full-session success path decays; the
        // TOTP-required half-success above defers decay to the
        // /api/auth/totp/login completion, mirroring the
        // password→TOTP path.
        recordIpSuccess(clientIp);
        if (!isKnownDevice) {
          // Mirror the new-device handling from /api/auth/login:
          // log the event, raise the in-memory threat signal, and
          // mark the session untrusted so sync/restore are gated
          // until the user explicitly approves the device. Same
          // rationale as the password login path — a brand-new
          // device is not a hard fail, but writes are gated.
          recordAudit(storage, {
            userId: stored.userId,
            action: "new_device_detected",
            ipAddress: clientIp,
            userAgent: appendInstallIdMetadata(
              req,
              `fingerprint=${deviceFingerprint.slice(0, 16)}`,
            ),
          });
          recordSecuritySignalHit(stored.userId, session.id, false);
          recordUntrustedSession(stored.userId, session.id);
        }

        // 200 (not 201): we are issuing a session, not creating a
        // new persistent resource the client can address by id —
        // matches /api/auth/login's status code exactly. Response
        // shape is the minimal set the spec requires
        // (sessionToken + expiresAt). NOT echoed: the credential
        // public key (never), the credential's internal id, or the
        // updated counter — all are server-side state.
        return res.status(200).json({
          sessionToken: rawToken,
          expiresAt: session.expiresAt,
        });
      } catch (err) {
        console.error("Passkey login/finish error");
        return res.status(500).json({ error: "Internal server error" });
      }
    },
  );

  app.get("/api/health", (req: Request, res: Response) => {
    const queryCheck = validateNoQueryParams(req);
    if (!queryCheck.ok) {
      return res.status(400).json({ error: queryCheck.error });
    }
    return res.status(200).json({ status: "ok", timestamp: Date.now() });
  });

  // Catch-all for unknown /api/* paths. Without this, Express returns its
  // default text/html 404 page, which violates the API's "always JSON
  // { error: ... }" contract and could confuse a JSON-only client. Mounted
  // as middleware (rather than `app.all("/api/*", ...)`) for compatibility
  // with Express 5 / path-to-regexp v8, which no longer accepts the bare
  // wildcard syntax. Order-based: only requests that didn't match any of
  // the routes registered above reach this handler.
  app.use("/api", (_req: Request, res: Response) => {
    return res.status(404).json({ error: "Not found" });
  });

  const httpServer = createServer(app);
  return httpServer;
}
