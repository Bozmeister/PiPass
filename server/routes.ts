import express, { type Express, type Request, type Response } from "express";
import { createServer, type Server } from "node:http";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
import {
  SESSION_LIFETIME_MS,
  AUDIT_LOG_LIMIT,
  type AuditEventInput,
  type IStorage,
} from "./storage";
import {
  validateRegister,
  validateLogin,
  validateVaultSync,
  validateVaultRestore,
  validateUsernameParam,
  validateAuthHeaders,
  validateSessionTokenHeader,
  validateNoQueryParams,
} from "./validation";

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
  // this Set is purely a hot-path cache. Lost on restart — a fresh
  // process derives "normal" until a new anomaly fires (fail-open).
  suspiciousSessions: Set<string>;
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
    };
    userSecurityState.set(userId, s);
  }
  return s;
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
    if (
      s?.recentAnomalyAt !== undefined &&
      Date.now() - s.recentAnomalyAt <= ANOMALY_RECENT_WINDOW_MS
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
    }
  } catch {
    // Transition logging is purely diagnostic. A failure here must
    // NOT block the response — newLevel was already computed above.
  }
  return newLevel;
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
function recordAudit(storage: IStorage, input: AuditEventInput): void {
  storage.logAuditEvent(input).catch(() => {
    // Errors are already logged inside storage.logAuditEvent. The
    // additional .catch() here is just to absorb any rejection so it
    // can't surface as an unhandled promise rejection.
  });
}

// Result of authenticating a request via either session token (preferred)
// or legacy x-auth-hash. `sessionId` is populated only when the request
// authenticated via a session token — a logout endpoint can use this to
// know which session row to delete. The "401 vs 400" split lives here so
// every authenticated route returns consistent responses; see comments
// inside authenticate() for why.
type AuthResult =
  | { ok: true; userId: string; sessionId: string | null }
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
    return { ok: true, userId: session.userId, sessionId: session.id };
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
  return { ok: true, userId, sessionId: null };
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

      const parsed = validateLogin(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const { username, authHash } = parsed.data;

      const user = await storage.getUserByUsername(username);
      if (!user) {
        hashForComparison(authHash);
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = Buffer.from(user.authHash, "hex");

      if (providedHash.length !== storedHash.length || !timingSafeEqual(providedHash, storedHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Issue a fresh session: 32 random bytes (256 bits of entropy) hex-
      // encoded for transport. We persist ONLY the SHA-256 hash so a
      // database leak cannot impersonate the user — the raw token is shown
      // to the client exactly once, in this response, and never again.
      const rawToken = randomBytes(32).toString("hex");
      const tokenHash = createHash("sha256").update(rawToken).digest("hex");
      const session = await storage.createSession({
        userId: user.id,
        tokenHash,
        expiresAt: Date.now() + SESSION_LIFETIME_MS,
        userAgent: captureUserAgent(req),
        ipAddress: getClientIp(req),
      });

      // Audit hooks AFTER successful auth + session creation. Two
      // separate events per spec: login_success (the credential
      // exchange) and session_created (a new server-side session row).
      // Both fire-and-forget — the response is sent regardless.
      const ip = getClientIp(req);
      const userAgent = captureUserAgent(req);
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

      // syncVault is fully transactional: it locks the existing row,
      // verifies version monotonicity (CAS), archives the previous blob to
      // vault_blob_history, writes the new blob, and prunes history — all
      // atomically. We no longer need the read-then-CAS-then-recheck dance
      // here in the route. Returns either { ok:true, blob } or
      // { ok:false, code:"version_conflict", serverVersion }.
      const result = await storage.syncVault(
        userId,
        parsed.data.encryptedBlob,
        parsed.data.version,
      );
      if (!result.ok) {
        // Version conflict is NOT a successful sync — do not audit-log
        // it. Per spec we only log AFTER success to avoid noise and to
        // prevent enumeration via repeated failed attempts.
        return res.status(409).json({
          error: "Version conflict",
          serverVersion: result.serverVersion,
        });
      }

      // Audit + anomaly hooks AFTER success. blobSize is the actual
      // byte length of the encrypted blob the client just stored
      // (NOT the blob contents themselves — we never log those, that
      // would break zero-knowledge). versionBefore is captured inside
      // syncVault's transaction so it's race-free.
      const ip = getClientIp(req);
      const userAgent = captureUserAgent(req);
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
      const userAgent = captureUserAgent(req);
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

      if (!blob) {
        return res
          .status(200)
          .json({ encryptedBlob: null, version: 0, securityLevel });
      }

      return res.status(200).json({
        encryptedBlob: blob.encryptedBlob,
        version: blob.version,
        updatedAt: blob.updatedAt,
        securityLevel,
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
          return res.status(409).json({
            error: "Version conflict",
            serverVersion: result.serverVersion,
          });
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
        userAgent: captureUserAgent(req),
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
      return res.status(200).json({ sessions: list, securityLevel });
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
      return res
        .status(200)
        .json({ entries, hasRecentAnomalies, securityLevel });
    } catch (err) {
      console.error("Vault audit error");
      return res.status(500).json({ error: "Internal server error" });
    }
  });

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
