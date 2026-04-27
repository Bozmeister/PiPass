import express, { type Express, type Request, type Response } from "express";
import { createServer, type Server } from "node:http";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
import { SESSION_LIFETIME_MS, type IStorage } from "./storage";
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
        return res.status(409).json({
          error: "Version conflict",
          serverVersion: result.serverVersion,
        });
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
      if (!blob) {
        return res.status(200).json({ encryptedBlob: null, version: 0 });
      }

      return res.status(200).json({
        encryptedBlob: blob.encryptedBlob,
        version: blob.version,
        updatedAt: blob.updatedAt,
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

      // restoreVault is itself transactional and idempotent: it picks the
      // new vault version as max(currentVersion, targetVersion) + 1 so the
      // restore can never violate version monotonicity, archives the
      // displaced current blob first (a restore IS a write, so it must
      // itself be reversible), and prunes history. The historical entry
      // is looked up by (userId, targetVersion); if absent → 404.
      const result = await storage.restoreVault(userId, parsed.data.version);
      if (!result.ok) {
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
      return res.status(200).json(list);
    } catch (err) {
      console.error("List-sessions error");
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
