import express, { type Express, type Request, type Response } from "express";
import { createServer, type Server } from "node:http";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
import type { IStorage } from "./storage";
import {
  validateRegister,
  validateLogin,
  validateVaultSync,
  validateUsernameParam,
  validateHeaders,
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

function isRateLimited(key: string): boolean {
  if (RATE_LIMIT_DISABLED) return false;
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
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

      return res.status(200).json({
        id: user.id,
        username: user.username,
        salt: user.salt,
        iterations: user.iterations,
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

      const auth = validateHeaders(req);
      if (!auth.ok) {
        return res.status(400).json({ error: auth.error });
      }
      const { userId, authHash } = auth.data;

      // Validate body shape BEFORE any DB lookup. Per the hardening spec,
      // no malformed input should reach the storage layer — even a wasted
      // getUser() round-trip on a junk request is avoidable. Header/query
      // checks above are pure CPU; auth (which costs a DB read) only runs
      // once we know the request is structurally valid.
      const parsed = validateVaultSync(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const user = await storage.getUser(userId);
      if (!user) {
        // Collapse "user does not exist" into the same response as "wrong
        // password" so an attacker who somehow guesses a UUID cannot
        // distinguish a real account from a fake one.
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = Buffer.from(user.authHash, "hex");
      if (providedHash.length !== storedHash.length || !timingSafeEqual(providedHash, storedHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const existing = await storage.getVaultBlob(userId);
      if (existing && existing.version >= parsed.data.version) {
        return res.status(409).json({
          error: "Version conflict",
          serverVersion: existing.version,
        });
      }

      const blob = await storage.upsertVaultBlob(userId, parsed.data.encryptedBlob, parsed.data.version);
      if (!blob) {
        const current = await storage.getVaultBlob(userId);
        return res.status(409).json({
          error: "Version conflict",
          serverVersion: current?.version ?? 0,
        });
      }

      return res.status(200).json({
        version: blob.version,
        updatedAt: blob.updatedAt,
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

      const auth = validateHeaders(req);
      if (!auth.ok) {
        return res.status(400).json({ error: auth.error });
      }
      const { userId, authHash } = auth.data;

      const user = await storage.getUser(userId);
      if (!user) {
        // See sync handler — same defense-in-depth collapse.
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = Buffer.from(user.authHash, "hex");
      if (providedHash.length !== storedHash.length || !timingSafeEqual(providedHash, storedHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
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
