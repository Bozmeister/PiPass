import type { Express, Request, Response } from "express";
import { createServer, type Server } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { storage } from "./storage";
import { validateRegister, validateLogin, validateVaultSync } from "./validation";

function hashForComparison(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

export async function registerRoutes(app: Express): Promise<Server> {

  app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
      const parsed = validateRegister(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const { username, authHash, salt, iterations } = parsed.data;

      const existing = await storage.getUserByUsername(username);
      if (existing) {
        return res.status(409).json({ error: "Username already taken" });
      }

      const user = await storage.createUser({ username, authHash, salt, iterations });

      return res.status(201).json({
        id: user.id,
        username: user.username,
        salt: user.salt,
        iterations: user.iterations,
      });
    } catch (err) {
      console.error("Register error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/auth/login", async (req: Request, res: Response) => {
    try {
      const parsed = validateLogin(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const { username, authHash } = parsed.data;

      const user = await storage.getUserByUsername(username);
      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = hashForComparison(user.authHash);

      if (!timingSafeEqual(providedHash, storedHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      return res.status(200).json({
        id: user.id,
        username: user.username,
        salt: user.salt,
        iterations: user.iterations,
      });
    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/auth/salt/:username", async (req: Request, res: Response) => {
    try {
      const user = await storage.getUserByUsername(req.params.username);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      return res.status(200).json({
        salt: user.salt,
        iterations: user.iterations,
      });
    } catch (err) {
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/vault/sync", async (req: Request, res: Response) => {
    try {
      const userId = req.headers["x-user-id"] as string;
      const authHash = req.headers["x-auth-hash"] as string;

      if (!userId || !authHash) {
        return res.status(401).json({ error: "Authentication required" });
      }

      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ error: "Invalid user" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = hashForComparison(user.authHash);
      if (!timingSafeEqual(providedHash, storedHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const parsed = validateVaultSync(req.body);
      if (!parsed.ok) {
        return res.status(400).json({ error: parsed.error });
      }

      const existing = await storage.getVaultBlob(userId);
      if (existing && existing.version >= parsed.data.version) {
        return res.status(409).json({
          error: "Version conflict",
          serverVersion: existing.version,
        });
      }

      const blob = await storage.upsertVaultBlob(userId, parsed.data.encryptedBlob, parsed.data.version);

      return res.status(200).json({
        version: blob.version,
        updatedAt: blob.updatedAt,
      });
    } catch (err) {
      console.error("Vault sync error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/vault/fetch", async (req: Request, res: Response) => {
    try {
      const userId = req.headers["x-user-id"] as string;
      const authHash = req.headers["x-auth-hash"] as string;

      if (!userId || !authHash) {
        return res.status(401).json({ error: "Authentication required" });
      }

      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ error: "Invalid user" });
      }

      const providedHash = hashForComparison(authHash);
      const storedHash = hashForComparison(user.authHash);
      if (!timingSafeEqual(providedHash, storedHash)) {
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
      console.error("Vault fetch error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/health", (_req: Request, res: Response) => {
    return res.status(200).json({ status: "ok", timestamp: Date.now() });
  });

  const httpServer = createServer(app);
  return httpServer;
}
