/**
 * Database connection policy: TLS mode, URL loading, and secret hygiene.
 *
 * Production defaults to encrypted connections with certificate
 * verification (`verify-full`). Local loopback and explicit
 * `DATABASE_SSL=disable` stay available for development and for
 * sidecar proxies (Cloud SQL Auth Proxy, etc.).
 *
 * The raw connection string is never interpolated into errors or logs.
 */

import { readFileSync } from "node:fs";
import type { ConnectionOptions } from "node:tls";

export type DatabaseSslMode = "disable" | "require" | "verify-full";

type EnvMap = Record<string, string | undefined>;

export type ResolvedDatabaseConfig = {
  connectionString: string;
  ssl: false | ConnectionOptions;
  sslMode: DatabaseSslMode;
  /** hostname:port only — never userinfo. */
  hostLabel: string;
};

const WEAK_PASSWORDS = new Set([
  "password",
  "pass",
  "secret",
  "changeme",
  "change-me",
  "change_me",
  "123456",
  "12345678",
  "admin",
  "postgres",
  "toor",
  "replace_with",
  "your_password",
  "your-password",
]);

export class DatabaseConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DatabaseConfigError";
  }
}

export function redactDatabaseUrl(raw: string): string {
  try {
    const url = new URL(raw);
    if (url.password) url.password = "****";
    if (url.username) url.username = "****";
    return url.toString();
  } catch {
    return "[unparseable-database-url]";
  }
}

function readOptionalFile(path: string, label: string): string {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    throw new DatabaseConfigError(
      `${label} could not be read. Check the path and file permissions.`,
    );
  }
}

export function loadDatabaseUrl(env: EnvMap = process.env): string {
  const fromEnv = env.DATABASE_URL?.trim();
  if (fromEnv) return fromEnv;

  const filePath = env.DATABASE_URL_FILE?.trim();
  if (filePath) {
    const fromFile = readOptionalFile(filePath, "DATABASE_URL_FILE");
    if (!fromFile) {
      throw new DatabaseConfigError(
        "DATABASE_URL_FILE is set but the file is empty.",
      );
    }
    return fromFile;
  }

  throw new DatabaseConfigError(
    "DATABASE_URL is not set. Provision a database before starting the server. " +
      "You may also set DATABASE_URL_FILE to a file that contains the URL " +
      "(Docker / Kubernetes secret mount).",
  );
}

function parsePostgresUrl(connectionString: string): URL {
  let url: URL;
  try {
    url = new URL(connectionString);
  } catch {
    throw new DatabaseConfigError(
      "DATABASE_URL is not a valid URL. Expected postgres:// or postgresql://.",
    );
  }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new DatabaseConfigError(
      "DATABASE_URL must use the postgres:// or postgresql:// scheme.",
    );
  }
  return url;
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "0.0.0.0"
  );
}

export function hostLabelFromUrl(connectionString: string): string {
  try {
    const url = new URL(connectionString);
    return url.host || "unknown";
  } catch {
    return "unknown";
  }
}

function sslModeFromQuery(raw: string | null): DatabaseSslMode | undefined {
  if (!raw) return undefined;
  switch (raw.trim().toLowerCase()) {
    case "disable":
    case "allow":
    case "prefer":
      return "disable";
    case "require":
    case "no-verify":
      return "require";
    case "verify-ca":
    case "verify-full":
    case "verify":
      return "verify-full";
    default:
      return undefined;
  }
}

function sslModeFromEnv(raw: string | undefined): DatabaseSslMode | "auto" | undefined {
  if (!raw) return undefined;
  const v = raw.trim().toLowerCase();
  if (v === "auto") return "auto";
  if (v === "disable") return "disable";
  if (v === "require" || v === "no-verify") return "require";
  if (v === "verify-full" || v === "verify-ca" || v === "verify") {
    return "verify-full";
  }
  throw new DatabaseConfigError(
    "DATABASE_SSL must be one of: disable, require, verify-full, auto.",
  );
}

function envFlag(env: EnvMap, name: string): boolean {
  const v = env[name]?.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

function loadCa(env: EnvMap): string | undefined {
  const inline = env.DATABASE_SSL_CA?.trim();
  if (inline) return inline.replace(/\\n/g, "\n");
  const filePath = env.DATABASE_SSL_CA_FILE?.trim();
  if (filePath) {
    const pem = readOptionalFile(filePath, "DATABASE_SSL_CA_FILE");
    if (!pem) {
      throw new DatabaseConfigError(
        "DATABASE_SSL_CA_FILE is set but the file is empty.",
      );
    }
    return pem;
  }
  return undefined;
}

export function resolveDatabaseSslMode(
  connectionString: string,
  env: EnvMap = process.env,
): DatabaseSslMode {
  const isProduction = env.NODE_ENV === "production";
  const url = parsePostgresUrl(connectionString);
  const loopback = isLoopbackHost(url.hostname);
  const fromUrl = sslModeFromQuery(url.searchParams.get("sslmode"));
  const fromEnv = sslModeFromEnv(env.DATABASE_SSL);

  let mode: DatabaseSslMode;
  if (fromEnv && fromEnv !== "auto") {
    mode = fromEnv;
  } else if (fromUrl) {
    mode = fromUrl;
  } else if (isProduction && !loopback) {
    mode = "verify-full";
  } else if (loopback) {
    mode = "disable";
  } else {
    // Remote host in development/test with no sslmode: encrypt, but
    // do not require a public CA (managed DBs often use sslmode=require).
    mode = "require";
  }

  if (mode === "disable" && isProduction && !loopback) {
    if (!envFlag(env, "DATABASE_SSL_ALLOW_INSECURE")) {
      throw new DatabaseConfigError(
        "Refusing a cleartext database connection in production. " +
          "Set DATABASE_SSL=require or DATABASE_SSL=verify-full, or put " +
          "sslmode=require on DATABASE_URL. Loopback hosts (local proxy) " +
          "are exempt. Override only with DATABASE_SSL_ALLOW_INSECURE=true.",
      );
    }
    console.error(
      "[db] WARNING: DATABASE_SSL_ALLOW_INSECURE=true — " +
        "production database traffic is NOT encrypted.",
    );
  }

  return mode;
}

function sslOptionsForMode(
  mode: DatabaseSslMode,
  env: EnvMap,
): false | ConnectionOptions {
  if (mode === "disable") return false;
  const ca = loadCa(env);
  if (mode === "require") {
    return { rejectUnauthorized: false };
  }
  return ca ? { rejectUnauthorized: true, ca } : { rejectUnauthorized: true };
}

export function assertDatabaseSecrets(
  connectionString: string,
  env: EnvMap = process.env,
): void {
  if (env.NODE_ENV !== "production") return;
  const url = parsePostgresUrl(connectionString);
  const password = decodeURIComponent(url.password);
  const username = decodeURIComponent(url.username);
  if (!password) {
    throw new DatabaseConfigError(
      "DATABASE_URL has an empty password. Production requires a real database secret.",
    );
  }
  if (WEAK_PASSWORDS.has(password.toLowerCase())) {
    throw new DatabaseConfigError(
      "DATABASE_URL uses a placeholder or well-known password. " +
        "Set a unique production credential (prefer DATABASE_URL_FILE or a secret manager).",
    );
  }
  if (
    username.toLowerCase() === "user" &&
    password.toLowerCase() === "password"
  ) {
    throw new DatabaseConfigError(
      "DATABASE_URL still has the .env.example credentials. " +
        "Replace them before running in production.",
    );
  }
}

export function resolveDatabaseConfig(
  env: EnvMap = process.env,
): ResolvedDatabaseConfig {
  const connectionString = loadDatabaseUrl(env);
  parsePostgresUrl(connectionString);
  assertDatabaseSecrets(connectionString, env);
  const sslMode = resolveDatabaseSslMode(connectionString, env);
  return {
    connectionString,
    sslMode,
    ssl: sslOptionsForMode(sslMode, env),
    hostLabel: hostLabelFromUrl(connectionString),
  };
}

export function poolConfigFromResolved(cfg: ResolvedDatabaseConfig): {
  connectionString: string;
  ssl?: ConnectionOptions;
} {
  return cfg.ssl === false
    ? { connectionString: cfg.connectionString }
    : { connectionString: cfg.connectionString, ssl: cfg.ssl };
}
