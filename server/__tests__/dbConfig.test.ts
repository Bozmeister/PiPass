import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DatabaseConfigError,
  loadDatabaseUrl,
  redactDatabaseUrl,
  resolveDatabaseConfig,
  resolveDatabaseSslMode,
} from "../dbConfig";

const LOCAL = "postgresql://pipass:s3cret@localhost:5432/pipass";
const REMOTE = "postgresql://pipass:s3cret@db.example.com:5432/pipass";
const REMOTE_REQUIRE =
  "postgresql://pipass:s3cret@db.example.com:5432/pipass?sslmode=require";
const REMOTE_VERIFY =
  "postgresql://pipass:s3cret@db.example.com:5432/pipass?sslmode=verify-full";
const EXAMPLE = "postgresql://user:password@localhost:5432/pipass";

test("redactDatabaseUrl strips userinfo", () => {
  const redacted = redactDatabaseUrl(
    "postgresql://alice:super-secret@db.example.com:5432/pipass?sslmode=require",
  );
  assert.ok(!redacted.includes("super-secret"));
  assert.ok(!redacted.includes("alice"));
  assert.match(redacted, /db\.example\.com/);
  assert.match(redacted, /sslmode=require/);
});

test("loadDatabaseUrl prefers DATABASE_URL over FILE", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipass-db-"));
  const file = join(dir, "url");
  writeFileSync(file, REMOTE, "utf8");
  const url = loadDatabaseUrl({
    DATABASE_URL: LOCAL,
    DATABASE_URL_FILE: file,
  });
  assert.equal(url, LOCAL);
});

test("loadDatabaseUrl reads DATABASE_URL_FILE when URL is unset", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipass-db-"));
  const file = join(dir, "url");
  writeFileSync(file, `  ${REMOTE}  \n`, "utf8");
  const url = loadDatabaseUrl({ DATABASE_URL_FILE: file });
  assert.equal(url, REMOTE);
});

test("loadDatabaseUrl errors do not include the secret", () => {
  assert.throws(
    () => loadDatabaseUrl({}),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseConfigError);
      assert.ok(!err.message.includes("s3cret"));
      assert.match(err.message, /DATABASE_URL is not set/);
      return true;
    },
  );
});

test("development localhost defaults to disable", () => {
  assert.equal(
    resolveDatabaseSslMode(LOCAL, { NODE_ENV: "development" }),
    "disable",
  );
});

test("production remote defaults to verify-full", () => {
  assert.equal(
    resolveDatabaseSslMode(REMOTE, { NODE_ENV: "production" }),
    "verify-full",
  );
});

test("production loopback is allowed without TLS (sidecar proxy)", () => {
  assert.equal(
    resolveDatabaseSslMode(LOCAL, { NODE_ENV: "production" }),
    "disable",
  );
});

test("URL sslmode=require / verify-full is honored", () => {
  assert.equal(
    resolveDatabaseSslMode(REMOTE_REQUIRE, { NODE_ENV: "development" }),
    "require",
  );
  assert.equal(
    resolveDatabaseSslMode(REMOTE_VERIFY, { NODE_ENV: "test" }),
    "verify-full",
  );
});

test("DATABASE_SSL overrides URL sslmode", () => {
  assert.equal(
    resolveDatabaseSslMode(REMOTE_REQUIRE, {
      NODE_ENV: "development",
      DATABASE_SSL: "verify-full",
    }),
    "verify-full",
  );
  assert.equal(
    resolveDatabaseSslMode(REMOTE, {
      NODE_ENV: "development",
      DATABASE_SSL: "disable",
    }),
    "disable",
  );
});

test("production refuses cleartext to a remote host", () => {
  assert.throws(
    () =>
      resolveDatabaseSslMode(REMOTE, {
        NODE_ENV: "production",
        DATABASE_SSL: "disable",
      }),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseConfigError);
      assert.match(err.message, /cleartext database connection/);
      assert.ok(!err.message.includes("s3cret"));
      return true;
    },
  );
});

test("DATABASE_SSL_ALLOW_INSECURE is required to disable TLS in production", () => {
  assert.equal(
    resolveDatabaseSslMode(REMOTE, {
      NODE_ENV: "production",
      DATABASE_SSL: "disable",
      DATABASE_SSL_ALLOW_INSECURE: "true",
    }),
    "disable",
  );
});

test("resolveDatabaseConfig sets rejectUnauthorized for verify-full", () => {
  const cfg = resolveDatabaseConfig({
    NODE_ENV: "production",
    DATABASE_URL: REMOTE,
  });
  assert.equal(cfg.sslMode, "verify-full");
  assert.notEqual(cfg.ssl, false);
  if (cfg.ssl !== false) {
    assert.equal(cfg.ssl.rejectUnauthorized, true);
  }
  assert.equal(cfg.hostLabel, "db.example.com:5432");
});

test("resolveDatabaseConfig require mode does not verify the cert", () => {
  const cfg = resolveDatabaseConfig({
    NODE_ENV: "development",
    DATABASE_URL: REMOTE_REQUIRE,
  });
  assert.equal(cfg.sslMode, "require");
  assert.notEqual(cfg.ssl, false);
  if (cfg.ssl !== false) {
    assert.equal(cfg.ssl.rejectUnauthorized, false);
  }
});

test("resolveDatabaseConfig omits ssl for local development", () => {
  const cfg = resolveDatabaseConfig({
    NODE_ENV: "development",
    DATABASE_URL: LOCAL,
  });
  assert.equal(cfg.sslMode, "disable");
  assert.equal(cfg.ssl, false);
});

test("production rejects the .env.example credentials", () => {
  assert.throws(
    () =>
      resolveDatabaseConfig({
        NODE_ENV: "production",
        DATABASE_URL: EXAMPLE,
      }),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseConfigError);
      assert.ok(!err.message.includes("password@localhost"));
      return true;
    },
  );
});

test("production rejects an empty password", () => {
  assert.throws(
    () =>
      resolveDatabaseConfig({
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://pipass@db.example.com:5432/pipass",
      }),
    DatabaseConfigError,
  );
});

test("non-postgres schemes are rejected", () => {
  assert.throws(
    () =>
      resolveDatabaseConfig({
        NODE_ENV: "development",
        DATABASE_URL: "mysql://root:s3cret@localhost/db",
      }),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseConfigError);
      assert.ok(!String(err).includes("s3cret"));
      return true;
    },
  );
});

test("invalid DATABASE_SSL is rejected", () => {
  assert.throws(
    () =>
      resolveDatabaseSslMode(LOCAL, {
        NODE_ENV: "development",
        DATABASE_SSL: "maybe",
      }),
    DatabaseConfigError,
  );
});
