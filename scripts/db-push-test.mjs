#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const envTestPath = resolve(projectRoot, ".env.test");
const drizzleBin = resolve(projectRoot, "node_modules", "drizzle-kit", "bin.cjs");

if (!existsSync(envTestPath)) {
  console.error(
    ".env.test not found. Create it from .env.test.example and set TEST_DATABASE_URL before running db:push:test.",
  );
  process.exit(1);
}

const loaded = dotenv.config({ path: envTestPath, override: true });
if (loaded.error) {
  console.error("Failed to load .env.test. Refusing to run db:push:test.");
  process.exit(1);
}

const testDatabaseUrl = process.env.TEST_DATABASE_URL?.trim();
if (!testDatabaseUrl) {
  console.error(
    "TEST_DATABASE_URL is not set in .env.test. Refusing to run db:push:test.",
  );
  process.exit(1);
}

if (!existsSync(drizzleBin)) {
  console.error("drizzle-kit is not installed. Run npm install first.");
  process.exit(1);
}

const childEnv = {
  ...process.env,
  DATABASE_URL: testDatabaseUrl,
  DOTENV_CONFIG_PATH: envTestPath,
};

console.log("Applying Drizzle schema to the configured TEST_DATABASE_URL database.");

const child = spawn(process.execPath, [drizzleBin, "push"], {
  cwd: projectRoot,
  env: childEnv,
  stdio: "inherit",
});

child.on("error", () => {
  console.error("Failed to start drizzle-kit push.");
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`drizzle-kit push exited after signal ${signal}.`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});
