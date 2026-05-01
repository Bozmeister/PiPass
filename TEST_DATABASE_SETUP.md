# Test Database Setup

This document explains the current test setup, the safety risk it
poses, and the recommended way to run tests without polluting your
development or production database.

## Current state (today)

- The project ships **one** test file: `server/__tests__/security.test.ts`.
- It is run with Node's built-in test runner via `tsx`:
  ```
  npx tsx --test --test-force-exit server/__tests__/security.test.ts
  ```
- There is **no `npm test` script** in `package.json` yet.
- There is **no `npm run typecheck` script** either; type-checking is
  done with `npx tsc --noEmit`.
- The test suite imports `DatabaseStorage` and connects to the
  **same `DATABASE_URL`** the dev server uses. It writes real rows
  to `users`, `sessions`, `audit_log`, and TOTP-related fields.
- Each test creates a uniquely-named user (so reruns don't collide),
  but **no row is cleaned up afterward**. Test data accumulates on
  every run.

## Why this matters

Because the test suite shares the dev `DATABASE_URL`, every test run
silently adds rows to your dev database. Over time:

- The `users` table fills up with throwaway test accounts.
- The `audit_log` table grows with test events that look real to any
  query that scans it.
- TOTP-related rows can accumulate — earlier this week, 59 TOTP
  enrollments had to be wiped from the dev database; they were almost
  certainly leftover test data.

If you ever wired tests against a production database, the same
writes would land there. That is the risk this document exists to
prevent.

## Recommended setup

### 1. Provision a separate test database

Pick whichever option matches your `LOCAL_DATABASE_SETUP.md` choice:

- **Neon / Supabase / Render**: create a second database in the
  same project, e.g. `pipass_test`. Free tiers usually allow this
  at no extra cost.
- **Docker**: spin up a second Postgres container on a different
  port, or just create a second database in the same container:
  ```bash
  docker exec -it pipass-pg psql -U pipass -c "CREATE DATABASE pipass_test;"
  ```
- **Native install**: `createdb pipass_test`.

### 2. Put the test connection string in `.env.test`

Copy `.env.test.example` to `.env.test` and fill in the connection
string for your test database:

```
TEST_DATABASE_URL=postgresql://user:pass@host:5432/pipass_test
TOTP_ENCRYPTION_KEY=<a throwaway 64-hex value>
```

`.env.test` is intended to be local-only — keep it out of git. (Add
`.env.test` to your local `.gitignore` if you want belt-and-braces;
the existing `.env` rule does not match it.)

### 3. Wire the test suite to prefer `TEST_DATABASE_URL`

This is the **only code change** required, and it's deliberately
left for you to apply (or assign to a follow-up task) so this
diagnostic prompt does not modify application logic.

The minimal change is one line at the top of
`server/__tests__/security.test.ts`, before any import that touches
the database:

```ts
// Prefer a dedicated test DB if one is configured. Falls back to
// DATABASE_URL with a loud warning so a misconfigured environment
// is impossible to miss.
if (process.env.TEST_DATABASE_URL) {
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
} else {
  console.warn(
    "[test] TEST_DATABASE_URL is not set — running tests against " +
    "DATABASE_URL. Test rows WILL be written to your dev database. " +
    "See TEST_DATABASE_SETUP.md.",
  );
}
```

That's it. Both `server/db.ts` and `drizzle.config.ts` read
`DATABASE_URL` only, so re-pointing the env var in-process is enough.

### 4. Loading `.env.test` automatically (optional, local-only)

Node does not auto-load `.env.test`. Two simple options:

- One-shot: `npx dotenv-cli -e .env.test -- npx tsx --test --test-force-exit server/__tests__/security.test.ts`
- Add a script (one-line addition to `package.json`):
  ```json
  "test": "dotenv -e .env.test -- tsx --test --test-force-exit server/__tests__/security.test.ts"
  ```
  This requires `dotenv-cli` as a dev dependency. Adding it is a
  small package change; this prompt does not perform it because the
  prompt asks for any `package.json` change to be explained and
  approved first. See "Files I did NOT change" below.

### 5. Resetting the test database

Because tests don't clean up after themselves, the simplest reset
is to drop and recreate the test schema between runs:

```bash
npm run db:push   # with DATABASE_URL pointed at the test DB
```

Or, more aggressively:

```bash
psql "$TEST_DATABASE_URL" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
npm run db:push
```

A future improvement is to wrap the test suite in `before`/`after`
hooks that truncate the affected tables. That is a behaviour change
to the test file and is out of scope for this prompt.

## Inside Replit

When running `npm test` (or the `tsx --test` invocation) inside Replit
without a `TEST_DATABASE_URL`, the suite will write to the same
database the running app uses. The 18 tests currently pass in ~17s
end-to-end, but each pass leaves test users behind. **Either set
TEST_DATABASE_URL inside Replit Secrets too**, or accept that test
data will accumulate and run a periodic cleanup.

## Files I did NOT change in this prompt

To stay strictly within the diagnostic scope of Prompt 001E, the
following were left untouched:

- `package.json` — no new `test` or `typecheck` script was added.
- `server/__tests__/security.test.ts` — the one-line `TEST_DATABASE_URL`
  preference shown above was not applied here.
- `server/db.ts`, `drizzle.config.ts`, any crypto / auth / vault /
  routes / storage / UI code — all untouched.

If you want any of those applied, that's a small follow-up task.
