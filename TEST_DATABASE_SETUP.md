# Test Database Setup

The server test suite writes rows through the real Express routes and storage layer.
Use a dedicated test database to avoid polluting a development database.

1. Copy `.env.test.example` to `.env.test`.
2. Set `TEST_DATABASE_URL` to a dedicated PostgreSQL database.
3. Set `TOTP_ENCRYPTION_KEY` to a test-only 32-byte key encoded as 64 hex characters.
4. Run `npm run db:push:test` to apply the existing Drizzle schema to the test database.
5. Run `npm test`.

When `TEST_DATABASE_URL` is set, the test setup assigns it to `DATABASE_URL` before
`server/db.ts` is imported. If it is not set, tests fall back to `DATABASE_URL` and
print a warning without revealing any secret values.

Rate limits and soft-lock state use in-process memory during tests. A stray
`REDIS_URL` from `.env` is ignored unless you set `TEST_REDIS_URL` to an
intentional Redis instance. Leave both unset for the default memory fallback.

The `db:push:test` script loads `.env.test`, verifies `TEST_DATABASE_URL` exists,
assigns it to `DATABASE_URL` only for the Drizzle command process, and does not
print the database URL.

TLS follows `server/dbConfig.ts`. A hosted URL that already includes
`sslmode=require` or `sslmode=verify-full` (Neon, RDS, etc.) keeps that mode.
A local Postgres URL (`localhost` / `127.0.0.1`) stays cleartext unless you set
`DATABASE_SSL=require` or `DATABASE_SSL=verify-full`. Do not put production
credentials in `.env.test`.
