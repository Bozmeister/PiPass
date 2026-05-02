# Test Database Setup

The server test suite writes rows through the real Express routes and storage layer.
Use a dedicated test database to avoid polluting a development database.

1. Copy `.env.test.example` to `.env.test`.
2. Set `TEST_DATABASE_URL` to a dedicated PostgreSQL database.
3. Set `TOTP_ENCRYPTION_KEY` to a test-only 32-byte key encoded as 64 hex characters.
4. Run migrations/schema setup against the test database before running `npm test`.

When `TEST_DATABASE_URL` is set, the test setup assigns it to `DATABASE_URL` before
`server/db.ts` is imported. If it is not set, tests fall back to `DATABASE_URL` and
print a warning without revealing any secret values.
