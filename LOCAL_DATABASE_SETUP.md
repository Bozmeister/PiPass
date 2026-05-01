# Local Database Setup (VS Code on Windows / macOS / Linux)

This document explains why `npm run db:push` fails locally with

```
getaddrinfo ENOTFOUND helium
```

and how to fix it without changing any application code.

## Why it fails

In Replit, the project's `DATABASE_URL` points at a Postgres instance
hosted on an internal hostname — currently `helium` (you can verify by
inspecting `PGHOST`, but **never paste the full `DATABASE_URL` into chat
or commit it**).

That hostname is only resolvable from inside Replit's container
network. From your laptop, DNS has no route to it, so `pg` fails to
open a TCP connection and Drizzle reports `getaddrinfo ENOTFOUND
helium`. The same root cause is why `npm test` (and the server itself
when started locally) returns 500 from `/api/auth/register` — it can't
reach the database, so every write fails.

This is a connectivity issue, not a schema or code issue. The Replit
copy of the project is healthy: `npm run db:push` is a no-op
("No changes detected") and the existing test suite passes.

## What to do

You need an **externally-reachable** Postgres instance whose
connection string you can put in a local `.env` file. Pick one of the
following options based on what you already have.

### Option A — Cloud Postgres (recommended for ease)

Free tiers that work out of the box:

| Provider | Free tier | Notes |
|---|---|---|
| [Neon](https://neon.tech) | Yes | Serverless Postgres, instant provisioning, branching for test DBs. |
| [Supabase](https://supabase.com) | Yes | Postgres + dashboard. Use the "connection pooler" URL for short-lived connections. |
| [Render](https://render.com) | 90-day trial | Standard managed Postgres. |

Steps:

1. Create a new Postgres database in the provider's dashboard.
2. Copy the connection string (looks like `postgresql://user:pass@host:5432/dbname`).
3. In your local checkout, copy `.env.example` to `.env` and paste the
   string into `DATABASE_URL`.
4. Run `npm run db:push` once to create the tables.
5. Run the server with `npm run server:dev`.

### Option B — Local Postgres via Docker

If you prefer to keep everything on your laptop:

```bash
docker run --name pipass-pg \
  -e POSTGRES_USER=pipass \
  -e POSTGRES_PASSWORD=pipass \
  -e POSTGRES_DB=pipass_dev \
  -p 5432:5432 \
  -d postgres:16
```

Then set in `.env`:

```
DATABASE_URL=postgresql://pipass:pipass@localhost:5432/pipass_dev
```

Run `npm run db:push` once, then `npm run server:dev`.

### Option C — Postgres.app / Homebrew / native install

Install Postgres locally however you prefer (Postgres.app on macOS,
`brew install postgresql@16`, or the official Windows installer).
Create a database named `pipass_dev` and a user with rights to it,
then set `DATABASE_URL` accordingly in `.env`.

## After picking an option

Whichever path you took:

1. Make sure `.env` is **never** committed (it's already gitignored).
2. You also need to populate `TOTP_ENCRYPTION_KEY` in `.env` — see
   `.env.example` for instructions on generating one. The server will
   refuse to start without it.
3. Run `npm run db:push` to create the schema.
4. Start the server: `npm run server:dev`. You should see
   `express server serving on port 5000` and no fatal errors.
5. `/api/auth/register` should now return a 2xx response.

## What NOT to do

- **Do not** copy the Replit `DATABASE_URL` value into your local
  `.env`. The hostname won't resolve, and exposing the full string
  also exposes the password.
- **Do not** edit `server/db.ts` or `drizzle.config.ts` to "skip"
  the database check — those fail-fast guards exist on purpose.
- **Do not** commit any populated `.env` file.

## See also

- `TEST_DATABASE_SETUP.md` — how to run tests safely without
  polluting your dev database with test data.
- `.env.example` — required environment variables, with placeholders.
