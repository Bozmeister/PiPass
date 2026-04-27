# Threat Model — PiPass

## Project Overview

PiPass is a **zero-knowledge mobile password manager**. The server stores only an opaque encrypted blob — it never sees plaintext passwords, vault entries, or master-key material. Architecture:

- **Client**: React Native / Expo (`app/`, `components/`, `crypto/`, `workers/`). Derives a master key from `password + salt + iterations` (Argon2 via `crypto/keyDerivation.ts`); SHA-256s the master key into an `authHash` used as a shared-secret credential; encrypts each vault entry with a per-entry HKDF subkey using **AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)** in `crypto/encryption.ts` — AES-GCM is not natively available in Expo Go, so this manual AEAD construction is used; format on disk is `iv(32hex) : ciphertext(hex) : mac(64hex)`. HMAC subkey is derived from the encryption key (`HmacSHA256("hmac-subkey", encKey)`). MAC is verified with constant-time comparison BEFORE AES decryption (authenticate-then-decrypt). Stores credentials in `expo-secure-store` (iOS Keychain / Android Keystore) and the device UUID in SecureStore.
- **Backend**: Express + TypeScript on Node (`server/`). Six REST endpoints. Per-route input validation via zod schemas derived from the Drizzle table definitions (`shared/schema.ts`). Per-route body-size limits (4 KB for auth, 11 MB for vault sync). IP-based rate limiting on auth endpoints. No sessions, no cookies — every protected request carries `x-user-id` and `x-auth-hash` headers.
- **Database**: PostgreSQL via Drizzle ORM (`server/db.ts`, `server/storage.ts`). Two tables — `users` and `vault_blobs`. DB-level CHECK constraints mirror the zod refinements as defense-in-depth.
- **Hosting**: Replit. TLS termination at the Replit edge proxy.

Primary user is a single individual managing their own vault. Multi-user, sharing, and admin roles do not exist.

## Assets

Ranked roughly by blast radius if compromised:

| Asset | Location | Why it matters |
|---|---|---|
| **Master password / master key** | Client memory only — never leaves the device, never reaches the server | Decrypts the entire vault. Compromise = full breach of every stored credential. |
| **Plaintext vault entries** | Client memory only (briefly, after decrypt) | Each entry is a real-world credential the user manages. |
| **`encryptedBlob`** | `vault_blobs.encrypted_blob` (DB) + on disk in client SecureStore | Ciphertext of the entire vault. Confidentiality is preserved by client-side encryption; integrity (no silent tampering) and freshness (no rollback to an older version) are server's responsibility. |
| **`authHash`** (client form) | Client memory + on the wire as `x-auth-hash` header | Bearer credential — anyone who possesses it can read/overwrite the vault until the user rotates their password. The server-side stored form is a SHA-256 of this value, so a DB leak does NOT yield this. |
| **`authHash`** (stored, SHA-256 of client form) | `users.auth_hash` (DB) | Stolen DB still requires preimage of SHA-256 to mount an online attack. |
| **`salt` + `iterations`** | `users.salt`, `users.iterations` (DB), exposed via `/api/auth/salt/:username` | Public-by-design — needed by the client to derive the master key. Not secrets, but per-user uniqueness matters (prevents rainbow tables across users). |
| **Username** | `users.username` (DB), exposed in `/api/auth/salt/:username` paths | Mild PII; used as account identifier. |
| **`userId`** (UUID) | `users.id` (DB), sent as `x-user-id` header | Only useful with a valid `authHash`. Enumeration is mitigated by collapsing "user not found" → 401 "Invalid credentials". |
| **`DATABASE_URL`** | `process.env.DATABASE_URL` (server only) | Direct DB credential. Compromise = full DB read/write. Required at startup; no fallback. |

Notably **NOT assets** (deliberate design):
- The server holds no decryption material. There is nothing on the server, even with full DB access, that lets an attacker decrypt a vault offline.
- There is no session/refresh token to steal. Auth is via shared-secret headers per request.

## Trust Boundaries

| # | Boundary | What crosses | Trust assumption |
|---|---|---|---|
| 1 | **Device ↔ Replit edge (TLS)** | All API requests/responses | TLS confidentiality + integrity. Replit-managed cert. The client SHOULD treat the server as untrusted for vault contents (it cannot decrypt anyway), but MUST trust the server for monotonic version freshness and for not silently dropping writes. |
| 2 | **Replit edge ↔ Express server** | All inbound HTTP | The edge proxy adds `x-forwarded-*` headers. The server treats `req.ip` as the client IP for rate-limiting (`server/routes.ts:64`). Any header-injection bug at the edge would let attackers bypass per-IP rate limits. |
| 3 | **Server ↔ PostgreSQL** | All DB operations via Drizzle | Server holds `DATABASE_URL`. Drizzle issues parameterized queries. Compromise of the DB process = full read/write of all user accounts and ciphertext blobs (but not plaintext vault data). |
| 4 | **Unauthenticated ↔ Authenticated routes** | Public: `/api/auth/{register,login,salt}`, `/api/health`. Authenticated: `/api/vault/{sync,fetch}` | Authenticated routes are gated by `validateAuthHeaders(req)` (`server/validation.ts`) — both `x-user-id` and `x-auth-hash` must be present, well-formed, and the hashed authHash must timing-safe-equal the stored hash. |
| 5 | **Server ↔ Client (data shape)** | API request bodies, headers, path params | Server treats every byte of client input as untrusted. Strict zod validation at every input source; no field is read before validation passes. |
| 6 | **JS heap ↔ Native SecureStore (client)** | Persisted credentials | `expo-secure-store` writes to iOS Keychain / Android EncryptedSharedPreferences. JS-side wipe of derived key shares (`wipeShares`, `crypto/secureMemory.ts`) is best-effort given JS string immutability. |

## Scan Anchors

- **Server entry point**: `server/index.ts` — wires CORS, urlencoded body parser (4 KB), request logging, Expo manifest serving, then `registerRoutes(app, storage)` from `server/routes.ts`.
- **All HTTP route handlers**: `server/routes.ts` (single file; ~280 lines). Every route is here.
- **All input schemas**: `shared/schema.ts` — Drizzle tables + zod schemas derived from them. Strict mode (`.strict()`) is on every body schema.
- **Validation adapters**: `server/validation.ts` — `validateRegister`, `validateLogin`, `validateVaultSync`, `validateUsernameParam`, `validateAuthHeaders`. Path/header validators were added in the most recent audit pass.
- **Storage layer (only place that touches DB)**: `server/storage.ts`. Uses Drizzle's `eq()` exclusively — no raw SQL, no string concatenation.
- **Authoritative crypto** (no-touch): `crypto/` directory — Argon2id key derivation, AES-GCM encryption, HKDF subkeys, Shamir secret sharing, biometric gate. Server files MUST import from `node:crypto` (with the prefix), never from `crypto`, to avoid resolving to this directory.
- **Public surface**: `/api/auth/register`, `/api/auth/login`, `/api/auth/salt/:username`, `/api/health`. All other API routes require valid auth headers.
- **Admin surface**: NONE. There is no admin role, no admin endpoint, no privileged user. Eliminating this whole class of attack is a deliberate design choice.
- **Dev-only signals**: `DISABLE_RATE_LIMIT=true` is honored only when `NODE_ENV !== "production"` (`server/routes.ts:36-49`). The flag is silently ignored with a startup warning if someone sets it on a production deploy.

## Threat Categories

### Spoofing — impersonating a legitimate user

**Attack scenarios.** (1) An attacker on the same network captures `x-auth-hash` from a request and replays it to read or overwrite the victim's vault. (2) An attacker steals the database and uses the stored `authHash` value directly. (3) An attacker brute-forces low-entropy `authHash` values online. (4) A malicious mobile app on the same device reads the SecureStore-resident credentials.

**Current mitigations.**
- All transport is HTTPS via the Replit edge (boundary #1).
- The wire-form `authHash` is SHA-256'd again before being compared (`hashForComparison` in `server/routes.ts:24`), so the value stored at `users.auth_hash` is **not** the same value the client sends. A DB leak does not yield a usable credential without a SHA-256 preimage attack.
- Comparison is constant-time (`timingSafeEqual` in `server/routes.ts:147,197,214,249,266`).
- Per-IP rate limit of 10 requests/minute on `/api/auth/login`, `/api/auth/register`, and `/api/auth/salt/:username` (`server/routes.ts:28-62`). Slows online brute-force.
- Failed-lookup paths still execute a constant-cost hash (`hashForComparison(authHash)` on the unknown-user branch in login, line 140) so timing does not leak account existence.
- Username enumeration via the salt endpoint is blocked by returning a deterministic dummy salt for unknown users (`deterministicDummySalt`, line 71).
- UserId enumeration via vault routes is blocked by collapsing "user not found" → 401 "Invalid credentials" (`server/routes.ts:209,261`).
- SecureStore-resident credentials are protected by the OS Keychain/Keystore.

**Required guarantees.**
- The client form of `authHash` MUST NEVER be persisted server-side, MUST NEVER be logged, and MUST only ever cross the wire under TLS.
- The server MUST continue using `timingSafeEqual` for every `authHash` comparison.
- Rate limiting on auth endpoints MUST remain enforced in production. The kill-switch MUST remain ignored when `NODE_ENV=production`.
- Salt and vault endpoints MUST NOT differentiate "unknown user" from "wrong credential" responses.

**Residual risk.**
- **No second factor.** Possession of `authHash` alone grants full vault access. Mitigation depends entirely on TLS, SecureStore, and the user's master-password entropy.
- **Per-IP rate limit only.** A distributed attacker spreading guesses across many IPs is not throttled. Per-userId rate limiting (in addition to per-IP) on `/api/vault/{sync,fetch}` would close this.
- **No request signing.** A captured request can be replayed within the rate-limit budget. For sync this is partially mitigated by version monotonicity (an old captured sync request will lose to the conflict check, line 207); for fetch it's idempotent so replay yields no extra info beyond what the attacker already had.

---

### Tampering — modifying data the attacker shouldn't

**Attack scenarios.** (1) An attacker who has obtained `authHash` overwrites the vault with their own ciphertext (or with junk). (2) An attacker with DB access modifies `vault_blobs.encrypted_blob` directly. (3) An attacker with DB access modifies `users.auth_hash` to a value of their choosing, then logs in as that user. (4) A network MitM (TLS broken) tampers with the vault sync body in flight. (5) A malicious client sends a body with extra fields hoping the server picks them up.

**Current mitigations.**
- Strict zod validation on every input source (`shared/schema.ts` schemas all use `.strict()`). Unknown fields → 400 "Unknown field" (`server/validation.ts:34-37`). No coercion — `z.string()` and `z.number().int()` reject mismatched types and fractions.
- Per-route body-size limits (`AUTH_BODY_LIMIT = "4kb"`, `VAULT_SYNC_BODY_LIMIT = "11mb"` in `server/routes.ts:21-22`) prevent unbounded payloads.
- All DB writes go through Drizzle's parameterized query builder (`server/storage.ts`). No raw SQL, no string interpolation, no SQL injection surface.
- Vault sync enforces version monotonicity at the SQL layer: the upsert `WHERE` clause is `vault_blobs.version < $newVersion` (`server/storage.ts:76`). A replayed or stale sync cannot overwrite a newer blob. Conflicts return 409 with the current server version so the client can re-sync.
- DB-level CHECK constraints mirror the zod refinements (`shared/schema.ts:18-22, 38-40`): `users_iterations_range` enforces 3 ≤ iterations ≤ 1,000,000; `vault_blobs_version_range` enforces version ≥ 1. Even a SQL-injection-grade bypass cannot store an out-of-range value.
- Strict mode catches "ID-spoofing" attempts where a client sends `{id: "<other-uuid>", ...}` in a register body — that field is now rejected (it was previously silently stripped, which was harmless but indistinguishable from "accepted").

**Required guarantees.**
- All DB queries MUST continue to use Drizzle's typed builders (no raw SQL).
- Body, path, query, and header validators MUST run **before** any storage operation that uses the corresponding value.
- The vault sync upsert WHERE clause (`version < $newVersion`) MUST remain to prevent rollback attacks.
- Schemas MUST stay derived from the Drizzle tables so column constraints and API constraints cannot drift apart.

**Residual risk.**
- **DB-level write access defeats integrity.** An attacker with `DATABASE_URL` can rewrite anything. Out of scope for the application, but argues for: (a) restricted DB credentials in production (read/write only on these two tables), (b) PITR backups so user can roll back from a compromise.
- **No additional integrity check beyond the cipher's own AEAD.** The blob is encrypted with AES-256-CBC + HMAC-SHA256 in Encrypt-then-MAC mode (`crypto/encryption.ts`). HMAC is verified BEFORE the AES decrypt step using `constantTimeEqual` (lines 14-25, 72) — this is the correct ordering, and the constant-time MAC compare prevents padding-oracle-style attacks (a forged MAC fails before decryption ever runs, so PKCS7 padding errors are unreachable to an attacker). Any in-flight tampering causes decryption to throw `"Authentication failed — data may be tampered"` noisily. **Future-maintenance risk:** the manual AEAD construction is more error-prone than a native AEAD primitive. Any change to the order of operations (decrypt-then-authenticate, non-constant-time MAC compare, or HMAC over only the ciphertext without the IV) would silently weaken the security model. The current implementation correctly HMACs `iv || ciphertext` and uses constant-time MAC verification — both invariants MUST be preserved.
- **No audit trail** of who modified the vault when (covered under Repudiation).

---

### Repudiation — denying an action took place

**Attack scenarios.** (1) After a credential compromise, the user wants to know "did the attacker actually access my vault, and when?" but cannot. (2) A bug or attacker silently overwrites the vault and the user has no way to recover or prove what changed.

**Current mitigations.**
- Drizzle's auto-managed timestamps (`updated_at` on `vault_blobs`) provide a coarse "last-write" signal. The client can compare its local `updatedAt` to the server's on `fetch` to detect unexpected writes since the user last synced.
- The version field is monotonic and visible to the client — a version skip ("I last synced v5, server says v9") is detectable.
- The request log line (method + path + status + duration) is written for every API request (`server/index.ts:67-85`). Bodies and response payloads are NOT logged.

**Required guarantees.**
- Request logging MUST continue to omit request bodies and response payloads (avoids PII / authHash leaks into stdout/stderr).
- The `updated_at` and `version` fields MUST always be returned to the client on `sync` and `fetch` so the client can detect anomalies.

**Residual risk.**
- **No durable audit log of vault writes.** The server overwrites the blob in place via upsert; only the most recent version exists. There is no per-write history. For a personal-use vault this is a reasonable tradeoff (less data = less attack surface, simpler GDPR story), but means a compromised user has no forensic record. **Recommendation if multi-user or compliance becomes a goal:** add an append-only `vault_blob_writes` audit table (userId, version, byte size, source IP, timestamp) and a versioned blob retention policy.
- **No login audit log.** The user cannot see "your account was logged into from IP X at time Y." **Recommendation:** add a lightweight `login_events` table populated on successful login, exposed via a future `/api/account/activity` endpoint.
- **Server has no integrity log of its own state.** A compromised server could backdate `updated_at` at write time — out of scope (the server is in the trusted compute base).

---

### Information Disclosure — accessing data the attacker shouldn't see

**Attack scenarios.** (1) An attacker probes the API hoping the server returns a stored `authHash` or some other secret. (2) An attacker enumerates usernames or userIds. (3) An attacker reads server logs and finds bodies, headers, or stack traces. (4) An attacker reads error responses and learns about server internals (file paths, library versions, DB driver). (5) An attacker reads CORS-permitted origins and sets up a phishing page.

**Current mitigations.**
- **`authHash` is never returned in any response.** Verified by an explicit greppable scan in the most recent audit. All response shapes are documented in `replit.md` Backend section.
- Login and salt endpoints do not differentiate real vs unknown users (deterministic dummy salt; same constant-cost hash on both branches).
- Vault routes collapse "user not found" → 401 "Invalid credentials" so userId-existence doesn't leak.
- Error handler returns only `{error: "Internal server error"}` for uncaught 500s — no stack trace, no error message, no file path (`server/index.ts:189-218`). The console-side log is the single string `"Internal Server Error"` with no error object dumped (`server/index.ts:216`). Same pattern in route-level catch blocks (`server/routes.ts:119, 158, 192, 246, 264`).
- Request logging deliberately omits both request bodies and response bodies (`server/index.ts:67-85`).
- CORS is allowlist-based: `REPLIT_DEV_DOMAIN`, the comma-split `REPLIT_DOMAINS`, plus localhost (any port) for Expo dev (`server/index.ts:17-54`). No `*` wildcard. Credentials are allowed only for permitted origins.
- Database connection uses a parameterized pool; column data types ensure DB-side validation.

**Required guarantees.**
- `authHash` (in either client form or stored form) MUST NEVER appear in API responses, log lines, or error messages.
- Error responses MUST be the single shape `{error: string}` with a generic message; details (validation issue paths, stack traces, library versions) MUST be redacted.
- The request logger MUST continue to omit bodies and response payloads.
- New endpoints MUST go through the explicit response-shape review described in `replit.md` ("No sensitive data ever returned" subsection).

**Residual risk.**
- **`/api/auth/salt/:username` reveals salt + iterations to anyone.** This is by design (the client needs them to derive the master key before login), and is mitigated by the dummy-salt fallback for unknown users — a probe cannot tell real from fake. **Risk accepted.**
- **TLS termination at the Replit edge.** Anything between the edge and the Express process (Replit-internal traffic) is out of the project's control. Architectural constraint.
- **Request log goes to stdout.** Replit captures stdout. If a future change accidentally adds `console.log(req.body)` or similar, it would leak `authHash` into the platform log store. Mitigated only by code review discipline. **Recommendation:** add a lint rule or a small unit test that fails if `routes.ts` or `index.ts` references `req.body` or `req.headers` inside a `console.*` call.

---

### Denial of Service — degrading or disrupting the service

**Attack scenarios.** (1) An attacker floods `/api/auth/login` with bad password attempts. (2) An attacker uploads many maximum-size 10 MB vault blobs to fill the DB. (3) An attacker sends pathologically large JSON bodies to auth endpoints. (4) An attacker sends pathologically deep nested JSON to exhaust the parser. (5) An attacker opens many slow-loris connections to keep sockets open.

**Current mitigations.**
- Per-IP rate limit of 10 req/min on register, login, and salt endpoints (`server/routes.ts:28-62`). Window resets via lazy expiry; a 5-minute sweep collects stale entries (`server/routes.ts:75-82`) so the map cannot grow unbounded.
- Per-route body-size limits — `4kb` for auth, `11mb` for vault sync (`server/routes.ts:21-22`). Oversize → 413 `{error: "Payload too large"}`. Auth endpoints CANNOT be DoS'd with multi-megabyte payloads anymore (this was the whole point of the prior task).
- The global JSON parser was removed from `server/index.ts`; bodies are only parsed on the routes that need them, so a request to a body-less endpoint can't trigger parsing at all.
- Vault sync enforces version monotonicity, so an attacker can write at most one new "winning" version per request — they cannot infinitely grow the row beyond the 10 MB blob cap.
- The schema cap of 10 MB on `encryptedBlob` is enforced by both zod (`shared/schema.ts:57`) and by the express body-parser limit. Even a SQL-direct write would be capped at the column's text limit (PG defaults).
- DATABASE_URL must be present at startup — no degraded-mode fallback that could be exploited.

**Required guarantees.**
- Rate limit middleware MUST run before any DB call on rate-limited routes.
- Body-size limits MUST stay route-specific. Adding a global `express.json()` without a limit would re-open the DoS vector.
- Schema and parser limits MUST agree (parser ≥ schema cap), or the schema cap becomes unreachable.

**Residual risk.**
- **Vault sync has no per-IP rate limit.** A single IP could write 11 MB blobs as fast as the server accepts them, eating CPU on JSON parsing + Drizzle round-trips + DB I/O. The schema's monotonic-version check means each write requires a winning higher version, but that's cheap to manufacture. **Recommendation:** add a per-userId (post-auth) rate limit of N writes/min on `/api/vault/sync`. Also add a per-IP rate limit on the unauthenticated body-parse step (i.e., before auth check).
- **No timeout on DB queries.** A pathological table state could hang an `eq(users.id, ...)` lookup. **Recommendation:** set `statement_timeout` on the PG pool (e.g., 5 seconds).
- **No connection-level throttle in front of Express.** Out of scope (Replit edge handles this).
- **JSON parser depth.** body-parser uses `JSON.parse`, which is recursive and bounded only by V8's stack. A pathologically nested body within the 11 MB limit could cause stack overflow during parsing. Low likelihood given the size cap, but worth noting. **Mitigation already in place:** body-size cap limits how deep nesting can practically go.
- **One process per Replit container.** Hosting-architectural; not a fix at the app layer.

---

### Elevation of Privilege — gaining access beyond authorized level

**Attack scenarios.** (1) IDOR — a logged-in user manipulates `x-user-id` to read someone else's vault. (2) SQL injection through username, encryptedBlob, or path params. (3) Path traversal via `:username` (e.g. `/api/auth/salt/..%2Fadmin`). (4) Prototype pollution via JSON body. (5) Mass assignment — injecting fields like `iterations: 0` or `id: "<victim-uuid>"` during register/sync.

**Current mitigations.**
- **No admin role exists.** There is no `isAdmin`, no `/api/admin/*` route, no privileged user account. The whole class of "horizontal vs vertical privilege escalation" reduces to "horizontal" (cross-user access).
- IDOR is blocked at the auth-header layer: `validateAuthHeaders` parses `x-user-id` and `x-auth-hash` together; the route then looks up the user by that `userId`, hashes the supplied `authHash`, and timing-safe-compares against the stored hash. To impersonate user B, an attacker needs B's `authHash`. Possessing B's UUID alone is useless. (`server/routes.ts:196-216, 250-269`).
- All DB queries use Drizzle's parameterized `eq()` — no SQL injection vector reachable from any input.
- Path traversal on `:username` is impossible: Express path matching limits `:username` to a single URL segment, then `validateUsernameParam` enforces 3–64 chars. Drizzle parameterizes the resulting query.
- Strict-mode zod schemas reject unknown fields (`shared/schema.ts:75, 82, 89`), so mass-assignment via extra body fields (like `id`, `createdAt`, `version` for register) is rejected with 400 instead of silently dropped or — worse — accepted. The `iterations` field is bounded by a refinement (3 ≤ x ≤ 1,000,000) AND a DB CHECK constraint, so a client cannot weaken its own KDF.
- `id`, `createdAt`, `updated_at` fields on user/vault rows are never client-controlled — they are server-generated (`defaultRandom`, `$defaultFn(() => Date.now())`).
- DB ON DELETE CASCADE on `vault_blobs.user_id` means deleting a user reliably wipes their vault — no orphan rows reachable by re-using a UUID.
- The `crypto/` directory is import-shadowed: server files MUST use `node:crypto` (with the `node:` prefix), not `crypto`, or they'd resolve to the local `crypto/` directory and break. This is a tooling constraint that prevents accidental local imports.

**Required guarantees.**
- Every protected route MUST resolve the user by the `x-user-id` header AND verify `x-auth-hash` against `users[userId].auth_hash` with `timingSafeEqual`. There MUST NOT be a route that takes a userId from a body, query, or path while expecting auth from somewhere else.
- All schemas for client-supplied data MUST stay `.strict()` so mass-assignment attempts are rejected, not silently stripped.
- DB queries MUST continue to use Drizzle's typed builders. Raw SQL would need a security review.
- Server files MUST import `node:crypto` (with prefix) — never `crypto` — to avoid resolving to the local `crypto/` directory.
- New routes that operate on user-owned resources MUST scope every storage call by the authenticated `userId` (taken from the validated header, not the body).

**Residual risk.**
- **Compromised user credentials = full impact** for that user. There is no privilege boundary inside a user's account to defend behind. **By design** for a personal vault.
- **No tenant separation testing in CI.** A future bug that loosens the userId scoping would not be caught by automated tests. **Recommendation:** add an integration test that registers two users, then asserts user A cannot fetch user B's blob even with a valid auth header for A.
