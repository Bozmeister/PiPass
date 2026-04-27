# PiPass — Authentication Trust Model & API Attack Surface Review

**Date:** 2026-04-27
**Scope:** Authentication flow + full `/api/*` attack surface, focused on trust model under credential compromise, replay/abuse scenarios, missing protections, and denial-of-vault.
**Status:** Analysis only. **No code changes proposed for implementation in this pass.**

---

## 0. Executive Summary

PiPass is a zero-knowledge password manager. The crypto layer (Argon2id KDF + per-blob AES-GCM with PBKDF2-derived sub-keys, see `crypto/`) is treated as a fixed correctness boundary by this review and is **not analyzed here** — earlier audits already cover it.

This review focuses on the layer **above** crypto: the API trust model, the protections around the encrypted blob, and the abuse paths a holder of valid credentials can exploit *without* breaking encryption.

### Verdict

The current API surface is **structurally sound for honest clients**: input validation is tight (see `auth_security_review.md` and the recent hardening pass), the storage layer enforces version monotonicity via UPSERT-with-CAS, and the server holds no plaintext key material.

It is **structurally weak against a credential-compromise threat model**, in three concrete ways:

1. **Stateless header-based auth means there is nothing to revoke.** Once `(x-user-id, x-auth-hash)` leaks, the attacker has indefinite, undetectable, and unrevokable access. The legitimate user has no way to "log out from all devices," rotate credentials without re-encrypting the entire vault, or even *know* an attacker is reading their vault.
2. **No per-user resource limits.** Rate limiting is per-IP only on auth endpoints, and the vault endpoints have no rate limiting at all. An attacker with valid credentials can flood reads/writes from a single IP without ever hitting `/api/auth/*`.
3. **No vault history, no recovery.** A valid-creds attacker can perform denial-of-vault by overwriting with junk encrypted by their own key, or by version-bombing to `INT32_MAX` to lock future writes. The single-row vault model has no rollback.

### Findings at a glance

| ID | Severity | Title |
|---|---|---|
| **T-1** | P0 | No credential revocation — leaked headers grant permanent access |
| **T-2** | P0 | Vault endpoints have no rate limit at all (per-IP or per-user) |
| **T-3** | P0 | Denial-of-vault: valid-creds attacker can destroy/lock the vault with no recovery path |
| **T-4** | P1 | No session concept — every request carries the long-lived secret |
| **T-5** | P1 | No device binding or per-device session tracking |
| **T-6** | P1 | No anomaly detection / no audit log of vault writes |
| **T-7** | P1 | Per-IP rate limit is bypassable via residential/mobile NAT proxies |
| **T-8** | P1 | No second factor — credential stuffing has unlimited per-username attempts (per-IP only) |
| **T-9** | P2 | Salt endpoint leaks `iterations` parameter, enabling cheap KDF-cost recon |
| **T-10** | P2 | No way to enumerate or terminate active sessions ("Where am I logged in?") |
| **T-11** | P2 | No defense against a malicious legitimate client (e.g. compromised app build) |

The rest of this document is structured to mirror the seven analysis goals from the brief:

- §1 — Trust model and credential-compromise risk (Goal 1)
- §2 — Replay and abuse scenarios (Goal 2)
- §3 — Missing protections (Goal 3)
- §4 — Auth flow attack resistance (Goal 4)
- §5 — Concrete improvement proposals (Goal 5)
- §6 — Denial-of-vault scenarios (Goal 6)
- §7 — Compatibility / what NOT to change (Goal 7)
- §8 — Cross-references to prior audits

---

## 1. Trust Model Under Credential Compromise (Goal 1)

### 1.1 — What the server treats as authority today

The server's authorization decision is, in pseudocode:

```
authorize(req):
  uid := req.headers["x-user-id"]            # UUID
  ah  := req.headers["x-auth-hash"]          # hex string (Argon2id output, hex)
  user := db.users.where(id = uid)
  if user is None:                  return 401
  if sha256(ah) != user.auth_hash:  return 401   # timing-safe compare
  return AUTHORIZED
```

That is the **entire** trust model. There is no notion of:

- *who* sent this request (no device, no client, no app version, no IP allowlist)
- *when* the credential was minted (no token issuance time, no expiry)
- *what* this credential is allowed to do (no scope — auth = full vault read AND full vault write)
- *whether* this credential has been revoked since some past event
- *how many times* this credential has been used in a window (no per-user rate limit)

In other words: **possession of `(uid, ah)` is the authorization.** This is equivalent to a permanent, non-expiring, single-purpose API key — except it is sent on **every** API request, not minted once and stored.

### 1.2 — Why this is risky

The `(uid, ah)` pair is a function of `(username, password)` only:

```
ah = Argon2id(password, salt = SHA-256(username + serverPepper), iterations = 100_000)
```

(See `crypto/keyDerivation.ts`. The salt is deterministic from the username, so the same password always produces the same `ah`.)

Consequences of this design:

| Property | Implication |
|---|---|
| `ah` is **deterministic** — same password → same `ah` forever | Rotating `ah` requires changing the password, which requires re-deriving the master encryption key, which requires re-encrypting the entire vault. There is no "rotate the auth credential without re-encrypting." |
| `ah` is **stable** for the account's lifetime | A leaked `ah` is valid until the user changes their password. There is no expiry. |
| `ah` is sent **on every API call** | Leakage surface includes: process memory of the client, OS keychain dumps (if the device is unlocked + rooted), TLS-terminating reverse proxies, request logs (if any), browser dev tools (web build), Replit's request-log infrastructure, etc. The blast radius scales with how often the API is called. |
| The server has **no way** to know an unauthorized party is using `ah` | No IP history, no device fingerprint, no anomaly detection, no audit log. Compromise is silent. |
| The user has **no way** to invalidate `ah` short of changing their password and re-encrypting the entire vault | "Sign out from all devices" is not implementable on the server side without shipping `T-4` (session concept). |

### 1.3 — Specific attack scenarios from credential compromise

**Scenario A — keychain extraction from an unlocked rooted device:**
The attacker reads `expo-secure-store` storage. Both `userId` and `authHash` are present (see `lib/credentials.ts`). They now have a stable, indefinite credential. The legitimate user notices nothing. Fix requires the user to (a) change their password, which (b) rotates the master key, which (c) requires uploading a freshly-encrypted blob, *and* (d) the legitimate user must be on a device they trust at the time of the rotation, since the attacker's device will still hold the old credentials and could push a stale (or hostile) blob in the meantime.

**Scenario B — memory disclosure on the client:**
Native crash-reporting tools (Bugsnag, Crashlytics, Sentry) can capture process memory in some configurations. `creds.userId` and `creds.authHash` are read into a local variable on every authenticated request (`lib/query-client.ts:97-98`). Any crash captured between the read and the network call could include them. Minimum mitigation is `T-4`: replace `ah` with a short-lived bearer token after login.

**Scenario C — TLS-terminating proxy log:**
If the server is later put behind a CDN/WAF that logs request headers (a common operational decision), `x-auth-hash` ends up in the access log. Mitigation: do not log custom headers. Better mitigation: switch to a session token that is short-lived enough to be useless once it appears in a log.

**Scenario D — malicious mobile app update:**
If an attacker compromises the Expo update channel (bypassing code signing) and pushes a hostile JavaScript bundle, the bundle can read SecureStore and exfiltrate credentials. This is OUT OF SCOPE for the server but MOTIVATES `T-1` (revocation): even if every other defense fails, the user must be able to revoke. Today they cannot.

### 1.4 — Risk rating

**P0**, captured as **T-1 — No credential revocation.** This is the foundational gap; almost every other recommendation in §5 follows from it.

---

## 2. Replay and Abuse Scenarios (Goal 2)

### 2.1 — Replay primitives available to a network attacker (no creds)

| Captured request | Replayable? | Effect |
|---|---|---|
| `POST /api/auth/register` | No (would 409 — username already exists) | Harmless |
| `POST /api/auth/login` | Yes | Reveals salt+iterations + 200 OK. No additional capability beyond the captured response itself. |
| `GET /api/auth/salt/:user` | Yes | Public-by-design endpoint; replay = no new info. |
| `POST /api/vault/sync` | Yes — replay succeeds at server level (no nonce, no signature) BUT will be rejected by the version monotonicity CAS once the legitimate client has advanced the version. | Attack window is the time between capture and the next legitimate sync. Inside that window, the server cannot distinguish the replay from the original. |
| `GET /api/vault/fetch` | Yes — replay returns the current encrypted blob. | Attacker gets the latest blob (encrypted; useless without `ah` already + `password` to derive master key). |

**What replay buys an attacker** (without creds): essentially nothing actionable, *because* the body is encrypted under a key derived from a password the attacker doesn't have.

**What replay buys an attacker WITH creds** (i.e. they hold `(uid, ah)`): everything in §2.2.

### 2.2 — Replay primitives available to a credential holder

| Action | Server limit today | Risk |
|---|---|---|
| Repeat `GET /api/vault/fetch` | **None.** No per-IP, no per-user rate limit on vault endpoints. | Attacker can scrape the (encrypted) blob arbitrarily fast. Useful for exfiltrating successive snapshots over time, e.g. to confirm the user changed something. |
| Repeat `POST /api/vault/sync` with monotonically-increasing version | **None** (only the version-CAS check). | Attacker can write to the vault as fast as the network and the DB allow. Each write replaces the previous encrypted blob; if the attacker has the master key (derived from `ah`+`password`), they can replace it with hostile content. Even *without* the master key, they can replace it with garbage and break the vault. |
| Drive `version` toward `INT32_MAX = 2_147_483_647` | The schema's `vault_blobs_version_range` check allows version up to integer max. Once `version` is at `INT32_MAX`, **no future write can succeed** because the CAS condition `version < newVersion` becomes unsatisfiable for any 32-bit `newVersion`. | **Permanent denial-of-vault.** Already noted in `vault_state_machine_audit.md` as P0-NEW. Combined with the fact that nothing rate-limits `/api/vault/sync`, an attacker can hit `INT32_MAX` in *one* request by simply choosing `version: 2147483647` — they don't even need to iterate. |
| Repeat `POST /api/auth/login` | Per-IP rate limit (10/min). | Per-username has no limit other than the per-IP cap. Attacker with a residential proxy pool of N IPs has effective limit `N × 10/min`. |
| Push the vault repeatedly to slowly pollute encrypted contents | None (no per-user write limit, no audit log). | Insider-style abuse. Even the legitimate user wouldn't notice unless they happen to open the app and see entries missing or scrambled. |

**Risk rating:** the lack of a per-user vault rate limit is **P0 (T-2)** because it is the enabler of T-3 (denial-of-vault). Even without the version-bomb, "unlimited writes per second per credential" allows a creds-holding attacker to spend the user's storage quota and waste DB I/O budget at no cost.

### 2.3 — State-machine abuse over time

Three slow-burn abuse paths the current server cannot detect or prevent:

1. **Version exhaustion (T-2 + T-3 combined).** One malicious sync with `version: 2147483647`. Vault is permanently locked. No alert, no recovery.
2. **Slow blob bloat.** Attacker pushes 9 MiB encrypted blobs at 1/second. Per-user storage usage grows; database disk fills; legitimate sync requests start timing out. No per-user storage cap exists.
3. **Read-amplification.** Attacker `GET /api/vault/fetch` continuously to capture every change the legitimate user makes. Combined with offline brute-force against the captured `ah` (if it ever leaks separately), the attacker reconstructs every state of the user's vault over time. Mitigation: per-user fetch rate limit AND audit log so the user can see "your vault was read 14,000 times today."

---

## 3. Missing Protections (Goal 3)

### 3.1 — No session concept (T-4, P1)

Every authenticated request re-presents the long-lived `ah`. Standard mitigations not in place:

- No session token issued on login
- No token expiry / refresh
- No "log out everywhere"
- No "active sessions list"

### 3.2 — No device binding (T-5, P1)

The server cannot tell whether request #1 came from the same device as request #2. Standard mitigations not in place:

- No device ID registered at first login
- No device fingerprint (IP+UA+ASN coarse fingerprint)
- No per-device approval ("a new device just logged in — was that you?")

### 3.3 — No anomaly detection (T-6, P1)

The server has no signal for:

- Geographic anomalies ("login from a country you've never used before")
- Time-of-day anomalies ("vault read at 3am when you usually use it 9-5")
- Volume anomalies ("4,000 fetches today vs your usual 12")
- Pattern anomalies (rapid sync-then-sync-again-with-different-content cycles)

Even raw audit data is missing — there is no `audit_log` table, no per-request log of `(userId, endpoint, timestamp, ip, ua)`. Without that data, anomaly detection cannot be added later because there's nothing to learn baselines from.

### 3.4 — No per-user write limits (T-2 / T-7, P0+P1)

| Endpoint | Per-IP limit | Per-user limit |
|---|---|---|
| `/api/auth/register` | 10/min | none (irrelevant — register is one-shot) |
| `/api/auth/login` | 10/min | **none** (T-8 — per-username brute force is bounded only by IP pool size) |
| `/api/auth/salt/:user` | 10/min | **none** |
| `/api/vault/sync` | **none** | **none** |
| `/api/vault/fetch` | **none** | **none** |
| `/api/health` | none | none (acceptable — public health check) |

The vault endpoints rely *entirely* on the auth check. There is no second layer of "even if you authenticated, you can only do this N times per minute."

### 3.5 — No second factor (T-8, P1)

Login accepts `(username, ah)` and that's it. The auth model has no provision for:

- TOTP (Authenticator app)
- Passkey / WebAuthn
- SMS (least desirable; included for completeness)
- Email magic link

This is a function of the zero-knowledge design: a second factor that the server controls would change what the server learns. But several second-factor designs are compatible with zero-knowledge — see §5.

---

## 4. Authentication Flow Attack Resistance (Goal 4)

### 4.1 — Credential stuffing

**Defense today:** per-IP rate limit (10/min) on `/api/auth/login` and `/api/auth/salt`. Per-username hashing is timing-safe (constant work whether the user exists or not — see `routes.ts:155-166`).

**Gaps:**
- No per-username lockout after N failed attempts. Attacker who controls many IPs (residential proxy pool, ~$5/mo gives thousands of IPs) gets `IPs × 10/min` attempts per username.
- No exponential backoff per username.
- Salt endpoint allows the attacker to *batch* the offline KDF cost: query `/api/auth/salt/:user` once per username, then run Argon2id for the candidate passwords offline using the stolen salt. Per-IP limit on `/api/auth/salt` slows down the *salt collection* phase but not the password testing.

**Rating:** the current per-IP-only rate limit is enough to defeat naive single-host stuffing but **not** a mid-tier proxy-pool attacker. **P1 (T-8).**

### 4.2 — Replay (covered §2.1, §2.2)

Server has zero replay protection at the HTTP layer (no nonce, no request signature, no time window). Within a single vault version it relies entirely on TLS to prevent replay. Cross-version, the CAS check protects against version-rollback but NOT against "replay the *same* request inside its valid window."

**Rating:** P1 — addressed by `T-4` (session tokens) and a request-id replay cache.

### 4.3 — Token leakage

There is no token; the `ah` *is* the credential. This means:

- No "the token was leaked, rotate the secret" possibility — leakage = full account compromise until password change.
- Leakage surface is large because `ah` is sent on every request.
- The client *does* keep `ah` in `expo-secure-store` (Keychain / Keystore on native; the prior audit confirmed AsyncStorage is NOT used, which is correct). On web, `lib/credentials.ts` falls back to `localStorage` — this is a known weak spot but is acceptable for the web build given the threat model is scoped to "first-party self-hosted by the user."

**Rating:** P0 / P1 — addressed by `T-1` (revocation) + `T-4` (session token replaces `ah` on the wire after login).

---

## 5. Concrete Improvement Proposals (Goal 5 — Do NOT Implement Yet)

Each proposal is rated by impact and labeled with the constraints from §7.

### 5.1 — Session tokens (T-4, addresses T-1, P0)

**Design sketch (NO crypto changes; compatible with zero-knowledge):**

- On successful `/api/auth/login`, server mints a random 256-bit session token (`randomBytes(32).toString("hex")`), stores `(token_hash = sha256(token), user_id, issued_at, expires_at, last_seen_at, device_fingerprint?)` in a new `sessions` table, returns the raw token in the response.
- Client stores the token in `expo-secure-store` instead of (or alongside) `ah`.
- Vault endpoints accept either `x-session-token` (preferred) or `x-auth-hash` (transitional). Eventually, only the token.
- Tokens have a TTL (e.g. 30 days sliding, or 7 days hard).
- **Revocation primitive:** `DELETE /api/auth/sessions/:token` and `DELETE /api/auth/sessions` (all). This is what unlocks T-1.
- The server still never sees the master encryption key — sessions only authorize *transport* of the encrypted blob, not decryption.

**Compatibility:** zero impact on `crypto/`. Adds one new table + two new endpoints. Existing `ah`-based auth can stay during migration.

**Trade-off:** the server now has long-lived state (session table). This is acceptable because the *contents* of sessions are hashes, not plaintext credentials, and the server already has long-lived state for the vault blob.

### 5.2 — Per-user rate limits in addition to per-IP (T-2, T-7, P0)

**Design sketch:**

- Extend `isRateLimited(key)` to check both `${endpoint}:ip:${ip}` AND `${endpoint}:uid:${userId}` (for endpoints where userId is known).
- Limits (initial proposal — needs tuning against real client behavior):
  - `/api/vault/fetch` — **60/min/user** (1/sec sustained; bursty foreground sync OK)
  - `/api/vault/sync` — **30/min/user** (one sync per 2 seconds; far above any plausible legitimate cadence)
  - `/api/auth/login` — **5/min/user** (in addition to 10/min/IP)
- 429 response must NOT distinguish "you hit the per-IP limit" from "you hit the per-user limit" (information leakage).
- Storage for the rate-limit counters: in-memory Map is fine for a single-node deploy; document that horizontal scaling will require Redis.

**Compatibility:** zero impact on `crypto/`. Adds a new key shape to the existing `rateLimitMap`.

### 5.3 — Vault write quotas (T-3, P0)

**Design sketch — two complementary controls:**

1. **Per-user write rate** (covered by 5.2 — 30/min/user on `/api/vault/sync`).
2. **Version cap below `INT32_MAX`.** Add a server-side check: if `parsed.data.version > MAX_USER_VERSION` (e.g. `1_000_000`), return 400 "Version out of range." This makes the version-bomb attack impossible; legitimate clients increment by 1, so a million versions is several lifetimes of ordinary use. (Alternative: switch the column to `bigint`. That avoids the cap but is a schema change. The cap is the smaller intervention.)
3. **Per-user storage budget.** Add `users.storage_budget_bytes` and reject syncs whose blob size exceeds the budget. Default e.g. 50 MiB.

**Compatibility:** zero impact on `crypto/`. Adds one nullable column + one server-side bound check. The MAX_USER_VERSION cap may also be expressed as a CHECK constraint in the schema for defense-in-depth.

### 5.4 — Optional second factor (T-8, P1)

Two zero-knowledge-compatible designs:

- **TOTP (RFC 6238):** server stores a per-user TOTP secret (encrypted with a server-side key, since this *is* server-side state by definition). On login, after `ah` check, server requires a 6-digit TOTP code. This *does* increase server-side state — that's the point of a second factor.
- **Passkeys (WebAuthn):** server stores per-user public keys; login challenges must be signed by the corresponding private key held in a TPM/Secure Enclave. This is the strongest option and is fully compatible with zero-knowledge (the private key is on the device, not the server). Cost: significant client+server work; partial web support; native works via `expo-passkey`.

**Recommendation:** start with TOTP (low effort, high benefit). Plan passkeys for v2.

### 5.5 — Device tracking and "active sessions" UI (T-5, T-10, P1)

Couples naturally with 5.1:

- At login, capture a device fingerprint: `{ip, user_agent, expo_app_version, platform}` (none of these are secrets; document that the IP is stored).
- Surface "Active sessions" to the user in-app so they can see *and revoke* each one.
- On a new-device login, optionally email the user (or send a push, if push is wired up later) — note: this requires a contact channel which the current schema does not have, so this is a P2 follow-on.

### 5.6 — Audit log of vault writes (T-6, P1)

**Design sketch:**

- New table `vault_audit_log(id, user_id, action, version_before, version_after, blob_size_bytes, ip, user_agent, created_at)`.
- Append-only (no UPDATE, no DELETE). Inserted by the server on every successful sync.
- Optionally exposed read-only at `GET /api/vault/audit` (authenticated, paginated).
- This is the foundation for any future anomaly detection.

**Compatibility:** zero impact on `crypto/`. The audit log records *that* a write happened, not *what* was written — so it does not weaken the zero-knowledge property.

### 5.7 — Vault history / recovery (P1, addresses T-3)

**Design sketch:**

- Keep the last N successful blobs per user (e.g. N=10) in a separate `vault_blob_history(user_id, version, encrypted_blob, archived_at)` table.
- Provide `GET /api/vault/history` and `POST /api/vault/restore?version=N` endpoints.
- Restore must require the second factor if 5.4 is enabled, else require the user to re-enter their password.
- Bound history table size aggressively — history is an N-snapshot ring buffer, not unbounded growth.

**Compatibility:** zero impact on `crypto/`. The history records exactly the same encrypted blobs the server already stores, just more of them.

---

## 6. Denial-of-Vault Scenarios (Goal 6)

### 6.1 — Concrete DoV attacks available to a credential holder TODAY

**Attack DOV-1: Permanent version exhaustion (P0 — T-3).**
Single request: `POST /api/vault/sync` with `version: 2147483647` and any encrypted blob the attacker constructs (could even be the legitimate current contents, just bumped). After this, the CAS condition `version < newVersion` is unsatisfiable for every 32-bit version, so the legitimate user can never sync again. The vault becomes read-only forever. There is no way to recover other than dropping the row (which loses all data).

**Attack DOV-2: Content destruction (P0).**
The attacker holds `ah` *and* (by assumption of credential compromise) likely also `password`. They can derive the master key and write a vault encrypted with the same key but containing all-empty entries. The legitimate user's app will accept the new blob (signature verifies, version is monotonic), and the user's data is gone — except the attacker still has it offline.

**Attack DOV-3: Storage flooding (P1).**
Attacker pushes a 9.99 MiB blob 60 times per second (current limits allow this — no rate limit, blob limit is 10 MiB). Per-user storage cost balloons; if the deploy uses a DB with storage quotas (most managed PG offerings), this hits the deploy's storage limit and breaks the app for *all* users.

**Attack DOV-4: Account takeover (out of crypto scope but worth noting).**
Attacker calls `/api/auth/login` with the right credentials, receives the salt+iterations, and is now in. Once in: see DOV-1, DOV-2, DOV-3.

**Attack DOV-5: Username squatting on register.**
The attacker, having captured a username, registers it before the legitimate user does. This is mitigated by the `users_username_unique` constraint *only after* one party registers. There is no out-of-band proof-of-ownership ("this email belongs to me") because PiPass deliberately collects no contact info. **Accepted residual risk.**

### 6.2 — Lack of recovery mechanisms

| Loss event | Recovery today | After §5 proposals |
|---|---|---|
| Vault row corrupted by attacker | None | Restore from `vault_blob_history` (5.7) |
| Vault row version-bombed | None (must drop the row, losing data) | (a) version cap from 5.3 prevents the bomb; (b) if it happens, restore from history |
| User forgets password | None — by zero-knowledge design, server cannot help. **Accepted.** | Same. (No change — that's the point of zero-knowledge.) |
| Credentials leaked to attacker | None — must change password (full re-encryption) | "Revoke all sessions" via 5.1; attacker is locked out instantly. |
| Device lost | None | "Revoke this device" via 5.5. |

### 6.3 — Recovery is the most-impactful gap to close

Even if every other recommendation slipped, **adding a vault history (5.7) is the single most-valuable defense against DoV**, because it converts every irreversible attack into a reversible one. It costs O(N) extra storage per user (small N = 10 acceptable), and it does not weaken the zero-knowledge property at all.

---

## 7. Compatibility & Constraints (Goal 7)

These constraints are taken as fixed by this review:

| Constraint | Adhered to in §5? |
|---|---|
| Do not modify `crypto/` logic | ✅ Every proposal explicitly preserves `crypto/`. Session tokens are an *additional* secret on the wire, not a replacement for `ah`'s role inside the KDF chain. |
| Do not weaken existing protections | ✅ All proposals are additive. The version-cap (5.3) tightens the existing CAS; per-user rate limits (5.2) tighten existing per-IP rate limits; sessions (5.1) tighten the long-lived `ah` model. |
| Do not change PK column types | ✅ All new tables use new PKs (e.g. `sessions.id`, `vault_blob_history.id`); no proposal mutates `users.id` or `vault_blobs.user_id`. |
| Do not break the zero-knowledge property | ✅ Verified per proposal. The audit log (5.6) records metadata only, not plaintext. The history (5.7) stores the same encrypted blob the server already stores. |
| Do not break the API contract for already-deployed clients | ⚠️ Sessions (5.1) are designed to be *additive* during a migration window: server accepts both `x-auth-hash` and `x-session-token`; clients move over at their own pace. Once telemetry shows no client uses `ah` for vault calls, the `ah` path on vault endpoints can be removed. |

### 7.1 — What NOT to do

These are tempting "improvements" that would weaken the model and should be **rejected**:

- ❌ **Do not** add server-side master-key escrow ("we'll let you reset your password"). Breaks zero-knowledge.
- ❌ **Do not** log `x-auth-hash` or `x-session-token` anywhere (no access logs, no error reports, no analytics).
- ❌ **Do not** distinguish "user not found" from "wrong password" in any response, on any endpoint, at any status code. The current code already does this correctly — it must stay correct in any new endpoints.
- ❌ **Do not** add a "security questions" recovery flow. Trivially socialed; weakens the zero-knowledge model.
- ❌ **Do not** weaken Argon2id parameters to make login faster. The 100k-iteration cost is a feature: it makes credential stuffing expensive.
- ❌ **Do not** allow client-supplied salt or iterations for any operation other than registration. Existing endpoints enforce this; new endpoints (5.x) must enforce it too.
- ❌ **Do not** add a "remember me" / "stay signed in for 1 year" toggle on top of the new session model. The 30-day TTL ceiling exists for a reason.

---

## 8. Cross-References to Prior Audits

This review **does not duplicate** the analysis in:

- `auth_security_review.md` — full prior coverage of registration / login / salt-fetch / replay-resistance / interception. This document **extends** it by focusing specifically on the credential-compromise and DoV threat surfaces.
- `vault_integrity_audit.md` — covers blob tamper resistance, integrity guarantees, concurrency, and the malformed-input edge cases. The relevant cross-ref is §3.8 ("No vault rate limit") — this review escalates that finding to **P0 (T-2)** because the recent /api/vault/* hardening pass did not add per-user limits.
- `vault_state_machine_audit.md` — the **P0-NEW version exhaustion lockout** finding from §1.4 of that document is the same root cause as **DOV-1 (T-3)** in this review. The mitigation proposed in §5.3 (`MAX_USER_VERSION` cap) addresses both.
- `threat_model.md` — the asset/boundary/threat-category framing. The findings here map back to: Spoofing (T-1, T-5, T-8), Tampering (T-3 via DOV-2), Repudiation (T-6), DoS (T-2, T-3, T-7), Elevation (T-1).

### 8.1 — Recommended order of remediation

1. **T-3 / DOV-1 — version cap** (one-line server check + optional CHECK constraint). Highest impact, lowest effort.
2. **T-2 — per-user rate limits on vault endpoints** (extension of existing rate-limit map). High impact, low effort.
3. **T-1 / T-4 — session tokens** (new table + new endpoints + client migration). Highest leverage; foundational for T-5 and T-10.
4. **§5.7 — vault history** (one new table + two endpoints). Converts DoV from terminal to reversible.
5. **T-6 — audit log** (one new table + write on every sync). Foundation for any later anomaly detection.
6. **T-8 — TOTP second factor** (new table + new endpoints + UX).
7. **T-5 / T-10 — device tracking + active sessions UI** (extends 5.1).
8. **Passkeys** — long-term replacement for `ah` on the wire.

Steps 1 and 2 close the highest-severity findings with the smallest possible change footprint. Everything else is incremental defense-in-depth.

---

*End of review.*
