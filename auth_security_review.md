# Authentication Flow Security Review — PiPass

Companion document to `threat_model.md`. Where the threat model surveys the whole system, this review drills into one question: **is the auth protocol — header-based shared-secret with no session — safe for public internet exposure and mobile-app usage?**

Scope: protocol-level only. No crypto-primitive changes proposed. No code modified.

---

## State of the implementation (read this first)

A grep over `app/`, `screens/`, `components/`, `hooks/`, `lib/`, `workers/` finds **zero call sites** for `/api/auth/*` or `/api/vault/*`. The only HTTP client (`lib/query-client.ts`) does not attach `x-user-id` or `x-auth-hash` headers anywhere — its `apiRequest` helper has no auth-injection path at all. The vault flows through `workers/storageWorker.ts` against `expo-secure-store` (Keychain/Keystore) only.

So:

- The **server-side protocol** is fully implemented, validated, and rate-limited. Six endpoints, strict input validation, timing-safe comparison, anti-enumeration responses (audited in the prior task).
- The **client-side wiring** does not yet exist. `lib/query-client.ts` uses `credentials: "include"` (a cookie pattern) but the server is sessionless and does not read cookies.

This means everything in this review is **forward-looking**. The protocol is well-designed in isolation, but the moment a screen calls `/api/vault/sync`, the client must implement the recommendations in §5 — otherwise good server-side hygiene is wasted at the seams.

---

## 1. Current auth model (factual baseline)

### Registration

- Client sends `POST /api/auth/register` with body `{username, authHash, salt, iterations}`.
- `authHash` is `SHA-256(deriveMasterKey(password + ":" + deviceUUID, salt, iterations))` — see `crypto/keyDerivation.ts` and the `hashMasterKey` function.
- Server SHA-256s the received `authHash` *again* before storing it: `users.auth_hash = SHA-256(client-form-authHash)` (`server/routes.ts:111`).
- Response returns `{id, username, salt, iterations}`. The client persists `id` somewhere.

### Login

- Client sends `POST /api/auth/login` with `{username, authHash}`.
- Server looks up by username, hashes the supplied `authHash`, `timingSafeEqual`s against the stored hash. Failure → 401 "Invalid credentials". Same constant-cost hash runs on the unknown-user branch (`server/routes.ts:140`) so timing does not leak account existence.

### Salt fetch (pre-login)

- Client sends `GET /api/auth/salt/:username`.
- Server returns `{salt, iterations}` for known users; **deterministic dummy** `{salt, iterations}` for unknown users (HMAC over username with a per-process secret — `server/routes.ts:71`). An attacker probing usernames cannot distinguish real from fake. Necessary because the client must derive the master key *before* it can produce `authHash`.

### Protected vault operations

- Every request to `/api/vault/sync` and `/api/vault/fetch` carries:
  - `x-user-id`: UUID, validated against `userIdHeaderSchema` = `z.string().uuid()`.
  - `x-auth-hash`: hex string in the same length range as the `authHash` body field (64–128 hex chars), validated against `authHashHeaderSchema`.
- Any malformed/missing/duplicate header → 401 "Authentication required" (single error message — no enumeration of failure type).
- After validation, server: `getUser(userId)` → if absent return 401 "Invalid credentials" (collapsed); else `SHA-256(authHash)` then `timingSafeEqual` against `users.auth_hash`. Failure → 401 "Invalid credentials". Success → process the request.

**No sessions. No cookies. No tokens. No state on the server beyond the user row itself.** Every request re-authenticates from first principles.

---

## 2. Replay resistance

**Question:** if an attacker captures a valid request (`x-user-id`, `x-auth-hash`, body), can they replay it to the server later?

### Header replay = full impersonation

`x-user-id + x-auth-hash` is a **bearer credential**. Possession is sufficient. There is no nonce, no timestamp, no signature over the request, and no key rotation. A captured `x-auth-hash` is valid until the user changes their master password (which causes `authHash` to change, which causes a new `users.auth_hash` to be stored). Because there's no server-side session, there is also no "log out everywhere" — an exfiltrated `authHash` remains valid until the user manually rotates their password.

This is **structurally identical to a long-lived bearer token** (e.g., a never-expiring JWT or a static API key). The security depends entirely on three things:

1. The credential never crosses an unencrypted channel.
2. The credential is never written to durable storage outside the SecureStore boundary.
3. The credential is never logged.

### Per-endpoint replay impact

| Endpoint | Captured request replay impact |
|---|---|
| `POST /api/auth/register` | Replay → 409 "Username already taken". Harmless after first registration. |
| `POST /api/auth/login` | Replay → 200 with `{id, salt, iterations}`. Attacker already has the body (which contains `authHash`), so login replay yields nothing they don't already have. **No DoS amplification** because rate-limited. |
| `GET /api/auth/salt/:username` | Idempotent. Already public. No new info from replay. |
| `GET /api/vault/fetch` | Replay returns the current `encryptedBlob`. Attacker who can replay can also issue fresh requests (they have the credential), so replay is not the attack — the credential exfiltration is. |
| `POST /api/vault/sync` | **Most interesting.** Replay of a STALE captured sync request loses the `version < $newVersion` check at the SQL layer (`server/storage.ts:76`) and is silently dropped (returns the current version, no rollback occurs). Replay of the MOST-RECENT captured sync just rewrites the same blob over itself — also harmless. Cannot be used to roll the vault back to an earlier state. |

**Verdict on replay:** the protocol is replay-resistant *in practice* not because it includes anti-replay primitives, but because (a) the credential alone is sufficient for any operation so replay is strictly weaker than fresh requests, (b) sync writes have a server-side monotonic version check that defeats rollback. There is no weaker-than-fresh-request capability that replay grants.

**The real attack is credential exfiltration**, not request replay. Section 3 below.

### Hypothetical sub-cases worth noting

- **Web client + browser cache.** N/A — `lib/query-client.ts` uses `credentials: "include"` (a cookie pattern), not header-based auth. When migrated to headers, the headers will be set per-request and not cached by the browser; this is fine.
- **Service worker / PWA.** N/A — Expo mobile is the target.
- **Replay across users.** Cannot — `x-user-id` and `x-auth-hash` must match the same row. An attacker cannot mix-and-match.

---

## 3. Interception analysis

### What an attacker on the network can do

PiPass is a Replit-hosted service: TLS terminates at the Replit edge proxy. The attacker scenarios are:

| Position | Capability against the protocol |
|---|---|
| Plain WiFi / passive eavesdropper, app on HTTPS | Sees nothing usable. TLS protects bodies and headers. |
| Active MitM with bogus CA installed on victim's device | Reads everything → full credential exfiltration → game over. |
| Compromise of Replit edge | Reads everything in flight after TLS termination. Out of project scope. |
| Compromise of the Express process | Sees `x-auth-hash` per request. Sees `users.auth_hash` (the SHA-256-wrapped form). Cannot derive the master key from either. |
| Compromise of the DB process | Sees `users.auth_hash` (server-side SHA-256-wrapped). Must invert SHA-256 to get a usable bearer credential — practically infeasible if the client-form `authHash` is the output of a 256-bit Argon2id key (the input space is too large). Sees the encrypted vault blob — useless without the master key. |

### What about the headers vs body?

A subtle but important detail: `authHash` appears **both** in the `POST /api/auth/login` body **and** in the `x-auth-hash` header on subsequent vault calls. They are the same value. So:

- Anyone who can intercept ONE login request has the same value an attacker who intercepts ONE vault request would have. The attack surface is the same for both endpoints.
- Implication: there is no benefit to "rotating" between login and vault calls, because the same secret travels on both.

### TLS hardening recommendations

1. **HSTS** — force HTTPS at the Replit edge if not already on. Strictly speaking outside the app code, but the Replit deploy config can opt in.
2. **Certificate pinning** in the mobile client. Expo supports this via `expo-network` or via custom native modules. **Recommended at production-launch maturity.** This is the strongest mitigation against active MitM with a bogus CA on the device — without pinning, a malicious enterprise root cert (or stolen MDM-installed cert) reads all traffic in plaintext.
3. **No mixed-content fallback.** `lib/query-client.ts` already constructs `https://${EXPO_PUBLIC_DOMAIN}` unconditionally — good. Reject `EXPO_PUBLIC_DOMAIN` values without a leading `https://` (or reject embedded `http://`) to defend against accidental dev-config bleeding into prod.

---

## 4. Sufficiency of header-only auth — vs sessions / JWT

### What the current model does well

| Property | This protocol | Session cookies | JWT |
|---|---|---|---|
| **Stateless server** | Yes — no session table, no token store. | No — session table required. | Yes. |
| **No CSRF surface** | Yes — custom headers cannot be sent cross-origin without CORS preflight. | No — cookies are sent automatically; needs CSRF token. | Yes only if NOT in cookies. |
| **Trivial to revoke an exfiltrated credential** | No — requires user to change password (forces `authHash` rotation). | Yes — delete the session row. | No (without a denylist). |
| **No expiration / refresh logic to get wrong** | True — there's no expiration logic to write. | True — sessions can have `expiresAt`. | False — refresh tokens are notoriously hard to get right. |
| **No PKI / signing key management** | True — no signing key to rotate. | True. | False — JWT signing keys must be rotated, and old keys must verify until the last issued JWT expires. |
| **No header-bloat per request** | True — two short headers (~104 bytes total). | Cookie can grow. | JWTs are typically 200–1000 bytes per request. |
| **Forensic logging** | Bad — no per-session ID, so logs can't correlate "this batch of requests was one user-agent's session." | Good — session ID in logs. | Good — `jti`. |
| **Server-side "kick all devices"** | Bad — only a master-password change rotates `authHash`. | Good — delete sessions. | Bad — needs a denylist. |
| **Crypto primitives required at runtime** | SHA-256 + timing-safe compare. That's it. | None additional. | HMAC (HS256) or RSA/ECDSA verify. |

### The honest assessment

For PiPass — a **single-user, zero-knowledge personal vault** — the header-based shared-secret model is **a deliberately simpler and arguably stronger choice than JWT**. Here's why:

1. **No session table = no session-table-leak.** A stolen DB still requires a SHA-256 preimage attack to produce a usable credential. With sessions, the leak gives the attacker a list of valid bearer tokens directly.
2. **No expiration logic = no expiration bug.** Most real-world session/JWT bugs are in the refresh / rotation / denylist code. There is none here to write.
3. **No CSRF surface.** Custom headers (not cookies) trigger CORS preflight; the existing CORS allowlist (`server/index.ts:17-54`) restricts permitted origins. A malicious site cannot make the user's browser issue authenticated requests.
4. **The crypto budget is spent on the right thing.** Argon2id over the user's master password is the security boundary. Layering JWT on top would not strengthen the vault — it would only add code that can break.

### The trade-offs the team must accept

1. **No "log out everywhere" UX** without a master-password rotation flow. A user whose phone is stolen and whose `authHash` may be exfiltrated has only one remediation: change the master password. This is fine for a personal vault but worth documenting in the user-facing security policy.
2. **No per-device session ID.** Forensic logs cannot distinguish "10 requests from this user" as one device or two. Mitigation in §5: client adds a `x-device-id` header (UUID, NOT for auth) so logs can correlate. This costs nothing security-wise.
3. **No expiration of an exfiltrated credential.** Mitigation in §5: optional master-password "auto-rotate every N months" reminder; or a server-side `auth_hash_rotated_at` column with a max-age policy that returns 401 forcing re-derivation.

### When this model is NOT enough

If PiPass ever adds:
- Multi-user features (shared vaults, family plans)
- Server-side computation that depends on user identity beyond ownership (e.g., admin dashboards, billing)
- Web access via a session cookie

…the model would need to be augmented with sessions or short-lived tokens. Until then, the simpler header-only model is **the right choice** and should be defended against feature creep that would erode it.

---

## 5. Recommendations (prioritized)

Each item is **protocol-level only** — no crypto-primitive changes.

### P0 — must-do before client wires up `/api/vault/*`

1. **Build an authenticated `apiRequest` helper.** Today's `lib/query-client.ts` doesn't attach `x-user-id` or `x-auth-hash`. The wiring must:
   - Read both values from `expo-secure-store` (NEVER from React state, which is heap-resident and inspectable via React DevTools in dev builds).
   - Attach them to every request to `/api/vault/*`.
   - On 401, clear the in-memory copy and require the user to re-derive (re-enter master password) — do NOT auto-retry with stale credentials.
   - Reject responses where `x-user-id` was not set (defensive — caller bug).
2. **Per-userId rate limit on vault endpoints.** Today only auth endpoints are IP-rate-limited. After auth wiring, an attacker who has obtained a valid `authHash` can hit `/api/vault/sync` as fast as the server accepts. Add a 60-req/min per-`userId` limit (post-auth, so the key is the validated header, not the IP). This blunts both DoS and bulk-write abuse.
3. **Server-side request log MUST omit `x-auth-hash`.** Verify this by writing a small unit test that asserts the logger's output never contains the substring `x-auth-hash` (case-insensitive) regardless of input. The existing logger in `server/index.ts:67-85` only logs method/path/status/duration, but a future change could regress this silently.

### P1 — strong recommendations for production maturity

4. **Certificate pinning in the mobile client.** Without pinning, a malicious root CA on the device defeats TLS and yields the credential in plaintext. Pin to the Replit edge cert (or a corporate CA if PiPass moves to its own domain). Plan for cert rotation (pin two — current and next-issuer's — to allow graceful change).
5. **Add an `x-device-id` header.** A non-secret, per-install UUID (already maintained by `getDeviceUUID` in `crypto/keyDerivation.ts`) sent on every authenticated request. Server logs the value alongside `userId`. Two benefits:
   - Forensic correlation across requests without requiring a session.
   - Optional future feature: per-user `known_devices` table — first-time access from a new device-id triggers a notification (server-side push or just a warning at next login).
6. **Implement master-password rotation flow.** Today there is no UI/server endpoint to rotate `authHash`. The DB schema doesn't even have `auth_hash_rotated_at`. Add: `POST /api/auth/rotate` taking `{oldAuthHash, newAuthHash, newSalt, newIterations, newEncryptedBlob, newVersion}` — atomic update of `users` and `vault_blobs` rows in a transaction. This is the "log out all sessions" capability under a sessionless model.
7. **Reject `EXPO_PUBLIC_DOMAIN` without HTTPS.** Add a startup assertion in `lib/query-client.ts` that `getApiUrl()` builds an `https://` URL in production. Currently it hardcodes `https://` so this is met by construction — formalize with a comment + assertion so it can't regress.

### P2 — nice-to-have, defense-in-depth

8. **Optional anti-replay window via timestamp header.** Add `x-request-time` (Unix seconds, signed by HMAC over `userId + timestamp + body-hash`, key derived from `authHash`). Server rejects timestamps outside ±60s of `now`. This is cheap (no key rotation, no nonce store) and provides:
   - Defense against captured-and-delayed requests on a partially-broken TLS pipeline.
   - Forensic timestamps the attacker can't trivially forge.
   - Verification that the attacker can compute HMAC(`authHash`, ...) — which they can if they have `authHash`, so this is *not* a real second factor; it's purely a hardening layer. Do **not** advertise it as one.
   *(Honest assessment: low marginal value if TLS holds. Skip unless certificate-pinning is also in place.)*
9. **Server-side `auth_hash_rotated_at` column with a soft max-age.** After N months without rotation, server starts returning a non-fatal warning header (e.g., `x-credential-age-warning: 180d`). Client surfaces it as a UI nudge to rotate.
10. **Audit log table for vault writes** (cross-listed in `threat_model.md` Repudiation section). Schema: `vault_blob_writes(userId, version, byteLen, deviceId, ip, ts)`. Append-only. Exposed via a future `/api/account/activity` endpoint so a user can see "your vault was written to from device X at time Y." This is the strongest defense against silent compromise.

### What NOT to do

- **Do NOT add JWTs.** They would not strengthen anything in this model and would introduce signing-key rotation as a new failure mode. The whole point of the header-shared-secret design is to eliminate that surface.
- **Do NOT add session cookies.** This would re-introduce CSRF surface.
- **Do NOT add a server-side "remember me" token.** Same problem — it becomes a long-lived bearer credential the server has to track and revoke, defeating the stateless property.
- **Do NOT weaken the rate limit kill-switch.** `DISABLE_RATE_LIMIT=true` is correctly silently-ignored in production (`server/routes.ts:36-49`). Don't add a "force enable" override.

---

## 6. Verdict

### Safe for public internet exposure?

**Yes, with the P0 recommendations applied** before the client wires up vault calls. The server-side protocol is sound: validated input, timing-safe compare, anti-enumeration responses, no leaks in error paths, rate-limited auth endpoints, monotonic-version-protected writes. The header-based shared-secret model has no CSRF surface and no session state to leak. The one real residual risk — credential exfiltration via active MitM with a bogus CA — is mitigated by certificate pinning (P1).

### Safe for mobile app usage?

**Yes, with two caveats:**

1. The credentials MUST be stored in `expo-secure-store` (Keychain/Keystore) and NEVER in `AsyncStorage` or React state. This is project-policy documented in `replit.md` and currently respected by the `crypto/` and `workers/storageWorker.ts` modules.
2. When the client wiring is built (P0 #1), the `apiRequest` helper must read credentials from SecureStore on every request rather than caching them in JS heap variables across React re-renders. The OS-managed Keychain is the boundary; the JS heap is not.

### Comparison summary

For a single-user zero-knowledge personal vault, the current header-based shared-secret model is **a better fit than session cookies or JWT.** It eliminates entire classes of bug (CSRF, refresh-token logic, signing-key rotation, session-table leaks) at the cost of forfeiting "log out everywhere" UX — a trade-off that is acceptable given the operational model. The recommendations above strengthen it incrementally without changing the underlying protocol.

The single highest-leverage improvement, by far, is **wiring the client correctly** (P0 #1) — until that lands, the well-designed server protocol is unused and any client-side bug introduced at integration time would land directly in the credential-handling code, where it would do the most damage.
