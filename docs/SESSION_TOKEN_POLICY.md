# Client Session Token Policy

## 1. Purpose

This document defines the design policy for client-side handling of raw server session tokens before PiPass adds logout UI, session-management UI, auth credential rotation, or password rotation.

It is design-only. It does not add storage keys, runtime code, tests, routes, schemas, crypto changes, UI, migrations, or environment changes.

## 2. Current State

The server already supports durable sessions:

- login creates a raw session token and stores only its SHA-256 `token_hash` in `sessions`
- `POST /api/auth/logout` requires `x-session-token` and deletes the matching session row
- `POST /api/auth/logout-all` accepts normal authentication and deletes all session rows for the user
- many server authenticated routes accept `x-session-token` first and fall back to legacy `x-user-id` plus `x-auth-hash`

The client currently stores API credentials through `lib/credentials.ts`:

- `pipass.auth.userId`
- `pipass.auth.authHash`

The client does not currently persist a raw server session token. Existing protected client helpers use `x-user-id` plus `x-auth-hash`. `logoutCurrentSession()` can best-effort call server logout only when a caller supplies a raw session token; otherwise it performs local credential clearing only.

## 3. Definitions

- `pipass.auth.userId`: local server user identifier. It identifies the account for legacy authenticated API calls.
- `pipass.auth.authHash`: local API credential proof. It is authentication secret material and must be rotated by a future server auth credential rotation flow.
- raw session token: server-issued bearer-like secret returned at login. Whoever holds it can authenticate as that session until expiry or revocation.
- `token_hash`: server-stored SHA-256 hash of the raw session token. The server must never store the raw token.
- device trust state: server-side trust state tied to device/session fingerprints. It is not proven by `installId`.
- `installId`: non-secret audit label. It is spoofable and must not prove identity, device trust, or vault access.
- biometric unlock: local convenience gate for local secrets. It is not server authentication proof.

## 4. Threat Model

Session-token policy must protect against:

- local storage compromise exposing bearer-like server access
- web storage compromise through XSS or browser profile access
- accidental logging of raw session tokens in request headers, errors, audits, or test output
- confusing session tokens with vault encryption or key derivation inputs
- using `installId` as false proof of session ownership
- stale session tokens remaining after logout, logout-all, nuclear reset, or auth credential rotation
- inconsistent API behavior when a request sends both session-token and legacy auth headers

This policy does not protect against a fully compromised runtime while the app is actively authenticated. A live compromised client can read any credential available to that process.

## 5. Option A: No Persisted Session Token

Option A keeps the current client model:

- do not persist raw session tokens client-side
- keep `x-user-id` plus `x-auth-hash` as the normal protected API credential path
- keep `logoutCurrentSession()` local-only unless an active flow supplies a raw session token
- use `POST /api/auth/logout-all` for server-side revocation when authenticated by legacy headers

Benefits:

- smallest local bearer-token storage risk
- no new storage key or native/web storage decision
- no migration needed before password/auth rotation design
- current tests and helpers remain aligned with the deployed client model

Costs:

- UI cannot reliably revoke "this exact current session" unless it still has a raw token in memory
- session list "current" semantics are limited for legacy-auth requests
- step-up continuity remains tied to server session rows but not necessarily to the client's main auth path

## 6. Option B: Persisted Session Token

Option B stores the raw session token client-side and moves more protected calls to `x-session-token`.

Native storage:

- store in SecureStore/Keychain/Keystore, preferably using the same platform storage abstraction used for credentials
- make it clearable independently and by `clearCredentials()` or a broader auth-state clear helper
- do not require biometric auth for every network request unless the product explicitly accepts the UX and failure-mode costs

Web storage:

- avoid plaintext `localStorage` if possible
- prefer memory-only session token for web when persistence is not required
- if persistence is required on web, document honestly that browser-accessible storage is vulnerable to XSS and profile compromise
- do not store it in cookies unless the server is redesigned for cookie CSRF protections and same-site policy

Benefits:

- enables reliable current-session logout from the client
- enables session-aware UI to identify and manage the active session
- aligns client authentication with server session, device-trust, anomaly, and step-up state
- allows future deprecation of broad `authHash` use

Costs:

- introduces a locally stored bearer-like secret
- requires new storage/wipe tests
- requires logging tests proving headers and errors never expose the token
- requires clear web-specific policy
- increases complexity during auth credential rotation and logout-all

## 7. Option C: Transitional Model

Option C keeps the current `authHash` model for existing protected vault and security APIs while preparing a narrow session-token path for session-management work.

Rules:

- do not persist raw session tokens broadly in the next implementation stage
- keep `x-user-id` plus `x-auth-hash` as the main protected API credential
- allow `logoutCurrentSession()` to use a raw session token only when a caller already has one
- introduce a dedicated session-token storage helper only when a concrete UI or flow needs current-session revoke or session continuity
- when introduced, the helper must have focused wipe, logging, and API-header tests before UI wiring

Benefits:

- preserves current stable auth behavior
- avoids broad bearer-token persistence before tests and UX policy exist
- creates a deliberate path to session-token adoption without blocking logout/local reset semantics

Costs:

- current-session server logout remains limited until session-token storage exists
- some server session features remain underused by the client
- implementation must avoid half-migrated requests that send inconsistent credentials

## 8. Recommendation

Recommend Option C for the next implementation stage.

PiPass should not broadly persist raw session tokens yet. The current client is built around `pipass.auth.userId` and `pipass.auth.authHash`, and Prompt 025 already gives local logout a safe behavior without creating a new bearer-token storage surface.

The next step should be a narrow session-token storage design and test prompt only when the product needs one of these concrete capabilities:

- current-session revoke from UI
- accurate "this session" marking in session management
- session-token-first migration for protected APIs
- step-up continuity that must be tied to the same client credential used for normal requests

Until then, `authHash` remains the main protected API credential, and session tokens remain server-side session state returned by login but not persisted by the client.

## 9. Storage And Wipe Rules

If a raw session token is stored later, use a new explicit key such as `pipass.auth.sessionToken`. Do not overload `pipass.auth.authHash`.

Storage rules:

- native: SecureStore/Keychain/Keystore via the platform storage abstraction
- web: prefer memory-only; if persistence is required, document the localStorage or IndexedDB risk explicitly
- never store in plaintext logs, analytics, crash reports, audit metadata, or request bodies
- never send to third-party services
- never mix into vault encryption, key derivation, recovery, key fingerprints, or `deviceUUID`

Wipe rules:

- vault lock: keep session token unless product decides logout should also lock and revoke
- local logout: clear session token and `pipass.auth.*`
- server logout success: clear local session token and `pipass.auth.*`
- server logout failure: still clear local session token and `pipass.auth.*`
- logout-all: clear local session token and `pipass.auth.*` after the local app processes the user action
- server `401` for session-token-auth requests: clear session token; decide whether to also clear `pipass.auth.*` based on the helper contract
- auth credential rotation: clear old session token by default, re-login or receive a new token only after server commit succeeds
- password rotation only: do not clear or rotate session token unless the flow also rotates server auth or product policy revokes sessions
- nuclear reset: clear session token, `pipass.auth.*`, local vault state, `installId`, and `deviceUUID`

Session token must not be needed to decrypt the local vault.

## 10. API Header Rules

Current rule:

- existing client helpers send `x-user-id` plus `x-auth-hash`
- `logoutCurrentSession()` sends `x-session-token` only if a caller supplies one

Future session-token rule:

- session-aware endpoints should use `x-session-token`
- endpoints that accept both schemes should follow the server's current precedence rule: if `x-session-token` is present, use it and ignore legacy headers
- clients should avoid sending both headers once migration is complete
- `POST /api/auth/logout` must remain session-token-only because legacy auth has no specific session row to delete
- `POST /api/auth/logout-all` may continue to accept either session-token auth or legacy auth

Recommended migration order:

1. keep vault sync/fetch on `x-auth-hash` until session-token storage is tested
2. move session-management UI to `x-session-token` first
3. move step-up-sensitive security actions to `x-session-token` only after UI and tests are ready
4. consider deprecating `x-auth-hash` for broad API access only after auth credential rotation and session-token storage are complete

## 11. Logout And Logout-All Behavior

Local logout:

- clear `pipass.auth.userId`
- clear `pipass.auth.authHash`
- clear future stored raw session token
- preserve local encrypted vault, shared vault blob, `installId`, and `deviceUUID`
- do not call `clearVault()` or `destroyAllData()`

Current-session server logout:

- use `POST /api/auth/logout` only with `x-session-token`
- clear local credentials even if the server call fails
- do not delete local vault data
- do not delete server vault blob/history, trusted devices, or audit history

Logout-all:

- call `POST /api/auth/logout-all` with whichever auth scheme is available
- clear the local session token and `pipass.auth.*` after the user confirms logout-all
- preserve local encrypted vault unless the user chooses reset
- server deletes session rows only; it must not delete vault blob/history, trusted devices, or audit history

## 12. Step-Up, TOTP, And Passkey Interaction

The server stores step-up freshness on session rows through `totp_verified_until`. That makes session tokens the natural long-term credential for step-up continuity.

Policy:

- TOTP/passkey setup, revoke, recovery acknowledgement, and other sensitive writes should prefer session-token auth once client token storage exists
- legacy `authHash` requests may continue during transition, but step-up errors must not be confused with invalid credentials
- a step-up challenge or temporary login token is not a session token and must not be persisted as one
- logout and logout-all should clear any local step-up UI state
- auth credential rotation should require fresh step-up when TOTP or passkeys are enabled
- password-only vault rotation should not depend on session token for local decryption

## 13. Logging And Audit Requirements

Raw session tokens must never appear in:

- console logs
- server request logs
- audit rows
- API response bodies except the one-time login response that intentionally returns the token
- thrown errors
- test assertion failure messages
- analytics or crash reports

Audit rows may record safe event names and metadata such as `logout` or `logout_all`, but must not include:

- raw session token
- `token_hash`
- `authHash`
- encrypted vault blob
- request headers
- request body
- cookies
- passkey internals
- recovery keys

Server storage must continue storing only `token_hash`, never raw session tokens.

## 14. Test Plan Before Implementation

Before any session-token storage implementation ships, add focused tests for:

- storing and reading a fake session token through a narrow helper
- clearing the token on local logout
- clearing the token on nuclear reset
- preserving `installId`, `deviceUUID`, and local encrypted vault data on logout
- `logoutCurrentSession()` using a stored token only through the new helper contract
- server logout failure still clearing local token and `pipass.auth.*`
- 401 handling clearing the right local auth state
- no logs or audit responses exposing raw session token, `token_hash`, `authHash`, headers, bodies, cookies, or encrypted blobs
- web behavior when persistent storage is unavailable
- native behavior using the SecureStore path
- requests with both auth schemes following the documented server precedence
- logout-all clearing local auth state while preserving local vault data

Do not add broad UI tests until the storage and helper behavior is covered by small deterministic tests.

## 15. Implementation Prompt Sequence

Recommended future sequence:

1. Add a design-reviewed `sessionToken` storage helper with no UI.
2. Add local storage tests for set/get/clear and reset boundaries.
3. Add logging and response hygiene tests for session-token-auth requests.
4. Update `logoutCurrentSession()` to read the stored token if present.
5. Wire an existing logout action to the helper.
6. Add logout-all client behavior and tests.
7. Move session-management UI requests to `x-session-token`.
8. Revisit whether vault sync and other protected APIs should migrate from `x-auth-hash` to `x-session-token`.
9. Design auth credential rotation with explicit session revocation policy.
10. Keep local password rotation and vault-root-key migration separate.

## 16. Open Decisions

- Should web ever persist raw session tokens, or should web use memory-only sessions?
- Should logout also lock the vault by wiping in-memory key shares?
- Should auth credential rotation revoke all sessions or only other sessions?
- Should password-only rotation revoke sessions, or should it leave server auth state unchanged?
- Should `x-auth-hash` eventually become login-only while `x-session-token` becomes the sole protected API credential?
- Should session-token storage be gated by biometrics on native, or would that create too much request friction?
- How should passkey-only users rotate or replace `authHash` if `authHash` remains a protected API credential?
- What is the exact retention policy for expired session rows and logout audit rows?
