# Logout And Reset Boundaries

## 1. Purpose

This document defines PiPass logout, credential clearing, vault reset, account reset, and nuclear reset boundaries before password rotation or server authentication credential rotation work begins.

It is an audit and product-semantics reference only. It does not add endpoints, UI, schemas, migrations, password rotation, auth credential rotation, crypto changes, or vault format changes.

## 2. Boundary Summary Table

| Boundary | Current implementation status | Local vault data | Local API credentials | installId | deviceUUID | Server sessions | Server vault/history | Server audit/trust |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Vault lock | Implemented in `app/(tabs)/index.tsx` and vault UI state | Kept | Kept | Kept | Kept | No server call | Unchanged | Unchanged |
| Local logout | Implemented as `logoutCurrentSession()` in `lib/logout.ts` | Kept | Clears `pipass.auth.*` | Kept | Kept | Best-effort server call only if caller provides a session token | Unchanged | May add logout audit if server logout is attempted and succeeds |
| Server current-session logout | Implemented as `POST /api/auth/logout` | Client responsibility | Client responsibility | Client responsibility | Client responsibility | Deletes current session row by session token | Unchanged | Adds `logout` audit row |
| Logout all sessions | Implemented as `POST /api/auth/logout-all` | Client responsibility | Client should clear current local `pipass.auth.*` | Keep | Keep | Deletes all session rows for user | Unchanged | Adds `logout_all` audit row |
| `clearVault()` | Implemented and tested | Deletes entries/index/hash/shared blob | Kept | Kept | Kept | No server call | Unchanged | Unchanged |
| `destroyAllData()` / nuclear reset | Implemented and tested | Deletes vault, notes, unlock metadata, shared blob, cached key | Deletes `pipass.auth.*` | Deletes | Deletes | No server call | Unchanged | Unchanged |
| Account deletion/reset | Not implemented | Future product decision | Future product decision | Future product decision | Future product decision | Future product decision | Future product decision | Future product decision |

## 3. Vault Lock

Vault lock is a local in-memory boundary. It should:

- wipe active key shares and hide unlocked vault UI
- clear plaintext views such as open decrypted entries or notes
- avoid server calls
- keep local encrypted vault data
- keep local unlock metadata
- keep local API credentials
- keep `installId`
- keep `deviceUUID`

Current code:

- `app/(tabs)/index.tsx` moves active shares into locked UI state, clears `keyShares`, and sets `vaultLocked`.
- `VaultScreen` receives the lock callback from the app root.
- No server logout endpoint is called by this boundary.

Important distinction: vault lock is not account logout. A locked vault may still have local API credentials available for future authenticated API requests.

## 4. Local Logout

`logoutCurrentSession()` exists in `lib/logout.ts`.

Current behavior:

- clear `pipass.auth.userId`
- clear `pipass.auth.authHash`
- attempt `POST /api/auth/logout` only when a caller provides a session token
- ignore server/network logout failures for local cleanup purposes
- keep local encrypted vault data unless the user chooses reset
- keep master salt/hash/security profile
- keep cached vault data only according to the separate vault-lock policy
- keep `installId`
- keep `deviceUUID`
- keep recovery key hash
- do not call `clearVault()` or `destroyAllData()`

Current limitation: no client-side stored session token was found. Protected client API calls currently use `pipass.auth.userId` plus `pipass.auth.authHash`, so the helper normally performs local credential clearing only. If a future caller has a raw server session token, it can pass that token to `logoutCurrentSession()` and the helper will make the existing server logout call before clearing credentials.

## 5. Server Current-Session Logout

`POST /api/auth/logout` exists in `server/routes.ts`.

Current behavior:

- requires `x-session-token`
- rejects missing or malformed session token headers with `{ error: string }`
- hashes the raw session token with SHA-256
- looks up an active session by token hash
- returns `401 { error: "Invalid credentials" }` for unknown or expired tokens
- deletes only the matching session row with `storage.deleteSessionById()`
- writes a safe `logout` audit event
- returns `200 { ok: true }`

Data ownership:

- deletes one row from `sessions`
- does not delete local client credentials by itself
- does not delete local vault data
- does not delete server vault blobs or history
- does not delete trusted device rows
- does not delete audit history

The endpoint is session-token-only by design. Legacy `x-user-id` plus `x-auth-hash` authentication has no session row to revoke for "current session" logout.

## 6. Logout All Sessions

`POST /api/auth/logout-all` exists in `server/routes.ts`.

Current behavior:

- accepts the normal authenticated request path, including session-token auth or legacy auth-hash auth
- applies the `logout_all` user/IP rate limit
- deletes all session rows for the authenticated user through `storage.deleteAllSessionsForUser()`
- writes a safe `logout_all` audit event
- returns `200 { ok: true, revoked }`

Data ownership:

- deletes every row in `sessions` for the user
- does not clear local credentials by itself
- does not delete local vault data
- does not delete server vault blobs or history
- does not delete trusted device rows
- does not delete audit history

Recommended client behavior:

- after a successful logout-all, call `logoutCurrentSession()` or otherwise clear the current app install's `pipass.auth.*`
- keep local encrypted vault data unless the user chooses reset
- keep `installId` and `deviceUUID`
- route the user to sign in again

## 7. `clearVault()`

`clearVault()` is a local vault reset boundary, not account logout.

Current behavior in `workers/storageWorker.ts`:

- deletes each `pipass_vault_<entryId>` listed in `pipass_vault_index`
- deletes `pipass_vault_index`
- deletes `pipass_master_hash`
- clears `pipass_shared_vault`

Current tested preservation:

- preserves `pipass.auth.userId`
- preserves `pipass.auth.authHash`
- preserves `pipass.installId`
- preserves `deviceUUID`

Recommended semantics:

- do not call server logout endpoints
- do not delete server vault blobs/history
- do not delete server sessions
- do not delete trusted device state
- do not clear API credentials unless a higher-level account/logout flow explicitly does so

`clearVault()` is covered by `workers/__tests__/storage-reset.test.ts`.

## 8. `destroyAllData()` / Nuclear Reset

`destroyAllData()` is the local fresh-install boundary.

Current behavior in `workers/storageWorker.ts`:

- calls `clearVault()`
- calls `clearAllNotes()`
- deletes master salt
- deletes security profile
- deletes show-keyprints preference
- deletes vault-initialized marker
- deletes fractal fingerprint
- deletes recovery key hash
- deletes shared migration marker
- clears cached master key from shared keychain storage where applicable
- clears local API credentials with `clearCredentials()`
- clears `installId`
- clears `deviceUUID`

Current UI flow:

- `components/NuclearResetModal.tsx` performs password verification, confirmation phrase, countdown, and optional biometric/passcode gate.
- `app/(tabs)/index.tsx` calls `destroyAllData()` from the nuclear reset confirm path.

Data ownership:

- local-only wipe
- does not delete server account data
- does not delete server sessions
- does not delete server trusted device rows
- does not delete server vault blobs/history
- does not delete server audit rows

That server-side preservation is intentional for this local boundary. A separate account deletion/reset product flow would need explicit server policy and dedicated tests.

`destroyAllData()` is covered by `workers/__tests__/storage-reset.test.ts`.

## 9. Account Deletion / Account Reset Status

No account deletion or account reset endpoint was found in this audit.

If added later, it should be designed separately from local nuclear reset. It must explicitly decide whether to:

- delete the `users` row
- cascade-delete vault blobs/history, sessions, trusted devices, passkeys, honeytokens, and audit rows
- preserve audit rows for abuse/fraud policy
- revoke all sessions first
- wipe local client credentials after server success
- wipe local encrypted vault data or offer it as a separate choice
- require step-up authentication
- add rate limits and safe audit events

Do not treat `destroyAllData()` as account deletion. It only resets local app state.

## 10. Server-Side Data Ownership

Server logout boundaries affect sessions only:

- `POST /api/auth/logout` deletes one current session row.
- `POST /api/auth/logout-all` deletes all session rows for the user.
- Both write safe audit rows.
- Neither endpoint changes `users.auth_hash`, vault blobs, vault history, trusted devices, passkeys, TOTP state, honeytokens, or audit history.

Server data that should remain unchanged by local logout:

- `users`
- `vault_blobs`
- `vault_blob_history`
- `trusted_devices`
- `webauthn_credentials`
- `honeytokens`
- `vault_audit_log`, except for new logout audit rows if a server logout endpoint is called

## 11. Client-Side Data Ownership

Client boundaries should remain separate:

- Vault lock owns in-memory key shares and plaintext views.
- Local logout owns `pipass.auth.*`.
- `clearVault()` owns local vault entries, vault index, master hash, and shared vault blob.
- Nuclear reset owns all local vault/unlock/recovery/API/install/device identifiers needed to make this app install behave fresh.

Recommended local logout wipe list:

- `pipass.auth.userId`
- `pipass.auth.authHash`
- future stored raw session token, if one is ever persisted

Recommended local logout preserve list:

- `pipass_vault_index`
- `pipass_vault_<entryId>`
- `pipass_notes_index`
- `pipass_note_<noteId>`
- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_master_key`, unless product decides logout should also lock the vault
- `pipass_recovery_key_hash`
- `pipass_shared_vault`
- `pipass.installId`
- `deviceUUID`

## 12. Tests Currently Covering These Boundaries

Covered:

- `workers/__tests__/storage-reset.test.ts` verifies `clearVault()` clears local vault data while preserving credentials, installId, and deviceUUID.
- `workers/__tests__/storage-reset.test.ts` verifies `destroyAllData()` clears vault data, notes, unlock metadata, cached key marker, recovery hash, shared blob, credentials, installId, and deviceUUID.
- `workers/__tests__/storage-reset.test.ts` verifies `logoutCurrentSession()` clears `pipass.auth.*`, preserves vault data, installId, and deviceUUID, is idempotent without a stored session token, and still clears local credentials when a server logout attempt fails.
- `server/__tests__/security.test.ts` verifies `POST /api/auth/logout` revokes only the current session, `POST /api/auth/logout-all` revokes all sessions, and neither deletes vault blob/history, trusted device state, or audit history.

Not directly covered yet:

- UI wiring for a logout action
- client behavior after logout-all clears local credentials from an actual screen
- account deletion/reset, because it is not implemented

## 13. Gaps / Recommended Future Prompts

1. Wire `logoutCurrentSession()` into an explicit UI action if product wants visible logout.
2. Decide whether logout should also lock the vault by wiping in-memory key shares.
3. Decide whether the client will persist session tokens or keep using legacy auth-hash credentials for most protected calls.
4. Design account deletion/reset separately, including server data deletion/retention policy and audit requirements.
5. Keep password rotation and auth credential rotation separate from logout until these boundaries have tests.
