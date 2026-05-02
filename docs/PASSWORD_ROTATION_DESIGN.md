# Password Rotation Design

## 1. Executive Summary

Changing a password in PiPass can mean two related but separate operations:

- changing the local master password that unlocks and encrypts the vault
- rotating the server authentication credential material used for API access

Those operations should be designed as separate security domains, even if the UI offers one combined "Change password" flow. The server must never receive the plaintext master password, plaintext vault data, master encryption key, recovery key, decrypted entries, or any key material that can decrypt the vault.

The safest long-term design is a vault-root-key model: entries are encrypted under a randomly generated vault root key or derived subkeys, and the master password only wraps that root key. Changing the password then rewraps the root key instead of re-encrypting every vault entry.

The short-term design can use the current architecture by decrypting entries locally with the old master key, re-encrypting them locally with the new master key, and syncing the new opaque encrypted blob only after the local re-encryption has completed and been verified.

## 2. Current Architecture Summary

PiPass currently separates local vault protection from server-side API authentication:

- Local vault unlock derives master key shares from the user password, local master salt, and KDF profile.
- The local master key hash is stored locally to verify unlock attempts.
- Vault entries are encrypted client-side. Per-entry keys are derived from the master key, entry id, and entry salt.
- The server stores an opaque encrypted vault blob and version metadata. It does not decrypt vault data.
- The sync API uses `expectedPrevVersion`; the server mints the next version.
- The server stores a hashed form of the client-provided `authHash` for authentication.
- Local API credential material is stored through `lib/credentials.ts`.
- Sessions, device trust, audit logs, recovery mode, rate limits, and installId metadata are server-side security context, not vault decryption material.

Important current limitation: there is not yet a durable vault root key that is independent of the master password. With the current model, changing the master password also changes the key path used for entry encryption, so existing entries must be re-encrypted or made readable through a compatibility path.

## 3. Definitions

- **Master password**: the user secret typed locally to unlock the vault. It must never be sent to the server.
- **Master encryption key**: key material derived locally from the master password and local KDF inputs. It must never be sent to the server.
- **Vault root key**: preferred future random key that encrypts vault data or derives vault subkeys. It would be wrapped by the master password instead of derived from it directly.
- **Server authHash**: client-side credential proof sent to the server for API authentication. The server stores only its hashed comparison value.
- **Recovery key**: a separate recovery path. It must not be confused with installId, biometrics, session tokens, or server trust state.
- **Session token**: server-issued token for authenticated sessions.
- **Device trust**: explicit server-side trust state for sessions/devices.
- **installId**: non-secret audit label only. It is spoofable and must not prove trust, auth, recovery, or vault access.

## 4. Threat Model For Password/Auth Rotation

The rotation flow must protect against:

- data loss from overwriting the server vault with a blob encrypted under the wrong key
- lockout when local password state changes but server auth state does not, or the reverse
- stale sessions remaining usable after credential material changes
- malicious clients attempting to skip old-password verification
- replay or race conditions during sync after rotation
- audit/log leaks of plaintext password, authHash, vault blobs, recovery keys, headers, request bodies, or stack traces
- using installId or biometrics as false proof of identity

The flow does not protect against a fully compromised client during rotation. The client necessarily sees decrypted vault data while the user is changing the master password.

## 5. Short-Term Design Using Current Architecture

The short-term flow should rotate master-password-derived vault encryption and server auth material in a carefully staged local-first transaction.

Recommended flow:

1. Require the vault to be unlocked with the current master password.
2. Require fresh step-up if the server account has TOTP or passkey step-up enabled.
3. Fetch the latest server vault and version.
4. If the local client is stale, stop and resolve the sync conflict before rotation.
5. Derive old key shares from the current password and verify the current local master key hash.
6. Derive new key shares from the new password using a newly generated local master salt and chosen KDF profile.
7. Re-encrypt every local vault entry using old shares to decrypt and new shares to encrypt.
8. Validate locally that the new encrypted entries can be decrypted with the new shares.
9. Build the new encrypted vault blob locally.
10. Sync the new blob with `expectedPrevVersion` equal to the last fetched server version.
11. Only after sync succeeds, update local master salt, local master key hash, security profile, SecureStore master key, and cached key shares.
12. Rotate server auth material through a separate authenticated API call or the same server transaction if a combined endpoint is added.
13. Re-login or update stored local API credentials only after the server confirms auth rotation.
14. Audit the rotation without storing passwords, auth hashes, or encrypted blobs in audit metadata.

The short-term design may use the existing `reEncryptEntry` helper, but implementation must still add a full transactional workflow around it. A helper by itself is not enough.

## 6. Preferred Future Design Using Vault Root Key / Key Wrapping

The preferred future architecture is:

- Generate a random vault root key when the vault is created.
- Encrypt entries using subkeys derived from the vault root key, entry id, entry salt, and domain separation labels.
- Derive a password wrapping key from the master password.
- Store an encrypted/wrapped vault root key locally and, if needed, inside the encrypted vault metadata.
- Changing the master password derives a new wrapping key and rewraps the vault root key.
- Existing entries do not need to be re-encrypted unless the root key itself is rotated.

Benefits:

- password changes are faster and less failure-prone
- fewer decrypted entries need to be rewritten during normal password changes
- recovery can wrap the same root key using recovery-key material without changing every entry
- future key rotation can be explicit: password rotation rewraps; root-key rotation re-encrypts

This model should be introduced through a migration that preserves existing users:

1. Unlock with the existing master password.
2. Decrypt existing entries.
3. Generate a vault root key.
4. Re-encrypt entries under root-key-derived subkeys.
5. Wrap the root key under the existing password wrapping key.
6. Sync a new encrypted vault blob at the next server-minted version.
7. Mark the local vault metadata version only after verification and sync success.

## 7. Server API Changes Needed

The server should not receive plaintext password or plaintext vault data. Possible API additions:

- `POST /api/auth/change-credential`
  - authenticated and step-up gated
  - request contains current credential proof and new credential proof, never plaintext password
  - server verifies current proof against stored credential
  - server stores the hashed new proof atomically
  - server revokes other sessions by default
  - response uses `{ success: true }` or `{ error: string }`

- Optional combined endpoint for rotation coordination:
  - `POST /api/vault/rotate`
  - authenticated and step-up gated
  - body contains `encryptedBlob`, `expectedPrevVersion`, and new auth credential proof
  - server verifies auth, checks version, stores the new blob, rotates auth credential, and revokes sessions in one transaction where possible
  - server still treats `encryptedBlob` as opaque and applies existing blob validation

If a combined endpoint is too large for the first implementation, use two endpoints with a resumable state machine on the client. The client must clearly know which stage has committed.

API requirements:

- strict body validation
- rate limiting similar to other sensitive auth/vault operations
- step-up where configured
- 409 version conflict if the vault version is stale
- safe `{ error: string }` responses
- no request-body, header, encryptedBlob, authHash, password, or secret logging

## 8. Client/Local Storage Changes Needed

Short-term rotation needs local updates for:

- master salt
- master key hash
- KDF/security profile if changed
- SecureStore cached master key
- active in-memory key shares
- local encrypted entries
- shared vault blob
- locally stored API credentials from `lib/credentials.ts`
- recovery-key wrapping/hash metadata if the recovery design requires it

Local storage updates must be ordered so the old password remains usable until the new encrypted vault has been written and verified. Do not update local master salt/hash first.

Recommended local staging:

- keep old local password metadata intact
- write staged new encrypted vault data under temporary keys or in memory
- verify decryptability with new key
- sync to server
- rotate server auth
- commit new local password metadata
- clear old key material and staged data

## 9. Vault Re-Encryption Or Key Rewrapping Strategy

Current architecture:

- changing the master password changes the derived master key
- all encrypted entries and secure notes that depend on that key must be re-encrypted locally
- honeytoken encrypted auxiliary metadata must be preserved
- sync must use `expectedPrevVersion` to avoid overwriting newer server data

Future vault-root-key architecture:

- normal password change rewraps the root key only
- vault entry ciphertext remains unchanged
- explicit root-key rotation is a separate operation that re-encrypts entries
- recovery key can wrap the same root key without becoming a server proof

The UI should call these different operations by clear names internally:

- password change: change unlock password and optionally auth credential
- auth credential rotation: change server sign-in proof
- vault root key rotation: re-encrypt vault data under a new root key

## 10. Session/Device Trust Handling

After server auth credential rotation:

- revoke all other sessions by default
- keep the current session only if the flow needs it to finish, then mint or require a fresh session
- clear local stored API credentials and store the new credential only after server confirmation
- clear any temporary step-up tokens
- keep device trust state unchanged unless product decides otherwise

Device trust should not be automatically expanded because a password changed. A trusted device remains trusted only because server-side trust state says so. An untrusted device remains untrusted.

For high-risk cases, the UI can offer:

- "Sign out other sessions" as the default
- "Keep trusted sessions" only if explicitly designed and tested later

The initial implementation should prefer revoking other sessions.

## 11. Recovery Interaction

Password rotation must not silently break recovery.

Current recovery-key model stores local recovery-key hash material. A future root-key model should let the recovery key wrap the vault root key separately from the password wrap.

Rules:

- recovery key must never be sent to the server
- recovery mode does not prove the user knows the current password
- changing password during recovery should require the recovery flow to unwrap or reconstruct the same vault key locally
- after password change, recovery wrapping/hash metadata must be refreshed if it depends on the old password-derived key
- audit recovery-assisted password changes distinctly

Open implementation question: decide whether the first short-term rotation supports recovery-assisted password reset or only password change while the vault is currently unlocked.

The safer first implementation is "change password while unlocked" only.

## 12. Failure/Rollback Strategy

Avoid partial commits. Treat rotation as a staged operation:

1. Preflight checks:
   - vault unlocked
   - current password verified locally
   - new password meets policy
   - latest server version fetched
   - step-up satisfied if required

2. Local preparation:
   - derive new key
   - re-encrypt in memory or staged storage
   - verify new ciphertext decrypts
   - keep old local state untouched

3. Server commit:
   - sync encrypted blob using `expectedPrevVersion`
   - rotate auth credential
   - revoke sessions according to policy

4. Local commit:
   - persist new salt/hash/profile
   - persist new local encrypted data
   - store new API credential material
   - wipe old and staged key material

5. Recovery:
   - if server sync fails, keep old local password and old server auth
   - if auth rotation fails after vault sync succeeds, client must detect "vault re-encrypted but auth unchanged" and continue using old auth while prompting to retry auth rotation
   - if local commit fails after server commit, client should retain enough staged metadata to unlock with the new password or present a safe recovery prompt

The combined server endpoint reduces partial states, but the client still needs local rollback/resume handling.

## 13. Audit Logging Requirements

Add safe audit events such as:

- `password_change_started` only if useful and not noisy
- `password_change_completed`
- `password_change_failed`
- `auth_credential_rotated`
- `sessions_revoked_after_password_change`
- `recovery_password_reset_completed` if recovery-assisted reset is implemented

Audit metadata may include:

- version before/after for the encrypted vault blob
- blob size only if already used by vault audit events
- installId label if valid and already available
- source such as `password_change` or `recovery_reset`

Audit metadata must not include:

- plaintext password
- old or new authHash
- master key or vault root key
- recovery key
- encryptedBlob
- session token
- request headers
- request bodies
- passkey internals
- database URLs or secrets

## 14. UI/UX Requirements

UI should say what is changing:

- "Change unlock password" for local vault password changes
- "Update sign-in credential" if server auth material is rotated separately
- "Sign out other sessions" for session revocation
- "Your vault will be re-encrypted on this device before it is synced" for the current architecture
- "Your vault key will be re-protected with the new password" for the future root-key model

UI must not say:

- "server changes your master password"
- "PiPass can recover your password"
- "installId verifies this device"
- "Face ID proves this device to the server"
- "recovery key is your server password"

Required UX states:

- locked vault: ask user to unlock first
- stale vault version: ask user to sync/refresh before changing password
- step-up required: ask for configured second factor
- server conflict: do not commit local password metadata
- offline: do not claim password change completed
- success: explain whether other sessions were signed out

## 15. Test Plan

Before implementation, add tests for:

- current password must be verified locally before rotation
- wrong current password does not change local state or server auth
- new password derives a different key and can decrypt re-encrypted entries
- all entry fields, notes, URLs, secure notes, and honeytoken encrypted metadata survive rotation
- server receives only opaque encryptedBlob and credential proof, never plaintext
- `expectedPrevVersion` conflict aborts rotation without local password commit
- auth credential rotation updates server login behavior
- old auth credential fails after successful rotation
- new auth credential succeeds after successful rotation
- other sessions are revoked after rotation
- current session behavior is exactly as designed
- trusted device state remains unchanged unless explicitly changed by product decision
- recovery mode interaction is blocked or supported according to the chosen first implementation
- audit rows are present and safe
- rate limits apply to new endpoints
- logging tests prove no password, authHash, encryptedBlob, recovery key, headers, bodies, or stack traces are logged
- interrupted client resumes or safely rolls back
- web and native storage paths behave consistently

Manual tests should include:

- successful password change with small vault
- successful password change with many entries
- password change while another device has changed the vault version
- app kill during re-encryption
- app kill after server sync but before local commit
- network failure during auth credential rotation
- biometric SecureStore fallback behavior on iOS development builds

## 16. Implementation Prompt Sequence

Suggested staged prompts:

1. Audit current local password/vault storage paths and document exact storage keys.
2. Add server auth credential rotation endpoint with tests only.
3. Add audit events and rate limits for auth credential rotation.
4. Add client API helper for credential rotation.
5. Add local rotation state machine without UI.
6. Add entry and note re-encryption tests.
7. Add password change UI for unlocked vault only.
8. Add session revocation behavior and UI copy.
9. Add interruption/resume tests.
10. Add recovery-assisted password reset design and implementation only after the unlocked-vault change flow is stable.
11. Design and migrate to vault-root-key wrapping.
12. Replace full re-encryption password changes with root-key rewrap.

Do not combine all stages into one implementation prompt. Password rotation touches too many security boundaries for a single broad change.

## 17. Open Questions / Decisions To Confirm

- Should the first implementation rotate server authHash at the same time as the local master password, or expose two separate flows?
- Should password change always revoke every other session?
- Should the current session survive rotation, or should the user always sign in again?
- Should device trust persist unchanged after password rotation?
- Should recovery-assisted password reset be supported in the first implementation, or deferred?
- Should the project introduce a vault root key before any user-facing password change flow?
- What password/KDF policy should new passwords use for future profiles?
- How should staged local rotation state be stored without risking rollback confusion?
- Should passkey-only users still have server authHash rotation, or should passkey account recovery be a separate design?
- How should existing users be migrated to the future root-key model without forcing immediate password change?

