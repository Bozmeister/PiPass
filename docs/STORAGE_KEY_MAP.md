# Storage Key Map

## 1. Purpose

This document maps PiPass storage ownership before password rotation, server authentication credential rotation, or a future vault-root-key migration. It records where current data lives, how sensitive it is, and which operations must update or wipe it.

This is a design and audit reference only. It does not introduce new storage keys, routes, schemas, migrations, UI, or runtime behavior.

## 2. Summary Table

| Area | Location | Main keys or tables | Sensitivity | Rotation impact |
| --- | --- | --- | --- | --- |
| Master unlock metadata | SecureStore on native, localStorage on web | `pipass_master_salt`, `pipass_master_hash`, `pipass_security_profile`, `deviceUUID` | Sensitive metadata | Master password rotation must update salt/hash/profile carefully; `deviceUUID` must remain stable unless migrating intentionally |
| Cached master key | SecureStore native only | `pipass_master_key` in `group.com.pipass.shared` | Secret key material | Must update after successful password rotation; wipe on lock/reset where intended |
| Local vault entries | SecureStore/localStorage | `pipass_vault_index`, `pipass_vault_<entryId>` | Sensitive encrypted vault data plus some metadata | Current architecture requires re-encryption during password rotation |
| Shared vault blob | Shared SecureStore/localStorage | `pipass_shared_vault` | Sensitive encrypted vault data plus metadata | Must be regenerated after local vault changes and password rotation |
| Secure notes | SecureStore/localStorage | `pipass_notes_index`, `pipass_note_<noteId>` | Sensitive encrypted note data plus metadata | Current architecture requires re-encryption during password rotation |
| Local API credentials | SecureStore/localStorage | `pipass.auth.userId`, `pipass.auth.authHash` | Authentication secret material | Server auth credential rotation must replace `authHash`; local logout and nuclear reset clear these keys |
| Recovery | SecureStore/localStorage | `pipass_recovery_key_hash` | Sensitive verifier metadata | Must be reviewed if recovery starts wrapping a vault root key |
| installId | SecureStore/localStorage | `pipass.installId` | Non-secret label | Must not change for password/auth rotation; may persist through reset |
| Server account/auth | PostgreSQL | `users` | Sensitive account/auth state | Server auth credential rotation updates `users.auth_hash` |
| Server vault sync | PostgreSQL | `vault_blobs`, `vault_blob_history` | Opaque encrypted blobs | Password rotation writes a new encrypted blob using `expectedPrevVersion` |
| Server sessions/devices/audit | PostgreSQL and memory | `sessions`, `trusted_devices`, `vault_audit_log`, in-memory security maps | Sensitive metadata | Auth rotation should revoke sessions as designed; device trust should not change implicitly |
| TOTP/passkeys/honeytokens | PostgreSQL and memory | `users.totp_*`, `webauthn_credentials`, `honeytokens`, WebAuthn/TOTP memory maps | Credential/security state | Must not be broken by password rotation; step-up may be required |

## 3. Local SecureStore/localStorage Keys

Most local keys are stored by `workers/storageWorker.ts` through `SecureStore` on native and `localStorage` on web.

| Key | Owner | Stored data | Sensitivity | Regenerable | Password rotation | Auth rotation | Root-key migration | Wipe behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pipass_master_salt` | `workers/storageWorker.ts` | Hex salt for local master key derivation | Sensitive metadata, not secret by itself | No, not without re-encrypting/rekeying | Must change if using a new salt for new password | No | May be replaced by wrapping-key salt metadata | Deleted by `destroyAllData()` |
| `pipass_master_hash` | `workers/storageWorker.ts` | Hash of derived local master key | Sensitive verifier | Yes, only with password and KDF inputs | Must change after successful local rotation | No | May be replaced or versioned | Deleted by `clearVault()` and `destroyAllData()` |
| `pipass_security_profile` | `workers/storageWorker.ts` | KDF iteration/profile number | Sensitive metadata | Yes if defaulting, but changing it affects unlock derivation | May change if new password selects new profile | No | May become wrapping KDF profile | Deleted by `destroyAllData()` |
| `deviceUUID` | `crypto/keyDerivation.ts` | Per-device UUID mixed into local KDF material | Sensitive local derivation input | No for existing vaults; changing it can make old vault data undecryptable | Should not change during ordinary password rotation unless a migration handles it | No | Needs explicit migration decision | Deleted by `destroyAllData()` only |
| `pipass_master_key` | `workers/storageWorker.ts` | Cached master key hex | Secret key material | Yes from password plus KDF inputs | Must update only after rotation success | No | Future cached root/wrapping key model needs redesign | Deleted by `clearMasterKeySecurely()` and `destroyAllData()`; native only |
| `pipass_vault_initialized` | `workers/storageWorker.ts` | `"1"` or `"0"` setup marker | Non-secret state | Yes | Usually unchanged | No | May need migration version split later | Deleted by `destroyAllData()` |
| `pipass_show_keyprints` | `workers/storageWorker.ts` | Keyprint display preference | Non-secret preference | Yes | No | No | No | Deleted by `destroyAllData()` |
| `pipass_fractal_fingerprint` | `workers/storageWorker.ts` | Expected fractal/key fingerprint record or legacy string | Sensitive integrity metadata | Recomputed from unlocked key | Must update after password/KDF rotation | No | Must be redesigned if key source changes | Deleted by `destroyAllData()` |
| `pipass_shared_migration_done` | `workers/storageWorker.ts` | `"1"` once local entries were mirrored to shared storage | Non-secret migration flag | Yes after migration check | No direct change | No | May need replacement migration marker | Deleted by `destroyAllData()` |

Native shared keychain service:

- `pipass_master_key` uses `keychainService: "group.com.pipass.shared"`.
- `app.json` declares iOS keychain access group `group.com.pipass.shared`.
- `pipass_master_key` may be stored with `requireAuthentication: true` when biometrics are available, with a fallback to unauthenticated SecureStore storage if the authenticated write fails.

### Local Vault Entry Keys

| Key | Owner | Stored data | Sensitivity | Regenerable | Password rotation | Auth rotation | Root-key migration | Wipe behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pipass_vault_index` | `workers/storageWorker.ts` | JSON array of vault entry ids | Sensitive metadata | Rebuildable only by scanning known keys, which the app does not currently do | Preserve after re-encryption | No | Preserve or migrate | Deleted by `clearVault()` and `destroyAllData()` |
| `pipass_vault_<entryId>` | `workers/storageWorker.ts` | JSON `VaultEntry` | Sensitive vault record | No, except from backup/sync | Must re-encrypt under current architecture | No | Must migrate to root-key-derived encryption | Deleted by `clearVault()`, per-entry delete, and `destroyAllData()` |

`VaultEntry` records include encrypted fields such as `encryptedPassword`, `encryptedTitle`, `encryptedUsername`, `encryptedUrl`, `notes`, and `encryptedAux`. Current records also include outer metadata fields such as `id`, `salt`, timestamps, and legacy/display fields such as `title`, `username`, and optional `url`. Treat the whole record as sensitive. Do not assume outer fields are safe to expose.

`encryptedAux` may contain encrypted honeytoken metadata. It must survive password rotation so decoys are not silently disarmed.

### Local Secure Note Keys

| Key | Owner | Stored data | Sensitivity | Regenerable | Password rotation | Auth rotation | Root-key migration | Wipe behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pipass_notes_index` | `workers/storageWorker.ts` | JSON array of secure note ids | Sensitive metadata | Rebuildable only by scanning known keys, which the app does not currently do | Preserve after re-encryption | No | Preserve or migrate | Deleted by `clearAllNotes()` and `destroyAllData()` |
| `pipass_note_<noteId>` | `workers/storageWorker.ts` | JSON `SecureNote` | Sensitive note record | No | Must re-encrypt under current architecture | No | Must migrate to root-key-derived encryption | Deleted by note delete, `clearAllNotes()`, and `destroyAllData()` |

`SecureNote` records include encrypted label/content fields and also a plaintext `label` compatibility/display field. Treat the whole note record as sensitive.

### Local API Credential Keys

These keys are owned by `lib/credentials.ts`.

| Key | Stored data | Sensitivity | Regenerable | Password rotation | Auth rotation | Root-key migration | Wipe behavior |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pipass.auth.userId` | Server user UUID | Sensitive account identifier | Yes after login/register | No | Usually unchanged | No | Deleted by `clearCredentials()` and `destroyAllData()` |
| `pipass.auth.authHash` | Client auth credential proof | Authentication secret material | Only from login/credential derivation | Maybe if combined password/auth flow rotates it | Must replace after server confirms new credential | No | Deleted by `clearCredentials()` and `destroyAllData()` |

`authedApiRequest()` clears these credentials on a server `401`. `logoutCurrentSession()` clears these credentials for local logout. `destroyAllData()` also calls `clearCredentials()` because nuclear reset is treated as a fresh local app state boundary. Ordinary vault lock does not clear these credentials.

Search note: no runtime caller of `setCredentials()` was found in this prompt's scan outside `lib/credentials.ts`. If login/register credential persistence is implemented elsewhere later or generated by another flow, update this map.

### installId

| Key | Owner | Stored data | Sensitivity | Regenerable | Password rotation | Auth rotation | Root-key migration | Wipe behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pipass.installId` | `lib/install-id.ts` | Random UUID label | Non-secret, spoofable audit label | Yes | No | No | No | Deleted by `destroyAllData()` only |

`installId` must remain label-only. It is not an auth factor, trust proof, recovery key, KDF input, or vault-access decision. It persists across ordinary lock/logout, but nuclear reset clears it so the app behaves like a fresh local install.

## 4. Shared Vault Storage Keys

Shared storage is owned by `workers/sharedVaultStorage.ts`.

| Key | Platform/location | Stored data | Sensitivity | Regenerable | Password rotation | Auth rotation | Root-key migration | Wipe behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pipass_shared_vault` | `SecureStore` with `keychainService: "group.com.pipass.shared"` on native; `localStorage` on web | JSON `{ encryptedBlob, version, updatedAt }`; current `encryptedBlob` is a JSON string of local encrypted entries | Sensitive vault blob | Rebuilt from local entries | Must regenerate after re-encryption | No | Must migrate shape/version | Deleted by `clearSharedVault()`, called from `clearVault()`/`destroyAllData()` |

Current shared blob `version` is local format version `1`, not the server vault sync version.

## 5. In-Memory Sensitive State

| State | Owner | Stored data | Sensitivity | Persistence | Wipe/expiry |
| --- | --- | --- | --- | --- | --- |
| `activeShares` | `lib/vaultSession.ts` | Active XOR-split vault key shares | Secret key material | JS heap only | Replaced/wiped by `setActiveKeyShares(null)` or `clearActiveKeyShares()` |
| `keyShares` React state and refs | `app/(tabs)/index.tsx`, `screens/VaultScreen.tsx` | Active key shares while unlocked | Secret key material | JS heap only | Wiped on lock/reset paths where implemented |
| `lockedSharesRef` | `app/(tabs)/index.tsx` | Shares retained while lock overlay is shown | Secret key material | JS heap only | Wiped when unlocked/reset |
| decrypted entry/note React state | `VaultScreen`, `EntryDetailModal`, `SecureNotesModal` | Plaintext entry/note fields while viewed | Plaintext secrets | JS heap only | Cleared on modal close/delete/navigation paths |
| clipboard contents | `EntryDetailModal`, `SecureNotesModal` | Copied secret values | Plaintext secrets outside app storage | OS clipboard | Timers attempt to clear after 30s |
| `cachedBiometricAvailable` | `workers/storageWorker.ts` | Boolean biometric availability | Non-secret | JS heap only | Process lifetime |
| honeytoken send dedupe map | `lib/honeytokenTrigger.ts` | Recent marker/context send timestamps | Sensitive-ish metadata | JS heap only | Pruned by code |

Locking the vault should wipe key shares and clear active decrypted views. It does not necessarily clear non-vault app credentials or installId.

## 6. Server Database Tables/Columns

All server tables are defined in `shared/schema.ts` and accessed through `server/storage.ts` and `server/routes.ts`.

### `users`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | User UUID | Sensitive identifier | No | No | No | Cascade deletes dependent rows if user deleted |
| `username` | Login name | Sensitive identifier | No | No | No | Delete if account deleted |
| `auth_hash` | Server-stored hash of client auth proof | Authentication verifier | Maybe if combined flow | Must update atomically | No | Delete if account deleted |
| `salt` | Server auth/register salt from current auth model | Sensitive metadata | Possibly if auth derivation changes | Possibly with auth credential rotation | No | Delete if account deleted |
| `iterations` | Server auth/register KDF iteration metadata | Sensitive metadata | Possibly if auth derivation changes | Possibly with auth credential rotation | No | Delete if account deleted |
| `totp_enabled` | TOTP enabled flag | Security state | No | No | No | Delete if account deleted |
| `totp_secret_encrypted` | TOTP secret encrypted with deployment key | Credential secret ciphertext | No | No | No | Delete if account deleted |
| `created_at` | Epoch-ms timestamp | Metadata | No | No | No | Delete if account deleted |

TOTP ciphertext depends on `TOTP_ENCRYPTION_KEY`, not the user's master password.

### `vault_blobs`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `encrypted_blob` | Opaque encrypted vault blob | Sensitive ciphertext | Must be replaced after successful local re-encryption | No | Must be replaced/migrated | Delete row |
| `version` | Server-minted vault version | Metadata | Server increments on sync | No | Server increments on migration sync | Delete row |
| `updated_at` | Epoch-ms timestamp | Metadata | Updates on sync | No | Updates on migration sync | Delete row |

The server must continue treating `encrypted_blob` as opaque.

### `vault_blob_history`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | History row UUID | Metadata | No | No | No | Cascades on user delete |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `version` | Historical server version | Metadata | New history row may be archived | No | New history row may be archived | Delete rows |
| `encrypted_blob` | Historical opaque vault ciphertext | Sensitive ciphertext | Old password may still decrypt older history until pruned | No | Old format may remain in history until pruned | Delete rows |
| `archived_at` | Epoch-ms timestamp | Metadata | Updates on archive | No | Updates on archive | Delete rows |

Password rotation should consider that history may retain older blobs encrypted under the old key. If that is unacceptable, a later prompt needs explicit history retention policy. Do not silently drop history in this prompt.

### `sessions`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Logout/reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | Session UUID | Sensitive metadata | Maybe current flow | Maybe current flow | No | Deleted by logout/logout-all |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `token_hash` | SHA-256 of raw session token | Authentication verifier | Should revoke according to policy | Should revoke other sessions by default | No | Deleted by logout/logout-all |
| `created_at`, `expires_at`, `last_seen_at` | Epoch-ms metadata | Metadata | No | No | No | Deleted with row |
| `user_agent`, `ip_address` | Request metadata | Sensitive metadata | No | No | No | Deleted with row |
| `suspicious` | Session flag | Security state | No | No | No | Deleted with row |
| `device_fingerprint` | Hashed device context | Sensitive metadata | No | No | No | Deleted with row |
| `trusted` | Per-session trust flag | Security state | No implicit change | No implicit change unless sessions revoked | No | Deleted with row |
| `totp_verified_until` | Step-up expiry | Security state | Clear by deleting session or expiry | Clear by deleting session or expiry | No | Deleted with row |

Raw session tokens are returned once and are not persisted server-side.

### `trusted_devices`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | Device row UUID | Metadata | No | No | No | Cascades on user delete |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `device_fingerprint` | Hash of request/device context | Sensitive metadata | No implicit change | No implicit change | No | Delete row |
| `label` | User label | Metadata, user-provided | No | No | No | Delete row |
| `trusted` | Durable device trust state | Security state | Should remain unless product decides otherwise | Should remain unless product decides otherwise | No | Delete row |
| `first_seen_at`, `last_seen_at` | Epoch-ms metadata | Metadata | No | No | No | Delete row |

Device trust is server state. It must not be inferred from installId.

### `vault_audit_log`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | Audit row UUID | Metadata | No | No | No | Cascades on user delete |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `action` | Event name | Security metadata | Add safe events | Add safe events | Add safe events | Delete rows |
| `version_before`, `version_after` | Vault version metadata | Metadata | Populate for vault write | Usually no | Populate for migration write | Delete rows |
| `blob_size_bytes` | Opaque blob size | Metadata | May populate | No | May populate | Delete rows |
| `ip_address`, `user_agent` | Request and safe event metadata | Sensitive metadata | May include safe installId label | May include safe installId label | May include safe installId label | Delete rows |
| `created_at` | Epoch-ms timestamp | Metadata | Add row | Add row | Add row | Delete rows |

Audit rows must never contain plaintext password, authHash values, encryptedBlob contents, request headers, request bodies, session tokens, recovery keys, or passkey internals.

### `webauthn_credentials`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | Internal credential UUID | Metadata | No | No | No | Cascades on user delete |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `credential_id` | WebAuthn credential id | Public-key credential identifier | No | No | No | Delete row |
| `public_key` | Authenticator public key | Public key material, sensitive metadata | No | No | No | Delete row |
| `counter` | WebAuthn signCount | Security state | No | No | No | Delete row |
| `device_name` | User label | Metadata | No | No | No | Delete row |
| `transports` | WebAuthn transport hint JSON | Metadata | No | No | No | Delete row |
| `created_at`, `last_used_at` | Epoch-ms metadata | Metadata | No | No | No | Delete row |
| `revoked` | Soft-delete flag | Security state | No | No | No | Delete row |

Authenticator private keys are never stored by PiPass.

### `honeytokens`

| Column | Data | Sensitivity | Password rotation | Auth rotation | Root-key migration | Account reset |
| --- | --- | --- | --- | --- | --- | --- |
| `id` | Honeytoken UUID | Metadata | Must preserve references from encrypted vault aux data | No | Must preserve references | Cascades on user delete |
| `user_id` | User UUID | Sensitive identifier | No | No | No | Cascades on user delete |
| `label` | User-visible decoy label | Sensitive metadata | No | No | No | Delete row |
| `token_type` | Honeytoken type | Metadata | No | No | No | Delete row |
| `marker_hash` | SHA-256 marker hash | Sensitive security marker | No, but encrypted vault aux marker must survive | No | Preserve or reissue deliberately | Delete row |
| `active` | Enabled flag | Security state | No | No | No | Delete row |
| `created_at`, `triggered_at`, `trigger_count` | Metadata/counters | Security metadata | No | No | No | Delete row |

The plaintext honeytoken marker lives only in decrypted vault memory and encrypted entry aux data, not in server rows.

## 7. Server Session/Device/Audit In-Memory State

`server/routes.ts` keeps several in-memory maps and sets. They are not durable storage, but they affect live security behavior.

| State | Purpose | Sensitivity | Persistence | Rotation impact |
| --- | --- | --- | --- | --- |
| `rateLimitMap` | IP/user endpoint rate limits | Security metadata | Process memory | New rotation endpoints should use existing limit patterns |
| `anomalyState` | Vault read/write anomaly counters | Security metadata | Process memory, GC'd | Password rotation writes may affect sync counts |
| `passkeyFailureState` | Passkey failure tracking | Security metadata | Process memory | No direct change |
| `loginFailureState` | Login failure tracking | Security metadata | Process memory | Auth rotation should not reset failure history unless designed |
| `ipThreatState` | Adaptive IP threat/block state | Security metadata | Process memory | No direct change |
| `sessionBindingDriftDedup` | Dedup for session binding drift audit | Security metadata | Process memory | No direct change |
| `userSecurityState` | Soft locks, suspicious/untrusted sessions | Security state | Process memory, hydrated from audit in some cases | Rotation flows must respect soft-lock/recovery gates |
| `userSecurityLevelState` | Derived level notification state | Security metadata | Process memory | Rotation events may change displayed state if designed |
| `recoveryState` | Recovery mode active state | Security state | Process memory | Password reset through recovery needs explicit design |
| `tempLoginTokens` | TOTP/passkey login temp tokens, stored as hashes | Authentication state | Process memory with TTL | Auth rotation should not leave stale temp paths dangerous |
| `pendingTotpSetups` | Pending TOTP secret before verification | Credential secret | Process memory with TTL | No direct password rotation change |
| `inflightHydrations` | Audit-derived security state hydration promises | Non-secret operational state | Process memory | No direct change |
| `auditDedupeBuckets` | High-volume audit dedupe | Security metadata | Process memory | New audit event dedupe must be explicit |

`server/webauthn.ts` also stores WebAuthn challenges in memory:

| State | Purpose | Sensitivity | Persistence | Wipe/expiry |
| --- | --- | --- | --- | --- |
| `challenges` | Registration/authentication/step-up challenge entries keyed by kind, user, and challenge | One-shot anti-replay nonces | Process memory only | Single-use consume, 5 minute TTL, periodic sweep |

## 8. TOTP, Passkey, Recovery, And Honeytoken Storage

### TOTP

- Durable TOTP state is in `users.totp_enabled` and `users.totp_secret_encrypted`.
- `totp_secret_encrypted` is encrypted server-side with `TOTP_ENCRYPTION_KEY`.
- Pending TOTP setup secrets live in `pendingTotpSetups` only until verification or expiry.
- TOTP login temp tokens live in `tempLoginTokens` as hashes only.
- TOTP state does not depend on the local master password.

### Passkeys

- Durable passkey state is in `webauthn_credentials`.
- WebAuthn challenge state is in memory only.
- PiPass stores public keys, counters, metadata, and revoked flags. It never stores authenticator private keys.
- Passkeys do not depend on the local master password.

### Recovery

- Local recovery verifier is `pipass_recovery_key_hash`.
- Recovery key plaintext is shown to the user at setup and should not be stored plaintext.
- Current server recovery mode is in memory (`recoveryState`) and represented through audit/security state.
- A future root-key model should add explicit recovery wrapping ownership before recovery-assisted password reset.

### Honeytokens

- Server honeytoken rows store marker hashes and counters.
- Local encrypted entries store encrypted honeytoken aux data.
- In-memory decrypted entries may hold plaintext honeytoken marker while unlocked.
- Password rotation must preserve encrypted aux data and server row references.

## 9. installId And Non-Secret Labels

`installId` is stored under `pipass.installId` and sent as optional `x-install-id` audit metadata. It is non-secret and spoofable.

Rules:

- do not use it as authentication
- do not use it as device trust proof
- do not mix it into key derivation
- do not gate vault access on it
- do not wipe or rotate it as part of password/auth rotation unless product explicitly wants a new audit label

See `docs/INSTALL_ID_UI_RULES.md` for UI language.

## 10. Nuclear Reset, Logout, Lock, And Wipe Behavior

| Operation | Current behavior found | Notable exclusions |
| --- | --- | --- |
| Vault lock | Clears active key shares and hides unlocked vault UI | Does not clear local API credentials, installId, or `deviceUUID` |
| Per-entry delete | Deletes `pipass_vault_<entryId>`, updates `pipass_vault_index`, regenerates shared vault blob | Does not touch server until sync flow writes blob |
| Secure note delete | Deletes `pipass_note_<noteId>` and updates notes index | Does not affect vault entries |
| `clearVault()` | Deletes all `pipass_vault_<entryId>`, `pipass_vault_index`, `pipass_master_hash`, and `pipass_shared_vault` | Does not delete master salt, security profile, recovery hash, credentials, installId, or `deviceUUID` |
| `destroyAllData()` | Calls `clearVault()` and `clearAllNotes()`, then deletes master salt, security profile, show keyprints, initialized flag, fractal fingerprint, recovery hash, migration flag, cached master key, `pipass.auth.*`, `pipass.installId`, and `deviceUUID` | Does not delete server-side account data or server-side sessions by itself |
| `clearCredentials()` | Deletes `pipass.auth.userId` and `pipass.auth.authHash` | Called directly on auth failure and by `destroyAllData()` |
| Server logout | Deletes current session row | Does not clear local SecureStore credentials unless client does so |
| Server logout-all | Deletes all session rows for user | Does not change trusted devices by itself |

Nuclear reset is now the "fresh local install" boundary. It clears local API credentials, installId, and `deviceUUID`. Lock, logout, and future password rotation must keep those boundaries separate.

See `docs/LOGOUT_RESET_BOUNDARIES.md` for the dedicated logout, server session revocation, local credential clearing, account reset, and nuclear reset boundary map.

## 11. Password Rotation Impact Map

Current architecture requires local re-encryption because entry/note keys derive from master password-derived key material.

Must change after successful password rotation:

- `pipass_master_salt` if generating a new salt
- `pipass_master_hash`
- `pipass_security_profile` if KDF profile changes
- `pipass_master_key`
- active key shares in memory
- every `pipass_vault_<entryId>` record
- every `pipass_note_<noteId>` record
- `pipass_shared_vault`
- `pipass_fractal_fingerprint`
- server `vault_blobs.encrypted_blob` and version through sync
- possibly `vault_blob_history` through normal archival

Should not change solely because of password rotation:

- `pipass.installId`
- `trusted_devices`
- passkeys
- TOTP secret
- server audit history, except adding new safe audit rows
- `deviceUUID`, unless an explicit migration handles it

Needs decision:

- whether server `authHash` rotates in the same UX flow
- whether sessions are revoked
- whether old server vault history encrypted under the old key is retained
- whether `pipass.auth.*` is updated or cleared in combined password/auth flows

## 12. Auth Credential Rotation Impact Map

Server auth credential rotation should be treated separately from local master password rotation.

Must change:

- `users.auth_hash`
- possibly `users.salt` and `users.iterations` if the auth derivation scheme changes
- local `pipass.auth.authHash` only after server success
- sessions according to policy, with revocation of other sessions recommended
- audit log with safe event names and metadata

Should not change:

- local master salt/hash/profile
- encrypted vault entries
- shared vault blob
- recovery key hash
- vault root key or future wrapping keys
- installId
- device trust, unless product explicitly decides otherwise

Must be tested:

- old auth proof fails
- new auth proof succeeds
- stale sessions are handled as designed
- local credentials do not update until server commit succeeds

## 13. Future Vault-Root-Key Migration Impact Map

A future root-key migration should introduce explicit versioned metadata for:

- vault format version
- random vault root key
- password wrapping salt/KDF profile
- wrapped root key under password-derived wrapping key
- optional wrapped root key under recovery-key-derived wrapping key
- entry subkey derivation labels

Likely changes:

- migrate every entry/note once from master-password-derived subkeys to root-key-derived subkeys
- replace password changes with root-key rewraps
- redesign `pipass_master_hash` to verify password wrapping key or unlock result
- redesign `pipass_master_key` cache to avoid ambiguity between master password key and vault root key
- add migration marker separate from `pipass_shared_migration_done`
- update `pipass_fractal_fingerprint` source definition

Must not do implicitly:

- silently drop old vault history
- make recovery key a server credential
- use installId as a root-key wrapper or trust signal
- invent custom cryptographic primitives

## 14. Unknowns, Risks, And Dead-Key Candidates

### Unclear Ownership

- `deviceUUID` is a local KDF input but is owned by `crypto/keyDerivation.ts`, not `workers/storageWorker.ts`. It now has a wipe API for nuclear reset, but still needs careful migration ownership because changing it makes existing vault data undecryptable.
- `pipass.auth.*` credentials are separate from vault lock/logout semantics, but nuclear reset now clears them.
- `pipass.installId` persists through lock/logout, but nuclear reset now clears it to make local state fresh.
- Server auth `users.salt` and `users.iterations` are distinct from local master salt/profile; naming could confuse future password rotation work.

### Risky Or Sensitive Compatibility Fields

- `VaultEntry` stores encrypted fields but also outer `title`, `username`, and optional `url` fields.
- `SecureNote` stores encrypted fields but also outer `label`.
- Shared vault storage mirrors the same local record shapes.

Treat those records as sensitive even if field names look like display metadata. A future privacy hardening prompt can decide whether to remove or migrate legacy/plain display fields.

### Possible Dead Or Legacy Keys

- `pipass_shared_migration_done` is a one-way migration marker and may become obsolete after a future vault-root-key migration.
- `pipass_show_keyprints` is a preference and is not password-rotation critical.
- `pipass_fractal_fingerprint` supports both a structured record and a legacy string shape.

Do not remove any of these without a dedicated migration and tests.

## 15. Recommended Implementation Order

1. Decide whether password rotation and server auth credential rotation ship together or separately.
2. Add tests around current local storage wipe behavior before changing it.
3. Add explicit docs/tests for `deviceUUID` ownership because it is part of key derivation.
4. Add server auth credential rotation endpoint and tests.
5. Add local credential update/rollback handling.
6. Add local vault re-encryption state machine tests.
7. Add UI only after storage and rollback behavior are covered.
8. Design vault-root-key metadata and migration separately.
9. Only then implement root-key rewrap password changes.

