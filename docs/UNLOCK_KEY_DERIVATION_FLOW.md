# Unlock And Key Derivation Flow

## 1. Purpose

This document maps the current PiPass local setup, unlock, key derivation, key-share, cached-key, vault-load, secure-note, and fractal fingerprint flow before password rotation or vault-root-key migration work begins.

This is an audit and implementation-planning reference only. It does not add storage keys, routes, schemas, migrations, UI, crypto changes, tests, password rotation, auth credential rotation, or vault-root-key migration.

## 2. High-Level Flow Summary

PiPass currently has two separate local gates:

- app access gate: `AuthScreen` prompts for biometrics/passcode where available before showing the vault setup/unlock flow
- vault unlock gate: `UnlockScreen` derives key shares from the master password, local salt, security profile, and `deviceUUID`

The local vault key pipeline is:

1. User enters a master password.
2. `deriveMasterKey()` combines password material with `deviceUUID`.
3. Argon2id is attempted through `hash-wasm`; PBKDF2-SHA256 is used as fallback.
4. The 32-byte master key is represented as 64 hex characters.
5. `hashMasterKey()` stores/verifies `SHA256(masterKeyHex)`.
6. `splitKeyIntoShares()` stores the live key as two XOR shares in JS memory.
7. Entry and note encryption combine the shares temporarily, derive per-record HKDF subkeys, then encrypt or decrypt fields.
8. A fractal fingerprint is derived from the master key for visual/integrity metadata.

The server never receives the master password, master key, key shares, decrypted vault records, recovery key, or fractal fingerprint source key.

## 3. First-Time Setup Flow

### UI And Password Collection

First-time setup is shown by `SeedSetupScreen` when `isVaultInitialized()` is not `"1"`.

`SeedSetupScreen` owns:

- master password input
- confirmation input
- minimum password length check of 8 characters
- password-match check
- security profile selection
- optional backup import before setup completion

Security profiles are UI labels for iteration counts:

- Balanced: `25000`
- Fortress: `100000`
- Deep Vault: `250000`

`SeedSetupScreen` does not derive or store the master key itself. It calls `onSetup(password, iterations)`, which is implemented in `app/(tabs)/index.tsx`.

### Setup Commit In App Root

The setup callback in `app/(tabs)/index.tsx` now delegates the commit-sensitive setup work to `performFirstTimeVaultSetup()`.

Current sequence:

1. Clamp iterations with `Math.max(iters || 100000, 3)`.
2. Generate a 32-byte hex master salt with `generateMasterSalt()`.
3. Compute the Argon2id parameters for the selected profile.
4. Derive the initial master key with `deriveMasterKeyWithArgon2id()` only.
5. If Argon2id is unavailable or fails, stop setup before writing setup metadata or publishing shares.
6. Build `pipass_kdf_metadata` with `algorithm: "argon2id"` and `source: "setup"` from the same parameters used for derivation.
7. Split the derived master key into shares.
8. Store `hashMasterKey(keyHex)` under `pipass_master_hash`.
9. Generate a 32-byte recovery key.
10. Store `hashRecoveryKey(rawKey)` under `pipass_recovery_key_hash`.
11. Store `pipass_master_salt`.
12. Store `pipass_security_profile`.
13. Store `pipass_kdf_metadata`.
14. Store cached master key with `storeMasterKeySecurely(keyHex)` on native only.
15. Hold the newly derived shares in `pendingSetupShares`.
16. Show `RecoveryKeyModal`.
17. Only after the user confirms the recovery key, call `setVaultInitialized(true)` and move `pendingSetupShares` into active `keyShares`.

Important boundary: `pipass_vault_initialized` is not set until the recovery-key modal is confirmed. Local metadata and cached key are written before that confirmation.

New vault setup does not use the legacy PBKDF2 fallback path. PBKDF2 remains available only for existing legacy unlock compatibility.

### Backup Import During Setup

`SeedSetupScreen` can import `.vault` or JSON backup data before password setup completes. Imported entries are saved directly through `saveEntry()` and imported secure notes through `saveSecureNote()`.

Risk/unknown: this import path writes encrypted records before the new local salt/profile/master verifier are committed. The current audit did not find backup metadata validation that proves imported records match the password/salt/profile being set. A future backup/restore audit should confirm whether imported encrypted records are expected to be portable, already encrypted under compatible key material, or require a rekey/import migration.

## 4. Returning Unlock Flow

### Startup State Loading

After `AuthScreen` sets `authenticated`, the app root loads:

- `pipass_vault_initialized`
- `pipass_security_profile`
- `pipass_master_salt`

`getSecurityProfile()` defaults to `100000` if missing, invalid, or non-positive.

### Password Unlock

`UnlockScreen` is nested in `app/(tabs)/index.tsx`; there is no separate `screens/UnlockScreen.tsx` in the current codebase.

Unlock currently:

1. Requires a non-empty password.
2. Calls `deriveMasterKeyShares(password, salt, iterations)`.
3. Combines shares to `keyHex`.
4. Computes `hashMasterKey(keyHex)`.
5. Reads `pipass_master_hash`.
6. If a stored hash exists and does not match, wipes the newly derived shares and shows an incorrect-password error.
7. If hash matches, writes `pipass_master_key` through `storeMasterKeySecurely(keyHex)` on native.
8. Passes the shares to app state through `onUnlocked(shares)`.

Current behavior if no stored hash exists: the mismatch check is skipped because it requires `storedHash`. That is likely legacy tolerance, but it is an important edge case for future migration work.

### Biometric Requirements

Unlock itself is password-based. Biometric/passcode gates appear in three separate places:

- `AuthScreen` gates app access before setup/unlock screens.
- `requireFreshBiometric()` gates entry detail decryption, secure note save/view, delete confirmation, and nuclear reset final confirmation.
- `storeMasterKeySecurely()` may store cached master key with SecureStore `requireAuthentication: true` when biometrics are available.

On web and simulators/no-hardware cases, `requireFreshBiometric()` returns true and updates a short freshness timestamp.

## 5. Key Derivation Details

### Salt And Device Binding

`generateMasterSalt()` uses `expo-crypto` random bytes to generate a 32-byte salt encoded as 64 hex characters.

`deriveMasterKey()` reads or creates `deviceUUID` through `getDeviceUUID()`. The KDF input material is:

```text
password + ":" + deviceUUID
```

`deviceUUID` is stored under `deviceUUID` through the platform storage abstraction. It is a local KDF input. Changing it makes existing password-derived keys fail unless a migration explicitly rekeys the vault.

### Argon2id Path

`deriveMasterKey()` attempts to dynamically import `hash-wasm` and call Argon2id with binary output.

Current Argon2id parameters are derived from the security profile:

- `25000` safe iterations maps to time cost `3`
- `100000` maps to time cost `4`
- higher profiles map to time cost `6`
- memory size is at least 64 MB and can rise to 128 MB or 256 MB
- `kdfVersion` defaults to `"v1"`, which uses parallelism `4`
- `"v2"` exists and enforces minimum memory/time cost with parallelism `1`, but no current storage metadata records a KDF version

The Argon2id output is 32 bytes and is converted to hex.

### PBKDF2 Fallback

If Argon2id cannot load or throws, `deriveMasterKey()` falls back to CryptoJS PBKDF2-SHA256:

- key size: 256 bits
- iterations: `Math.max(iterations || 100000, 3)`
- salt argument: the master salt hex string
- material: password plus `deviceUUID`

Risk/unknown: local metadata stores only the numeric security profile. It does not record whether Argon2id or PBKDF2 produced the current key. If a device previously fell back to PBKDF2 and later Argon2id becomes available, deriving the same password/salt/profile may produce a different key.

### Master Hash

`hashMasterKey(masterKeyHex)` is `SHA256(masterKeyHex)` encoded as hex. It is a local verifier only. It does not encrypt records by itself.

Password rotation must not update `pipass_master_hash` until new key material has been proven to decrypt/re-encrypt the vault and any server sync staging has succeeded according to the chosen transaction design.

## 6. Key Share Lifecycle

`deriveMasterKeyShares()` derives the master key hex, splits it with `splitKeyIntoShares()`, wipes a byte copy of the raw key, and returns `{ shareA, shareB }`.

The share scheme is XOR split:

- `shareA` is random bytes
- `shareB = keyBytes XOR shareA`
- `combineShares()` XORs both shares and returns the master key hex
- `wipeShares()` zeroes both `Uint8Array` share buffers

Live share locations:

- `app/(tabs)/index.tsx` keeps `keyShares` React state.
- `app/(tabs)/index.tsx` mirrors state into `keySharesRef`.
- `lockedSharesRef` may retain shares while the lock overlay is shown.
- `VaultScreen` keeps `keySharesRef`.
- `lib/vaultSession.ts` holds module-level `activeShares` for sibling screens such as honeytoken management.
- `SecureNotesModal` receives shares through props while open.

Wipe/clear points:

- tamper callback in app root wipes current shares and unauthenticates
- vault lock moves current shares into `lockedSharesRef`, clears active state, and `VaultScreen` passes null to `setActiveKeyShares()`
- unlocking from the lock overlay wipes `lockedSharesRef` before setting new shares
- reset paths wipe current or locked shares where implemented
- `setActiveKeyShares(newShares)` wipes the previous module-level shares when replacing with a different object
- `clearActiveKeyShares()` is available but current lock clearing happens through `setActiveKeyShares(null)` via `VaultScreen`

Risk/unknown: `combineShares()` returns a JavaScript string. Callers often convert that string back to bytes and wipe the byte buffer, but the JS string itself cannot be zeroed.

## 7. Vault Load And Decrypt Flow

### Storage Load

`VaultScreen.loadVault()` currently:

1. Calls `migrateToSharedStorage()`.
2. Reads `pipass_show_keyprints`.
3. Reads all local vault entries through `getAllEntries()`.
4. Reads all secure notes through `getAllSecureNotes()`.
5. If at least one entry exists and key shares are available, attempts to decrypt the first entry as a key-mismatch check.
6. On mismatch, offers local `destroyAllData()` plus `onReset()`.
7. Starts the auto-lock interval.

`getAllEntries()` only follows `pipass_vault_index`. It does not scan storage for orphan `pipass_vault_<entryId>` keys.

### Entry Encryption And Decryption

`encryptVaultEntry()`:

1. Combines key shares to master key hex.
2. Generates or reuses an entry id.
3. Generates a per-entry salt with `generateSaltHex()`.
4. Derives `entryKey = HKDF(masterKeyHex, "pipass-entry-key:" + entryId, entrySalt)`.
5. Encrypts password and encrypted display fields.
6. Optionally encrypts honeytoken aux metadata into `encryptedAux`.
7. Stores plaintext compatibility fields such as `title`, `username`, and optional `url`.
8. Wipes byte copies of `entryKey` and master key where possible.

`decryptVaultEntry()`:

1. Combines key shares to master key hex.
2. Derives the per-entry key if `entry.salt` exists; otherwise it uses the master key directly for legacy entries.
3. Decrypts encrypted title/username/url/password/notes fields.
4. Attempts to decrypt and validate `encryptedAux`.
5. Swallows aux-decryption failures and treats the row as not a honeytoken.
6. Wipes byte copies of derived keys where possible.

Current encryption primitive is in `crypto/encryption.ts`: AES-256-CBC with HMAC-SHA256 encrypt-then-MAC, with legacy support for older `iv:ciphertext` records. This audit does not change that design.

### Shared Vault Storage

`saveEntry()`, `deleteEntry()`, and `updateEntry()` call `syncSharedVaultBlob()`, which writes the current local encrypted entries as JSON into `pipass_shared_vault`.

`migrateToSharedStorage()` mirrors existing local entries once if `pipass_shared_migration_done` is not `"1"`.

The shared vault blob is encrypted-record JSON, not plaintext. It still contains sensitive metadata and compatibility fields and must be treated as sensitive.

## 8. Secure Notes Flow

Secure notes are stored separately from vault entries:

- index: `pipass_notes_index`
- rows: `pipass_note_<noteId>`

`encryptSecureNote()`:

- combines key shares
- derives note key with `deriveEntryKey(masterKeyHex, noteId, noteSalt)`
- encrypts label/content
- also stores plaintext `label` compatibility/display field

`decryptSecureNote()`:

- combines key shares
- derives note key or uses master key for legacy no-salt notes
- decrypts label/content

`SecureNotesModal` applies biometric/passcode gating before saving a new note and before decrypting a selected note. The list view receives encrypted note rows from `VaultScreen`.

Password rotation under the current architecture must re-encrypt secure notes along with vault entries.

## 9. Cached Master Key And Biometric Behavior

`pipass_master_key` is written by `storeMasterKeySecurely()` on native only. On web, the function returns without writing.

Native behavior:

- key: `pipass_master_key`
- service: `group.com.pipass.shared`
- if biometric hardware and enrollment are available, write with `requireAuthentication: true`
- if authenticated write fails, retry without `requireAuthentication`

`getMasterKeySecurely()` exists and attempts to read the cached key, but this audit found no runtime caller outside `workers/storageWorker.ts`. Current returning-user unlock still requires password derivation and master-hash verification.

`clearMasterKeySecurely()` deletes the cached key on native. `destroyAllData()` calls it. Ordinary lock/logout does not clear it.

Password rotation must update `pipass_master_key` only after the new local key path is proven valid and commit policy says the rotation succeeded.

## 10. Fractal Fingerprint And Keyprint Behavior

Fractal keyprints are visual/integrity metadata. They are not encryption keys, authentication factors, recovery proofs, or server trust signals.

`VaultScreen` derives fractal data from active key shares:

1. Combine shares to master key hex.
2. Call `deriveFractalSeed(masterKeyHex)`.
3. Wipe byte copies of the master key where possible.
4. Use returned `seedNumber`, `fingerprint`, and `fractalParams` for display.

`deriveFractalSeed()`:

- HKDF-extracts with static salt `SHA256("pipass-hkdf-salt-v1")`
- HKDF-expands info label `"fractal"` to 32 bytes
- computes fingerprint as `SHA256(seedHex)`
- maps seed bytes into Mandelbrot parameters

`pipass_fractal_fingerprint` stores either:

- current structured record `{ fingerprint, iterations, kdf: "argon2id", version: 1 }`
- legacy string fingerprint

`verifyFractalFingerprint()`:

- writes the current record if missing
- upgrades matching legacy string/current string records
- accepts a legacy HKDF fingerprint and upgrades it
- sets `fractalTampered` on mismatch or invalid record

Risk/unknown: the stored record currently says `kdf: "argon2id"` even though `deriveMasterKey()` can fall back to PBKDF2. A future KDF metadata design should distinguish intended KDF profile, actual KDF used, and fingerprint derivation version.

## 11. Native Vs Web Differences

Native:

- most storage uses SecureStore
- shared vault and cached master key use keychain service `group.com.pipass.shared`
- cached master key can be written with `requireAuthentication`
- biometric/passcode prompts are used for app access and sensitive reveals when hardware/enrollment exist
- screen capture is prevented while `VaultScreen` is mounted

Web:

- platform storage maps to `localStorage`
- `storeMasterKeySecurely()` and `getMasterKeySecurely()` are no-ops/null
- `requireFreshBiometric()` returns true
- `AuthScreen` allows bypass for testing
- shared vault storage also maps to `localStorage`

The web path has weaker local-secret storage guarantees and must be handled honestly in future password/session designs.

## 12. Password Rotation Implications

Reusable helpers:

- `deriveMasterKeyShares()` for deriving old and new shares
- `hashMasterKey()` for computing the new verifier after validation
- `reEncryptEntry()` for individual entry re-encryption
- `reEncryptSecureNote()` for individual secure-note re-encryption
- `storeMasterKeySecurely()` for post-commit cached-key update
- `saveFractalFingerprint()` for post-commit fingerprint update

Do not reuse directly without staging:

- `saveMasterKeyHash()`
- `saveMasterSalt()`
- `saveSecurityProfile()`
- `storeMasterKeySecurely()`
- `saveFractalFingerprint()`
- `setActiveKeyShares()`

Those functions mutate commit-visible state. Password rotation needs a staged transaction that proves all new encrypted entries/notes can decrypt with the new shares before replacing local metadata.

During password rotation, old and new shares will temporarily coexist:

- old shares decrypt current entries/notes
- new shares encrypt rotated entries/notes
- both must be wiped on failure
- active app state must not switch to new shares until commit succeeds

Minimum safe commit ordering for current architecture:

1. Verify current password against current salt/profile/hash.
2. Derive old shares and new shares.
3. Load all entries and notes from indexes.
4. Decrypt each record with old shares.
5. Re-encrypt each record with new shares.
6. Verify every rotated record decrypts with new shares.
7. Build/regenerate shared vault blob from rotated local records.
8. Sync server vault blob with expected previous server version if server sync participates.
9. Only after successful validation/sync, write new salt/profile/hash/cache/fingerprint.
10. Replace active shares and wipe old shares.
11. Handle rollback or recovery prompt if any post-sync local commit step fails.

`deviceUUID` must not change during ordinary password rotation. Changing it invalidates the KDF input for existing vault data unless a dedicated migration handles rekeying.

## 13. Risks And Unknowns

- KDF algorithm used is not stored. Argon2id fallback to PBKDF2 can create cross-runtime unlock risk if availability changes.
- `FractalFingerprintRecord.kdf` is hard-coded to `"argon2id"` even though PBKDF2 fallback exists.
- `getMasterKeySecurely()` is implemented but not used by current unlock flow.
- `reEncryptEntry()` and `reEncryptSecureNote()` exist but are not wired into a transactional password rotation flow.
- Security profile changes are now blocked when indexed local vault entries or secure notes exist. This is a short-term safety guard only; profile changes for populated vaults still need a real staged re-encryption transaction before they can be enabled.
- Setup backup import writes encrypted records before local password metadata is finalized. Compatibility and rekey expectations need a backup/restore audit.
- `combineShares()` creates non-wipeable JavaScript strings.
- `clearVault()` deletes `pipass_master_hash` but preserves salt/profile/recovery hash/deviceUUID; that is intentional reset-boundary behavior but important for rotation staging.
- The first-entry decrypt check in `loadVault()` does not verify every entry or any secure note.
- Plaintext compatibility/display metadata remains in vault entries and secure notes.

## 14. Future Implementation Checklist

Before implementing password rotation:

- decide whether KDF algorithm/version must be stored before rotation
- replace the short-term profile-change block with a staged re-encryption flow before enabling profile changes for populated vaults
- add tests around current unlock with Argon2id and PBKDF2 fallback behavior where practical
- add tests for password mismatch and missing `pipass_master_hash`
- add tests proving all entries and secure notes survive staged re-encryption
- add rollback tests for local commit failure after re-encryption
- add server sync conflict tests if rotation writes server vault blobs
- decide how to handle imported backup records during setup
- decide cached-key semantics: password convenience only, or future root/wrapping key cache
- update fractal fingerprint metadata if KDF/version metadata changes
- keep auth credential rotation and session-token policy separate from local vault password rotation

