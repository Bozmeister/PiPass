# Unlock KDF Migration Commit Boundary

## 1. Purpose

This document defines the future commit boundary for wiring KDF metadata migration into real unlock. It explains when unlock may call `planUnlockKdfDerivation()`, when `metadataToPersist` may be written to `pipass_kdf_metadata`, and how controlled failures should behave.

This is a design-only document. It does not change runtime code, tests, storage helpers, setup, unlock, crypto behavior, UI, server routes, schemas, vault formats, or package scripts.

## 2. Current State

Pre-Prompt-038 runtime unlock:

1. Reads `pipass_master_salt`, numeric `pipass_security_profile`, and `pipass_master_hash`.
2. Calls `deriveMasterKeyShares()`.
3. Uses current `deriveMasterKey()`, which attempts Argon2id and falls back to PBKDF2.
4. Compares `hashMasterKey(candidate)` with `pipass_master_hash`.
5. Saves the cached native master key after a hash match.
6. Sets active key shares and lets `VaultScreen` load/decrypt the vault.

Prompt 038 wires the unlock decision path through `performCurrentUnlockVerification()` and `planUnlockKdfDerivation()`. New vault setup, password rotation, profile changes, fractal fingerprint metadata, vault formats, and server behavior remain unchanged.

KDF helpers now used or available for unlock migration:

- `getKdfMetadata()`, `saveKdfMetadata()`, and `clearKdfMetadata()`
- `deriveMasterKeyWithArgon2id()`
- `deriveMasterKeyWithPbkdf2()`
- `deriveMasterKeyFromKdfMetadata()`
- `detectLegacyKdfFromMasterHash()`
- `planUnlockKdfDerivation()`

## 3. Future Unlock Decision Tree

Future unlock should call `planUnlockKdfDerivation()` after the user submits the master password and after the app has read these local values:

- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- optional `pipass_kdf_metadata`
- `deviceUUID` through the derivation helper path

Unlock must not call the planner if `pipass_master_hash` is missing unless a separate legacy policy explicitly defines that case.

Decision tree:

1. If valid `pipass_kdf_metadata` exists:
   - derive only with that metadata
   - compare `hashMasterKey(candidate)` with `pipass_master_hash`
   - on match, unlock may continue
   - on mismatch, fail closed
   - do not try legacy detection
   - do not update metadata
2. If metadata is missing:
   - run legacy detection through `planUnlockKdfDerivation()`
   - Argon2id candidate is tried first
   - PBKDF2 candidate is tried only as legacy compatibility
   - on hash match, unlock may continue and may persist `metadataToPersist`
   - on no match, fail as an incorrect password or incompatible local state
3. If metadata exists but is invalid:
   - fail closed by default
   - do not silently delete, ignore, replace, or fall back to legacy detection

## 4. Commit Boundary Rules

`pipass_kdf_metadata` may be written only after all of these are true:

- user-submitted password produced a candidate master key
- `hashMasterKey(candidateMasterKeyHex)` matched `pipass_master_hash`
- the planner returned `ok: true`
- the planner returned `metadataToPersist`
- the metadata validates with `isValidKdfMetadata()`
- `pipass_master_hash` existed before the planner ran

Metadata must never be written based only on successful Argon2id execution. The hash match is the commit boundary.

Recommended ordering for missing-metadata unlock:

1. User submits password.
2. Read salt/hash/profile/metadata.
3. Call `planUnlockKdfDerivation()`.
4. If planner fails, stop unlock.
5. If planner succeeds, split `masterKeyHex` into shares or adapt the helper path to return shares.
6. Persist `metadataToPersist` before saving cached master key and before setting active key shares, if possible.
7. If metadata persistence succeeds, continue unlock normally.
8. If metadata persistence fails, unlock may continue for this session using the already verified key, but the app must surface a safe non-secret warning and retry on the next successful unlock.

Rationale for persisting before active shares:

- the metadata write is not required to decrypt the vault in the current session once the key is verified
- writing before active shares reduces the chance that the app appears fully migrated when metadata was not saved
- if the write fails, the app can still choose a deliberate degraded-success path before exposing the unlocked vault

The implementation should keep this write as the only storage mutation in the unlock migration step. It must not update salt, profile, master hash, fractal fingerprint, vault entries, notes, server blobs, credentials, installId, or `deviceUUID`.

## 5. Failure Handling

### Metadata Persistence Fails After Verification

If `metadataToPersist` fails to write after the password hash has matched:

- unlock may continue for the current session
- do not discard the verified key solely because metadata persistence failed
- do not retry in a tight loop
- show a safe warning such as "PiPass unlocked, but could not save a local compatibility update. You may be asked to unlock again next time."
- retry metadata persistence on the next successful unlock
- do not log password, key material, salt, hash, `deviceUUID`, or metadata JSON

This is a deliberate degraded-success state, not a partial password rotation. It does not change encrypted data or the master hash.

### Metadata Exists But Hash Verification Fails

If valid metadata exists but the candidate hash does not match `pipass_master_hash`:

- fail closed
- show the normal incorrect-password message where possible
- do not try PBKDF2 or any other KDF
- do not clear metadata
- do not rewrite metadata
- do not update cached key or active shares

This protects against silent algorithm switching.

### Metadata Exists But Is Invalid

If `pipass_kdf_metadata` exists but validation fails:

- fail closed by default
- do not treat it as missing
- do not run legacy detection
- do not automatically delete it
- do not write replacement metadata
- offer only a future repair/reset path

Invalid metadata may indicate corruption or an unsupported future version. Automatic fallback could turn corruption into a silent downgrade.

### Argon2id Is Unavailable

If metadata requires Argon2id and Argon2id is unavailable:

- fail with a clear controlled message
- do not fall back to PBKDF2
- do not clear metadata
- do not rewrite metadata
- do not set active key shares

If metadata is missing and Argon2id is unavailable, legacy detection may still try PBKDF2 because that path is explicitly for old un-migrated vaults.

## 6. User-Facing Messages

Messages should be short, non-secret, and avoid implementation details that look like instructions to attackers.

Recommended messages:

- Invalid metadata: "This vault's local unlock settings look inconsistent. PiPass cannot unlock it safely. Use recovery or reset options."
- Metadata hash mismatch: use the existing incorrect-password message.
- Argon2id unavailable for Argon2id metadata: "This device cannot run the required unlock protection right now. Update or restart the app and try again."
- Legacy no-match: use the existing incorrect-password message unless diagnostics clearly indicate local corruption.
- Metadata persistence failed after successful unlock: "PiPass unlocked, but could not save a local compatibility update. You may be asked to unlock again next time."

Do not display raw algorithm parameters, hashes, salts, `deviceUUID`, key material, stack traces, or metadata JSON.

## 7. Ordering With Key Shares And Cached Key

Future unlock should avoid creating long-lived shares until the planner returns success.

Recommended order:

1. Planner verifies candidate master key against `pipass_master_hash`.
2. If missing metadata was detected, attempt `saveKdfMetadata(metadataToPersist)`.
3. Convert verified `masterKeyHex` to shares.
4. Save cached native key with `storeMasterKeySecurely(masterKeyHex)`.
5. Wipe byte buffers where possible.
6. Set React state and `activeShares`.

If implementation cannot avoid deriving shares before the metadata write, it must not publish shares into app/global state until the planner has succeeded and the metadata write decision has completed.

The cached key write should not happen before hash verification. If metadata persistence fails but unlock continues, cached key may still be saved because the key has been verified; however, the app should still warn that KDF metadata migration was not saved.

## 8. Fractal Fingerprint Interaction

Fractal fingerprint verification should happen after the unlock key has been verified and after KDF metadata migration has either succeeded or entered the degraded-success state.

For this migration:

- do not update `pipass_fractal_fingerprint` solely because `pipass_kdf_metadata` was written
- do not use fractal fingerprint mismatch as password verification
- do not use fractal fingerprint to decide KDF algorithm
- future fractal record version 2 should reference actual KDF metadata only after the KDF metadata migration is complete

If fractal verification fails after unlock, it should use the existing tamper/keyprint behavior and remain separate from KDF metadata persistence.

## 9. Vault Load And Decrypt Interaction

Vault load/decrypt checks should remain downstream of successful unlock planning.

Recommended order:

1. KDF planner verifies master hash.
2. Metadata persistence boundary is handled.
3. Active shares are published.
4. `VaultScreen.loadVault()` runs.
5. Existing first-entry decrypt check runs.

The vault decrypt check must not be used as the primary KDF metadata commit boundary. It is useful as defense-in-depth, but metadata should be based on the master-hash match from the local verifier.

Future tests should eventually expand beyond the first-entry check to include secure notes and every indexed vault entry during password/profile rotation. That is separate from unlock metadata migration.

## 10. Storage And Wipe Behaviour

`pipass_kdf_metadata` remains local-only:

- vault lock preserves it
- local logout preserves it
- `clearVault()` preserves it for now
- `destroyAllData()` deletes it
- password/profile rotation updates it only through a staged transaction
- invalid metadata is not automatically deleted

Unlock migration must not send KDF metadata to the server, store it in audit logs, or include it in request headers.

## 11. Test Plan

Before wiring into real unlock, add tests for:

- valid Argon2id metadata path unlocks and does not run legacy detection
- valid PBKDF2 metadata path unlocks and does not run legacy detection
- valid metadata hash mismatch fails closed
- invalid metadata fails closed and does not run legacy detection
- missing metadata with Argon2id match persists `metadataToPersist` only after hash verification
- missing metadata with PBKDF2 match persists `metadataToPersist` only after hash verification
- missing metadata no-match writes no metadata
- metadata write failure after hash match can return a degraded-success state if product accepts that policy
- cached master key is not written before hash verification
- active shares are not published before planner success
- metadata migration does not update salt/profile/master hash/fractal fingerprint/vault entries/notes/server state
- controlled failure messages do not include secrets
- Argon2id unavailable with Argon2id metadata fails without PBKDF2 fallback
- PBKDF2 legacy detection remains available only when metadata is missing

Existing tests for `planUnlockKdfDerivation()` should remain pure and storage-free. Wiring tests should cover the app root unlock callback separately.

## 12. Implementation Prompt Sequence

Recommended implementation order:

1. Add app-root unlock tests around current behavior before changing it.
2. Add a storage-read wrapper that classifies metadata as `valid`, `missing`, or `invalid`.
3. Wire `planUnlockKdfDerivation()` into unlock behind focused tests.
4. Persist `metadataToPersist` after hash verification in the missing-metadata path.
5. Add tests for metadata write failure and the chosen degraded-success behavior.
6. Add user-facing controlled failure messages.
7. Add tests proving metadata path does not fall back.
8. Only after unlock migration is stable, update new-vault setup to require Argon2id and write metadata at setup.
9. Later, update fractal fingerprint metadata to version 2.

Do not combine this with password rotation, profile changes, vault-root-key migration, server auth rotation, session-token changes, or encryption algorithm changes.

## 13. Open Decisions

- Should metadata persistence failure after successful verification allow unlock on every platform, or only native where storage failures are expected to be transient?
- Should the degraded-success warning be modal, toast-like, or only visible in diagnostics?
- Should invalid metadata offer a repair flow that requires explicit user confirmation before deleting `pipass_kdf_metadata`?
- Should missing `pipass_master_hash` remain a hard failure, or should a separate legacy verifier policy exist?
- Should cached master key save happen before or after the metadata write if the metadata write fails repeatedly?
- Should the first implementation persist metadata before splitting shares, or split shares first but keep them unpublished until the metadata write decision completes?
