# Setup Import Atomic Commit Design

## 1. Purpose

This document designs the future atomic commit boundary for first-time vault setup plus staged backup import. It explains what must be staged, verified, written, rolled back, and surfaced to the user before runtime wiring changes.

This is design-only. It does not change runtime code, tests, setup, import UI, storage writes, crypto algorithms, server routes, schemas, vault formats, password rotation, profile changes, or package scripts.

## 2. Current Commit Behaviour

Current first-time setup is split across two boundaries:

1. `performFirstTimeVaultSetup()` prepares a new Argon2id setup and writes local setup metadata.
2. `RecoveryKeyModal` confirmation later sets `pipass_vault_initialized` to `"1"` and publishes active key shares.

Setup currently writes these before recovery confirmation:

- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_kdf_metadata`
- `pipass_recovery_key_hash`
- native cached `pipass_master_key`, where supported

Current backup import is earlier and less controlled:

- `SeedSetupScreen` parses a selected file immediately.
- entries are saved through `saveEntry(entry)`
- secure notes are saved through `saveSecureNote(note)`
- `saveEntry()` updates `pipass_vault_index` and regenerates `pipass_shared_vault` after each entry
- secure note import updates `pipass_notes_index`

This means imported records can exist before setup metadata, recovery confirmation, or the vault initialized marker.

## 3. Future Staged Import Prerequisites

Runtime import wiring should not commit backup records directly from the file picker. The future flow should require these prerequisites before any storage write:

- strict backup parse and staging through `stagePipassBackup()`
- metadata-only compatibility classification through `classifyBackupCompatibility()`
- verifier schema validation if backup metadata includes a verifier
- sentinel verification through `verifyBackupSentinel()` when a valid verifier exists
- staged decryptability verification through `verifyStagedBackupDecryptability()`
- honeytoken `encryptedAux` warning classification
- explicit Argon2id setup preparation
- recovery key generation and user confirmation
- a rollback manifest for every storage key the commit helper may write or overwrite

Plaintext import, encrypted rekey, cross-device restore, and vault-root-key import are separate flows. They must produce the same staged final records before entering this commit boundary.

## 4. Data To Stage In Memory

Before any storage write, the app should stage:

- parsed backup envelope and metadata
- staged encrypted entries
- staged secure notes
- compatibility classification result
- parsed verifier result, if present
- sentinel verification result, if attempted
- staged decryptability result for every entry and note
- final records to commit, after any future plaintext encryption or rekey transform
- final `pipass_vault_index` contents
- final `pipass_notes_index` contents
- final `pipass_shared_vault` payload
- setup salt for `pipass_master_salt`
- setup key hash for `pipass_master_hash`
- numeric profile for `pipass_security_profile`
- setup KDF metadata for `pipass_kdf_metadata`
- recovery key hash for `pipass_recovery_key_hash`
- pending native cached master key decision
- pending key shares
- recovery key plaintext for the modal
- rollback manifest containing previous values or tombstones for every affected key

Staged memory must not be logged. Passwords, master keys, key shares, recovery keys, salts, hashes, ciphertext, plaintext, `deviceUUID`, and metadata JSON dumps must not appear in diagnostics.

## 5. Verification Gates Before Commit

The commit helper should refuse to write unless all required gates pass:

- password and confirmation satisfy the setup UI rules
- explicit Argon2id setup derivation succeeds
- generated KDF metadata validates
- recovery key hash is prepared
- backup schema is strict and supported
- backup compatibility is not `incompatible`
- valid backup verifier, if present, verifies successfully
- every staged entry and secure note decryptability check succeeds when encrypted records are being imported as-is
- honeytoken warnings are acknowledged or routed through the chosen future policy
- no unsupported portable encrypted backup path is being attempted
- no unresolved partial setup/import data exists locally
- recovery key confirmation has completed

The staged decryptability check is defense against metadata-only false positives. It should check every staged entry and every staged secure note, not only the first entry.

## 6. Recommended Commit Ordering

Future setup plus staged import should commit only after recovery key confirmation. This intentionally tightens the current setup boundary because it avoids leaving durable setup metadata behind when the user closes the app at the recovery modal.

Recommended order:

1. Re-read local state and ensure `pipass_vault_initialized` is still not `"1"`.
2. Build a rollback manifest from all keys that may be changed.
3. Acquire an in-process setup/import commit guard.
4. Write setup metadata:
   - `pipass_master_salt`
   - `pipass_security_profile`
   - `pipass_kdf_metadata`
   - `pipass_master_hash`
   - `pipass_recovery_key_hash`
5. Write staged entry records directly as `pipass_vault_<entryId>` without calling `saveEntry()`.
6. Write `pipass_vault_index` once after all entry records are written.
7. Write staged secure note records directly as `pipass_note_<noteId>` without calling `saveSecureNote()`.
8. Write `pipass_notes_index` once after all note records are written.
9. Regenerate and write `pipass_shared_vault` once from the final staged entry set.
10. Store native cached `pipass_master_key`, if platform policy allows.
11. Write `pipass_vault_initialized` as `"1"` last.
12. Publish active key shares and clear pending setup/import memory.

Setup metadata should be written before imported records because records are meaningful only under the prepared key path. The initialized marker remains the real success boundary: if anything fails before it is written, the app must roll back or enter repair.

Imported records should be committed after recovery confirmation. If the user does not confirm the recovery key, the staged backup remains memory-only and no setup/import storage is changed.

## 7. Rollback Strategy

The commit helper should behave like a transaction even though platform storage is key-value based.

Before writing, it should record for each affected key:

- whether the key existed
- the previous value if it existed
- whether the key is newly created by this commit
- whether the key is a per-entry or per-note record

On failure before `pipass_vault_initialized` is written, rollback should:

- delete newly written setup keys
- restore overwritten setup keys, if any existed
- delete newly written imported entries and notes
- restore overwritten entry and note records
- restore or delete `pipass_vault_index` according to its previous state
- restore or delete `pipass_notes_index` according to its previous state
- restore or delete `pipass_shared_vault` according to its previous state
- clear native cached `pipass_master_key` if it was written by the failed commit
- ensure `pipass_vault_initialized` is absent or not `"1"`
- wipe pending shares and recovery plaintext where possible

Rollback must not call broad destructive helpers unless the user explicitly chose a reset path. `clearVault()` is not enough for this boundary because it preserves some setup metadata and does not cover every partial setup/import key.

If rollback itself fails, the app should fail closed into an unfinished-setup repair state. It must not mark the vault initialized and must not publish active shares.

## 8. Recovery Confirmation Boundary

Recovery key confirmation should become the human confirmation gate before durable setup/import writes.

Recommended future flow:

1. User enters password and selects profile.
2. User chooses and stages backup, if any.
3. App prepares setup key, recovery key, staged records, and verification results in memory.
4. App shows recovery key modal.
5. User confirms recovery key.
6. App performs the atomic commit.
7. App sets active shares only after `pipass_vault_initialized` is written.

If the app closes before confirmation, no setup/import storage should be changed. If the app closes after confirmation but before commit completes, startup repair should detect initialized is still false and reconcile partial keys.

## 9. Shared Vault Regeneration Policy

Future staged import should avoid `saveEntry()` during commit because `saveEntry()` regenerates `pipass_shared_vault` after each record.

The commit helper should write entry records first, then write `pipass_vault_index`, then generate `pipass_shared_vault` once from the final staged entries. This avoids server/share-facing partial blobs and keeps rollback simpler.

Secure notes should not affect `pipass_shared_vault` unless a future vault format explicitly includes them in shared blobs.

## 10. Existing Partial-Data Repair

Before runtime wiring, add a detector for unfinished setup/import state:

- `pipass_vault_initialized` is not `"1"`
- setup metadata exists, or
- vault entry index/records exist, or
- secure note index/records exist, or
- `pipass_shared_vault` exists

If detected, the app should not silently continue setup over that state. It should offer a safe repair/reset path such as clearing unfinished local setup data.

The repair action should be explicit and scoped to unfinished setup/import artifacts. It should not delete credentials, install id, or server/account state unless the user chooses the broader reset path.

## 11. User-Facing Messages

Messages should be short and non-secret.

Recommended copy:

- Unsupported backup: "This backup format is not supported by this version of PiPass."
- Incompatible encrypted backup: "This encrypted backup was created for a different unlock environment. PiPass cannot restore it safely yet."
- Verifier failed: "PiPass could not verify that this backup matches the current unlock key."
- Decrypt verification failed: "Some backup records could not be verified. Nothing was imported."
- Commit failed with rollback success: "PiPass could not finish creating the vault. No changes were saved."
- Commit failed and repair is needed: "PiPass found an unfinished setup. Use repair or reset before creating a vault."

Do not display raw salts, hashes, KDF metadata JSON, record ciphertext, record plaintext, key material, `deviceUUID`, or stack traces.

## 12. Test Plan

Before runtime wiring, add tests for:

- setup plus staged import performs no storage writes before recovery confirmation
- recovery modal cancellation leaves no setup/import keys
- app interruption before recovery confirmation leaves no durable staged import state
- commit writes setup metadata before imported records
- entry records are written before `pipass_vault_index`
- note records are written before `pipass_notes_index`
- `pipass_shared_vault` is written once after final entry records and index
- `pipass_vault_initialized` is always the final success marker
- active shares are not published before initialized marker success
- cached master key is not saved before setup verification and commit readiness
- empty staged backup commits setup without entry/note writes
- every injected write failure before initialized marker triggers rollback
- rollback restores overwritten entry, note, index, shared blob, and setup values
- rollback deletes newly created setup/import keys
- rollback clears cached master key if written during a failed commit
- rollback failure enters repair state without setting initialized
- existing partial data is detected before commit
- repair cleanup removes unfinished setup/import artifacts without deleting account credentials or install id
- incompatible backup, verifier failure, and staged decryptability failure write nothing
- no user-facing or diagnostic error includes passwords, keys, salts, hashes, ciphertext, plaintext, recovery keys, or `deviceUUID`

Existing tests for KDF metadata, unlock migration, backup parsing, compatibility classification, sentinel verification, staged decryptability, and storage reset should keep passing.

## 13. Implementation Prompt Sequence

Recommended sequence:

1. Add a pure commit-plan builder for setup plus staged import.
2. Add a rollback manifest model and tests.
3. Add low-level batch storage helpers that can write entries/notes without regenerating shared vault per record.
4. Add a storage-injected atomic commit helper with failure injection tests.
5. Add unfinished setup/import detection.
6. Add scoped repair cleanup for unfinished setup/import artifacts.
7. Move `SeedSetupScreen` import from immediate writes to memory staging.
8. Move setup commit from pre-recovery metadata writes to post-recovery atomic commit.
9. Regenerate `pipass_shared_vault` once during commit.
10. Publish active shares only after initialized marker success.
11. Add user-facing failure and repair messages.

Do not combine this with password rotation, profile changes, vault-root-key migration, server auth changes, session-token changes, or encryption algorithm changes.

## 14. Open Decisions

- Should the future flow support setup without any storage writes before recovery confirmation on every platform, including low-memory mobile sessions?
- Should native cached master key write failure block setup, or should setup continue without cache?
- Should repair cleanup be offered automatically on startup or only when the user attempts setup?
- Should old partial imported records be shown as recoverable diagnostics before cleanup, or treated as unsafe unfinished data?
- Should setup metadata and records be committed under a single explicit `pipass_setup_commit_in_progress` marker?
- Should `pipass_shared_vault` be omitted for an empty imported entry set, or written as an empty encrypted blob for consistency?
- Should future encrypted rekey import commit old and new record ids exactly, or generate fresh ids to avoid collisions?
