# Staged Backup Import Wiring Plan

## 1. Purpose

This document plans how future prompts should wire staged backup import into first-time setup without preserving the current immediate-write import behavior.

This is design-only. It does not change runtime code, tests, UI, storage writes, setup flow, import flow, crypto algorithms, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Current Runtime Import Problem

`SeedSetupScreen` currently owns the backup picker and import loop. When a user selects a file, it:

1. reads the file as JSON
2. accepts any truthy `version` with `entries` as an array
3. calls `saveEntry(entry)` for matching entries
4. calls `saveSecureNote(note)` for matching secure notes
5. shows a count before setup metadata or recovery confirmation is finalized

This means imported records, indexes, and `pipass_shared_vault` can be written before:

- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_kdf_metadata`
- `pipass_recovery_key_hash`
- cached master key policy
- `pipass_vault_initialized`
- recovery key confirmation

The future staged flow must stop writing records from the picker.

## 3. Existing Helper Layers

Prepared helper layers are available but not fully wired into import:

- `parsePipassBackup()` / `stagePipassBackup()` for strict schema parsing and in-memory staging
- `classifyBackupCompatibility()` for metadata-only compatibility classification
- `parseBackupVerifier()` / `getBackupVerifierFromMetadata()` for verifier schema validation
- `verifyBackupSentinel()` for injected sentinel verification
- `verifyStagedBackupDecryptability()` for injected entry/note decryptability checks
- `buildSetupImportCommitPlan()` for deterministic storage operation planning
- `executeSetupImportCommitPlan()` for storage-injected commit and rollback
- `classifySetupImportLocalState()` / `buildSetupImportRepairPlan()` for partial-state detection
- `executeSetupImportRepairPlan()` and the startup repair surface for scoped cleanup

These helpers should stay pure/injected until runtime wiring has focused tests.

## 4. Ownership And Data Flow

Recommended ownership:

- `SeedSetupScreen` owns file selection UI, selected-file status, and non-secret import summary.
- App root owns staged backup state that must survive until setup/recovery confirmation.
- App root owns setup/import commit orchestration because it already owns `performFirstTimeVaultSetup()`, `RecoveryKeyModal`, pending shares, and initialized routing.

Future data flow:

1. User selects a backup file in `SeedSetupScreen`.
2. `SeedSetupScreen` reads the file text and calls an injected `onStageBackup(fileText)` prop.
3. App root calls `parsePipassBackup()` / `stagePipassBackup()`.
4. App root stores a staged result, counts, warnings, and safe status text in React state.
5. `SeedSetupScreen` receives a non-secret staged summary prop and renders it.
6. User creates the vault normally.
7. Setup preparation receives the staged backup summary/result from app root.
8. Recovery key confirmation becomes the commit trigger.
9. App root builds and executes the atomic setup/import commit plan.

`SeedSetupScreen` should not directly call `saveEntry()`, `saveSecureNote()`, `syncSharedVaultBlob()`, `performFirstTimeVaultSetup()`, or commit helpers.

## 5. Future Staged Import UI States

Minimum future UI states:

- no backup selected
- reading backup file
- backup staged successfully with entry/note counts
- unsupported backup schema or format
- encrypted backup compatibility unknown
- encrypted backup incompatible
- verifier missing, invalid, passed, or failed
- staged decryptability passed or failed
- staged import will be included after recovery confirmation
- setup can continue without import after clearing/replacing staged backup

Unsupported or incompatible backup should not block creating a new empty vault unless the user explicitly chooses to keep the unsupported backup attached. The safer default is:

- block importing that backup
- allow the user to remove the staged backup
- allow setup to continue with no import

Visible text must not include backup contents, ciphertext, salts, hashes, KDF metadata JSON, `deviceUUID`, record ids if unnecessary, or stack traces.

## 6. Compatibility And Verifier Gates

Recommended first implementation for `encrypted-local-records`:

1. `parsePipassBackup()` / `stagePipassBackup()` runs immediately after file read.
2. If parsing fails, store only a safe error and no staged backup.
3. `classifyBackupCompatibility()` runs after parsing against the current local compatibility context.
4. If classification is `incompatible`, reject import for this setup session.
5. If classification is `unknown`, do not import by default. Let setup continue only after the user removes or dismisses the staged backup.
6. If classification is `compatible`, continue to verifier handling.
7. If verifier metadata exists, validate it with verifier schema helpers.
8. If a valid verifier exists and a verified key path is available, run `verifyBackupSentinel()`.
9. If sentinel verification fails, reject import without storage writes.
10. Run `verifyStagedBackupDecryptability()` after setup key preparation provides the key material or shares needed by injected decryptors.
11. If any staged entry or secure note fails decryptability verification, reject import without storage writes.

Compatibility for current encrypted-local-record backups should be treated as same-install/same-key-path only. Different-device encrypted import should remain blocked until an explicit rekey flow or vault-root-key model exists.

## 7. Recovery Confirmation Boundary

Recovery confirmation should gate all durable setup/import writes.

Recommended future setup sequence:

1. User stages backup, if any.
2. User enters password and security profile.
3. App root prepares explicit Argon2id setup result in memory.
4. App root prepares recovery key and pending shares in memory.
5. If a compatible staged backup exists, app root verifies sentinel/decryptability in memory.
6. App shows `RecoveryKeyModal`.
7. If the user does not confirm, no setup/import storage writes occur.
8. On confirmation, app root executes the setup/import commit plan.
9. Only after commit success does app publish active shares and route to the vault.

This tightens the current setup boundary, where setup metadata is already written before recovery confirmation. That change should be made in a focused future prompt with tests.

## 8. Atomic Commit Orchestration

The future commit orchestration helper should accept prepared data, not raw passwords:

- setup salt
- setup master hash
- security profile
- setup KDF metadata
- recovery key hash
- staged entries
- staged secure notes
- staged vault index
- staged notes index
- staged shared vault blob
- optional cached-key write marker/reference
- initialized marker value

The helper should:

1. recheck local state is still safe to commit
2. build a `SetupImportCommitPlan`
3. execute it through injected storage with `executeSetupImportCommitPlan()`
4. rollback on failure before `pipass_vault_initialized`
5. return safe success/failure status only

`executeSetupImportCommitPlan()` should eventually replace the current immediate import writes. The future commit path should write entries directly and regenerate `pipass_shared_vault` once, rather than calling `saveEntry()` for each record.

## 9. Failure Handling

Parse/stage failure:

- no storage writes
- show a safe invalid/unsupported backup message
- allow setup without import

Compatibility failure:

- no storage writes
- block importing that backup
- allow setup after removing/dismissing backup

Sentinel or decryptability failure:

- no storage writes
- show that the backup could not be verified
- do not partially import records

Recovery modal cancellation/interruption:

- no setup/import writes in the future target design
- staged memory is discarded on app close

Commit failure with rollback success:

- do not publish active shares
- do not mark initialized
- show safe setup failure message
- route through startup repair if any partial keys remain

Commit failure with rollback failure:

- fail closed
- do not publish active shares
- leave app in repair-required state
- rely on startup repair surface for scoped cleanup

## 10. Test Plan

Before runtime wiring, add tests for:

- `SeedSetupScreen` import action calls a staging callback rather than `saveEntry()` / `saveSecureNote()`
- selected valid backup produces a staged summary with counts only
- invalid backup shows safe error and performs no storage writes
- unsupported format blocks import but allows setup after staged backup is cleared
- `classifyBackupCompatibility()` runs before any verifier/decryptability checks
- incompatible encrypted backup never reaches commit planning
- unknown compatibility does not silently import
- valid verifier is parsed and passed to sentinel verification
- invalid verifier blocks import or is surfaced according to chosen policy
- sentinel verification failure performs no writes
- staged decryptability checks every entry and secure note
- decryptability failure performs no writes
- recovery confirmation cancellation writes no setup/import keys in the future target flow
- successful recovery confirmation builds a commit plan with setup metadata, entries, notes, shared blob, cached key policy, and initialized marker last
- commit failure does not publish active shares
- old immediate import writes are removed or blocked
- startup repair still handles old partial import data
- UI copy and automation output contain no secrets or backup contents

Manual verification should reuse `docs/STARTUP_REPAIR_MANUAL_VERIFICATION.md` and add staged import cases once selectors exist.

## 11. Implementation Prompt Sequence

Recommended staged rollout:

1. Prompt 059: change `SeedSetupScreen` import button to parse/stage only through an injected callback, with no storage writes.
2. Prompt 060: pass staged backup summary to app root/setup flow, still with no commit.
3. Prompt 061: add a setup/import commit orchestration helper using existing plan/executor, with injected dependencies.
4. Prompt 062: wire commit helper behind recovery confirmation.
5. Prompt 063: remove or block old immediate import writes.
6. Prompt 064: add manual/UI verification for staged import.

Keep each prompt narrow. Do not combine staged import wiring with password rotation, profile changes, vault-root-key migration, KDF changes, server auth changes, session-token changes, or encryption algorithm changes.

## 12. Open Decisions

- Should `SeedSetupScreen` call `parsePipassBackup()` directly for immediate UI feedback, or should app root own all parsing through an injected callback?
- Should unknown compatibility block only import or block the entire setup submission until the staged backup is removed?
- Should valid same-install encrypted backups require both metadata compatibility and full decryptability verification, or is a valid sentinel enough for small backups?
- What exact compatibility context is available during first-time setup before `pipass_kdf_metadata` is committed?
- Should recovery confirmation happen before or after staged decryptability verification if verification requires prepared key material?
- How should the UI explain that encrypted backups are same-install only without exposing `deviceUUID` or KDF details?
- Should honeytoken `encryptedAux` warnings block import or allow import with a post-restore reissue warning?
- Should setup without import remain available after an incompatible backup is selected?
- How should native cached master key writes be represented in the atomic commit plan without exposing key material?
