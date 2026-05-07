# Staged Backup First Commit Checklist

## 1. Purpose

This checklist defines the conditions that must be true before PiPass enables the first real staged backup record commit during first-time setup.

This is documentation-only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

Prompt 077 implementation note: `determineStagedBackupImportCommitEligibility()` now provides a pure safe-state decision for whether runtime `importCommitEnabled` may become true. It does not parse backups, decrypt records, write storage, or wire staged records into runtime commit.

Prompt 078 implementation note: `prepareSetupImportCommitFromRuntimeState()` now models the future app-root setup/import orchestration shape with injected dependencies. It evaluates import eligibility before calling the setup/import orchestrator.

Prompt 079 implementation note: app-root recovery confirmation now uses `prepareRuntimeStagedBackupCommitContext()` plus `prepareSetupImportCommitFromRuntimeState()` to commit the first supported staged backup case: schema `pipass-backup`, version `1`, format `encrypted-local-records`, same-install/same-key-path only. Ineligible staged backups fail closed before the staged commit path; no backup records, notes, indexes, or shared vault blob are written unless all runtime gates pass. Active shares are still published only after the full setup/import commit succeeds.

## 2. Current Runtime State

Current behavior is mixed by eligibility:

- backup selection parses and stages the backup in memory
- app root owns staged backup state in memory only
- first-time setup without a staged backup remains setup-only
- unsupported, incompatible, unverified, undecryptable, or warning-blocked staged backups do not write records
- eligible same-install encrypted-local-record backups are included only after recovery confirmation
- the existing setup/import commit plan and executor write staged entries, secure notes, indexes, shared vault blob, setup metadata, cached-key policy, and initialized marker
- `pipass_vault_initialized` remains the final durable setup/import marker
- staged memory clears after successful setup/import commit, explicit removal, abandonment, or recovery-confirmed commit failure

The checked-only bridge remains the setup-screen source-boundary behavior before recovery confirmation and for backups that do not pass the first supported import gates.

## 3. First Supported Import Scope

The first runtime record-commit implementation may support only:

- schema: `pipass-backup`
- version: `1`
- format: `encrypted-local-records`
- same-install / same-key-path encrypted backups

Out of scope:

- portable encrypted restore
- cross-device restore
- plaintext import
- legacy unversioned backups
- server-side honeytoken reissue
- password rotation
- vault-root-key migration
- vault format changes

## 4. Enabling Condition For `importCommitEnabled`

Runtime may flip `importCommitEnabled` from `false` to `true` only inside the first-time setup path after all of these are available:

1. A staged backup exists in app-root memory.
2. The staged backup matches the supported schema, version, and format.
3. Prepared setup metadata exists in memory.
4. Prepared recovery key state and pending shares exist in memory.
5. A local/prepared compatibility context is available.
6. Compatibility, verifier, sentinel, decryptability, and warning gates have run.
7. `decideStagedBackupCommitGate()` returns `allowed: true` and `mode: "commit-staged-backup"`.
8. The user has explicit import intent, or the UI has a clearly visible ready-for-commit state before recovery confirmation.

Until these are all true, keep `importCommitEnabled: false` and keep checked-only copy.

## 5. Required Gate Order

Required runtime order:

1. Parse and stage the selected file in memory.
2. Prepare first-time setup data in memory.
3. Build the compatibility context.
4. Run `classifyBackupCompatibility()`.
5. Reject `unknown` and `incompatible` by default.
6. Parse verifier metadata if present.
7. Run `verifyBackupSentinel()` when a valid verifier is present.
8. Run `verifyStagedBackupDecryptability()` across every staged entry and secure note.
9. Evaluate warnings through `decideStagedBackupCommitGate()`.
10. Only if the gate allows `commit-staged-backup`, show ready-for-commit copy.
11. Only after recovery confirmation, include staged records in the setup/import commit plan.

No backup record write may happen before recovery confirmation.

## 6. Verifier Policy

Missing verifier:

- allowed for the first implementation only if compatibility is compatible and full decryptability passes
- must not be described as verified by sentinel
- may surface a safe generic warning if product wants visible caution

Invalid verifier:

- blocks import
- does not fall back to commit
- allows setup-only only after the staged backup is cleared or explicitly dismissed

Valid verifier:

- must pass sentinel verification
- sentinel failure blocks import
- sentinel success is not enough by itself; full decryptability is still required

## 7. Decryptability Policy

`verifyStagedBackupDecryptability()` must check:

- every staged entry
- every staged secure note
- all record shapes that would be written

If any entry or secure note fails:

- no backup records are included in the commit plan
- no partial import is allowed
- UI shows safe failure copy only
- no record ids, contents, ciphertext, plaintext, salts, hashes, or metadata JSON are shown

## 8. Honeytoken Warning Policy

Use the current conservative gate default:

- honeytoken, `encryptedAux`, decoy, or equivalent warnings block import by default
- do not reissue server-side honeytokens in the first implementation
- do not decrypt or expose aux contents in UI, logs, test output, or errors
- allow warnings only if a future explicit product decision sets `allowHoneytokenWarnings`

If warnings block import, the user may continue setup-only only after clearing or dismissing the staged backup.

## 9. Setup-Only Continuation Policy

If any import gate fails:

- do not write backup records
- do not include staged entries, notes, indexes, or shared vault blob in the commit plan
- do not silently continue as setup-only while implying import will happen
- let the user clear the staged backup or explicitly dismiss import
- after clear/dismiss, setup-only continuation may proceed with safe copy that no backup records have been written and setup will continue without backup records

Recommended first implementation: require clearing or explicit dismissal before the setup submit path continues.

## 10. Durable Write Allowlist

During a successful setup/import commit, durable writes may include only:

- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_kdf_metadata`
- `pipass_recovery_key_hash`
- staged `pipass_vault_<entryId>` records
- `pipass_vault_index`
- staged `pipass_note_<noteId>` records
- `pipass_notes_index`
- `pipass_shared_vault`
- optional cached master key marker/reference if already represented by the setup commit path
- `pipass_vault_initialized`

Every write must be planned by `buildSetupImportCommitPlan()` and executed by `executeSetupImportCommitPlan()` through injected storage.

## 11. Durable Write Denylist

The staged backup commit must not write or delete:

- `pipass.auth.*`
- `pipass.installId`
- `deviceUUID`
- server session state
- passkey credentials
- trust/audit state
- password rotation metadata
- vault-root-key migration state
- unsupported backup metadata
- raw backup file contents
- plaintext records
- decrypted record contents
- recovery key value
- master key value except the existing cached-key path already owned by setup

Do not call `saveEntry()`, `saveSecureNote()`, or `syncSharedVaultBlob()` for staged import commit.

## 12. Required Write Order

The commit plan must remain deterministic:

1. Setup metadata first.
2. Entry records.
3. Vault index.
4. Secure note records.
5. Notes index.
6. Shared vault blob.
7. Cached-key marker/reference if included.
8. `pipass_vault_initialized` last.

`pipass_vault_initialized` being last is non-negotiable.

## 13. Rollback And Failure Handling

On pre-commit gate failure:

- do not call the commit executor
- do not publish active shares
- do not mark initialized

On commit failure before initialized marker:

- executor must rollback completed writes
- active shares must not publish
- show safe setup/import failure copy

On initialized-marker failure:

- executor must rollback previous setup/import writes
- active shares must not publish

On rollback failure:

- fail closed
- do not publish active shares
- do not claim setup/import success
- rely on startup repair detection for partial local state

## 14. Active Share Publication

Active shares may be published only after:

- setup/import commit executor returns success
- `pipass_vault_initialized` has been written last
- any staged backup records included in the plan have committed successfully
- staged backup memory is cleared or marked committed without retaining raw file contents

If commit fails, wipe pending shares according to the existing setup failure policy.

## 15. UI Wording Requirements

Before gates pass:

- keep "Backup checked only"
- say no backup records have been written

After gates pass and `importCommitEnabled` is true:

- "Backup ready for recovery-confirmed commit."
- "No backup records have been written."
- show counts only, not record contents

After durable commit succeeds:

- "Backup imported."
- "X entries and Y secure notes were added."

Never say "imported", "restored", or "added" before commit success.

Never show secrets, ciphertext, plaintext, salts, hashes, metadata JSON, `deviceUUID`, recovery key, master key, raw backup values, record titles, usernames, secure note labels, or real record ids.

## 16. Required Automated Tests

Before runtime record commit is allowed, tests must prove:

- `importCommitEnabled` remains false until every required gate passes
- unsupported schema/version/format cannot enable import commit
- unknown compatibility blocks import by default
- incompatible compatibility blocks import
- missing verifier follows the first-implementation policy
- invalid verifier blocks import
- present verifier requires successful sentinel verification
- sentinel failure blocks import before decryptability/commit
- full decryptability checks every entry and secure note
- decryptability failure writes no backup records
- honeytoken warnings block import by default
- clear/dismiss permits setup-only continuation without backup records
- ready-for-commit copy appears only after gate allow
- imported/restored/added copy appears only after commit success
- staged records are added to the commit plan only when gate allows `commit-staged-backup`
- commit plan includes setup metadata, entries, notes, indexes, shared vault, cached-key policy if applicable, and initialized marker
- initialized marker is last
- commit executor rollback handles failures before initialized marker
- rollback failure fails closed
- active shares publish only after full commit success
- staged backup state clears after success or abandon paths
- source-boundary guard still blocks old immediate import helpers in `SeedSetupScreen`
- output contains no backup contents, ciphertext, plaintext, salts, hashes, metadata JSON, `deviceUUID`, recovery key, master key, or raw backup values

Existing parser/stager, compatibility, verifier, sentinel, decryptability, transition, bridge, orchestrator, commit-plan, executor, startup repair, setup, KDF, server, and storage tests must continue to pass.

## 17. Required Manual Tests

Use `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION.md` for the step-by-step Prompt 080 manual verification pass.

Manual verification must cover:

- no-backup setup still works
- valid same-install backup reaches ready-for-commit state
- ready-for-commit copy does not say imported/restored/added
- recovery confirmation imports records only after confirmation
- imported entries and secure notes appear after commit success
- invalid backup blocks import and writes no records
- unknown compatibility blocks import
- incompatible compatibility blocks import
- decryptability failure blocks import
- honeytoken warning blocks import by default
- clearing/dismissing a blocked backup permits setup-only
- setup-only after clear creates an empty vault
- commit failure does not publish active shares
- startup repair handles intentionally simulated partial state
- web behavior
- native/Expo behavior if available

Manual logs and screenshots must not include real backups, passwords, recovery keys, salts, hashes, encrypted blobs, metadata JSON, `deviceUUID`, or record contents.

## 18. Implementation Prompt Sequence

Recommended sequence:

1. Prompt 077: add a pure runtime import-commit eligibility helper that decides whether `importCommitEnabled` may be true.
2. Prompt 078: add app-root setup/import commit orchestration tests with staged backup present, still injected and no UI commit.
3. Prompt 079: wire real staged backup commit behind recovery confirmation for same-install backups only.
4. Prompt 080: add manual verification for real staged backup import commit.

Keep these separate from portable restore, cross-device restore, server honeytoken reissue, password rotation, vault-root-key migration, KDF changes, route/schema changes, and vault format changes.

## 19. Open Decisions

- Is explicit import intent required as a checkbox/button, or is visible ready-for-commit copy enough?
- Should missing verifier show a non-blocking warning even when decryptability passes?
- Should missing verifier become blocking after all new backups include sentinels?
- Should honeytoken warnings ever be acknowledgement-based instead of blocking?
- Should setup-only continuation require clearing the backup, or is explicit dismissal enough?
- How should long decryptability checks show progress without exposing record names?
- Should staged backup memory be wiped immediately after gate failure, or kept for clear/dismiss/retry?
- How should commit failure copy distinguish setup-only failure from setup/import failure without leaking details?
