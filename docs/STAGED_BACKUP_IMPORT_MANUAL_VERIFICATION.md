# Staged Backup Import Manual Verification

## 1. Purpose

Use this checklist before merging or release-testing the Prompt 079 recovery-gated staged backup import work.

Record manual run results in `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RESULTS.md`.

Prompt 079 supports only the first same-install case:

- schema: `pipass-backup`
- version: `1`
- format: `encrypted-local-records`
- same-install / same-key-path compatible

This checklist is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

Do not use this checklist to verify portable restore, plaintext import, cross-device import, password rotation, profile changes, vault-root-key migration, server honeytoken reissue, or export changes. Those features are out of scope.

## 2. Privacy Rules

Use fake fixtures only. Do not paste any of these into logs, screenshots, issue trackers, chat, or test notes:

- passwords
- master keys or key shares
- recovery keys
- salts or hashes from real vaults
- `deviceUUID`
- install id
- auth/session values
- KDF metadata JSON from a real vault
- encrypted vault blobs
- plaintext entry or secure note contents
- real backup file contents
- stack traces that include local secrets or raw storage values

Record only pass/fail observations and safe fixture labels such as `same-install-valid`, `unsupported-format`, `device-mismatch`, or `injected-write-failure`.

## 3. Fixture Guidance

Prepare fake fixtures or harness-generated backups for these cases:

- no backup selected
- eligible same-install `pipass-backup` v1 `encrypted-local-records`
- unsupported schema
- unsupported version
- unsupported format
- same-format but cross-device or non-same-install shape
- missing required same-device binding, if the fixture policy requires it
- device UUID mismatch
- decryptability failure
- invalid verifier
- verifier present with sentinel failure
- verifier missing with otherwise compatible and decryptable records
- honeytoken, decoy, or `encryptedAux` warning fixture
- injected storage/write failure during setup/import commit

Fixtures must use fake encrypted placeholders only. Do not use real exported vault data.

## 4. Baseline Setup With No Backup

- [ ] Start from a clean uninitialized local state.
- [ ] Complete first-time setup without selecting a backup.
- [ ] Confirm the recovery key confirmation modal appears before durable setup completes.
- [ ] Before recovery confirmation, confirm no initialized marker exists.
- [ ] Confirm no staged backup import, imported, restored, or added wording appears.
- [ ] Confirm recovery confirmation commits setup-only metadata.
- [ ] Confirm `pipass_vault_initialized` exists only after recovery confirmation.
- [ ] Confirm the vault initializes normally and unlock still works after restart.

Expected result: setup remains setup-only and no backup records are written.

## 5. Backup Selection Remains Staged-Only

- [ ] Start from a clean uninitialized local state.
- [ ] Select a fake supported backup file on `SeedSetupScreen`.
- [ ] Confirm the UI uses checked, staged, selected, preflight, or ready-for-commit wording only.
- [ ] Confirm the UI shows counts only and no record contents or metadata.
- [ ] Before recovery confirmation, inspect local storage with a safe dev harness.
- [ ] Confirm no `pipass_vault_<entryId>` keys are written.
- [ ] Confirm `pipass_vault_index` is not written.
- [ ] Confirm no `pipass_note_<noteId>` keys are written.
- [ ] Confirm `pipass_notes_index` is not written.
- [ ] Confirm `pipass_shared_vault` is not written from the staged backup.
- [ ] Confirm the cached master key is not written.
- [ ] Confirm `pipass_vault_initialized` is not written.

Expected result: backup selection parses and stages in memory only. Recovery confirmation remains the durable boundary.

## 6. Ineligible Backup

Run each ineligible fixture separately:

- [ ] Unsupported schema.
- [ ] Unsupported version.
- [ ] Unsupported format.
- [ ] Cross-device or non-same-install shape.
- [ ] Device UUID mismatch or missing required same-device binding.
- [ ] Decryptability failure.
- [ ] Invalid verifier.
- [ ] Verifier present with failed sentinel verification.
- [ ] Honeytoken, decoy, or `encryptedAux` warning.

For each run, verify:

- [ ] The staged commit path is not reached.
- [ ] No staged entry records are written.
- [ ] No secure note records are written.
- [ ] No vault or notes index is written from the staged backup.
- [ ] No staged shared vault blob is written.
- [ ] No active shares are published.
- [ ] The app does not show imported, restored, or added success wording.
- [ ] The user is required to clear or dismiss the backup when policy requires that before setup-only continuation.
- [ ] If setup-only continuation is allowed, visible UI/state clearly says setup continues without backup records.

Expected result: ineligible backups fail closed or require clear/dismiss safely. Honeytoken and decoy warnings remain conservative unless an explicit future policy changes that.

## 7. Eligible Same-Install Backup

Use a fake backup that satisfies all current Prompt 079 gates:

- [ ] schema is `pipass-backup`
- [ ] version is `1`
- [ ] format is `encrypted-local-records`
- [ ] compatibility is same-install / same-key-path compatible
- [ ] decryptability passes for every entry and secure note
- [ ] verifier missing is allowed by current policy when compatibility and decryptability pass
- [ ] verifier present passes sentinel verification
- [ ] warning policy allows the commit, with honeytoken/decoy warnings blocked by default

Before recovery confirmation:

- [ ] Confirm no staged records, notes, indexes, shared vault blob, cached master key, or initialized marker are written.
- [ ] Confirm copy avoids imported, restored, and added.
- [ ] Confirm any ready wording still makes recovery confirmation required.

Expected result: records are eligible for commit, but are not durable until recovery confirmation succeeds.

## 8. Successful Import Commit

Complete recovery confirmation with an eligible same-install backup.

- [ ] Confirm entry records are written.
- [ ] Confirm `pipass_vault_index` is written.
- [ ] Confirm secure note records are written.
- [ ] Confirm `pipass_notes_index` is written.
- [ ] Confirm `pipass_shared_vault` is written only after gates pass.
- [ ] Confirm setup metadata is written.
- [ ] Confirm cached master key behavior matches the existing setup policy.
- [ ] Confirm `pipass_vault_initialized` is the final durable marker.
- [ ] Confirm active shares are published only after the full setup/import commit succeeds.
- [ ] Confirm staged backup memory is cleared after success.
- [ ] Confirm imported/restored/added wording appears only after durable success.
- [ ] Restart the app and confirm imported fake entries and secure notes are available through normal vault loading.

Expected result: the setup/import executor commits the full plan successfully, then the app enters the initialized vault state.

## 9. Commit Failure

Use an injected storage/write failure or a dev harness that can fail one planned setup/import write.

- [ ] Trigger failure before the initialized marker.
- [ ] Trigger failure at the initialized marker if practical.
- [ ] Confirm the app shows safe generic failure copy only.
- [ ] Confirm failure output does not include record contents, ciphertext, plaintext, salts, hashes, metadata JSON, device identifiers, recovery keys, master keys, raw backup values, or stack traces.
- [ ] Confirm executor rollback assumptions are preserved.
- [ ] Confirm active shares are not published.
- [ ] Confirm import success is not claimed.
- [ ] Confirm no partial initialized vault is presented as usable.
- [ ] Confirm staged backup state is cleared after failure.
- [ ] Confirm the user must restart setup after failure.
- [ ] Restart the app and confirm startup repair handles any partial setup/import state safely.

Expected result: failure is closed, secret-free, and recoverable through retry or startup repair.

## 10. App Restart And Startup Repair

- [ ] Restart after clean setup-only success and confirm normal unlock.
- [ ] Restart after successful staged import and confirm normal unlock plus imported fake records.
- [ ] Restart after injected commit failure and confirm no initialized vault is presented unless the marker and metadata are consistent.
- [ ] Restart after a manually interrupted setup/import state and confirm startup repair routes partial state to the safe repair prompt.
- [ ] Confirm scoped startup repair remains narrower than nuclear reset.
- [ ] Confirm manual-repair cases do not delete initialized vault data automatically.

Expected result: startup repair still routes clean, partial, and inconsistent local states safely.

## 11. UI Wording Checks

Before durable commit, avoid:

- [ ] imported
- [ ] restored
- [ ] added

Allowed before durable commit:

- [ ] checked
- [ ] staged
- [ ] selected
- [ ] ready to import, only when gates allow and recovery confirmation is still clearly required
- [ ] ready for recovery-confirmed commit

After durable success:

- [ ] committed, imported, or added wording may be used.
- [ ] Counts may be shown.
- [ ] Record contents, identifiers, ciphertext, salts, hashes, keys, and metadata JSON must not be shown.

## 12. Regression Checks

- [ ] Nuclear reset behavior is unchanged.
- [ ] Unlock behavior is unchanged.
- [ ] KDF behavior is unchanged.
- [ ] Profile/auth behavior is unchanged.
- [ ] Backup picker still does not directly write records.
- [ ] Existing setup test IDs remain intact:
  - `setup-backup-select`
  - `setup-backup-loading`
  - `setup-backup-summary`
  - `setup-backup-entry-count`
  - `setup-backup-note-count`
  - `setup-backup-warning`
  - `setup-backup-error`
  - `setup-backup-clear`
- [ ] Server routes and schemas are unchanged.
- [ ] Package files and TypeScript config are unchanged.

## 13. Platform Notes

Web:

- [ ] Verify backup selection through the browser file picker.
- [ ] Inspect local storage only with safe fake fixtures.
- [ ] Refresh after each success and failure case.

Native / Expo dev build:

- [ ] Verify backup selection through the document picker.
- [ ] Use a temporary dev-only storage inspector or harness for storage assertions.
- [ ] Restart the dev build after success and failure cases.

## 14. Required Automated Checks

Run these before sign-off:

```sh
npm run lint
npm run typecheck
npm test
```

Expected Prompt 080 baseline:

- `npm run lint` passes with 0 errors and the 2 existing documented React hook warnings.
- `npm run typecheck` passes.
- `npm test` passes.

## 15. Manual Result Format

Record only:

- platform: `web`, `ios`, `android`, or `expo-dev`
- app build or commit id
- fixture label
- observed gate result
- whether recovery confirmation was reached
- whether durable commit succeeded or failed
- whether initialized marker appeared only at the expected point
- whether active shares were published only after success
- whether staged backup memory cleared
- pass/fail
- non-secret notes

Do not include raw storage values, real backup contents, screenshots of secrets, full metadata JSON, recovery keys, master keys, salts, hashes, ciphertext, or plaintext record contents.
