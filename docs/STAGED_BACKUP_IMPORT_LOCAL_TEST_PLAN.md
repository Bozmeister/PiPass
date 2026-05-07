# Staged Backup Import Local Test Plan

## 1. Scope

This is the local/manual test plan for the Prompt 079 staged backup import work.

This plan covers only the first supported case:

- schema: `pipass-backup`
- version: `1`
- format: `encrypted-local-records`
- same-install / same-key-path compatible
- recovery confirmation remains the durable commit boundary

This is not a portable restore test. This is not a cross-device restore test. This is not a plaintext import test.

This plan is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, package files, or TypeScript config.

## 2. Before You Start

- Work from a clean branch or known commit.
- Confirm automated checks pass:
  - `npm run lint`
  - `npm run typecheck`
  - `npm test`
- Do not use real personal vault secrets.
- Use throwaway test data only.
- Do not paste recovery keys, master passwords, plaintext entries, ciphertext blobs, backup file contents, or screenshots containing secrets into docs, issues, chat, or commit messages.
- Make sure the tester understands nuclear reset and destroy-all-data behavior before testing.
- Keep `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md` open and update it as each flow is completed.

## 3. Recommended Test Environment

- Local development build or Expo/dev environment.
- Test account only.
- Throwaway entries and secure notes only.
- Same device/install for the supported same-install case.
- Separate incompatible, cross-device, unsupported, invalid, and warning-bearing backup samples if available.
- Do not include backup sample contents in docs.
- Use a safe storage inspection method or dev harness that reports key presence and operation order without printing raw values.

## 4. Flow A: Baseline No-Backup Setup

Preconditions:

- Clean uninitialized local state.
- No backup selected.

Steps:

1. Start the app in the local test environment.
2. Complete first-time setup without selecting a backup file.
3. Stop before recovery confirmation and inspect only safe state indicators.
4. Confirm recovery key confirmation is shown before durable setup completion.
5. Confirm recovery confirmation completes setup.
6. Restart the app and unlock the vault.

Expected result:

- No staged backup import wording appears.
- No initialized marker exists before recovery confirmation.
- Setup metadata and `pipass_vault_initialized` appear only after recovery confirmation.
- The vault initializes and unlocks normally.

Evidence to record safely:

- Date, platform, build type, branch or commit.
- Safe summary that no backup was selected.
- Safe summary that recovery confirmation was the durable boundary.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 3.

## 5. Flow B: Backup Selection Staged-Only Check

Preconditions:

- Clean uninitialized local state.
- Fake supported backup fixture is available.
- Safe storage inspection method is available.

Steps:

1. Start first-time setup.
2. Select the fake backup file.
3. Verify the setup screen uses checked, staged, selected, preflight, or ready-for-commit wording only.
4. Before recovery confirmation, inspect safe storage key presence.
5. Clear the selected backup and confirm the staged summary disappears.

Expected result:

- Backup selection parses and stages in memory only.
- No entry records are written.
- No secure note records are written.
- No vault index is written.
- No notes index is written.
- No staged shared vault blob is written.
- No cached master key is written.
- No initialized marker is written.
- UI shows counts only and does not expose backup contents or metadata.

Evidence to record safely:

- Safe UI wording summary.
- Fixture label only.
- Safe key-presence summary with no raw values.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 4.

## 6. Flow C: Unsupported Or Ineligible Backup Handling

Preconditions:

- Clean uninitialized local state for each run.
- Fake unsupported or ineligible samples are available.

Steps:

1. Test unsupported schema.
2. Test unsupported version.
3. Test unsupported format.
4. Test cross-device or non-same-install shape if a safe fixture exists.
5. Test device UUID mismatch or missing required same-device binding if a safe fixture exists.
6. Test decryptability failure.
7. Test invalid verifier or failed sentinel.
8. Test honeytoken, decoy, or `encryptedAux` warning behavior.
9. For each case, verify setup-only continuation requires clear/dismiss when policy requires it.

Expected result:

- Staged commit path is not reached.
- No staged records, notes, indexes, or shared vault blob are written.
- No active shares are published.
- No imported, restored, or added success wording appears.
- Honeytoken and decoy warnings remain conservative.
- Unsupported, cross-device, and plaintext backups are not accepted as supported restore modes.

Evidence to record safely:

- Fixture label only.
- Safe blocked/clear/dismiss wording summary.
- Safe storage key-presence summary with no raw values.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 5.

## 7. Flow D: Eligible Same-Install Backup Import Success

Preconditions:

- Clean uninitialized local state.
- Fake eligible same-install backup is available.
- Fixture uses schema `pipass-backup`, version `1`, format `encrypted-local-records`.
- Fixture is same-install / same-key-path compatible.
- Decryptability passes.
- Verifier is either missing under the current allowed policy or present and sentinel verification passes.

Steps:

1. Select the eligible fake backup.
2. Complete setup preparation.
3. Confirm ready wording still makes recovery confirmation required.
4. Before recovery confirmation, verify staged records are not durable.
5. Complete recovery confirmation.
6. Verify the setup/import commit succeeds.
7. Restart the app and unlock the vault.
8. Confirm fake imported entries and secure notes are available through normal vault loading.

Expected result:

- Records are committed only after recovery confirmation.
- Entries are written.
- Vault index is written.
- Secure note records are written.
- Notes index is written.
- Shared vault blob is written only after gates pass.
- Setup metadata is written.
- Cached master key behavior matches existing setup behavior.
- `pipass_vault_initialized` remains the final durable marker.
- Active shares publish only after full commit success.
- Staged backup memory clears after success.
- Imported/restored/added wording appears only after durable success.

Evidence to record safely:

- Fixture label only.
- Safe success wording summary.
- Safe key-presence and marker-order summary with no raw values.
- Restart/unlock pass/fail summary.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, sections 6 and 7.

## 8. Flow E: Commit Failure Handling

Preconditions:

- Eligible same-install backup is staged.
- Injected storage/write failure or equivalent safe dev harness is available.

If manual UI simulation is not practical, use a development harness that can fail one planned setup/import write without printing raw values.

Steps:

1. Trigger failure before the initialized marker.
2. Trigger failure at the initialized marker if practical.
3. Observe only safe generic failure wording.
4. Restart the app.
5. Verify startup repair or manual repair handles any partial state safely before continuing.

Expected result:

- Safe error only.
- Executor rollback assumptions are preserved.
- No active shares are published.
- Import success is not claimed.
- No partial initialized vault is presented as usable.
- Staged backup state is cleared after failure.
- Tester restarts setup or verifies startup repair before continuing.

Evidence to record safely:

- Injected failure point label.
- Safe generic error wording summary.
- Startup repair route summary.
- No raw storage values or stack traces.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 8.

## 9. Flow F: Restart And Startup Repair Checks

Preconditions:

- Completed setup-only success state is available.
- Completed staged import success state is available.
- Failed or interrupted setup/import state is available through a safe harness.

Steps:

1. Restart after setup-only success.
2. Restart after successful staged import.
3. Restart after injected commit failure.
4. Restart after manually interrupted setup/import state if practical.
5. Verify repair prompts and manual-repair surfaces with safe state summaries only.

Expected result:

- Setup-only success routes to normal unlock.
- Successful staged import routes to normal unlock with fake imported records available.
- Failed or interrupted setup/import routes partial state safely through startup repair.
- Manual-repair cases do not delete initialized vault data automatically.

Evidence to record safely:

- Restart route summaries.
- Safe startup repair wording summary.
- Pass/fail status.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 9.

## 10. Flow G: UI Wording Checks

Preconditions:

- UI states are available for no backup, staged backup, eligible backup, blocked backup, commit success, and commit failure.

Steps:

1. Review no-backup setup copy.
2. Review staged-only selection copy.
3. Review eligible ready-for-commit copy.
4. Review blocked/ineligible copy.
5. Review commit success copy.
6. Review commit failure copy.

Expected result:

- Before durable commit, UI does not say imported, restored, or added.
- Before durable commit, UI may say checked, staged, selected, or ready to import only when gates allow and recovery confirmation is still required.
- After durable success, committed/imported wording may be used.
- UI does not expose record contents, identifiers, ciphertext, salts, hashes, keys, recovery keys, or metadata JSON.

Evidence to record safely:

- Safe wording summaries.
- Screenshots only if they contain no secrets, keys, record contents, ciphertext, or backup contents.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 10.

## 11. Flow H: Regression Checks

Preconditions:

- App can be exercised through setup, unlock, backup picker, and reset surfaces.

Steps:

1. Verify normal unlock behavior.
2. Verify nuclear reset behavior.
3. Verify KDF/profile/auth behavior remains unchanged.
4. Verify backup picker does not directly write records.
5. Verify existing setup test IDs remain intact if using UI automation or inspector tools.

Expected result:

- Nuclear reset behavior is unchanged.
- Unlock behavior is unchanged.
- KDF/profile/auth behavior is unchanged.
- Backup picker does not directly write records.
- Existing setup test IDs remain intact.

Evidence to record safely:

- Pass/fail summary.
- Test IDs checked, if applicable.
- No raw storage values.

Record result in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`, section 11.

## 12. Safe Evidence Examples

Acceptable:

- test date
- branch or commit
- platform
- build type
- pass/fail status
- safe UI wording summaries
- terminal check summaries
- fixture labels
- storage key presence summaries without values

Not acceptable:

- secrets
- recovery keys
- passwords
- raw encrypted blobs
- plaintext entry details
- backup file contents
- screenshots containing sensitive values
- raw KDF metadata
- `deviceUUID`
- master keys or key shares

## 13. Stop Conditions

Stop testing and record a safe failure summary if any of these occur:

- `pipass_vault_initialized` appears before recovery confirmation.
- Active shares appear to publish before commit success.
- Imported, restored, or added wording appears before durable success.
- Unsupported backups are accepted as supported imports.
- Cross-device backups are accepted as supported imports.
- Plaintext backups are accepted as supported imports.
- Any secret appears in logs, errors, screenshots, docs, or chat.
- Partial failed import state is not handled by startup repair or manual repair paths.

Do not continue testing from a partial failed setup/import state until startup repair or manual repair behavior has been verified.

## 14. After Test Completion

- Update `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`.
- Re-run these checks if docs changed:
  - `npm run lint`
  - `npm run typecheck`
  - `npm test`
- Commit only docs/results for the manual verification pass.
- Do not mark release-ready unless all manual checks pass and are recorded.
