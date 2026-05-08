# Staged Backup Import Manual Verification Record

This record starts manual verification tracking for the Prompt 079 recovery-gated staged backup import work.

Use `docs/STAGED_BACKUP_IMPORT_LOCAL_TEST_PLAN.md#4-first-manual-run-order` for the recommended first manual run order.

Use `docs/STAGED_BACKUP_IMPORT_FIRST_MANUAL_RUN.md` to execute and record the first two safest manual flows without claiming broader manual verification.

This record is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, package files, or TypeScript config.

Manual UI/device verification has not been executed in this record. Prompt 087 records the current automated baseline only. Do not treat this feature as manually release-verified until manual checks are run and recorded.

## 1. Status

- Verification date: 2026-05-08
- Tester: TODO
- Branch or commit: `docs/prompt-087-record-automated-verification-baseline` / `2aeb696`
- Platform: TODO
- Build type: TODO
- Test data source: TODO
- Overall result: In progress

## 2. Automated Baseline Captured

- `npm run lint`: passed with 0 errors and 2 existing documented React hook warnings.
- `npm run typecheck`: passed.
- `npm test`: passed 311/311.

These are automated checks only. They do not replace manual local UI/device verification from `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION.md`. Release readiness is not claimed until manual verification is executed and recorded.

## 3. Baseline Setup With No Backup

Preconditions:

- Clean uninitialized local state.
- No backup selected.

Steps performed:

- Not yet manually executed.

Expected result:

- First-time setup reaches recovery key confirmation.
- Durable setup state is written only after recovery confirmation.
- Vault initializes normally.
- No staged backup import wording appears.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 4. Backup Selection Remains Staged-Only

Preconditions:

- Clean uninitialized local state.
- Fake supported backup fixture is available.
- Safe storage inspection method is available.

Steps performed:

- Not yet manually executed.

Expected result:

- Backup selection shows checked, staged, selected, preflight, or ready-for-commit wording only.
- Before recovery confirmation, no entry records, secure note records, vault index, notes index, shared vault blob, cached master key, or initialized marker are written.
- UI shows counts only and does not expose backup contents or metadata.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 5. Unsupported Or Ineligible Backup

Preconditions:

- Clean uninitialized local state for each fixture.
- Fake unsupported or ineligible fixtures are available.

Fixtures exercised:

- [ ] Unsupported schema.
- [ ] Unsupported version.
- [ ] Unsupported format.
- [ ] Cross-device or non-same-install shape.
- [ ] Device UUID mismatch or missing required same-device binding.
- [ ] Decryptability failure.
- [ ] Invalid verifier.
- [ ] Verifier present with failed sentinel verification.
- [ ] Honeytoken, decoy, or `encryptedAux` warning.

Steps performed:

- Not yet manually executed.

Expected result:

- Staged commit path is not reached.
- No staged records, notes, indexes, or shared vault blob are written.
- No active shares are published.
- No imported, restored, or added success wording appears.
- Clear/dismiss is required when policy requires it before setup-only continuation.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 6. Eligible Same-Install Backup

Preconditions:

- Clean uninitialized local state.
- Fake eligible same-install backup fixture is available.
- Fixture uses schema `pipass-backup`, version `1`, format `encrypted-local-records`.
- Fixture is same-install / same-key-path compatible.
- Decryptability passes.
- Verifier is either missing under the current allowed policy or present and sentinel verification passes.

Steps performed:

- Not yet manually executed.

Expected result:

- Backup reaches the eligible ready state.
- Before recovery confirmation, records are not durable.
- Any ready wording still makes recovery confirmation required.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 7. Successful Staged Import Commit

Preconditions:

- Eligible same-install backup is staged.
- Recovery confirmation is ready.
- Safe storage inspection method is available.

Steps performed:

- Not yet manually executed.

Expected result:

- Entry records are written.
- Vault index is written.
- Secure note records are written.
- Notes index is written.
- Shared vault blob is written only after gates pass.
- Setup metadata is written.
- Cached master key policy matches existing setup behavior.
- `pipass_vault_initialized` is the final durable marker.
- Active shares are published only after full commit success.
- Staged backup memory is cleared after success.
- Imported/restored/added wording appears only after durable success.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 8. Commit Failure And Rollback Assumptions

Preconditions:

- Eligible same-install backup is staged.
- Injected storage/write failure or equivalent safe dev harness is available.

Steps performed:

- Not yet manually executed.

Expected result:

- App shows safe generic failure wording only.
- Executor rollback assumptions are preserved.
- Active shares are not published.
- Import success is not claimed.
- No partial initialized vault is presented as usable.
- Staged backup state is cleared after failure.
- Tester restarts setup or verifies startup repair before continuing.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 9. App Restart And Startup Repair

Preconditions:

- Completed setup-only success state is available.
- Completed staged import success state is available.
- Failed or interrupted setup/import state is available through a safe harness.

Steps performed:

- Not yet manually executed.

Expected result:

- Restart after setup-only success routes to normal unlock.
- Restart after successful staged import routes to normal unlock with fake imported records available.
- Restart after failed or interrupted setup/import routes partial state safely through startup repair.
- Manual-repair cases do not delete initialized vault data automatically.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 10. UI Wording Checks

Preconditions:

- UI states are available for no backup, staged backup, eligible backup, blocked backup, commit success, and commit failure.

Steps performed:

- Not yet manually executed.

Expected result:

- Before durable commit, UI does not say imported, restored, or added.
- Before durable commit, UI may say checked, staged, selected, or ready to import only when gates allow and recovery confirmation is still required.
- After durable success, committed/imported wording may be used.
- UI does not expose record contents, identifiers, ciphertext, salts, hashes, keys, recovery keys, or metadata JSON.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 11. Regression Checks

Preconditions:

- App can be exercised through setup, unlock, backup picker, and reset surfaces.

Steps performed:

- Not yet manually executed.

Expected result:

- Nuclear reset behavior is unchanged.
- Unlock behavior is unchanged.
- KDF/profile/auth behavior is unchanged.
- Backup picker does not directly write records.
- Existing setup test IDs remain intact.
- Server routes, package files, and TypeScript config are unchanged.

Actual result:

- Not yet manually verified.

Status: Not run

Notes:

- Manual execution required.

## 12. Automated Checks

Preconditions:

- Dependencies are installed.
- Test environment is configured with safe non-production values.

Steps performed:

- [x] `npm run lint`
- [x] `npm run typecheck`
- [x] `npm test`

Expected result:

- `npm run lint` passes with 0 errors and only the existing documented warnings.
- `npm run typecheck` passes.
- `npm test` passes.

Actual result:

- Automated baseline captured: lint passed with 0 errors and 2 existing documented warnings; typecheck passed; tests passed 311/311.
- Manual UI/device checks are still pending.

Status: Pass

Notes:

- Automated checks passed.
- This automated baseline does not replace manual local UI/device verification.
- Release readiness is not claimed until manual verification is executed and recorded.

## 13. Manual Evidence Still Needed

- Safe screenshots or notes for no-backup setup.
- Safe screenshots or notes for staged-only backup selection.
- Safe notes for ineligible backup handling.
- Safe notes for eligible same-install import success.
- Safe notes for commit failure handling.
- Restart/startup repair notes.

Do not paste secrets, recovery keys, master keys, plaintext backup contents, ciphertext blobs, backup file contents, raw storage values, full metadata JSON, or real record contents into this record.

## 14. Evidence To Capture

Capture:

- Safe screenshots of UI states only.
- Terminal output for `npm run lint`, `npm run typecheck`, and `npm test`.
- Commit hash or branch name.
- Fixture labels and pass/fail status.
- Safe generic error wording.

Do not capture or paste:

- plaintext secrets
- passwords
- recovery keys
- master keys or key shares
- ciphertext blobs
- backup contents
- real record contents
- salts or hashes from real vaults
- full metadata JSON
- `deviceUUID`
- raw storage values
- secret-bearing logs

## 15. Known Out Of Scope

Do not mark these as failed because they are not implemented by Prompt 079:

- portable restore
- plaintext import
- cross-device import
- password rotation
- profile changes
- vault-root-key migration
- server honeytoken reissue

## 16. Failure Handling Notes

- Do not continue testing from a partially failed setup/import state unless startup repair has been verified.
- Do not reuse failed staged backup state unless the documented flow explicitly allows it.
- Record safe error wording only.
- Do not preserve or paste secret-bearing logs.
- If a failure leaves uncertainty about durable state, restart the app and verify startup repair before running the next case.

## 17. Do Not Claim Release Readiness Yet

Until manual UI/device checks are executed and recorded, this feature should be treated as implemented and automated-test passing, but not manually release-verified.
