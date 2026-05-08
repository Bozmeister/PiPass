# Staged Backup Import First Manual Run

## 1. Scope

This is the first manual run sheet for Prompt 079 staged backup import verification.

This sheet covers only:

- baseline no-backup setup
- staged-only backup selection

This sheet does not cover eligible import success, ineligible backups, commit failure, restart repair, or release readiness.

Prompt 079 remains limited to same-install `pipass-backup` version `1` backups with format `encrypted-local-records`. This sheet is documentation only and does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, package files, or TypeScript config.

## 2. Status

- Date:
- Tester:
- Branch or commit:
- Platform:
- Build type:
- Overall result: Not started / In progress / Passed / Failed / Blocked

## 3. Safety Reminders

- Use fake test data only.
- Do not record passwords, recovery keys, master keys, key shares, salts, hashes, KDF metadata JSON, device UUIDs, install ids, auth/session values, ciphertext blobs, raw backup contents, or plaintext record contents.
- Do not paste screenshots containing secrets.
- Record safe labels and observations only.
- Do not mark release-ready from this sheet.
- Use `docs/STAGED_BACKUP_IMPORT_STORAGE_INSPECTION_GUIDE.md` for key-name-only storage inspection.
- Use `docs/STAGED_BACKUP_IMPORT_FIRST_RUN_EVIDENCE_CHECKLIST.md` before capturing evidence.

## 4. Flow A: Baseline Setup With No Backup

Preconditions:

- Clean uninitialized local state.
- No backup selected.
- Safe way to restart the app after setup.
- Safe notes location available for non-secret observations.

Steps:

- [ ] Start the app from the clean uninitialized state.
- [ ] Complete first-time setup without selecting a backup.
- [ ] Stop at recovery key confirmation and confirm durable setup is not complete before confirmation.
- [ ] Confirm recovery key confirmation.
- [ ] Confirm the vault initializes normally.
- [ ] Restart the app.
- [ ] Confirm normal unlock after restart.

Expected result:

- First-time setup works without selecting a backup.
- Recovery key confirmation remains the durable setup boundary.
- No staged backup import wording appears.
- No imported, restored, or added wording appears.
- Vault initializes normally after recovery confirmation.
- Normal unlock after restart is expected.

Actual result:

- Not yet manually verified.

Status: Not run / Pass / Fail / Blocked

Safe evidence to capture:

- Date, platform, and build type.
- Branch or commit.
- Safe summary that no backup was selected.
- Safe summary that recovery confirmation appeared before durable setup completion.
- Safe summary of unlock-after-restart result.
- Follow `docs/STAGED_BACKUP_IMPORT_FIRST_RUN_EVIDENCE_CHECKLIST.md`.

Notes:

- 

## 5. Flow B: Backup Selection Remains Staged-Only

Preconditions:

- Clean uninitialized local state.
- Fake supported backup fixture is available.
- Fixture is identified only by a safe label from `docs/STAGED_BACKUP_IMPORT_FIXTURE_MATRIX.md`.
- Safe storage inspection method or dev harness is available and does not print raw values.
- Tester can stop before recovery confirmation.

Steps:

- [ ] Start the app from the clean uninitialized state.
- [ ] Select the fake backup fixture.
- [ ] Confirm the UI shows checked, staged, selected, preflight, or equivalent non-durable wording only.
- [ ] Confirm the UI does not show record contents, secure note contents, raw metadata, ciphertext, salts, hashes, keys, or identifiers.
- [ ] Stop before recovery confirmation.
- [ ] Inspect storage with the safe method or harness.
- [ ] Confirm no staged entry records are written.
- [ ] Confirm no staged secure note records are written.
- [ ] Confirm no vault index or notes index is written from the staged backup.
- [ ] Confirm no staged shared vault blob is written.
- [ ] Confirm no cached master key is written.
- [ ] Confirm `pipass_vault_initialized` is not written.

Expected result:

- Selecting/checking a fake backup shows checked, staged, selected, or preflight wording only.
- No record contents are shown.
- No staged records, notes, indexes, shared vault blob, cached master key, or initialized marker are written before recovery confirmation.
- Recovery confirmation remains required before any durable setup/import commit.
- No imported, restored, or added success wording appears before durable success.

Actual result:

- Not yet manually verified.

Status: Not run / Pass / Fail / Blocked

Safe evidence to capture:

- Fixture label only.
- Safe UI wording summary.
- Safe storage key-presence summary without values.
- Whether recovery confirmation remained required.
- Follow `docs/STAGED_BACKUP_IMPORT_FIRST_RUN_EVIDENCE_CHECKLIST.md`.

Notes:

- 

## 6. Stop Immediately If

- `pipass_vault_initialized` appears before recovery confirmation.
- Staged records or notes are written before recovery confirmation.
- Active shares appear to publish before full commit success.
- Imported, restored, or added wording appears before durable success.
- Any secret appears in logs, screenshots, errors, or docs.

If any stop condition occurs, stop the run and record only a safe failure summary. Do not continue from a partial or uncertain local state until startup repair or manual repair behavior has been verified.

## 7. Where To Record Final Outcome

Record final outcomes in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`
- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RESULTS.md`

Record safe observations only. Do not paste secrets, raw storage values, backup contents, ciphertext, recovery keys, master keys, salts, hashes, full metadata JSON, or screenshots containing sensitive values.
