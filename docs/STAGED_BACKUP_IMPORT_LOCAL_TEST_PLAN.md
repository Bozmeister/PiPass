# Staged Backup Import Local Test Plan

## 1. Scope

This is the local/manual test plan for the Prompt 079 staged backup import verification.

Scope is limited to same-install `pipass-backup` version `1` backups with format `encrypted-local-records`. This is not a portable restore test, not a cross-device restore test, and not a plaintext import test.

This plan is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, package files, or TypeScript config.

## 2. Before You Start

- Work from a clean branch or known commit.
- Confirm automated checks pass.
- Use a test account and throwaway test data only.
- Do not use real personal vault secrets.
- Do not paste recovery keys, master passwords, plaintext entries, ciphertext blobs, backup file contents, raw storage values, or screenshots containing secrets into docs, issues, chat, or commit messages.
- Make sure the tester understands nuclear reset and destroy-all-data behavior before testing.
- Use `docs/STAGED_BACKUP_IMPORT_FIXTURE_MATRIX.md` to choose fixture labels and expected safe outcomes.

## 3. Recommended Environment

- Local development build or Expo/dev environment.
- Same device/install for the supported same-install case.
- Throwaway entries and secure notes only.
- Separate unsupported, invalid, incompatible, or warning-bearing backup samples if available.
- A safe storage inspection method or dev harness that reports key presence/order without printing raw values.

## 4. First Manual Run Order

Use this order for the first human verification pass. Record results in `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`.

### 1. Automated baseline

Run:

- `npm run lint`
- `npm run typecheck`
- `npm test`

Record:

- pass/fail status
- known warning count
- test count
- branch or commit

Do not record:

- environment secrets
- raw `.env` values
- secret-bearing logs

### 2. Baseline no-backup setup

Run this before backup import testing to prove normal setup still works.

Record:

- platform and build type
- whether setup reached recovery confirmation
- whether the vault initialized only after recovery confirmation
- unlock/restart pass/fail summary

Do not record:

- recovery keys
- master passwords
- screenshots containing secrets

### 3. Backup selection staged-only check

Use a fake supported backup fixture and stop before recovery confirmation.

Record:

- fixture label only
- safe UI wording summary
- safe storage key-presence summary showing no records, indexes, shared vault blob, cached master key, or initialized marker were written before recovery confirmation

Do not record:

- backup file contents
- ciphertext blobs
- plaintext entries or note contents
- raw storage values

### 4. Ineligible backup handling

Use unsupported, cross-device, incompatible, invalid, decryptability-failing, sentinel-failing, or warning-bearing fixtures where available.
Use fixture labels from `docs/STAGED_BACKUP_IMPORT_FIXTURE_MATRIX.md`.

Record:

- fixture labels only
- blocked/clear/dismiss behavior
- whether no staged records were written
- whether no active shares were published
- whether no imported/restored/added success wording appeared

Do not record:

- raw backup contents
- device identifiers
- verifier metadata
- stack traces containing sensitive values

### 5. Eligible same-install backup success

Run this only with a fake eligible same-install backup.
Use supported success fixture labels from `docs/STAGED_BACKUP_IMPORT_FIXTURE_MATRIX.md`.

Record:

- fixture label only
- whether ready wording still required recovery confirmation
- whether records were durable only after recovery confirmation
- safe summary that entries, notes, indexes, shared vault blob, setup metadata, and initialized marker appeared in the expected commit boundary
- whether active shares published only after full commit success
- restart/unlock pass/fail summary

Do not record:

- recovery keys
- master keys or key shares
- plaintext backup contents
- ciphertext blobs
- raw storage values

### 6. Commit failure / restart repair checks

Run this only after the success path has been verified. This may require injected failure or harness support.

Record:

- injected failure point label
- safe failure wording summary
- whether active shares were not published
- whether import success was not claimed
- startup repair or manual repair route summary

Do not record:

- stack traces containing secrets
- raw failed operation values
- backup contents
- raw storage values

### 7. UI wording and regression sweep

Finish with UI copy and boundary regressions.

Record:

- safe wording summaries confirming no pre-success imported/restored/added wording
- unlock/reset/KDF/profile boundary pass/fail summaries
- test IDs checked, if applicable

Do not record:

- screenshots containing secrets
- passwords
- recovery keys
- record contents

Do not mark release-ready until all required manual checks are executed and recorded.

## 5. Safe Evidence Examples

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

## 6. Stop Conditions

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

## 7. After Test Completion

- Update `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`.
- Re-run `npm run lint`, `npm run typecheck`, and `npm test` if docs changed.
- Commit only docs/results for the manual verification pass.
- Do not mark release-ready unless all manual checks pass and are recorded.
