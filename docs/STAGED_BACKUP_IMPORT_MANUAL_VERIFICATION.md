# Staged Backup Import Manual Verification

## 1. Purpose

This checklist verifies the staged backup import surface before staged backup records are wired into the first-time setup commit flow.

This is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Privacy Rules

Do not paste any of these into logs, screenshots, issue trackers, chat, or test notes:

- passwords
- master keys or key shares
- recovery keys
- salts from real vaults
- hashes from real vaults
- `deviceUUID`
- install id
- auth/session values
- `pipass_kdf_metadata` JSON from a real vault
- encrypted vault blobs
- real entry or secure note JSON
- real backup file contents

Use fake placeholder values only, such as `entry-a`, `note-a`, `encrypted-password-placeholder`, `manual-test-salt`, and `manual-test-hash`.

## 3. Safe Example Backup

Use a fake file like this for manual staging checks. Do not use real exported vault data.

```json
{
  "schema": "pipass-backup",
  "version": 1,
  "format": "encrypted-local-records",
  "createdAt": 1234567890,
  "entries": [
    {
      "id": "entry-a",
      "title": "encrypted-title-placeholder",
      "username": "encrypted-username-placeholder",
      "encryptedPassword": "encrypted-password-placeholder",
      "encryptedTitle": "encrypted-title-ciphertext",
      "encryptedUsername": "encrypted-username-ciphertext",
      "salt": "entry-salt-placeholder",
      "createdAt": 1,
      "updatedAt": 2
    }
  ],
  "secureNotes": [
    {
      "id": "note-a",
      "label": "encrypted-label-placeholder",
      "encryptedLabel": "encrypted-label-ciphertext",
      "encryptedContent": "encrypted-content-ciphertext",
      "salt": "note-salt-placeholder",
      "createdAt": 3,
      "updatedAt": 4
    }
  ],
  "metadata": {
    "app": "PiPass"
  }
}
```

Expected result: PiPass validates the file, shows only counts and safe warnings, and does not write imported records.

## 4. Staged Import Checklist

- [ ] Fresh uninitialized setup screen shows the backup selection option.
- [ ] Selecting a valid versioned PiPass backup shows a safe validated/staged summary.
- [ ] The summary shows entry and secure note counts only.
- [ ] The summary does not show record titles, usernames, note labels, ciphertext, salts, hashes, metadata JSON, or `deviceUUID`.
- [ ] The summary or alert honestly says import commit is not enabled yet.
- [ ] Selecting invalid JSON shows a safe error.
- [ ] Selecting a backup with a missing or unsupported `schema` shows a safe error.
- [ ] Selecting a backup with an unsupported `version` shows a safe error.
- [ ] Selecting a backup with an unsupported `format` shows a safe error.
- [ ] Clearing the selected backup removes the staged summary.
- [ ] Clearing the selected backup notifies app-root staged state where applicable.
- [ ] Creating a vault after selecting a staged backup does not import entries yet.
- [ ] Recovery confirmation still commits setup-only state.
- [ ] After setup, the vault is empty if no entries were manually added later.
- [ ] Backup selection alone does not write `pipass_vault_<entryId>`.
- [ ] Backup selection alone does not write `pipass_vault_index`.
- [ ] Backup selection alone does not write `pipass_notes_index`.
- [ ] Backup selection alone does not write `pipass_note_<noteId>`.
- [ ] Backup selection alone does not write or regenerate `pipass_shared_vault`.
- [ ] Startup repair still detects and handles old partial import state from previous builds or manual test setup.

## 5. Web Checklist

- [ ] Start from a clean uninitialized web state.
- [ ] Authenticate through the normal app access gate.
- [ ] Confirm `SeedSetupScreen` appears.
- [ ] Choose the fake `.json` or `.vault` backup.
- [ ] Confirm the browser alert says the backup was validated and import commit is future work.
- [ ] Confirm the in-screen backup summary shows only fake counts and safe warning copy.
- [ ] Inspect local storage after backup selection and confirm no imported entry, note, note index, vault index, or shared vault keys were created.
- [ ] Clear the staged backup and confirm the summary disappears.
- [ ] Complete first-time setup and recovery confirmation.
- [ ] Confirm setup metadata and `pipass_vault_initialized` exist only after recovery confirmation.
- [ ] Confirm no imported entry or secure note keys were created by the staged backup.
- [ ] Confirm normal unlock works after app refresh.

## 6. Native / Expo Dev Build Checklist

Run this section only when a native or Expo dev build is available.

- [ ] Start from a clean uninitialized native state.
- [ ] Authenticate through the normal app access gate.
- [ ] Confirm `SeedSetupScreen` appears.
- [ ] Use the document picker to choose the fake backup file.
- [ ] Confirm the native alert says the backup was validated and import commit is future work.
- [ ] Confirm the in-screen summary shows only counts and safe warning copy.
- [ ] Use a temporary dev-only storage inspector or harness to verify backup selection did not write imported entry, note, index, or shared vault keys.
- [ ] Clear the staged backup and confirm the summary disappears.
- [ ] Complete first-time setup and recovery confirmation.
- [ ] Confirm setup-only commit succeeds.
- [ ] Confirm no imported backup records were committed.
- [ ] Confirm normal unlock works after restarting the dev build.

## 7. Regression Checklist

Normal setup without backup:

- [ ] Fresh setup without selecting a backup still reaches the recovery key modal.
- [ ] Recovery confirmation creates an initialized setup-only vault.
- [ ] The new vault unlocks normally.

Setup with invalid or cleared backup:

- [ ] Invalid backup selection does not block setup after the error is dismissed.
- [ ] Cleared staged backup does not affect setup.
- [ ] Setup still commits only after recovery confirmation.

Already initialized vault:

- [ ] Existing initialized vault routes to unlock.
- [ ] Correct password unlocks.
- [ ] Backup staging UI is not shown on the unlock path.

Old partial import state:

- [ ] Manually created uninitialized `pipass_vault_index` or `pipass_notes_index` still routes through startup repair.
- [ ] Scoped startup repair remains narrower than nuclear reset.

## 8. Automated Coverage Already Present

Existing automated tests cover:

- strict backup parser/stager schema validation
- staged backup parse errors returning controlled results
- backup parser/stager no-storage-write behavior
- metadata-only backup compatibility classification
- verifier schema validation and sentinel verification helpers
- staged decryptability helper behavior
- setup/import commit plan and executor behavior
- setup-only recovery-gated preparation through `prepareFirstTimeVaultSetup()`
- startup repair classification, decision, and scoped repair helpers
- source-boundary guard proving `SeedSetupScreen` does not import or call old immediate-write helpers or setup/import commit helpers
- existing setup, unlock, KDF, backup, repair, reset, and server checks

Prompt 063 baseline: `npm test` passed `227/227`.

## 9. UI Automation Selectors

Future UI automation should target these stable hooks instead of visible copy:

- backup select button: `setup-backup-select`
- backup loading indicator: `setup-backup-loading`
- staged summary container: `setup-backup-summary`
- staged entry count text: `setup-backup-entry-count`
- staged secure note count text: `setup-backup-note-count`
- staged warning text: `setup-backup-warning`
- staged error text: `setup-backup-error`
- clear staged backup button: `setup-backup-clear`

Selector assertions should still avoid reading or snapshotting backup contents. Prefer checks that the selector exists, count text is present, storage remains unchanged, and setup can proceed without importing staged records.

## 10. Remaining Testability Gaps

- No app-root UI automation currently selects a backup through `SeedSetupScreen`.
- No browser end-to-end test currently verifies local storage after backup selection.
- No native UI automation currently verifies document picker staging behavior.
- No rendered component test currently asserts the staged backup summary copy.
- No automated test currently proves app-root staged backup state is cleared through every possible navigation path.
- No staged backup record commit tests exist yet because record commit remains future work.

## 11. Recommended Manual Result Format

For each manual run, record only:

- platform: `web`, `ios`, `android`, or `expo-dev`
- app build or commit id
- backup fixture type: `valid`, `invalid-json`, `unsupported-schema`, `unsupported-version`, or `unsupported-format`
- observed staging result
- whether staged backup was cleared
- whether setup was completed
- whether imported record keys were absent
- pass/fail
- non-secret notes

Do not include raw storage values, real backup contents, screenshots of secrets, or full metadata JSON.
