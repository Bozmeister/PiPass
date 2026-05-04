# Staged Backup Bridge Preflight Verification

## 1. Purpose

This checklist verifies the staged-backup bridge preflight/status layer before staged backup records are wired into first-time setup commit.

This is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Privacy Rules

Use fake, non-secret backup fixtures only.

Do not paste any of these into logs, screenshots, issue trackers, chat, or test notes:

- real backup files
- passwords
- master keys or key shares
- recovery keys
- salts
- hashes
- `pipass_kdf_metadata` JSON
- encrypted blobs
- ciphertext
- record contents
- record ids from a real vault
- `deviceUUID`
- install id
- auth or session values

Use placeholders such as `entry-a`, `note-a`, `encrypted-password-placeholder`, `manual-test-salt`, and `manual-test-hash`.

## 3. Preflight Checklist

- [ ] Fresh setup with no backup selected shows the normal first-time setup flow.
- [ ] Fresh setup with no backup selected does not show a staged-backup bridge summary.
- [ ] Selecting a valid fake PiPass backup shows the checked-only bridge status.
- [ ] The checked-only UI clearly says backup records will not be added to this vault in this setup step.
- [ ] The checked-only UI avoids "restored", "imported", "loaded", or any wording that implies records were committed.
- [ ] The staged summary shows only entry and secure note counts plus generic warnings.
- [ ] The staged summary does not show record titles, usernames, note labels, ciphertext, salts, hashes, metadata JSON, `deviceUUID`, or backup contents.
- [ ] A staged backup whose gates would pass still shows checked-only/not-imported-yet copy.
- [ ] A staged backup whose gates would pass still does not import records.
- [ ] A staged backup whose gates are blocked still allows setup-only continuation only while the UI clearly says no records will be imported.
- [ ] If a future configuration blocks setup for gate-blocked backups, the UI requires clearing the selected backup before continuing.
- [ ] Clear selected backup removes the bridge/preflight summary.
- [ ] Clear selected backup clears app-root staged backup memory.
- [ ] Setup success clears staged backup memory.
- [ ] Recovery confirmation commits setup-only state.
- [ ] Recovery confirmation does not commit backup entries.
- [ ] Recovery confirmation does not commit secure notes.
- [ ] Recovery confirmation does not commit staged backup indexes.
- [ ] Recovery confirmation does not commit or regenerate a staged backup shared vault blob.
- [ ] After setup with a staged backup, the new vault contains no imported backup entries.
- [ ] After setup with a staged backup, the new vault contains no imported secure notes.
- [ ] Backup selection/preflight alone does not write `pipass_vault_<entryId>`.
- [ ] Backup selection/preflight alone does not write `pipass_vault_index`.
- [ ] Backup selection/preflight alone does not write `pipass_notes_index`.
- [ ] Backup selection/preflight alone does not write `pipass_note_<noteId>`.
- [ ] Backup selection/preflight alone does not write `pipass_shared_vault`.
- [ ] No shared vault blob is generated from staged backup records during preflight.
- [ ] Startup repair behavior remains unchanged for clean uninitialized, initialized, partial setup, partial import, manual repair, and safe-error states.
- [ ] Existing setup without backup still reaches recovery confirmation and creates a setup-only vault.
- [ ] Existing unlock behavior for an initialized vault remains unchanged.

## 4. Web Manual Checks

- [ ] Start from a clean uninitialized web state.
- [ ] Authenticate through the normal app access gate.
- [ ] Confirm the first-time setup screen appears.
- [ ] Select a valid fake `.json` or `.vault` backup.
- [ ] Confirm the browser alert and in-screen summary use checked-only/not-imported-yet language.
- [ ] Inspect browser storage after selection and confirm no imported entry, note, note index, vault index, or shared vault keys were created.
- [ ] Complete setup and recovery confirmation.
- [ ] Confirm setup metadata and `pipass_vault_initialized` are written only by setup confirmation.
- [ ] Confirm no staged backup record keys were written.
- [ ] Refresh the app and confirm normal unlock works.

## 5. Native / Expo Manual Checks

Run this section only when a native or Expo dev build is available.

- [ ] Start from a clean uninitialized native state.
- [ ] Authenticate through the normal app access gate.
- [ ] Confirm the first-time setup screen appears.
- [ ] Select a valid fake backup through the document picker.
- [ ] Confirm the native alert and in-screen summary use checked-only/not-imported-yet language.
- [ ] Use a temporary dev-only storage inspector or harness to verify no imported entry, note, index, or shared vault keys were created by selection/preflight.
- [ ] Complete setup and recovery confirmation.
- [ ] Confirm setup-only commit succeeds.
- [ ] Confirm no staged backup records were committed.
- [ ] Restart the dev build and confirm normal unlock works.

## 6. UI Selectors

Future UI automation should target these stable hooks from Prompt 065 instead of visible copy:

- backup select button: `setup-backup-select`
- backup loading indicator: `setup-backup-loading`
- staged summary container: `setup-backup-summary`
- staged entry count text: `setup-backup-entry-count`
- staged secure note count text: `setup-backup-note-count`
- staged warning text: `setup-backup-warning`
- staged error text: `setup-backup-error`
- clear staged backup button: `setup-backup-clear`

Selector-based tests should assert that the bridge status appears, copy remains safe, clear removes the summary, and storage remains unchanged. Avoid snapshots that include backup contents or raw storage values.

## 7. Automated Coverage Present

Existing automated tests cover:

- strict backup parser/stager schema validation
- parser/stager controlled failures
- parser/stager no-storage-write behavior
- source-boundary guard proving `SeedSetupScreen` does not call old immediate write or commit helpers
- staged backup commit gate decisions
- staged backup bridge status helper behavior
- bridge status secret-output safety
- bridge status no-storage-write behavior
- setup/import orchestrator gate ordering
- setup/import orchestrator blocked-gate behavior
- setup/import commit plan and executor behavior
- recovery-gated setup-only commit preparation and failure handling
- startup repair classification, decision, and scoped repair helpers
- existing setup, unlock, KDF, backup, repair, reset, and server checks

Prompt 071 baseline: `npm test` passed `252/252`.

## 8. Remaining Testability Gaps

- No app-root rendered test currently asserts the bridge status prop reaches `SeedSetupScreen`.
- No file picker UI automation currently selects a backup through the web file input.
- No native UI automation currently verifies document picker behavior.
- No browser end-to-end test currently inspects local storage after backup selection/preflight.
- No native automated test currently verifies SecureStore remains untouched by staged backup preflight.
- No rendered component test currently checks bridge status copy in the setup screen.
- No automated test currently verifies staged backup memory clearing across every possible navigation path.
- No staged backup record commit UI automation exists yet because record commit remains intentionally disabled.

## 9. Recommended Manual Result Format

Record only:

- platform: `web`, `ios`, `android`, or `expo-dev`
- app build or commit id
- backup fixture type: `none`, `valid`, `gate-passable`, `gate-blocked`, `invalid-json`, or `unsupported`
- observed bridge status
- whether setup was allowed
- whether staged backup was cleared
- whether setup completed
- whether imported record keys were absent
- pass/fail
- non-secret notes

Do not include raw backup contents, raw storage values, screenshots of secrets, full metadata JSON, or encrypted blobs.
