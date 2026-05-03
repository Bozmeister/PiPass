# Startup Repair Manual Verification

## 1. Purpose

This checklist verifies the startup repair surface added in Prompt 055 before expanding staged backup import or commit wiring.

This is documentation only. It does not change runtime code, tests, UI, storage behavior, setup/import flow, crypto, server code, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Privacy Rules

Do not paste any of these into logs, screenshots, issue trackers, chat, or test notes:

- passwords
- master keys or key shares
- recovery keys
- salts
- hashes
- `deviceUUID`
- install id
- auth/session values
- `pipass_kdf_metadata` JSON
- encrypted vault blobs
- entry or secure note JSON
- backup file contents

Use placeholder values only, such as `manual-test-salt`, `manual-test-hash`, `entry-a`, `note-a`, and `encrypted-placeholder`.

## 3. Creating Manual Test States

Use browser dev tools on web, or a temporary local dev harness in native/Expo, to set and clear local keys. Do not commit temporary harness code.

Suggested placeholder states:

Clean fresh install:

- remove `pipass_vault_initialized`
- remove setup/import keys listed below

Healthy initialized vault:

- `pipass_vault_initialized = "1"`
- `pipass_master_salt = "manual-test-salt"`
- `pipass_master_hash = "manual-test-hash"`
- `pipass_security_profile = "100000"`
- `pipass_kdf_metadata = "<valid non-secret test metadata JSON>"`
- `pipass_recovery_key_hash = "manual-test-recovery-hash"`

Partial setup:

- remove `pipass_vault_initialized`
- set one or more setup metadata keys, for example `pipass_master_salt = "manual-test-salt"`

Partial import:

- remove `pipass_vault_initialized`
- set `pipass_vault_index = ["entry-a"]`
- set `pipass_vault_entry-a = "encrypted-placeholder"`
- optionally set `pipass_notes_index = ["note-a"]`
- optionally set `pipass_note_note-a = "encrypted-note-placeholder"`

Inconsistent initialized:

- set `pipass_vault_initialized = "1"`
- omit one or more critical setup metadata keys

Safe-error:

- use a temporary injected storage driver or dev harness that throws while reading a startup snapshot key
- do not simulate this by corrupting real native secure storage internals

Scoped setup/import repair keys include setup metadata, vault indexes, entry records, note indexes, note records, shared vault blob, cached master key marker, and initialized marker. Scoped repair must not include `pipass.auth.*`, `pipass.installId`, or `deviceUUID`.

## 4. Startup Routing Checklist

- [ ] Clean fresh install routes to `SeedSetupScreen`.
- [ ] Existing initialized vault routes to `UnlockScreen`.
- [ ] Partial setup metadata without `pipass_vault_initialized = "1"` shows the repair prompt.
- [ ] Partial imported entries without `pipass_vault_initialized = "1"` shows the repair prompt.
- [ ] Partial imported secure notes without `pipass_vault_initialized = "1"` shows the repair prompt.
- [ ] "Not now" returns to the auth gate.
- [ ] Confirming "Clear incomplete setup" clears only scoped setup/import keys.
- [ ] Confirming repair does not clear `pipass.auth.*`.
- [ ] Confirming repair does not clear `pipass.installId`.
- [ ] Confirming repair does not clear `deviceUUID`.
- [ ] After successful repair, startup rechecks state and routes to setup again.
- [ ] Manual repair state shows the manual repair message and does not auto-delete.
- [ ] Safe-error state shows the safe error message and does not auto-delete.
- [ ] UI copy contains no hashes, salts, encrypted blobs, metadata JSON, `deviceUUID`, or record contents.

## 5. Web Checklist

- [ ] In a browser dev build, authenticate through the normal app access gate.
- [ ] Use dev tools storage inspection to create each placeholder state.
- [ ] Refresh the page after creating each state.
- [ ] Verify routing and repair prompts match the startup routing checklist.
- [ ] Confirm repair deletes only expected local storage keys.
- [ ] Confirm auth credentials and install identity keys remain present when they existed before repair.
- [ ] Confirm normal first-time setup still reaches the recovery key modal.
- [ ] Confirm normal unlock still accepts a valid password for an initialized vault.
- [ ] Confirm logout still affects auth/session state only.
- [ ] Confirm nuclear reset still performs full local destruction through its existing confirmation path.

## 6. Native / Expo Dev Build Checklist

Run this section only when a native or Expo dev build is available.

- [ ] Use a temporary dev-only harness or storage inspector to create placeholder states.
- [ ] Confirm repair detection runs after the app access gate.
- [ ] Confirm partial setup/import states show the repair prompt.
- [ ] Confirm "Not now" returns to the auth gate.
- [ ] Confirm repair clears scoped setup/import keys.
- [ ] Confirm repair does not clear account credentials, install id, or `deviceUUID`.
- [ ] Confirm cached native master key clearing is limited to the scoped `pipass_master_key` repair target.
- [ ] Confirm normal unlock still works for a healthy initialized vault.
- [ ] Confirm first-time setup still uses the existing recovery confirmation flow.

## 7. Regression Checklist

Normal unlock:

- [ ] Healthy initialized vault shows unlock.
- [ ] Correct password unlocks.
- [ ] Wrong password does not unlock.
- [ ] KDF metadata behavior remains unchanged from Prompt 055 baseline.

First-time setup:

- [ ] Clean uninitialized state shows setup.
- [ ] Setup still derives with explicit Argon2id.
- [ ] Recovery key modal still appears before initialized marker is set.
- [ ] Cancelling or interrupting recovery confirmation can still be detected as partial setup on next startup.

Backup import:

- [ ] Existing backup import UI behavior is unchanged.
- [ ] Startup repair prompt appears for old partial imported entries/notes when initialized marker is absent.
- [ ] No staged import commit flow is invoked by this prompt.

Reset/logout boundaries:

- [ ] Logout does not trigger setup/import repair.
- [ ] `clearVault()` semantics are unchanged.
- [ ] Nuclear reset still uses `destroyAllData()`.
- [ ] Scoped repair is visibly narrower than nuclear reset.

## 8. Automated Coverage Already Present

## 8. Startup Repair Testability Hooks

Prompt 057 adds stable React Native `testID` selectors for future UI automation. Tests should target these IDs instead of visible copy where possible.

Repair prompt:

- container: `startup-repair-prompt`
- title: `startup-repair-title`
- message: `startup-repair-message`
- confirm button: `startup-repair-confirm`
- cancel button: `startup-repair-cancel`

Manual repair blocking state:

- container: `startup-repair-manual`
- title: `startup-repair-manual-title`
- message: `startup-repair-manual-message`

Safe-error blocking state:

- container: `startup-repair-safe-error`
- title: `startup-repair-safe-error-title`
- message: `startup-repair-safe-error-message`

Future UI tests should verify:

- `startup-repair-prompt` appears for partial setup/import states.
- `startup-repair-confirm` exists but does not run until clicked.
- `startup-repair-cancel` returns to the auth gate.
- `startup-repair-manual` appears for initialized inconsistent states.
- `startup-repair-safe-error` appears for snapshot read failures.
- No repair surface text contains hashes, salts, encrypted blobs, metadata JSON, `deviceUUID`, or record contents.

Accessibility labels are intentionally generic and safe:

- `Startup repair prompt`
- `Manual startup repair required`
- `Startup repair check failed`
- button labels match the visible button text

## 9. Automated Coverage Already Present

Existing tests cover:

- `classifySetupImportLocalState()` classification
- `buildSetupImportRepairPlan()` key-only repair plans
- `executeSetupImportRepairPlan()` scoped deletion and refusals
- `readSetupImportStateSnapshot()` injected snapshot reads
- `decideStartupRepairState()` route mapping
- repair confirmation refusing manual repair and safe-error states
- repair confirmation executing only for `repair-prompt`
- no stored values in helper decisions/results
- existing setup, unlock, KDF, backup, repair, reset, and server checks

Prompt 055 baseline: `npm test` passed `211/211`.

Prompt 057 does not add a UI test framework or app-root rendered component tests. It only adds stable hooks for later automation.

## 10. Remaining Testability Gaps

- No app-root UI automation currently verifies the rendered repair screens.
- No end-to-end browser test currently clicks "Not now" or "Clear incomplete setup".
- No native UI automation currently verifies SecureStore-backed repair behavior.
- Safe-error routing currently depends on injected read failure tests rather than a live platform failure.
- Manual repair copy is not snapshot-tested.
- The current snapshot reader cannot enumerate dangling record keys that are not referenced by indexes unless a future scoped key-listing abstraction is added.

## 11. Recommended Manual Result Format

For each manual run, record only:

- platform: `web`, `ios`, `android`, or `expo-dev`
- app build or commit id
- placeholder state name
- observed route
- whether repair was confirmed
- whether scoped keys were removed
- whether auth/install/device identity keys remained
- pass/fail
- non-secret notes

Do not include raw storage values.
