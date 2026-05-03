# Staged Backup Bridge Policy

## 1. Purpose

This document defines the temporary staged-backup bridge policy before staged backup record commit is enabled.

This is design-only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Current Temporary Staged-Backup State

Current behavior after Prompts 059, 060, 062, 063, 064, and 065:

- a user can select a backup on the first-time setup screen
- `SeedSetupScreen` validates the file with the strict backup parser
- no imported entries, secure notes, indexes, or shared vault blob are written
- a safe in-screen summary shows counts and generic warnings only
- staged backup data is held in React memory through app-root state
- first-time setup can still complete
- recovery confirmation commits setup-only state
- staged backup records are not committed
- UI copy says import commit will be enabled in a future step

This bridge exists only to remove the old immediate-write import risk before the final staged import commit flow is ready.

## 3. User Trust Risk

The main risk is user misunderstanding. If PiPass says or implies that a backup was restored, a user may believe their old entries and secure notes are safely available in the new vault even though record commit is not enabled yet.

The temporary bridge must therefore avoid these claims:

- "backup restored"
- "entries imported"
- "secure notes imported"
- "restore complete"
- "your backup will be available after setup"

The bridge may say:

- the backup was validated
- counts were staged in memory
- no records have been imported yet
- import commit will be enabled in a future step

The product should favor a slightly awkward but honest message over smoother copy that over-promises. This is one of those places where boring is brave.

## 4. Recommended Temporary Behavior

First-time setup may complete while a backup is staged, but only under this temporary condition:

- visible copy clearly says the backup was validated or staged, not imported
- visible copy clearly says import commit is not enabled yet
- setup completion writes setup-only state
- staged backup records are not written
- staged backup memory is cleared after setup success

Setup should not be blocked solely because a backup is staged under the current copy. Blocking setup until the user clears the backup would be stricter, but it would also make the temporary bridge feel broken when the UI already says import commit is future work.

If future copy becomes less explicit, the safer fallback is to block setup until the user clears the staged backup.

## 5. UI Copy Requirements

Temporary bridge copy must be explicit and safe:

- use "validated" or "staged in memory"
- say "not imported yet" or "import commit will be enabled in a future step"
- show entry and secure note counts only
- show generic compatibility warnings only
- provide a clear way to remove the staged backup

Temporary bridge copy must not include:

- record titles
- usernames
- note labels
- record ids
- ciphertext
- salts
- hashes
- full KDF metadata JSON
- `deviceUUID`
- stack traces
- raw parse errors
- real backup contents

Suggested acceptable copy:

"Backup validated: X entries, Y secure notes. Import commit will be enabled in a future step."

"X entries and Y secure notes were staged in memory only. Import commit will be enabled in a future step."

## 6. State Clearing Rules

Staged backup state is memory-only and must not be persisted.

Clear staged backup memory when:

- the user presses the clear staged backup action
- selected backup parsing fails
- the user leaves the first-time setup path for auth/startup repair/reset flows
- setup succeeds
- setup/reset/auth flow explicitly abandons first-time setup
- the app process closes or reloads

Do not clear durable storage because of staged backup memory alone. In particular, bridge cleanup must not delete:

- `pipass.auth.*`
- `pipass.installId`
- `deviceUUID`
- setup metadata
- initialized marker
- existing initialized vault data

Once staged backup commit is enabled, these memory-clearing rules should be revisited so that successful setup-plus-import clears staged memory only after the commit succeeds.

## 7. Manual Verification Checklist

Use fake, non-secret backup fixtures only.

- [ ] Fresh first-time setup shows the backup select action.
- [ ] Selecting a valid fake backup shows "validated" or "staged" copy, not "restored" or "imported".
- [ ] The staged summary says import commit is not enabled yet.
- [ ] The staged summary shows counts only.
- [ ] The staged summary does not expose record contents, salts, hashes, metadata JSON, `deviceUUID`, ciphertext, or record ids.
- [ ] Creating a vault with a staged backup still reaches recovery confirmation.
- [ ] Recovery confirmation commits setup-only state.
- [ ] After setup success, no backup entries or secure notes are present in the new vault.
- [ ] Backup selection alone does not write `pipass_vault_<entryId>`.
- [ ] Backup selection alone does not write `pipass_vault_index`.
- [ ] Backup selection alone does not write `pipass_notes_index`.
- [ ] Backup selection alone does not write `pipass_note_<noteId>`.
- [ ] Backup selection alone does not write or regenerate `pipass_shared_vault`.
- [ ] Clearing a staged backup removes the summary.
- [ ] Returning to auth or a reset path clears staged memory without deleting account, install, or device identity state.
- [ ] Invalid backup selection clears staged memory and shows only a safe error.
- [ ] Startup repair still handles old partial import data from earlier builds or manual test setup.

For selector-based checks, use the test IDs documented in `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION.md`.

## 8. Future Removal Criteria

Remove this temporary bridge policy when staged backup record commit is enabled behind recovery confirmation.

The replacement behavior should require:

1. selected backup is parsed and staged in memory
2. compatibility is classified
3. verifier/sentinel checks run where available
4. staged decryptability checks run before storage writes
5. setup and import are committed through the atomic commit path
6. `pipass_vault_initialized` remains the last durable setup/import marker
7. setup success copy can accurately say whether records were imported
8. staged memory clears only after success, explicit removal, or abandoned setup

The future prompt that enables staged backup record commit should update or retire this document. Until then, this policy remains the guardrail for the temporary UX.

## 9. Open Decisions

- Should setup be blocked until the staged backup is cleared if users continue to interpret "validated" as "will be imported"?
- Should the UI add stronger copy such as "This backup will not be imported in this version" during the bridge period?
- Should the setup button show a secondary reminder when a backup is staged?
- Should manual verification require checking app-root staged memory clearance through every auth/reset path before staged import commit is enabled?
- Should bridge behavior vary between web and native if the file picker makes staged state feel more like a completed restore?
- Which prompt should explicitly remove this bridge policy once record commit is wired?
