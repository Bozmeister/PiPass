# Staged Backup Bridge Policy

## 1. Purpose

This document defines the staged-backup bridge policy for the setup-screen checked-only boundary and for backups that are not eligible for the first recovery-confirmed record commit.

This is design-only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Current Staged-Backup State

Current behavior after Prompt 079:

- a user can select a backup on the first-time setup screen
- `SeedSetupScreen` validates the file with the strict backup parser
- no imported entries, secure notes, indexes, or shared vault blob are written by selection or setup-screen parsing
- a safe in-screen summary shows counts and generic warnings only
- staged backup data is held in React memory through app-root state
- first-time setup without an eligible staged backup can still complete as setup-only when the UI/state clearly says no backup records have been written
- recovery confirmation commits setup-only state when no backup is staged or import is not eligible/enabled
- recovery confirmation may commit staged records only for eligible same-install schema `pipass-backup`, version `1`, format `encrypted-local-records` backups
- UI copy before commit success still avoids restored/imported claims

Prompt 067 implementation note: the first-time setup backup surface now uses "Backup File Check" / "Backup checked only" language and explicitly says staged records are held in memory only.

Prompt 071 implementation note: app root computes a safe runtime staged-backup preflight/bridge status from the in-memory staged backup. The setup screen still says no backup records have been written before recovery confirmation.

Prompt 079 implementation note: the checked-only bridge is narrowed, not fully retired. It remains the source-boundary guard before recovery confirmation and for non-eligible backups. Eligible same-install backups now pass through the runtime adapter, eligibility helper, commit gate, setup/import plan, and executor only after recovery confirmation.

## 3. User Trust Risk

The main risk is user misunderstanding. If PiPass says or implies that a backup was restored before durable commit succeeds, a user may believe their old entries and secure notes are safely available in the new vault when they are not.

The temporary bridge must therefore avoid these claims:

- "backup restored"
- "entries imported"
- "secure notes imported"
- "restore complete"
- "your backup will be available after setup"

The bridge may say:

- the backup was checked or validated
- counts were staged in memory
- no backup records have been written
- eligible backups can commit only after recovery confirmation

The product should favor a slightly awkward but honest message over smoother copy that over-promises. This is one of those places where boring is brave.

## 4. Recommended Temporary Behavior

First-time setup may complete while a backup is staged, but only when the current UI/state makes the import outcome explicit:

- visible copy clearly says the backup was validated or staged, not imported
- visible copy clearly says no backup records have been written before recovery confirmation
- setup completion writes setup-only state when no eligible import is attached
- eligible same-install backups write staged records only after recovery-confirmed commit success
- staged backup memory is cleared after setup/import success or recovery-confirmed commit failure

Setup should not silently imply import will happen while continuing setup-only. If a staged backup is ineligible or warning-blocked, setup-only continuation should be allowed only when the UI/state clearly says no backup records will be imported, or after the user clears/dismisses the staged backup according to the active policy.

If future copy becomes less explicit, the safer fallback is to block setup until the user clears the staged backup.

## 5. UI Copy Requirements

Temporary bridge copy must be explicit and safe:

- use "validated" or "staged in memory"
- say no backup records have been written
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

"Backup checked: X entries, Y secure notes. Backup records are staged in memory only. No backup records have been written."

"X entries and Y secure notes were found. Backup records are staged in memory only. No backup records have been written."

## 6. State Clearing Rules

Staged backup state is memory-only and must not be persisted.

Clear staged backup memory when:

- the user presses the clear staged backup action
- selected backup parsing fails
- the user leaves the first-time setup path for auth/startup repair/reset flows
- setup/import succeeds
- recovery-confirmed setup/import commit fails
- setup/reset/auth flow explicitly abandons first-time setup
- the app process closes or reloads

Do not clear durable storage because of staged backup memory alone. In particular, bridge cleanup must not delete:

- `pipass.auth.*`
- `pipass.installId`
- `deviceUUID`
- setup metadata
- initialized marker
- existing initialized vault data

Successful setup-plus-import clears staged memory only after the durable commit succeeds. Failure clears staged memory so the next setup attempt cannot silently reuse a backup whose visible setup summary was remounted.

## 7. Manual Verification Checklist

Use fake, non-secret backup fixtures only.

- [ ] Fresh first-time setup shows the backup select action.
- [ ] Selecting a valid fake backup shows "checked" or "staged in memory" copy, not "restored" or "imported".
- [ ] The staged summary says no backup records have been written.
- [ ] The staged summary shows counts only.
- [ ] The staged summary does not expose record contents, salts, hashes, metadata JSON, `deviceUUID`, ciphertext, or record ids.
- [ ] Creating a vault with a staged backup still reaches recovery confirmation.
- [ ] Recovery confirmation commits setup-only state when no backup is selected or the backup is not eligible.
- [ ] Eligible same-install backup records appear only after recovery-confirmed durable commit success.
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

## 8. Retirement Criteria

Remove this bridge policy only when the setup-screen copy and runtime status are fully replaced by explicit import/dismiss controls for every supported backup class.

The replacement behavior still must require:

1. selected backup is parsed and staged in memory
2. compatibility is classified
3. verifier/sentinel checks run where available
4. staged decryptability checks run before storage writes
5. setup and import are committed through the atomic commit path
6. `pipass_vault_initialized` remains the last durable setup/import marker
7. setup success copy can accurately say whether records were imported
8. staged memory clears only after success, explicit removal, or abandoned setup

Until then, this policy remains the guardrail for the pre-confirmation UX and for backups outside the first supported same-install encrypted-local-record case.

## 9. Open Decisions

- Should setup be blocked until the staged backup is cleared if users continue to interpret "validated" as "will be imported"?
- Should the UI add stronger copy such as "This backup will not be imported in this version" during the bridge period?
- Should the setup button show a secondary reminder when a backup is staged?
- Should manual verification require checking app-root staged memory clearance through every auth/reset path before staged import commit is enabled?
- Should bridge behavior vary between web and native if the file picker makes staged state feel more like a completed restore?
- Which prompt should explicitly remove this bridge policy once every supported backup class has explicit import/dismiss controls?
