# Staged Backup Import Transition Design

## 1. Purpose

This document designs the transition from the current "backup checked only" bridge state to real staged backup import commit during first-time setup.

This is design-only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

Prompt 074 implementation note: `determineStagedBackupImportTransition()` now maps supplied staged-backup state and gate decisions into safe transition statuses and copy tokens without parsing, decrypting, writing storage, or wiring runtime record commit.

Prompt 075 implementation note: the runtime staged-backup bridge/preflight status now derives its checked-only copy from `determineStagedBackupImportTransition()` with runtime import commit disabled. Backup records remain staged in memory only and are still not added to the setup commit plan.

## 2. Current Checked-Only Bridge State

Current temporary behavior:

- a backup file can be selected on first-time setup
- `SeedSetupScreen` parses and stages the backup in memory only
- app root owns the staged backup state in memory
- app root computes a safe bridge preflight/status value
- UI says the backup is checked only
- UI says records will not be added to this vault in this setup step
- setup can complete as setup-only
- staged backup records are not committed
- no backup entries, secure notes, indexes, or shared vault blobs are written
- recovery confirmation commits setup-only durable state

This bridge remains correct until PiPass can prove a staged backup is importable and can include those records in the atomic setup/import commit plan.

## 3. User Trust Risk

The transition risk is over-promising. Users must never confuse:

- "backup checked"
- "backup ready to import after recovery confirmation"
- "backup imported"

PiPass should not say "restored" or "imported" until after the durable setup/import commit succeeds. Before commit, the strongest safe phrase is "ready to import after recovery confirmation."

If any import gate has not run or has failed, the UI must stay in checked-only or blocked-import wording.

## 4. Conditions For Ready To Import

The UI may say a staged backup will be imported only when all of these are true:

1. Runtime staged backup record commit is actually enabled.
2. The backup was parsed and staged with the strict backup helpers.
3. Backup schema is `pipass-backup`.
4. Backup version is `1`.
5. Backup format is `encrypted-local-records`.
6. Compatibility classification has run.
7. Compatibility classification is `compatible`.
8. Any present verifier metadata parsed successfully.
9. Any present verifier passed sentinel verification.
10. If a verifier is required by a future policy, it is present and valid.
11. Full staged decryptability verification has checked every entry and secure note.
12. Decryptability verification returned `ok: true`.
13. Honeytoken or other warnings are allowed by the active gate policy.
14. The setup/import orchestrator gate decision allows `commit-staged-backup`.
15. The app has enough prepared setup metadata to build an atomic setup/import commit plan.

Until all conditions are true, UI must not say the backup will be imported.

## 5. UI Wording Policy

Before gates pass:

- "Backup checked only."
- "Backup records are staged in memory only."
- "Records will not be added to this vault in this setup step."
- "Clear this backup to create a new empty vault."

After all gates pass and runtime import commit is enabled:

- "Backup ready to import after recovery confirmation."
- "X entries and Y secure notes will be added when setup is confirmed."
- "No records have been imported yet."

After full setup/import commit succeeds:

- "Backup imported."
- "X entries and Y secure notes were added."

Never show:

- record titles
- usernames
- secure note labels
- ciphertext
- plaintext
- salts
- hashes
- KDF metadata JSON
- `deviceUUID`
- raw verifier metadata
- record ids from real data
- stack traces
- key material

## 6. Explicit Import Confirmation

Recommended first implementation: require explicit user intent for staged backup import before recovery confirmation.

Acceptable UX:

- selecting a valid backup stages it
- gates run after setup preparation
- if gates pass, show "Backup ready to import after recovery confirmation"
- provide a clear "Import this backup during setup" checked state or confirmation step
- recovery confirmation remains the final durable commit action

This prevents a user from accidentally selecting a backup, forgetting it is attached, and creating a vault with imported records they did not intend to commit.

If the product chooses not to add a separate import confirmation, the setup screen must still show an unmistakable ready-to-import state before the recovery modal appears.

## 7. Setup-Only Continuation Policy

Unknown, incompatible, failed, or warning-blocked backups should block import, not permanently block vault creation.

Recommended policy:

- setup-only continuation is allowed only after the user clears or explicitly dismisses the staged backup
- do not silently continue as setup-only while a staged backup remains attached
- if the user dismisses import, show copy that no backup records will be added
- clearing or dismissing the staged backup must clear app-root staged backup memory

This is stricter than the current bridge. The bridge allows setup-only continuation with attached checked-only backup because record commit is not enabled. Once real import commit exists, an attached backup has stronger meaning and should require clear user choice.

## 8. Gate Failure Handling

Unknown compatibility:

- block import
- do not include staged records in the commit plan
- tell the user PiPass cannot prove this backup is compatible
- allow setup-only only after clear/dismiss

Incompatible compatibility:

- block import
- do not include staged records in the commit plan
- tell the user the encrypted backup does not match this local setup
- allow setup-only only after clear/dismiss

Decryptability failure:

- block import
- do not include any staged record in the commit plan
- show safe copy that every record could not be verified
- do not show record ids, ciphertext, or plaintext

Verifier missing:

- default policy: allowed only if verifier is not required and compatibility plus full decryptability pass
- if future policy sets `requireVerifier`, block import
- if missing verifier is allowed, show a safe non-blocking warning only if product wants extra transparency

Invalid verifier:

- block import
- no fallback to record commit unless the user selects a different backup

Sentinel failure:

- block import
- do not run commit
- do not include staged records in the plan

## 9. Honeytoken And Warning Policy

Use the conservative policy currently encoded in `decideStagedBackupCommitGate()`:

- honeytoken or decoy warnings block import by default
- honeytoken warnings may be allowed only if a future explicit product decision enables `allowHoneytokenWarnings`
- warnings must be shown in safe generic form
- raw `encryptedAux`, decoy metadata, server ids, record ids, ciphertext, or decrypted aux content must never be shown

If warnings are blocked:

- do not include staged records in the commit plan
- let the user clear/dismiss the backup and continue setup-only
- preserve enough safe status for manual verification

## 10. Recovery Confirmation And Commit Boundary

Recovery confirmation remains the durable commit boundary.

Recommended setup-plus-import flow:

1. User selects backup.
2. App parses/stages backup in memory.
3. User enters password and security profile.
4. App prepares setup metadata, recovery key, and pending shares in memory.
5. App runs compatibility, verifier, sentinel, decryptability, and warning gates.
6. If gates fail, block import before recovery confirmation.
7. If gates pass and user has confirmed import intent, show recovery confirmation.
8. On recovery confirmation, recheck staged backup identity/status has not changed.
9. Build setup/import commit plan with setup metadata, staged entries, staged notes, indexes, shared vault blob, optional cached-key marker, and initialized marker.
10. Execute the plan through the atomic executor.
11. Write `pipass_vault_initialized` last.
12. Publish active shares only after the full setup/import commit succeeds.
13. Clear staged backup memory only after success, explicit clear, or abandoned setup.

If gates fail after recovery confirmation, fail closed:

- do not write backup records
- do not publish active shares
- do not mark initialized unless the user explicitly chooses a setup-only retry
- show safe failure copy

Preferred implementation runs gates before recovery confirmation to avoid this late-failure path.

## 11. Same-Install Limitation Copy

Same-install limitations should be explained without exposing device or KDF details.

Safe copy examples:

- "This encrypted backup can only be imported on the same local setup that created it."
- "PiPass cannot prove this encrypted backup matches this setup."
- "No records were added. You can clear this backup and create an empty vault."

Avoid:

- `deviceUUID`
- raw salt names or values
- full KDF metadata
- "device binding" internals
- record ids
- hash details

## 12. Removing The Bridge State

Remove the checked-only bridge state only when:

- runtime record commit is enabled behind recovery confirmation
- gate pass/fail states are visible and safe
- passable backup copy says "ready to import after recovery confirmation"
- blocked backup copy tells the user to clear/dismiss before setup-only continuation
- setup-only success copy does not imply backup import
- setup-plus-import success copy says import happened only after commit success
- source-boundary guard still prevents old immediate write helpers from returning
- manual verification covers both setup-only and setup-plus-import paths

`docs/STAGED_BACKUP_BRIDGE_POLICY.md` should be retired or rewritten at that point. `docs/STAGED_BACKUP_BRIDGE_PREFLIGHT_VERIFICATION.md` should be replaced with real staged import commit verification.

## 13. Test Plan

Before runtime wiring, add tests for:

- checked-only copy remains until gates pass
- ready-to-import copy appears only when gate decision allows `commit-staged-backup`
- no "restored" or "imported" copy appears before commit success
- unknown compatibility blocks import
- incompatible compatibility blocks import
- decryptability failure blocks import
- invalid verifier blocks import
- missing verifier follows the configured policy
- honeytoken warnings block import by default
- `allowHoneytokenWarnings` changes only the gate behavior, not raw warning exposure
- blocked staged backup is not included in the commit plan
- setup-only continuation requires clear/dismiss after real import commit is enabled
- cleared/dismissed backup removes app-root staged backup state
- recovery confirmation with import-ready backup builds a plan including entries, notes, indexes, shared vault, setup metadata, cached-key policy, and initialized marker
- initialized marker remains last
- active shares publish only after full setup/import commit success
- commit failure does not publish shares
- rollback failure routes to startup repair
- no UI or result output includes passwords, keys, key shares, recovery keys, salts, hashes, metadata JSON, `deviceUUID`, ciphertext, plaintext, or real backup contents

Existing parser/stager, compatibility, verifier, sentinel, decryptability, gate-decision, orchestrator, commit-plan, executor, setup-only recovery, startup repair, KDF, storage, and server tests must continue to pass.

## 14. Implementation Prompt Sequence

Recommended future sequence:

1. Add a pure transition/status helper that maps bridge status plus gate decision to checked-only, ready-to-import, blocked-import, or setup-only-dismissed.
2. Add tests for UI-safe copy state transitions.
3. Wire compatibility classification into first-time setup preparation using injected dependencies, still no record commit.
4. Wire verifier/sentinel/decryptability pre-recovery gates, still no record commit.
5. Add explicit clear/dismiss/import intent state for staged backup.
6. Include staged backup records in `prepareAndExecuteSetupImportCommit()` only when gates pass and import intent is confirmed.
7. Build shared vault blob once for staged entries during commit orchestration.
8. Update recovery confirmation success/failure copy.
9. Add manual verification for setup-plus-import.
10. Retire the checked-only bridge policy.

Keep these prompts separate from cross-device import, vault-root-key migration, plaintext import, password rotation, profile changes, KDF changes, server auth changes, route changes, schema changes, and vault format changes.

## 15. Open Decisions

- Should ready-to-import require a separate checkbox or confirmation button before recovery confirmation?
- Should setup-only continuation require clearing the staged backup, or is an explicit "continue without importing" dismissal enough?
- Should missing verifier show a warning even when decryptability passes?
- Should missing verifier eventually become blocking after enough backups include sentinels?
- Should honeytoken warnings stay blocked by default or become acknowledgement-based?
- Should gate checks run immediately after setup preparation or only after the user asks to proceed?
- Should large backup decryptability checks show progress?
- Should failed decryptability keep the staged backup attached for retry, or clear it automatically?
- What exact same-install compatibility context should be used before setup metadata is durable?
- When should the bridge documents be archived rather than updated in place?
