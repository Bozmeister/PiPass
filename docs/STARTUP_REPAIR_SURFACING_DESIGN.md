# Startup Repair Surfacing Design

## 1. Purpose

This document designs how future app startup should detect, classify, and surface unfinished first-time setup/import repair states before the runtime startup flow is changed.

This is design and testability guidance only. It does not change runtime startup code, UI, storage reads or writes, setup flow, backup import flow, reset buttons, crypto flow, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

## 2. Current Startup Behaviour

Current app-root startup in `app/(tabs)/index.tsx` does this after mount:

1. Calls `isVaultInitialized()`.
2. Stores the result in `vaultExists`.
3. If initialized, reads `pipass_security_profile` and `pipass_master_salt`.
4. Uses `vaultExists` to choose setup or unlock after `AuthScreen` completes.

Startup currently does not inspect unfinished setup/import state before choosing setup versus unlock. That means old partial data can be hidden behind the normal first-time setup path when `pipass_vault_initialized` is absent or false.

## 3. Future Detection Timing

Future repair detection should run after basic app integrity/auth gating is ready to show local UI, but before `isVaultInitialized()` decides setup versus unlock.

Recommended order:

1. App mounts and integrity guard starts as it does today.
2. `AuthScreen` completes local app access authentication.
3. Startup reads a setup/import local-state snapshot.
4. Startup calls `classifySetupImportLocalState()` and `buildSetupImportRepairPlan()`.
5. If the plan action is `none`, startup continues to the existing initialized/setup branch.
6. If the plan requires repair or manual handling, startup shows a repair surface instead of setup/unlock.

Running this after `AuthScreen` avoids exposing local state before the app access gate. Running it before the setup/unlock decision prevents partial data from being mistaken for a clean fresh install.

## 4. Keys To Snapshot

Startup should read only key presence and raw string values needed by the pure classifier. It must not log or display values.

Required direct keys:

- `pipass_vault_initialized`
- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_kdf_metadata`
- `pipass_recovery_key_hash`
- `pipass_vault_index`
- `pipass_notes_index`
- `pipass_shared_vault`
- `pipass_master_key`, or a native-cache presence marker if direct read is inappropriate

Record keys:

- every `pipass_vault_<entryId>` referenced by `pipass_vault_index`
- every `pipass_note_<noteId>` referenced by `pipass_notes_index`
- optionally, known dangling record keys if a platform-specific key listing helper exists later

Because most key-value stores do not provide safe key enumeration, the first implementation can detect indexed records and malformed indexes without enumerating every possible dangling record. A future platform abstraction may add scoped key listing for `pipass_vault_` and `pipass_note_` prefixes, but it must not list or return account/session secrets.

The snapshot wrapper should return `Record<string, string | null | undefined>` and pass it to the pure helpers. It should not call `clearVault()`, `destroyAllData()`, credential helpers, setup helpers, or crypto helpers.

## 5. Classification-To-UI Mapping

Recommended mapping:

| Classification | Startup behaviour | Repair action |
| --- | --- | --- |
| `clean-uninitialized` | Continue to normal first-time setup. | None |
| `initialized` | Continue to normal unlock. | None |
| `partial-setup` | Show interrupted setup repair screen. | User-confirmed scoped repair |
| `partial-import` | Show interrupted setup/import repair screen. | User-confirmed scoped repair |
| `unknown-inconsistent` with initialized false | Show interrupted setup/import repair screen with more cautious wording. | User-confirmed scoped repair |
| `inconsistent-initialized` | Do not show setup or normal unlock. Show manual repair/recovery message. | Manual repair required |

The repair surface should be a blocking local screen. It should not show the imported record count, metadata JSON, salts, hashes, key ids, ciphertext, `deviceUUID`, or stack traces.

## 6. Repair Confirmation Policy

Startup should not silently delete partial setup/import state by default.

Recommended policy:

- For `partial-setup`, `partial-import`, and uninitialized `unknown-inconsistent`, ask for explicit confirmation before executing repair.
- Explain that the app found an unfinished local setup/import and that clearing it lets the user start setup again.
- Make clear that account credentials, install identity, and device identity are not part of the scoped repair.
- Keep a separate nuclear reset path for full local destruction.

Auto-repair can be revisited later only after product review. The safer first implementation is explicit user confirmation.

## 7. Repair Execution Wrapper

Startup should call `executeSetupImportRepairPlan()` only through a small app-root wrapper.

The wrapper should:

- build the storage snapshot
- call `buildSetupImportRepairPlan()`
- render the appropriate repair UI state
- on user confirmation, call `executeSetupImportRepairPlan()` with an injected storage driver
- after successful repair, rebuild the snapshot and reclassify
- continue to normal setup only if the new classification is `clean-uninitialized`

The wrapper should not call broad reset helpers. In particular, it must not call:

- `clearVault()`
- `destroyAllData()`
- `clearCredentials()`
- `clearInstallId()`
- `clearDeviceUUID()`

The scoped repair executor owns only keys listed in its repair plan and refuses account/device identity keys.

## 8. Failure Handling

If repair execution succeeds:

- re-read the snapshot
- confirm the classification is `clean-uninitialized`
- then show normal setup

If repair execution partially fails:

- keep the user on the repair screen
- show a safe message
- allow retry
- do not proceed to setup or unlock

If the state is `inconsistent-initialized`:

- do not delete anything automatically
- do not run `executeSetupImportRepairPlan()`
- show manual repair or recovery guidance
- keep normal unlock disabled until a future repair/recovery path is implemented

If snapshot reading fails:

- fail closed to a local repair/error state
- do not assume clean setup
- do not mark initialized
- do not clear data automatically

Recommended messages:

- Partial setup/import: "PiPass found an unfinished setup or restore. Clear the unfinished local setup data before creating a vault."
- Confirmation detail: "This clears only unfinished local setup and restore files. It will not clear your account, install identity, or device identity."
- Repair success: "Unfinished setup data was cleared. You can create your vault again."
- Repair failure: "PiPass could not clear every unfinished setup item. Try again or use secure reset."
- Inconsistent initialized: "PiPass found inconsistent local vault state. Manual repair or recovery is required before unlocking."

## 9. Logging And Privacy Rules

Startup repair detection may log only coarse, non-secret classification metadata in development diagnostics.

Allowed:

- classification name
- repair action
- count of keys planned for repair
- safe reason codes such as `malformed-vault-index` or `dangling-vault-entry`

Forbidden:

- passwords
- master keys or key shares
- recovery keys
- salts
- hashes
- `deviceUUID`
- install id
- auth/session values
- KDF metadata JSON
- encrypted blobs
- entry or note JSON
- stack traces containing storage values

Production logging should be minimal or disabled unless a future privacy review approves safe telemetry.

## 10. Interaction With Existing Reset And Logout Boundaries

Scoped setup/import repair is narrower than existing reset helpers.

- `destroyAllData()` remains the full local destruction boundary and still clears account credentials, install id, and `deviceUUID`.
- `clearVault()` remains its existing vault-clearing helper and should not be reused for unfinished setup/import repair because it does not own every setup/import key and intentionally preserves some metadata.
- logout should remain auth/session-only and should not trigger setup/import repair.
- install id and `deviceUUID` must be preserved by setup/import repair.
- auth credentials must be preserved by setup/import repair.

The startup repair surface may offer a separate secure reset route, but the default repair button should execute only the scoped repair plan.

## 11. Test Plan

Before wiring startup, add tests for:

- startup snapshot reads the required direct keys without writing storage
- startup classifies before calling `isVaultInitialized()` branch logic
- clean uninitialized state routes to normal setup
- healthy initialized state routes to normal unlock
- partial setup routes to repair screen
- partial import routes to repair screen
- uninitialized unknown/inconsistent state routes to repair screen
- inconsistent initialized state routes to manual repair screen
- repair confirmation calls the wrapper and executor only after user action
- repair success re-snapshots state before showing setup
- repair failure keeps the user on repair screen
- repair wrapper never calls `clearVault()` or `destroyAllData()`
- repair wrapper never deletes `pipass.auth.*`, `pipass.installId`, or `deviceUUID`
- snapshot/read failures fail closed and do not route to setup/unlock
- UI copy does not include stored values, key names that reveal sensitive material, ciphertext, salts, hashes, or metadata JSON
- existing setup, unlock, backup, commit, repair, reset, and server tests still pass

Use injected reader/deleter dependencies rather than broad native module mocking. Keep app-root tests focused on decision states, not visual styling.

## 12. Implementation Prompt Sequence

Recommended sequence:

1. Add a storage snapshot reader with injected `getItem()` dependencies and tests.
2. Add an app-root startup decision helper that consumes classification and repair plans.
3. Add tests proving detection runs before setup/unlock branching.
4. Add a minimal repair screen component with safe copy.
5. Add wrapper tests proving repair executes only after explicit user action.
6. Wire the wrapper to `executeSetupImportRepairPlan()`.
7. Re-snapshot after successful repair and route to setup only when clean.
8. Add failure-state UI tests.
9. Only after startup repair is stable, wire staged backup import into setup.

Do not combine this with password rotation, profile changes, vault-root-key migration, server auth changes, session-token changes, or encryption algorithm changes.

## 13. Open Decisions

- Should repair detection run before or after app access authentication on platforms where partial setup data is non-sensitive but state existence may still be private?
- Should the first implementation support scoped prefix key enumeration for dangling records, or only indexed records?
- Should uninitialized unknown/inconsistent state use the same confirmation copy as partial setup/import, or a stronger warning?
- Should repair success route immediately to setup, or require the user to press "Continue"?
- Should repair failure offer secure reset directly, or keep secure reset behind the existing reset flow?
- Should production diagnostics record classification counts locally for support, or avoid repair telemetry entirely?
