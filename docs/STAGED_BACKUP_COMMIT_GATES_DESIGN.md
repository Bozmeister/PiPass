# Staged Backup Commit Gates Design

## 1. Purpose

This document defines the runtime gates required before staged backup records can be committed during first-time setup.

This is design-only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, or package scripts.

Prompt 070 implementation note: the pure setup/import commit orchestrator now accepts the staged backup commit gate decision as an injected dependency and requires that gate to allow `commit-staged-backup` before shared vault building, commit-plan building, or executor calls for staged records. Runtime setup and recovery confirmation are still not wired to staged backup record commit.

## 2. Current Bridge State

Current first-time setup backup behavior is intentionally temporary:

- `SeedSetupScreen` checks a selected backup with the strict parser
- staged backup data is held in app-root memory only
- the UI says records are staged in memory and will not be added in this setup step
- setup-only durable writes happen after recovery confirmation
- no backup entries, secure notes, indexes, or shared vault blob are committed
- the source-boundary guard blocks old immediate import calls from returning to `SeedSetupScreen`

This bridge should remain until the runtime gates below are implemented and tested.

Prompt 069 implementation note: `decideStagedBackupCommitGate()` now combines already-supplied compatibility, verifier, sentinel, decryptability, and warning results into a safe pure commit decision. It does not derive keys, decrypt records, write storage, or wire runtime commit.

## 3. Eligible Backup Formats

First runtime commit implementation should accept only:

- `schema: "pipass-backup"`
- `version: 1`
- `format: "encrypted-local-records"`

Encrypted-local-records should be eligible only for same-install and same-key-path restore under the current architecture.

Not eligible for the first record-commit implementation:

- portable encrypted backups
- different-device encrypted-local-record backups
- plaintext backups
- legacy unversioned backups
- unsupported schema, version, or format
- backups that require rekey or vault-root-key import

Different-device encrypted import should stay blocked until an explicit rekey flow or vault-root-key model exists.

## 4. Compatibility Context During Setup

During first-time setup, there are two local contexts to consider:

1. Existing local compatibility context before setup commit:
   - staged helper can read whether local `pipass_master_salt` exists
   - staged helper can read local KDF metadata if present
   - staged helper can read whether `deviceUUID` is present
   - staged helper can identify the device binding policy, such as `deviceUUID:v1`

2. Prepared setup context after Argon2id setup preparation:
   - pending setup salt
   - pending setup KDF metadata
   - pending security profile
   - pending master key material or shares in memory
   - pending recovery key state

For same-install encrypted-local-record import, the staged backup must match the key path that will decrypt the records. A new first-time setup normally creates a new salt/key path, so same-install encrypted backup commit is expected to be narrow: it is viable only when the prepared setup context intentionally matches the backup's declared compatibility metadata and decryptability checks succeed.

The runtime code must not infer compatibility from password entry alone. It must call `classifyBackupCompatibility()` with a supplied local compatibility context and then prove decryptability before commit.

## 5. Runtime Gate Order

Required gate order for a staged backup:

1. File selection reads backup text.
2. `parsePipassBackup()` / `stagePipassBackup()` validates and stages in memory.
3. App stores only a safe summary and staged result in memory.
4. On setup submission, prepare Argon2id setup data in memory.
5. Build the local compatibility context from available setup/local metadata.
6. Call `classifyBackupCompatibility()` before any sentinel, decryptability, plan, or executor step.
7. If compatibility is `incompatible`, block import.
8. If compatibility is `unknown`, block import by default.
9. If compatibility is `compatible`, continue to verifier handling.
10. Parse verifier metadata with `getBackupVerifierFromMetadata()` / `parseBackupVerifier()` if present.
11. If a valid verifier is present, run `verifyBackupSentinel()`.
12. If sentinel verification fails, block import.
13. Run `verifyStagedBackupDecryptability()` for every staged entry and secure note.
14. If any entry or note fails decryptability, block import.
15. Build final staged entry/note records, indexes, and shared vault blob in memory.
16. Show or continue recovery confirmation only when setup and import gates are ready.
17. After recovery confirmation, call setup/import commit orchestration.
18. Commit through the plan/executor path.
19. Write `pipass_vault_initialized` last.
20. Publish active shares only after full commit success.

No backup record storage write may happen before these gates pass.

## 6. Verifier And Decryptability Policy

A valid encrypted sentinel verifier is preferred but should not be required for the first commit implementation because existing staged backups may not contain verifier metadata yet.

Policy:

- if a verifier is present, it must be valid and must pass sentinel verification
- if a verifier is present but invalid, block import
- if a verifier is absent, continue only when compatibility metadata passes and full staged decryptability passes
- full staged decryptability is mandatory for every committed encrypted-local-record backup
- checking only a sentinel is not enough
- checking only the first entry is not enough
- secure notes must be checked with entries

Justification: the sentinel proves the candidate key path can decrypt a synthetic record, but full staged decryptability catches per-record corruption, entry/note key-path differences, and legacy inconsistencies.

## 7. Honeytoken And Warning Policy

Compatibility and decryptability warnings must be carried forward in a safe form.

Honeytoken `encryptedAux` warning policy:

- if staged entries include detectable `encryptedAux`, return a safe warning
- core entry decryptability must pass before aux is considered
- aux decrypt/reissue should not be silently assumed
- a honeytoken warning should not automatically block first implementation if core record decryptability passes
- user-facing copy should warn that decoy trigger metadata may need review after import

Warnings that should block import:

- incompatible format
- incompatible KDF metadata
- incompatible salt/device binding
- invalid verifier
- sentinel verification failure
- any entry decryptability failure
- any secure note decryptability failure

Warnings that may allow import after safe acknowledgement:

- honeytoken aux present and requiring post-import review
- verifier absent on otherwise compatible backup with full decryptability pass

Do not display raw aux metadata, record ids, server honeytoken ids, ciphertext, or decrypted aux contents.

## 8. Recovery Confirmation Integration

Recovery confirmation should remain the durable commit trigger.

Recommended flow:

1. User selects backup and sees staged-only summary.
2. User enters password and profile.
3. App prepares setup data in memory.
4. App runs compatibility/verifier/decryptability gates in memory.
5. If gates pass, recovery key modal is shown or remains actionable.
6. If gates fail before modal display, show safe import failure and require clearing/dismissing staged backup before setup-only commit.
7. On recovery confirmation, recheck that the staged backup is still the verified backup.
8. Execute setup/import commit through `prepareAndExecuteSetupImportCommit()`.
9. If commit succeeds, clear staged memory and publish active shares.
10. If commit fails, do not publish shares and rely on rollback/startup repair.

If gates run after the user has already confirmed recovery and then fail, the app must fail closed:

- write no backup records
- do not publish active shares
- do not mark initialized unless setup-only retry is explicitly selected by the user
- show safe copy explaining that backup records could not be verified
- keep or clear staged memory according to the chosen retry UX, but do not persist it

Preferred UX is to run gates before recovery confirmation so the user knows whether setup will be setup-only or setup-plus-import before confirming.

## 9. Failure Handling

Parse/stage failure:

- no storage writes
- safe unsupported backup message
- setup can continue after the failed staged backup is cleared

Unknown compatibility:

- block import
- allow setup-only commit after the user clears or dismisses the staged backup
- do not silently proceed as import

Incompatible compatibility:

- block import
- do not block setup forever
- allow setup-only commit after the staged backup is cleared or dismissed

Verifier failure:

- block import
- write nothing
- do not fall back to runtime import

Decryptability failure:

- block import
- write nothing
- report counts/failure state only, not contents

Commit failure after all gates pass:

- rollback through the executor
- do not publish active shares
- do not mark initialized unless the full setup/import commit succeeds
- if rollback fails, startup repair must surface scoped cleanup

## 10. UI And Message Requirements

User-facing states needed before record commit wiring:

- backup checked/staged
- unsupported backup
- compatibility unknown
- compatibility incompatible
- verifier missing
- verifier invalid
- verifier failed
- decryptability failed
- honeytoken review warning
- ready to include backup after recovery confirmation
- setup-only continuation after removing staged backup
- commit failed with no vault initialized

Safe copy examples:

- "This backup can be checked, but PiPass cannot import it safely yet."
- "This encrypted backup does not match this local vault setup. No records were added."
- "PiPass could not verify every record in this backup. No records were added."
- "Some decoy trigger metadata may need review after import."
- "Clear this staged backup to create a new empty vault."

Do not show:

- record titles
- usernames
- note labels
- record ids unless needed for developer-only diagnostics
- salts
- hashes
- KDF metadata JSON
- `deviceUUID`
- ciphertext
- plaintext
- stack traces
- key material

## 11. Test Plan

Before wiring record commit, add tests for:

- only schema `pipass-backup`, version `1`, format `encrypted-local-records` can reach runtime gates
- unsupported schema/version/format blocks import without writes
- same-install compatibility context is passed to `classifyBackupCompatibility()`
- compatibility classification runs before sentinel and decryptability
- `unknown` compatibility blocks import by default
- `incompatible` compatibility blocks import
- setup-only commit remains possible only after staged backup is cleared or dismissed
- valid verifier is parsed and verified when present
- invalid verifier blocks import
- sentinel failure blocks import before decryptability
- missing verifier can proceed only with compatible metadata and full decryptability pass
- every staged entry is checked
- every staged secure note is checked
- one entry failure aborts the whole import
- one secure note failure aborts the whole import
- honeytoken `encryptedAux` produces safe warning
- honeytoken warning does not expose aux contents
- no backup record writes occur before all gates pass
- recovery confirmation cancellation writes no backup records
- setup/import commit writes entries, notes, indexes, shared blob, and initialized marker in planned order
- `pipass_vault_initialized` is last
- active shares publish only after full commit success
- commit failure rolls back setup/import keys
- rollback failure routes to startup repair
- bridge copy is removed or replaced when real import commit is enabled
- no UI, result, or log output contains passwords, keys, key shares, recovery keys, salts, hashes, metadata JSON, `deviceUUID`, ciphertext, plaintext, or real backup contents

Existing parser, classifier, verifier, decryptability, commit-plan, executor, startup repair, KDF, storage, and server tests should continue to pass.

## 12. Implementation Prompt Sequence

Recommended sequence after this design:

1. Add pure gate-decision helper that maps staged backup plus prepared setup context to import-ready, setup-only-required, or blocked.
2. Add tests for unknown/incompatible/verifier/decryptability gate ordering.
3. Wire gate-decision helper into first-time setup after setup preparation but before recovery confirmation.
4. Keep setup-only commit available only after staged backup is cleared or dismissed.
5. Wire `prepareAndExecuteSetupImportCommit()` with staged backup only when gates pass.
6. Add recovery confirmation recheck for stale staged backup state.
7. Update success/failure UI copy for setup-plus-import.
8. Update manual verification docs for real record commit.
9. Retire or replace the temporary bridge policy.

Do not combine this with plaintext import, cross-device restore, vault-root-key migration, password rotation, profile changes, server auth changes, session-token changes, or encryption algorithm changes.

## 13. Bridge Policy Removal Criteria

Remove or retire `docs/STAGED_BACKUP_BRIDGE_POLICY.md` when:

- staged backup records can be committed only after all runtime gates pass
- setup-only path requires clearing/dismissing an uncommitted staged backup
- user-facing copy accurately distinguishes setup-only success from setup-plus-import success
- staged memory clears after successful setup-plus-import commit
- staged memory clears after setup-only commit when no backup is attached
- the source-boundary guard still prevents immediate-write import calls from returning
- manual verification covers real imported records and absence of partial writes

Until then, bridge copy must continue to say records are not added to the vault in the current setup step.

## 14. Open Decisions

- Should setup-only continuation require clearing the staged backup or allow an explicit "continue without importing" dismissal?
- Should a missing verifier require an additional user acknowledgement even when full decryptability passes?
- Should honeytoken aux warnings block import until the user acknowledges decoy review?
- Should gate failures before recovery confirmation keep the recovery key modal closed?
- Should gate failures after recovery confirmation offer setup-only retry, or force the user back to setup?
- What exact same-install compatibility context is available before setup metadata is committed?
- Should first implementation support only backups whose metadata exactly matches the prepared setup context?
- Should large backup decryptability checks show progress without exposing record names?
- Should vault-root-key migration happen before any cross-device encrypted import work?
