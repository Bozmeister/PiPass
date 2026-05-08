# Staged Backup Import First-Run Evidence Checklist

## 1. Scope

This is the evidence capture checklist for the first staged backup manual run.

It covers only:

- Flow A: baseline setup with no backup
- Flow B: backup selection remains staged-only

It does not cover eligible import success, ineligible backups, commit failure, restart repair, or release readiness.

This checklist is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, package files, TypeScript config, or app behavior.

## 2. Never Capture

Do not capture, paste, screenshot, log, or record:

- passwords
- recovery keys
- master keys
- key shares
- salts
- hashes
- KDF metadata JSON
- device UUID values
- install ID values
- auth/session values
- raw backup JSON
- raw storage values
- ciphertext blobs
- plaintext entries
- secure note contents
- screenshots containing any sensitive values
- logs or stack traces containing secret-bearing data

## 3. Safe Evidence

Safe evidence for the first run is limited to:

- date/time
- branch or commit
- platform
- build type
- fixture label
- flow label
- safe UI wording summary
- storage key presence/absence by key name or category only
- initialized marker present/absent
- automated check summaries
- pass/fail/blocked status
- non-secret notes

## 4. Flow A Evidence: Baseline Setup With No Backup

Record safe evidence for:

- branch/commit and platform
- fixture label `no-backup`
- no backup selected
- recovery confirmation appeared before durable setup completion
- no staged backup import wording appeared
- no imported, restored, or added wording appeared before durable success
- initialized marker absent before recovery confirmation
- initialized marker present after recovery confirmation
- normal unlock after restart, if executed
- only safe wording summaries and key presence/absence observations are recorded

Do not record the recovery key, master password, setup metadata values, storage values, screenshots containing secrets, or logs with secret-bearing data.

## 5. Flow B Evidence: Backup Selection Remains Staged-Only

Record safe evidence for:

- fixture label only, not fixture contents
- backup selection/checking produced checked, staged, selected, or preflight wording only
- no record contents shown in UI
- no entry, note, index, shared-vault, cached-key, or initialized-marker durable write before recovery confirmation
- no imported, restored, or added success wording before durable success
- storage inspection recorded key names/categories only
- blocked status if safe key-name-only inspection is not available

Do not record fixture contents, backup metadata, entry IDs, note IDs, raw storage values, ciphertext, plaintext entries, secure note contents, or screenshots containing sensitive values.

## 6. Screenshot Rules

- Screenshots are optional.
- Screenshots must show only safe UI states.
- Crop or redact anything sensitive.
- Do not capture recovery keys, passwords, backup file contents, entry/note contents, storage values, identifiers, or raw logs.
- If unsure, record a text summary instead of a screenshot.

## 7. Terminal Output Rules

It is safe to record summarized results of:

- `npm run lint`
- `npm run typecheck`
- `npm test`

Do not paste full logs if they contain environment values, local paths with sensitive names, stack traces with raw storage values, or any secret-bearing data.

Prefer summaries such as:

- lint passed with 0 errors and 2 known warnings
- typecheck passed
- tests passed 311/311

## 8. Where To Record Evidence

Use this checklist while filling:

- `docs/STAGED_BACKUP_IMPORT_FIRST_MANUAL_RUN.md`
- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`
- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RESULTS.md`

Record safe observations only. Do not paste secrets, raw storage values, backup contents, ciphertext, recovery keys, master keys, salts, hashes, KDF metadata JSON, device or install identifiers, auth/session values, or screenshots containing sensitive values.
