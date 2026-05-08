# Staged Backup Import Storage Inspection Guide

## 1. Scope

This is the safe storage inspection guide for Prompt 079 manual verification.

It covers only storage key presence or absence and safe state labels during the first staged backup manual verification flows. It does not permit recording raw values, backup contents, ciphertext, plaintext, keys, or metadata JSON.

This guide is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, package files, TypeScript config, or app behavior.

## 2. Strict Privacy Warning

- Do not copy, paste, screenshot, or record storage values.
- Do not record passwords, recovery keys, master keys, key shares, salts, hashes, KDF metadata JSON, device UUIDs, install IDs, auth/session values, ciphertext blobs, raw backup contents, or plaintext record contents.
- Record only key names, safe labels, and present/absent observations.
- If a tool displays values automatically, redact or avoid capturing that output.
- If key-name-only inspection is not available, mark storage inspection as blocked.

## 3. Safe Things To Record

- branch or commit
- platform
- fixture label
- flow label
- key present or absent
- initialized marker present or absent
- safe UI wording summary
- pass/fail/block status
- non-secret notes

## 4. Never Record

- raw storage values
- raw backup JSON
- ciphertext strings
- plaintext entries or notes
- recovery key
- master password
- master key or key shares
- salts or hashes
- KDF metadata JSON
- `deviceUUID` or `installId` values
- auth/session values
- stack traces containing secret-bearing data

## 5. Flow A Storage Inspection: Baseline Setup With No Backup

Flow label: `Flow A: Baseline setup with no backup`

Fixture label: `no-backup`

Before recovery confirmation, expected safe observations:

- no staged backup records are written
- no backup-derived vault entry keys are present
- no backup-derived secure note keys are present
- initialized marker is not present before confirmation
- no imported, restored, or added wording is shown

After recovery confirmation, expected safe observations:

- setup metadata exists according to existing setup policy
- initialized marker exists
- setup-only vault state is coherent
- no backup import record claims are made
- no backup-derived entry or secure note keys are recorded as imported

Record only the key names observed and whether each key category is present or absent. Do not record the stored value for any setup metadata key.

## 6. Flow B Storage Inspection: Backup Selection Remains Staged-Only

Flow label: `Flow B: Backup selection remains staged-only`

Suggested fixture label: `same-install-valid-minimal`

After selecting/checking a fake backup but before recovery confirmation, expected safe observations:

- no entry record keys from the staged backup are durable
- no secure note record keys from the staged backup are durable
- vault index is not written from the staged backup
- notes index is not written from the staged backup
- shared vault blob is not written from the staged backup
- cached master key is not written solely by backup selection
- initialized marker is not written
- UI uses checked, staged, selected, or preflight wording only
- no imported, restored, or added wording is shown

Record only the fixture label, safe UI wording summary, and key category present/absent observations. Do not record entry IDs, note IDs, backup contents, storage values, or backup metadata.

## 7. Key Categories To Inspect By Name Only

Inspect these by key name or category only. Never record their values.

| Category | Key name or category | Safe observation |
| --- | --- | --- |
| Initialized marker | `pipass_vault_initialized` | present / absent |
| Setup metadata | `pipass_master_salt` | key present / absent only |
| Setup metadata | `pipass_master_hash` | key present / absent only |
| Setup metadata | `pipass_security_profile` | key present / absent only |
| KDF metadata | `pipass_kdf_metadata` | key present / absent only |
| Recovery verifier metadata | `pipass_recovery_key_hash` | key present / absent only |
| Vault index | `pipass_vault_index` | key present / absent only |
| Vault entry records | `pipass_vault_` prefix/category | category present / absent only |
| Notes index | `pipass_notes_index` | key present / absent only |
| Secure note records | `pipass_note_` prefix/category | category present / absent only |
| Shared vault | `pipass_shared_vault` | key present / absent only |
| Cached master key | `pipass_master_key` | key/category present / absent only |
| Auth credentials | `pipass.auth.*` category | do not record values |
| Install identity | `pipass.installId` category | do not record value |
| Device identity/KDF input | `deviceUUID` category | do not record value |

Notes:

- `pipass_vault_` record keys and `pipass_note_` record keys may include record identifiers. Treat those identifiers as sensitive during manual verification; record the category, not individual IDs.
- `pipass_kdf_metadata` is sensitive metadata. Record only that the key is present or absent.
- `pipass_master_key` is secret key material. Record only that the key/category is present or absent, and only when the inspection method can avoid showing the value.

## 8. Platform Notes

Web/dev browser storage inspection:

- Use browser storage tooling only to observe key names and presence.
- Do not expand, copy, screenshot, or export stored values.
- If the browser UI cannot hide values, record observations manually without capturing the storage panel.

Native/Expo/dev build inspection:

- Use a dev-only harness or logs that print key names only, never values.
- Do not add runtime behavior or weaken gates for manual inspection.
- Do not capture native secure storage values, cached master key values, or keychain output.

Blocked inspection:

- If safe key-name-only inspection is not available, mark storage inspection as blocked.
- Do not weaken privacy rules to complete a manual run.

## 9. Stop Immediately If

- `pipass_vault_initialized` appears before recovery confirmation.
- Entry or secure note records are durable before recovery confirmation.
- `pipass_shared_vault` is durable before gates and recovery confirmation.
- Active shares appear to publish before full commit success.
- UI says imported, restored, or added before durable success.
- Any tool exposes secret values in captured evidence.

If a stop condition occurs, stop the run and record only a safe failure summary. Do not continue from partial or uncertain local state until startup repair or manual repair behavior has been verified.

## 10. Where To Record Results

Use this guide while filling:

- `docs/STAGED_BACKUP_IMPORT_FIRST_MANUAL_RUN.md`
- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`
- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RESULTS.md`

Record safe observations only. Do not paste raw storage values, backup contents, ciphertext, recovery keys, master keys, salts, hashes, full metadata JSON, auth/session values, device identifiers, or screenshots containing sensitive values.
