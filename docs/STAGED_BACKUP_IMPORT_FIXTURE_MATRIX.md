# Staged Backup Import Fixture Matrix

## 1. Scope

This fixture matrix supports Prompt 079 manual verification.

The supported success path is limited to same-install `pipass-backup` version `1` backups with format `encrypted-local-records`.

Unsupported, cross-device, plaintext, portable, password/profile/vault-root-key migration, and server honeytoken reissue cases remain out of scope except as blocked or ineligible negative cases.

This matrix is documentation only. It does not change runtime code, tests, UI, storage writes, setup flow, recovery confirmation, crypto/KDF behavior, server code, routes, schemas, password rotation, profile changes, vault formats, package files, or TypeScript config.

## 2. Privacy And Safety Rules

- Use fake throwaway data only.
- Do not store or paste real backup files.
- Do not paste plaintext entries, secure note contents, recovery keys, master keys, key shares, salts, hashes, KDF metadata JSON, device UUIDs, install ids, auth/session values, ciphertext blobs, or raw backup contents.
- Refer to fixtures only by safe labels.
- Record key presence, gate status, and safe UI summaries only.

## 3. Fixture Matrix

| Fixture label | Purpose | Backup shape | Expected gate/eligibility result | Expected UI/result | Expected durable writes | Evidence to record safely |
| --- | --- | --- | --- | --- | --- | --- |
| `no-backup` | Prove setup-only baseline still works. | No backup selected. | No staged backup; setup-only allowed. | No staged import wording. Recovery confirmation remains setup boundary. | Setup metadata and `pipass_vault_initialized` only after recovery confirmation. No staged records. | Platform, build type, setup-only pass/fail, initialized-after-confirmation summary. |
| `same-install-valid-minimal` | Prove first supported success path with entries only. | Same-install `pipass-backup` v1 `encrypted-local-records`; fake entry data only. | Eligible after compatibility and decryptability pass; verifier policy follows current config. | Ready wording before recovery confirmation; success wording only after durable commit. | After recovery confirmation only: entry records, vault index, shared vault blob, setup metadata, cached master key only per existing setup policy, `pipass_vault_initialized` last. | Fixture label, ready/success wording summary, safe key-presence/order summary. |
| `same-install-valid-with-notes` | Prove supported success path includes secure notes. | Same-install `pipass-backup` v1 `encrypted-local-records`; fake entries and fake secure notes. | Eligible after compatibility and decryptability pass; verifier policy follows current config. | Ready wording before recovery confirmation; success wording only after durable commit. | After recovery confirmation only: entry records, vault index, secure note records, notes index, shared vault blob, setup metadata, cached master key only per existing setup policy, `pipass_vault_initialized` last. | Fixture label, counts summary, safe key-presence/order summary. |
| `same-install-valid-missing-verifier` | Confirm missing verifier follows current allowed policy when other gates pass. | Same-install encrypted-local-records with no verifier metadata. | Eligible only if current policy allows missing verifier and compatibility plus decryptability pass. | Must not claim sentinel verification. Ready/success wording follows durable boundary. | Same as applicable supported success fixture, only after recovery confirmation. | Fixture label, verifier-missing policy result, safe success/block summary. |
| `same-install-valid-verifier-passed` | Confirm present verifier with passed sentinel can import when other gates pass. | Same-install encrypted-local-records with valid verifier and passing sentinel. | Eligible after compatibility, sentinel, decryptability, and warning gates pass. | Ready before recovery confirmation; imported/added only after durable success. | Same as applicable supported success fixture, only after recovery confirmation. | Fixture label, sentinel-passed status, safe key-presence/order summary. |
| `unsupported-schema` | Prove unsupported schema blocks import. | Not `pipass-backup`. | Blocked or parse rejected before staged commit. | Safe unsupported/blocked wording; no import success wording. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe blocked wording. |
| `unsupported-version` | Prove unsupported version blocks import. | `pipass-backup` with unsupported version. | Blocked or parse rejected before staged commit. | Safe unsupported/blocked wording; no import success wording. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe blocked wording. |
| `unsupported-format` | Prove unsupported format blocks import. | Supported schema/version with unsupported format. | Blocked before staged commit. | Safe unsupported/blocked wording; no import success wording. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe blocked wording. |
| `plaintext-or-portable-shape` | Prove plaintext or portable shapes are not supported restore modes. | Plaintext-like or portable-like backup shape. | Blocked or parse rejected; not eligible. | Safe unsupported/blocked wording; no import/restored/added success wording. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label only; do not record contents. |
| `cross-device-shape` | Prove cross-device restore is not supported. | Encrypted-local-records shape that cannot prove same-install compatibility. | Blocked as incompatible or unknown. | Safe same-install limitation wording; clear/dismiss per policy. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and compatibility status summary. |
| `device-uuid-mismatch` | Prove device mismatch blocks import when binding is present. | Same-format backup with mismatched device binding. | Blocked as incompatible. | Safe mismatch/compatibility wording without device identifiers. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe incompatible summary. |
| `missing-required-device-binding` | Prove missing required same-device binding fails closed. | Same-format backup lacking required same-device proof. | Blocked as unknown, missing, or incompatible according to helper policy. | Safe blocked wording; clear/dismiss per policy. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe reason category. |
| `kdf-algorithm-mismatch` | Prove incompatible KDF algorithm context blocks same-install proof. | Same-format backup with incompatible KDF algorithm context. | Blocked as incompatible or unknown. | Safe compatibility wording; no KDF internals. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe compatibility summary. |
| `kdf-parameter-mismatch` | Prove incompatible KDF parameters block same-install proof. | Same-format backup with incompatible KDF parameter context. | Blocked as incompatible or unknown. | Safe compatibility wording; no parameter values. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe compatibility summary. |
| `salt-key-mismatch` | Prove key/salt mismatch blocks decryptability or compatibility. | Same-format backup that cannot be decrypted by current setup key path. | Blocked by compatibility or decryptability failure. | Safe blocked wording; no record ids or raw errors. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe failure category. |
| `invalid-verifier` | Prove invalid verifier blocks import. | Same-format backup with malformed or invalid verifier metadata. | Blocked before commit. | Safe verifier failure wording; no verifier metadata. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe verifier status. |
| `verifier-sentinel-failed` | Prove failed sentinel blocks import. | Same-format backup with present verifier and failed sentinel. | Blocked before decryptability/commit according to gate order. | Safe sentinel failure wording; no sentinel contents. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe sentinel status. |
| `decryptability-entry-failed` | Prove any failed entry decryptability blocks full import. | Same-format backup with at least one fake entry failing decryptability. | Blocked before commit. | Safe decryptability failure wording; no record ids or contents. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and failed-check category only. |
| `decryptability-note-failed` | Prove any failed secure note decryptability blocks full import. | Same-format backup with at least one fake secure note failing decryptability. | Blocked before commit. | Safe decryptability failure wording; no note ids or contents. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and failed-check category only. |
| `honeytoken-or-decoy-warning` | Prove warning policy remains conservative. | Same-format backup with honeytoken or decoy warning metadata. | Blocked by warning policy unless future explicit policy allows. | Safe warning/blocked wording; clear/dismiss per policy. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe warning category. |
| `encrypted-aux-warning` | Prove encrypted auxiliary warning remains conservative. | Same-format backup with encrypted auxiliary warning. | Blocked by warning policy unless future explicit policy allows. | Safe warning/blocked wording; clear/dismiss per policy. | No staged records, notes, indexes, shared vault blob, cached import state, or active shares. | Fixture label and safe warning category. |
| `injected-write-failure-before-initialized-marker` | Prove commit failure before initialized marker fails closed. | Eligible same-install backup plus injected write failure before final marker. | Gates pass; executor fails during commit. | Safe failure wording; no import success claim. | Rollback expected; no active shares; no usable partial initialized vault. Startup repair handles any partial state. | Failure point label, safe failure wording, startup repair route summary. |
| `injected-write-failure-at-initialized-marker` | Prove initialized marker remains final and marker failure fails closed. | Eligible same-install backup plus injected failure at `pipass_vault_initialized`. | Gates pass; executor fails at final marker. | Safe failure wording; no import success claim. | Rollback expected; no active shares; no usable partial initialized vault. Startup repair handles any partial state. | Failure point label, safe failure wording, startup repair route summary. |

## 4. Success Fixture Durable Write Expectations

For supported success fixtures, durable writes are expected only after recovery confirmation and only after all gates pass:

- entry records
- vault index
- secure note records where applicable
- notes index where applicable
- shared vault blob after gates pass
- setup metadata
- cached master key only per existing setup policy
- `pipass_vault_initialized` last

Before recovery confirmation, supported fixtures must remain staged in memory only.

## 5. Blocked Fixture Expectations

For blocked fixtures, the expected outcome is:

- no staged records written
- no secure note records written
- no vault or notes indexes written from staged backup
- no staged shared vault blob written
- no active shares published
- no imported, restored, or added success wording
- clear/dismiss or safe failure according to policy
- no release-readiness claim

## 6. Fixture Creation Notes

- Use test-only or harness-generated backups.
- Keep fixture labels stable across manual runs.
- Keep fixture contents outside documentation.
- If a fixture cannot be created manually, mark it as requiring harness support.
- Do not weaken runtime gates to make a fixture easier to create.
- Do not copy raw backup JSON into docs, issues, chat, or screenshots.

## 7. Where To Record Results

Record execution results in:

- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RECORD.md`
- `docs/STAGED_BACKUP_IMPORT_MANUAL_VERIFICATION_RESULTS.md`

Record fixture labels and safe summaries only. Do not record fixture contents.
