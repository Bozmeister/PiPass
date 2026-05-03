# Backup Compatibility Policy

## 1. Purpose

This document defines encrypted backup compatibility and future rekey/import policy for PiPass before staged backup import is wired into setup.

This is design-only. It does not change runtime code, tests, setup, import UI, storage writes, crypto algorithms, server routes, schemas, vault formats, password rotation, profile changes, or package scripts.

## 2. Current Encryption And Import Model

Prompt 041 adds pure parsing and staging for versioned backups with:

- `schema: "pipass-backup"`
- `version: 1`
- `format: "encrypted-local-records"`

Those helpers validate the backup envelope and minimal encrypted record shapes only. They do not decrypt records, re-encrypt records, write storage, regenerate shared vault state, prove KDF compatibility, or decide whether import is safe.

Current local record encryption depends on:

- the master password
- `pipass_master_salt`
- KDF algorithm and parameters from `pipass_kdf_metadata` or legacy profile detection
- `deviceUUID`
- entry or note id
- entry or note salt

Vault entries and secure notes are therefore not portable just because the JSON shape is valid.

## 3. Compatibility Requirements

An encrypted-local-records backup is compatible with a target install only if the target can reproduce the same master key and per-record subkeys used to encrypt the records.

For current records, compatibility requires:

- the same master password
- the same `pipass_master_salt`
- the same KDF algorithm
- the same KDF parameters and version
- the same `deviceUUID`
- the same entry or note ids
- the same entry or note salts
- unchanged ciphertext fields

If any master-key input differs, the target install derives a different master key. The per-entry and per-note HKDF labels can still be structurally valid, but decryption will fail or produce invalid MAC checks.

The password alone is not enough. A user entering the same password on another device will not decrypt encrypted-local-records backups unless the rest of the local key path also matches.

## 4. Same-Install Encrypted Backup Policy

Encrypted-local-records backups should be treated as same-install and same-key-path backups under the current architecture.

Same-install means:

- the backup was produced from the same local vault key path
- `deviceUUID` is unchanged
- local salt and KDF metadata match
- entries and notes retain their original ids and salts

Same-install restore can be useful for repair or local rollback, but it still needs explicit compatibility verification before writing records.

Policy:

- staging may accept encrypted-local-records backups
- runtime import must not commit staged records until compatibility is verified
- compatibility failure must leave storage unchanged
- successful import must regenerate indexes and shared vault state as one controlled commit

## 5. Different-Device Import Policy

Different-device encrypted-local-records import should be rejected by default until PiPass has a real rekey flow or vault-root-key model.

Reason: `deviceUUID` is part of the current KDF input. A different install normally has a different `deviceUUID`, so the same password, salt, and KDF profile are still insufficient to decrypt records.

Do not migrate or overwrite `deviceUUID` to make an encrypted backup work. That would risk breaking existing local data and would turn a device-local KDF input into a backup portability mechanism it was not designed to be.

Future cross-device restore should use one of these explicit paths:

- plaintext export/import with clear user confirmation and re-encryption under the target setup key
- encrypted export that includes a portable vault root key wrapped for recovery or password unlock
- rekey import that decrypts with the source key path and re-encrypts under the target key path after explicit verification

## 6. Backup Metadata Requirements

Future encrypted backups should carry compatibility metadata outside the encrypted records. This metadata is sensitive operational metadata, not key material.

Recommended backup metadata fields:

- backup schema and version
- backup format
- vault format version
- record encryption family, such as `master-key-hkdf-records-v1`
- KDF metadata version
- KDF algorithm and parameters
- salt identity, such as `pipass_master_salt`
- salt value or a salted compatibility verifier decision, depending on export policy
- device binding policy, such as `deviceUUID:v1`
- whether `deviceUUID` is required to match
- created timestamp
- source platform class if needed for diagnostics

Do not include:

- master password
- master key
- key shares
- raw cached key
- recovery key
- session tokens
- server auth hashes
- plaintext vault contents

## 7. Compatibility Verification Options

Future import needs a verifier that proves compatibility without exposing plaintext or key material.

Options to evaluate:

1. Master-hash compatibility verifier:
   - backup includes the source `hashMasterKey(masterKeyHex)` or a backup-specific verifier derived from the master key
   - target derives a candidate key and compares the verifier before record import
   - risk: reusing `pipass_master_hash` in exported files may increase verifier exposure

2. Backup-specific keyed verifier:
   - derive a backup verifier from the source master key with a dedicated label, for example `pipass-backup-compat-v1`
   - target recomputes the verifier after password/KDF derivation
   - preferred over exporting the normal master hash

3. Sample-record decrypt verification:
   - target attempts to decrypt selected records after candidate key derivation
   - useful as defense-in-depth
   - not enough by itself if only the first record is checked

4. Full staged decrypt verification:
   - target decrypts every staged entry and note in memory before commit
   - strongest current-architecture check
   - must avoid logging plaintext and must wipe buffers where possible

Recommended policy: use a backup-specific verifier plus full staged decrypt verification before committing encrypted-local-records.

## 8. Secure Notes And Honeytokens

Secure notes must follow the same compatibility policy as vault entries.

Rules:

- notes must be staged with entries
- notes must be included in compatibility verification
- notes must be included in rollback and commit tests
- import must not mark setup initialized if note import fails

Honeytoken `encryptedAux` needs special handling:

- preserve `encryptedAux` only when record rekey/import is proven compatible
- if rekeying, decrypt and re-encrypt aux data with the rest of the entry
- if aux decryption fails, do not silently treat the restored decoy as healthy
- surface a safe warning that decoy metadata could not be restored

Server honeytoken rows are not included in local encrypted-local-record backups today. Restored aux data may reference server rows that do not exist for the current account, server, or device context.

Recommended policy:

- do not export server honeytoken rows in local backup v1
- on restore, either reissue honeytokens with new server rows or warn that restored decoy triggers require reconfiguration
- do not silently preserve aux references as if server-backed triggers are guaranteed active

## 9. User-Facing Messages

Messages should be plain, short, and non-secret.

Unsupported encrypted import on another device:

> This backup is encrypted for a different local vault setup. PiPass cannot import it safely on this device yet.

Encrypted import needs future rekey flow:

> This encrypted backup needs a compatibility check before it can be restored. Your vault has not been changed.

Honeytoken warning:

> Some decoy trigger metadata could not be restored. Review decoys after import.

Generic parse/stage failure:

> This does not look like a supported PiPass backup file.

Do not show raw salts, hashes, KDF metadata JSON, device identifiers, record ids, ciphertext, stack traces, or decrypted values.

## 10. Future Rekey And Import Design

Future staged import should split into phases:

1. Parse and validate the versioned backup envelope.
2. Stage entries and notes in memory.
3. Classify backup format as encrypted-local-records, plaintext export, or unsupported.
4. For encrypted-local-records, read compatibility metadata.
5. Derive the source-compatible key only after the user provides the required password or recovery material.
6. Verify a backup-specific compatibility verifier.
7. Decrypt every entry and secure note in memory.
8. Re-encrypt records under the target setup key if importing into a new vault.
9. Preserve or reissue honeytoken aux metadata according to server policy.
10. Build final indexes and shared vault blob data in memory.
11. Commit setup metadata, records, notes, indexes, shared blob, and initialized marker in a controlled order.
12. Roll back or leave storage untouched on failure.

For first-time setup, the safest model is:

- stage backup first
- derive the new setup key with explicit Argon2id
- verify or rekey staged data
- show recovery key
- commit only when setup, import, and recovery confirmation all succeed

## 11. Relationship To Vault-Root-Key Migration

The current architecture makes encrypted local records device-bound because password-derived master key material directly encrypts entry and note subkeys.

A vault-root-key model would make backup compatibility cleaner:

- records are encrypted under a random vault root key or subkeys derived from it
- password changes rewrap the root key instead of re-encrypting every record
- recovery can wrap the same root key separately
- cross-device restore can import the wrapped root key if the user proves the correct password or recovery secret
- `deviceUUID` can remain local policy metadata instead of being required for record portability

Recommendation: do not build complex cross-device encrypted-local-record import before deciding the vault-root-key migration. A minimal same-install restore path can ship earlier if compatibility is strongly verified.

## 12. Test Plan

Before runtime import wiring, add tests for:

- encrypted-local-record backup with missing compatibility metadata is staged but not committed
- same-install compatibility metadata passes only when salt, KDF metadata, and device binding match
- different `deviceUUID` rejects encrypted-local-record import without writes
- different KDF algorithm rejects encrypted-local-record import without writes
- different KDF parameters reject encrypted-local-record import without writes
- wrong password rejects encrypted-local-record import without writes
- backup-specific verifier mismatch rejects without writes
- every entry is decrypted during staged verification
- every secure note is decrypted during staged verification
- any entry failure aborts the whole import
- any note failure aborts the whole import
- partial commit failures roll back entries, notes, indexes, and shared vault blob
- honeytoken `encryptedAux` survives compatible import
- honeytoken aux failure triggers explicit warning or reissue path
- unsupported different-device encrypted import shows safe copy
- no logs contain passwords, keys, key shares, salts, hashes, `deviceUUID`, ciphertext, plaintext, or metadata JSON

Existing parser tests from Prompt 041 should remain pure and storage-free.

## 13. Implementation Prompt Sequence

Recommended sequence:

1. Extend backup schema design with optional compatibility metadata fields.
2. Add parser tests for compatibility metadata without accepting it for commit yet.
3. Add pure compatibility classification helpers.
4. Add backup-specific verifier design and tests.
5. Add staged full decrypt verification helpers for entries and notes.
6. Add rekey helpers that decrypt with source shares and re-encrypt with target setup shares.
7. Add honeytoken aux preservation or reissue policy tests.
8. Add atomic setup-plus-import commit helper with rollback tests.
9. Wire first-time setup import to staging only.
10. Wire encrypted import only for verified same-install or explicitly rekeyed data.
11. Defer cross-device encrypted restore until vault-root-key policy is settled.

Do not combine this with password rotation, profile changes, server auth changes, session-token changes, or encryption algorithm changes.

## 14. Open Decisions

- Should encrypted-local-record backups include a backup-specific verifier, or should compatibility be proven only by full staged decrypt?
- Should exported compatibility metadata include the salt value, a salt identifier, or both?
- Should same-install restore require exact `deviceUUID` match, or allow an explicit source `deviceUUID` only inside a rekey flow?
- Should plaintext export/import exist, and how should the UI communicate its risk?
- Should local backups include server honeytoken context, or should decoys always be reissued after restore?
- Should first-time setup commit any metadata before recovery confirmation when a staged import is present?
- Should cross-device encrypted import wait entirely for vault-root-key migration?
