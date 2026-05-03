# Backup Verifier Design

## 1. Purpose

This document designs a future backup compatibility verifier and staged decrypt verification policy for PiPass encrypted-local-record backups.

This is design-only. It does not change runtime code, tests, setup, import UI, storage writes, crypto algorithms, server routes, schemas, vault formats, password rotation, profile changes, or package scripts.

## 2. Current Limitation

Prompt 043 adds metadata-only backup compatibility classification. That can reject obvious mismatches, such as unsupported format, portable encrypted backups, KDF parameter mismatch, salt-key mismatch, or device-binding mismatch.

Metadata alone cannot prove the current unlock key can decrypt staged records. Metadata can be missing, stale, copied from another backup, or structurally valid but wrong for the ciphertext.

A future runtime import must therefore add a cryptographic verification step before committing staged backup data.

## 3. What Compatibility Verification Must Prove

A backup verifier should prove that the candidate unlock key path can decrypt data produced by the source vault key path.

It must prove:

- the supplied password or unlock material derives the expected master key
- the current KDF metadata, salt, and `deviceUUID` path matches the backup's encrypted records
- the current entry/note subkey derivation path can decrypt backup ciphertext
- the backup was not merely shape-valid JSON with incompatible ciphertext

It must not prove:

- user identity on the server
- trusted-device state
- ownership of server honeytoken rows
- recovery-key possession unless a future recovery import flow explicitly uses it
- vault-root-key compatibility before a root-key model exists

## 4. Verifier Record Design Options

### Option A: Encrypted Sentinel

The backup contains a small synthetic encrypted record created only for compatibility verification.

Pros:

- does not use real user secrets
- can exercise the same record key path as entries or notes
- can fail before touching storage
- avoids decrypting real records just to learn whether the key path is plausible

Cons:

- requires backup writers to include a new field
- legacy backups will not have it
- still needs full staged decrypt for defense-in-depth

### Option B: Backup-Specific Keyed Verifier

The backup includes a verifier derived from the master key using a dedicated label.

Pros:

- compact
- does not decrypt record ciphertext
- avoids exporting `pipass_master_hash`

Cons:

- proves the master key but not the record HKDF/encryption path
- needs careful label/version design
- should not replace staged record verification

### Option C: Sample Real Record Decrypt

The app attempts to decrypt one staged entry or note before import.

Pros:

- works for legacy encrypted-local-record backups
- exercises real ciphertext

Cons:

- one record is not enough
- can miss note failures or later entry failures
- touches real plaintext in memory
- does not distinguish corrupted backup from wrong key without careful messaging

### Option D: Full Staged Decrypt

The app decrypts every staged entry and secure note in memory before commit.

Pros:

- strongest current-architecture verification
- catches per-record corruption and note-specific failures
- required before re-encryption into a new vault

Cons:

- temporarily brings plaintext into memory
- requires careful wiping where possible
- needs non-secret error handling and no logging

Recommended policy: use an encrypted sentinel for quick compatibility proof, then perform full staged decrypt verification before any storage write.

## 5. Recommended Verifier Schema

Future backup schema should add a verifier object outside user records:

```json
{
  "verifier": {
    "version": 1,
    "type": "encrypted-sentinel",
    "recordKeyDerivation": "master-key-hkdf-record-v1",
    "recordKind": "entry",
    "recordId": "pipass-backup-verifier-v1",
    "salt": "hex",
    "ciphertext": "string",
    "expectedPlaintextHash": "hex",
    "plaintextLabel": "pipass-backup-sentinel-v1"
  }
}
```

Prompt 045 adds pure schema validation helpers for this verifier shape. They validate and stage the verifier metadata only; they do not decrypt the sentinel, derive keys, require the verifier during backup parsing, or authorize import.

Prompt 046 adds a pure sentinel verification helper that uses injected entry/note decryptors and compares a SHA-256 hash of the returned sentinel plaintext. It does not wire runtime import, derive keys itself, or write storage.

Design notes:

- `recordId` and `salt` should be synthetic and independent from user entries.
- sentinel plaintext must be fixed, non-secret, and versioned.
- `expectedPlaintextHash` should hash the non-secret sentinel plaintext plus version/domain context.
- encryption should use the existing record encryption path for the selected `recordKind`.
- do not store master key, password, key shares, recovery key, `pipass_master_hash`, session tokens, or server auth values.
- do not invent a new encryption primitive for the sentinel.

If a backup-specific keyed verifier is added later, it should use a separate versioned domain label and should not replace the encrypted sentinel unless a crypto review explicitly approves that design.

## 6. Verification Flow

Future runtime import should verify in this order:

1. Parse the backup using the versioned parser.
2. Stage entries and secure notes in memory.
3. Run metadata-only compatibility classification.
4. Reject known incompatible states before deriving keys.
5. Ask for the needed password or unlock material.
6. Derive candidate key material using explicit KDF metadata.
7. If a verifier exists, decrypt the sentinel with the same record key path.
8. Compare the sentinel plaintext hash.
9. If the sentinel passes, decrypt every staged entry and secure note in memory.
10. If all staged records decrypt, prepare re-encryption or same-install restore.
11. Commit only after all verification and import preparation succeeds.

No setup metadata, entries, notes, indexes, shared vault blob, cached key, or initialized marker should be written before verification succeeds.

## 7. Legacy Backup Handling

Legacy backups without a verifier should not be treated as proven compatible.

Recommended handling:

- metadata match plus no verifier: status remains "unknown"
- same-install restore can proceed only through explicit user confirmation and full staged decrypt verification
- different-device encrypted import remains unsupported without a rekey/root-key path
- if staged decrypt fails, reject import without writes

Do not silently commit legacy encrypted records based only on shape validation or metadata match.

## 8. Entry And Secure Note Verification

Staged decrypt verification must include:

- every staged vault entry
- every staged secure note
- encrypted display fields where present
- legacy no-salt records only if a legacy import policy explicitly supports them

For entries, verification should decrypt:

- title path
- username path
- password
- optional URL
- optional notes

For secure notes, verification should decrypt:

- label
- content

Verification must not rely on the current `VaultScreen` first-entry check. That check is useful after unlock, but it is not an import commit boundary.

## 9. Honeytoken Handling

Honeytoken `encryptedAux` should be handled separately from core entry decryptability.

Recommended policy:

- attempt aux decrypt only after the core entry decrypts
- if aux decrypt succeeds, preserve or re-encrypt it according to the import path
- if aux decrypt fails, do not silently mark the decoy as healthy
- return a warning that decoy trigger metadata needs review or reissue

Server honeytoken rows are not part of local encrypted-local-record backups today. Even if aux decrypts, the server row it references may not exist for the current account or environment.

Future import should either:

- reissue honeytokens with new server rows after restore, or
- preserve local aux but warn that server-backed triggers require review

## 10. User-Facing Messages

Messages should be safe, short, and avoid secrets.

Missing verifier:

> This backup needs a full compatibility check before PiPass can restore it.

Verifier mismatch:

> This backup does not match the current vault unlock settings. Your vault has not been changed.

Staged decrypt failure:

> PiPass could not decrypt all records in this backup. Your vault has not been changed.

Unsupported different-device encrypted backup:

> This encrypted backup was made for a different local vault setup. PiPass cannot import it safely on this device yet.

Honeytoken warning:

> Some decoy trigger metadata needs review after restore.

Do not display raw metadata JSON, salts, hashes, `deviceUUID`, record ids, ciphertext, plaintext, keys, stack traces, or decrypted values.

## 11. Failure Handling And Atomicity

Verification failure must be fail-closed:

- write no entries
- write no secure notes
- write no indexes
- write no shared vault blob
- write no setup metadata
- do not mark the vault initialized
- do not update cached key
- do not update KDF metadata

If a future implementation decrypts staged records before commit, plaintext should live only in short-lived memory. Byte buffers should be wiped where practical. JavaScript strings cannot be reliably zeroed, so implementation should avoid retaining decrypted strings longer than needed.

Metadata says compatible but verifier fails:

- treat as incompatible or corrupted
- reject import without writes
- do not attempt fallback algorithms
- do not rewrite backup metadata

Verifier passes but a staged entry/note fails:

- reject import without writes
- report a generic backup decrypt failure
- do not import a partial subset

## 12. Test Plan

Before implementation, add tests for:

- valid encrypted sentinel verifies with matching key path
- sentinel mismatch rejects without storage writes
- sentinel with wrong record id rejects
- sentinel with wrong salt rejects
- sentinel with unsupported verifier version rejects
- metadata-compatible backup with verifier failure is rejected
- backup without verifier remains unknown until full staged decrypt policy runs
- every staged entry is decrypted before commit
- every staged secure note is decrypted before commit
- one failing entry aborts the whole import
- one failing secure note aborts the whole import
- honeytoken aux decrypt failure returns warning and does not silently mark decoy healthy
- no storage writes occur before verifier and staged decrypt success
- no logs contain password, master key, key shares, recovery key, salts, hashes, ciphertext, plaintext, metadata JSON, or `deviceUUID`

Existing Prompt 041 parser tests and Prompt 043 classifier tests should remain pure and storage-free.

## 13. Implementation Prompt Sequence

Recommended sequence:

1. Extend the design schema with optional `verifier` metadata.
2. Add pure verifier schema validation helpers and tests.
3. Add sentinel encryption/decryption helpers using existing record encryption primitives.
4. Add backup-specific verifier generation for future exports.
5. Add verifier checking for staged imports.
6. Add full staged decrypt verification helpers for entries and secure notes.
7. Add honeytoken aux warning classification.
8. Add no-write tests for every failure point.
9. Only then wire runtime import to staged verification.
10. Add atomic setup-plus-import commit and rollback tests.

Do not combine this with password rotation, profile changes, vault-root-key migration, server auth changes, session-token changes, or encryption algorithm changes.

## 14. Open Decisions

- Should the sentinel use entry-style key derivation, note-style derivation, or one of each?
- Should `expectedPlaintextHash` be a plain hash of a fixed non-secret sentinel, or should it be derived with a backup-specific domain label?
- Should backups without verifier be allowed through full staged decrypt after explicit confirmation, or rejected until re-exported?
- Should full staged decrypt be mandatory even when the sentinel passes?
- How should large backups report progress without exposing record names or decrypted fields?
- Should honeytoken server reissue be part of import commit or a post-import review flow?
- Should this verifier design be replaced by vault-root-key wrapping before cross-device encrypted import is attempted?
