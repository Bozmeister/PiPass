# Setup Import Atomicity Audit

## 1. Purpose

This document audits the current first-time vault setup and backup import boundary. It records what is written during setup and import, where atomicity currently breaks down, and what a safer future import design should require before runtime behavior changes.

This is documentation and audit only. It does not change setup, import, crypto, UI, storage keys, tests, server routes, schemas, vault formats, password rotation, profile changes, or KDF metadata wiring.

## 2. Current First-Time Setup Sequence

First-time setup is shown by `SeedSetupScreen` when `isVaultInitialized()` is not `"1"`.

The user enters:

- master password
- confirmation password
- selected security profile

After the user presses create, `SeedSetupScreen` calls `onSetup(password, iterations)`, implemented in `app/(tabs)/index.tsx`. Prompt 039 moved the commit-sensitive setup work into `performFirstTimeVaultSetup()`.

Current setup sequence:

1. Clamp the selected profile iterations.
2. Generate `pipass_master_salt`.
3. Derive the initial master key with explicit Argon2id only.
4. Build `pipass_kdf_metadata` with `algorithm: "argon2id"` and `source: "setup"`.
5. Split the master key into shares.
6. Compute and save `pipass_master_hash`.
7. Generate and hash the recovery key.
8. Save setup metadata and cached key.
9. Store pending setup shares in React state.
10. Show `RecoveryKeyModal`.
11. Only after recovery confirmation, write `pipass_vault_initialized` as `"1"` and publish setup shares as active vault shares.

If explicit Argon2id derivation fails, setup stops before setup metadata is written.

## 3. Current Backup Import Sequence

Backup import is exposed on the first-time setup screen under "Restore From Backup". The button remains available before the vault initialized marker exists and before setup metadata is committed.

Accepted file selection differs by platform:

- web: file input accepts `.vault,.json`
- native: `DocumentPicker.getDocumentAsync({ type: "*/*" })` allows any selected file type

The content must parse as JSON and pass the current minimal shape check:

- `backup.version` must be truthy
- `backup.entries` must be an array

The import loop writes:

- every `backup.entries` item where `entry.id && entry.title`
- every `backup.secureNotes` item where `note.id && note.encryptedContent`, if `secureNotes` is an array

The import path does not derive a key, decrypt records, re-encrypt records, verify KDF metadata, verify entry salts, verify note salts, or verify that imported ciphertext is compatible with the new password.

## 4. Storage Writes During Setup

Successful setup currently writes:

- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_kdf_metadata`
- `pipass_recovery_key_hash`
- native cached `pipass_master_key` where supported

It does not write `pipass_vault_initialized` until the recovery key modal is confirmed.

Setup also stores pending key shares in React state after setup metadata writes succeed. Those shares are not active vault shares until recovery confirmation.

## 5. Storage Writes During Import

Imported vault entries are written through `saveEntry(entry)`.

For each imported entry, `saveEntry()`:

- writes `pipass_vault_<entryId>`
- updates `pipass_vault_index`
- calls `syncSharedVaultBlob()`
- rewrites `pipass_shared_vault` from all indexed local entries

Imported secure notes are written through `saveSecureNote(note)`.

For each imported note, `saveSecureNote()`:

- writes `pipass_note_<noteId>`
- updates `pipass_notes_index`

Secure note import does not regenerate `pipass_shared_vault`; the shared vault blob currently mirrors local vault entries, not secure notes.

Import does not write:

- `pipass_master_salt`
- `pipass_master_hash`
- `pipass_security_profile`
- `pipass_kdf_metadata`
- `pipass_recovery_key_hash`
- cached `pipass_master_key`
- `pipass_vault_initialized`

## 6. Atomicity Gaps

Import is not atomic with setup.

Current gaps:

- import can write entries and notes before the new password, salt, KDF metadata, recovery hash, cached key, or initialized marker exists
- import commits each entry and note incrementally
- failed import can leave earlier entries or notes behind
- imported entries trigger shared vault blob regeneration during import, before setup is complete
- imported secure notes can be partially written independently from entries
- recovery confirmation is not part of the import transaction
- setup failure after import does not roll back imported rows
- closing the app at the recovery modal can leave setup metadata and imported data present while `pipass_vault_initialized` is still not `"1"`

`destroyAllData()` can clear these records, but import itself does not stage or roll back.

## 7. Compatibility And Encryption Assumptions

Imported records are currently treated as already-formed `VaultEntry` and `SecureNote` objects. They are not encrypted under the newly entered password during import.

Current import therefore implicitly assumes one of these is true, but does not prove either:

- imported encrypted records are portable and compatible with the new local key path
- imported records already match the password, salt, profile, KDF algorithm, and `deviceUUID` that will later unlock the vault

That assumption is risky because local entry and secure note decryption depends on the master key and per-record derivation. If imported ciphertext was created under a different password, salt, `deviceUUID`, KDF algorithm, or profile path, setup may succeed but imported data can fail to decrypt later.

The current backup shape check does not distinguish:

- plaintext export
- encrypted local-record export
- same-device backup
- different-device backup
- legacy no-salt record
- Argon2id metadata-aware export
- PBKDF2 legacy export

## 8. Failure Scenarios

### Import Succeeds, Setup Later Fails

If import writes entries or notes and explicit Argon2id setup later fails, setup metadata is not committed, but imported entries, notes, indexes, and possibly `pipass_shared_vault` may remain.

The next app start can still see `pipass_vault_initialized` as false while local encrypted vault data exists.

### Import Succeeds, Recovery Confirmation Is Not Completed

Setup metadata and imported records can exist while `pipass_vault_initialized` remains unset. The current UI provides only the recovery confirmation path while the modal is visible; interruption or app close may leave a partially prepared local state.

### Setup Succeeds, Imported Data Is Incompatible

The vault can initialize successfully, but imported entries or notes may fail to decrypt with the new shares. `VaultScreen.loadVault()` currently checks only the first entry as a key-mismatch check. It does not verify every entry and does not verify every secure note as part of setup.

### Partial Entry Import

If one entry write succeeds and a later entry fails, earlier entries remain. Because `saveEntry()` regenerates `pipass_shared_vault` after each write, the shared blob can also reflect a partial import.

### Partial Secure Note Import

If one note write succeeds and a later note fails, earlier notes remain. There is no shared vault blob update for notes, so entries and notes can be partially inconsistent.

### Honeytoken Metadata

Imported `encryptedAux` is preserved if present on the imported entry object. The import path does not decrypt or validate it. If the entry key is incompatible, `decryptVaultEntry()` later swallows aux-decryption failures and treats the entry as not a honeytoken.

Even if `encryptedAux` decrypts, server-side honeytoken rows are not imported by this local backup path. A restored decoy may reference a server honeytoken id that does not exist in the current account or device context.

## 9. Recommended Safe Future Design

Future import should not write imported vault records before setup metadata is committed.

Recommended design:

1. Parse the backup file into a staged in-memory representation.
2. Validate backup type, version, and required metadata before storage writes.
3. Classify the backup as plaintext export, encrypted local-record export, or unsupported.
4. Derive and verify the new setup key with explicit Argon2id.
5. Build setup KDF metadata from the actual Argon2id parameters.
6. If the backup is plaintext, encrypt entries and notes under the newly prepared setup key.
7. If the backup is encrypted, require explicit metadata proving compatibility or route through a rekey/import flow.
8. Stage all resulting entries, notes, indexes, and shared vault blob data before commit.
9. Commit setup metadata and imported records in a controlled order.
10. Regenerate `pipass_shared_vault` only after final entry records are committed.
11. Do not write `pipass_vault_initialized` until import, setup metadata, cached key policy, and recovery confirmation have all succeeded.
12. On failure before commit, write nothing.
13. On failure after partial commit, use an explicit rollback plan or force a safe repair/reset path.

Preferred future UX:

- "Import backup" should stage and preview count only.
- "Create vault" should perform the real commit.
- The user should not see "entries loaded" if records have already been committed but setup can still fail.

Prompt 041 adds pure versioned backup parsing/staging helpers for `schema: "pipass-backup"`, `version: 1`, and `format: "encrypted-local-records"`. These helpers validate and classify backup content in memory only; they are not wired into runtime import and do not prove ciphertext compatibility.

## 10. Test Plan

Before changing runtime behavior, add tests for:

- import parse accepts only the intended backup schema
- import staging performs no storage writes
- setup failure after staged import writes no vault entries, notes, indexes, shared blob, or setup metadata
- successful plaintext import encrypts records under the new Argon2id setup key
- encrypted import without compatibility metadata is rejected without writes
- encrypted import with compatible metadata can be verified or rekeyed according to the chosen design
- partial entry write failure rolls back entries, index, and shared vault blob
- partial note write failure rolls back notes and notes index
- recovery confirmation remains the initialized marker boundary
- imported `encryptedAux` survives compatible rekey/import
- incompatible `encryptedAux` does not silently disarm a server-backed honeytoken without an explicit warning or reissue policy
- secure notes are included in import validation and rollback
- `pipass_shared_vault` is regenerated once after final entry commit, not after each staged entry

Current tests should remain in place for:

- explicit Argon2id setup
- KDF metadata storage and wipe boundaries
- unlock KDF metadata migration
- clear/reset boundaries

## 11. Implementation Prompt Sequence

Recommended sequence:

1. Define a versioned backup schema and whether it is plaintext, encrypted, or both.
2. Add pure backup parsing and validation helpers with tests.
3. Add an in-memory staged import model for entries and notes.
4. Add tests proving staged import does not write storage.
5. Add plaintext import encryption under the prepared setup key, if plaintext export is supported.
6. Add encrypted import compatibility checks or an explicit rekey flow.
7. Add an atomic setup-plus-import commit helper with injected storage dependencies.
8. Add rollback tests for each storage write failure point.
9. Wire `SeedSetupScreen` to stage backups instead of writing immediately.
10. Update shared vault blob regeneration to happen after final committed entries.
11. Add UI copy that distinguishes staged backups from committed imports.

Do not combine this with password rotation, profile changes, vault-root-key migration, server auth changes, session-token changes, or encryption algorithm changes.

## 12. Open Decisions

- Should PiPass support plaintext backup import, encrypted local-record import, or both?
- What metadata must an encrypted backup carry to prove KDF, salt, `deviceUUID`, profile, and format compatibility?
- Should backup import support cross-device encrypted backups before a vault-root-key model exists?
- Should imported honeytokens be reissued with new server rows instead of preserving old `encryptedAux` references?
- Should setup metadata and imported records commit before recovery confirmation, or should all writes wait until recovery confirmation?
- What repair path should appear when old partial import data already exists while `pipass_vault_initialized` is false?
- Should `clearVault()` or a dedicated setup-abort action clear staged/partial import data?
