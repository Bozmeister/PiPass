# KDF Metadata Design

## 1. Purpose

This document defines a design for recording and using local key derivation metadata before PiPass implements password rotation, KDF profile changes, or a future vault-root-key migration.

This is a design-only document. It does not add storage keys, runtime behavior, tests, schemas, routes, crypto changes, UI, server protocol changes, or migrations.

## 2. Current Risk

PiPass currently stores `pipass_security_profile` as a numeric profile/iteration value. That value is not enough to reproduce the complete KDF path.

Current derivation attempts Argon2id through `hash-wasm`. If Argon2id cannot load or throws, it falls back to PBKDF2-SHA256. Because the actual algorithm used is not stored, a vault created during PBKDF2 fallback may later run in an environment where Argon2id works and derive a different key from the same password, salt, profile, and `deviceUUID`.

The same ambiguity affects fractal metadata: `pipass_fractal_fingerprint` currently records `kdf: "argon2id"` even though PBKDF2 fallback may have produced the actual master key.

Prompt 030 paused security profile changes for populated local vaults. That prevents one lockout path, but it does not solve algorithm/version reproducibility.

## 3. Current KDF Flow Summary

Current unlock inputs:

- master password
- `pipass_master_salt`
- numeric `pipass_security_profile`
- `deviceUUID`
- implicit default `kdfVersion` of `"v1"`
- whichever KDF path succeeds at runtime

Current Argon2id profile mapping:

- profile `25000`: time cost `3`, memory `65536` KiB, parallelism `4` for `v1`
- profile `100000`: time cost `4`, memory `131072` KiB, parallelism `4` for `v1`
- higher profiles: time cost `6`, memory `262144` KiB, parallelism `4` for `v1`
- `v2` exists in code and changes parallelism to `1`, but no current storage metadata records it

Current PBKDF2 fallback:

- algorithm: PBKDF2-SHA256
- output length: 32 bytes
- iterations: numeric profile after the existing guard
- salt: `pipass_master_salt`
- material: `password + ":" + deviceUUID`

## 4. Metadata Requirements

KDF metadata must:

- preserve zero-knowledge and stay local by default
- record the actual KDF algorithm used for vault unlock
- record enough parameters to reproduce the same master key later
- keep `deviceUUID` stable and explicitly represented as a binding input
- avoid automatic algorithm switching for an existing vault
- distinguish intended profile labels from concrete KDF parameters
- support legacy users who only have `pipass_security_profile`
- support future password rotation and root-key wrapping
- be clearable by nuclear reset
- not be used as server authentication, device trust, recovery proof, or audit identity
- not involve `installId`

The metadata is sensitive operational metadata but not secret key material. It must still be treated carefully because it describes the vault unlock path.

## 5. Recommended Metadata Schema

Recommendation: add a separate local key named `pipass_kdf_metadata` instead of changing `pipass_security_profile` into structured JSON.

Rationale:

- preserves current numeric profile compatibility
- avoids breaking older code that expects `pipass_security_profile` to parse as a number
- makes migration explicit and easy to detect
- keeps the UI profile value separate from complete derivation metadata
- lets future root-key wrapping add separate wrapper metadata without overloading the old key

Recommended JSON shape:

```json
{
  "version": 1,
  "algorithm": "argon2id",
  "profileIterations": 100000,
  "kdfVersion": "v1",
  "parameters": {
    "memoryKiB": 131072,
    "timeCost": 4,
    "parallelism": 4,
    "outputBytes": 32
  },
  "saltKey": "pipass_master_salt",
  "deviceBinding": "deviceUUID:v1",
  "createdAt": 1234567890,
  "source": "setup"
}
```

For PBKDF2:

```json
{
  "version": 1,
  "algorithm": "pbkdf2-sha256",
  "profileIterations": 100000,
  "kdfVersion": "legacy-pbkdf2-v1",
  "parameters": {
    "iterations": 100000,
    "outputBytes": 32
  },
  "saltKey": "pipass_master_salt",
  "deviceBinding": "deviceUUID:v1",
  "createdAt": 1234567890,
  "source": "legacy-detected"
}
```

Allowed `algorithm` values for version 1:

- `argon2id`
- `pbkdf2-sha256`

Allowed `source` values:

- `setup`
- `unlock-migration`
- `password-rotation`
- `profile-change`
- `legacy-detected`

`profileIterations` should continue to mirror the value in `pipass_security_profile` while that legacy key exists. The concrete KDF parameters are the authority for derivation reproducibility.

## 6. Legacy Migration Strategy

Existing users may have:

- `pipass_master_salt`
- `pipass_master_hash`
- numeric `pipass_security_profile`
- no `pipass_kdf_metadata`

Migration should happen only after a successful password unlock proves the derived key matches `pipass_master_hash`.

Recommended legacy unlock detection:

1. Read `pipass_kdf_metadata`.
2. If metadata exists and validates, use only that metadata for derivation.
3. If metadata is missing, read numeric `pipass_security_profile`.
4. Try explicit Argon2id `v1` with the stored profile and current `deviceUUID`.
5. Compare `hashMasterKey(candidateKey)` with `pipass_master_hash`.
6. If it matches, write `pipass_kdf_metadata` with `algorithm: "argon2id"` and `source: "unlock-migration"`.
7. If Argon2id does not match, try explicit PBKDF2-SHA256 with the stored profile.
8. If PBKDF2 matches, write `pipass_kdf_metadata` with `algorithm: "pbkdf2-sha256"` and `source: "legacy-detected"`.
9. If neither matches, treat unlock as failed and do not write metadata.

This requires future implementation to split the current "try Argon2id then fallback" behavior into explicit derivation modes. Without explicit modes, unlock cannot safely identify which algorithm produced the matching key.

Migration should not change entry ciphertext, note ciphertext, server vault blobs, `deviceUUID`, installId, auth credentials, or trusted device state.

## 7. New-Vault Setup Behaviour

New vault setup should require Argon2id by default.

Recommended policy:

- do not silently create a new vault under PBKDF2 fallback
- if Argon2id is unavailable, setup should stop with a clear local error
- no local master hash, profile metadata, initialized marker, recovery hash, cached key, or entries should be committed for that failed setup
- PBKDF2 should remain available only for unlocking legacy vaults that are proven by `pipass_master_hash` to have used PBKDF2

An explicit user-visible "compatibility mode" for PBKDF2 could be designed later, but it should not be the default. If it is ever added, metadata must record it at setup time and the UI must communicate the weaker local KDF posture honestly.

## 8. Existing-Vault Unlock Behaviour

Once `pipass_kdf_metadata` exists, unlock should not auto-switch algorithms.

Recommended unlock rule:

- valid metadata present: derive with exactly the recorded algorithm and parameters
- metadata missing: run the legacy detection flow once and write metadata only after hash verification
- metadata invalid or unsupported: fail closed with a recoverable error path; do not silently fall back to another algorithm

The unlock screen may still show the profile label from `profileIterations`, but the derivation code must treat the metadata parameters as authoritative.

If `pipass_security_profile` and `pipass_kdf_metadata.profileIterations` disagree, future implementation should prefer `pipass_kdf_metadata` for derivation and surface a safe repair prompt only after successful unlock.

## 9. PBKDF2 Fallback Policy

PBKDF2 fallback should become compatibility-only.

Recommended rules:

- new vault setup: Argon2id required
- existing vault with Argon2id metadata: PBKDF2 must not be tried automatically
- existing vault with PBKDF2 metadata: PBKDF2 is used intentionally
- legacy vault with no metadata: PBKDF2 may be tried only after explicit Argon2id verification fails
- password rotation from PBKDF2: derive old key with recorded PBKDF2 metadata, derive new key with Argon2id metadata unless the user explicitly chooses otherwise

This keeps existing users from being locked out while avoiding silent downgrade for new vaults.

## 10. Fractal Fingerprint Metadata Update

Fractal fingerprint records should represent the actual KDF metadata used to derive the master key.

Recommended next shape:

```json
{
  "version": 2,
  "fingerprint": "hex",
  "kdf": {
    "metadataVersion": 1,
    "algorithm": "argon2id",
    "profileIterations": 100000,
    "kdfVersion": "v1"
  },
  "fractalVersion": "hkdf-fractal-v1"
}
```

The fractal fingerprint remains visual/integrity metadata only. It must not become an authentication factor, KDF input, recovery proof, server trust signal, or encryption key.

For legacy fingerprint records:

- accept current version 1 records only after the unlock key has already been verified
- upgrade to version 2 after successful unlock and KDF metadata migration
- do not treat a fingerprint mismatch as proof of password failure

## 11. Password Rotation And Profile-Change Implications

Password rotation must treat KDF metadata as staged commit state.

A safe rotation flow should:

1. Load old KDF metadata.
2. Derive old shares with exactly the old metadata.
3. Verify old password with `pipass_master_hash`.
4. Create new KDF metadata for the new password/profile.
5. Derive new shares with the new metadata.
6. Re-encrypt all entries and secure notes.
7. Verify all rotated records decrypt with the new shares.
8. Sync server vault blob if server sync participates.
9. Only after successful verification/sync, commit `pipass_master_salt`, `pipass_security_profile`, `pipass_kdf_metadata`, `pipass_master_hash`, cached key, active shares, and fractal fingerprint metadata.

Profile change without password change is still a key-path change in the current architecture. It must follow the same staged re-encryption rules for populated vaults.

Prompt 030's short-term guard should remain until this transaction exists.

## 12. Root-Key Future Implications

A future vault-root-key model should separate:

- data-encryption metadata for entries and notes
- password-wrapping KDF metadata
- recovery-key wrapping metadata
- server authentication/session metadata

In that model, normal password changes should create new wrapping KDF metadata and rewrap the vault root key instead of re-encrypting all entries.

Recommended future wrapper metadata should include:

- wrapper version
- algorithm and parameters
- salt location or inline wrapping salt identifier
- device binding policy, if any
- wrapped root key ciphertext metadata
- creation/update timestamp

The current `pipass_kdf_metadata` can either become the password-wrapper metadata or be migrated into a more explicit `pipass_password_wrapper_metadata` key. That decision should happen during the root-key migration design, not during this metadata prompt.

## 13. Storage, Wipe, And Reset Behaviour

Recommended local storage key:

- `pipass_kdf_metadata`

Recommended owner:

- `workers/storageWorker.ts`

Recommended storage location:

- same platform storage abstraction as `pipass_security_profile`
- SecureStore on native
- localStorage on web

Wipe rules:

- vault lock: preserve
- local logout: preserve
- password/auth credential rotation: update only through staged commit
- profile change: update only through staged commit
- `clearVault()`: needs explicit product decision; preserving it matches current salt/profile behavior, deleting it matches current master-hash deletion behavior
- `destroyAllData()`: delete

Recommendation for `clearVault()`: preserve `pipass_kdf_metadata` initially because `clearVault()` currently preserves salt/profile/recovery/deviceUUID. A later reset-boundary prompt can decide whether clearing the master hash should also clear KDF metadata.

Server storage:

- do not send KDF metadata to the server by default
- do not store it in audit logs
- do not include it in vault blob metadata unless a future encrypted vault format explicitly needs local metadata inside the opaque encrypted blob

## 14. Test Plan

Before implementation, add tests for:

- new vault setup writes Argon2id metadata when Argon2id is available
- new vault setup fails without committing partial setup state when Argon2id is unavailable
- unlock with valid Argon2id metadata uses only Argon2id
- unlock with valid PBKDF2 metadata uses only PBKDF2
- legacy unlock with no metadata detects Argon2id and writes metadata after hash match
- legacy unlock with no metadata detects PBKDF2 and writes metadata after hash match
- legacy unlock writes no metadata when password/hash verification fails
- invalid metadata fails closed and does not silently switch algorithms
- metadata/profile disagreement prefers metadata for derivation after successful unlock
- nuclear reset deletes `pipass_kdf_metadata`
- logout and vault lock preserve `pipass_kdf_metadata`
- profile-change guard remains active for populated vaults until staged re-encryption exists
- fractal fingerprint version 2 records actual KDF metadata
- no logs include password, master key, key shares, raw cached key, recovery key, or derived key material

Implementation tests should mock Argon2id availability and failure explicitly. Tests must not depend on incidental runtime module loading.

## 15. Implementation Prompt Sequence

Recommended sequence:

1. Add explicit KDF mode helpers that can derive Argon2id or PBKDF2 without automatic fallback.
2. Add `pipass_kdf_metadata` read/write validation helpers.
3. Add tests for metadata parsing, wipe behavior, and invalid metadata handling.
4. Update new vault setup to require Argon2id and write metadata atomically with setup metadata.
5. Add legacy unlock detection and post-verification metadata migration.
6. Update fractal fingerprint record design to version 2.
7. Add tests for Argon2id/PBKDF2 legacy unlock migration.
8. Only then revisit profile change and password rotation staging.
9. Later, design root-key wrapper metadata separately.

Do not combine metadata implementation with password rotation, root-key migration, session-token work, auth credential rotation, or encryption algorithm changes.

## 16. Open Decisions

- Should `clearVault()` preserve or delete `pipass_kdf_metadata` when it deletes `pipass_master_hash`?
- Should web ever allow explicit PBKDF2 compatibility setup, or should Argon2id remain mandatory for all new vaults?
- Should KDF metadata include measured derivation duration for local diagnostics, or would that create noisy/irrelevant metadata?
- Should metadata include a platform field for troubleshooting, or would that invite unnecessary platform coupling?
- Should legacy migration attempt PBKDF2 after Argon2id failure only, or should it try both explicit candidates even when Argon2id matches and flag impossible ambiguity?
- Should future root-key wrapping reuse `pipass_kdf_metadata` or move to a more explicit wrapper metadata key?
