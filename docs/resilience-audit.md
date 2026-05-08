# PiPass — Resilience & State-Integrity Audit

**Date**: 2026-05-08  
**Scope**: All local mutation paths in client + credential write paths. No crypto, auth protocol, vault format, DB schema, or UI changes permitted.  
**Method**: Full file read of every writer of durable state, traced against crash/interrupt scenarios.

---

## Mutation Surface Map

Every durable write in the client, grouped by storage layer:

| Store | Key(s) | Writers |
|---|---|---|
| SecureStore (local) | `pipass_master_salt` | `saveMasterSalt()` — setup only |
| SecureStore (local) | `pipass_master_hash` | `saveMasterKeyHash()` — setup + `confirmProfileChange()` |
| SecureStore (local) | `pipass_security_profile` | `saveSecurityProfile()` — setup + `onIterationsChange()` |
| SecureStore (local) | `pipass_vault_initialized` | `setVaultInitialized()` — setup (last step) + `destroyAllData()` |
| SecureStore (local) | `pipass_vault_index` | `setVaultIndex()` — `saveEntry()`, `deleteEntry()`, `clearVault()` |
| SecureStore (local) | `pipass_vault_<id>` | `saveEntry()`, `updateEntry()`, `deleteEntry()`, `clearVault()`, profile re-encryption |
| SecureStore (local) | `pipass_note_index` | `setNotesIndex()` — `saveSecureNote()`, `deleteSecureNote()`, `clearAllNotes()` |
| SecureStore (local) | `pipass_note_<id>` | `saveSecureNote()`, `deleteSecureNote()`, `clearAllNotes()` |
| SecureStore (local) | `pipass_recovery_key_hash` | `saveRecoveryKeyHash()` — setup only |
| SecureStore (local) | `pipass_fractal_fingerprint` | `saveFractalFingerprint()` — setup + `confirmProfileChange()` |
| SecureStore (local) | `pipass_show_keyprints` | `saveShowKeyprints()` — settings toggle |
| SecureStore (local) | `pipass_shared_migration_done` | `migrateToSharedStorage()` — one-time on first load |
| Shared keychain group | `pipass_shared_vault` | `syncSharedVaultBlob()` — every `saveEntry/updateEntry/deleteEntry` |
| Keychain (native) | master key | `storeMasterKeySecurely()` — setup + `confirmProfileChange()` |
| SecureStore (local) | `pipass.auth.userId` | `setCredentials()`, `clearCredentials()` |
| SecureStore (local) | `pipass.auth.authHash` | `setCredentials()`, `clearCredentials()` |
| In-memory (module) | `activeShares` in `lib/vaultSession.ts` | `VaultScreen` only — set on unlock/profile change, cleared on lock |

**Confirmed safe (not listed in risks below):**
- `AppState` background-to-lock: guarded by `isBiometricActive.current` and `lockedRef.current` — no double-lock race.
- `deleteEntry` interrupted between step 1 (blob delete) and step 2 (index rewrite): self-healing — `getAllEntries()` silently skips null results, so the dangling index reference is invisible but harmless.
- `NuclearResetModal` multi-step guards: `executingRef`, `verifyingRef`, and `sessionRef` prevent fast-tap double-execution and stale async results.
- Auto-lock during undo snackbar: `commitPendingDeletion()` is called in the `useEffect` cleanup — unmount commits correctly.
- `setActiveKeyShares` previous-shares wipe: before replacing, `wipeShares(old)` is called if old ≠ new.
- Server-side vault sync: `WHERE version < newVersion` upsert in `storage.ts:syncVault` — version monotonicity is correct and race-safe.
- `selectTokenRef` in VaultScreen: prevents stale decrypt results from showing after lock/re-unlock cycle.

---

## Ranked Risk Register

### R1 — **CRITICAL** | Profile change destroys all existing vault entries

**File**: `screens/VaultScreen.tsx` — `confirmProfileChange()` lines 501–537  
**Confirmed by**: tracing `decryptVaultEntry(entry, keySharesRef.current)` after `confirmProfileChange()` completes in the same session.

**Runtime scenario**:

1. User has a vault with 10 entries, all encrypted with master key `K_old` (derived from `password + salt + 100 000 iterations`).
2. User opens Settings → switches to "Fortress" profile (500 000 iterations).
3. Enters current master password. `confirmProfileChange()` runs:
   - Derives `K_new = deriveMasterKey(password, salt, 500 000)` — a **different key** than `K_old`.
   - Saves `hash(K_new)` as the new unlock verification hash.
   - Saves 500 000 as the security profile.
   - Updates `keySharesRef.current` to `newShares` (derived from `K_new`).
   - Existing vault entries on disk are **still encrypted with HKDF subkeys of `K_old`**.
4. User taps any existing entry — `decryptVaultEntry(entry, newShares)` derives the per-entry key from `K_new` → MAC verification fails → `"Authentication failed — data may be tampered"`.
5. **Every existing entry is permanently inaccessible.** The old iterations value is gone (overwritten by `saveSecurityProfile`). There is no recovery path.

**Why it wasn't caught earlier**: The in-session symptoms are immediately visible (decryption errors after profile change), but the function has no test coverage and the error message ("tampered data") obscures the root cause.

**Minimal fix** (implemented — see Fixes section): re-encrypt all entries and notes in memory using the old key before writing a single byte of new metadata. Only commit to storage after all re-encryption succeeds. If decryption fails (wrong password), abort with no writes.

---

### R2 — **HIGH** | Vault setup sequence: `setVaultInitialized(true)` deferred past 5 unguarded writes

**File**: `app/(tabs)/index.tsx` — `SeedSetupScreen.onSetup` callback lines 140–162  
**Confirmed by**: reading the write sequence against the `isVaultInitialized()` check at startup.

**Runtime scenario**:

1. First launch. User completes the setup wizard. The callback fires:
   - `saveMasterSalt(salt)` ← write 1
   - `saveMasterKeyHash(keyHash)` ← write 2
   - `saveSecurityProfile(iters)` ← write 3
   - `saveRecoveryKeyHash(keyHashRecovery)` ← write 4
   - `storeMasterKeySecurely(keyHex)` ← write 5
   - Shows `RecoveryKeyModal`. User sees recovery key.
   - User taps "I've saved it" → `setVaultInitialized(true)` ← write 6 (THE ONLY ONE THAT GATEKEEPS STARTUP)
2. App crashes between write 5 and write 6 (background kill, OS memory pressure, battery pull).
3. On next launch: `isVaultInitialized()` returns `false` → `vaultExists` is `false` → startup shows `SeedSetupScreen`.
4. User creates a **new** vault with a different password. Writes 1–5 execute again, overwriting the old salt/hash/profile.
5. If the user had imported entries before completing setup (see R3), those entries are now encrypted under a key that no longer exists.
6. If the user creates the same password again, the new key will be different (different random salt) and entries remain inaccessible.

**Residual severity even with fix**: Without a transactional store, a fully atomic recovery is impossible at this layer. The risk window is small (only during the recovery key display), but data loss is permanent.

**Minimal fix** (not implemented — requires flow change): Write `pipass_vault_initialized = "pending"` as the **first** write in the setup sequence, and `"1"` as the **last**. On startup, treat `"pending"` as not initialized but offer a "Continue Setup" path if salt + hash already exist. Flag raised for a future task.

---

### R3 — **HIGH** | Import-before-setup: entries saved before master key exists

**File**: `screens/SeedSetupScreen.tsx` — `handleImport()` (import from backup)  
**Confirmed by**: tracing `saveEntry()` call in import path against `deriveMasterKeyShares` / `setVaultInitialized` order.

**Runtime scenario**:

1. New user imports a backup file. `saveEntry()` is called for each entry (they arrive as already-encrypted blobs keyed to the backup vault's master key — correct behavior).
2. App crashes before the user sets a master password and completes setup.
3. On next launch: `isVaultInitialized()` is `false` → shows `SeedSetupScreen`.
4. The vault index now contains IDs for all imported entries.
5. User creates a new vault with a new password → the imported entries are in the index but encrypted with the old key. `getAllEntries()` returns them, decryption fails silently per entry.
6. Entries appear in the list (title/username visible as stored) but passwords cannot be decrypted.

**Actual severity**: Lower than R1/R2 in practice — the user would only import as their first action, the entries are encrypted under their OLD key (which they know), and they can re-import after setup completes. Not a silent data loss, but a confusing state.

**Minimal fix**: No code change recommended here — the entries are not corrupted, just orphaned. On a clean re-install the user can re-import successfully. Adding a `destroyAllData()` call at the start of `SeedSetupScreen` would fix this but has its own risks (wipes a legitimate partial vault). Flag for UX review.

---

### R4 — **MEDIUM** | Null `masterSalt` causes crash in `UnlockScreen` after partial `destroyAllData()`

**File**: `app/(tabs)/index.tsx` line 170 — `<UnlockScreen salt={masterSalt!} .../>`  
**Confirmed by**: tracing `destroyAllData()` sequence against startup state machine.

**Runtime scenario**:

1. User initiates Nuclear Reset. `destroyAllData()` runs ~10 sequential `deleteItem` calls.
2. App is killed between `deleteItem(MASTER_SALT_KEY)` (step 3 in `destroyAllData`) and `deleteItem(VAULT_INITIALIZED_KEY)` (step 6).
3. On next launch:
   - `isVaultInitialized()` returns `true` (key not yet deleted) → `vaultExists = true`.
   - `getMasterSalt()` returns `null` (already deleted) → `masterSalt = null`.
   - `vaultExists && !keyShares && !vaultLocked` → renders `<UnlockScreen salt={null!} .../>`.
   - `UnlockScreen` passes `null` as `salt` to `deriveMasterKeyShares(password, null, iterations)` → `deriveMasterKey(password, null, ...)` → Argon2id / PBKDF2 with null salt → **unhandled error or undefined behavior → crash**.
4. App restart loops: every launch hits the same crash.

**Minimal fix** (implemented — see Fixes section): guard the `UnlockScreen` render path with an explicit null check on `masterSalt`. If null while `vaultExists` is true, show a "vault metadata corrupted" recovery view offering `destroyAllData()` to clear the stuck state.

---

### R5 — **MEDIUM** | `saveEntry()` three-step write: new entry invisible if interrupted between step 1 and 2

**File**: `workers/storageWorker.ts` — `saveEntry()` lines 89–99  
**Confirmed by**: tracing write order against `getAllEntries()` index iteration.

**Write order**:
1. `setItem(VAULT_KEY_PREFIX + entry.id, JSON.stringify(entry))` — entry blob written  
2. `getVaultIndex()` — index read  
3. `setVaultIndex([...index, entry.id])` — index updated  
4. `syncSharedVaultBlob()` — shared blob updated  

**Runtime scenario**:

App terminates between step 1 and step 3. On next launch:
- Entry blob exists in SecureStore under `pipass_vault_<id>`.
- Vault index does **not** contain `entry.id`.
- `getAllEntries()` iterates the index → entry is not returned.
- The entry is **permanently invisible**. It cannot be recovered without knowing its exact `id`, which is not displayed anywhere in the UI.
- The user believes they saved the entry but it is gone.

**Why not self-healing**: Unlike `deleteEntry` (where an interrupted delete leaves a dangling index reference that `getAllEntries()` silently skips), `saveEntry` leaves an invisible blob. There is no mechanism to scan for orphaned `pipass_vault_*` keys because `expo-secure-store` does not expose key enumeration.

**Minimal fix** (not implemented — requires index-first write order): Swap step 1 and step 3: write the index with the new id **first**, then write the entry blob. If interrupted between index write and blob write, `getAllEntries()` returns null for the id (silently skipped, self-healing). A dangling index reference is less harmful than an invisible blob. Flagged for a future task — the write order reversal requires careful testing.

---

### R6 — **LOW** | `setCredentials()` two-step write: partial write causes one unexpected logout

**File**: `lib/credentials.ts` — `setCredentials()` lines ~38–42  
**Confirmed by**: reading `getCredentials()` null-guard logic.

**Write order**: `writeItem(USER_ID_KEY, creds.userId)` → `writeItem(AUTH_HASH_KEY, creds.authHash)`

**Runtime scenario**: App terminates between the two writes. On next launch, `getCredentials()` reads both — finds `userId` but `authHash` is null → clears both → returns null → user is prompted to log in again → re-login succeeds → credentials restored. **Self-healing after one login.**

**Severity**: LOW — no data loss, no security issue, one extra login.

**Minimal fix**: Not warranted given self-healing nature. Could be mitigated by writing `authHash` first (if interrupted, `userId` is missing → same null-return behavior) but the outcome is identical.

---

### R7 — **LOW** | Shared vault blob hardcodes `version: 1` — no monotonic versioning for autofill copy

**File**: `workers/sharedVaultStorage.ts` — `syncSharedVaultBlob()` and `migrateToSharedStorage()`  
**Confirmed by**: full read of `sharedVaultStorage.ts`.

**Issue**: The shared vault blob (written to the shared keychain access group for the iOS AutoFill extension) always sets `version: 1` and `Date.now()`. The `version` field has a validator that checks `parsed.version === 1` — so it can never be incremented without a validator change. This is not the server vault version.

**Impact**: Current code has one writer (main app) and one reader (AutoFill extension). No conflict scenario exists. If a future path adds a second writer, last-write-wins with `updatedAt` timestamp comparison, with no monotonic version guard.

**Minimal fix**: Not warranted now. If a second writer is ever added, increment `version` and update the validator.

---

### R8 — **LOW** | `destroyAllData()` partial wipe leaves metadata residue (secondary risk from R4 scenario)

**File**: `workers/storageWorker.ts` — `destroyAllData()` ~10 sequential `deleteItem` calls  
**Confirmed by**: tracing the delete sequence and startup state machine.

**Distinct from R4**: R4 is the crash scenario; this is the observation that even a **complete** `destroyAllData()` that runs to the end still leaves some data behind (e.g., the shared keychain blob `pipass_shared_vault` is cleared via `clearSharedVault()`, but if that call fails silently, the AutoFill extension retains the old vault data until the next write). No security implication because the blob is accessible only to the app and its extension (same entitlement group), but the autofill extension could show stale credentials after a reset.

**Minimal fix**: Add a post-`destroyAllData()` `clearSharedVault()` call with explicit error handling. Already partially present — `clearVault()` calls `syncSharedVaultBlob()` with an empty entries list, which should overwrite the shared blob. Low priority.

---

### R9 — **INFO** | No client→server vault sync from VaultScreen

**Confirmed by**: grepping all `authedApiRequest` usages — none in `VaultScreen.tsx`, `storageWorker.ts`, or `vaultWorker.ts`. The only client code that calls `/api/vault/sync` is `server/__tests__/security.test.ts` (test-only direct HTTP calls).

**Implication**: The `/api/vault/sync` and `/api/vault/fetch` endpoints exist on the backend and are fully implemented, but the client never calls them for day-to-day vault operations. All vault data lives only in local `expo-secure-store`.

**Impact**: Device loss or wipe = permanent vault data loss. The server-side vault history, version monotonicity, and conflict detection features are fully built but currently unreachable from the UI. The recovery key and Shamir share features exist but there is no restore flow that reads from the server.

**This is a missing feature, not a bug.** It is outside the scope of this audit. Flagged for a future implementation task.

---

## Fixes Implemented in This Audit

### Fix 1 (R1): `confirmProfileChange()` — re-encrypt before committing

**File**: `screens/VaultScreen.tsx`  
**Change**: All existing entries and notes are re-encrypted in memory using the **old** key shares before any metadata write. If decryption fails (wrong password), the function aborts with no writes and no state change. Only after all in-memory re-encryption succeeds are the blobs written to storage, followed by the new key hash and iterations. See the code change for the exact sequence.

**Invariant preserved**: At no point does the stored key hash diverge from the key used to encrypt stored entries.

### Fix 2 (R4): `UnlockScreen` null-guard on `masterSalt`

**File**: `app/(tabs)/index.tsx`  
**Change**: Before rendering `UnlockScreen`, `masterSalt` is checked for null. If null while `vaultExists` is true (indicating a corrupted or partially-wiped metadata state), a recovery view is shown instead of crashing. The recovery view offers `destroyAllData()` to clear the stuck state and restart.

---

## Recommended Follow-up Tasks (Not Implemented Here)

| ID | Severity | Description |
|---|---|---|
| FU-1 | HIGH | R2: Write `pipass_vault_initialized = "pending"` as the first write in setup and `"1"` as the last; detect `"pending"` on startup and offer a continue/clear recovery path. |
| FU-2 | MEDIUM | R5: Reverse `saveEntry()` write order — index first, then entry blob — so an interrupted save leaves a self-healing dangling reference instead of an invisible orphaned blob. |
| FU-3 | HIGH | R9: Implement client→server vault sync (`POST /api/vault/sync` + `GET /api/vault/fetch`) in `VaultScreen` so vault data survives device loss. The backend is fully ready. |
| FU-4 | MEDIUM | Add a startup self-repair pass: after `getAllEntries()`, strip any index IDs that return null blobs, and re-write the index if it changed. |

---

## Test Scenarios (Manual)

| Scenario | Expected |
|---|---|
| Change security profile (iterations) with existing entries | All entries still decrypt after profile change |
| Change security profile with wrong password | Alert "Migration Failed", entries unchanged, profile unchanged |
| Relaunch after profile change | Unlock succeeds with the same password; all entries accessible |
| Open app with `masterSalt = null` and `vaultExists = true` | Shows "Vault Metadata Corrupted" recovery view, not a crash |
| `destroyAllData()` followed by fresh setup | No residual metadata; setup completes normally |
| Add entry, kill app during save, relaunch | Entry may be missing (R5 not yet fixed); no crash or index corruption |
| Import entries, kill before setup completes, relaunch | Shows setup screen; re-import and complete setup — entries accessible |
