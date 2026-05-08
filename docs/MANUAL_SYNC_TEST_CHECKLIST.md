# PiPass — Manual Sync & Functionality Test Checklist

**App version checkpoint:** Stage 1 upload + Stage 2A restore + Stage 2B additive import  
**Backend:** Neon/PostgreSQL via Express (port 5000)  
**Frontend:** Expo web preview (port 8081) or Expo Go on physical device  
**Date of test:** _______________  
**Tester:** _______________

---

## ⛔ Stop Immediately If This Happens

These outcomes indicate a data-loss or security bug. Stop testing, preserve logs, and do not continue until the root cause is found.

| Condition | Why it matters |
|---|---|
| An existing local entry disappears after login | Stage 2A/2B wrote over a non-empty vault — critical invariant broken |
| An entry imported via Stage 2B shows different content than the remote source | Decryption produced wrong plaintext — key or HKDF bug |
| The unlock screen appears but the vault is empty after a previous successful add | Local storage was wiped unexpectedly |
| The server returns plaintext password or plaintext vault entry in any API response | Zero-knowledge invariant broken |
| `authHash` appears in the terminal backend log | Secret leaked into logs |
| Nuclear reset wipes data without the user completing the full confirmation flow | Accidental data destruction |
| Two entries with the same ID and different content both appear after Stage 2B import | Conflict was auto-merged instead of kept-local |

---

## Prerequisites

- Both workflows running (`Start Backend` on port 5000, `Start Frontend` on port 8081).
- A clean test username ready (e.g. `testuser_<date>`). Using a fresh username avoids leftover Neon rows from prior runs.
- Neon console or `psql` access for DB verification steps (optional but recommended).
- Browser devtools (Network tab) or `curl` available.
- Two browser profiles or two devices available for conflict/multi-device scenarios (optional).

### Quick backend smoke test (run before starting)
```bash
curl -s http://localhost:5000/api/health
# Expected: {"status":"ok"} or {"ok":true} — any 200 response
```

---

## Pass / Fail Summary Table

Fill in after running all scenarios.

| # | Scenario | Pass | Fail | Notes |
|---|---|---|---|---|
| 1 | First-run setup | | | |
| 2 | Lock / unlock cycle | | | |
| 3 | Add entry | | | |
| 4 | Delete entry with undo | | | |
| 5 | Secure notes save / delete | | | |
| 6 | Backend registration & login | | | |
| 7 | Device trust | | | |
| 8 | Stage 1 upload-only sync | | | |
| 9 | Stage 2A empty-vault restore | | | |
| 10 | Stage 2B additive import (approve) | | | |
| 11 | Stage 2B additive import (cancel) | | | |
| 12 | Stage 2B conflict behaviour | | | |
| 13 | Offline / backend unreachable | | | |
| 14 | Nuclear reset | | | |
| 15 | App restart persistence | | | |

---

## Scenario 1 — First-Run Setup

**Goal:** New user can complete setup and reach the vault screen.

### Steps
1. Open the app with a fresh browser profile (or clear localStorage: `localStorage.clear()` in devtools console, then refresh).
2. Observe: `AuthScreen` appears (biometric gate). On web, biometric auto-passes.
3. Observe: `SeedSetupScreen` appears (first-run master password setup).
4. Enter a strong test password (e.g. `TestPass!123`). Confirm it.
5. Tap **Create Vault**.
6. Note the **Recovery Key** displayed. Write it down or screenshot it.
7. Tap **I've saved my recovery key**.
8. Observe: `VaultScreen` appears, empty entry list.

### Expected
- No network errors in browser console.
- Vault is empty.
- Backend log shows NO request yet (registration happens only on first login attempt, not setup).

### Must NOT happen
- Setup completes without showing the recovery key.
- Vault shows pre-existing entries from a previous session.

---

## Scenario 2 — Lock / Unlock Cycle

**Goal:** Auto-lock and manual lock work; unlock restores the session without backend login.

### Steps
1. From an unlocked vault, tap the **lock** button (or wait 2 minutes idle for auto-lock).
2. Observe: `UnlockScreen` overlay appears over the vault. Vault list is not visible.
3. Enter the master password. Tap **Unlock**.
4. Observe: Vault list reappears. No network request to `/api/auth/login` should fire (re-unlock is local-only).

### Evidence
- Open browser Network tab before step 3. Confirm no `/api/auth/login` call is made on re-unlock.

### Expected
- Unlock is instant (no key-derivation spinner unless Argon2id is running).
- Previous entries are visible immediately after unlock.

### Must NOT happen
- Re-unlock calls `/api/auth/login` (that path is only for the initial post-setup login).
- Vault is empty after unlock when entries existed before lock.

---

## Scenario 3 — Add Entry

**Goal:** A new credential entry is saved locally and immediately visible.

### Steps
1. From unlocked vault, tap **+** (Add Entry).
2. Fill in: Title = `Test Site`, Username = `user@example.com`, Password = `hunter2`, URL = `https://example.com`.
3. Confirm password field. Tap **Save**.
4. Observe: Entry appears in vault list with title `Test Site`.
5. Tap the entry to open `EntryDetailModal`. Confirm all fields decrypt correctly.
6. Check: backend terminal shows no vault sync yet (sync fires only after save; look for `POST /api/vault/sync`).

### Evidence
- Screenshot of vault list showing the new entry.
- Backend terminal: `POST /api/vault/sync 200` (or 403 if device not yet trusted — see Scenario 7).

### Expected
- Entry appears immediately.
- If backend is reachable and device trusted: sync fires within a second. Backend log: `POST /api/vault/sync 200 in Xms`.

### Must NOT happen
- Password visible in plaintext anywhere in the backend log.
- Save fails silently (entry not added to list).

---

## Scenario 4 — Delete Entry with Undo

**Goal:** Deletion is soft-deletable within the 10-second window and permanent after.

### Steps
1. Long-press or tap the delete affordance on an entry (overflow menu → Delete).
2. Confirm the Alert. Complete biometric (auto-passes on web).
3. Type `DELETE` in the confirmation modal. Tap confirm.
4. Observe: Snackbar appears at the bottom ("Undo" button visible, ~10 seconds).
5. **Undo path**: Tap **Undo** before the timer expires. Observe: entry reappears. ✓
6. Repeat steps 1–4. Let the timer expire without tapping Undo.
7. Observe: entry is gone from the list permanently. Backend sync fires.

### Expected
- Entry reappears cleanly after Undo.
- After timer expiry, entry is gone. Backend log shows another `POST /api/vault/sync 200`.

### Must NOT happen
- Entry is immediately deleted without showing the snackbar.
- Undo restores entry but a duplicate also appears.

---

## Scenario 5 — Secure Notes Save / Delete

**Goal:** Notes are encrypted and stored independently of vault entries.

### Steps
1. From vault, open **Secure Notes** (button or tab in VaultScreen).
2. Tap **+**, enter Label = `Bank PIN`, Content = `1234`. Tap Save.
3. Observe: note appears in the notes list.
4. Tap the note. Confirm label and content are correct.
5. Delete the note. Confirm it disappears.

### Expected
- Notes appear and decrypt correctly.
- Backend sync fires after add and after delete (`POST /api/vault/sync 200` × 2).

### Must NOT happen
- Note content appears in plaintext in the backend log.

---

## Scenario 6 — Backend Registration & Login

**Goal:** First-time backend registration and login succeed; credentials are stored.

### Steps
1. From a setup vault (Scenario 1 complete, no prior login), tap any action that triggers a backend login (e.g. the app may auto-login post-setup — check the network tab, or trigger by re-opening the app).
2. If registration hasn't happened: in the app's unlock flow, the first successful unlock triggers `POST /api/auth/login`. If the account doesn't exist yet it auto-registers via `POST /api/auth/register`.
3. Observe network tab: `POST /api/auth/register` → 201, then `POST /api/auth/login` → 200.

#### Curl verification (optional, use your test credentials)
```bash
# Check salt endpoint — returns dummy salt for unknown users too
curl -s "http://localhost:5000/api/auth/salt/testuser_20260508"

# Register
curl -s -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_20260508","authHash":"<64-char-hex>","salt":"<64-char-hex>","iterations":100000}'
# Expected: 201 {"id":"<uuid>","username":"testuser_20260508","salt":"...","iterations":100000}

# Login
curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_20260508","authHash":"<same-hex>","salt":"<same-hex>","iterations":100000}'
# Expected: 200 {"id":"<uuid>",...}
```

### Expected
- Registration returns 201 with a UUID.
- Login returns 200.
- Backend log never contains the raw `authHash` value.

### Negative tests
```bash
# Wrong authHash → 401
curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_20260508","authHash":"0000000000000000000000000000000000000000000000000000000000000000","salt":"<real-salt>","iterations":100000}'
# Expected: 401 {"error":"Invalid credentials"}

# Unknown user → same 401 (no enumeration)
curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nobody_xyzzy","authHash":"0000000000000000000000000000000000000000000000000000000000000000","salt":"aaaa","iterations":100000}'
# Expected: 401 {"error":"Invalid credentials"} — identical to wrong-password response

# Extra field → 400 strict mode
curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"x","authHash":"y","salt":"z","iterations":3,"extra":"bad"}'
# Expected: 400 {"error":"Unknown field"}
```

### Must NOT happen
- `authHash` value appears anywhere in the backend terminal output.
- "Unknown user" and "wrong password" return different responses (enumeration).

---

## Scenario 7 — Device Trust

**Goal:** A new device/session starts untrusted and is blocked from sync until approved.

### Steps
1. Log into the app on a **second browser profile** (or private window) using the same credentials.
2. Try to add an entry and trigger a sync.
3. Observe: backend returns **403** for `POST /api/vault/sync`. The app should show a device-trust banner or silently defer sync.
4. Approve the device from the app UI (Settings → Trust this device, or the in-app banner).
5. Observe: `POST /api/auth/trust-device` → 200.
6. Retry adding an entry. Observe: `POST /api/vault/sync` → 200.

### Evidence
- Network tab showing the 403 before approval and 200 after.

### Must NOT happen
- An untrusted device successfully uploads or overwrites the vault blob.
- Trust approval has no effect (still 403 after approval).

---

## Scenario 8 — Stage 1 Upload-Only Sync

**Goal:** Every local vault mutation triggers an encrypted upload to Neon.

### Steps
1. From a logged-in, trusted session, add a new entry (`Entry A`).
2. Watch backend terminal: expect `POST /api/vault/sync 200 in Xms`.
3. Check Neon (optional):
   ```sql
   SELECT version, length(encrypted_blob), updated_at
   FROM vault_blobs
   WHERE user_id = '<your-uuid>';
   ```
   - `version` should have incremented.
   - `length(encrypted_blob)` should be non-zero.
   - `encrypted_blob` should be unreadable ciphertext, not JSON.
4. Add another entry (`Entry B`). Verify version increments again.
5. Delete `Entry A`. Verify version increments again.

### Expected
- `version` goes up by 1 (or more) with each mutation.
- `encrypted_blob` is always ciphertext — never a JSON object with visible passwords.

### Must NOT happen
- `encrypted_blob` contains readable text like `{"entries":[{"password":"hunter2"` — would indicate missing encryption.
- `version` stays the same after a mutation (upload silently failed and swallowed the error without updating).

---

## Scenario 9 — Stage 2A Empty-Vault Restore

**Goal:** After logging into a fresh device with an empty vault, the remote backup is restored automatically, without user prompts.

### Steps
1. Ensure the account has at least one entry synced to Neon (complete Scenario 8 first).
2. **Simulate a new device**: In devtools console, clear only vault and credential storage:
   ```js
   // Clear vault + credentials but leave the master-password derivation params
   // (easiest: just clear all localStorage for the origin)
   localStorage.clear();
   location.reload();
   ```
3. On reload: complete biometric gate (`AuthScreen`).
4. Since `VAULT_INITIALIZED_KEY` is gone, `SeedSetupScreen` appears again — **do NOT create a new vault**. Instead, observe whether the app offers a "restore" or "existing account" path.
   - **If the app asks for credentials directly** (UnlockScreen appears after detecting existing server account): enter the same master password and username.
5. After unlock + backend login: wait ~1-2 seconds.
6. Observe: vault entries that were synced in Scenario 8 should appear **without any user prompt**.

> **Note:** The exact flow depends on whether the onboarding UI has an explicit "I already have an account" branch. If not, the Stage 2A restore fires automatically during the post-login IIFE whenever local vault is empty.

### Expected
- Entries appear silently (no import Alert).
- Backend log: `GET /api/vault/fetch 200`.
- `pipass_sync_last_version` is set in localStorage after restore.

### Must NOT happen
- The Stage 2A prompt asks the user for approval (it should be silent — approval is only for Stage 2B).
- Entries from Scenario 8 do not reappear (restore failed silently with no fallback).
- Any new entry added during the clear window is silently overwritten.

---

## Scenario 10 — Stage 2B Additive Import (Approve)

**Goal:** When a non-empty local vault logs in and the remote has additional entries, an import prompt appears and approved entries are added additively.

### Setup
You need two accounts' worth of data, or simulate by using two browser profiles that share one PiPass account and diverge:

**Setup steps:**
1. **Profile A**: Log in, add `Entry A` (syncs to Neon). Note the version.
2. **Profile B** (second browser, same credentials): Log in. At this point Profile B has `Entry A` restored (Stage 2A or already present). Add `Entry B` on Profile B — this syncs `Entry A + Entry B` to Neon.
3. **Back on Profile A**: Profile A still has only `Entry A` locally. Now **lock and re-login** on Profile A (to re-trigger the post-login IIFE).
4. After login on Profile A: since `Entry B` is remote-only, an **Alert** should appear.

### Steps
5. Observe Alert: title "Import from Cloud?", body lists `Entry B`, mentions importing will only add items and will not change existing ones.
6. Tap **Import N** (where N = 1).
7. Observe: `Entry B` appears in Profile A's vault. `Entry A` is unchanged.
8. Backend log: `GET /api/vault/fetch 200`, then `POST /api/vault/sync 200` (push merged state back).

### Evidence
- Screenshot of the import Alert showing correct entry names.
- Screenshot of vault after import showing both `Entry A` and `Entry B`.
- Neon query confirming version incremented after the merge-upload.

### Must NOT happen
- Alert does not appear (import silently auto-applied without user consent).
- `Entry A` is modified or deleted after import.
- Alert shows a different entry name than `Entry B`.
- Import fires repeatedly on every unlock (watermark not advancing).

---

## Scenario 11 — Stage 2B Additive Import (Cancel)

**Goal:** Tapping Cancel on the import Alert writes nothing.

### Steps
1. Set up the same diverged state as Scenario 10 (remote-only `Entry B`).
2. Alert appears. Tap **Cancel**.
3. Observe: Alert dismisses. Only `Entry A` is in the local vault.
4. Check localStorage: `pipass_sync_last_version` should NOT have advanced (the watermark only advances on successful import or "no-changes").
5. Lock and re-login. Observe: Alert appears again (same remote-only entry still pending).

### Expected
- Zero vault writes after Cancel.
- No `POST /api/vault/sync` after Cancel.

### Must NOT happen
- `Entry B` appears in the vault without the user tapping Import.
- App crashes or hangs after Cancel.

---

## Scenario 12 — Conflict Behaviour

**Goal:** An entry with the same ID but different ciphertext on the remote is never imported; local version is kept.

### How to simulate a conflict
This is hard to force naturally (requires the same entry ID on two devices with different passwords). The closest approximation without a second device:

1. Add `Entry A` on Profile A (syncs to Neon, gets an ID like `abc123`).
2. On Profile A, **edit** `Entry A`'s password to a new value. This syncs. Remote now has the new value.
3. **Simulate stale local state**: manually lower the `pipass_sync_last_version` in localStorage to 0:
   ```js
   localStorage.setItem('pipass_sync_last_version', '0');
   ```
4. Lock and re-login. `planVaultMerge` now re-fetches the remote blob.
5. Since `Entry A` exists locally with a different (older) ciphertext, it should be counted as a **conflict** — not offered in the import Alert.

### Expected
- If only conflicts exist (no remote-only entries): no Alert appears (silent no-changes path, watermark advances).
- If the Alert does appear (because there are also remote-only entries): conflict count is shown as informational text. The conflicted entry is NOT in the import list.
- Local `Entry A` remains exactly as it was (local wins).

### Must NOT happen
- Conflicted entry appears in the import Alert as an import candidate.
- Local `Entry A` is overwritten with the remote version without user action.

---

## Scenario 13 — Offline / Backend Unreachable

**Goal:** Vault is fully usable without a backend connection.

### Steps
1. Open app in a fully working state (vault unlocked, entries visible).
2. Stop the backend: kill or stop the `Start Backend` workflow.
3. Add a new entry. Observe: entry appears in the local vault list immediately.
4. Backend terminal: sync attempt fires and fails silently (no crash, no error modal).
5. Delete an entry. Observe: deletion works locally with the undo snackbar.
6. Lock the vault. Unlock with master password. Observe: vault re-opens with all local entries (no backend call needed for local unlock).
7. Restart the backend. Add another entry. Observe: sync resumes and `POST /api/vault/sync 200` appears in the backend terminal.

### Expected
- No crash or error modal on any local operation while backend is down.
- No "loading" spinner that blocks the UI indefinitely.
- All local mutations are preserved; when backend comes back, next mutation syncs successfully.

### Must NOT happen
- App crashes or freezes when the backend is unreachable.
- Vault entries disappear because sync failed.
- Unlock is blocked waiting for a backend response.

---

## Scenario 14 — Nuclear Reset

**Goal:** The nuclear reset flow destroys all local data after the full confirmation sequence.

### Steps
1. From the vault, access **Settings** → **Nuclear Reset** (or the secret tap sequence if applicable).
2. Read the warning screen. Tap **Continue**.
3. Enter the master password when prompted.
4. Type the exact phrase `DELETE MY VAULT` in the confirmation field.
5. Wait for the 10-second countdown to complete.
6. Complete biometric (auto-passes on web).
7. Observe: app returns to `SeedSetupScreen` (as if first run).
8. Check localStorage: all `pipass_*` keys should be gone:
   ```js
   Object.keys(localStorage).filter(k => k.startsWith('pipass_'));
   // Expected: []
   ```

### Expected
- All vault entries, notes, master salt, key hash, recovery key hash, and sync watermark are wiped.
- No network call is made during reset (reset is local only).
- App is in a clean first-run state.

### Must NOT happen
- Reset completes without the password + phrase + countdown + biometric sequence (any step skipped = bug).
- Some `pipass_*` keys remain in localStorage after reset.
- App crashes during reset and leaves partial state.

---

## Scenario 15 — App Restart Persistence

**Goal:** Local vault survives a full app reload (browser refresh / Expo app restart).

### Steps
1. From a working vault: add two entries. Note their titles.
2. Hard-refresh the browser (`Ctrl+Shift+R` / `Cmd+Shift+R`) or kill and reopen the Expo Go app.
3. Complete `AuthScreen` biometric (auto-passes on web).
4. Complete `UnlockScreen` with master password.
5. Observe: vault shows the same two entries.
6. Open each entry. Confirm all fields decrypt correctly.

### Expected
- All entries survive a full restart.
- Decryption succeeds (correct key derived from same password + stored salt).

### Must NOT happen
- Vault is empty after restart.
- Decryption fails with "Authentication failed" error.
- App crashes on restart.

---

## Evidence Collection Reference

| Evidence type | How to collect |
|---|---|
| Backend log line | Copy terminal output — format: `POST /api/vault/sync 200 in 12ms` |
| Network request | Browser devtools → Network tab → filter by `/api/` |
| localStorage state | `Object.entries(localStorage).filter(([k])=>k.startsWith('pipass_'))` in console |
| Neon DB check | `SELECT version, updated_at, length(encrypted_blob) FROM vault_blobs WHERE user_id='<uuid>';` |
| Backend secret-leak check | `grep -i "authHash\|password\|encryptedBlob" <backend-log-file>` — should return 0 hits |
| TypeScript clean | `npx tsc --noEmit` — should exit 0 |
| Screenshot | Browser screenshot or device screenshot at the moment of each UI state |

---

## Risk Notes

| Risk | Mitigation during testing |
|---|---|
| Using a production Neon DB for tests | Create a dedicated test username (e.g. `testuser_<date>`) — reset rows: `DELETE FROM vault_blobs WHERE user_id IN (SELECT id FROM users WHERE username LIKE 'testuser_%');` |
| localStorage.clear() deletes non-PiPass keys | Only run in a dedicated test browser profile |
| Reducing `pipass_sync_last_version` to 0 manually | Reset it after the test: `localStorage.setItem('pipass_sync_last_version', '<real-version>')` or re-login naturally |
| Nuclear reset in a real-data session | Always use a dedicated test account and test device/profile |
| Testing with real passwords | Use obviously fake passwords (`hunter2`, `TestPass!123`) during testing |
