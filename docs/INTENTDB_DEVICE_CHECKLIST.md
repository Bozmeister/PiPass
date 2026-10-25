# IntentDB device test checklist

Use this on a physical Android device before a Play track. The default build leaves every IntentDB flag unset. Unlock and search are on the vault screen. Item upload, receipt verification, bot move, replicate, envelope migration, and account delete are helpers. The vault screen does not call them. Exercise those helpers from a separate debug build. Do not ship that debug build to production.

Record the build's `versionCode`, the flag set, and pass or fail for each step.

## 0. Build under test

- Play candidate: no `EXPO_PUBLIC_INTENTDB_*` value and no `EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE`. Confirm `.env` and the EAS profile do not set them to `1`.
- Debug candidate: a second install with one flag set to `1` at a time, unless a step below says to combine flags.
- `EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY` is a pin, not a feature switch. Leave it unset on the Play candidate.

## 1. Unlock

1. Install the Play candidate. Create a vault or unlock an existing one with the master password.
2. Confirm the entry list appears and a biometric prompt is required again for a destructive action.
3. In logcat, find one line that starts with `intentdb status`.
4. Pass: `upload=0 delete=0 bot=0 envelope=0 verify=0`. `searchIndex` is `1` after the local index is stored, and `0` if that write did not happen. The line contains no master password, session token, vault-key proof, or key hex.
5. Lock the vault. Pass: the list is cleared and the search box is gone.
6. Unlock again. Pass: the same entries return. A failed search-index rebuild still shows the list.

## 2. Search and sort with many entries

1. Add at least 20 entries. Use titles that sort differently from insertion order, including `citrus`, `Apple`, and `banana`, plus numbered titles.
2. Give one entry a unique username, one a unique URL, and one a unique notes string. Put a unique password on another entry.
3. Stay unlocked. Pass: the field placeholder is `Search vault`, and the sort controls are `None`, `A-Z`, and `Z-A`.
4. Empty query and `None`. Pass: the list order matches the order before you searched.
5. `A-Z`. Pass: `Apple`, then `banana`, then `citrus`, then the numbered titles. Matching titles ignore case.
6. `Z-A`. Pass: the reverse of that title order.
7. Search the unique username, then the URL, then a notes fragment. Pass: only the matching row remains.
8. Search the unique password. Pass: `No matches`. Passwords are not in the index.
9. Search a string that matches nothing. Pass: `No matches`, and the vault is not empty.
10. Clear the query and set sort back to `None`. Pass: the full list returns.
11. Turn on airplane mode and repeat steps 4–6. Pass: search still works. It does not use the network.

## 3. Optional flag enablement

1. On the Play candidate, repeat the unlock log check. Pass: upload, delete, bot, envelope, and verify are all `0`.
2. Install the debug build with only `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1`. Unlock. Pass: `upload=1` and the other switches `0`.
3. Repeat with only `EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE=1`. Pass: `delete=1`.
4. Repeat with only `EXPO_PUBLIC_INTENTDB_BOT_MOVE=1`. Pass: `bot=1`.
5. Repeat with only `EXPO_PUBLIC_INTENTDB_ENVELOPE=1`. Pass: `envelope=1`.
6. Repeat with only `EXPO_PUBLIC_INTENTDB_VERIFY=1`. Pass: `verify=1`.
7. Set `EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY` to a 64-character hex pin and leave the switches unset. Unlock. Pass: the status bits stay `0` and the log does not contain the pin.
8. Rebuild with the flags unset. Pass: the status line returns to zeros.

## 4. Upload of a new item

Use a debug build with `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1` and a test account. Leave bot move and verify off.

1. Unlock and add one new entry titled `Upload check`. Confirm it opens and the password matches what you typed.
2. While unlocked, call `syncIntentdbOutbox` with that session token and vault-key proof. The vault screen does not do this by itself.
3. Pass: the server item row has `v4` ciphertext fields, a 64-character `contentSha256`, and locator `phone`. The title and password strings are absent from the row and from the request log.
4. Pass: the phone entry still opens with the same password.
5. Pass: the server has a receipt with `op` `put` whose `contentSha256` equals the item hash.
6. Confirm the Play candidate never created that server row.

## 5. Receipt verification

Use the same debug account. Set `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1`, `EXPO_PUBLIC_INTENTDB_VERIFY=1`, and `EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY` to the server receipt public key from the put response.

1. Add an entry and run `syncIntentdbOutbox` once.
2. Pass: logcat has no `intentdb verifier audit` line for that item. The phone entry is unchanged.
3. Run sync again against a receipt whose content hash or signature does not match the item (test server or a substituted response).
4. Pass: logcat contains `intentdb verifier audit itemId=<id> op=put reason=hash-mismatch` or `reason=bad-signature`. The line has no ciphertext and no signature.
5. Pass: the phone entry still opens, and its locator is still `phone`.

## 6. Bot move and replicate

Use a debug build with `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1` and `EXPO_PUBLIC_INTENTDB_BOT_MOVE=1`, plus the receipt pin from section 5.

1. Add an entry and run `syncIntentdbOutbox` while the upload locator is `phone`.
2. Pass: after a successful upload, the client requests a move. The receipt `op` is `move`, the content hash is unchanged, and the destination locator is `tier-1`.
3. Pass: the phone entry still decrypts. The local locator changes only when the caller supplied `applyLocator` and the receipt was accepted.
4. Call `proposeIntentBotReplicate` for that item.
5. Pass: the receipt `op` is `copy`. The stored item locator on the server stays the original locator. Local locators change only when `applyLocators` runs after an accepted receipt.
6. Repeat the move with a receipt signature that does not verify.
7. Pass: the local locator stays where it was, and the entry still opens.

## 7. Envelope migration on one item

1. On the Play candidate (envelope flag unset), add an entry named `Derived key`. Inspect the stored record. Pass: it has no `encryptedItemKey`. Unlock and confirm the password.
2. On a debug build with only `EXPO_PUBLIC_INTENTDB_ENVELOPE=1`, add a new entry named `Random item key` through the vault screen.
3. Pass: that new record has `encryptedItemKey`. The password decrypts. `Derived key` is unchanged.
4. Migration is not a screen button. While unlocked, call `migrateVaultEntryEnvelope` on the stored `Derived key` entry with `unlocked: true`, then `saveEntry` on the returned object only.
5. Pass: that entry gains `encryptedItemKey`, the other field ciphertext is unchanged, and the password still decrypts. A second migration returns the same wrapped-key ciphertext.
6. Pass: `Random item key` and every other entry are untouched. Logcat does not contain the master key or the raw item key.
7. Reinstall the Play candidate flags. Pass: a newly added entry has no `encryptedItemKey`.

## 8. Account delete

Use a disposable test account. Set only `EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE=1` for the helper steps. The vault screen does not call `deleteAccountAndResetLocal`.

1. Put two entries in the local vault and confirm both open.
2. Call `DELETE /api/account` with a valid session token, or call `deleteAccountAndResetLocal` after a successful server delete.
3. Pass: the response is HTTP 204. The user row is gone, and these rows for that user are gone with it: `vault_blobs`, `vault_blob_history`, `vault_items`, `vault_item_receipts`, `sessions`, `vault_audit_log`, `webauthn_credentials`, `trusted_devices`, `honeytokens`.
4. Pass: the local nuclear reset runs only after that 204. The device vault is empty.
5. Do not run account delete against a vault you need to keep.

## 9. Failed network call leaves local data unchanged

Run this section last on a vault you can recreate.

1. Play candidate, airplane mode on. Add an entry named `Offline keep`. Lock, unlock, and search for it.
2. Pass: the entry is present and the password matches. No item row appears on the server.
3. Debug build with item upload on. Point the API at an unreachable host, or enable airplane mode, then call `syncIntentdbOutbox`.
4. Pass: the result counts the upload as failed. `Offline keep` still opens. The local outbox record is still present. The locator is unchanged. The server has no plaintext and no new item row from that attempt.
5. Restore the network and return HTTP 500 from the item route. Sync again.
6. Pass: same local result as step 4. A rejected response does not remove the entry.
7. With bot move on, fail the move request after a successful upload.
8. Pass: the upload can stay successful, the local locator does not change, and the entry still opens.
9. With account delete on, call `deleteAccountAndResetLocal` in airplane mode, and again against a non-204 response.
10. Pass: both calls leave the local vault in place. Nuclear Reset does not run. Confirm `Offline keep` still opens before you delete anything on purpose.
