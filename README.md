# PiPass

Local-first encrypted password manager. Vault plaintext, the search key, and unwrapped item keys stay on the device. The privacy policy is `PRIVACY_POLICY.md`. A device pass for Play is `docs/INTENTDB_DEVICE_CHECKLIST.md`.

## IntentDB flags

Every switch below is **off** unless the value is the string `1`. Leave them unset in a Play build. A boolean argument passed by a caller overrides the env value for that call. `EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY` is a pin, not a switch.

| Variable | Default | What it enables |
| --- | --- | --- |
| `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD` | off | Upload of a staged ciphertext manifest (`PUT /api/vault/items`) or tombstone (`PUT /api/vault/items/:itemId/tombstone`). Also required before a locator move or replicate request is sent. Sync does not run while this is off. |
| `EXPO_PUBLIC_INTENTDB_BOT_MOVE` | off | After a successful manifest upload at the `phone` locator, propose a bot move to `tier-1`. The same switch gates `proposeIntentBotReplicate` (`copy` receipt, locator unchanged). Item upload must also be on for the network call. |
| `EXPO_PUBLIC_INTENTDB_VERIFY` | off | Re-check the latest receipt signature and `contentSha256` (`verifyIntentItem`, bot id `intentdb-verifier-v1`). Sync runs that check only after a successful manifest upload. A mismatch is logged and does not change the item. |
| `EXPO_PUBLIC_INTENTDB_ENVELOPE` | off | New items store a random 32-byte item key as the ciphertext field `encryptedItemKey`. `migrateVaultEntryEnvelope` wraps the existing derived key for one item when the caller also passes `unlocked: true`. This flag does not upload data and does not migrate the vault by itself. |
| `EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY` | unset | Hex pin for receipt signatures. Verification does not trust the public key returned beside the receipt. Unset fails closed with reason `unpinned-key` when a check runs. |

`EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE` is separate. Default off. It allows `deleteAccountAndResetLocal` to call `DELETE /api/account`. Local vault data is wiped only after HTTP 204.

The unlock log line `intentdb status upload=0 delete=0 bot=0 envelope=0 verify=0 searchIndex=0` reports these switches and whether the local search-index header is stored. It does not include key material.
