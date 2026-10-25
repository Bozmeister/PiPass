# PiPass Privacy Policy

**Last updated:** 25 October 2026

PiPass is a **local-first encrypted password manager**. Vault entries are encrypted on your device with a key derived from your master password. We do not receive your master password or the plaintext contents of your vault.

That is **not** a claim that the operator learns nothing. If you use the optional account, the server can see account and activity metadata, as described below. Optional ciphertext item sync exists in the client and is **off unless a build sets a feature flag**. The default build does not upload item manifests.

## Information We Collect

### Local Device Storage (Primary)

- Website URLs, usernames, passwords, and secure notes are encrypted on your device before they are written to storage.
- Unlock uses Argon2id, or a strong PBKDF2 fallback. Field encryption is AES-256-GCM (ciphertext version `v4`). Older CBC formats are not written.
- On iOS and Android, encrypted vault records are stored with the platform secure-storage APIs (`expo-secure-store`).
- A local search index may hold titles, usernames, URLs, entry notes, and secure-note labels. That index is encrypted on the device under a search key derived from the master key. The search key and the decrypted index stay in memory only while the vault is unlocked. Lock drops that plaintext. The search index is not uploaded.
- An optional per-item envelope key can wrap the key that encrypts one item's fields. That feature is off unless `EXPO_PUBLIC_INTENTDB_ENVELOPE=1`. The unwrapped item key and the master key stay on the device. The stored form is ciphertext. The default build does not create envelope keys.
- We cannot read local vault plaintext from your device over the network.

### Optional Account and Cloud Features

These apply only if you create an account or use server-backed features. They are optional. The default app is not a multi-device sync product.

The server **does not** receive:

- Your master password
- Vault encryption keys, search keys, or unwrapped item keys
- Plaintext passwords, usernames, notes, titles, or other vault field contents

The server **can** see, when those account features are used:

- Account identifiers (username, user id)
- Approximate activity: login and vault sync/fetch times, IP address, user agent, device/session metadata
- Encrypted blob size and version (not the contents)
- Security-event metadata (for example audit actions, device trust, rate-limit and anomaly signals)
- Honeytoken/decoy *trigger* metadata if you enable that feature (that a decoy was used, not the decoy password)
- If you enable TOTP step-up, an encrypted copy of the TOTP secret stored with a **server deployment key**. The operator of that server can decrypt those TOTP secrets. That is escrowed 2FA, not a claim that we cannot access second-factor material.

We do **not** claim that we cannot decrypt uploaded vault data “even if compelled.” We do not have your master password, so we cannot open the vault ciphertext. We can still be compelled to produce account records, metadata, and any material the server actually holds (including escrowed TOTP secrets).

### Optional Ciphertext Item Sync

Item sync is separate from the local vault and from the optional account blob above. Every `EXPO_PUBLIC_INTENTDB_*` switch defaults **off**. A store build leaves them unset, so saving an entry does not upload it.

If a build sets `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1` and a caller runs sync, the server stores an opaque item:

- Ciphertext fields (names and `v4` ciphertext only)
- A SHA-256 content hash of the canonical ciphertext manifest
- The entry salt, timestamps, item id, kind, locator, and a tombstone flag when the item was deleted
- A vault-key proof that the client knows the vault key. That proof is not the master password and does not let the server decrypt fields

The server checks the hash and the ciphertext shape. It does not decrypt fields.

After a successful item write, tombstone, locator move, or replicate, the server stores one Ed25519 **receipt**. The receipt binds the content hash, operation (`put`, `copy`, `move`, or `delete`), locators, item version, and bot id. It does not contain vault plaintext. The signing seed stays on the server. The client checks the signature with a pinned public key (`EXPO_PUBLIC_INTENTDB_RECEIPT_PUBLIC_KEY`), not with a key that arrived next to the signature.

Related switches, also off by default:

- `EXPO_PUBLIC_INTENTDB_VERIFY` re-checks the latest receipt. A mismatch is logged as item id, operation, and reason. The phone vault is left as it was.
- `EXPO_PUBLIC_INTENTDB_BOT_MOVE` can request a locator move or a replicate (`copy`) receipt. The phone copy stays the authority. A failed check does not change local data.
- `EXPO_PUBLIC_INTENTDB_ENVELOPE` is local. It does not by itself upload anything. If item upload is also on, a wrapped item key may be included as the opaque ciphertext field `itemKey`. The server cannot unwrap it.

A failed or unreachable network call does not change the phone vault, does not drop the local outbox record, and does not apply a locator or a receipt the client rejected.

### Account Deletion

- **Nuclear Reset** on the device permanently destroys local vault data, including the local search index. It does not need the server.
- If you have a server account, you can ask us to delete that account and the server records we control.
- `DELETE /api/account` deletes the user row. Foreign keys `ON DELETE CASCADE` then remove that user's vault blobs, blob history, vault items, item receipts, sessions, audit log, WebAuthn credentials, trusted devices, and honeytoken rows. The route writes an `account_delete` audit row with metadata only (no token, no vault ciphertext) and the same cascade removes that row with the account.
- The client helper that calls this route is off unless `EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE=1`. It wipes the local vault only after the server returns HTTP 204. A network failure, or any other status, leaves local data in place.
- We cannot reconstruct vault plaintext from ciphertext without your master password, so we cannot export your passwords for you.

### Biometric Authentication

- Face ID, fingerprint, or device passcode is used **only locally** on your device to unlock PiPass or authorize destructive actions.
- We never receive or store biometric data or templates.

### Other Data

- Basic anonymous usage statistics and crash reports, if you opt in. These must not contain vault contents.
- No analytics SDKs that track you across other apps.
- The official client does not send your saved site list to third-party favicon services.

## What We Do Not Collect

- Plaintext vault contents
- Your master password, search key, or unwrapped item keys
- The local search index
- Precise location data
- Contacts, photos, or other personal files
- Browsing activity outside of PiPass

## How Your Data Is Protected

- Vault secrets are encrypted on the device before local storage or any optional upload.
- Unlock and destructive actions require a fresh biometric or master-password confirmation where the platform supports it.
- Screenshot protection is enabled in release builds on supported platforms.
- There is no operator recovery path for a forgotten master password.

## Your Rights

- You can delete local data with Nuclear Reset.
- You can ask us to delete a server account. When account deletion runs, cascaded server rows for that user are removed as described above.
- We cannot export your passwords for you.

## Data Retention

- Local data: you control it on the device. Lock drops in-memory search plaintext. Nuclear Reset deletes the stored search ciphertext.
- Server account data, if an account exists: kept while the account is active. Deleted when the account is deleted, or as required by law.
- Optional item rows and receipts, if a build uploaded them: removed with the account cascade. They are not created by the default build.

## Changes to This Policy

We will update this document when features change what we collect. The current version is linked from the app and from the store listing.

## Store Listing Language

Use this tone in the Play listing. Do not describe the default build as multi-device sync, and do not say the operator can see vault plaintext.

**Short description** (under 80 characters):

Encrypted passwords on your device. Optional account. Plaintext stays local.

**Full description** (opening paragraph):

PiPass encrypts each vault entry on your device. Your master password and vault plaintext stay on that device. Search runs against a local encrypted index while the vault is unlocked. An optional account can store account and security metadata. Optional item sync stores ciphertext and a signed receipt, and it is off unless a build turns that flag on. The server does not receive vault plaintext, the master password, the search key, or unwrapped item keys. There is no recovery of a forgotten master password.

## Google Play Data Safety

Answers below match this policy for a **default build** (IntentDB flags unset). If a build sets `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1`, add the extra row in the last bullet before you submit that build.

**Does the app collect or share the required user data types?**

- Yes, if the user uses an optional account or server security feature. Declare that data as collected by the developer and not shared with third parties.
- Vault entries, the search index, and envelope keys that never leave the device are **not** collected. Do not declare on-device vault use as collection.

**Is all of the user data collected by your app encrypted in transit?**

- Yes. Account and optional item traffic uses HTTPS.

**Do you provide a way for users to request that their data is deleted?**

- Yes. Local data: Nuclear Reset in the app.
- Server account: the user can ask the operator to delete it. `DELETE /api/account` removes the user and cascaded rows. The in-app helper for that call is off by default.

**Data types for the default build**

| Play data type | Collected? | Shared? | Purpose | Notes |
| --- | --- | --- | --- | --- |
| Personal info → User IDs | Yes, if an account is used | No | Account management, security | Username and user id. Optional. |
| App activity → App interactions | Yes, if an account is used | No | Security, fraud prevention, account management | Login, sync/fetch, and audit metadata. Optional. |
| Device or other IDs | Yes, if an account is used | No | Security | Session, IP address, and user agent stored with the account. Optional. |
| Personal info → Other info (passwords, vault fields) | No | No | — | Processed on device only in the default build. |
| App activity → In-app search history | No | No | — | Search stays on device. |
| Location | No | No | — | Not collected. |
| Contacts, photos, files | No | No | — | Not collected. |

**If item upload is enabled in the build you submit**

- Also declare App activity → Other user-generated content as collected, not shared, purpose App functionality, optional.
- Describe it as encrypted vault-field ciphertext, a content hash, locators, and receipt metadata. State that the developer cannot read vault plaintext.
- Still answer No for the search index and for unwrapped item keys. Those stay on the device.
- Keep deletion as the account cascade plus Nuclear Reset.

**Security practices (form checkboxes)**

- Data is encrypted in transit.
- Users can request deletion of local data and of a server account.

## Contact

Privacy questions or security reports:  
Open an issue at https://github.com/pipass/pipass  
or email: security@pipass.app

---

**For developers / self-hosters:**  
This is the canonical privacy policy for the official PiPass distribution. If you fork or self-host the server, you are responsible for publishing your own policy and for the metadata and TOTP escrow that *your* deployment can see. Leave every `EXPO_PUBLIC_INTENTDB_*` flag unset in a store build. Flag meanings are listed in `README.md` and `.env.example`.
