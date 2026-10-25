# PiPass × IntentDB integration analysis

Date: 2026-10-25
Scope: full PiPass codebase at `C:\PiPass`
Role: Senior React Native + Security + Database Design review

PiPass can take an IntentDB-style store without giving up zero-knowledge, but only if IntentDB stores addressable ciphertext and proofs. The current vault is local-first AES-256-GCM with keys derived on the device. The server already has an opaque blob API, and the mobile app does not call it. There is no per-item wrapped key, no movement proof, and no short-lived retrieval token yet.

IntentDB design constraints this analysis respects:

- PiPass performs all encryption/decryption client-side. IntentDB and all bots see only ciphertext + non-sensitive metadata.
- Envelope encryption: each item has its own key; item keys are wrapped by a master key that never leaves PiPass.
- IntentBots may split, replicate, tier, or re-cluster encrypted blobs but cannot decrypt them.
- Every data movement returns a verifiable cryptographic proof (hash + auth tag). PiPass and verification bots must be able to check proofs.
- Retrieval uses short-lived authenticated tokens issued by PiPass.
- Anomaly detection uses only safe metadata and audit logs.
- Deletion must be cryptographically verifiable.

---

## 1. Current storage and crypto architecture

PiPass is a local-first Expo app. Vault crypto runs in the client. The optional Express and PostgreSQL server stores accounts, sessions, audit metadata, and one opaque blob per user. The vault UI never uploads that blob.

### Key hierarchy

Unlock derives a 32-byte master key and checks it against a local SHA-256 verifier.

| Step | What the code does | Where |
| --- | --- | --- |
| KDF | Argon2id for current vaults. Legacy unlock can still match PBKDF2-SHA256. | `crypto/keyDerivation.ts` |
| Parameters | Profile label maps to Argon2id. Fortress (100k) is about 64 MiB, time cost 4, parallelism 2. Deep Vault is about 96 MiB. Output is 32 bytes. Salt is 32 random bytes in `pipass_master_salt`. | `getArgon2idKdfParameters` |
| Device binding | New vaults use `deviceBinding: "none"` (password only). Legacy `deviceUUID:v1` mixes `password + ":" + deviceUUID`. | `crypto/kdfMetadata.ts`, `getKdfMaterial` |
| Unlock check | `pipass_master_hash` is SHA-256 of the master key. The master key is not sent anywhere. | `hashMasterKey` |
| Memory | The master key is XOR-split into two shares and wiped after each encrypt or decrypt. | `crypto/secureMemory.ts`, `lib/vaultSession.ts` |
| Cached key | `pipass_master_key` may sit in the shared keychain group `group.com.pipass.shared`, and only if biometrics can gate it. Otherwise the cache is refused. | `workers/storageWorker.ts` |

Item keys are derived, not wrapped. For each record:

```text
entryKey = HKDF-SHA256(
  ikm  = masterKey,
  salt = per-record salt stored beside the ciphertext,
  info = "pipass-entry-key:" + recordId
)
gcmKey = HKDF-SHA256(entryKey, info = "pipass-aes-gcm-v1", fixed domain salt)
```

That is `deriveEntryKey` and `deriveAesGcmKey` in `crypto/hkdf.ts`. HKDF is crypto-js. AES-256-GCM is native OpenSSL through `crypto/aesGcm.ts`. Password change re-encrypts every field (`reEncryptEntry` / `reEncryptSecureNote`) because there is no wrapped item key to rewrap.

### Field ciphertext

`crypto/encryption.ts` writes only this form:

```text
v4 : nonce(12 bytes hex) : ciphertext(hex) : tag(16 bytes hex)
```

Associated data is `pipass-aad-v1:<recordId>:<field>` and is not stored in the blob. The client must supply the same record id and field name on decrypt. Retired AES-CBC plus HMAC strings (`v2`, `v3`, and unversioned `iv:ct:mac`) are rejected.

Fields bound this way: `password`, `title`, `username`, `url`, `notes`, `aux`, and for notes `label` and `content`.

New entries from `encryptVaultEntry` persist ciphertext only. Optional legacy `title`, `username`, and `url` on `VaultEntry` are still accepted on decrypt. `notes` on the stored record is ciphertext, despite the name. Honeytoken state lives only inside `encryptedAux` as `{h, i, m}`.

### Where records live

| Data | Location | Shape |
| --- | --- | --- |
| Vault entries | SecureStore `pipass_vault_<id>` plus index `pipass_vault_index` | JSON `VaultEntry` |
| Secure notes | SecureStore `pipass_note_<id>` plus `pipass_notes_index` | JSON `SecureNote`. Not copied into the shared blob. |
| Shared blob | SecureStore `pipass_shared_vault` in `group.com.pipass.shared` | `{ encryptedBlob, version: 1, updatedAt }`. `encryptedBlob` is `JSON.stringify(entries)`, not an outer ciphertext. Rebuilt on every entry save or delete. |
| Unlock metadata | SecureStore | Salt, master-key hash, security profile, KDF metadata JSON, fractal fingerprint, initialized flag |
| Recovery | `pipass_recovery_key_hash` | Legacy only. The feature is removed. `destroyAllData` deletes the hash. There is no recovery wrap. |
| Account secrets | SecureStore `pipass.auth.userId`, `pipass.auth.authHash` | Long-lived API credential. Lock does not clear them. Nuclear reset does. |
| Server blob | `vault_blobs` plus `vault_blob_history` (latest 10) | Opaque text, max 10 MiB, server-minted version, optimistic concurrency via `expectedPrevVersion` |
| Write proof | `vault_blobs.key_verifier` | SHA-256 of `HMAC-SHA256(masterKey, "pipass.vault.pop.v1\|" + userId)`. The server never sees the master key. |

`lib/platformStorage.ts` refuses web writes and purges leftover `localStorage`. `lib/webVaultPolicy.ts` and `screens/WebVaultDisabledScreen.tsx` disable the vault in a browser.

`authedApiRequest` in `lib/query-client.ts` has no callers. Vault save and delete stay on device. The server routes `POST /api/vault/sync`, `GET /api/vault/fetch`, and `POST /api/vault/restore` exist and are tested, but the app does not use them. Security screens do call audit, honeytoken, passkey, TOTP, and device routes.

Sessions last 30 days (`SESSION_LIFETIME_MS`). They are account sessions, not per-object retrieval tokens. Raw session tokens are stored only as SHA-256.

### Where plaintext or sensitive metadata exists

On the device, while unlocked:

- XOR key shares in `lib/vaultSession.ts` and React state.
- `VaultScreen.withDisplayFields` decrypts title, username, and URL into React state for the list. Passwords are decrypted in the detail modal, not the list.
- Clipboard copies are cleared on a timer (`lib/secureClipboard.ts`).
- Honeytoken marker bytes exist only in decrypted memory. The client sends SHA-256(marker) to the server.
- Optional biometric-gated copy of the master key in the shared keychain.
- Legacy `deviceUUID` for old KDF binding. It is an install secret mixed into the password, and it is not a vault key.

On disk, next to ciphertext (readable by anyone who can read SecureStore or the shared keychain):

- Record ids, per-record salts, `createdAt` and `updatedAt`.
- Field names and ciphertext lengths. `encryptedAux` length is a honeytoken side channel.
- Legacy plaintext title, username, or URL if an old record still has them. New `encryptVaultEntry` does not write those fields. Saves go through `encryptVaultEntry`, then `saveEntry`, so the display-field copy in React state is not what gets written.
- KDF metadata: algorithm, memory, time, parallelism, profile, device-binding mode. The salt is not secret. The metadata describes how to derive the key.
- Fractal fingerprint: SHA-256 of an HKDF visual seed from the master key. It is an integrity canary, not a decryption key.
- `pipass.auth.authHash`, a bearer-equivalent credential.

On the server, if the optional account is used:

- Username, user id, auth salt, iteration count, and SHA-256(client auth hash).
- Session IP, user agent, device-fingerprint hash, trust and suspicion flags.
- Audit rows: action, vault version, blob size, IP, user agent. The `userAgent` column is also reused for short event details.
- Honeytoken label, type, marker hash, and trigger counts. Labels are user-chosen and can be sensitive.
- TOTP secret encrypted under `TOTP_ENCRYPTION_KEY` (`server/totp.ts`). The operator who holds that deployment key can decrypt it. This is escrowed 2FA, separate from the vault key.
- WebAuthn public keys and counters. Authenticator private keys are not stored.
- The vault blob and up to 10 historical blobs, opaque only if the client uploads opaque bytes. The natural client payload today would be the shared-vault JSON, which exposes ids, salts, timestamps, lengths, and any legacy plaintext. The server does not parse it. History means a deleted entry remains inside older blobs until the ring buffer drops them.

There is no account-delete API. `PRIVACY_POLICY.md` says the user can ask for deletion.

Backups (`lib/backupSchema.ts`) are versioned `pipass-backup` documents of the same encrypted records. They are staged and not a sync protocol. `lib/backupVerifier.ts` checks a client-side sentinel decrypt. Keep `expectedPlaintextHash` off any server.

---

## 2. Integration points for IntentDB

IntentDB should sit beside the local vault, not inside decrypt paths. Bots may split, copy, tier, or re-cluster ciphertext. They must preserve record id and field name, because those are the AES-GCM associated data. Renaming an id makes the tag fail.

### What to extend, and what to leave alone

| Component | Role for IntentDB |
| --- | --- |
| `workers/vaultWorker.ts` | Keep as the only encrypt and decrypt API. Later add an optional wrapped item key. Do not let bots call it. |
| `workers/storageWorker.ts` | Remains the source of truth for the phone. Add an export of ciphertext-only manifests after local commit. `deleteEntry` is where a tombstone must be created. |
| `workers/sharedVaultStorage.ts` | Local autofill cache of entry JSON, format version 1. Keep it local. Do not treat it as the IntentDB object format. It omits secure notes. |
| `lib/backupSchema.ts` | Closest existing ciphertext document. Use its entry and note validation as the manifest checker. |
| `crypto/vaultKeyProof.ts` and `server/vaultKeyProof.ts` | Keep as the account-level possession proof for blob writes. It does not authenticate a single item move. |
| `server/storage.ts` `syncVault` / `restoreVault` | One row per user, 10 MiB cap, history of 10. Phase 1 can keep this as a transitional monolithic snapshot. Per-item IntentDB needs a new table or service, not a bigger JSON string. |
| `server/routes.ts` | Auth, device trust, step-up, anomaly, and audit gates are reusable around a new object API. Do not overload `userAgent` with proof payloads. |
| `lib/query-client.ts` | `authedApiRequest` is the unused authenticated client. Retrieval calls need a different header: a short-lived token, not the 30-day session and not `x-auth-hash`. |
| `screens/VaultScreen.tsx` | Stays a local UI. It must not upload the display-field objects from `withDisplayFields`. |

### From today's blob to a hybrid layout, still ciphertext-only

Today one user has one JSON document. IntentDB wants many objects. Map them like this. Nothing below is decrypted outside PiPass.

**Transactional store.** One row per entry or note:

- `itemId` (current 15-character id; stable forever)
- `kind`: `vault-entry` or `secure-note`
- `schema`: `pipass-item-v1`
- `version` (per item)
- `salt` (HKDF salt, non-secret)
- `fields`: map of field name to the existing `v4:...` string, unchanged
- `contentSha256` over a canonical encoding of id, kind, salt, and fields
- `wrappedItemKey`: absent in phase 1 (key stays derived). Present only after an envelope migration.
- `locator`: which tier or replica set holds the body
- `tombstone`: absent, or a client-signed delete record

The transactional row is the authority for "what is the current byte string." GCM tags stay inside the field strings.

**Graph store.** Edges such as `itemId -> itemId` with an encrypted label blob, or no label at all. Domain, username, and "this is the same site" relations are plaintext only after local decrypt. A safe server graph is structural: entry id linked to note id, folder id, or replica id. Folder names are ciphertext.

**Vector store.** There is no embedding code today. A server-side vector of a title or URL is sensitive. Embedding inversion and similarity both leak. Phase 2 can keep a vector index inside the client, encrypted at rest like any other record. A server ANN index is a product choice that weakens the zero-knowledge claim. Do not describe it as ciphertext-only.

**Specialised stores.** Proof log, retrieval-token revocation list, and the existing audit log. These hold hashes, signatures, sizes, locators, and timestamps. They do not hold field plaintext, master keys, auth hashes, or session tokens.

The phone keeps the same SecureStore records so the current app still unlocks if IntentDB is down.

### Lifecycle

1. **Staging.** After a successful local `saveEntry` or `saveSecureNote`, PiPass writes a manifest into an outbox: canonical bytes, `contentSha256`, item version, and the current GCM field strings. Legacy plaintext title, username, url, and note label are stripped before staging. The master key never enters the outbox.

2. **IntentBot analysis.** A bot may read manifests, sizes, hashes, versions, and locators. It may propose split, replica, tier, or cluster moves. It cannot propose field rewrites. A valid proposal preserves `contentSha256` and the record id inside associated data.

3. **Proposal scoring.** Score only operational features: size, age from `updatedAt`, replica count, last verified hash, and whether a tombstone exists. Do not score decrypted title, URL, or password strength on the server. Those scores belong in PiPass, after decrypt, if the product wants them.

4. **Move with proof.** The bot copies canonical bytes, then returns a receipt (section 3). PiPass accepts the new locator only when the receipt's hash equals the local hash and the signature verifies.

5. **Verification.** A second bot, or PiPass itself on the next fetch, re-reads the locator, recomputes SHA-256, and checks the receipt. Mismatch locks that item as local-only and surfaces a sync error. It does not attempt server-side decrypt.

Delete follows the same path: local delete, signed tombstone staged, bot acknowledges with a proof that the authoritative locator no longer serves the body and that the tombstone hash is in the log. History policy must say how long replica copies and `vault_blob_history` may keep the old ciphertext. A proof of "current head does not contain this item" is achievable. A proof of "every disk sector was wiped" is not, and the product should not claim it.

---

## 3. Security and trust boundary

Decryption already stays in PiPass for vault fields. `encryptData` and `decryptData` are client-only. The server vault API compares a hash of an HMAC and stores the blob as text. IntentDB can preserve that if the new object API does the same.

These current paths have to be locked before a bot can see storage:

- Do not upload `pipass_shared_vault` JSON as-is. Strip legacy plaintext fields and omit the master-key cache, KDF metadata, fractal fingerprint, `deviceUUID`, and `pipass.auth.*`.
- Do not upload secure-note bodies by accident. They are outside the shared blob today, so a naive "sync the shared blob" drops them and a naive "sync all SecureStore keys" would also sync the master key.
- Keep `expectedPlaintextHash` and backup sentinels on the client.
- Keep honeytoken markers on the client. Server labels are already metadata. Prefer opaque labels if honeytokens move into the hosted product.
- TOTP escrow under `TOTP_ENCRYPTION_KEY` is outside the vault zero-knowledge model. Leave it out of IntentDB. For a stricter product, store the TOTP secret only on the device.
- `x-auth-hash` is a long-lived bearer stored on the device. Do not reuse it as a retrieval token. Session lifetime is 30 days.
- Anomaly detection in `server/routes.ts` already uses rates, IP, user agent, and device fingerprint. Keep it on that data plus proof-log failures (hash mismatch, bad signature, token reuse). Do not feed it titles, URLs, or ciphertext structure beyond size and count.
- In-memory anomaly and threat maps die on process restart. A hosted service needs a durable, still metadata-only, store before those signals are a control.
- Web `localStorage` must stay disabled until a separate web threat model exists.
- Autofill's shared keychain is a local trust boundary. IntentDB bots must not be given that keychain group.

### Proof format

Use two layers. Do not invent a new cipher.

**Content.** Existing GCM tag plus a SHA-256 over canonical item bytes. Canonical form should be a fixed field order, lowercase hex, and no legacy plaintext keys. PiPass computes it before upload and again after download.

**Movement and deletion receipt.** A small signed object, version 1:

- `op`: `put`, `copy`, `move`, `delete`
- `itemId`, `itemVersion`, `contentSha256`
- `fromLocator`, `toLocator` (delete sets `toLocator` to `tombstone`)
- `botId`, `issuedAt`
- `prevReceiptHash` so receipts chain

Sign with Ed25519. Pin bot public keys in the app or in account configuration. PiPass verifies the signature, the hash, and that `itemId` still matches the associated data it will use on decrypt. The server stores the receipt in the proof log and returns it on fetch. A verification bot checks the same fields and that the bytes at `toLocator` hash to `contentSha256`.

Deletion receipt includes the client tombstone. The tombstone is `HMAC-SHA256(masterKey, "pipass.tombstone.v1|" + itemId + "|" + version + "|" + contentSha256)`, and the server stores only that MAC plus the item id. The master key still never leaves the device. The bot proves the authoritative row is the tombstone and the body locator is empty. Retain or purge historical ciphertext under an explicit policy. `vault_blob_history` today keeps ten full snapshots, so delete is not complete on the server even after a local wipe.

### Retrieval tokens

PiPass mints these. Suggested HKDF info: `pipass-retrieval-v1`. The token is signed by a device key whose public key was registered at login. Claims: `aud = intentdb`, `sub = userId`, `itemIds` or a prefix, `op = read`, `exp` about 60 to 120 seconds, and a nonce. IntentDB checks the signature, expiry, and audience, then returns ciphertext and the latest receipt. It does not see the signing private key.

Keep the existing vault-key HMAC for writes that replace authoritative ciphertext. A stolen 30-day session must not be enough to overwrite items. That property already exists for the monolithic blob via `decideVaultWriteProof`. Carry it forward.

### Audit

Extend `vault_audit_log` with safe fields only: `itemId`, `op`, `contentSha256`, locator ids, receipt id, blob size, result (`ok`, `hash-mismatch`, `bad-token`). Keep the current rule that rows never contain passwords, blobs, auth hashes, tokens, or recovery material. Hash-mismatch and tombstone events are the anomaly inputs.

---

## 4. Implementation roadmap

Estimates assume one or two engineers who already know this repo. They are planning ranges, not measurements.

### Phase 1 — Ciphertext item store the current app still owns

**Goal.** Local SecureStore behaviour stays. Add a manifest builder and a verifier. Optionally mirror manifests into the existing `vault_blobs` row or a new `vault_items` table. No bots, no vectors, no password-change rewrap.

**Work.**

- Canonical item encoding and SHA-256, stripping legacy plaintext.
- Round-trip test: manifest bytes decrypt with the current `decryptVaultEntry` / `decryptSecureNote`.
- Local outbox. If upload fails, the phone vault is unchanged.
- Server stores manifests as opaque text and returns them with the hash. Reject hash mismatch. Keep `vaultKeyProof` on write.
- Document that `deviceBinding: "deviceUUID:v1"` vaults are not portable. Multi-device sync requires `deviceBinding: "none"`.

**Complexity.** Medium. Mostly serialization, tests, and one new persistence path.

**Risk.** Medium. The dangerous bug is uploading a display-field entry or the master-key cache. Format version must stay distinct from shared-blob version 1 and from the server's integer version. Autofill must keep reading the local shared blob.

### Phase 2 — Bots, receipts, tokens, and optional envelope keys

**Goal.** Bots move and replicate items. PiPass checks receipts. Retrieval uses short-lived tokens. Semantic features that need plaintext run on the device.

**Work.**

- Receipt schema, Ed25519 bot keys, client verifier, proof log.
- Token issuer in PiPass and a checker in front of item fetch.
- Tombstones and an explicit history-retention rule. Decide whether item delete also purges matching history rows.
- Client-only encrypted index for search (titles and URLs encrypted like other fields).
- Optional envelope migration: random 32-byte item key, wrap it with a key from `HKDF(master, "pipass-item-wrap-v1")`, store the wrap as another `v4` field. Old items keep derived keys until a re-encrypt. After that, password change rewraps item keys instead of every field. This is the step that actually matches IntentDB's envelope constraint. It is a migration, not a requirement for bots that only copy bytes.

**Complexity.** High. Crypto migration plus a new authorization protocol.

**Risk.** High. A bad canonicalization makes every receipt fail, or worse, makes a tampered body look valid. Token scope mistakes become data-access bugs. Envelope migration can destroy a vault if wrap and unwrap infos diverge. Ship behind a format flag and keep Phase 1 derived-key decrypt working.

### Phase 3 — Hybrid model and predictive organisation

**Goal.** Graph and placement are first-class, still without server decrypt. Predictive grouping is a client feature that writes opaque folder ids and encrypted labels.

**Work.**

- Graph edges between item ids. Encrypted edge labels.
- Tiering policies executed only through Phase 2 receipts.
- Client suggestions (for example "these entries share a hostname") computed after decrypt, then stored as ciphertext. The bot sees new edges and locators, not hostnames.
- Conflict handling when two devices edit one item. The current single-blob compare-and-swap does not translate. Use per-item versions and keep the loser as a history object the client can decrypt.

**Complexity.** High, mostly product and distributed state.

**Risk.** High for privacy and support. Predictive features are where plaintext tends to leak into logs, embeddings, and crash reports. Treat any server-side vector index as a conscious weakening of the zero-knowledge claim, with a policy update, or do not build it.

---

## 5. Web and business readiness

The shipping client is a native Expo app. The web bundle deliberately refuses the vault because a browser has no Keychain or Keystore equivalent. That is the right default. A marketable online product needs a separate web decision, not a flip of `isWebVaultDisabled`.

### What a usable web experience requires

- A web client that holds the master key only in page memory for the session, uses WebCrypto for AES-GCM and Argon2 via the existing WASM path, and never writes vault material to `localStorage`, IndexedDB, or service-worker caches.
- The same threat model written down: any XSS in the origin can use the in-memory key while the tab is unlocked. SecureStore-level protection is not available. Session lock must wipe shares, and the origin must stay small.
- Login can keep the existing WebAuthn and session flow. Login must stay separate from vault unlock. The server session does not decrypt the vault.
- Fetch and put of ciphertext through IntentDB using Phase 2 retrieval tokens.
- No favicon or other third-party calls with saved URLs. `components/FaviconImage.tsx` already stays local. Keep that.
- A native app and a web tab are two devices. Only vaults with `deviceBinding: "none"` open on both. Legacy device-bound vaults need an on-device migration first.

A browser extension with an isolated extension origin is a stronger web option than a normal tab, because page JavaScript on other sites does not share its memory. It is still not equivalent to the hardware-backed keystore.

### Product shapes

| Shape | What it is | Zero-knowledge impact |
| --- | --- | --- |
| Native app only, optional self-host | Current architecture. Server is optional blob hosting. | Strongest match to the existing policy. |
| Open-source core plus paid hosting | Publish the client and a single-tenant server. Charge for hosted IntentDB, devices, and support. | Holds if the host stores only ciphertext, proofs, and the metadata already disclosed. |
| Hosted IntentDB as the sync plane | Phone remains the vault. Host runs item store, proof log, and bots. | Holds if bots stay on the Phase 2 allow-list. |
| Full web app as a primary client | Session-memory crypto plus hosted ciphertext. | Possible, with a weaker device boundary. Say that in the product and the policy. |
| "Smart" server organisation | Server embeddings or classification of titles and URLs. | Breaks the ciphertext-only rule. Keep intelligence on the client. |

Public API for a paid product is not the current route set. You would add per-item read and write, receipt fetch, token issue, and account delete, with the existing rate limits, device trust, and step-up on writes. Publish an OpenAPI document that lists opaque fields and forbids plaintext vault schemas. `x-auth-hash` should not be the public credential. Prefer the session token plus retrieval tokens.

### What must stay client-side on every platform

- Master password and KDF (Argon2id / legacy PBKDF2).
- Master key, XOR shares, and any cached key.
- Item-key derivation and, later, item-key unwrap.
- Field encrypt and decrypt, including `encryptedAux` and note bodies.
- Vault-key HMAC and tombstone HMAC.
- Retrieval-token signing key.
- Honeytoken marker plaintext.
- Any search index or embedding built from decrypted fields.
- Backup sentinel checks.

The server may hold ciphertext, salts, ids, versions, sizes, locators, receipts, public keys, and the account and audit metadata it already holds.

### Licensing, privacy, and data safety

There is no root `LICENSE`. `modules/pipass-argon2/package.json` is `UNLICENSED`. A paid or hosted product needs a chosen license for the open-source core, a commercial agreement for hosting, and a review of crypto-js, hash-wasm, Expo, Drizzle, and the Argon2 native module before redistribution.

`PRIVACY_POLICY.md` (August 2026) already matches the code better than `replit.md`. It states that the operator sees account and activity metadata and can decrypt escrowed TOTP secrets, and that vault plaintext is not received. `replit.md` still describes AES-CBC, recovery keys, and Google favicons. Those comments are stale. Field encryption is AES-256-GCM `v4`, recovery is removed, and favicons are local.

Before charging money, update the policy and the store data-safety form for:

- Hosted ciphertext is still personal data under GDPR and UK GDPR because it is tied to an account. You need a lawful basis, a processor list, retention, and a real export and delete path. There is no delete-account route today.
- History and replicas: how long deleted ciphertext remains. The local Nuclear Reset does not delete server rows.
- IntentDB operator, region, and subprocessors.
- TOTP escrow, honeytoken labels, IP, and user agent.
- Crash and diagnostic payloads must exclude vault fields, shares, and tokens.
- A compelled-disclosure statement consistent with the current policy: the operator can produce account records, metadata, escrowed TOTP, and ciphertext, and cannot open the ciphertext without the master password.
- App-store answers: data is encrypted in transit and at rest on device. Server content is user-encrypted. Account creation is optional until sync is actually wired on. Marketing must not say the vault is already a multi-device cloud product. The client does not sync it.

Store listings should describe a local password manager with optional encrypted backup, until Phase 1 is shipping in the app.

---

## 6. Concrete next files and changes

These files move first:

1. `workers/vaultWorker.ts` — record shape, legacy plaintext, later the wrapped item key.
2. `workers/storageWorker.ts` — local commit, outbox hook, delete tombstone. Notes and entries must both be covered.
3. `workers/sharedVaultStorage.ts` — keep the autofill blob local and on format version 1.
4. `lib/backupSchema.ts` — validation pattern for ciphertext records.
5. `crypto/hkdf.ts` — new info strings for retrieval and wrap keys. Do not change `pipass-entry-key` or `pipass-aes-gcm-v1`.
6. `crypto/encryption.ts` — reuse `v4` for wrapped keys. No new cipher.
7. `crypto/vaultKeyProof.ts` and `server/vaultKeyProof.ts` — pattern for "HMAC locally, store a hash."
8. `shared/schema.ts` — item and receipt tables when a server store is added.
9. `server/storage.ts` and `server/routes.ts` — authoritative put and fetch, still opaque.
10. `lib/webVaultPolicy.ts`, `PRIVACY_POLICY.md` — web and hosting claims stay aligned with behaviour.

`screens/VaultScreen.tsx` matters because `withDisplayFields` puts plaintext titles into memory. The export path must read SecureStore via `getAllEntries` and `getAllSecureNotes`, then strip legacy fields, and must not serialize React state.

### First three changes

Do these before any bot or schema migration. Each one is testable with the current vault.

1. **`lib/intentdb/itemManifest.ts`.** Pure functions that turn a `VaultEntry` or `SecureNote` into a canonical ciphertext manifest and a SHA-256. Drop `title`, `username`, `url`, and note `label` when those plaintext fields are present. Refuse to encode a record that still lacks authenticated `v4` fields. Unit-test against fixtures from `encryptVaultEntry` so decrypt still works and the manifest contains no password plaintext.

2. **`lib/intentdb/receipt.ts`.** Build and verify a movement and deletion receipt over that hash: canonical bytes, SHA-256 check, and a signature check behind an injected key so tests do not need a network. No server calls. This is the proof object PiPass and a later verification bot both use.

3. **`workers/intentdbOutbox.ts`.** After `saveEntry`, `deleteEntry`, `saveSecureNote`, and `deleteSecureNote`, append a local SecureStore outbox record containing only the manifest or tombstone. Do not change the shared autofill blob and do not call `/api/vault/sync`. Add a test that the outbox has no master key, no auth hash, no legacy title, and that notes are included. Upload can wait until this snapshot matches what the phone can decrypt.

That sequence leaves the zero-knowledge boundary where it is now: keys and plaintext on the device, and a byte format that IntentDB can store, move, and prove without reading.
