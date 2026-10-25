# Security Audit – Stage 1: Cryptography

**Role:** Principal Cryptographer / OWASP MASVS  
**Date:** 2026-08-06  
**Target:** `C:\PiPass` — cryptographic layer only  
**Method:** Full source review of `crypto/*`, crypto-consuming vault/KDF paths (`workers/vaultWorker.ts`, `lib/currentUnlock.ts`, `lib/firstTimeSetup.ts`, `workers/storageWorker.ts` key cache, `plugins/native-patches/RNArgon2Module.java`), and runtime verification of CryptoJS encoding semantics for HMAC keys and PBKDF2 salts.  
**Posture:** Nothing is treated as secure unless verified in code. No compliments.

---

## Executive summary

The vault crypto is a **custom pure-JS stack** (`crypto-js` AES-CBC + custom HMAC, custom HKDF, Argon2 via native/wasm with silent PBKDF2 fallback). There are real design choices that are defensible (Encrypt-then-MAC, per-entry HKDF salts, Argon2id preference with metadata on create). There are also **multiple Critical/High defects** that break key consistency, integrity, or claimed memory/key-separation properties.

Highest-impact issues:

1. **`deriveMasterKey()` silently changes algorithm and strength** and is still used for password verification, profile change, and legacy unlock paths.
2. **Legacy ciphertext format is unauthenticated AES-CBC** (full malleability).
3. **Encrypt-then-MAC does not properly separate ENC and MAC keys**; MAC key is a deterministic function of the AES key string encoding.
4. **JS “memory wiping” of secrets is largely theater** (immutable strings; both XOR shares live in the same heap).
5. **Password field sanitizer silently strips characters** before encryption, corrupting real passwords.
6. **Native Argon2 salt normalization can diverge from wasm/JS salt decoding.**

---

## Scope reviewed

| Path | Role |
|------|------|
| `crypto/keyDerivation.ts` | Argon2id / PBKDF2, salt, device binding, unlock planner |
| `crypto/encryption.ts` | AES-CBC + HMAC EtM, IV, constant-time MAC compare |
| `crypto/hkdf.ts` | HKDF-Extract/Expand, entry keys, salts, fractal KDF |
| `crypto/secureMemory.ts` | wipe, XOR shares, RNG wrapper |
| `crypto/kdfMetadata.ts` | KDF metadata schema |
| `crypto/recoveryKey.ts` | Recovery key gen/hash/verify |
| `crypto/shamir.ts` | Custom Shamir SSS |
| `crypto/generateSecurePassword.ts` | Password generator |
| `crypto/deviceUUIDStorage.ts` | KDF device binding UUID |
| `crypto/hyperbaricSanitizer.ts` | Pre-encrypt field mutation |
| `crypto/integrityGuard.ts` | Crypto self-test (incomplete) |
| `crypto/biometricGate.ts` | Biometric freshness (key access gate only) |
| `plugins/native-patches/RNArgon2Module.java` | Native Argon2id salt/hash |
| `workers/vaultWorker.ts` | Entry/note encrypt path, legacy master-key fallback |
| `lib/currentUnlock.ts` | Unlock + legacy no-hash path |
| `lib/firstTimeSetup.ts` | Create-vault KDF policy |
| `workers/storageWorker.ts` | Cached master key in SecureStore |

UI/navigation/backend intentionally out of scope except where they invoke crypto APIs above.

---

## Findings

### C1 — Silent KDF algorithm/strength downgrade in `deriveMasterKey`

| Field | Detail |
|-------|--------|
| **Location** | `crypto/keyDerivation.ts` lines 857–940 (`deriveMasterKey`); consumers: `workers/vaultWorker.ts` 75–88 (`deriveMasterKeyShares`); `screens/VaultScreen.tsx` 631, 665; `app/(tabs)/index.tsx` 511, 590; `lib/currentUnlock.ts` 105–109 |
| **What is wrong** | On any Argon2 load/runtime failure, `deriveMasterKey` **falls through to PBKDF2-SHA256 using raw profile iterations** (e.g. 25 000 / 100 000 / 250 000). It does **not** use `STRONG_PBKDF2_FALLBACK_FLOOR` (600 000). It does **not** record which algorithm produced the key. Create-vault (`prepareFirstTimeVaultSetup`) correctly prefers Argon2 then strong PBKDF2 **with metadata**. Unlock planner correctly requires metadata/legacy match. But several security-critical paths still call the silent-downgrade API. |
| **Risk** | **Critical** |
| **Attack / failure scenario** | (1) Vault created with Argon2id metadata. Device temporarily lacks native/wasm Argon2. User triggers nuclear-reset password verify or profile migration via `deriveMasterKeyShares` → PBKDF2(100k) key ≠ stored Argon2 hash → false “wrong password” or, on empty-vault profile change, **rewrites `pipass_master_hash` to a PBKDF2-derived key without updating KDF metadata** → permanent unlock desync. (2) Offline brute-force of any vault whose master key was actually produced under weak PBKDF2@≤100k is far cheaper than Argon2id 64 MiB. |
| **Recommendation** | Delete or hard-fail `deriveMasterKey` silent fallback for any path that verifies or rotates keys. Route all unlock/verify/rotate through `planUnlockKdfDerivation` / metadata parameters only. Never change algorithm without writing matching metadata. If PBKDF2 fallback remains for create, only use `getStrongPbkdf2FallbackParameters` and persist it. |

---

### C2 — Legacy unauthenticated AES-CBC decrypt path

| Field | Detail |
|-------|--------|
| **Location** | `crypto/encryption.ts` lines 54–60, 97–117 (`decryptData` 2-part format → `decryptLegacy`) |
| **What is wrong** | Ciphertext format `iv:ciphertext` (no MAC) is still accepted. AES-CBC with PKCS#7 and **no authentication** is malleable: bit-flips in ciphertext produce predictable plaintext changes in the corresponding block (and garble the next). CryptoJS empty-string failure is not integrity protection. |
| **Risk** | **Critical** (integrity / authenticity of vault secrets for any legacy records or downgraded writers) |
| **Attack scenario** | Adversary with write access to SecureStore / backup / shared vault blob modifies `encryptedPassword` of a legacy entry. On unlock, app decrypts attacker-controlled password (or injects structured JSON into notes). No MAC failure. For a password manager, forged credentials are a direct integrity break (MASVS-STORAGE / crypto integrity). |
| **Recommendation** | Reject 2-part format in production builds, or accept only after one-time migration that re-encrypts under 3-part EtM and deletes legacy blobs. Never emit 2-part format. Prefer real AEAD (AES-256-GCM) from a native crypto provider. |

---

### C3 — Encrypt-then-MAC key separation is incorrect

| Field | Detail |
|-------|--------|
| **Location** | `crypto/encryption.ts` lines 10, 25–27, 47–49, 69–70 |
| **What is wrong** | `deriveHmacKey(encKey)` = `HmacSHA256("hmac-subkey", encKey)` where `encKey` is the **64-char hex string**, not the 32-byte key. AES uses `CryptoJS.enc.Hex.parse(keyHex)` (binary). Verified with CryptoJS 4.2.0: HMAC over string key ≠ HMAC over binary WordArray of the same key material. Compromise of the AES key immediately yields the MAC key (encode hex → recompute). This is **not** independent ENC/MAC key separation (NIST/SP 800-108 / RFC 5869 style). Also, the HMAC key is itself a hex string fed back into CryptoJS as UTF-8 for the outer MAC. |
| **Risk** | **High** |
| **Attack scenario** | Any bug, log, side channel, or backup that leaks the entry AES key (or master key used as entry key on legacy records) also allows MAC forgery. EtM’s authentication guarantee collapses under ENC-key compromise, which is expected only if keys are independent; related-key design removes that margin. |
| **Recommendation** | From each entry key (or master key), derive two 256-bit keys with HKDF: `info="pipass-aes-v1"` and `info="pipass-hmac-v1"`. Use binary keys only. Version the ciphertext format when changing derivation. |

---

### C4 — JavaScript secret wiping is ineffective; XOR share split is colocated theater

| Field | Detail |
|-------|--------|
| **Location** | `crypto/secureMemory.ts` entire file (esp. 1–5, 50–82); `workers/vaultWorker.ts` 85–86, 147–148, 239–240; `lib/vaultSession.ts` 31–46 |
| **What is wrong** | Master keys, passwords, and recovery keys are handled primarily as **immutable JS strings** (`masterKeyHex`, password material). `wipeBuffer(hexToBytes(masterKeyHex))` zeros a temporary copy; the original string remains on the heap until GC (and may be retained in rope/intern structures). `useKeyBriefly` has the same flaw. XOR split (`shareA` random, `shareB = key ⊕ shareA`) provides **zero protection against process memory disclosure** while both shares are resident — which is the normal unlocked state (`setActiveKeyShares`). |
| **Risk** | **High** (false sense of security; does not meet MASVS expectations for in-memory secret handling claims) |
| **Attack scenario** | Malware, debug bridge, compromised WebView, or memory dump while vault unlocked reads both `Uint8Array` shares or residual hex strings → full master key → all entries. |
| **Recommendation** | Document honestly that RN/JS cannot guarantee wipe. Minimize secret lifetime; avoid caching master key hex; prefer native secure enclaves / keystore-held keys for long-lived material; wipe only binary buffers you control and never claim string wipe. If shares remain, store one share in hardware-backed storage requiring auth, not both in JS heap. |

---

### C5 — Password sanitizer silently mutates secrets before encryption

| Field | Detail |
|-------|--------|
| **Location** | `crypto/hyperbaricSanitizer.ts` lines 1, 20–40, 64–67; used from `screens/VaultScreen.tsx` before encrypt |
| **What is wrong** | `FORBIDDEN_CHARS = /[<>{}\[\]\\\/]/g` is stripped from **password** (and other fields) with `ok: true`. Characters common in generated/random passwords (`/`, `\`, `<`, `>`, etc.) are removed without failing closed. |
| **Risk** | **High** (integrity of stored credentials — user-visible crypto pipeline defect) |
| **Attack scenario** | Not an external attacker: user saves password `a/B\c<d>`. Stored ciphertext encrypts corrupted value `aBcd`. User cannot log into target site; “password manager corrupted my password.” Also enables subtle integrity failures if attacker can influence fields that get re-sanitized on edit. |
| **Recommendation** | Never strip password/notes content for “XSS” on a local encrypted store. At most validate length. If sanitization is required for display contexts, sanitize only at render time, not pre-encrypt. |

---

### C6 — Native Argon2 salt decode can disagree with JS/wasm salt

| Field | Detail |
|-------|--------|
| **Location** | `plugins/native-patches/RNArgon2Module.java` `hexToExactly32Bytes` lines 45–89; vs `crypto/keyDerivation.ts` `hexToBytes` 458–467 and native adapter requiring `params.salt.length === 32` (236–241) |
| **What is wrong** | Java path: strips non-hex, left-pads short salts with `'0'`, truncates long salts to rightmost 64 hex chars. JS path: strict even-length decode, no pad/truncate. Adapter tries to force 32-byte salts for native invoke, but any alternate caller or partial hex still risks **native hash ≠ wasm hash for “same” salt string**. |
| **Risk** | **High** |
| **Attack / failure scenario** | Cross-backend unlock failure (availability / support DoS). In migration/probe edge cases, different backends producing different master keys for identical password+salt string → hash mismatch or, worse, dual-key ambiguity during legacy detection if paths differ mid-flight. |
| **Recommendation** | Single canonical salt: reject anything except `^[0-9a-f]{64}$`. Native module must hard-fail on wrong length, never pad/truncate. Interop test vectors: native vs hash-wasm for fixed password/salt/params. |

---

### C7 — Legacy unlock without master-hash verification

| Field | Detail |
|-------|--------|
| **Location** | `lib/currentUnlock.ts` lines 62–64, 101–120 (`performLegacyNoHashUnlock`) |
| **What is wrong** | If `getMasterKeyHash()` returns null, unlock **accepts any password**, derives a key via `deriveMasterKeyShares` (see C1), caches it, and returns shares. `hashMasterKey(keyHex)` result is **discarded** (line 111). Wrong password “unlocks” with a useless key; right password may still fail entry decrypt depending on path. No binding to vault contents. |
| **Risk** | **High** |
| **Attack scenario** | Corrupted/missing `pipass_master_hash` (backup bug, partial wipe, import): attacker or confused user “unlocks” vault, app may present empty/errors, or partially decrypt legacy master-key entries incorrectly. Removes password gate when verifier missing. |
| **Recommendation** | Fail closed if master hash missing unless recovering via recovery-key flow that re-establishes verifier. Never treat “derived something” as unlock success without proof (hash match or successful decrypt of a vault verifier blob). |

---

### C8 — Legacy entries encrypt under master key (no HKDF separation)

| Field | Detail |
|-------|--------|
| **Location** | `workers/vaultWorker.ts` lines 160–164, 327–329 |
| **What is wrong** | If `entry.salt` / `note.salt` is missing, `entryKey = masterKeyHex`. Master key used directly as AES key for field encryption. Violates key separation; amplifies C3; one broken ciphertext implementation path exposes master key use. |
| **Risk** | **High** for any residual legacy records |
| **Attack scenario** | Cryptanalytic or implementation bug against AES-CBC/HMAC on an entry ciphertext targets the master key itself, not a single-entry subkey. Compromise of one entry’s key material is compromise of all vault data. |
| **Recommendation** | Mandatory migration: re-encrypt all saltless records with `deriveEntryKey` + new salt; refuse decrypt of saltless records after migration deadline. |

---

### C9 — PBKDF2 salt and password material encoding are non-binary / non-wiped

| Field | Detail |
|-------|--------|
| **Location** | `crypto/keyDerivation.ts` 652–670, 928–935; `getKdfMaterial` 473–476 |
| **What is wrong** | `CryptoJS.PBKDF2(material, saltHex, …)` passes **UTF-8 salt string** (64 hex characters), not 32 raw salt bytes. Verified: string-salt PBKDF2 ≠ hex-parsed salt PBKDF2. Entropy is still high for random hex, but the construction is non-standard and **incompatible with any external tool** that uses binary salt. Password material `password + ":" + deviceUUID` is a JS string never wiped. |
| **Risk** | **Medium** (correctness / interoperability / hygiene); elevates to High if mixed with binary-salt tooling or naive “reimplement offline” recovery |
| **Attack scenario** | Third-party recovery utility uses binary salt → wrong keys → user forced into unsafe recovery. Offline attacker still faces full entropy if hex is random; main issue is footgun and standards violation (RFC 8018 / NIST expect binary salt). |
| **Recommendation** | `CryptoJS.PBKDF2(material, CryptoJS.enc.Hex.parse(saltHex), …)` and lock that into metadata version. Keep algorithm version field. |

---

### C10 — Custom HKDF + default random salt footgun in `deriveSubkey`

| Field | Detail |
|-------|--------|
| **Location** | `crypto/hkdf.ts` lines 7–43, 114–119 |
| **What is wrong** | Custom HKDF-Extract/Expand reimplementation (not a vetted library). Counter encoding appears correct under CryptoJS 4.2 WordArray typed-array path (spot-checked). But `deriveSubkey(master, context)` with omitted salt calls `generateSaltHex()` and **discards the salt** — derived key is unreproducible. `deriveEntryKey` always passes salt (good). Fixed app-wide `HKDF_SALT_V1` for fractal is OK for domain separation of non-secret visual params. |
| **Risk** | **Medium** (custom crypto + API footgun) |
| **Attack scenario** | Future caller omits salt → encrypts under unrecoverable key → permanent data loss (availability). Custom HKDF bugs would be systemic if Expand were wrong for multi-block OKM (currently length=32, single block). |
| **Recommendation** | Require salt parameter (no default RNG). Prefer platform HKDF (iOS CryptoKit / Android Keystore/Conscrypt / WebCrypto) or a single audited implementation with test vectors against RFC 5869. |

---

### C11 — Device UUID KDF binding is co-located with vault data

| Field | Detail |
|-------|--------|
| **Location** | `crypto/deviceUUIDStorage.ts`; `crypto/keyDerivation.ts` `getKdfMaterial` 473–476; metadata claims `deviceBinding: "deviceUUID:v1"` |
| **What is wrong** | Master password is mixed as `password + ":" + deviceUUID`. UUID is generated with `expo-crypto.randomUUID()` and stored via platform storage (`deviceUUID` key) **on the same device as the vault**. Full device image / backup that includes SecureStore/localStorage yields UUID + salt + ciphertext. Binding does **not** protect against the primary threat (stolen device / full app data extract). It mainly breaks legitimate restore on a new device without UUID export. |
| **Risk** | **Medium** (threat-model mismatch; restore hazard) |
| **Attack scenario** | Attacker extracts app data → has salt, UUID, ciphertext, metadata → offline attacks password only (as usual). User migrates phone without UUID → cannot unlock even with correct password. |
| **Recommendation** | Treat UUID as optional hardening for “vault file alone” leaks only; document restore requirements; include UUID in encrypted backup header or stop binding for new vaults if restore UX is required. |

---

### C12 — Master key cached as raw hex in SecureStore / Keychain

| Field | Detail |
|-------|--------|
| **Location** | `workers/storageWorker.ts` 361–448 (`storeMasterKeySecurely` / `getMasterKeySecurely`) |
| **What is wrong** | After unlock/setup, full master key hex is written under `pipass_master_key` with `requireAuthentication: true` when biometrics/device secret enrolled. Good that unauthenticated store is refused in production. Residual risks: (1) key is still extractable after OS auth by any code path that calls get; (2) App Group service `group.com.pipass.shared` widens process boundary; (3) `__DEV__` can read without authentication when biometric unavailable; (4) key is not wrapped under a non-exportable hardware key object — it is exportable secret material. |
| **Risk** | **Medium** |
| **Attack scenario** | Malicious app update / compromised JS bundle after user authenticates once → reads keychain item → full vault. Shared keychain group increases blast radius to other binaries in the group. |
| **Recommendation** | Prefer non-exportable keystore keys + wrap DEK; minimize cache lifetime; clear cache on lock/background; never store master key on web; audit App Group membership. |

---

### C13 — Secure notes store plaintext `label` beside ciphertext

| Field | Detail |
|-------|--------|
| **Location** | `workers/vaultWorker.ts` 300–307 (`encryptSecureNote` sets `label: note.label` and `encryptedLabel`) |
| **What is wrong** | Confidentiality failure for note titles/labels at rest despite encryption path existing. |
| **Risk** | **Medium** |
| **Attack scenario** | Device backup / SecureStore dump reveals all note labels without master password. |
| **Recommendation** | Stop persisting plaintext `label`; migrate existing records; decrypt only from `encryptedLabel`. |

---

### C14 — Constant-time comparisons incomplete / weak

| Field | Detail |
|-------|--------|
| **Location** | `crypto/encryption.ts` 12–23 (`constantTimeEqual` early length bail); `crypto/recoveryKey.ts` 31–38 (char-wise on hex strings — OK-ish); `crypto/keyDerivation.ts` 730, 748, 809 (`hashMasterKey(...) === storedMasterHash` **not** constant-time) |
| **What is wrong** | Master-hash checks use JS `===`. MAC compare exits early on length mismatch (usually fixed 64 hex so low impact). No `crypto.timingSafeEqual` / native constant-time for verifier. |
| **Risk** | **Low** for remote attackers (KDF dominates); **Low–Medium** for local high-precision timing on hash compare after KDF |
| **Attack scenario** | Local attacker measures short-circuit on master hash after derivation to validate password guesses slightly faster — usually negligible vs Argon2 cost. |
| **Recommendation** | Always compare digests with fixed-length `timingSafeEqual` on raw bytes; reject non-64-hex verifiers before compare. |

---

### C15 — Argon2 parameters: acceptable floors, weak metadata validation, odd profile mapping

| Field | Detail |
|-------|--------|
| **Location** | `crypto/keyDerivation.ts` 482–557, 508–520; `crypto/kdfMetadata.ts` 63–76 |
| **What is wrong** | Fortress-ish defaults: 64 MiB, timeCost 3–5, p=1–2 — **above OWASP minimum** for Argon2id, acceptable for mobile. Profile “iterations” (25k/100k/250k) are **not** Argon2 iterations; they are a UI label mapped to small timeCost. Metadata validator accepts `memoryKiB: 1`, `timeCost: 1` (any positive int) — no security floor. Create path can still fall back to PBKDF2 (strong floor 600k — good) if Argon2 unavailable. |
| **Risk** | **Medium** (metadata integrity / future downgrade DoS); parameters themselves when using defaults: **Low** |
| **Attack scenario** | Attacker modifies stored metadata to impossible params → unlock DoS. Cannot lower params and still match `pipass_master_hash` without password. |
| **Recommendation** | Enforce floors in `isValidKdfMetadata` (e.g. m≥19456, t≥2, p≥1, outputBytes=32). Keep mapping documented. Prefer reporting real Argon2 params in UI, not fake PBKDF2 iteration counts. |

---

### C16 — Pure-JS AES/HMAC (`crypto-js`) side channels and maintenance risk

| Field | Detail |
|-------|--------|
| **Location** | `crypto/encryption.ts`, `crypto/hkdf.ts`, `crypto/keyDerivation.ts` PBKDF2; dependency `crypto-js@^4.2.0` |
| **What is wrong** | Software AES/HMAC in JS is not constant-time; susceptible to cache/timing analysis by privileged local adversaries. No AES-GCM. Comment claims EtM provides “same security guarantees as GCM” — **false** regarding misuse resistance, nonce handling APIs, and AAD; only roughly similar confidentiality+integrity when EtM is implemented correctly (see C2, C3). |
| **Risk** | **Medium** |
| **Attack scenario** | Compromised process co-resident with precise timers extracts key bits over many operations (advanced). More realistically: implementation bugs in CBC/PKCS7/HMAC glue (already partially present) are the dominant risk. |
| **Recommendation** | Move to native AES-GCM-SIV or AES-GCM (iOS/Android) or `react-native-quick-crypto` / WebCrypto; drop crypto-js for vault payload crypto. |

---

### C17 — Custom Shamir secret sharing

| Field | Detail |
|-------|--------|
| **Location** | `crypto/shamir.ts` |
| **What is wrong** | Hand-rolled GF(256) tables and Lagrange. Higher-degree coefficients forced away from 0 (`if (coeffs[c] === 0) coeffs[c] = 1`) bias the coefficient distribution. Secrets returned as hex strings (unwipeable). Custom secret sharing is a classic footgun class. |
| **Risk** | **Medium** if used for recovery of master secrets; **Low** if unused in production paths |
| **Attack scenario** | Implementation error in combine → wrong secret or leakage; biased coeffs slightly reduce share entropy (minor). |
| **Recommendation** | Prefer audited SSS library or eliminate if unused. Add known-answer tests against a reference implementation. Do not force nonzero coefficients; redraw instead. |

---

### C18 — Password generator modulo bias

| Field | Detail |
|-------|--------|
| **Location** | `crypto/generateSecurePassword.ts` lines 10–26 |
| **What is wrong** | `bytes[i] % charset.length` is biased when 256 % len ≠ 0. Shuffle uses `shuffleBytes[i] % (i+1)` (Fisher–Yates with bias). |
| **Risk** | **Low** |
| **Attack scenario** | Offline attacker of generated passwords gains negligible advantage at length 16+ with mixed alphabet; still incorrect CSPRNG usage. |
| **Recommendation** | Rejection sampling (`while (b >= maxValid)`); same pattern already used in `vaultWorker.generateId`. |

---

### C19 — Integrity self-test does not exercise production crypto

| Field | Detail |
|-------|--------|
| **Location** | `crypto/integrityGuard.ts` 87–128 |
| **What is wrong** | Self-test encrypts with raw CryptoJS AES-CBC **without HMAC**, fixed IV, no call to `encryptData`/`decryptData`, no Argon2/HKDF vectors. Can pass while production EtM is broken. Hook detection is trivial to bypass. |
| **Risk** | **Low** (gives false confidence; not a direct vault break) |
| **Recommendation** | Self-test must call production APIs with known answers; fail closed on mismatch. |

---

### C20 — Sensitive crypto logging

| Field | Detail |
|-------|--------|
| **Location** | `crypto/keyDerivation.ts` multiple `console.log` (password length material via `pwLen`, params, backend); `lib/firstTimeSetup.ts` 109–110 (`masterPasswordLength=…`); `app/(tabs)/index.tsx` / `SeedSetupScreen` password length logs |
| **What is wrong** | Logs password length and KDF material length. Length leaks aid password guessing (especially short master passwords; min UI length is 8). |
| **Risk** | **Low–Medium** on shared debug logs / crash reporters |
| **Recommendation** | Strip all password-length and key-material logs from release builds. |

---

### C21 — Master password policy is weak relative to KDF

| Field | Detail |
|-------|--------|
| **Location** | `screens/SeedSetupScreen.tsx` `MIN_PASSWORD_LENGTH = 8` (policy at crypto boundary) |
| **What is wrong** | 8-character master passwords remain brute-forceable even with Argon2id 64 MiB if low entropy. KDF cannot save `Password1`. |
| **Risk** | **Medium** (offline attack after data extract) |
| **Recommendation** | Enforce higher min length + strength meter; optional diceware; rate-limit is irrelevant offline. |

---

### C22 — Recovery key hashing is bare SHA-256

| Field | Detail |
|-------|--------|
| **Location** | `crypto/recoveryKey.ts` 27–28 |
| **What is wrong** | `hashRecoveryKey` = SHA-256(hex). Recovery key is 256-bit random so preimage is hard — **acceptable**. Not a password; no KDF needed if entropy holds. Verify is roughly constant-time on hex chars. Risk is operational (user photographs recovery key) not algorithmic. |
| **Risk** | **Low** (algorithmic); operational user handling out of scope |
| **Recommendation** | Keep 32-byte entropy; store as SHA-256 or better HMAC under device key; never log raw recovery key. |

---

### C23 — Profile change / password verify ignore KDF metadata

| Field | Detail |
|-------|--------|
| **Location** | `screens/VaultScreen.tsx` 611–659, 662–672; tied to C1 |
| **What is wrong** | `confirmProfileChange` derives via `deriveMasterKeyShares`, writes new `pipass_master_hash`, does not update `pipass_kdf_metadata` consistently with actual algorithm/params used, and stamps fractal kdf label `"argon2id"` unconditionally. |
| **Risk** | **Critical** (key lifecycle correctness) |
| **Attack / failure scenario** | User changes security profile on empty vault → unlock path uses old metadata → correct password fails forever, or vault re-keyed under different algorithm than metadata claims. |
| **Recommendation** | Profile change must re-derive with explicit algorithm, re-encrypt all entries, rewrite metadata + verifier atomically, or refuse if vault non-empty (partially already refuses non-empty — still broken for empty vault hash rewrite). |

---

## Component assessment (verified claims only)

| Topic | Verdict |
|-------|---------|
| **Argon2id** | Prefer native (`RNArgon2` / argon2kt) then `hash-wasm`; mode string `"argon2id"`. Params ~64–96 MiB, t=3–5. Create path is intentional. Silent fallback path is not. |
| **PBKDF2 fallback** | Create: ≥600k SHA-256 (good floor). `deriveMasterKey`: profile iterations, can be 25k–100k (inadequate vs OWASP). Salt is UTF-8 hex string. |
| **Salt generation** | Master salt: 32 bytes via `expo-crypto.getRandomBytes` → hex (good). Entry salts: 16 bytes (acceptable). |
| **IV / nonce** | 16-byte IV per `encryptData` via `expo-crypto` (good for CBC). No GCM nonce API. |
| **AES** | AES-256-CBC PKCS7 via crypto-js + custom HMAC. Not GCM. Legacy unauthenticated path remains. |
| **Key separation** | Per-entry HKDF with salt+entryId (good when used). EtM ENC/MAC separation broken (C3). Legacy master-key reuse (C8). |
| **HKDF** | Custom RFC-shaped HMAC-SHA256; needs vectors; salt-optional API is dangerous. |
| **RNG** | `expo-crypto.getRandomBytes` / `randomUUID` for salts, IVs, recovery keys, shares — appropriate if expo-crypto CSPRNG is OS-backed (standard on modern Expo). |
| **Constant-time** | Partial MAC compare; master hash uses `===`. |
| **Memory wiping** | Buffer fills only; strings/key shares remain. |
| **Master password** | Bound with deviceUUID; min length 8; lengths logged. |
| **Key lifecycle** | XOR shares in JS; optional auth-gated cache of raw master hex; wipe on lock is best-effort. |
| **Custom crypto** | EtM glue, HKDF, Shamir, sanitizer — primary risk concentration. |

---

## Risk tally

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 3 | C1, C2, C23 |
| **High** | 6 | C3, C4, C5, C6, C7, C8 |
| **Medium** | 9 | C9–C13, C15, C16, C17, C21 |
| **Low** | 5 | C14, C18, C19, C20, C22 |

---

## Priority remediation order

1. **Fail closed on KDF path** — remove silent PBKDF2 from any verify/rotate/unlock helper; metadata-only derivation (fixes C1, C7, C23).  
2. **Kill legacy unauthenticated CBC** and migrate records (C2, C8).  
3. **Fix EtM key separation** with HKDF dual keys; re-encrypt (C3).  
4. **Stop pre-encrypt password stripping** (C5).  
5. **Native/wasm salt parity + strict hex salts** (C6, C9).  
6. **Stop plaintext note labels; honest memory model; reduce master-key cache** (C4, C12, C13).  
7. **Replace crypto-js vault crypto with native AEAD** (C16).  
8. **Hardening**: metadata floors, constant-time compares, logging, password policy (C14–C15, C20–C21).

---

## What was not claimed secure

- No formal proof of HKDF/Shamir correctness beyond limited counter encoding check.  
- No dynamic instrumentation of native Argon2 on device in this stage.  
- No side-channel lab measurement of crypto-js AES.  
- Server, WebAuthn, TOTP, honeytokens, and UI auth gates: out of stage scope.

---

## Appendix — Encoding verification (CryptoJS 4.2.0)

Executed locally against installed `crypto-js`:

- `HmacSHA256(msg, hexStringKey)` ≠ `HmacSHA256(msg, Hex.parse(hexStringKey))`  
- `PBKDF2(pw, saltHexString)` ≠ `PBKDF2(pw, Hex.parse(saltHexString))`  

These confirm C3 and C9 are not theoretical.

---

*End of Stage 1 – Cryptography*

# Security Audit – Stage 2: Vault Encryption & Secure Storage

**Role:** Principal Security Engineer (password managers)  
**Date:** 2026-08-06  
**Scope:** Vault encrypt/decrypt, SecureStore/Keychain/Keystore vs web storage, key use at rest and in memory, metadata protection, recovery handling, clipboard, secrets in logs/React state.  
**Out of scope:** Pure UI/navigation; Stage 1 primitive crypto defects are not re-listed unless required for vault-storage context.  
**Method:** Source review of `workers/vaultWorker.ts`, `workers/storageWorker.ts`, `workers/sharedVaultStorage.ts`, `lib/platformStorage.ts`, `lib/vaultSession.ts`, `lib/currentUnlock.ts`, `lib/firstTimeSetup.ts`, `lib/credentials.ts`, `app/(tabs)/index.tsx`, `screens/VaultScreen.tsx`, `components/EntryDetailModal.tsx`, `components/SecureNotesModal.tsx`, `components/RecoveryKeyModal.tsx`, `crypto/recoveryKey.ts`.

---

## Architecture (verified)

| Concern | Implementation |
|---------|----------------|
| Per-entry encryption | Master key → HKDF `deriveEntryKey(master, entryId, salt)` → `encryptData` per field (password, title, username, url, notes, aux) |
| At-rest store (native) | `expo-secure-store` via `writePlatformItem` / `readPlatformItem` — **no** AsyncStorage usage in app code |
| At-rest store (web) | `localStorage` for the **same** keys |
| Cached master key | `pipass_master_key` in keychain service `group.com.pipass.shared` with `requireAuthentication: true` when biometrics/device secret available; otherwise refuse to store |
| Shared vault mirror | `pipass_shared_vault` in same keychain group; field named `encryptedBlob` is `JSON.stringify(entries)` of local entry records — **not** an outer encryption layer |
| Recovery | Generate 32-byte key → store **SHA-256 hash only**; unlock-with-recovery is **explicitly unimplemented** |
| Lock | UI lock + auto-lock 120s / background; key shares moved to `lockedSharesRef`, not wiped |

---

## Findings

### V1 — Recovery key cannot recover the vault (false recovery promise)

| Field | Detail |
|-------|--------|
| **Location** | `crypto/recoveryKey.ts` (hash only); `lib/firstTimeSetup.ts` 229–230, 286; `workers/storageWorker.ts` 225–230 (`pipass_recovery_key_hash`); `app/(tabs)/index.tsx` 800, 820–835; `components/RecoveryKeyModal.tsx` (UX claims sole recovery path) |
| **What is wrong** | Setup generates a recovery key and persists only `hashRecoveryKey(raw)`. The recovery key **never wraps the master key**, never encrypts vault DEKs, and is never an input to unlock. UI copy says vault recovery needs password **or recovery key**. Forgot-password flow admits: "Recovery key unlock is not yet available" / "Coming Soon". Stored hash can only prove possession of a key that **does nothing cryptographic**. Shamir split in the modal only splits this non-functional secret. |
| **Risk** | **Critical** (product/security integrity; users rely on a dead recovery mechanism) |
| **Attack / failure scenario** | User loses master password, produces recovery key as instructed → still cannot decrypt vault. Only option is nuclear wipe. Users who believed recovery existed may have weaker operational backups. |
| **Recommendation** | Either implement recovery properly (wrap master key under recovery-key-derived KEK; store wrapped DEK; unlock path verifies hash then unwraps) or **stop generating/storing recovery keys and remove all UX claims**. Partial recovery (hash-only) is worse than none. |

---

### V2 — "Lock" does not destroy key material

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` 531–536 (`onLock`: `lockedSharesRef.current = keyShares` then `setKeyShares(null)`); auto-lock / background in `screens/VaultScreen.tsx` 321–324, 398–400; `lib/vaultSession.ts` cleared via `setActiveKeyShares(null)` when React state nulls |
| **What is wrong** | Lock is a UI overlay. Master-key XOR shares are **retained** in `lockedSharesRef` for the entire locked period. Process dump, debugger, or compromised JS after "lock" still yields vault key without re-deriving from password. Cached `pipass_master_key` is **not** cleared on lock (only on nuclear paths / explicit clear). |
| **Risk** | **Critical** for any threat model that includes locked phone / backgrounded app / in-process malware |
| **Attack scenario** | User locks vault or app backgrounds. Attacker with runtime access (Frida, compromised JS, same-process inspection) reads `lockedSharesRef` → full decrypt of all entries without biometric or password. |
| **Recommendation** | On lock: wipe all shares (refs + `vaultSession`), clear decrypted React state, clear keychain cache. Unlock must re-derive from password or authenticated keychain read. Soft-lock without wipe is not a lock. |

---

### V3 — Web platform stores the entire vault in localStorage

| Field | Detail |
|-------|--------|
| **Location** | `lib/platformStorage.ts` 50–55, 72–74; all vault keys go through this path when `Platform.OS === "web"` |
| **What is wrong** | On web there is **no** SecureStore/Keychain. Ciphertexts, salts, master hash, KDF metadata, recovery hash, auth credentials, entry JSON, and shared vault blob all live in `localStorage`. XSS, browser extensions, shared machine profiles, and DevTools export get the full vault package. `storeMasterKeySecurely` no-ops on web (good) but does not fix ciphertext/metadata exposure. |
| **Risk** | **Critical** for web builds / browser deploy |
| **Attack scenario** | XSS or malicious extension reads `localStorage` → offline brute-force of master password + full encrypted vault. |
| **Recommendation** | Do not ship vault secrets to web without WebCrypto non-extractable keys and no `localStorage` for vault blobs; or disable vault on web and document native-only. |

---

### V4 — Shared "encrypted" blob is not encrypted as a blob; expands attack surface

| Field | Detail |
|-------|--------|
| **Location** | `workers/storageWorker.ts` 113–119, 122–140; `workers/sharedVaultStorage.ts` (`pipass_shared_vault`, keychain group `group.com.pipass.shared`, **no** `requireAuthentication`) |
| **What is wrong** | `encryptedBlob: JSON.stringify(entries)` duplicates every vault entry record into an App Group keychain item accessible to any binary entitled to `group.com.pipass.shared`. Naming implies an extra encryption layer; there is none. Writes on every save/update/delete entry. |
| **Risk** | **High** |
| **Attack scenario** | Second app in the same keychain access group (or backup of the group) obtains the full entry set (ciphertext + salts + ids + plaintext note labels / legacy fields) without user auth prompt. |
| **Recommendation** | Gate shared container with device auth, encrypt outer blob under a non-shared key, minimize group membership, or remove shared duplicate if unused. Rename field until real outer encryption exists. |

---

### V5 — Vault entry envelopes are unauthenticated; same entry key enables field swap

| Field | Detail |
|-------|--------|
| **Location** | `workers/vaultWorker.ts` 119–140 (multi-field encrypt under one `entryKey`); `crypto/encryption.ts` MAC covers only iv+ciphertext with no field AAD; `storageWorker.saveEntry` |
| **What is wrong** | (1) No vault-level MAC over the set of entries or the index — attacker with write access can delete/reorder/orphan entries via `pipass_vault_index` without detection. (2) All fields of one entry use the **same** subkey. MAC does not bind field name. Attacker can swap `encryptedPassword` with `encryptedUsername`: both verify under the entry key; app shows attacker-chosen mapping. (3) Outer JSON fields (`id`, `salt`, timestamps, optional legacy plaintext) are integrity-free. |
| **Risk** | **High** |
| **Attack scenario** | Malware or backup tampering swaps password/username ciphertexts → user copies wrong secret into a login form; or hides high-value entries by pruning the index. |
| **Recommendation** | Include associated data in MAC/AEAD (`entryId + fieldName + version`). Add vault root MAC over sorted (id, ciphertext hash) updated on each write. |

---

### V6 — Secrets and sensitive plaintext live in React state while unlocked

| Field | Detail |
|-------|--------|
| **Location** | `screens/VaultScreen.tsx` 105 `decryptedEntry`; 343–365 `withDisplayFields` decrypts every entry title/username/url into list state; `profilePassword`; `app/(tabs)/index.tsx` 111–115 `keyShares`, `pendingRecoveryRawHex`, `pendingRecoveryKey`; `pendingSetupCommitRef` holds `masterKeyHex`; SecureNotes / EntryDetail plaintext |
| **What is wrong** | List path decrypts all titles/usernames/urls on load into `entries` React state. Setup holds raw recovery key hex and master key across the recovery modal. Open entry keeps full decrypted password in state. |
| **Risk** | **High** |
| **Attack scenario** | While unlocked, memory dump or React DevTools yields all site titles/usernames and any open password. During setup, recovery key sits in state until confirm. |
| **Recommendation** | Lazy-decrypt list fields; minimize password lifetime in state; wipe setup secrets immediately after commit. |

---

### V7 — Master key cache written but never used for unlock (dead secret at rest)

| Field | Detail |
|-------|--------|
| **Location** | `workers/storageWorker.ts` 383–448; stored from unlock/setup; **no production caller of `getMasterKeySecurely` for unlock** |
| **What is wrong** | Full master key hex is persisted to the shared keychain group under biometric protection, then ignored for unlock (password re-derive always). Increases at-rest secret inventory for no product benefit. `__DEV__` can read cache without authentication when biometrics unavailable. |
| **Risk** | **High** |
| **Attack scenario** | Compromised app binary after one successful biometric prompt exports `pipass_master_key` → full vault. |
| **Recommendation** | Remove cache until a real biometric-unlock path exists; or implement unlock-from-cache. Prefer non-exportable hardware keys. |

---

### V8 — Most vault data stored without per-read biometric gate

| Field | Detail |
|-------|--------|
| **Location** | `workers/storageWorker.ts` entry/note/salt/hash/KDF/recovery paths use `writePlatformItem` without `requireAuthentication`; only `pipass_master_key` uses auth |
| **What is wrong** | Default SecureStore accessibility is device-unlock class, not user-presence per read. Unlocked phone or class-eligible backup yields full offline attack package (ciphertext + salt + kdf metadata + deviceUUID + master hash). |
| **Risk** | **Medium-High** |
| **Attack scenario** | Unlocked device extract / backup → offline password attack without Face ID for vault blobs. |
| **Recommendation** | Clarify threat model; keep DEK only in memory after unlock; do not market entry blobs as biometric-isolated. |

---

### V9 — Secure notes store plaintext label at rest

| Field | Detail |
|-------|--------|
| **Location** | `workers/vaultWorker.ts` 300–307 (`label` plaintext + `encryptedLabel`); `pipass_note_*` |
| **What is wrong** | Note titles readable from SecureStore/localStorage without master password. Storage confidentiality break (Stage 1 C13 restated for storage layer). |
| **Risk** | **High** |
| **Attack scenario** | SecureStore dump lists note titles ("Bank PINs", "Seed phrase") without unlock. |
| **Recommendation** | Drop plaintext `label`; migrate; list UI decrypts only while unlocked. |

---

### V10 — Legacy plaintext fields and re-save footgun

| Field | Detail |
|-------|--------|
| **Location** | `workers/vaultWorker.ts` optional `title`/`username`/`url`; `withDisplayFields` re-injects plaintext into in-memory entry objects |
| **What is wrong** | New encrypt omits plaintext (good). Display enrichment puts plaintext back on objects that must never be persisted via a naive `saveEntry(listItem)`. |
| **Risk** | **Medium** |
| **Attack scenario** | Future code path saves list state → plaintext credentials re-enter storage. |
| **Recommendation** | Strip plaintext on every `saveEntry`; migration scan; disk type forbids plaintext fields. |

---

### V11 — Clipboard: recovery key never auto-cleared; password clear incomplete on unmount

| Field | Detail |
|-------|--------|
| **Location** | `EntryDetailModal.tsx` 13, 48–51, 91–104 (30s clear; unmount clears **timer only**, not clipboard); `SecureNotesModal.tsx` same; `RecoveryKeyModal.tsx` 63–69 (copy; **no** wipe) |
| **What is wrong** | Recovery key / Shamir shares remain on clipboard indefinitely after copy. Password clipboard may survive navigation if component unmounts before 30s (timer cancelled without wipe). No platform sensitive-clipboard flags. |
| **Risk** | **High** (recovery key); **Medium** (passwords) |
| **Attack scenario** | User copies recovery key during setup → clipboard history / other apps retain full secret. |
| **Recommendation** | Wipe clipboard on modal unmount and app background. Force short TTL for recovery material. Prefer non-clipboard export. |

---

### V12 — Secrets appear in logs (lengths and setup diagnostics)

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` passwordLength logs; `lib/firstTimeSetup.ts` masterPasswordLength; `crypto/keyDerivation.ts` pwLen |
| **What is wrong** | Password/material lengths leak to logcat/metro. Full master key hex not observed in reviewed log paths. |
| **Risk** | **Medium** |
| **Recommendation** | Production builds: no password-length or key-material logs. |

---

### V13 — Auth credentials co-resident with vault storage

| Field | Detail |
|-------|--------|
| **Location** | `lib/credentials.ts` `pipass.auth.userId`, `pipass.auth.authHash` unauthenticated platform storage |
| **What is wrong** | Server auth proof stored alongside vault metadata. Vault lock does not clear credentials. Nuclear reset does. |
| **Risk** | **Medium** |
| **Attack scenario** | Local extract yields online auth proof + offline vault package. |
| **Recommendation** | Keystore with auth; consider clearing on vault lock; never use web localStorage for authHash. |

---

### V14 — Partial wipe paths leave attack inputs behind

| Field | Detail |
|-------|--------|
| **Location** | `workers/storageWorker.ts` `clearVault` 215–223 vs `destroyAllData` 233–250 |
| **What is wrong** | `clearVault` removes entries/index/master hash/shared vault; **keeps** salt, KDF metadata, profile, recovery hash, notes (notes only in destroy). |
| **Risk** | **Medium** if misused as secure erase |
| **Recommendation** | User-facing wipe must call `destroyAllData` only. |

---

### V15 — AsyncStorage not used for vault (informational)

| Field | Detail |
|-------|--------|
| **Location** | No AsyncStorage imports in app source; vault uses SecureStore/localStorage only |
| **What is wrong** | Nothing for AsyncStorage. Residual risk is SecureStore/localStorage as above. |
| **Risk** | **Informational** |
| **Recommendation** | Remove unused async-storage dependency if present and unused. |

---

### V16 — Setup / recovery UX ordering and half-written state

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` recovery modal then commit; prepare holds keys in memory; staged backup can import under setup key |
| **What is wrong** | Crash after metadata writes but before user saves recovery key leaves vault shell with unusable recovery hash and no shown recovery secret. |
| **Risk** | **Medium** |
| **Recommendation** | Atomic commit; do not mark initialized until recovery acknowledged; solid repair path. |

---

### V17 — Fractal fingerprint is not vault integrity protection

| Field | Detail |
|-------|--------|
| **Location** | `screens/VaultScreen.tsx` fractal verify; `pipass_fractal_fingerprint` |
| **What is wrong** | Derived from master key; stored without binding to entry set. Storage errors **fail open**. Does not authenticate ciphertexts. |
| **Risk** | **Low-Medium** (false confidence) |
| **Recommendation** | Do not treat as vault integrity root. |

---

## Storage inventory (sensitivity)

| Key / state | Store | Auth gated? | Sensitivity |
|-------------|-------|-------------|-------------|
| `pipass_vault_<id>` | SecureStore / localStorage | No | Ciphertext + salt + metadata |
| `pipass_vault_index` | same | No | Entry existence/order |
| `pipass_note_<id>` | same | No | Ciphertext + **plaintext label** |
| `pipass_notes_index` | same | No | Note existence |
| `pipass_master_salt` | same | No | KDF salt |
| `pipass_master_hash` | same | No | Master key verifier |
| `pipass_kdf_metadata` | same | No | Algorithm/params |
| `pipass_security_profile` | same | No | Profile label |
| `pipass_recovery_key_hash` | same | No | Recovery verifier (non-functional unlock) |
| `deviceUUID` | same | No | KDF binding |
| `pipass_master_key` | Keychain group + biometrics when available | Yes (when stored) | **Raw master key hex** |
| `pipass_shared_vault` | Keychain group, no user-presence | No | Full entry set JSON |
| `pipass.auth.*` | SecureStore / localStorage | No | Online auth proof |
| `keyShares` / `lockedSharesRef` | JS heap | N/A | Live master key |
| `decryptedEntry` / list display fields | React state | N/A | Plaintext secrets/metadata |
| Clipboard | OS | N/A | Copied secrets |

---

## Stage 2 risk tally

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 3 | V1, V2, V3 |
| **High** | 6 | V4, V5, V6, V7, V9, V11 |
| **Medium** | 6 | V8, V10, V12, V13, V14, V16 |
| **Low / Info** | 2 | V15, V17 |

---

## Priority remediation (Stage 2 only)

1. Implement real recovery wrapping **or delete recovery feature and all claims** (V1).  
2. Hard lock: wipe shares + clear cache; re-auth to unlock (V2, V7).  
3. Disable or redesign web vault storage (V3).  
4. Outer MAC/AEAD with field AAD; fix shared blob (V4, V5).  
5. Remove plaintext note labels; clipboard TTL + unmount wipe (V9, V11).  
6. Minimize React plaintext surface; strip production logs (V6, V12).  

---

## Explicit non-claims

- SecureStore on native is **not** hardware-bound non-exportable isolation for vault entry blobs.  
- Biometric AuthScreen gate does not encrypt vault blobs by itself.  
- Server vault blob sync was not fully re-audited beyond the local shared mirror.

---

*End of Stage 2 – Vault Encryption & Secure Storage*

# Security Audit – Stage 3: Authentication, Unlock & Session

**Role:** Senior Mobile Security Engineer  
**Date:** 2026-08-06  
**Scope:** Device authentication gate, master-password unlock, biometric step-up, auto-lock / soft-lock, in-memory key lifetime, recovery/reset, client session/credential handling.  
**Out of scope:** Re-deriving Stage 1 primitive crypto defects or Stage 2 storage layout except where they directly change unlock/session risk.  
**Method:** Trace `AuthScreen` → unlock → vault session → lock/background; review `biometricGate`, `currentUnlock`, `VaultScreen` auto-lock, nuclear reset, `credentials` / `logout` / `query-client`.

---

## Verified unlock architecture

```
App cold start
  └─ AuthScreen (device Face ID / fingerprint / device passcode)
       └─ authenticated = true  (React state only; not vault crypto)
            └─ Startup repair → setup | unlock
                 └─ UnlockScreen (master password)
                      └─ planUnlockKdfDerivation + hashMasterKey check
                           └─ masterKeyHex → splitKeyIntoShares
                           └─ storeMasterKeySecurely(masterKeyHex)  [side effect]
                           └─ keyShares in React state + vaultSession
                                └─ Soft lock: keyShares=null, shares kept in lockedSharesRef
                                └─ Hard wipe: only nuclear reset / destroyAllData / tamper path
```

**Two independent gates**

| Gate | What it proves | What it unlocks |
|------|----------------|-----------------|
| AuthScreen | Device owner (OS biometrics or device passcode) | App UI shell only |
| UnlockScreen | Knowledge of master password (+ deviceUUID + salt + KDF) | Cryptographic vault key shares |

They are **not** bound: passing AuthScreen does not derive the vault key; deriving the vault key does not re-check device biometrics.

---

## Master key movement during unlock (traced)

1. User submits password string in `UnlockScreen` React state (`app/(tabs)/index.tsx` UnlockScreen).  
2. `performCurrentUnlockVerification` loads `pipass_master_hash` + KDF metadata.  
3. `planUnlockKdfDerivation` derives `masterKeyHex` (Argon2id or PBKDF2 per metadata / legacy detection).  
4. `hashMasterKey(masterKeyHex)` compared to stored hash (`===`, not constant-time — Stage 1).  
5. On success: `splitKeyIntoShares(masterKeyHex)` → `{ shareA, shareB }` `Uint8Array`s.  
6. `storeMasterKeySecurely(masterKeyHex)` may persist full key hex to keychain (auth-gated when biometrics available).  
7. `masterKeyHex` string is not explicitly wiped after split (immutable JS string).  
8. Shares returned to `onUnlocked` → `setKeyShares(shares)` → `VaultScreen` + `setActiveKeyShares(shares)`.  
9. Entry ops: `combineShares` → temporary hex → HKDF entry key → encrypt/decrypt → best-effort buffer wipe of copies only.  
10. Soft lock: React `keyShares` nulled; **same share object** stored in `lockedSharesRef`; `vaultSession` cleared.

---

## Findings

### A1 — Soft lock leaves the vault cryptographically unlocked

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` 531–537 (`onLock` assigns `lockedSharesRef.current = keyShares`); re-unlock 560–567 wipes only after **successful** password re-entry |
| **What is wrong** | Auto-lock, manual lock, and AppState background call `onLock`, which only hides UI and nulls React key state. Master-key shares remain live in `lockedSharesRef`. No password re-derivation is required for the process to keep decrypt capability. This is the primary “vault unlocked longer than intended” defect. (Storage cache behavior: Stage 2 V2/V7.) |
| **Risk** | **Critical** |
| **Attack scenario** | User locks or backgrounds app. Attacker with runtime access (malware, debugging, compromised WebView bridge) reads `lockedSharesRef` and decrypts every entry without master password or biometric. |
| **Recommendation** | Soft lock must `wipeShares`, clear `lockedSharesRef`, clear keychain master-key cache, and clear plaintext list state. Next unlock must fully re-run KDF (or auth-gated keychain unwrap of a wrapped DEK). |

---

### A2 — Device biometric gate is once-per-process and is not re-checked on vault re-unlock

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` 104, 250–251 (`authenticated`); `screens/AuthScreen.tsx` success → `onAuthenticated()`; soft-lock UnlockScreen path never re-mounts AuthScreen |
| **What is wrong** | After first successful device auth, `authenticated` stays `true` until nuclear reset, tamper lock, or `onReset`. Soft-locked vault re-unlock is **master password only**. Device biometric is not a continuous vault policy; it is an app entry gate. |
| **Risk** | **High** |
| **Attack scenario** | User unlocks device auth once, walks away after soft-lock. Co-worker who knows/guesses master password (or weaker, if legacy path) re-opens vault without Face ID. Conversely, device passcode thief who does not know master password is blocked at UnlockScreen only — but already saw setup/unlock UI and salt-driven timing. |
| **Recommendation** | Product decision: either re-prompt device auth on every vault unlock, or stop marketing biometrics as vault unlock. Prefer binding soft re-unlock to biometric **or** password, with wipe-on-lock. |

---

### A3 — Device passcode fallback demotes “biometric” to device unlock secret

| Field | Detail |
|-------|--------|
| **Location** | `screens/AuthScreen.tsx` 72–78 (`disableDeviceFallback: false`); `crypto/biometricGate.ts` 95–101 (same for secret viewing) |
| **What is wrong** | Both app entry and “view password” prompts allow OS passcode fallback. Any party who knows the device PIN/pattern satisfies AuthScreen and step-up for entry decryption (while vault key is in memory). For a password manager, this is weaker than “biometrics only” if advertised that way. |
| **Risk** | **High** (policy / threat-model) |
| **Attack scenario** | Shoulder-surfed device PIN → AuthScreen pass → if vault already soft-unlocked in process with retained shares (A1), or after password entry, step-up for each secret is also PIN. |
| **Recommendation** | Optional strict mode: `disableDeviceFallback: true` for secret reveal; accept UX failure when biometrics unavailable. Document that device PIN is equivalent to biometric gate. |

---

### A4 — Plaintext vault metadata remains in React state while “locked”

| Field | Detail |
|-------|--------|
| **Location** | `screens/VaultScreen.tsx` 343–365 `withDisplayFields`; lock effect 148–165 clears selected/decrypted entry but **not** `entries` |
| **What is wrong** | While soft-locked, `VaultScreen` stays mounted (`keyShares \|\| vaultLocked`). `entries` still holds decrypted titles/usernames/urls injected for list display. Overlay may hide UI; memory and any accessibility/debug surface still hold the directory of vault contents. |
| **Risk** | **High** |
| **Attack scenario** | Soft-locked phone + memory inspection or residual UI leak reveals all account labels without master password re-entry. |
| **Recommendation** | On lock: `setEntries([])` or strip to ciphertext-only shapes; re-hydrate display fields only after unlock. |

---

### A5 — No client-side unlock throttling or attempt accounting

| Field | Detail |
|-------|--------|
| **Location** | `UnlockScreen.handleUnlock` (`app/(tabs)/index.tsx` 746–787); nuclear `verifyPassword` wrappers |
| **What is wrong** | Unlimited sequential master-password attempts. Work factor is only the KDF (Argon2/PBKDF2). No exponential backoff, no local attempt counter, no wipe-after-N, no OS-level progressive delay. Online attackers on an unlocked device can script attempts as fast as KDF allows. |
| **Risk** | **Medium-High** (depends on master password strength and KDF) |
| **Attack scenario** | Stolen unlocked phone / debug build: automated password list against UnlockScreen; Argon2 64 MiB slows but does not stop weak passwords. |
| **Recommendation** | After N failures: increasing delay, temporary lockout, optional wipe warning; never reduce KDF cost. |

---

### A6 — Nuclear-reset password verify uses silent-downgrade KDF path

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` 508–516, 587–595; `screens/VaultScreen.tsx` 662–672 — all call `deriveMasterKeyShares` → `deriveMasterKey` (Stage 1 C1), **not** `planUnlockKdfDerivation` |
| **What is wrong** | Destructive reset authorization may fail closed (false wrong password) or, worse in edge algorithm mismatch cases, behave inconsistently with real unlock. Reset is a high-risk control that must use the same verifier as unlock. |
| **Risk** | **High** |
| **Attack / failure scenario** | User cannot authorize legitimate wipe when Argon2 path differs; or verification accepts wrong algorithm-derived key under exotic failure modes. |
| **Recommendation** | Route all password proofs through `performCurrentUnlockVerification` / metadata planner; never `deriveMasterKeyShares` for authz. |

---

### A7 — Recovery path is non-functional; only nuclear wipe remains

| Field | Detail |
|-------|--------|
| **Location** | UnlockScreen forgot flow (`app/(tabs)/index.tsx` 789–838); Stage 2 V1 |
| **What is wrong** | UI still implies recovery key helps; implementation is “Coming Soon”. Forgot-password security control is effectively **destroy all data** after multi-step confirm. No session invalidation of server accounts is tied to vault wipe beyond `destroyAllData` → `clearCredentials`. |
| **Risk** | **High** (availability / false recovery); wipe path itself is relatively careful |
| **Recommendation** | Implement wrap-based recovery or remove claims; ensure nuclear wipe always clears server credentials and any future session tokens. |

---

### A8 — Auto-lock timing is coarse; biometric suppress window is exploitable only briefly

| Field | Detail |
|-------|--------|
| **Location** | `AUTO_LOCK_MS = 120000`; interval 5s (`VaultScreen` 398–400); AppState lock 321–324; `isBiometricActive` suppress during entry open bio |
| **What is wrong** | Idle lock can fire up to ~5s late (poll interval). Continuous touch resets activity — correct for UX, means vault can stay open indefinitely while user interacts or a malicious overlay generates touch events. `inactive` locks on Control Center / notification shade — aggressive UX; suppressed only when `isBiometricActive`. If `isBiometricActive` stuck true due to thrown path before `finally`, auto background lock could be disabled — code uses `finally` to clear (good). Multiple `loadVault` retries can stack intervals (timer leak), not an unlock extension of consequence. |
| **Risk** | **Medium** |
| **Attack scenario** | Accessibility malware synthesizes touches → prevents idle lock while reading screen. Or user expects instant lock on leave; 2 min + 5s grace leaves secrets visible. |
| **Recommendation** | Configurable shorter idle; lock on `background` always; consider lock on blur of secure screens; single auto-lock timer lifecycle. |

---

### A9 — Step-up biometric for secrets is inconsistently applied

| Field | Detail |
|-------|--------|
| **Location** | Entry open: `handleSelectEntry` requires bio then decrypts (`VaultScreen` 455–483). List already shows title/username without bio. Secure notes: bio on save/view paths. Clipboard copy in `EntryDetailModal`: **no** additional bio after detail already open. `biometricDecryptGuard` (2s freshness + invalidate) exported but entry path uses raw `requireFreshBiometric` instead. |
| **What is wrong** | Directory of sites/usernames is free once vault unlocked. Full password needs bio once per open; after open, show/copy password has no re-auth. `STALENESS_MS = 2000` only matters for the rarely used guard helper. |
| **Risk** | **Medium** |
| **Attack scenario** | Unlocked vault + brief physical access: scroll list (no bio) harvests usernames/sites; open one entry after one Face ID, copy password. |
| **Recommendation** | Align policy: bio for list decrypt optional; bio for copy password; or master-password re-prompt for high-risk actions. |

---

### A10 — App-level `authenticated` flag is pure memory; no secure session object for vault

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` `useState(false)` for `authenticated` |
| **What is wrong** | No signed session, no expiry, no idle timeout on the device gate itself. Vault soft-lock does not clear `authenticated`. Process survival = device gate still open. This is acceptable only if soft lock is cryptographically hard (it is not — A1). |
| **Risk** | **Medium** (combined with A1 → High) |
| **Recommendation** | Tie `authenticated` false on vault lock, or drop AuthScreen entirely and use password+optional bio only at unlock. |

---

### A11 — Client server “session” is long-lived authHash; raw session tokens not persisted (and login never stores credentials)

| Field | Detail |
|-------|--------|
| **Location** | `lib/credentials.ts`; `lib/query-client.ts` `authedApiRequest`; `lib/logout.ts` (“client does not persist session tokens”); `setCredentials` has **zero** production callers in repo |
| **What is wrong** | Server supports `x-session-token` sessions; client policy/docs choose legacy `x-user-id` + `x-auth-hash`. Logout cannot revoke a server session without a raw token. Vault lock does not clear API credentials. Additionally, **no app code calls `setCredentials`**, so server-authenticated features may be dead or wired outside this tree — either credentials are never set (features fail closed) or an untracked path sets them. If authHash is present, it outlives vault lock and is a durable bearer-like secret (Stage 2 V13). |
| **Risk** | **Medium** for account API; **Low** for local vault crypto isolation (gates are separate — good) |
| **Attack scenario** | Extracted `authHash` works for API while vault soft-locked; server session list “logout this device” may not match client reality. |
| **Recommendation** | Finish one auth model: persist session token in SecureStore with logout-all on nuclear reset, **or** keep authHash but rotate and clear on vault lock/logout UI. Wire `setCredentials` or delete dead security dashboard paths. |

---

### A12 — Unlock success still writes master key to keychain without using it for next unlock

| Field | Detail |
|-------|--------|
| **Location** | `performCurrentUnlockVerification` 90–96 always `storeMasterKeySecurely`; re-lock does not clear; UnlockScreen never calls `getMasterKeySecurely` |
| **What is wrong** | Every successful password unlock refreshes an exportable master-key cache that is unused for session resume. Extends secret lifetime beyond the in-memory session without enabling biometric-only vault unlock. |
| **Risk** | **High** (same class as Stage 2 V7; session-lifetime angle) |
| **Recommendation** | Stop writing on unlock until biometric-unlock-from-keystore is implemented; clear cache on every lock. |

---

### A13 — AuthScreen `__DEV__` bypass

| Field | Detail |
|-------|--------|
| **Location** | `AuthScreen.tsx` 94–99, 104–106; `biometricGate` `canUseDevBypass: __DEV__` |
| **What is wrong** | Dev bypass correctly gated on `__DEV__`. Residual risk: mis-built release with `__DEV__` true, or attackers using dev clients against production data. |
| **Risk** | **Low** if release builds strip `__DEV__`; **Critical** if not |
| **Recommendation** | CI assert `__DEV__ === false` in release; never ship dev client against real vault backups. |

---

### A14 — Integrity/tamper lock vs soft lock inconsistency

| Field | Detail |
|-------|--------|
| **Location** | `app/(tabs)/index.tsx` 156–173 tamper callback wipes shares and sets `authenticated false`; soft lock does not |
| **What is wrong** | Tamper path is closer to correct (wipe + drop device gate). Soft lock is weaker than “security alert” lock, teaching two security levels where users only perceive one “lock”. |
| **Risk** | **Medium** (policy inconsistency) |
| **Recommendation** | Make soft lock equal tamper lock for key material; differ only in UX copy. |

---

### A15 — Password string lifetime on unlock / reset modals

| Field | Detail |
|-------|--------|
| **Location** | UnlockScreen `password` state; NuclearResetModal `password` state cleared on close via `resetState` |
| **What is wrong** | UnlockScreen does not `setPassword("")` immediately on success (relies on unmount). Nuclear modal clears on hide (good). Standard RN limitation; still increases heap exposure during KDF (seconds). |
| **Risk** | **Low-Medium** |
| **Recommendation** | Clear password state in `finally` after unlock attempt; avoid logging. |

---

## Session / lock duration summary

| Event | Device gate | Master key shares | Plaintext list | Keychain master cache | Server authHash |
|-------|-------------|-------------------|----------------|----------------------|-----------------|
| Cold start | Required | Absent | Absent | May exist from prior unlock | May exist |
| AuthScreen pass | Open for process | Absent | Absent | Untouched | Untouched |
| Password unlock | Open | Live in state + vaultSession | Loaded/decrypted fields | Written/refreshed | Untouched |
| Idle 2 min / background | Open | **Kept in lockedSharesRef** | **Still in entries state** | **Kept** | Untouched |
| Soft re-unlock | Open | New shares after KDF | Reloaded | Written again | Untouched |
| Nuclear wipe | Closed | Wiped | Destroyed storage | Cleared | Cleared |

**Intended max unlock:** ~2 minutes idle or until background — **not enforced for key material** (A1).  
**Actual max unlock:** process lifetime of retained shares + any keychain cache.

---

## Stage 3 risk tally

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 1 | A1 |
| **High** | 6 | A2, A3, A4, A6, A7, A12 |
| **Medium / Medium-High** | 6 | A5, A8, A9, A10, A11, A14 |
| **Low** | 2 | A13, A15 |

---

## Priority remediation (Stage 3)

1. **Hard soft-lock:** wipe shares, strip list plaintext, clear master-key cache (A1, A4, A12).  
2. **Single password verifier** for unlock and nuclear reset (A6).  
3. **Policy honesty:** re-auth device on vault unlock or stop calling biometrics “vault unlock” (A2, A3).  
4. **Unlock throttling** (A5).  
5. **Recovery implement or remove** (A7).  
6. **Finish server credential lifecycle** (set/clear/logout) aligned with vault lock (A11).  

---

*End of Stage 3 – Authentication, Unlock & Session*

# Security Audit – Stage 4: React Native & Platform Risks

**Role:** React Native / mobile platform security (Android + iOS)  
**Date:** 2026-08-06  
**Scope:** Storage APIs, React state/context, screenshots, clipboard, deep links, logging, root/jailbreak posture, debug vs release, backup exposure, reverse-engineering resistance.  
**Out of scope:** Pure cryptographic algorithms (Stages 1–3); do not re-list those except where a platform control interacts with them.  
**Method:** Review `AndroidManifest.xml`, `MainActivity.kt`, `build.gradle`, `proguard-rules.pro`, `gradle.properties`, `app.json`, Expo plugins (`withFlagSecure`, `withNativeArgon2`), `platformStorage`, screen-capture usage, deep-link routing, `integrityGuard`, WebView usage, logging sites.

---

## Platform posture (verified facts)

| Area | Finding |
|------|---------|
| Vault storage API | `expo-secure-store` on native via `lib/platformStorage.ts`; **not** AsyncStorage for vault keys |
| Web storage | Same keys in `localStorage` (Stage 2 V3) |
| Android backup | `android:allowBackup="true"` in `AndroidManifest.xml` |
| Android screenshots | `FLAG_SECURE` when `BuildConfig.ALLOW_SCREENSHOTS == false` (release); **allowed** in debug |
| iOS screenshots | `expo-screen-capture.preventScreenCaptureAsync()` only while `VaultScreen` is mounted |
| Deep links | Schemes `pipass`, `exp+pipass`; `app/+native-intent.tsx` forces path `'/'` |
| Root/jailbreak | **No** real root/Magisk/jailbreak API checks; only weak emulator/devtools heuristics |
| Minify/R8 | Enabled for release via `expo-build-properties` / `gradle.properties` |
| JS engines | Android Hermes (`hermesEnabled=true`); iOS **JSC** (`app.json` `ios.jsEngine: "jsc"`) |
| Signing secrets | **Plaintext** `storePassword` / `keyPassword` in local `android/app/build.gradle` |

---

## Findings

### P1 — Android Auto Backup enabled (`allowBackup="true"`)

| Field | Detail |
|-------|--------|
| **Location** | `android/app/src/main/AndroidManifest.xml` line 19: `android:allowBackup="true"`; no `fullBackupContent` / `dataExtractionRules` exclusions found |
| **What is wrong** | For a password manager this is a default **fail**. Cloud/device backup and `adb backup` (where still available) can extract app-private files. Even when secrets sit in SecureStore/Keystore-wrapped storage, backup surfaces ciphertext, salts, KDF metadata, indexes, and any non-keystore material. MASVS expects backup disabled or tightly filtered for high-value apps. |
| **Risk** | **Critical** |
| **Attack scenario** | Attacker with Google account access to device backups, or physical access + backup tooling, obtains vault package offline and attacks the master password (Stage 1 KDF). |
| **Recommendation** | Set `android:allowBackup="false"` (and/or `dataExtractionRules` deny-all). Enforce via Expo config plugin so prebuild cannot regress. Review iOS Keychain accessibility / iCloud backup class for SecureStore items separately. |

---

### P2 — Upload keystore passwords hardcoded in Gradle; keystores present on disk

| Field | Detail |
|-------|--------|
| **Location** | `android/app/build.gradle` release `signingConfigs`: `storePassword 'PiPass2026!'`, `keyPassword 'PiPass2026!'`, `storeFile file('upload-keystore.jks')`; `debug` uses default `android`/`android`. Files: `android/app/debug.keystore`, `upload-keystore.jks` (workspace). `*.jks` is gitignored; entire `/android/` is gitignored — secrets still live on developer machines and any shared prebuild output. |
| **What is wrong** | Anyone with the project tree can sign malicious updates as PiPass if they also have the JKS, or crack a weak password. Hardcoded passwords in build scripts are a classic supply-chain and insider failure. Debug keystore with known password ships in every RN template. |
| **Risk** | **Critical** (release signing compromise) |
| **Attack scenario** | Leaked workspace / CI log / zip of project → extract JKS + password → publish trojan update signed as the real app (Play sideload / enterprise). |
| **Recommendation** | Immediate: **rotate upload key** if this password ever left the machine; move secrets to env/`keystore.properties` not in VCS; use EAS secrets / CI secret store; never commit JKS. Treat current password as burned. |

---

### P3 — Screenshot / screen-recording protection is incomplete and inconsistent

| Field | Detail |
|-------|--------|
| **Location** | Android: `plugins/withFlagSecure.js` + `MainActivity.kt` FLAG_SECURE only if `!ALLOW_SCREENSHOTS` (release false, **debug true**). iOS/JS: `screens/VaultScreen.tsx` 273–274 `preventScreenCaptureAsync` on mount, **`allowScreenCaptureAsync` on unmount**. AuthScreen / UnlockScreen / SeedSetupScreen do **not** call preventScreenCapture. |
| **What is wrong** | (1) Password entry on unlock/setup can be screen-recorded on iOS before vault mounts. (2) Leaving VaultScreen re-enables capture. (3) Debug/dev builds intentionally allow screenshots of live vault UI. (4) FLAG_SECURE does not stop all recording paths (some OEM bugs, external cameras). (5) Web has no equivalent. |
| **Risk** | **High** |
| **Attack scenario** | Malicious screen recorder / screen-sharing during unlock; or developer debug build used with production vault data. |
| **Recommendation** | Apply FLAG_SECURE / preventScreenCapture for entire authenticated session (root layout), including unlock and setup. Keep release-only enforcement; never use debug builds with real vaults. |

---

### P4 — Excessive Android permissions expand attack surface

| Field | Detail |
|-------|--------|
| **Location** | `AndroidManifest.xml` 2–11: `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `RECORD_AUDIO`, `SYSTEM_ALERT_WINDOW`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, plus INTERNET, biometrics, VIBRATE |
| **What is wrong** | A password manager does not need location, microphone, or system-alert-window for core vault function. These likely enter via Expo module manifests. `SYSTEM_ALERT_WINDOW` enables overlay UI that can phishing-steal master passwords. Storage permissions broaden file access expectations on older APIs. `app.json` claims `"permissions": []` but **merged native manifest still has them**. |
| **Risk** | **High** |
| **Attack scenario** | Overlay attack draws fake unlock UI over PiPass; user types master password into attacker window. Location/mic unused permissions increase store review scrutiny and malware interest. |
| **Recommendation** | Strip unused permissions with Expo `android.blockedPermissions` / manifest merger tools. Audit every dependency that pulls dangerous permissions. |

---

### P5 — Deep link schemes registered; path forced home (limited but not zero risk)

| Field | Detail |
|-------|--------|
| **Location** | `app.json` `"scheme": "pipass"`; manifest intent-filter `pipass` + `exp+pipass`; `app/+native-intent.tsx` always `return '/'` |
| **What is wrong** | Custom schemes are claimable by other apps on Android (no app-link verification observed for `https://pipass.app` intent filters beyond queries). `+native-intent` correctly collapses paths to `/`, reducing open-redirect/router injection. Residual risks: app wake via `pipass://` to foreground an unlocked session; Expo dev scheme `exp+pipass` in **production** manifest if prebuild retains it. |
| **Risk** | **Medium** |
| **Attack scenario** | Evil app registers same scheme on older Android; steals OAuth-style tokens if ever put in URL (currently not observed). Or link opens app while soft-unlocked (Stage 3), exposing UI. |
| **Recommendation** | Remove `exp+pipass` from release manifests. Prefer verified App Links / Universal Links if external entry needed. On cold start from link, force vault lock. |

---

### P6 — “Root / jailbreak / tamper” detection is security theater

| Field | Detail |
|-------|--------|
| **Location** | `crypto/integrityGuard.ts` — `detectDebugger` (devtools hook / timing loop), `detectEmulator` (brand strings), `detectFunctionHooks` (AES.encrypt toString heuristics), periodic 30s; **no** root binaries, Magisk, SafetyNet/Play Integrity, DeviceCheck, jailbreak paths |
| **What is wrong** | Does not detect real rooted/jailbroken devices. Emulator detection is string-matching and false-positive prone. Hook detection trivial to bypass (rename functions). Tamper callback wiped only in non-`__DEV__`. Advanced attackers ignore this entirely. Marketing this as “integrity protection” would be dishonest. |
| **Risk** | **Medium** (false confidence); **Low** as actual control effectiveness |
| **Attack scenario** | Rooted device with Frida: integrity guard never fires; vault keys extracted from JS heap (Stages 2–3). |
| **Recommendation** | Either invest in Play Integrity / DeviceCheck as **signals** (not hard roots of trust) or delete the theater and document “no root resistance.” Never block legitimate users solely on weak heuristics without server policy. |

---

### P7 — Production logging of unlock/setup diagnostics on device logcat

| Field | Detail |
|-------|--------|
| **Location** | `crypto/keyDerivation.ts` extensive `console.log` (backend, memory, **pwLen**, success); `lib/firstTimeSetup.ts` password length; `app/(tabs)/index.tsx` / `SeedSetupScreen` setup logs — **not** wrapped in `__DEV__` |
| **What is wrong** | On Android, `console.log` → Logcat readable by other apps (older) / `adb logcat` with USB debugging. Password length and KDF path aid attacks and fingerprinting. Release minification does **not** strip `console.log` unless a babel plugin removes them. |
| **Risk** | **High** for physical/USB access; **Medium** otherwise |
| **Attack scenario** | Attacker with `adb` during unlock captures `masterPasswordLength=…` and algorithm choice. |
| **Recommendation** | Babel plugin `transform-remove-console` in production; never log lengths of secrets; gate remaining diagnostics on `__DEV__`. |

---

### P8 — Debug vs production gaps that weaken real vaults

| Field | Detail |
|-------|--------|
| **Location** | `ALLOW_SCREENSHOTS=true` debug; AuthScreen / biometric `__DEV__` bypass; integrity checks skipped or softened in `__DEV__`; `getMasterKeySecurely` unauthenticated read path in `__DEV__` (`storageWorker.ts`); `EX_DEV_CLIENT_NETWORK_INSPECTOR=true` in `gradle.properties`; ErrorFallback stack UI only in `__DEV__` (good) |
| **What is wrong** | Dev affordances are reasonable **if** never pointed at production data. Network inspector flag is project-global. No CI gate observed that fails release builds when `__DEV__` paths are wrong. |
| **Risk** | **Medium** (process); becomes **Critical** if debug APK + real vault |
| **Recommendation** | Document “debug builds = disposable vaults only.” Release checklist: screenshots off, no dev bypass, no network inspector in customer builds. |

---

### P9 — Secrets in React state, refs, module scope (platform memory angle)

| Field | Detail |
|-------|--------|
| **Location** | No Redux. Secrets live in: React state/refs (`keyShares`, `lockedSharesRef`, `decryptedEntry`, passwords, recovery hex) in `app/(tabs)/index.tsx` / `VaultScreen`; module singleton `lib/vaultSession.ts` `activeShares`; **not** in `SecurityContext` (audit UX only — good). WebView fractal does not receive vault keys (good). |
| **What is wrong** | RN bridge + Hermes/JSC heap dumps / Frida can read all of the above. Context is not the problem; **process memory** is. Soft-lock retention (Stage 3 A1) multiplies platform memory risk. |
| **Risk** | **High** on compromised/rooted device; **Medium** baseline RN limitation |
| **Recommendation** | Minimize lifetime; hard lock wipes; avoid global module key holders; never put master key in Context/Redux. Accept RN cannot provide enclave-grade secrecy in JS. |

---

### P10 — AsyncStorage not used for vault (positive); SecureStore misuse classes remain

| Field | Detail |
|-------|--------|
| **Location** | No AsyncStorage imports in app source. Vault path = SecureStore (native) / localStorage (web). |
| **What is wrong** | Correct API choice for native vs AsyncStorage. Residual platform issues: SecureStore size limits, no biometric gate on vault blobs (Stage 2), web localStorage, shared keychain group. Dependency `@react-native-async-storage/async-storage` may still be pulled transitively — ensure nothing migrates vault keys there. |
| **Risk** | **Informational** / residual **Medium** if future misuse |
| **Recommendation** | Lint ban: no vault keys in AsyncStorage. Keep SecureStore for secrets only; never log SecureStore values. |

---

### P11 — Clipboard platform controls missing

| Field | Detail |
|-------|--------|
| **Location** | `expo-clipboard` `setStringAsync` in entry/notes/recovery modals (Stage 2 V11). No Android `ClipDescription.EXTRA_IS_SENSITIVE` / iOS sensitive pasteboard APIs observed. |
| **What is wrong** | OS keyboard/clipboard suggestions and other apps can read clipboard. Recovery key copy has no TTL wipe. |
| **Risk** | **High** for recovery key; **Medium** for passwords |
| **Recommendation** | Mark sensitive clips; wipe on background; short TTL; prefer share sheet with expiry for recovery. |

---

### P12 — WebView used for fractal UI (contained, but JS-enabled)

| Field | Detail |
|-------|--------|
| **Location** | `components/AnimatedFractalView.tsx` — `javaScriptEnabled={true}`, `originWhitelist={["about:blank"]}`, local HTML source; web iframe `postMessage(..., "*")` for security state only |
| **What is wrong** | Local static HTML is lower risk than remote WebView. Still a second JS engine surface. `postMessage` target `"*"` on web is loose. No vault secrets observed in postMessage payload (security level only). |
| **Risk** | **Low-Medium** |
| **Recommendation** | Keep HTML fully static/no remote URLs; avoid injecting user-controlled strings into HTML; pin postMessage origin on web. |

---

### P13 — Reverse-engineering resistance is minimal (expected for RN, poorly compensated)

| Field | Detail |
|-------|--------|
| **Location** | Release R8/ProGuard minify on; `proguard-rules.pro` **keeps** entire Argon2 packages (`com.poowf.argon2.**`, `com.lambdapioneer.argon2kt.**`); Hermes bytecode on Android extractable; iOS JSC bundle easier to inspect than Hermes in some workflows; x86/x86_64 still in `buildArchs` (emulator-friendly release analysis); pure JS crypto (`crypto-js`) fully visible in bundle |
| **What is wrong** | Password managers cannot rely on obfuscation, but this app’s **security-critical logic is almost entirely JS**, so RE cost is low. ProGuard keeps crypto natives fully named. No string encryption, no SSL pinning observed client-side, no anti-Frida. Integrity guard does not change this. |
| **Risk** | **Medium** (accelerates offline attacks and patching); not a substitute for crypto strength |
| **Recommendation** | Assume client is fully reverse-engineered. Put trust in KDF + OS keystore, not obfuscation. Optionally drop x86 from Play releases; enable Hermes on iOS if supported by Expo version. Do not market “anti-tamper.” |

---

### P14 — iOS Keychain access group widens process boundary

| Field | Detail |
|-------|--------|
| **Location** | `app.json` entitlements `keychain-access-groups: group.com.pipass.shared`; shared vault + master key use this service (Stage 2) |
| **What is wrong** | Any binary with the same access group can read shared items. Extra attack surface vs app-private keychain. |
| **Risk** | **Medium-High** |
| **Recommendation** | Use private keychain unless a second app truly needs share; document and minimize. |

---

### P15 — Network inspector enabled in Gradle properties

| Field | Detail |
|-------|--------|
| **Location** | `android/gradle.properties` `EX_DEV_CLIENT_NETWORK_INSPECTOR=true` |
| **What is wrong** | Dev client network inspection should never be on customer release tooling by default. If this property influences release dev-client hybrids, traffic interception becomes easier. |
| **Risk** | **Low-Medium** |
| **Recommendation** | Default false; enable only in local debug properties files excluded from release. |

---

### P16 — Deep link / router origin configured to production site

| Field | Detail |
|-------|--------|
| **Location** | `app.json` expo-router `origin: https://pipass.app` |
| **What is wrong** | Not inherently vulnerable; ensure no token-in-URL auth flows are added later. Current native-intent redirect to `/` is the right defensive default. |
| **Risk** | **Low** (future footgun) |
| **Recommendation** | Forbid auth secrets in query strings via policy and code review. |

---

## Storage comparison (Stage 4 lens)

| Store | Used for vault? | Platform risk |
|-------|-----------------|---------------|
| AsyncStorage | **No** (good) | Would be wrong for secrets |
| SecureStore | Yes (native) | OS-backed; still extractable on unlocked/rooted device; backup policy matters |
| localStorage | Yes (web) | XSS/extensions (Stage 2) |
| Keychain group | Master key cache + shared vault | Cross-app if group shared |
| React state / module | Live keys while unlocked/soft-locked | Frida/heap |

---

## Stage 4 risk tally

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 2 | P1, P2 |
| **High** | 5 | P3, P4, P7, P9, P11 |
| **Medium** | 6 | P5, P6, P8, P12, P13, P14 |
| **Low / Info** | 3 | P10, P15, P16 |

---

## Priority remediation (Stage 4)

1. **`allowBackup="false"`** (+ iOS backup review) — P1.  
2. **Rotate signing keys; remove plaintext passwords from Gradle** — P2.  
3. **Screen protection for all secret screens, release-only** — P3.  
4. **Strip dangerous permissions** — P4.  
5. **Strip production console logging** — P7.  
6. **Clipboard sensitivity + wipe** — P11.  
7. **Replace or demote integrity theater** — P6.  
8. **Assume RE; harden process boundaries (keychain group)** — P13, P14.  

---

*End of Stage 4 – React Native & Platform Risks*

# Security Audit – Stage 5: Architecture & Zero-Knowledge

**Role:** Security Architect (zero-knowledge password managers)  
**Date:** 2026-08-06  
**Scope:** End-to-end architecture: ZK claims, trust boundaries, data egress, sync, offline mode, device trust, migration, backup/recovery.  
**Out of scope:** Re-auditing crypto primitives or RN platform controls except where they define architectural trust.  
**Method:** Server schema/routes (`shared/schema.ts`, `server/routes.ts`, `server/storage.ts`, `server/totp.ts`), client local vault path, backup/import design docs and code, privacy policy vs implementation, prior auth/vault reviews in-repo.

---

## Architecture snapshot (as built)

PiPass is **two systems glued by branding**, not one fully closed ZK product:

| Layer | Role today |
|-------|------------|
| **Local vault (primary)** | Master-password KDF → per-entry encrypt → SecureStore/localStorage. Works fully offline. |
| **Server (optional / partial client wire-up)** | Account auth, opaque vault blob sync/history, sessions, device trust, TOTP/passkeys, audit, honeytokens, rate/anomaly controls. |
| **Client online surface** | Security dashboard + honeytoken APIs use `x-user-id` / `x-auth-hash` when credentials exist. **No production caller of `setCredentials` found**; vault sync from the main app shell is not a first-class closed loop. |

Marketing and `PRIVACY_POLICY.md` describe a complete zero-knowledge cloud password manager. The **implementation is local-first with a sophisticated server that the client only partially consumes.**

---

## Is this truly Zero-Knowledge?

### Strict definition used here

A ZK password manager means: **the service operator cannot obtain plaintext vault secrets or master password under any normal or breach scenario short of breaking modern crypto**, and learns **minimal metadata** required to run the service. Users can verify that claim from protocol design, not marketing.

### Verdict

| Claim | Verdict |
|-------|---------|
| Master password never uploaded | **Supported** (no password field on register/login/sync APIs) |
| Server cannot decrypt vault entry secrets from `encrypted_blob` alone | **Supported by design** if client only uploads ciphertext and never sends keys |
| “We have no technical ability to read vault data” | **Overstated** — operator can read all **metadata**, decrypt **TOTP secrets** with `TOTP_ENCRYPTION_KEY`, observe **usage patterns**, and if client `authHash` is password-derived with weak parameters, offline attack auth material |
| True multi-device ZK product with seamless sync | **Not delivered** — `deviceUUID` in local KDF blocks portable encrypted records; client sync wiring incomplete |
| Offline-only local vault without cloud | **Closest to honest ZK for vault contents** — secrets stay on device; residual: OS, backups, soft-lock, RE (Stages 2–4) |

**Bottom line:** PiPass is **local encryption + optional opaque-blob hosting**, not a complete zero-knowledge *service* in the Bitwarden/1Password/Proton-sense of a finished multi-device product. Server-side security engineering is often careful about not logging blob contents; that is **necessary but not sufficient** for a ZK product claim.

---

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  USER DEVICE                                                 │
│  OS (can dump memory, screenshots, backups if allowed)       │
│  App JS heap (keys while unlocked / soft-locked)             │
│  SecureStore / Keychain group / localStorage                 │
│  Master password knowledge                                   │
└───────────────────────────┬─────────────────────────────────┘
                            │ TLS (assumed; no pinning observed)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  PiPass SERVER (trusted for availability & 2FA secrets)      │
│  PostgreSQL: users, vault_blobs, history, sessions,          │
│  trusted_devices, audit, honeytokens, webauthn, TOTP CT     │
│  TOTP_ENCRYPTION_KEY (can unwrap 2FA secrets)                │
└─────────────────────────────────────────────────────────────┘
```

| Boundary | Who is trusted? | What they can do |
|----------|-----------------|------------------|
| User ↔ OS | OS is **fully trusted** for confidentiality while unlocked | Extract keys, capture UI, backup app data |
| Client ↔ Server | Server **not** trusted for vault plaintext; **is** trusted for TOTP key, audit honesty, not silently rewriting blobs without detection (version CAS helps integrity, not confidentiality) |
| Server DB ↔ Operator | Operator sees all rows | Encrypted vault blob + rich metadata + decryptable TOTP |
| Network observer | Should not see secrets if TLS holds | Sees sizes, timing, IPs, auth header traffic |

**Architectural weakness:** The app’s security model often assumes “device locked = safe” while soft-lock and backup settings contradict that (Stages 3–4). ZK claims do not reduce the **client trust boundary**, which is where most password-manager compromises occur.

---

## What data leaves the device

### Never designed to leave (vault secrets)

- Master password  
- Master key / entry keys  
- Plaintext passwords, notes, usernames (if client is correct)  
- Recovery key material (when only hash stored locally)

### Leaves or is created on server when online features are used

| Data | Where | ZK impact |
|------|--------|-----------|
| `username` | `users` | Identity |
| `authHash` (client form; server stores SHA-256 of it) | `users.auth_hash` | If derived from master password, enables **offline password attack on server-stored verifier** |
| Auth `salt`, `iterations` | `users` | Parameterizes above attack |
| `encryptedBlob` | `vault_blobs` / history | Opaque payload; size leaked |
| Blob `version`, timestamps | DB + responses | Sync metadata |
| Session token (once) | Client memory; hash on server | Bearer session |
| IP, user-agent | `sessions`, audit | Location/activity profiling |
| Device fingerprint hash(es) | `sessions`, `trusted_devices` | Device graph (UA+IP based — unstable) |
| TOTP secret ciphertext | `users.totp_secret_encrypted` | **Server can decrypt** with deployment key |
| WebAuthn public keys / counters | `webauthn_credentials` | 2FA public material (OK) |
| Honeytoken **marker hashes** + triggers | honeytoken tables / audit | Server learns decoy interaction events |
| `installId` | request headers / audit UA append | Install tracking label |
| Audit actions, blob sizes | `vault_audit_log` | Behavioral metadata |

### Local-only but not “invisible”

Nuclear reset, soft lock, and exports are client-side; they do not create server ZK. Android backup (Stage 4) can exfiltrate **local** vault packages without the PiPass server.

---

## Findings

### Z1 — Product claim “zero-knowledge password manager” overreaches current architecture

| Field | Detail |
|-------|--------|
| **Location** | `app.json` description; `PRIVACY_POLICY.md` (“we cannot access… even if compelled”); incomplete client cloud wiring vs full server |
| **What is wrong** | Policy asserts technical inability to read vault data and optional cloud sync of a single E2E blob. Reality: (1) server holds decryptable TOTP secrets; (2) extensive behavioral metadata; (3) client may not complete secure multi-device sync; (4) authHash design can couple account login to password-guessing if clients derive it poorly; (5) local platform failures (backup, soft-lock) dominate user risk. |
| **Risk** | **Critical** (trust / compliance / user mental model) |
| **Attack scenario** | Users believe cloud provider cannot help attackers or governments learn anything useful. Compelled operator produces usernames, IPs, blob history sizes, TOTP secrets, session graphs — and encrypted vaults for offline cracking. |
| **Recommendation** | Rewrite claims: “local-first encrypted vault; optional opaque backup blob; operator can see account metadata and decrypt server-held 2FA secrets.” Ship or cut unfinished sync. |

---

### Z2 — Split architecture: powerful server, incomplete client product loop

| Field | Detail |
|-------|--------|
| **Location** | Server: full `/api/vault/*`, auth, devices, honeytokens. Client: local `storageWorker` primary; `setCredentials` unused; security UI expects credentials |
| **What is wrong** | Security features (step-up, device trust, audit) assume an authenticated online account. Local vault does not require it. Users can have a “vault” with no server account, or a server account with no consistent vault sync. Architecture risks **false sense of remote protection** (session list, recovery mode banners) while secrets live only under local soft-lock rules. |
| **Risk** | **High** |
| **Attack scenario** | User enables “security dashboard” features thinking devices are monitored; vault key still sits in JS after soft lock; no server involvement. |
| **Recommendation** | Either wire one coherent product (local + sync + auth derivation + clear UX modes) or hard-split “offline vault” vs “synced account” with explicit enrollment. |

---

### Z3 — Account `authHash` is a long-lived bearer; design couples poorly to ZK vault keys

| Field | Detail |
|-------|--------|
| **Location** | `POST /api/auth/register|login`; headers `x-user-id` + `x-auth-hash`; server `SHA-256(authHash)` store; client `lib/credentials.ts`; reviews in `auth_security_review.md` |
| **What is wrong** | Possession of client `authHash` authenticates vault sync/fetch without master password. There is no request binding (nonce/signature over method+path+body). If the client ever derives `authHash` from the same password as the vault (common PM pattern) without a strong separate KDF domain, server DB leak ≈ offline attack on password ≈ vault. Even if separate, leaked `authHash` allows **replace vault blob with garbage** (availability/DoS) or fetch ciphertext forever until rotation — and **rotation UI is not finished**. |
| **Risk** | **High** |
| **Attack scenario** | XSS/localStorage steal of `authHash` → attacker syncs garbage encryptedBlob → user loses cloud copy; or steals successive ciphertext versions for cracking. |
| **Recommendation** | Derive `authHash` with **explicit domain separation** and memory-hard KDF independent of vault master key; short-lived sessions only for writes; force rotation; bind requests (HMAC over body with session key). |

---

### Z4 — DeviceUUID-in-KDF blocks honest multi-device ZK sync and honest encrypted backup portability

| Field | Detail |
|-------|--------|
| **Location** | Local KDF material `password:deviceUUID`; `docs/BACKUP_COMPATIBILITY_POLICY.md`; backup format `encrypted-local-records` |
| **What is wrong** | Architectural decision: bind vault key to install. That **strengthens single-device extract slightly** and **destroys** cross-device restore without rekey. Cloud sync of “the encrypted vault” cannot work across phones unless blob is re-encrypted under a portable root key. Current backup policy correctly rejects different-device import by default — meaning the product is **not** a portable ZK vault. |
| **Risk** | **High** (availability / product security tradeoff mishandled) |
| **Attack scenario** | User loses phone; cloud blob or file backup cannot be opened on new device with password alone → data loss; user reuses weak cloud password managers as workaround. |
| **Recommendation** | Introduce portable **vault root key** wrapped by password (and recovery). Stop mixing install-local binding into the only vault DEK path. |

---

### Z5 — Server “opaque blob” sync is ZK-friendly for contents but metadata-rich and integrity-only

| Field | Detail |
|-------|--------|
| **Location** | `vault_blobs`, `vault_blob_history`, `POST /api/vault/sync` (expectedPrevVersion CAS), audit logs blob **size** not content |
| **What is wrong** | Good: server does not decrypt blobs; history enables rollback. Weak: version CAS does not prove blob was produced by holder of master key — only by holder of **auth** (session or authHash). Attacker with auth can upload random ciphertext (DoS). Blob size + sync timing leaks activity. History retains old ciphertexts under old passwords after rotation if rotation is incomplete. |
| **Risk** | **Medium-High** |
| **Attack scenario** | Stolen session → overwrite cloud vault with junk; user discovers on next fetch; history may allow restore if attacker cannot prune history. |
| **Recommendation** | Require client proof (MAC under vault key or signed version vector) for sync; rate-limit; never delete history on auth-only compromise without step-up. |

---

### Z6 — TOTP secrets break operator ZK for second factor

| Field | Detail |
|-------|--------|
| **Location** | `users.totp_secret_encrypted`; `server/totp.ts` AES-GCM with `TOTP_ENCRYPTION_KEY` |
| **What is wrong** | Correct for preventing *DB-only* TOTP theft, but the **operator and anyone with the deployment key** can mint codes. That is **escrowed 2FA**, not zero-knowledge. Passkeys are closer to ZK-compatible 2FA (server has public keys only). |
| **Risk** | **Medium** for ZK claim; **High** if TOTP key leaks |
| **Recommendation** | Prefer passkeys; document TOTP as server-recoverable 2FA; protect `TOTP_ENCRYPTION_KEY` as crown jewel; consider client-held TOTP only. |

---

### Z7 — Device trust is IP+UA fingerprint theater relative to real device identity

| Field | Detail |
|-------|--------|
| **Location** | `getDeviceFingerprint` / `deriveDeviceFingerprint` (UA + IP [+ platform]); `trusted_devices`; step-up on untrusted writes |
| **What is wrong** | “Device” is not hardware-bound (no Secure Enclave attestation, no installId in fingerprint for trust table). NAT, mobile IP changes, and browser UA updates churn trust. Two users on same NAT can collide more easily than hardware IDs (hash still wide). Sessions also store **raw IP and UA**, so fingerprint hashing does not hide identity from the operator. |
| **Risk** | **Medium** |
| **Attack scenario** | Attacker on same network path / stolen session from “trusted” fingerprint window performs sensitive sync without user noticing new hardware. |
| **Recommendation** | Bind trust to passkey/platform authenticator or app-attested install key; treat IP/UA as anomaly signals only. |

---

### Z8 — Offline mode is the strong path; online features add attack surface without reducing local risk

| Field | Detail |
|-------|--------|
| **Location** | Local vault independent of network; security APIs optional |
| **What is wrong** | Offline security equals local platform security (Stages 2–4). Going online adds auth theft, sync DoS, metadata surveillance, honeytoken callbacks — **without** fixing soft-lock or backup. Architecture does not use the server as a second factor for **local** unlock (by ZK design, correct) but still exposes users to server-side account takeover side effects. |
| **Risk** | **Medium** |
| **Recommendation** | Default offline; explicit opt-in sync with threat UI (“cloud can see when you sync, not passwords”). |

---

### Z9 — Backup and recovery architecture is incomplete and user-hostile relative to ZK promises

| Field | Detail |
|-------|--------|
| **Location** | Staged `pipass-backup` import; recovery key hash-only (Stage 2 V1); nuclear wipe; no server password recovery (correct for ZK) |
| **What is wrong** | True ZK forbids server-side password reset — acceptable only if **client recovery** works. Here recovery key does not unwrap vault keys; encrypted backups are same-install; deviceUUID blocks portability. Users are left with **nuclear erase** or broken “Coming Soon” recovery. That is an architectural safety failure, not a crypto primitive bug. |
| **Risk** | **Critical** for data survival; **High** for trust |
| **Recommendation** | Recovery key wraps vault root key; export includes wrapped root + ciphertext; test restore on clean device. |

---

### Z10 — Migration / version upgrade security is partial and multi-path

| Field | Detail |
|-------|--------|
| **Location** | KDF metadata unlock migration; profile change blocked when vault non-empty; staged setup import commit machinery; server blob version monotonicity |
| **What is wrong** | Multiple parallel versioning concepts: app version, backup schema version, KDF metadata version, vault blob version, shared vault `version: 1`. Incomplete rekey means security profile changes and password rotation are architecturally deferred while metadata can still drift (Stage 1 C23). Server history versions help cloud rollback but not local KDF confusion. |
| **Risk** | **High** for integrity of long-lived vaults |
| **Recommendation** | Single vault format version document; atomic rekey protocol; refuse unlock on conflicting metadata rather than best-effort migration without proofs. |

---

### Z11 — Honeytoken / security telemetry is anti-ZK by design (acceptable only if disclosed)

| Field | Detail |
|-------|--------|
| **Location** | Honeytoken marker hashes registered server-side; client triggers on view/copy; audit/security level |
| **What is wrong** | Server learns that a specific decoy was interacted with, from which IP/session — useful deception, **not** zero-knowledge about user behavior. Indistinguishability is only vs a thief reading **local** ciphertext (encryptedAux), not vs the operator. |
| **Risk** | **Medium** (privacy / claim honesty) |
| **Recommendation** | Disclose clearly; keep triggers minimal; never put real secret metadata in server-visible honeytoken rows. |

---

### Z12 — Shared local “encryptedBlob” naming confuses local architecture with cloud ZK

| Field | Detail |
|-------|--------|
| **Location** | `pipass_shared_vault` JSON of entries (Stage 2 V4); server `encrypted_blob` truly opaque string |
| **What is wrong** | Same vocabulary, different security properties. Local shared blob is not an outer E2E layer. Architects and auditors can mis-score the system. |
| **Risk** | **Medium** (design clarity → bugs) |
| **Recommendation** | Rename local field; reserve “encryptedBlob” for server-bound opaque payloads only. |

---

## Cloud sync design assessment

| Property | Assessment |
|----------|------------|
| Confidentiality of entry secrets | **Good design** if only ciphertext uploaded |
| Integrity against auth-holding attacker | **Weak** — no vault-key proof on sync |
| Multi-device | **Broken by deviceUUID KDF** without rekey |
| Conflict handling | Version CAS — solid for concurrency, not authz |
| History / recovery | Server history helps rollback; good |
| Client completeness | **Incomplete** relative to server |

---

## Offline mode assessment

| Property | Assessment |
|----------|------------|
| Full vault CRUD offline | **Yes** (primary path) |
| Security without server | Depends on local lock/storage (weak soft-lock) |
| Offline auth for cloud features | N/A / credentials cached if ever set |
| Split-brain after offline edits | Undefined until sync client exists |

---

## Architectural decisions that weaken security (summary list)

1. **deviceUUID mixed into vault KDF** — kills portable E2E backup/sync.  
2. **Soft lock without key wipe** — “locked” is not a security state.  
3. **Long-lived authHash bearer** without vault-key-bound writes.  
4. **Server-held TOTP under operator key** while claiming pure ZK.  
5. **Recovery key without wrap** — ZK forbids server recovery but client recovery missing.  
6. **Dual incomplete product surfaces** (local vault vs security cloud) without unified threat model.  
7. **Metadata-heavy “security” features** sold next to ZK branding.  
8. **Android backup enabled** — local architecture ignores cloud-of-the-OS.  
9. **IP/UA device trust** instead of hardware-backed identity.  
10. **Marketing/privacy policy ahead of client wire-up** — trust debt.

---

## What is architecturally sound

- Server treats vault blob as opaque and avoids logging contents.  
- Vault history + monotonic versions for cloud integrity/rollback.  
- Session token stored only as hash server-side.  
- Passkeys model is ZK-compatible for 2FA.  
- Local encrypt-then-store means offline use does not require trusting the network.  
- Staged backup import trying to be atomic (directionally correct).  
- Explicit refusal (in docs) of server password escrow.

---

## Stage 5 risk tally

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 2 | Z1, Z9 |
| **High** | 5 | Z2, Z3, Z4, Z5, Z10 |
| **Medium** | 5 | Z6, Z7, Z8, Z11, Z12 |

---

## Priority remediation (architecture)

1. **Honest threat model + privacy policy** aligned to real data flows (Z1).  
2. **Portable vault root key** + recovery wrap; remove deviceUUID from DEK path or make it optional (Z4, Z9).  
3. **Finish or remove** cloud account loop: auth derivation, `setCredentials`, sync with vault-key proof (Z2, Z3, Z5).  
4. **Hard local lock** so offline ZK is not theater (cross-stage).  
5. **Prefer passkeys; document TOTP escrow** (Z6).  
6. **Hardware-backed device trust** (Z7).  

---

*End of Stage 5 – Architecture & Zero-Knowledge*

# Security Audit – Stage 6: Dependencies & Backend

**Role:** Supply-chain + backend security  
**Date:** 2026-08-06  
**Scope:** npm dependency risk (`npm audit` against lockfile), intentional risky libraries, and backend API security (authn/authz, validation, rate limits, secrets).  
**Out of scope:** Re-listing pure client crypto design (Stage 1) or ZK product claims (Stage 5) except where deps/backend implement them.  
**Method:** `npm audit` / `npm audit --omit=dev`, package tree inspection, review of `server/*`, `shared/schema.ts`, env templates.

---

## A. Dependency findings

### Audit summary (this machine / lockfile)

| Metric | Count |
|--------|------:|
| Critical | 2 |
| High | 16 |
| Moderate | 24 |
| Low | 2 |
| **Total advisories (packages)** | **44** |

Production tree still carries critical/high issues because **Expo/RN toolchain is in `dependencies`**, not only devDependencies.

---

### D1 — `tar` (critical) via Expo CLI toolchain

| Field | Detail |
|-------|--------|
| **Package** | `tar@7.5.9` ← `@expo/cli` |
| **Issue** | GHSA hardlink/symlink path traversal (drive-relative linkpath) — class: supply-chain / malicious archive extract during prebuild/export |
| **Risk** | **Critical** (build-time compromise of developer machine / CI) |
| **Recommendation** | Upgrade Expo/CLI when patched `tar` is available; pin CI to trusted registries; do not extract untrusted archives in build scripts; run `npm audit fix` after Expo upgrade. |

---

### D2 — `shell-quote` (critical) via React DevTools

| Field | Detail |
|-------|--------|
| **Package** | `shell-quote@1.8.3` ← `react-devtools-core` ← `react-native` |
| **Issue** | Newline escape / quadratic parse DoS (GHSA) |
| **Risk** | **Critical** on paper; **Medium** practical if only used by devtools in debug — still in dependency graph of production app packages |
| **Recommendation** | Upgrade `react-native` when fixed; ensure release bundles do not ship devtools; monitor RN release notes. |

---

### D3 — `drizzle-orm@0.39.3` SQL identifier injection (high)

| Field | Detail |
|-------|--------|
| **Package** | `drizzle-orm@0.39.3` (direct); advisory for `<0.45.2` |
| **Issue** | GHSA-gpj5-g38j-94v9 — SQL injection via improperly escaped **SQL identifiers** |
| **Risk** | **High** if any user-controlled string is interpolated into identifiers; **Lower** if only parameterized values and static table/column refs (current `server/storage.ts` mostly uses schema objects + `sql` fragments with bound values — review still required on every `sql\`...\``) |
| **Recommendation** | Upgrade to `drizzle-orm@>=0.45.2` promptly; ban dynamic table/column names from request input; re-run security tests after upgrade. |

---

### D4 — `path-to-regexp@8.3.0` ReDoS/DoS (high) via Express 5

| Field | Detail |
|-------|--------|
| **Package** | `path-to-regexp@8.3.0` ← `express@5.2.1` / `router` |
| **Issue** | DoS via sequential optional groups / multiple wildcards |
| **Risk** | **High** if app defines complex wildcard routes; PiPass routes are mostly static paths — residual risk from Express internals |
| **Recommendation** | Upgrade Express/router when fixed path-to-regexp ships; avoid `:param*` style routes. |

---

### D5 — `http-proxy-middleware@3.0.5` (high)

| Field | Detail |
|-------|--------|
| **Package** | Direct dependency `http-proxy-middleware@^3.0.5` |
| **Issue** | CRLF injection in fixRequestBody; host/path substring routing bypass (≤3.0.6) |
| **Risk** | **High** if used as reverse proxy to backends with Host routing; **Low** if unused at runtime |
| **Recommendation** | Confirm runtime usage; if unused, **remove** the dependency. If used, upgrade ≥ fixed release and never trust client Host for routing. |

---

### D6 — `undici@6.23.0` (high) via Expo CLI

| Field | Detail |
|-------|--------|
| **Package** | `undici@6.23.0` |
| **Issue** | WebSocket length overflow crash; HTTP request smuggling class issues |
| **Risk** | **High** for tooling that fetches remote content; build/dev path |
| **Recommendation** | Upgrade Expo toolchain; isolate CI network. |

---

### D7 — `node-forge@1.3.3` (high) via Expo/config chain

| Field | Detail |
|-------|--------|
| **Package** | `node-forge@<=1.3.3` |
| **Issue** | Cert chain basicConstraints bypass; Ed25519 signature forgery |
| **Risk** | **High** if used to validate untrusted certs/signatures in build or runtime |
| **Recommendation** | Upgrade Expo/config-plugins when fixed forge lands. |

---

### D8 — `postcss` / Expo config plugin chain (high–moderate)

| Field | Detail |
|-------|--------|
| **Packages** | `postcss`, `@expo/config-plugins`, `xcode`, `xmldom`, `brace-expansion`, `minimatch`, `picomatch`, `js-yaml`, `flatted`, `fast-uri` |
| **Issue** | Mix of XSS in CSS stringify, path traversal, ReDoS, XML injection — mostly **build/tooling** |
| **Risk** | **High** for compromised project files / malicious dependency updates during prebuild; not direct vault crypto |
| **Recommendation** | `npm audit fix` where non-breaking; plan Expo SDK upgrade for the rest; treat prebuild as trusted-input only. |

---

### D9 — `body-parser` / `qs` (low–moderate) via Express

| Field | Detail |
|-------|--------|
| **Issue** | DoS if limit misconfigured; qs arrayLimit / stringify crashes |
| **Risk** | **Medium** for DoS; vault routes set explicit JSON limits (`4kb` auth, `11mb` sync, `64kb` passkey) which mitigates some body-parser cases |
| **Recommendation** | Upgrade Express stack; keep explicit per-route limits (already a good pattern). |

---

### D10 — Risky / sensitive libraries (design risk, not just CVE)

| Package | Version | Concern | Severity | Recommendation |
|---------|---------|---------|----------|----------------|
| **`crypto-js`** | 4.2.0 | Pure-JS crypto; side channels; historical packaging supply-chain incidents; used for vault AES/HMAC/PBKDF2 | **High** (architecture) | Replace with native/WebCrypto/libsodium for vault crypto |
| **`@sphereon/react-native-argon2`** | 2.0.9 | Low-velocity package; requires invasive local Java patches (`withNativeArgon2`); crash history on Pixel | **High** (maintenance/supply) | Prefer maintained Argon2 binding or first-party native module; pin + integrity verify |
| **`hash-wasm`** | 4.12.0 | WASM Argon2 fallback; large attack surface if wasm compromised | **Medium** | Pin version; SRI/lockfile only; prefer native path in release |
| **`expo-dev-client`** | in **dependencies** | Dev tooling capability in production dependency set | **Medium** | Move to devDependencies / exclude from store builds |
| **`@expo/ngrok`** | devDependency | Tunnels local server to public internet if misused | **Medium** | Never use with real `DATABASE_URL`/secrets |
| **`ws`** | 8.19.0 | WebSocket server surface if exposed | **Low–Medium** | Confirm necessity; auth all sockets |
| **`otplib` + `@simplewebauthn/server`** | current | Appropriate for 2FA; keep updated | **Low** if patched | Track advisories |
| **`drizzle-kit`** | 0.31.x | Vulnerable esbuild transitive (dev) | **Medium** (dev server) | Don’t expose drizzle-kit/esbuild to untrusted networks |

---

### D11 — Lockfile / process hygiene

| Field | Detail |
|-------|--------|
| **What is wrong** | 44 vulnerable package entries with many “fix available” only via major Expo jumps; no evidence of automated Dependabot/Renovate in-repo. `patch-package` postinstall is good for controlled patches but increases supply-chain uniqueness. |
| **Risk** | **Medium** (process) |
| **Recommendation** | CI job: `npm audit --omit=dev --audit-level=high` fails build; scheduled upgrades; document accepted risks. |

---

## B. Backend findings

Backend is substantial (`server/routes.ts`, `storage.ts`, `totp.ts`, `webauthn.ts`, `validation.ts`). Overall quality is **above average** for an app-server (zod strict bodies, timing-safe compares, rate-limit design notes, opaque vault blobs). Remaining issues are still real.

---

### B1 — In-memory rate limiting does not survive multi-instance or restart

| Field | Detail |
|-------|--------|
| **Location** | `server/routes.ts` `rateLimitMap` / multiple Maps for IP threat, login failures, soft locks |
| **What is wrong** | All counters and soft-lock state are process-local. Horizontal scale or crash resets limits; attacker can distribute across workers. Soft-lock “security” evaporates on restart unless rehydrated from DB (partial hydration exists for some signals only). |
| **Risk** | **High** in multi-instance production |
| **Recommendation** | Redis/Postgres-backed rate limits and soft locks; sticky sessions are not a fix. |

---

### B2 — Legacy `x-auth-hash` path cannot carry step-up / session trust state

| Field | Detail |
|-------|--------|
| **Location** | `authenticate()` returns `sessionId: null`, `totpVerifiedUntil: null` for header auth-hash |
| **What is wrong** | Step-up TTL and per-session trust live on session rows. Legacy path always has null step-up. Write paths that require step-up will reject or behave inconsistently; paths that only check soft signals may still allow full vault sync/fetch with a long-lived stolen `authHash` (no logout-all without rotation). Matches Stage 5 Z3, backend enforcement angle. |
| **Risk** | **High** |
| **Recommendation** | Deprecate legacy headers for write APIs; require session token + step-up for sync/restore; force rotation endpoint. |

---

### B3 — Stolen credentials can overwrite cloud vault without vault-key proof

| Field | Detail |
|-------|--------|
| **Location** | `POST /api/vault/sync` — auth then store `encryptedBlob` with version CAS only |
| **What is wrong** | Authorization is “possesses account auth,” not “possesses master key.” Attacker with session/authHash can upload garbage ciphertext (availability attack) or exfiltrate blob history. |
| **Risk** | **High** |
| **Recommendation** | Client proof (MAC/signature under vault key over version+hash); server verifies without learning key (e.g. store public verifier or check client-sent proof against prior commitment). |

---

### B4 — Secrets management: critical env vars, DB SSL not enforced

| Field | Detail |
|-------|--------|
| **Location** | `DATABASE_URL` (`server/db.ts` Pool with no `ssl` config); `TOTP_ENCRYPTION_KEY` (boot assert — good); no app-level use of `SESSION_SECRET` observed for vault (tests mention it); `.env.example` shows local plaintext DB URL |
| **What is wrong** | Postgres connection may run without TLS depending on provider URL. TOTP key is crown jewel (decrypts all 2FA). No secret rotation runbook in code. Listening `0.0.0.0` binds all interfaces. |
| **Risk** | **High** for misconfigured deploy |
| **Recommendation** | Require `sslmode=require` / `rejectUnauthorized` for non-local DB; secret manager in prod; restrict bind address behind reverse proxy; rotate TOTP key with dual-key decrypt window. |

---

### B5 — CORS allows any localhost origin with credentials

| Field | Detail |
|-------|--------|
| **Location** | `server/index.ts` `setupCors` — any `http://localhost:*` / `127.0.0.1:*` allowed; `Access-Control-Allow-Credentials: true` |
| **What is wrong** | Malicious local processes / malicious localhost pages can call API with credentialed browser requests if tokens live in JS-accessible storage (web localStorage authHash). Combined with web vault storage (Stage 2/4), this is a real browser-side footgun. |
| **Risk** | **Medium-High** for web clients |
| **Recommendation** | Explicit allowlist of dev ports; never credentials+wildcard-style localhost in production builds; prefer session cookies with strict SameSite only if web product is intentional. |

---

### B6 — Authorization model is mostly correct (userId from auth); residual IDOR surface is low

| Field | Detail |
|-------|--------|
| **Location** | Vault/device/honeytoken routes use `auth.userId` from `authenticate()`, not client-supplied user id in body for ownership |
| **What is wrong** | No classic “pass victim userId in body” IDOR found on vault sync/fetch. Residual: **username** on public salt endpoint; device fingerprint in body for trust/revoke must match auth’d user (verify revoke checks user ownership — pattern in storage is user-scoped). |
| **Risk** | **Low** for IDOR if storage queries always filter `userId`; **verify** every new route |
| **Recommendation** | Code review checklist: every SELECT/UPDATE/DELETE includes `userId` from auth only. |

---

### B7 — Input validation is strong on JSON bodies; public salt endpoint is intentional oracle-resistant

| Field | Detail |
|-------|--------|
| **Location** | Zod `.strict()` schemas; per-route body size caps; `GET` salt returns dummy salt for unknown users |
| **What is good** | Unknown fields rejected; size limits; dummy salt anti-enumeration |
| **Residual** | Salt endpoint still enables **password-guessing prep** (attacker gets parameters for known usernames); rate-limited per IP (10/min) — OK but not global |
| **Risk** | **Low-Medium** |
| **Recommendation** | Keep dummy salts; maintain IP + progressive delays (already present on login). |

---

### B8 — Rate limiting design is thoughtful but incomplete

| Field | Detail |
|-------|--------|
| **Location** | Per-IP login/register; per-user vault endpoints; adaptive IP threat; soft lock; `DISABLE_RATE_LIMIT` ignored in production (good) |
| **What is wrong** | In-memory only (B1). No distributed CAPTCHA/PoW for register. Vault sync 30/min still allows substantial overwrite attempts. |
| **Risk** | **Medium** |
| **Recommendation** | Redis limits; stricter sync after failures; CAPTCHA on register in prod. |

---

### B9 — Security state in process memory (soft lock, untrusted sets) is fail-open on errors

| Field | Detail |
|-------|--------|
| **Location** | Multiple try/catch around device upsert, drift checks — fail-open so auth always succeeds |
| **What is wrong** | Correct for availability; means DB errors **disable** trust/soft-lock protections while still serving vault APIs. |
| **Risk** | **Medium** |
| **Recommendation** | Fail-closed on **write** paths when security DB subsystem is down; fail-open only on reads. |

---

### B10 — Logging may aid attackers; errors strip detail (good)

| Field | Detail |
|-------|--------|
| **Location** | `setupRequestLogging` logs method/path/status/duration for `/api/*`; handlers log generic `"Login error"` without stacks of secrets (good) |
| **What is wrong** | Timing logs can support traffic analysis; ensure proxies don’t log `x-auth-hash` / `x-session-token` (not verified at infra layer). |
| **Risk** | **Low-Medium** |
| **Recommendation** | Redact auth headers at reverse proxy; avoid verbose access logs in prod. |

---

### B11 — No security headers middleware (Helmet)

| Field | Detail |
|-------|--------|
| **Location** | `server/index.ts` — CORS + static + routes; no `helmet`, CSP, HSTS |
| **What is wrong** | Landing page / static web assets lack defense-in-depth headers. API-only clients care less; browser clients care more. |
| **Risk** | **Medium** for web surface |
| **Recommendation** | Add Helmet; HSTS at TLS terminator; CSP for static landing. |

---

### B12 — WebAuthn / TOTP backend quality vs secrets

| Field | Detail |
|-------|--------|
| **Location** | `server/webauthn.ts`, `server/totp.ts` |
| **What is good** | TOTP key required at boot; no silent fallback to DATABASE_URL (removed intentionally) |
| **Residual** | Operator escrow of TOTP (Stage 5); origin/RP ID misconfig breaks or weakens passkeys — must match production domain |
| **Risk** | **Medium** (ops) |
| **Recommendation** | Document RP ID/origin; dual-control for TOTP key; prefer passkeys. |

---

## C. Concerning dependency list (actionable)

| Severity | Package | Notes |
|----------|---------|--------|
| Critical | `tar@7.5.9` | Path traversal via Expo CLI |
| Critical | `shell-quote@1.8.3` | Via react-devtools-core |
| High | `drizzle-orm@0.39.3` | Identifier SQLi class — **upgrade** |
| High | `path-to-regexp@8.3.0` | Express DoS class |
| High | `http-proxy-middleware@3.0.5` | Proxy injection — remove or upgrade |
| High | `undici@6.23.0` | HTTP/WS issues via Expo |
| High | `node-forge@1.3.3` | Cert/signature issues |
| High | `brace-expansion` / `minimatch` / `@xmldom/xmldom` / `postcss` / `js-yaml` / `flatted` / `fast-uri` / `tmp` | Toolchain DoS/injection |
| High (design) | `crypto-js@4.2.0` | Vault crypto library choice |
| High (design) | `@sphereon/react-native-argon2@2.0.9` | Patched third-party native crypto |
| Moderate | Expo SDK 54 tree (`@expo/*`, `expo*`) | Multiple config/plugin advisories — plan SDK 57+ |
| Moderate | `esbuild` via `drizzle-kit` | Dev server request leak |
| Moderate | `follow-redirects`, `qs`, `ajv` | Transitive |
| Low | `body-parser`, `@babel/core` | DoS / arbitrary file read in tooling |

---

## D. Backend issue list (actionable)

| Severity | ID | Issue | Recommendation |
|----------|-----|--------|----------------|
| High | B1 | In-memory rate limit / soft-lock | Redis/DB-backed |
| High | B2 | Legacy authHash without session step-up | Require session tokens for writes |
| High | B3 | Sync without vault-key proof | Add proof-of-possession |
| High | B4 | DB SSL / bind / secret ops | Enforce TLS; secret manager |
| Medium-High | B5 | CORS localhost + credentials | Tighten allowlist |
| Medium | B8 | Rate limit gaps under auth compromise | Stricter write caps + CAPTCHA |
| Medium | B9 | Fail-open security checks | Fail-closed writes |
| Medium | B11 | No Helmet/CSP/HSTS | Add security headers |
| Medium | B12 | TOTP operator key / WebAuthn config | Ops runbooks |
| Low-Medium | B7/B10 | Salt oracle residual; access logs | Keep controls; redact headers |
| Low | B6 | IDOR posture currently OK | Keep authz discipline |

---

## E. What the backend gets right (for balance of honesty, not praise)

- Zod strict validation and per-route body size limits  
- Timing-safe auth hash compare; session tokens stored hashed  
- Production cannot disable rate limits via env flag  
- Vault blob treated as opaque; audit avoids content  
- TOTP key fail-closed at boot  
- Dummy salts on username salt endpoint  

These do **not** cancel D1–D10 or B1–B5.

---

## Priority remediation (Stage 6)

1. **Upgrade `drizzle-orm` ≥ 0.45.2** and retest storage.  
2. **Clear critical/high npm audit** via Expo/RN upgrade plan + remove unused `http-proxy-middleware`.  
3. **Redis rate limits**; deprecate legacy authHash for vault writes.  
4. **Vault sync proof-of-key**; DB TLS + secret hygiene.  
5. **Replace `crypto-js` / fragile Argon2 package** on a roadmap (cross-stage).  
6. **CI audit gate** + Dependabot.  

---

*End of Stage 6 – Dependencies & Backend*

# Security Audit – Final Report

**Product:** PiPass (React Native / Expo password manager + optional Node/Express backend)  
**Codebase:** `C:\PiPass`  
**Stages consolidated:** 1 Cryptography · 2 Vault storage · 3 Auth/unlock/session · 4 RN/platform · 5 Architecture/ZK · 6 Dependencies/backend  
**Date:** 2026-08-06  
**Posture:** Evidence-based. No soft-pedaling. Severity reflects a **password manager** threat model (stolen device, malware, backup extract, account takeover, offline cracking).

---

## 1. Executive Summary

### Overall security rating: **3.5 / 10**

Not competitive with production password managers. Local encryption exists, but **lock, recovery, backup, platform defaults, and product claims systematically fail** security and honesty tests. The backend is often more carefully written than the client vault lifecycle; that does not make the product safe.

### Production readiness

| Question | Answer |
|----------|--------|
| Ready for production as a password manager? | **No** |
| Ready for closed beta with real user secrets? | **No** (unless users accept permanent data-loss and false recovery, and builds are hardened first) |
| Ready for further security testing (pen test / bug bounty)? | **Only after Immediate fixes** — testing a soft-lock that does not wipe keys wastes effort |

### Critical concerns

1. **Soft lock is not a lock** — master-key shares retained in `lockedSharesRef`; auto-lock/background only hide UI (A1, V2).  
2. **Recovery key does not recover the vault** — hash stored; unlock “Coming Soon”; UX claims otherwise (V1, Z9, A7).  
3. **Android `allowBackup="true"`** — backup/extract path for vault-related app data (P1).  
4. **Release signing passwords hardcoded** in Gradle (`PiPass2026!`); keystores on disk (P2).  
5. **Silent KDF downgrade** in `deriveMasterKey` / profile & nuclear verify paths; algorithm can desync from metadata (C1, C23, A6).  
6. **Legacy unauthenticated AES-CBC** still decryptable (C2).  
7. **“Zero-knowledge” / privacy claims overreach** operator metadata + TOTP escrow + incomplete sync (Z1).  
8. **Web vault in `localStorage`** (V3).  
9. **npm audit: 2 critical + 16 high** in dependency tree including `tar`, `shell-quote`, vulnerable `drizzle-orm` (D1–D3).

### Major concerns

- Encrypt-then-MAC key separation wrong; field swap under same entry key (C3, V5).  
- Password sanitizer strips characters from secrets (C5).  
- Master key cached to keychain unused for unlock; not cleared on soft lock (V7, A12).  
- Secure notes **plaintext labels**; list decrypts titles/usernames into React state while “locked” (V9, A4, C13).  
- DeviceUUID in KDF blocks portable backup/sync (Z4, C11).  
- Long-lived `authHash` bearer; vault sync without vault-key proof (Z3, B2, B3).  
- Incomplete screenshot protection on unlock/setup (P3).  
- Dangerous Android permissions including `SYSTEM_ALERT_WINDOW` (P4).  
- Production logcat of password lengths / KDF (P7, C20, V12).  
- In-memory server rate limits; no multi-instance safety (B1).  
- Integrity/root detection is theater (P6).  
- `crypto-js` + patched `@sphereon/react-native-argon2` supply/maintenance risk (D10, C16).

### Minor concerns

- Constant-time gaps on master-hash compare (C14).  
- Password generator modulo bias (C18).  
- Clipboard missing OS sensitive flags; recovery copy never wiped (V11, P11).  
- Deep links / `exp+pipass` in release manifest (P5).  
- No Helmet/CSP/HSTS (B11).  
- CORS any localhost + credentials (B5).  
- Shamir coefficient bias; unused integrity self-test gaps (C17, C19).  
- Min password length 8 (C21).

### Positive findings

- Create-vault path **prefers Argon2id** and can fall back to **strong PBKDF2 (≥600k)** with **KDF metadata** stored for unlock (when that path is used).  
- New ciphertexts use **Encrypt-then-MAC** (iv:ct:mac), not naked CBC — when the 3-part format is used.  
- Per-entry **HKDF** with entry id + salt when salts exist.  
- Vault storage uses **SecureStore** on native, **not AsyncStorage** (P10).  
- Server treats vault blob as **opaque**; avoids logging contents; session tokens stored as **SHA-256 hashes**; **timing-safe** auth-hash compare; Zod **`.strict()`** bodies; body size caps; production cannot disable rate limits via env.  
- TOTP encryption key **fail-closed at boot** (no silent fallback to `DATABASE_URL`).  
- Public salt endpoint returns **deterministic dummy salts** for unknown users (anti-enumeration design).  
- Staged backup import machinery attempts **atomic commit** discipline (directionally correct).  
- Passkeys model is a **ZK-compatible** second factor direction (when fully used).

These positives do **not** outweigh Critical lifecycle and claim failures.

---

## 2. Vulnerability Table

Severity scale: **Critical** / **High** / **Medium** / **Low**. IDs map to detailed stage findings.

| Severity | File | Description | Risk | Recommendation |
|----------|------|-------------|------|----------------|
| Critical | `app/(tabs)/index.tsx` | Soft lock keeps key shares in `lockedSharesRef` | Process compromise after “lock” decrypts vault | Wipe shares + key cache on every lock |
| Critical | `crypto/recoveryKey.ts`, `lib/firstTimeSetup.ts`, unlock UI | Recovery key hash only; cannot unlock | Permanent data loss; false trust | Wrap vault root key or remove recovery UX |
| Critical | `AndroidManifest.xml` | `android:allowBackup="true"` | Cloud/USB backup of vault package | `allowBackup=false` + data extraction rules |
| Critical | `android/app/build.gradle` | Plaintext release keystore passwords | Malicious signed updates | Rotate keys; env-based secrets only |
| Critical | `crypto/keyDerivation.ts` | `deriveMasterKey` silent PBKDF2 fallback | Weak/desynced keys; verify/rotate bugs | Metadata-only KDF; hard-fail missing Argon2 when required |
| Critical | `crypto/encryption.ts` | Legacy `iv:ciphertext` decrypt without MAC | Tamper / malleability of stored secrets | Reject legacy format; migrate re-encrypt |
| Critical | Product claims / `PRIVACY_POLICY.md` | ZK claims vs metadata + TOTP escrow + unfinished sync | Users mis-assess risk | Rewrite claims to match architecture |
| Critical | `lib/platformStorage.ts` (web) | Full vault keys in `localStorage` | XSS/extension full vault theft | Disable web vault or WebCrypto non-extractable design |
| Critical | npm: `tar`, `shell-quote` | Known critical advisories in toolchain graph | CI/dev machine compromise | Upgrade Expo/RN; audit CI |
| High | `crypto/encryption.ts` | HMAC key from hex string of enc key | Related-key MAC forgery if AES key known | HKDF dual keys (AES + MAC) |
| High | `crypto/hyperbaricSanitizer.ts` | Strips `/ \ < > { } [ ]` from passwords | Silent corruption of real passwords | Never mutate password pre-encrypt |
| High | `workers/vaultWorker.ts` | Same entry key all fields; no field AAD | Swap password/username ciphertexts | AAD = entryId+fieldName |
| High | `workers/vaultWorker.ts` | Secure note plaintext `label` | Titles leak at rest | Encrypt-only labels |
| High | `workers/storageWorker.ts` | Master key cache write; no unlock read; no soft-lock clear | Exportable secret at rest | Remove cache or implement bio-unlock + clear on lock |
| High | `workers/sharedVaultStorage.ts` | `encryptedBlob` = JSON entries, no outer crypto, shared group | Cross-app / backup expansion | Outer encrypt or delete share |
| High | `plugins/native-patches/RNArgon2Module.java` | Salt pad/truncate | Native≠wasm key divergence | Strict 64-hex salt only |
| High | `lib/currentUnlock.ts` | Missing master hash → any password “unlocks” | Gate bypass | Fail closed |
| High | `screens/VaultScreen.tsx` | List titles/usernames stay decrypted while soft-locked | Metadata leak when “locked” | Clear/strip entries on lock |
| High | `screens/AuthScreen.tsx` / `biometricGate.ts` | Device gate once/process; passcode fallback | Weak continuous auth | Re-auth policy; optional disable fallback |
| High | Nuclear verify paths | Uses `deriveMasterKeyShares` not unlock planner | Wrong password authz for wipe | Same verifier as unlock |
| High | `app.json` / manifest | Location, mic, `SYSTEM_ALERT_WINDOW`, storage | Overlay phishing; privacy | Block unused permissions |
| High | KDF/setup `console.log` | Password length / material length in logcat | Offline attack assist | Strip production logs |
| High | `server/routes.ts` | In-memory rate limits; sync without vault-key proof | Scale bypass; cloud vault overwrite | Redis limits; proof-of-possession |
| High | `server` auth | Legacy `authHash` long-lived bearer | Account/vault API abuse | Session-only writes; rotation |
| High | `drizzle-orm@0.39.3` | Identifier SQLi class advisory | Backend injection if identifiers dynamic | Upgrade ≥0.45.2 |
| High | `crypto-js` / sphereon argon2 | Weak crypto lib choice; fragile native dep | Side channels; maintenance breaks | Native AEAD + maintained Argon2 |
| Medium | `crypto/keyDerivation.ts` | PBKDF2 salt as UTF-8 hex string | Non-standard; interop footgun | Binary salt WordArray |
| Medium | `deviceUUIDStorage.ts` | UUID co-located with vault | Weak device bind; blocks portability | Portable vault root key |
| Medium | Clipboard modules | No sensitive flag; recovery never cleared | Clipboard spyware / history | OS sensitive APIs + wipe |
| Medium | `integrityGuard.ts` | Fake root/jailbreak resistance | False confidence | Remove or real attestations |
| Medium | iOS screen capture | Only while VaultScreen mounted | Unlock screen recordable | App-wide prevent while secrets shown |
| Medium | CORS localhost + credentials | Local malicious origin | Web token theft | Explicit allowlist |
| Medium | DB `Pool` | No forced SSL | Network MITM of DB | `sslmode=require` |
| Medium | Honeytoken triggers | Server sees decoy interaction | Privacy vs ZK marketing | Disclose |
| Low | Various | CT compare early exit; RNG charset bias; fractal “integrity”; deep links | Limited | Hardening backlog |

---

## 3. Cryptography Review (summary)

**Intent:** Argon2id master KDF, per-entry HKDF, AES-256-CBC + HMAC-SHA256 Encrypt-then-MAC, expo-crypto RNG.

**Reality:** Custom pure-JS stack (`crypto-js`) with serious glue bugs and lifecycle errors.

| Area | Assessment |
|------|------------|
| Argon2id create path | Acceptable params (~64 MiB, t≈3–5) when native/wasm works; metadata can record algorithm |
| PBKDF2 | Strong floor on **create** fallback; **weak/silent** floor inside `deriveMasterKey` |
| EtM | Format OK for new data; MAC key derivation incorrect; legacy CBC unauthenticated |
| Key separation | Per-entry HKDF good when salted; legacy saltless uses master key; field-level AAD missing |
| Memory | String keys/passwords unwipeable; XOR shares colocated = theater |
| Recovery crypto | Random 32-byte key hashed — **not linked to vault decrypt** |
| RNG | `expo-crypto.getRandomBytes` appropriate for salts/IVs when used |

**Stage 1 bottom line:** Do not ship until KDF is single-path, legacy CBC is dead, EtM keys are dual-derived, and password sanitization is removed.

---

## 4. Architecture Review (summary)

PiPass is **local-first encryption** plus a **partially wired** server security/sync platform, marketed as a **zero-knowledge cloud password manager**.

| Claim | Verdict |
|-------|---------|
| Master password never uploaded | Supported by API design |
| Server cannot read entry plaintext from blob alone | Supported **if** client only uploads ciphertext |
| True multi-device ZK product | **Failed** — deviceUUID in KDF; incomplete client sync/`setCredentials` |
| Operator learns nothing | **False** — accounts, IPs, UAs, sizes, audit, honeytokens; TOTP decryptable with deployment key |
| Recovery without server escrow | **Failed** — client recovery non-functional |

**Trust boundary:** OS and unlocked JS heap are fully trusted; soft-lock does not reduce that. Server is untrusted for vault plaintext but **trusted** for TOTP secrets and metadata honesty.

**Architectural decisions that damage security:** deviceUUID-in-KDF; soft-lock without wipe; long-lived authHash; recovery without wrap; dual incomplete product surfaces; ZK branding ahead of implementation.

---

## 5. React Native / Mobile Review (summary)

| Area | Verdict |
|------|---------|
| Storage API | SecureStore native good; web localStorage fatal for vault |
| Soft lock / auto-lock | UI only; keys + list metadata remain |
| Screenshots | Android FLAG_SECURE release OK; iOS incomplete coverage; debug allows shots |
| Permissions | Excess (location, mic, overlay) |
| Logging | Production-sensitive length logs |
| Root/jailbreak | Theater |
| RE resistance | Minimal (expected for RN; not compensated) |
| Signing | Hardcoded passwords — operational catastrophe |
| Backup | Android allowBackup true — unacceptable for PM |

**Stage 3–4 bottom line:** Mobile UX pretends to lock; platform defaults and memory model keep the vault open to anyone who can read the process or a backup.

---

## 6. Dependency & Backend Review (summary)

### Dependencies

- **44** npm audit findings (2 critical, 16 high, 24 moderate, 2 low) as of audit date.  
- Critical: `tar`, `shell-quote` in Expo/RN graph.  
- High direct/backend-relevant: **`drizzle-orm@0.39.3`** (upgrade ≥0.45.2), `path-to-regexp` via Express 5, `http-proxy-middleware` (remove if unused).  
- Design-risk: `crypto-js`, `@sphereon/react-native-argon2`, `hash-wasm`, `expo-dev-client` in production deps.

### Backend

| Control | Assessment |
|---------|------------|
| Authn | Session hash + legacy authHash; timing-safe compare |
| Authz | Generally userId-from-auth (good); writes not vault-key-bound |
| Validation | Strong Zod strict + size limits |
| Rate limit | Well-designed, **wrong medium** (memory) for multi-instance |
| Secrets | TOTP key boot check good; DB SSL not forced; bind 0.0.0.0 |
| Vault blob | Opaque storage + history — solid design for hosting ciphertext |

**Stage 6 bottom line:** Backend craftsmanship > client vault lifecycle. Hosting encrypted blobs carefully does not fix client soft-lock, recovery, or dependency rot.

---

## 7. Threat Model (most realistic attack paths)

Ranked by **likelihood × impact** for this codebase:

### T1 — Physical / shared device after “lock” (Critical, high likelihood)

User soft-locks or backgrounds app. Shares remain in `lockedSharesRef`; titles/usernames may remain in React state; device gate already passed. Malware, accessibility abuse, or debugger reads memory → full decrypt. **No master password needed.**

### T2 — Android backup / device extract (Critical)

`allowBackup=true` + SecureStore/local package → offline ciphertext + salt + KDF metadata + deviceUUID → password cracking offline. Soft-lock irrelevant.

### T3 — False recovery → permanent loss (Critical availability)

User loses password, uses “recovery key” as instructed → cannot open vault → nuclear wipe only. Not an attacker win, but **product security failure**.

### T4 — Web XSS / extension (Critical if web shipped)

`localStorage` vault package + optional authHash → total compromise.

### T5 — Stolen `authHash` / session (High if cloud used)

Fetch encrypted blobs for cracking; **overwrite** cloud vault with garbage (no vault-key proof). Legacy path skips session step-up state.

### T6 — Tampered local entry fields (High)

Unauthenticated legacy CBC or same-key field swap (password ↔ username) → wrong secret used at login sites; integrity break without knowing master password.

### T7 — Overlay / excessive permissions (High)

`SYSTEM_ALERT_WINDOW` class risk + unlock UI → credential phishing for master password.

### T8 — Build/signing compromise (Critical operational)

Hardcoded keystore password + JKS → attacker-signed trojan as “PiPass”.

### T9 — Supply chain / CI (High)

Vulnerable `tar`/tooling during prebuild; compromised native argon2 path.

### T10 — Operator / compelled metadata (Medium–High vs ZK claim)

Server produces account activity, IPs, blob sizes, TOTP under deployment key — contradicts pure ZK marketing even when entry plaintext stays sealed.

### Out of realistic scope (for honesty)

Nation-state side-channel on crypto-js AES without device compromise is less likely than T1–T3. Do not prioritize academic side channels over soft-lock and backup.

---

## 8. Prioritised Action Plan

### Immediate (must fix before further security testing)

1. **Hard soft-lock:** wipe `lockedSharesRef` / `vaultSession` / keychain master cache; strip decrypted list fields (A1, V2, A4, A12).  
2. **`allowBackup="false"`** and extraction rules (P1).  
3. **Rotate upload signing key;** remove passwords from Gradle; treat `PiPass2026!` as burned (P2).  
4. **Stop shipping recovery UX** that cannot recover — or implement wrap in the same sprint (V1, Z9).  
5. **Kill silent KDF fallback** on all verify/rotate paths; nuclear reset must use unlock planner (C1, A6, C23).  
6. **Reject legacy unauthenticated CBC** (or forced migration) (C2).  
7. **Remove password field sanitizer** (C5).  
8. **Strip production `console.log` of password/KDF lengths** (P7).  
9. **Upgrade `drizzle-orm` ≥ 0.45.2**; run `npm audit` gate in CI (D3, D11).

Without 1–3 and 5–6, pen tests will re-discover the same Criticals and waste budget.

### Before beta

1. Dual-key EtM (or native AES-GCM) + field AAD; re-encrypt vault (C3, V5).  
2. Plaintext note labels gone; shared vault outer encrypt or removed (V9, V4).  
3. Screen protection for unlock/setup/auth session (P3).  
4. Strip dangerous Android permissions (P4).  
5. Clipboard sensitive + wipe; recovery never on clipboard without TTL (V11, P11).  
6. Unlock attempt throttling (A5).  
7. Honest privacy/ZK copy (Z1).  
8. Web vault disabled or redesigned (V3).  
9. Clear critical/high npm issues via Expo upgrade path; remove unused `http-proxy-middleware` (D1–D5).  
10. Redis (or DB) rate limits; require session tokens for vault writes (B1, B2).

### Before production

1. **Portable vault root key** + working recovery wrap; remove deviceUUID from sole DEK path or make optional with rekey (Z4, Z9).  
2. Finish **one** cloud model: auth derivation domain separation, `setCredentials`, sync with **vault-key proof**, logout/rotation (Z2, Z3, B3).  
3. DB TLS enforced; secret manager; Helmet/HSTS; CORS lockdown (B4, B5, B11).  
4. Replace `crypto-js` vault crypto with platform AEAD; maintainable Argon2 (C16, D10).  
5. Strict salt parity native/wasm; automated interop vectors (C6).  
6. Single versioned vault format + atomic rekey; kill metadata drift paths (Z10, C23).  
7. Passkeys preferred; TOTP documented as operator-escrowed (Z6).  
8. Release checklist: no `__DEV__` bypass paths, screenshots off, no network inspector, no debug keystores.

### Future hardening

1. Hardware-backed non-exportable keys / wrap DEK.  
2. Hardware-backed device trust (not IP+UA) (Z7).  
3. Play Integrity / DeviceCheck as **signals only** (replace integrity theater P6).  
4. Request binding (HMAC session over method+body).  
5. Formal backup/export with verified restore drills on clean devices.  
6. Continuous dependency automation (Dependabot + audit budget).  
7. External pen test after Immediate + Before beta complete.  
8. Bug bounty only after production checklist.

---

## Final statement

PiPass shows **serious engineering investment** in KDF metadata, server-side opaque blobs, validation, and rate-limit *design*. As a **password manager users should trust with real secrets**, it currently fails on the controls users believe they already have: **lock, recovery, backup hygiene, signing hygiene, and honest zero-knowledge positioning**.

**Do not market, beta, or store irreplaceable credentials in this build until Immediate items are fixed and re-audited.**

---

*End of Final Report — consolidates Stages 1–6*  
*Detailed evidence remains in the stage sections above in this file.*
