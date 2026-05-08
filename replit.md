# PiPass — Replit Agent Guide

## Overview

PiPass is a local-first mobile password manager (Expo / React Native) with a zero-knowledge backend. The server stores only an opaque encrypted blob — it never sees plaintext passwords, vault entries, or master-key material. Vault entries are encrypted client-side with per-entry HKDF-derived AES-256-CBC+HMAC keys. An Express backend (Neon/PostgreSQL) handles registration, login, and encrypted blob sync.

## User Preferences

Preferred communication style: Simple, everyday language.

## Do Not Touch Without Explicit Prompt

These systems are stable and security-sensitive. Do not modify them unless the task explicitly requires it and spells out exactly what to change:

- `crypto/` — key derivation, HKDF, AES-CBC encryption, secure memory, biometric gate
- Encryption format: `ivHex:cipherHex:macHex` (3-part). Legacy 2-part still decryptable.
- `VaultEntry` / `SecureNote` shapes in `workers/vaultWorker.ts`
- `shared/schema.ts` — Drizzle table definitions + zod schemas (single source of truth)
- `server/` — all server code, routes, validation, database storage
- Recovery key flow (`crypto/recoveryKey.ts`, `crypto/shamir.ts`)
- Biometric gate (`crypto/biometricGate.ts`)
- Auth architecture (`lib/credentials.ts`, `lib/query-client.ts`)
- Deletion / tombstone semantics — tombstones are deliberately not implemented

## Current Sync State

`lib/vaultSync.ts` implements three stages:

| Stage | Function | When triggered | Write rule |
|---|---|---|---|
| 1 — Upload | `syncVaultToBackend(keyShares)` | After every local vault mutation | Encrypts all entries+notes → `POST /api/vault/sync` |
| 2A — Restore | `restoreVaultFromRemote(keyShares)` | Post-login, only if local vault is empty | Writes remote blob into empty local vault; blocked if any local entries/notes exist |
| 2B — Import | `planVaultMerge` → Alert → `applyVaultImport` | Post-login, only if local vault is non-empty | Remote-only ids → user approval Alert; same-id conflicts kept local; never deletes/overwrites |
| 2C — Tombstones | not implemented | — | deferred |

**Sync invariants (enforced in code, not just convention):**
- Remote sync/restore/import never blocks unlock — all runs in a best-effort fire-and-forget IIFE with catch.
- `planVaultMerge` only writes the sync watermark (`saveSyncVersion`), never vault data.
- `applyVaultImport` re-checks candidate IDs immediately before writing (Guard 2 race protection).
- `lastSyncedVersion` (`pipass_sync_last_version`) short-circuits planning when `serverVersion <= lastSyncedVersion`.

## System Architecture

### Frontend (Expo / React Native)
- **Framework**: Expo SDK 54, expo-router (file-based routing)
- **Auth flow** (`app/(tabs)/index.tsx`): AuthScreen (biometric) → SeedSetupScreen (first run) → UnlockScreen (returning users) → VaultScreen
- **Auto-lock**: 2-minute idle timer; VaultScreen stays mounted but sensitive state is wiped; overlay UnlockScreen appears
- **Key shares**: Master key is XOR-split into two shares (`KeyShares`). Shares live only in React state and refs; wiped on lock/reset via `wipeShares()`.
- **UI components**: AddEntryModal, EntryDetailModal, DeleteEntryModal, SecureNotesModal, NuclearResetModal, RecoveryKeyModal, FractalKeyprint (visual only), AnimatedFractalView, FaviconImage
- **Input theme**: `styles/inputTheme.ts` — WCAG AA dark inputs used across all screens

### Cryptography (`crypto/`)
| File | Purpose |
|---|---|
| `keyDerivation.ts` | Argon2id (hash-wasm) → PBKDF2-SHA256 fallback; mixes device UUID; `Math.max(iterations, 3)` guard |
| `hkdf.ts` | RFC 5869 HKDF-SHA256; `deriveEntryKey(masterKey, entryId, salt)` for per-entry keys; `deriveSubkey` for blob key |
| `encryption.ts` | AES-256-CBC + HMAC-SHA256 Encrypt-then-MAC; constant-time MAC compare; random IV per call |
| `secureMemory.ts` | XOR key split/combine; `wipeBuffer()` zeroes Uint8Array; TextEncoder/Decoder UTF-8 |
| `biometricGate.ts` | Fresh biometric per prompt; 2-second staleness window; web auto-passes |
| `hyperbaricSanitizer.ts` | Per-field input sanitizer before encryption |
| `integrityGuard.ts` | Crypto self-test every 30s; debugger/emulator detection (prod only); tamper → wipe + lock |
| `recoveryKey.ts` | 256-bit recovery key; SHA-256 hash stored only; displayed once; constant-time verify |
| `shamir.ts` | Optional 2-of-3 GF(256) split of recovery key |

### Local Storage (`workers/`)
- **`storageWorker.ts`**: All SecureStore (native) / localStorage (web) I/O. Stores master salt, key hash, security profile, recovery key hash, sync watermark (`pipass_sync_last_version`), notes index. `destroyAllData()` wipes everything including the watermark.
- **`vaultWorker.ts`**: `encryptVaultEntry`, `decryptVaultEntry`, `encryptSecureNote`, `decryptSecureNote`, `reEncryptEntry`, `reEncryptSecureNote`, `deriveMasterKeyShares`. Per-entry HKDF subkeys throughout.
- **`sharedVaultStorage.ts`**: Mirrors vault blob to shared keychain group (`group.com.pipass.shared`) for future native extension access. Synced on every mutation.

### Backend (Express — `server/`)
- **Zero-knowledge**: server stores `encryptedBlob`, never plaintext. `authHash` stored as SHA-256 of the client-form value (pass-the-hash mitigation).
- **Validation**: All input validated via zod schemas derived from Drizzle tables (`shared/schema.ts`) with `.strict()` — unknown fields → 400. No type coercion. Path params, headers, and bodies all validated before any DB call.
- **Body limits**: 4 KB for auth routes; 11 MB for `/api/vault/sync`.
- **API routes**: `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/salt/:username`, `GET /api/auth/sessions`, `POST /api/auth/trust-device`, `POST /api/vault/sync`, `GET /api/vault/fetch`, `POST /api/vault/restore`, `GET /api/vault/audit`, `POST /api/vault/recovery/acknowledge`, `GET /api/health`
- **Security**: `timingSafeEqual` for authHash compare; no username/userId enumeration (dummy salt, collapsed 401); 10 req/min IP rate limit on auth (kill-switch ignored in production); errors return `{error: string}` only — no stack traces or field paths logged.
- **Device trust**: Per-login SHA-256 device fingerprint; untrusted sessions blocked from sync/restore (403); user approves via `POST /api/auth/trust-device`.
- **IMPORTANT**: Server files must import `node:crypto` (with prefix) — never bare `crypto` — or they resolve to the local `crypto/` directory.

### Client Helpers (`lib/`)
- **`credentials.ts`**: `getCredentials()` / `setCredentials()` / `clearCredentials()`. SecureStore only — never cached in React state. Validates UUID + hex on read and write.
- **`query-client.ts`**: `authedApiRequest` attaches `x-user-id`/`x-auth-hash` headers, throws `AuthRequiredError` if absent, clears creds on 401. `apiRequest` for unauthenticated routes.
- **`vaultSync.ts`**: `syncVaultToBackend`, `restoreVaultFromRemote`, `planVaultMerge`, `applyVaultImport`. Blob subkey: `deriveSubkey(masterKey, "vault-blob-sync-v1", "00"×32)`.
- **`vaultSession.ts`**: Cross-screen `KeyShares` holder; wiped on lock.

### Database (Neon/PostgreSQL via Drizzle ORM)
- **`server/db.ts`**: `DATABASE_URL` required at startup — no in-memory fallback.
- **`shared/schema.ts`**: `users` (uuid PK, username unique, authHash, salt, iterations, createdAt) and `vault_blobs` (userId FK ON DELETE CASCADE, encryptedBlob, version, updatedAt). DB CHECK constraints mirror zod bounds.
- **Migrations**: `npm run db:push` (Drizzle Kit — no hand-written SQL).

## Project Structure
```
app/(tabs)/        # Expo Router — index.tsx is the full auth+vault flow
components/        # All modals and visual components
screens/           # AuthScreen, SeedSetupScreen, VaultScreen
crypto/            # Security primitives (do not touch casually)
workers/           # Storage and vault encryption logic
server/            # Express backend (do not touch without explicit task)
shared/            # Drizzle schema + zod schemas (single source of truth)
lib/               # credentials, query-client, vaultSync, vaultSession
styles/            # inputTheme.ts
utils/             # Visual-only: pi.ts, mandelbrot.ts, fractalKeyprint.ts
```

## Key Scripts & Environment
```
npm run expo:dev           # Start Expo dev server (port 8081)
npm run server:dev         # Start Express backend (port 5000)
npm run expo:static:build  # Build static web bundle
npm run db:push            # Apply schema changes to Neon/PostgreSQL
```

Environment variables:
- `EXPO_PUBLIC_DOMAIN` — public domain for Expo client API calls
- `REPLIT_DEV_DOMAIN` — Replit dev domain (CORS + Expo config)
- `REPLIT_DOMAINS` — comma-separated deployment domains (CORS)
- `DATABASE_URL` — Neon/PostgreSQL connection string (required at server startup)

## Known Deferred Work

| Item | Notes |
|---|---|
| Stage 2C — tombstones/deletion sync | Requires schema change + user-approved apply semantics. Not started. |
| Manual conflict-resolution UI | Stage 2B surfaced only import candidates; same-id conflicts are silently kept-local. A future UI should let users compare and choose. |
| Password rotation / vault re-key | Requires re-encrypting all entries with new per-entry HKDF keys. Non-trivial. |
| Vault-root-key migration | Future-proofing for key derivation algorithm upgrades. |
| Per-userId rate limit on `/api/vault/sync` | Currently only per-IP. A distributed attacker can still flood sync. |
| DB query timeout | No `statement_timeout` on PG pool — a pathological query could hang. |
| Real-device testing checklist | Biometric gate, SecureStore, auto-lock, Argon2id timing should all be verified on physical iOS and Android hardware before any App Store submission. |
