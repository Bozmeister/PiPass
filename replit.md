# PiPass - Replit Agent Guide

## Overview

PiPass is a mobile password manager built with Expo (React Native) that uses a zero-knowledge security architecture with industry-standard cryptographic primitives. The app stores encrypted vault entries locally on-device using Expo SecureStore (with localStorage fallback on web), protected by a master password and optional biometric authentication. An Express backend server provides user registration, authentication, and encrypted vault blob sync — the server never sees plaintext passwords or vault data.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend (Expo / React Native)
- **Framework**: Expo SDK 54 with expo-router for file-based routing
- **Navigation**: Tab-based layout under `app/(tabs)/` with a single main tab. The tab bar is hidden — the app presents as a single-screen flow
- **State Management**: React Query (`@tanstack/react-query`) for server state; React `useState` for local UI state
- **Auth Flow**: `app/(tabs)/index.tsx` manages the full flow:
  1. `AuthScreen` — biometric gate (first layer)
  2. `SeedSetupScreen` — master password setup (first-time only)
  3. `UnlockScreen` — password verify against stored hash (returning users)
  4. `VaultScreen` — main vault UI with key shares prop
- **UI Components**: Custom modals (`AddEntryModal`, `EntryDetailModal`) for CRUD operations on vault entries
  - `AddEntryModal`: Includes double-entry password validation (confirm password field), red "Mismatch" warning, success Alert on save, try/catch error handling
  - `FaviconImage`: Fetches website favicons from Google's favicon service, caches locally via expo-file-system on native, globe icon fallback
- **Error Handling**: Class-based `ErrorBoundary` component wraps the app with a fallback UI

### Cryptography (`crypto/` directory) — Industry-Standard Primitives

1. **Key Derivation** (`keyDerivation.ts`):
   - `deriveMasterKey(password, salt, iterations)`: Tries Argon2id (via `hash-wasm`) first, falls back to PBKDF2-SHA256. Mixes password with device UUID for device-binding.
   - `generateMasterSalt()`: 32-byte random salt via expo-crypto
   - `hashMasterKey(keyHex)`: SHA-256 hash for verification (stored locally, never sent raw)
   - All iteration parameters guarded with `Math.max(iterations || 100000, 3)`

2. **HKDF Subkeys** (`hkdf.ts`):
   - RFC 5869-compliant HKDF-SHA256: expand step operates on raw byte WordArrays (`T(n-1) || info || counter`)
   - `deriveSubkey(masterKey, salt, info)`: HKDF-SHA256 for per-entry key derivation
   - `deriveEntryKey(keyShares, entryId)`: Per-entry keys from master key + entry ID
   - `generateSaltHex()`: Random salt generation

3. **AES-256-CBC Encryption** (`encryption.ts`):
   - Encrypt-then-MAC: Format is `ivHex:cipherHex:macHex` (3-part)
   - Constant-time MAC comparison to prevent timing attacks
   - Legacy 2-part format (`ivHex:cipherHex`) still decryptable for backward compatibility
   - Random IVs per encryption via expo-crypto

4. **Secure Memory** (`secureMemory.ts`):
   - `wipeBuffer()`: Zeroes out Uint8Array buffers immediately after use
   - `splitKeyIntoShares()`: Splits key into two XOR shares (ShareA ⊕ ShareB = Key)
   - `combineShares()`: Recombines at moment of use, wiped after
   - `stringToBytes()`/`bytesToString()`: UTF-8 aware via TextEncoder/TextDecoder
   - All sensitive data uses Uint8Array for controlled memory allocation

5. **Biometric Gate** (`biometricGate.ts`):
   - `requireFreshBiometric()`: Forces new biometric prompt every time
   - 2-second staleness window — biometric result expires after 2000ms
   - Web fallback auto-passes (no biometric hardware available)

6. **Visual-Only** (`utils/pi.ts`, `utils/mandelbrot.ts`):
   - Pi/Mandelbrot computations are used ONLY for fractal keyprint visuals
   - NOT used for any security operations — completely decoupled from crypto layer
   - `deriveVisualSeed(keyShares)` in VaultScreen generates a visual seed from master key hash

### Local Storage (`workers/` directory)
- **Storage Worker** (`storageWorker.ts`): Password-based with no piSeed. Stores master salt, master key hash, security profile. Uses `expo-secure-store` on native, `localStorage` on web. Includes `destroyAllData()` for nuclear wipe.
- **Vault Worker** (`vaultWorker.ts`): Uses per-entry HKDF subkeys with `KeyShares` throughout. `deriveMasterKeyShares()` returns XOR-split key shares. Encrypt/decrypt operations use per-entry keys derived from master key + entry ID via HKDF.

### Backend (Express server) — Zero-Knowledge API
- **Location**: `server/` directory
- **Validation**: `server/validation.ts` — hand-written validators (no shared schema dependency to avoid tsx/react-native resolution conflicts)
- **API Routes** (`server/routes.ts`):
  - `POST /api/auth/register` — Create user with username, authHash, salt, iterations
  - `POST /api/auth/login` — Verify credentials with timing-safe comparison
  - `GET /api/auth/salt/:username` — Retrieve salt/iterations for client-side key derivation
  - `POST /api/vault/sync` — Upload encrypted vault blob (version-checked)
  - `GET /api/vault/fetch` — Download encrypted vault blob
  - `GET /api/health` — Health check
- **Storage** (`server/storage.ts`): In-memory storage (MemStorage) with User and VaultBlob maps
- **Security**:
  - Timing-safe auth hash comparison via `node:crypto` `timingSafeEqual`
  - AuthHash stored as SHA-256 hash server-side (not raw), mitigating pass-the-hash if DB leaks
  - Rate limiting on all auth endpoints (10 requests/minute per IP)
  - Username enumeration prevented: salt endpoint returns dummy salt/iterations for non-existent users
  - Error handlers never log error objects/stack traces to prevent information leakage
  - Request logging omits response bodies
  - Rate limit map auto-cleaned every 5 minutes to prevent memory leaks
  - Server never sees plaintext passwords or vault data
- **CORS**: Configured for Replit dev/deployment domains and localhost
- **IMPORTANT**: Server files must use `node:crypto` (not `crypto`) to avoid resolving to the local `crypto/` directory

### Database
- **Current**: In-memory storage (MemStorage class)
- **Schema**: `shared/schema.ts` has zod schemas for validation (used by frontend only)
- **Types**: User (id, username, authHash, salt, iterations, createdAt), VaultBlob (userId, encryptedBlob, version, updatedAt)

### Project Structure
```
app/              # Expo Router pages (file-based routing)
  (tabs)/         # Tab navigator group
assets/           # Images
components/       # Reusable UI components (AddEntryModal, EntryDetailModal, FractalKeyprint, KeyprintViewer, FractalBackground)
screens/          # Full-screen components (AuthScreen, VaultScreen, SeedSetupScreen)
utils/            # Visual-only modules (pi.ts, mandelbrot.ts, fractalKeyprint.ts)
crypto/           # Security primitives (keyDerivation, encryption, hkdf, secureMemory, biometricGate)
workers/          # Storage and vault encryption logic
server/           # Express backend (routes, storage, validation, templates)
shared/           # Shared types and schemas (frontend-only zod validation)
lib/              # Client utilities (React Query config, logoUrl)
constants/        # Theme colors
scripts/          # Build scripts
```

### Key Scripts
- `npm run expo:dev` — Start Expo dev server (configured for Replit)
- `npm run server:dev` — Start Express backend in dev mode
- `npm run expo:static:build` — Build static web bundle for deployment

## External Dependencies

### Core Services
- **Expo SecureStore**: Primary storage for vault entries on mobile devices (uses iOS Keychain / Android Keystore)
- **Expo LocalAuthentication**: Biometric auth (Face ID, Touch ID, fingerprint)
- **Expo Device**: Provides device identifiers for key derivation device-binding
- **Expo Crypto**: Random bytes generation for salts and IVs

### Key Libraries
- **crypto-js**: AES-256-CBC encryption, SHA-256 hashing, PBKDF2, HMAC (client-side crypto)
- **hash-wasm**: Argon2id key derivation (WebAssembly, with PBKDF2 fallback)
- **@tanstack/react-query**: Async state management for API calls
- **expo-router**: File-based navigation
- **express**: Backend HTTP server
- **zod**: Schema validation (frontend-only)

### Environment Variables
- `EXPO_PUBLIC_DOMAIN` — Public domain for API requests from the Expo client
- `REPLIT_DEV_DOMAIN` — Replit dev domain (used for CORS and Expo config)
- `REPLIT_DOMAINS` — Comma-separated deployment domains (CORS)

### Hyperbaric Sanitization Layer (`crypto/hyperbaricSanitizer.ts`)
- Pure function sanitizer that "scrubs" data before it reaches the Encryption Engine
- Strips forbidden characters, non-printable characters, enforces per-field length limits
- `hyperbaricSanitize(raw, field)` → returns `{ clean, ok, error }`
- `sanitizeEntryFields(entry)` → validates all fields at once

### Anti-Reverse-Engineering (`crypto/integrityGuard.ts`)
- **Debugger detection**: Checks for React DevTools hooks, timing anomalies in calibration loops, and Function constructor timing on web
- **Emulator detection**: Uses expo-device to check `isDevice`, plus brand/model/device name matching against known emulator indicators (Genymotion, BlueStacks, Nox, etc.)
- **Crypto self-test**: Verifies AES-CBC round-trip, HMAC-SHA256 output, SHA-256 output, and RNG non-degeneracy on every launch and periodically (30s interval)
- **Function hook detection**: Checks if core crypto functions have been monkey-patched (Proxy wrapping, prototype tampering)
- **Tamper response**: On detection, immediately wipes all key shares from memory and locks the vault with a non-dismissable security alert screen
- **Production-only enforcement**: Debugger/emulator/hook checks are gated behind `!__DEV__` to avoid false positives during development; crypto self-test runs always
- **Periodic guard**: `startPeriodicGuard(30000)` re-runs all checks every 30 seconds while the app is open

### Production Build Obfuscation (`metro.config.js`)
- **Terser minification** with `drop_console`, `drop_debugger`, toplevel mangling, and ASCII-only output
- Comments stripped, dead code eliminated, two-pass compression
- Obfuscation applies only to production builds; development builds remain readable for debugging

### Critical Implementation Notes
- **Server imports**: Always use `node:crypto` prefix in server files to avoid resolving to local `crypto/` directory
- **Iteration guard**: All iteration parameters use `Math.max(iterations || 100000, 3)` to prevent null/zero/undefined from reaching crypto
- **PBKDF2 Fallback**: `hash-wasm` Argon2id requires WebAssembly; if unavailable, falls back to PBKDF2-SHA256 via `crypto-js`
- **Encryption format**: New format is `ivHex:cipherHex:macHex` (3-part with HMAC); legacy `ivHex:cipherHex` (2-part) still decryptable
- **Visual seed**: Fractal keyprints derive a visual seed from master key hash — visual-only, no security implication
