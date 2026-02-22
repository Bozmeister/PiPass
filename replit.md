# PiPass - Replit Agent Guide

## Overview

PiPass is a mobile password manager built with Expo (React Native) that uses a novel cryptographic approach — the "Entropy Engine" — combining on-the-fly Pi digit computation (Chudnovsky algorithm), Mandelbrot set orbit computations, and device-specific identifiers for deterministic key derivation. The app stores encrypted vault entries locally on-device using Expo SecureStore (with localStorage fallback on web), protected by biometric authentication (Face ID/fingerprint). It includes an Express backend server, though the core vault functionality operates client-side.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend (Expo / React Native)
- **Framework**: Expo SDK 54 with expo-router for file-based routing
- **Navigation**: Tab-based layout under `app/(tabs)/` with a single main tab. The tab bar is hidden — the app presents as a single-screen flow
- **State Management**: React Query (`@tanstack/react-query`) for server state; React `useState` for local UI state
- **Auth Flow**: `app/(tabs)/index.tsx` toggles between `AuthScreen` (biometric gate) and `VaultScreen` based on local auth state. Biometric prompt uses `fallbackLabel: ""` and checks `hasHardwareAsync()` before prompting
- **UI Components**: Custom modals (`AddEntryModal`, `EntryDetailModal`) for CRUD operations on vault entries
  - `AddEntryModal`: Includes double-entry password validation (confirm password field), red "Mismatch" warning, success Alert on save, try/catch error handling
  - `FaviconImage`: Fetches website favicons from Google's favicon service, caches locally via expo-file-system on native, globe icon fallback
- **Error Handling**: Class-based `ErrorBoundary` component wraps the app with a fallback UI

### Cryptography — The Entropy Engine (`crypto/` directory)

The key derivation pipeline ("Cluster Key") works as follows:

1. **Pi Extraction** (`pi.ts`): Compute Pi digits on-the-fly using the Chudnovsky algorithm with binary splitting (no static file). Extract 30 digits starting from a user-defined seed index. Results cached in memory.
   - Digits 1–10: Map to X-coordinate (Range: -2.0 to 2.0)
   - Digits 11–20: Map to Y-coordinate (Range: -2.0 to 2.0)
   - Digits 21–25: Map to Logarithmic Zoom Factor (Range: 10^1 to 10^12)
   - Digits 26–30: Used for deterministic jitter

2. **3x3 Grid Mandelbrot** (`mandelbrot.ts`):
   - Calculate a grid of 9 coordinates centered on (X, Y) with spacing = 1/zoomFactor
   - Run escape-time algorithm (z = z² + c) for all 9 points with MAX_ITERATIONS = 2000
   - Capture full orbit arrays (all Z values) for each point
   - **Deterministic Jitter**: If center point hits 2000 limit, apply microscopic coordinate offsets using Pi digits 26–30 until escape time < 2000

3. **Orbit Hash** (`keyDerivation.ts`):
   - Serialize all 9 orbit arrays to JSON (coordinates rounded to 12 decimal places)
   - Combine: `SHA256(JSON.stringify(orbits) + DeviceUUID + UserPiSeed)`
   - DeviceUUID sourced from `Device.osBuildId`, `Device.osInternalBuildId`, `Device.modelName`, `Device.brand` (or `navigator.userAgent` on web)
   - Result is a 64-character hex string used as the AES-256 key

4. **AES-256-CBC Encryption** (`encryption.ts`): Random IVs per encryption. Ciphertext stored as `iv:ciphertext` hex format.

5. **Secure Memory** (`secureMemory.ts`):
   - `wipeBuffer()`: Zeroes out Uint8Array buffers immediately after use
   - `splitKeyIntoShares()`: Splits a key into two XOR shares (ShareA ⊕ ShareB = Key)
   - `combineShares()`: Recombines shares at moment of use, result wiped after
   - All sensitive data uses Uint8Array for controlled memory allocation
   - `hexToBytes()`/`bytesToHex()` conversions keep data in byte arrays

6. **Biometric Gate** (`biometricGate.ts`):
   - `requireFreshBiometric()`: Forces a new biometric prompt every time
   - 2-second staleness window — biometric result expires after 2000ms
   - `invalidateBiometric()`: Immediately marks auth as stale
   - No cached "authenticated" state — each decryption triggers a fresh check
   - Web fallback auto-passes (no biometric hardware available)

### Local Storage (`workers/` directory)
- **Vault Storage** (`storageWorker.ts`): Uses `expo-secure-store` for encrypted on-device storage on native, with `localStorage` fallback on web. Entries stored individually with a separate index key tracking all entry IDs
- **Vault Worker** (`vaultWorker.ts`): Handles encrypt/decrypt operations on `VaultEntry` objects. Encrypts password and optionally notes fields. `deriveMasterKeyShares()` returns XOR-split key shares, never a raw key string. Key is recombined only inside encrypt/decrypt functions and wiped immediately after

### Backend (Express server)
- **Location**: `server/` directory
- **Purpose**: Currently minimal — serves as a landing page and API scaffold. No vault-related API routes are implemented yet
- **CORS**: Configured for Replit dev/deployment domains and localhost
- **Static Build**: `scripts/build.js` handles building the Expo web bundle for production deployment on Replit

### Database
- **ORM**: Drizzle ORM configured for PostgreSQL
- **Schema Location**: `shared/schema.ts`
- **Current Schema**: Single `users` table with `id` (UUID), `username`, and `password` fields
- **Status**: Schema exists but isn't actively used — vault data is stored client-side in SecureStore, not in Postgres

### Project Structure
```
app/              # Expo Router pages (file-based routing)
  (tabs)/         # Tab navigator group
assets/           # Images and pi_digits.txt (1M digits)
components/       # Reusable UI components (AddEntryModal, EntryDetailModal)
screens/          # Full-screen components (AuthScreen, VaultScreen)
crypto/           # Entropy Engine (Pi extraction, Mandelbrot orbits, key derivation, AES)
  pi.ts           # Load Pi digits, extract 30, map to X/Y/zoom coordinates
  mandelbrot.ts   # 3x3 grid, 2000-iter orbit capture, deterministic jitter
  keyDerivation.ts # Orbit hash + Device UUID + UserPiSeed → SHA-256 cluster key
  encryption.ts   # AES-256-CBC encrypt/decrypt with random IVs
  index.ts        # Re-exports
workers/          # Storage and vault encryption logic
  storageWorker.ts # SecureStore (native) / localStorage (web) persistence
  vaultWorker.ts  # Encrypt/decrypt VaultEntry objects
server/           # Express backend
shared/           # Shared types and database schema
lib/              # Client utilities (React Query config, logoUrl)
constants/        # Theme colors
scripts/          # Build scripts
```

### Key Scripts
- `npm run expo:dev` — Start Expo dev server (configured for Replit)
- `npm run server:dev` — Start Express backend in dev mode
- `npm run db:push` — Push Drizzle schema to PostgreSQL
- `npm run expo:static:build` — Build static web bundle for deployment

## External Dependencies

### Core Services
- **PostgreSQL**: Configured via `DATABASE_URL` environment variable. Used with Drizzle ORM but not yet integral to app functionality
- **Expo SecureStore**: Primary storage for vault entries on mobile devices (uses iOS Keychain / Android Keystore)
- **Expo LocalAuthentication**: Biometric auth (Face ID, Touch ID, fingerprint) — checks hasHardwareAsync() before prompting
- **Expo Device**: Provides device identifiers (osBuildId, modelName, brand) used in key derivation
- **Expo FileSystem + Asset**: Load pi_digits.txt from app assets at runtime

### Key Libraries
- **crypto-js**: AES-256-CBC encryption and SHA-256 hashing (client-side crypto)
- **drizzle-orm + drizzle-zod**: Database ORM and schema validation
- **@tanstack/react-query**: Async state management for API calls
- **expo-router**: File-based navigation
- **express**: Backend HTTP server
- **pg**: PostgreSQL client driver
- **zod**: Schema validation (used with Drizzle)

### Environment Variables
- `DATABASE_URL` — PostgreSQL connection string (required for Drizzle)
- `EXPO_PUBLIC_DOMAIN` — Public domain for API requests from the Expo client
- `REPLIT_DEV_DOMAIN` — Replit dev domain (used for CORS and Expo config)
- `REPLIT_DOMAINS` — Comma-separated deployment domains (CORS)

### Metro Configuration
- `metro.config.js` — default Expo config (no custom asset extensions needed)

## Recent Changes
- 2026-02-22: Watchman Security Layer — input sanitization (strips <>{}[]\/ chars, 64-char limit on title/username), heuristic lockout on Pi Seed input (>5 changes/sec or >20 char paste triggers 30s freeze), expo-screen-capture screenshot prevention on native, secureTextEntry + autoCorrect=false on all sensitive inputs
- 2026-02-22: utils/watchman.ts — sanitizeInput(), createHeuristicState(), checkHeuristicLockout(), getLockoutRemaining() utility functions
- 2026-02-22: Ghost Backup — export encrypted vault entries as .vault JSON file (web: Blob download, native: expo-file-system + expo-sharing)
- 2026-02-22: Recovery Protocol — import .vault backup on SeedSetupScreen via expo-document-picker (web: FileReader, native: DocumentPicker)
- 2026-02-22: Nuclear Option — biometric-gated complete data wipe (entries, Pi seed, security profile) with DELETE text confirmation, resets app to seed setup
- 2026-02-22: destroyAllData() in storageWorker — wipes vault, Pi seed, and security profile keys
- 2026-02-22: User-configurable Pi seed — SeedSetupScreen prompts on first launch (0-999999), stored in SecureStore, replaces hardcoded 42
- 2026-02-22: User-configurable security profiles — Balanced (25k), Fortress (100k default), Deep Vault (250k) PBKDF2 iterations; stored in SecureStore; selectable on Seed Setup screen and via Settings modal in VaultScreen
- 2026-02-22: Multi-round key derivation — PBKDF2 with configurable iterations on top of SHA-256 orbit hash for brute-force resistance
- 2026-02-22: Encrypted metadata — titles, usernames, and URLs now encrypted alongside passwords in vault entries (backward-compatible with unencrypted entries)
- 2026-02-22: Auto-lock — vault locks after 60 seconds of inactivity or when app enters background, wiping key shares from memory
- 2026-02-22: Clipboard auto-clear — clipboard wiped 30 seconds after copying any field via expo-clipboard
- 2026-02-22: Copy buttons — username, password, and URL fields now have copy-to-clipboard buttons in EntryDetailModal
- 2026-02-22: Cryptographic ID generation — vault entry IDs now use expo-crypto.getRandomBytes() instead of Math.random()
- 2026-02-21: Added secure memory management — wipeBuffer() zeroes Uint8Array after use, all sensitive data in byte arrays
- 2026-02-21: Implemented XOR key splitting — master key stored as ShareA ⊕ ShareB, never as single string in memory
- 2026-02-21: Added biometric gate — requireFreshBiometric() forces new check per decryption, 2-second staleness window, no cached auth
- 2026-02-21: Removed static pi_digits.txt — Pi digits now computed on-the-fly using Chudnovsky algorithm with binary splitting. Key derivation is fully synchronous, no file I/O needed
- 2026-02-21: Implemented full Entropy Engine — Pi-based 3x3 Mandelbrot grid with orbit capture, deterministic jitter, device-tied SHA-256 hashing for AES key derivation
- 2026-02-21: Added double-entry password validation, success alerts, and try/catch error handling in AddEntryModal
- 2026-02-21: Updated biometric auth to use empty fallbackLabel and check hasHardwareAsync() before prompting
- 2026-02-21: Added web fallback (localStorage) for SecureStore operations
- 2026-02-21: Created hidden Debug screen (long-press "Vault" title) for testing determinism/sensitivity of key derivation with orbit logging
