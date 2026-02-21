# PiPass - Replit Agent Guide

## Overview

PiPass is a mobile password manager built with Expo (React Native) that uses a novel cryptographic approach — the "Entropy Engine" — combining 1 million Pi digits, Mandelbrot set orbit computations, and device-specific identifiers for deterministic key derivation. The app stores encrypted vault entries locally on-device using Expo SecureStore (with localStorage fallback on web), protected by biometric authentication (Face ID/fingerprint). It includes an Express backend server, though the core vault functionality operates client-side.

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
- **Error Handling**: Class-based `ErrorBoundary` component wraps the app with a fallback UI

### Cryptography — The Entropy Engine (`crypto/` directory)

The key derivation pipeline ("Cluster Key") works as follows:

1. **Pi Extraction** (`pi.ts`): Load 1 million digits of Pi from `assets/pi_digits.txt`. Extract 30 digits starting from a user-defined seed index.
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

### Local Storage (`workers/` directory)
- **Vault Storage** (`storageWorker.ts`): Uses `expo-secure-store` for encrypted on-device storage on native, with `localStorage` fallback on web. Entries stored individually with a separate index key tracking all entry IDs
- **Vault Worker** (`vaultWorker.ts`): Handles encrypt/decrypt operations on `VaultEntry` objects. Encrypts password and optionally notes fields. `deriveMasterKey()` is now async and calls `deriveClusterKey(userPiSeed)`

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
lib/              # Client utilities (React Query config)
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
- `metro.config.js` includes `.txt` in asset extensions to support loading `pi_digits.txt`

## Recent Changes
- 2026-02-21: Implemented full Entropy Engine — Pi-based 3x3 Mandelbrot grid with orbit capture, deterministic jitter, device-tied SHA-256 hashing for AES key derivation
- 2026-02-21: Added double-entry password validation, success alerts, and try/catch error handling in AddEntryModal
- 2026-02-21: Updated biometric auth to use empty fallbackLabel and check hasHardwareAsync() before prompting
- 2026-02-21: Added web fallback (localStorage) for SecureStore operations
