# PiPass - Replit Agent Guide

## Overview

PiPass is a mobile password manager built with Expo (React Native) that uses a novel cryptographic approach combining Pi digits and Mandelbrot set iterations for key derivation. The app stores encrypted vault entries locally on-device using Expo SecureStore, protected by biometric authentication (Face ID/fingerprint). It includes an Express backend server, though the core vault functionality operates client-side.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend (Expo / React Native)
- **Framework**: Expo SDK 54 with expo-router for file-based routing
- **Navigation**: Tab-based layout under `app/(tabs)/` with a single main tab. The tab bar is hidden — the app presents as a single-screen flow
- **State Management**: React Query (`@tanstack/react-query`) for server state; React `useState` for local UI state
- **Auth Flow**: `app/(tabs)/index.tsx` toggles between `AuthScreen` (biometric gate) and `VaultScreen` based on local auth state. No server-side auth is implemented yet
- **UI Components**: Custom modals (`AddEntryModal`, `EntryDetailModal`) for CRUD operations on vault entries. Uses `react-native-gesture-handler`, `react-native-reanimated`, and `react-native-keyboard-controller`
- **Error Handling**: Class-based `ErrorBoundary` component wraps the app with a fallback UI

### Cryptography (`crypto/` directory)
- **Key Derivation**: Custom multi-step process:
  1. Extract digits from a hardcoded Pi string (`pi.ts`)
  2. Feed digits through Mandelbrot set iterations (`mandelbrot.ts`)
  3. Combine results with master password and salt, then SHA-256 hash (`keyDerivation.ts`)
  4. Multiple rounds supported via `deriveKeyWithRounds()`
- **Encryption**: AES-256-CBC via `crypto-js` with random IVs. Ciphertext stored as `iv:ciphertext` hex format (`encryption.ts`)
- **Note**: Currently uses a hardcoded master password (`"pipass-local-master"`) in `VaultScreen.tsx` — this is a placeholder

### Local Storage (`workers/` directory)
- **Vault Storage** (`storageWorker.ts`): Uses `expo-secure-store` for encrypted on-device storage. Entries are stored individually with a separate index key tracking all entry IDs
- **Vault Worker** (`vaultWorker.ts`): Handles encrypt/decrypt operations on `VaultEntry` objects. Encrypts password and optionally notes fields

### Backend (Express server)
- **Location**: `server/` directory
- **Purpose**: Currently minimal — serves as a landing page and API scaffold. No vault-related API routes are implemented yet
- **CORS**: Configured for Replit dev/deployment domains and localhost
- **Storage**: In-memory storage (`MemStorage`) with a basic User model. Not connected to the vault system
- **Database Schema**: Drizzle ORM with PostgreSQL configured (`shared/schema.ts`) — defines a `users` table but it's not actively used by the app yet
- **Static Build**: `scripts/build.js` handles building the Expo web bundle for production deployment on Replit

### Database
- **ORM**: Drizzle ORM configured for PostgreSQL
- **Schema Location**: `shared/schema.ts`
- **Current Schema**: Single `users` table with `id` (UUID), `username`, and `password` fields
- **Migrations**: Output to `./migrations` directory via `drizzle-kit`
- **Status**: Schema exists but isn't actively used — vault data is stored client-side in SecureStore, not in Postgres

### Project Structure
```
app/              # Expo Router pages (file-based routing)
  (tabs)/         # Tab navigator group
components/       # Reusable UI components
screens/          # Full-screen components (AuthScreen, VaultScreen)
crypto/           # Cryptographic utilities (Pi, Mandelbrot, AES)
workers/          # Storage and vault encryption logic
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
- **Expo LocalAuthentication**: Biometric auth (Face ID, Touch ID, fingerprint)

### Key Libraries
- **crypto-js**: AES encryption and SHA-256 hashing (client-side crypto)
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