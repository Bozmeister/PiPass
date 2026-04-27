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
- **UI Components**: Custom modals (`AddEntryModal`, `EntryDetailModal`, `DeleteEntryModal`, `NuclearResetModal`, `RecoveryKeyModal`) for CRUD operations and vault lifecycle; `FractalFullscreenViewer` for immersive animated fractal viewing; `AnimatedFractalView` for WebView+Canvas animated Mandelbrot rendering
  - `AddEntryModal`: Includes double-entry password validation (confirm password field), red "Mismatch" warning, success Alert on save, try/catch error handling
  - `FaviconImage`: Fetches website favicons from Google's favicon service, caches locally via expo-file-system on native, globe icon fallback. Shown in vault list items (when keyprints are off) and next to URLs in EntryDetailModal
- **Input Theme** (`styles/inputTheme.ts`): WCAG AA-compliant dark input styling used across all input screens. Constants: INPUT_BG (#1e1e1e), INPUT_TEXT (#f0f0f0), INPUT_PLACEHOLDER (#777), INPUT_BORDER (#3a3a3a), INPUT_BORDER_FOCUS (#4a90d9 blue), INPUT_BORDER_ERROR (#ef4444), INPUT_BORDER_SUCCESS (#4CAF50), LABEL_COLOR (#999). Applied to: UnlockScreen, SeedSetupScreen, AddEntryModal, EntryDetailModal, SecureNotesModal, VaultScreen profile password
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
- **Storage Worker** (`storageWorker.ts`): Password-based with no piSeed. Stores master salt, master key hash, security profile, recovery key hash. Uses `expo-secure-store` on native, `localStorage` on web. Includes `destroyAllData()` for nuclear wipe.
- **Vault Worker** (`vaultWorker.ts`): Uses per-entry HKDF subkeys with `KeyShares` throughout. `deriveMasterKeyShares()` returns XOR-split key shares. Encrypt/decrypt operations use per-entry keys derived from master key + entry ID via HKDF.

### Backend (Express server) — Zero-Knowledge API
- **Location**: `server/` directory
- **Validation**: `server/validation.ts` — thin adapters around the zod schemas in `shared/schema.ts`, which are themselves derived from the Drizzle table definitions via `drizzle-zod`'s `createInsertSchema` (single source of truth). Adapters call `safeParse` and map the first issue back to the legacy `{error: "Invalid <field>"}` response shape (with `encryptedBlob` → `"blob"`) so API behavior matches the previous hand-written validators on every real input. Single intentional divergence: a JSON array body (e.g. `[]`) now returns 400 `"Invalid body"` instead of 400 `"Invalid <first_field>"` — the legacy `"Invalid username"` reply for `[]` was an artifact of object destructuring, not an intentional contract; both responses are 400 and clients sending arrays to JSON-object endpoints are malformed regardless.
- **API Routes** (`server/routes.ts`):
  - `POST /api/auth/register` — Create user with username, authHash, salt, iterations
  - `POST /api/auth/login` — Verify credentials with timing-safe comparison
  - `GET /api/auth/salt/:username` — Retrieve salt/iterations for client-side key derivation
  - `POST /api/vault/sync` — Upload encrypted vault blob (version-checked)
  - `GET /api/vault/fetch` — Download encrypted vault blob
  - `GET /api/health` — Health check
- **Storage** (`server/storage.ts`): `DatabaseStorage` class implementing `IStorage`, backed by PostgreSQL via Drizzle ORM (`server/db.ts` — pg `Pool` + node-postgres adapter, fail-fast on missing `DATABASE_URL`). Instantiated explicitly in `server/index.ts` and injected into `registerRoutes(app, storage)`.
- **Security**:
  - Timing-safe auth hash comparison via `node:crypto` `timingSafeEqual`
  - AuthHash stored as SHA-256 hash server-side (not raw), mitigating pass-the-hash if DB leaks
  - Rate limiting on all auth endpoints (10 requests/minute per IP). Can be disabled for local integration testing by setting `DISABLE_RATE_LIMIT=true`. The flag is silently ignored when `NODE_ENV=production` (with a startup warning logged), so a misconfigured deploy cannot turn off the protection.
  - Username enumeration prevented: salt endpoint returns dummy salt/iterations for non-existent users
  - Error handlers never log error objects/stack traces to prevent information leakage
  - Request logging omits response bodies
  - Rate limit map auto-cleaned every 5 minutes to prevent memory leaks
  - Server never sees plaintext passwords or vault data
- **CORS**: Configured for Replit dev/deployment domains and localhost
- **IMPORTANT**: Server files must use `node:crypto` (not `crypto`) to avoid resolving to the local `crypto/` directory

### Database
- **Current**: PostgreSQL via Drizzle ORM (node-postgres adapter). Connection in `server/db.ts` reads `DATABASE_URL` and fails fast if missing — there is no in-memory fallback.
- **Schema** (`shared/schema.ts`): `users` table (uuid PK `defaultRandom`, unique `username`, `authHash`, `salt`, `iterations`, `createdAt` bigint mode:"number") and `vaultBlobs` table (uuid `userId` PK + FK → `users.id` ON DELETE CASCADE, `encryptedBlob`, `version`, `updatedAt` bigint). DB-level CHECK constraints provide defense-in-depth mirrors of the zod schemas: `users_iterations_range` enforces `iterations BETWEEN 3 AND 1000000` (matches `registerSchema`), and `vault_blobs_version_range` enforces `version >= 1` (matches `vaultSyncSchema`). Even a raw SQL bypass cannot store an out-of-range iteration count or a non-positive vault version. The zod schemas (`registerSchema`, `loginSchema`, `vaultSyncSchema`) are derived from the Drizzle tables via `drizzle-zod`'s `createInsertSchema(table, refinements).pick({...})`, so column types come from the table definition and the API-level bounds (length/range caps) are layered on as refinements — eliminating duplicated validation logic. `User`/`NewUser`/`VaultBlob`/`NewVaultBlob` types come from `$inferSelect`/`$inferInsert`.
- **Migrations**: `drizzle.config.ts` + `npm run db:push` (no hand-written SQL).

### Project Structure
```
app/              # Expo Router pages (file-based routing)
  (tabs)/         # Tab navigator group
assets/           # Images
components/       # Reusable UI components (AddEntryModal, EntryDetailModal, FractalKeyprint, AnimatedFractalView, FractalFullscreenViewer, KeyprintViewer, FractalBackground)
screens/          # Full-screen components (AuthScreen, VaultScreen, SeedSetupScreen)
utils/            # Visual-only modules (pi.ts, mandelbrot.ts, fractalKeyprint.ts, animatedFractalCanvas.ts)
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
- **Fractal seed derivation**: `HKDF(master_key, info="fractal")` derives a deterministic seed for the Mandelbrot visualization — uses fixed all-zero salt, completely independent from encryption subkey derivation. SHA-256 fingerprint of the HKDF output is stored and verified on every unlock; mismatch triggers a security warning banner. Fingerprint is updated after security profile changes (re-derived key).
- **Animated Fractal Renderer**: `AnimatedFractalView` uses WebView (native) or iframe (web) with HTML Canvas for animated Mandelbrot rendering with drift, hue-rotating edges, particle halo (60 particles at radii 0.92-0.97), glow bloom, and adaptive FPS scaling (<30fps → pause drift + skip frames, <45fps → reduce particles). `FractalFullscreenViewer` opens a full-screen modal with animated fractal on tap. Static `FractalKeyprint` (Image+dataUri) remains for list item thumbnails. `animatedFractalCanvas.ts` generates the complete HTML document with seeded deterministic animation personality.
- **Recovery Key** (`crypto/recoveryKey.ts`): 256-bit recovery key generated on vault creation via `expo-crypto`. Only SHA-256 hash is stored (`saveRecoveryKeyHash`). Key displayed once to user in `RecoveryKeyModal`, formatted as `XXXX-XXXX-...` groups. Verification uses constant-time comparison. Raw key never logged, stored, or sent over network.
- **Shamir's Secret Sharing** (`crypto/shamir.ts`): Optional 2-of-3 split of recovery key using polynomial interpolation over GF(256). Per-byte random polynomial with secret as constant term. Shares formatted as `S01:XXXX-XXXX-...`. `combineShares()` reconstructs via Lagrange interpolation at x=0. Input validation enforces unique indices, matching lengths, valid hex. All temporary buffers wiped after use.
- **Auto-lock behavior**: `AUTO_LOCK_MS = 120000` (2 minutes). On lock, VaultScreen stays mounted (preserving add-entry form state, entries list, scroll position) but all sensitive state is cleared (decrypted entries, settings, secure notes, profile password). An overlay `UnlockScreen` covers the vault. Activity is detected via `onTouchStart`/`onTouchMove` on root views and all modal surfaces (`AddEntryModal`, `EntryDetailModal`, `SecureNotesModal`). Timer and AppState listeners skip while already locked. Key shares are wiped from VaultScreen on lock and refreshed on unlock.
- **Safe Entry Deletion**: Multi-stage secure deletion flow: overflow menu (•••) → Alert confirmation → fresh biometric → type "DELETE" modal (`DeleteEntryModal`) → soft delete with 10-second undo snackbar → permanent storage deletion after timer expires. Edge cases: auto-lock during undo commits deletion immediately, app close/unmount commits deletion, multiple rapid deletions commit previous. `onRequestDelete` callback replaces direct `onDelete`.
- **Nuclear Reset** (`components/NuclearResetModal.tsx`): Multi-step guarded flow: warning → password verification → exact phrase "DELETE MY VAULT" → 10-second countdown → optional biometric → `destroyAllData()`. Session tokens and ref guards prevent race conditions and fast-tap bypasses.
- **Shared Vault Storage** (`workers/sharedVaultStorage.ts`): Stores the full encrypted vault blob in a shared keychain access group (`group.com.pipass.shared`) so native extensions (e.g., autofill) can read it. iOS uses SecureStore with `keychainService`; Android uses EncryptedSharedPreferences; web falls back to localStorage. Blob format: `{ encryptedBlob, version: 1, updatedAt }`. Every vault mutation (`saveEntry`, `deleteEntry`, `updateEntry`, `clearVault`) syncs the blob. One-time migration via `migrateToSharedStorage()` runs on vault load with timestamp guard to avoid overwriting newer shared data.
- **iOS AutoFill Extension** (`ios/AutoFillExtension/`): `CredentialProviderViewController.swift` implements `ASCredentialProviderViewController` with biometric gate (LAContext, zero reuse), reads vault blob from shared keychain, decrypts with master key via `readMasterKey()`, per-entry HKDF key derivation, HMAC-SHA256 verify then AES-CBC decrypt, domain matching, returns credentials via `ASPasswordCredential`. `CryptoHelper.swift` provides CommonCrypto wrappers. All sensitive Data buffers wiped via `defer` blocks.
- **Native Workflow (Prebuild)**: Project uses Expo Prebuild (Bare/Dev Client). `npx expo prebuild --platform android` regenerates `/android` from config plugins. `/android` and `/ios` are gitignored at root level only (`/android/`, `/ios/`) so other dirs named "android" can exist. Custom native source-of-truth lives under `native/android/` (Kotlin sources, autofill XML resources) and is copied into the prebuild output by `withAutofillService.js`. Scripts: `npm run android` → `expo run:android`, `npm run ios` → `expo run:ios`, `npm run prebuild` → `expo prebuild`. `expo-dev-client` and `react-native-get-random-values` installed; the polyfill is imported as the very first line of `app/_layout.tsx` so it runs before any crypto code. Note: Replit's Linux container has no Java/Android SDK, so `expo run:android` must be executed locally or via Replit's Expo Launch flow for actual APK builds.
- **Autofill JS↔Vault Integration** (`native/AutofillBridge.ts` — `prepareAutofillPayload`, `wipeAutofillPayload`): JS-side function that bridges the Android autofill request flow to the existing PiPass vault crypto. Signature: `prepareAutofillPayload({ entries, shares?, password?, salt?, iterations?, requireBiometric? })` → `Promise<AutofillPayloadEntry[]>` where `AutofillPayloadEntry = { id, domain, username, password }` (intentionally narrow — no titles/notes/timestamps). Flow: (1) gates on `requireFreshBiometric()` from `crypto/biometricGate` unless `requireBiometric: false` is explicitly passed; (2) uses caller-provided `KeyShares` if given, else falls back to deriving fresh shares via `deriveMasterKeyShares(password, salt, iterations)` from `workers/vaultWorker`; (3) iterates encrypted `VaultEntry[]` and calls `decryptVaultEntry(entry, shares)` per entry — which already wipes the master-key bytes internally via HKDF; (4) extracts `domain` from the entry's `url` field via a `URL`-based parser with a hostname-style fallback (strips `www.`, lowercases); (5) skips per-entry decrypt failures with a `__DEV__` warn rather than throwing, so one corrupt entry can't poison the whole response; (6) wipes derived shares via `wipeShares()` in a `finally` block — even on partial failure. Ownership rule: caller-provided shares are NOT wiped (caller retains ownership and must wipe them itself); only shares derived inside this function are owned-and-wiped here. `wipeAutofillPayload(payload)` is a best-effort cleanup that overwrites each entry's fields with empty strings and truncates the array — JS string immutability means original password bytes can't actually be zeroed, but it removes references for GC. Always call in a `finally` after forwarding to native. No persistence, no async storage writes — decrypted data lives only in the returned array.
- **Android Autofill RN Bridge** (`native/android/java/com/pipass/app/autofill/PiPassAutofillModule.kt` + `PiPassAutofillPackage.kt`, `native/AutofillBridge.ts`, `plugins/withAutofillModule.js`): Plumbing-only bridge between the Android Autofill Service and React Native JS. `PiPassAutofillModule` extends `ReactContextBaseJavaModule` (registered name `PiPassAutofillModule`); exposes `@ReactMethod getVaultEntriesForAutofill(promise)` resolving to a JSON array string, and `@ReactMethod(isBlockingSynchronousMethod = true) isVaultUnlocked(): Boolean`. Locked-state safety: when the cached `unlocked` flag is false, returns `"[]"` rather than rejecting. Companion object holds `@Volatile cachedVaultJson` + `unlocked` with `@JvmStatic snapshotVaultJson()` / `snapshotUnlocked()` accessors so the autofill service can read cached state without going through the JS bridge. `PiPassAutofillPackage` implements `ReactPackage` (returns the module from `createNativeModules`, empty `createViewManagers`). Registered in `MainApplication.kt` via `withAutofillModule.js` config plugin which idempotently injects the import + `add(PiPassAutofillPackage())` into the `PackageList(this).packages.apply { ... }` block. JS side `native/AutofillBridge.ts` wraps `NativeModules.PiPassAutofillModule`, exports `AutofillVaultEntry` type (`{ id, name, username, password, url }`), `getVaultEntriesForAutofill()` (parsed array), `getVaultEntriesJsonForAutofill()` (raw JSON), and `isVaultUnlocked()`. Gracefully handles iOS/web (returns `[]` / `false` with dev-only warn). No vault data is actually wired yet — both `cachedVaultJson` and `unlocked` start as stubs (`"[]"` and `false`) and will be populated when the vault integration step lands.
- **Android Autofill Domain Matcher** (`native/android/java/com/pipass/app/autofill/PiPassDomainMatcher.kt`): Dependency-free 3-tier matcher between `ParsedStructure` (webDomain + packageName) and the cached vault snapshot. Tiers (returned in priority order, de-duplicated by entry id): **EXACT** — registrable host equals target host, OR opt-in package match where the vault entry's URL field literally contains the request's package name (raw `com.spotify.music` or `androidapp://com.spotify.music`); **SUBDOMAIN** — same registrable domain (`accounts.google.com` ↔ `mail.google.com`); **FUZZY** — token overlap on host labels with the public suffix stripped (substring match requires shorter token ≥5 chars AND ≥60% length ratio of the longer one, so `acme` matches inside `myacme` but `micro` won't false-positive `microstrategy`). `normalizeHost()` strips scheme/userinfo/port/path/`www.` and lowercases. `registrableDomain()` is a heuristic eTLD+1 using a small allow-list of multi-part suffixes (`co.uk`, `com.au`, etc.) — not a full PSL. **Security note**: deliberately does NOT auto-convert package names to web domains (`com.spotify.music` → `spotify.com`) because that lets a malicious app named `com.spotify.evil` harvest real Spotify credentials. Native-app matching is opt-in only — user must store the package name in the vault entry's URL. A future Digital Asset Links verifier can lift this restriction safely. `VaultRecord` is the in-Kotlin shape `{id, name, username, password, url}`; `Match` pairs the record with its `MatchKind`.
- **Android AutoFill Service** (`native/android/java/com/pipass/app/autofill/PiPassAutofillService.kt` → copied into `android/app/...` by `withAutofillService.js` plugin): `AutofillService` subclass — entry point for Android's autofill framework. `onFillRequest`: parses the `AssistStructure` via `PiPassAutofillParser` (4-tier field detection — autofillHints → inputType mask → HTML attrs → viewId/hint heuristics), reads the cached vault snapshot from `PiPassAutofillModule.snapshotVaultJson()` only if `snapshotUnlocked()` returns true, parses the JSON defensively (`JSONArray.optJSONObject` + `optString`, single bad entry never throws), runs `PiPassDomainMatcher.match(records, webDomain, packageName)` to get tier-ordered matches, builds one `Dataset` per match (capped at `MAX_DATASETS = 5` to keep the dropdown usable). Each dataset uses fresh per-`setValue` `RemoteViews` (sharing one across `setValue` calls causes ghosting where only the last presentation renders). Presentation = title (entry name) + subtitle (`username · related/similar` for non-exact matches) + `R.mipmap.ic_launcher` PiPass icon. SaveInfo attached when at least one identifier/password field exists, with `SAVE_DATA_TYPE_USERNAME | EMAIL_ADDRESS | PASSWORD` flags as appropriate. All error paths call `callback.onSuccess(null)` (never `onFailure`) — `onFailure` surfaces a system error popup. Layout `res/layout/autofill_item.xml` is `LinearLayout(horizontal)` with `ImageView` (32dp PiPass icon) + nested `LinearLayout(vertical)` for title/subtitle; falls back to `simple_list_item_1` if the layout is unavailable. Vault locked or no matches → `onSuccess(null)` so Android falls through to other autofill providers.
- **FLAG_SECURE Toggle** (`plugins/withFlagSecure.js`): Expo config plugin that controls screenshot blocking via `BuildConfig.ALLOW_SCREENSHOTS`. Debug builds allow screenshots (for Play Store assets); release builds block them via `FLAG_SECURE`. Injects `buildConfigField` into both debug/release `buildTypes` in `build.gradle`, and patches `MainActivity.onCreate()` to conditionally apply `FLAG_SECURE`. Registered in `app.json` plugins array as `./plugins/withFlagSecure`.
- **Android Autofill Config Plugin** (`plugins/withAutofillService.js`): Expo config plugin that injects all required native configuration during prebuild: (1) adds `<service>` to AndroidManifest.xml with `BIND_AUTOFILL_SERVICE` permission, `android:label="PiPass Autofill"`, `android:exported="true"`, `android.service.autofill.AutofillService` intent-filter, and `@xml/autofill_service_config` meta-data; (2) copies `res/xml/autofill_service_config.xml` (with `android:supportsInlineSuggestions="true"`) to the build output; (3) copies Kotlin source files with prebuild validation (fail-fast on missing sources); (4) injects `androidx.biometric:biometric` and `androidx.security:security-crypto` Gradle dependencies; (5) injects ProGuard/R8 keep rules for the service and crypto classes to prevent obfuscation in release builds. Registered in `app.json` plugins array as `./plugins/withAutofillService`.
