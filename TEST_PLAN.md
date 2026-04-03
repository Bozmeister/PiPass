# PiPass Test Plan

## 1. Functional Testing

### 1.1 Authentication Flow
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F01 | Launch app on device with biometrics enrolled | Face ID / Fingerprint prompt appears |
| F02 | Authenticate successfully | Proceeds to SeedSetup or Unlock screen |
| F03 | Cancel biometric prompt | Error message shown, retry button available |
| F04 | Launch on web (no biometrics) | Bypass message shown, tap proceeds |
| F05 | Launch on emulator (no physical device) | Bypass message shown, tap proceeds |

### 1.2 Vault CRUD Operations
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F06 | Create first vault (seed setup) | Master password set, salt generated, vault initialized |
| F07 | Add entry with all fields | Entry encrypted and saved, appears in list |
| F08 | Add entry with mismatched passwords | Red "Mismatch" warning, save button disabled |
| F09 | Add entry with empty required fields | Validation prevents save |
| F10 | View entry detail | Biometric gate, then decrypted fields shown |
| F11 | Copy field to clipboard | "Copied" feedback, clipboard cleared after 30s |
| F12 | Delete entry (full flow) | Overflow menu > Alert > Biometric > Type DELETE > Undo snackbar > Permanent delete |
| F13 | Undo delete within 10s | Entry restored to list |
| F14 | Let delete timer expire | Entry permanently removed from storage |

### 1.3 Auto-Lock Behaviour
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F15 | Idle for 2 minutes | Vault locks, unlock overlay appears |
| F16 | Touch/interact resets timer | Lock does not trigger while active |
| F17 | Lock during pending undo delete | Pending deletion commits immediately |
| F18 | Lock clears all sensitive state | Decrypted entries, notes, password fields cleared |

### 1.4 Biometric Gate
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F19 | View entry requires biometric | Prompt appears before decryption |
| F20 | Delete entry requires fresh biometric | New prompt even if recent auth exists |
| F21 | Biometric staleness (2s window) | Second decrypt within 2s skips re-prompt |

### 1.5 Recovery Key Flow
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F22 | View recovery key | Key displayed in XXXX-XXXX format |
| F23 | Copy recovery key | Clipboard set, "Copied" feedback |
| F24 | Split key (Shamir 2-of-3) | 3 shares generated, each displayed |
| F25 | Verify recovery key | Correct key accepted, wrong key rejected |

### 1.6 Nuclear Reset
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F26 | Trigger nuclear reset | Warning > Password verify > Type phrase > 10s countdown > Biometric > All data destroyed |
| F27 | Cancel at any stage | Returns to vault, no data lost |
| F28 | Wrong password during reset | Error message, cannot proceed |
| F29 | Wrong phrase during reset | Button stays disabled |
| F30 | Keyboard visible during phrase step | Input and buttons remain visible above keyboard |

### 1.7 Server Sync
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F31 | Register new vault | Salt, auth hash, encrypted blob sent to server |
| F32 | Login existing vault | Auth hash verified, encrypted blob returned |
| F33 | Sync vault | Updated encrypted blob pushed to server |
| F34 | Fetch vault | Latest encrypted blob pulled and decrypted |

### 1.8 Secure Notes
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F35 | Add secure note | Note encrypted and stored |
| F36 | View secure note | Biometric gate, then decrypted content shown |
| F37 | Delete secure note | Confirmation dialog, then removed |
| F38 | Copy note content | Clipboard set and auto-cleared |

### 1.9 Fractal Viewer
| # | Test Case | Expected Result |
|---|-----------|-----------------|
| F39 | Fractal keyprint in vault list | Static green neon thumbnail per entry |
| F40 | Tap entry shows animated fractal | Animated Mandelbrot with drift/glow/particles |
| F41 | Fullscreen fractal viewer | Modal with animated fractal, tap to close |
| F42 | Fractal fingerprint verification | Stored fingerprint matches on unlock |

## 2. Security Testing

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| S01 | Key derivation uses Argon2id | Argon2id primary, PBKDF2 fallback only on failure |
| S02 | AES-256-CBC + HMAC-SHA256 (EtM) | MAC covers IV + ciphertext, verified before decrypt |
| S03 | Tampered ciphertext detected | HMAC mismatch throws error, data not decrypted |
| S04 | Master key split via XOR shares | Key only reconstructed briefly via useKeyBriefly |
| S05 | Buffer wiping after use | Uint8Array buffers zeroed after crypto operations |
| S06 | HKDF per-entry subkeys | Each entry uses unique derived key |
| S07 | Recovery key hash only stored | Raw key never persisted, only SHA-256 hash |
| S08 | Auth hash double-hashed on server | Server stores sha256(authHash), never plaintext |
| S09 | Biometric freshness enforced | 2000ms staleness window, new prompt after expiry |
| S10 | Integrity guard periodic check | Tamper detection runs every 30s |
| S11 | No secrets in console output | No console.log of keys, passwords, or sensitive data |

## 3. Edge Case Testing

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| E01 | App background during decrypt | Lock triggers, sensitive state cleared |
| E02 | App background during delete undo | Pending deletion committed on lock |
| E03 | Rapid add/delete cycles | No race conditions, state consistent |
| E04 | Double-tap on destructive buttons | Guards prevent duplicate execution |
| E05 | Storage failure during save | Error alert shown, no silent data loss |
| E06 | Storage failure during delete | Entry restored, error alert shown |
| E07 | Network loss during sync | Appropriate error message |
| E08 | Corrupt stored data | Graceful error, option to wipe |
| E09 | App restart mid-operation | State recovers cleanly on relaunch |
| E10 | Multiple modals cannot stack | Only one modal visible at a time |

## 4. UX Testing

| # | Test Case | Expected Result |
|---|-----------|-----------------|
| U01 | All destructive actions have friction | Confirmation dialogs before delete/reset |
| U02 | Error messages are clear and actionable | User understands what went wrong and what to do |
| U03 | Loading states shown during async ops | Spinner/indicator during decrypt, save, verify |
| U04 | Input validation with visual feedback | Red borders on error, green on valid |
| U05 | Keyboard handling on all input screens | Content visible above keyboard on iOS |
| U06 | Safe area insets respected | No content hidden behind notch/Dynamic Island |
| U07 | Dark theme consistent throughout | All screens use dark palette |
