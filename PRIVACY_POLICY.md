# PiPass Privacy Policy

**Last updated:** October 2026

PiPass is a zero-knowledge password manager. Our fundamental design principle is that **we cannot access, read, or recover your passwords or vault contents**.

## Information We Collect

### Local Device Storage (Primary)
- All your vault data (website URLs, usernames, passwords, secure notes) is encrypted on your device before it is ever written to storage.
- Encryption uses Argon2id key derivation + per-entry AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
- Data is stored in the operating system's secure enclave (iOS Keychain / Android Keystore) using `expo-secure-store`.
- We have no technical ability to read this data.

### Optional Cloud Sync
- When (and if) you enable cloud sync, only a single end-to-end encrypted blob containing your entire vault is uploaded to our servers.
- The server never receives your master password, any encryption keys, or any plaintext vault data.
- We cannot decrypt the data even if compelled by law or if our systems are breached.

### Biometric Authentication
- Face ID, fingerprint, or device passcode is used **only locally** on your device to unlock PiPass or authorize destructive actions.
- We never receive or store any biometric data or templates.

### Other Data
- Basic anonymous usage statistics and crash reports (opt-in only, never contains vault contents).
- No analytics SDKs that track you across apps.
- No third-party services receive information about the sites or services you store in PiPass (we disabled all external favicon lookups for this reason).

## What We Do Not Collect
- Your passwords or any plaintext vault data
- Your master password (never leaves your device)
- Precise location data
- Contacts, photos, or other personal files
- Browsing activity outside of PiPass

## How Your Data Is Protected
- Zero-knowledge architecture by design.
- All sensitive operations require fresh biometric or password confirmation.
- Screenshot protection is enabled in release builds on Android.
- Tamper detection and integrity checks run in the background.
- "Nuclear Reset" permanently destroys all local data with no recovery path.

## Your Rights
- You can export your data at any time.
- You can permanently delete everything using the built-in Nuclear Reset feature.
- Because we cannot access your data, we cannot fulfill "right to be forgotten" requests for vault contents — the data simply does not exist on our servers in readable form.

## Data Retention
- Local data: You control it completely.
- Cloud sync (if used): The encrypted blob remains on our servers only as long as you keep the account active. Deleting your account or performing a reset removes the server-side copy.

## Changes to This Policy
We will update this document when we add new features that affect privacy. The current version is always linked from inside the app and published at the URL configured in the app store listing.

## Contact
Privacy questions or security reports:  
Open an issue at https://github.com/yourusername/pipass  
or email: security@pipass.example.com

This policy is intentionally concise because PiPass is built to minimize the amount of data that exists in the first place.

---

**For developers / self-hosters:**  
This is the canonical privacy policy for the official PiPass distribution. If you fork or self-host the server component, you are responsible for publishing your own policy.