# PiPass - Google Play Store Release Checklist

## Pre-Submission

1. **Final Build & Signing**
   - Run production build using EAS or local Gradle with release keystore.
   - Verify the AAB is signed with the production key (not debug keystore).
   - Confirm `versionCode` and `versionName` are correct in app.json / EAS.

2. **Privacy Policy**
   - Host `PRIVACY_POLICY.md` at `https://pipass.app/privacy`
   - Confirm the URL is set in `app.json` under `privacyPolicyUrl`.

3. **App Content & Assets**
   - Prepare high-quality screenshots (phone + tablet) for dark theme.
   - Write compelling short & full description.
   - Choose appropriate category: "Productivity" or "Tools".
   - Set content rating (likely "Everyone" or "Teen" depending on final copy).

## Google Play Console Setup

4. **Create App Listing**
   - Upload signed AAB to Internal Testing track first.
   - Fill in App name, Short description, Full description.
   - Upload app icon, feature graphic, and screenshots.

5. **Data Safety Section** (see copy below)
   - Complete the Data Safety form using the ready-to-copy answers.
   - Declare optional account identifiers and security metadata when an account is used.
   - Do not declare vault plaintext, on-device search, or unwrapped item keys as collected.
   - Use the store listing paragraph in `PRIVACY_POLICY.md`. Do not call the default build multi-device sync.

6. **App Access**
   - If using any gated features, provide test credentials or instructions.
   - For PiPass, mark as "All functionality is available without special access".

7. **Content Rating Questionnaire**
   - Complete the questionnaire honestly (no violence, gambling, etc.).

## Final Review & Launch

8. **Pre-Launch Report**
   - Review the Pre-launch report for crashes, ANRs, and policy issues.
   - Fix any critical issues found.

9. **Release to Production**
   - Promote the build from Internal → Closed → Open Testing → Production.
   - Set rollout percentage (start at 5–10% if desired).

10. **Post-Launch Monitoring**
    - Monitor Crashlytics / Play Console for issues in the first 48 hours.
    - Be ready to respond to user reviews quickly.

---

## Store listing

**Short description**

Encrypted passwords on your device. Optional account. Plaintext stays local.

**Full description** (opening paragraph)

PiPass encrypts each vault entry on your device. Your master password and vault plaintext stay on that device. Search runs against a local encrypted index while the vault is unlocked. An optional account can store account and security metadata. Optional item sync stores ciphertext and a signed receipt, and it is off unless a build turns that flag on. The server does not receive vault plaintext, the master password, the search key, or unwrapped item keys. There is no recovery of a forgotten master password.

## Ready-to-Copy Data Safety Answers

Copy the table in `PRIVACY_POLICY.md` under "Google Play Data Safety". Summary for a default build, flags unset:

**Data collected**
- Vault contents, the search index, and envelope keys stay on the device. That on-device processing is not collection.
- An optional account, if used, collects account identifiers, security-activity metadata, IP address, and user agent.

**Data shared**
- No data type above is shared with third parties.
- Vault plaintext is not uploaded by the default build.

**Security practices**
- Data is encrypted in transit (HTTPS).
- Vault records are encrypted on-device before storage (AES-256-GCM `v4` in platform secure storage).

**User data**
- Users can delete local data with Nuclear Reset, which also deletes the local search index.
- `DELETE /api/account` deletes the user row and cascades vault blobs, blob history, vault items, receipts, sessions, the audit log, WebAuthn credentials, trusted devices, and honeytoken rows.
- The client helper is off unless `EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE=1`, and it wipes the device only after HTTP 204.

**Location**
- Location is not collected.

**App activity**
- In-app search history stays on the device. Do not declare it.
- Optional account features record security and sync activity metadata.
- Declare encrypted item ciphertext and receipts only if the submitted build sets `EXPO_PUBLIC_INTENTDB_ITEM_UPLOAD=1`.

**Other**
- The developer cannot open vault ciphertext without the user's master password. The operator can still see account activity, blob sizes, and (if enabled) escrowed TOTP secrets.