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
   - Declare that PiPass does **not** collect personal information.

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

## Ready-to-Copy Data Safety Answers

**Data collected**
- No personal information is collected.

**Data shared**
- Data is not shared with third parties.

**Security practices**
- Data is encrypted in transit.
- Data is encrypted at rest (on-device using Android Keystore / iOS Keychain).

**User data**
- Users can delete all their data using the "Nuclear Reset" feature inside the app.
- All data is stored locally on the user's device.
- Optional cloud sync (when implemented) uses end-to-end encryption — we cannot access user data.

**Location**
- Location is not collected.

**App activity**
- No app activity is collected.

**Other**
- This is a zero-knowledge password manager. The developer has no access to user passwords or vault contents.