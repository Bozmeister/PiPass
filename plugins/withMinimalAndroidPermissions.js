const { withAndroidManifest } = require("@expo/config-plugins");

/**
 * Password-manager Android permission policy (P4).
 *
 * Libraries (expo-location, expo-image-picker, expo-file-system, RN debug,
 * expo-screen-capture, etc.) merge dangerous permissions into the final
 * manifest. Expo's android.blockedPermissions is also set in app.json; this
 * plugin hardens the main manifest so:
 *   1) Dangerous permissions never appear as positive <uses-permission>
 *   2) tools:node="remove" blocks re-injection from dependency manifests
 *
 * Allowed (positive) permissions for core vault function:
 *   - INTERNET              optional encrypted sync / account API
 *   - USE_BIOMETRIC         biometric unlock / SecureStore auth
 *   - USE_FINGERPRINT       legacy biometric API
 *   - VIBRATE               haptics / auth feedback
 *   - DETECT_SCREEN_CAPTURE optional screen-capture listener (API 34+)
 */

const ALLOWED_PERMISSIONS = new Set([
  "android.permission.INTERNET",
  "android.permission.USE_BIOMETRIC",
  "android.permission.USE_FINGERPRINT",
  "android.permission.VIBRATE",
  "android.permission.DETECT_SCREEN_CAPTURE",
  // Normal install/network state is harmless if a dep adds it; allow explicitly.
  "android.permission.ACCESS_NETWORK_STATE",
]);

/** Always emit tools:node="remove" for these, even if a library re-adds them. */
const BLOCKED_PERMISSIONS = [
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_BACKGROUND_LOCATION",
  "android.permission.ACCESS_MEDIA_LOCATION",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAPTURE_AUDIO_OUTPUT",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.MANAGE_EXTERNAL_STORAGE",
  "android.permission.CAMERA",
  "android.permission.READ_MEDIA_IMAGES",
  "android.permission.READ_MEDIA_VIDEO",
  "android.permission.READ_MEDIA_AUDIO",
  "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
  "android.permission.FOREGROUND_SERVICE",
  "android.permission.FOREGROUND_SERVICE_LOCATION",
  "android.permission.FOREGROUND_SERVICE_MICROPHONE",
  "android.permission.FOREGROUND_SERVICE_CAMERA",
  "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
  "android.permission.ACTIVITY_RECOGNITION",
  "android.permission.BLUETOOTH",
  "android.permission.BLUETOOTH_CONNECT",
  "android.permission.BLUETOOTH_SCAN",
  "android.permission.NEARBY_WIFI_DEVICES",
  "android.permission.READ_CONTACTS",
  "android.permission.WRITE_CONTACTS",
  "android.permission.READ_PHONE_STATE",
  "android.permission.CALL_PHONE",
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.SEND_SMS",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.QUERY_ALL_PACKAGES",
];

function ensureToolsNamespace(manifest) {
  if (!manifest.$) manifest.$ = {};
  if (!manifest.$["xmlns:tools"]) {
    manifest.$["xmlns:tools"] = "http://schemas.android.com/tools";
  }
}

function permissionName(entry) {
  return entry?.$?.["android:name"] || "";
}

function isRemoveNode(entry) {
  return entry?.$?.["tools:node"] === "remove";
}

function withMinimalAndroidPermissions(config) {
  // Keep Expo's blockedPermissions list in sync so prebuild + merger both strip.
  const android = config.android ?? {};
  const existingBlocked = Array.isArray(android.blockedPermissions)
    ? android.blockedPermissions
    : [];
  const blockedSet = new Set([...existingBlocked, ...BLOCKED_PERMISSIONS]);
  config.android = {
    ...android,
    blockedPermissions: Array.from(blockedSet),
  };

  return withAndroidManifest(config, (config) => {
    const manifest = config.modResults.manifest;
    ensureToolsNamespace(manifest);

    const existing = manifest["uses-permission"] || [];
    const kept = [];
    const seenRemove = new Set();
    const seenAllow = new Set();

    for (const entry of existing) {
      const name = permissionName(entry);
      if (!name) continue;

      if (isRemoveNode(entry)) {
        if (!seenRemove.has(name)) {
          kept.push(entry);
          seenRemove.add(name);
        }
        continue;
      }

      if (BLOCKED_PERMISSIONS.includes(name) || !ALLOWED_PERMISSIONS.has(name)) {
        // Drop positive declaration of blocked/unknown dangerous permissions.
        continue;
      }

      if (!seenAllow.has(name)) {
        kept.push(entry);
        seenAllow.add(name);
      }
    }

    // Ensure core allowlist is present (positive).
    for (const name of [
      "android.permission.INTERNET",
      "android.permission.USE_BIOMETRIC",
      "android.permission.USE_FINGERPRINT",
      "android.permission.VIBRATE",
    ]) {
      if (!seenAllow.has(name)) {
        kept.push({ $: { "android:name": name } });
        seenAllow.add(name);
      }
    }

    // Ensure blocked permissions are actively removed by the merger.
    for (const name of BLOCKED_PERMISSIONS) {
      if (!seenRemove.has(name)) {
        kept.push({
          $: {
            "android:name": name,
            "tools:node": "remove",
          },
        });
        seenRemove.add(name);
      }
    }

    manifest["uses-permission"] = kept;

    // Also strip uses-permission-sdk-23 style if present.
    if (manifest["uses-permission-sdk-23"]) {
      manifest["uses-permission-sdk-23"] = manifest["uses-permission-sdk-23"].filter(
        (entry) => {
          const name = permissionName(entry);
          return ALLOWED_PERMISSIONS.has(name) && !BLOCKED_PERMISSIONS.includes(name);
        },
      );
    }

    return config;
  });
}

module.exports = withMinimalAndroidPermissions;
// Exported for unit tests / docs
module.exports.BLOCKED_PERMISSIONS = BLOCKED_PERMISSIONS;
module.exports.ALLOWED_PERMISSIONS = ALLOWED_PERMISSIONS;
