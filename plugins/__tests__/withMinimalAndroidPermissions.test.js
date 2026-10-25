/**
 * Minimal Android permission policy (P4).
 */
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  BLOCKED_PERMISSIONS,
  ALLOWED_PERMISSIONS,
} = require("../withMinimalAndroidPermissions");

test("blocked list includes dangerous password-manager-irrelevant permissions", () => {
  const required = [
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
  ];
  for (const p of required) {
    assert.ok(BLOCKED_PERMISSIONS.includes(p), `missing blocked: ${p}`);
  }
});

test("allowlist is minimal (internet + biometrics + vibrate)", () => {
  assert.ok(ALLOWED_PERMISSIONS.has("android.permission.INTERNET"));
  assert.ok(ALLOWED_PERMISSIONS.has("android.permission.USE_BIOMETRIC"));
  assert.ok(ALLOWED_PERMISSIONS.has("android.permission.USE_FINGERPRINT"));
  assert.ok(ALLOWED_PERMISSIONS.has("android.permission.VIBRATE"));
  assert.equal(ALLOWED_PERMISSIONS.has("android.permission.SYSTEM_ALERT_WINDOW"), false);
  assert.equal(ALLOWED_PERMISSIONS.has("android.permission.ACCESS_FINE_LOCATION"), false);
  assert.equal(ALLOWED_PERMISSIONS.has("android.permission.RECORD_AUDIO"), false);
});

test("no permission is both allowed and blocked", () => {
  for (const p of BLOCKED_PERMISSIONS) {
    assert.equal(
      ALLOWED_PERMISSIONS.has(p),
      false,
      `permission both allowed and blocked: ${p}`,
    );
  }
});
