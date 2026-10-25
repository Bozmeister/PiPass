/**
 * Screen capture protection policy tests (P3).
 */
import assert from "node:assert/strict";
import test from "node:test";

// Minimal Platform stub before module load is not needed — shouldBlockScreenCapture
// uses react-native Platform which is stubbed in setup-env as web.
// On web, protection must be off.

test("shouldBlockScreenCapture is false on web / Node test env", async () => {
  const mod = await import("../screenCaptureProtection");
  // setup-env stubs Platform.OS = "web"
  assert.equal(mod.shouldBlockScreenCapture(), false);
});

test("enableScreenCaptureProtection is safe to call (no throw) on web", async () => {
  const mod = await import("../screenCaptureProtection");
  await assert.doesNotReject(async () => {
    await mod.enableScreenCaptureProtection();
    await mod.disableScreenCaptureProtection();
  });
});
