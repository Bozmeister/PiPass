const assert = require("node:assert/strict");
const test = require("node:test");
const { applyReleaseSigningToGradle } = require("../withNativeArgon2");

const EXPO_TEMPLATE = `
android {
    signingConfigs {
        debug {
            storeFile file('debug.keystore')
            storePassword 'android'
            keyAlias 'androiddebugkey'
            keyPassword 'android'
        }
    }
    buildTypes {
        debug {
            signingConfig signingConfigs.debug
        }
        release {
            signingConfig signingConfigs.debug
            minifyEnabled enableMinifyInReleaseBuilds
        }
    }
}
`;

test("defines signingConfigs.release and wires the release buildType", () => {
  const out = applyReleaseSigningToGradle(EXPO_TEMPLATE);
  assert.match(out, /pipassReleaseSigningConfigured/);
  assert.match(out, /pipass-signingConfigs-release/);
  assert.match(out, /signingConfigs\.release/);
  assert.doesNotMatch(
    out,
    /buildTypes\s*\{[\s\S]*\brelease\s*\{[\s\S]*signingConfig signingConfigs\.debug/,
  );
  assert.doesNotMatch(out, /PiPass2026!/);
  assert.match(out, /PIPASS_UPLOAD_STORE_PASSWORD/);
  assert.match(out, /keystore\.properties/);
  assert.match(out, /pipassResolvedStoreFile/);
  assert.match(out, /pipassReadSigningMap/);
  assert.match(out, /storepassword/);
  assert.match(
    out,
    /signingConfig \(pipassReleaseSigningConfigured \? signingConfigs\.release : signingConfigs\.debug\)/,
  );
});

test("is idempotent and does not drop signingConfigs.release", () => {
  const once = applyReleaseSigningToGradle(EXPO_TEMPLATE);
  const twice = applyReleaseSigningToGradle(once);
  assert.equal(
    (twice.match(/pipass-signingConfigs-release/g) || []).length,
    1,
  );
  assert.equal(
    (twice.match(/pipassReleaseSigningConfigured = /g) || []).length,
    1,
  );
  assert.match(twice, /signingConfigs\.release/);
});

test("repairs a file that already points at a missing signingConfigs.release", () => {
  const broken = EXPO_TEMPLATE.replace(
    /buildTypes\s*\{[\s\S]*signingConfig signingConfigs\.debug/,
    `buildTypes {
        debug {
            signingConfig signingConfigs.debug
        }
        release {
            signingConfig signingConfigs.release`,
  );
  const out = applyReleaseSigningToGradle(broken);
  assert.match(out, /pipass-signingConfigs-release/);
  assert.match(
    out,
    /signingConfigs\s*\{[\s\S]*release\s*\{[\s\S]*pipass-signingConfigs-release/,
  );
});
