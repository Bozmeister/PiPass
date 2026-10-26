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

function releaseSigningBlock(gradle) {
  const marker = "// pipass-signingConfigs-release";
  const markerAt = gradle.indexOf(marker);
  assert.notEqual(markerAt, -1);
  const releaseAt = gradle.lastIndexOf("release", markerAt);
  const open = gradle.indexOf("{", releaseAt);
  let depth = 0;
  for (let i = open; i < gradle.length; i++) {
    if (gradle[i] === "{") depth += 1;
    else if (gradle[i] === "}") {
      depth -= 1;
      if (depth === 0) return gradle.slice(releaseAt, i + 1);
    }
  }
  throw new Error("release signing block did not close");
}

test("local keystore configures signingConfigs.release from properties or PIPASS_UPLOAD_*", () => {
  const out = applyReleaseSigningToGradle(EXPO_TEMPLATE);
  const block = releaseSigningBlock(out);
  assert.match(out, /keystore\.properties/);
  assert.match(out, /PIPASS_UPLOAD_STORE_PASSWORD/);
  assert.match(out, /PIPASS_UPLOAD_KEY_PASSWORD/);
  assert.match(out, /PIPASS_UPLOAD_KEY_ALIAS/);
  assert.match(out, /PIPASS_UPLOAD_STORE_FILE/);
  assert.match(block, /if \(pipassReleaseSigningConfigured\)/);
  assert.match(block, /storeFile pipassResolvedStoreFile/);
  assert.match(block, /storePassword pipassStorePassword/);
  assert.match(block, /keyAlias pipassKeyAlias/);
  assert.match(block, /keyPassword pipassKeyPassword/);
  assert.doesNotMatch(block, /storePassword\s+['"][^'"]+['"]/);
  assert.doesNotMatch(block, /keyPassword\s+['"][^'"]+['"]/);
  assert.doesNotMatch(out, /PiPass2026!/);
  assert.match(
    out,
    /buildTypes\s*\{[\s\S]*\brelease\s*\{[\s\S]*signingConfig signingConfigs\.release/,
  );
});

test("EAS fallback leaves release empty and throws only when no store file was injected", () => {
  const out = applyReleaseSigningToGradle(EXPO_TEMPLATE);
  const block = releaseSigningBlock(out);
  const beforeGate = block.split("if (pipassReleaseSigningConfigured)")[0];
  assert.doesNotMatch(beforeGate, /storeFile/);
  assert.doesNotMatch(beforeGate, /storePassword/);
  assert.doesNotMatch(beforeGate, /keyPassword/);
  assert.match(out, /eas-build\.gradle/);
  assert.match(out, /project\.android\.signingConfigs\.release\.storeFile/);
  assert.match(
    out,
    /if \(signingRelease && !pipassReleaseSigningConfigured && easInjectedStoreFile == null\)/,
  );
  assert.doesNotMatch(
    out,
    /buildTypes\s*\{[\s\S]*\brelease\s*\{[\s\S]*signingConfig signingConfigs\.debug/,
  );
  assert.doesNotMatch(
    out,
    /signingConfig \(pipassReleaseSigningConfigured \? signingConfigs\.release : signingConfigs\.debug\)/,
  );
});

test("prebuild refreshes a marked release block that still has a hardcoded password", () => {
  const current = applyReleaseSigningToGradle(EXPO_TEMPLATE);
  const stale = current.replace(
    /if \(pipassReleaseSigningConfigured\) \{[\s\S]*?keyPassword pipassKeyPassword\s*\}/,
    "storePassword 'hardcoded-secret'\n            keyPassword 'hardcoded-secret'",
  );
  assert.match(stale, /hardcoded-secret/);
  const out = applyReleaseSigningToGradle(stale);
  const block = releaseSigningBlock(out);
  assert.doesNotMatch(out, /hardcoded-secret/);
  assert.match(block, /if \(pipassReleaseSigningConfigured\)/);
  assert.match(block, /storePassword pipassStorePassword/);
  assert.equal((out.match(/easInjectedStoreFile == null/g) || []).length, 1);
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
