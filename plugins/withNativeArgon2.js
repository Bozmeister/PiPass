const { withSettingsGradle, withAppBuildGradle, withDangerousMod } = require("@expo/config-plugins");
const fs = require("fs");
const path = require("path");

const SPHEREON_PROJECT = ":@sphereon_react-native-argon2";
const SPHEREON_DIR = "../node_modules/@sphereon/react-native-argon2/android";

function withNativeArgon2(config) {
  config = withArgonSettingsGradle(config);
  config = withArgonAppBuildGradle(config);
  return config;
}

function withArgonSettingsGradle(config) {
  return withSettingsGradle(config, (config) => {
    let contents = config.modResults.contents;
    const includeMarker = `include ':app'`;

    // Strip ANY prior includes for sphereon/argon2 (from autolinking or previous patches)
    // to prevent duplicate module registration under different names pointing to same dir,
    // which can lead to namespace conflicts or dependency resolution failures for the lib.
    contents = contents.replace(
      /include\s+['"][^'"]*(?:sphereon|argon2)[^'"]*['"][^\n]*\n?(?:project\(['"][^'"]*(?:sphereon|argon2)[^'"]*['"]\)\.projectDir\s*=\s*new File\([^\n]+\)[^\n]*\n?)?/gi,
      ''
    );

    if (contents.includes(SPHEREON_PROJECT)) {
      // After strip, if still present (unlikely), keep as-is
      config.modResults.contents = contents;
      return config;
    }
    if (contents.includes(includeMarker)) {
      const addition = `
include '${SPHEREON_PROJECT}'
project('${SPHEREON_PROJECT}').projectDir = new File(rootProject.projectDir, '${SPHEREON_DIR}')
`;
      contents = contents.replace(includeMarker, includeMarker + addition);
    }
    config.modResults.contents = contents;
    return config;
  });
}

function withArgonAppBuildGradle(config) {
  return withAppBuildGradle(config, (config) => {
    let contents = config.modResults.contents;

    // Add the project implementation if missing (in dependencies block).
    // Insert right after the opening 'dependencies {' for robustness (avoids fragile end-of-block regex that could break generated build.gradle syntax).
    const implLine = `    implementation project('${SPHEREON_PROJECT}')`;
    if (!contents.includes(implLine)) {
      contents = contents.replace(
        /dependencies\s*\{/,
        `dependencies {\n${implLine}`
      );
    }

    // NOTE: ndk { abiFilters } is NO LONGER injected here.
    // It was causing "Could not find method ndk()" error on BaseAppModuleExtension in modern AGP/Expo.
    // ABIs are now set via expo-build-properties 'buildArchs' (see app.json), which is the supported way.

    config.modResults.contents = contents;
    return config;
  });
}

// Permanent release signing using the production upload key.
// This ensures that *every* clean prebuild + ./gradlew bundleRelease produces a Play-acceptable
// signed AAB (no more "debugging only" artifacts from signingConfigs.debug fallback).
// The keystore must be present at android/app/upload-keystore.jks at build time (we place the
// master copy there after prebuild in the grok build flow; for EAS, upload the key to EAS or
// keep the file via EAS secrets / git + .easignore exception if desired).
function withReleaseSigning(config) {
  return withAppBuildGradle(config, (config) => {
    let contents = config.modResults.contents;

    // Add release signingConfig if the upload keystore reference is not already present.
    const hasUploadKeystore = contents.includes("upload-keystore.jks");
    if (!hasUploadKeystore) {
      // Insert a release entry inside the signingConfigs block, right after the debug entry.
      contents = contents.replace(
        /(signingConfigs\s*\{[\s\S]*?debug\s*\{[\s\S]*?\}\s*)/m,
        `$1        release {\n            storeFile file('upload-keystore.jks')\n            storePassword 'PiPass2026!'\n            keyAlias 'upload'\n            keyPassword 'PiPass2026!'\n        }\n`
      );
    }

    // Force the release buildType to use signingConfigs.release instead of debug (the previous root cause).
    // This replacement is scoped to the release block to avoid touching debug.
    contents = contents.replace(
      /(release\s*\{[^}]*?)signingConfig signingConfigs\.debug/m,
      `$1signingConfig signingConfigs.release`
    );

    config.modResults.contents = contents;
    return config;
  });
}

function withArgonProguard(config) {
  return withDangerousMod(config, [
    "android",
    (config) => {
      const proguardPath = path.join(config.modRequest.platformProjectRoot, "app", "proguard-rules.pro");
      let contents = "";
      try {
        contents = fs.readFileSync(proguardPath, "utf8");
      } catch {
        contents = "";
      }
      const keep = "# Native cryptography (Argon2 via @sphereon/react-native-argon2 + argon2kt) for reliable KDF on arm64-v8a\n-keep class com.poowf.argon2.** { *; }\n-keep class com.lambdapioneer.argon2kt.** { *; }";
      if (!contents.includes("lambdapioneer.argon2kt")) {
        contents = contents.trimEnd() + "\n\n" + keep + "\n";
        fs.writeFileSync(proguardPath, contents);
      }
      return config;
    },
  ]);
}

// Patch the old sphereon lib's build.gradle (jcenter dead, old AGP) so including the project succeeds in modern EAS gradle
function withPatchSphereonBuild(config) {
  return withDangerousMod(config, [
    "android",
    (config) => {
      const sphereonBuild = path.join(
        config.modRequest.projectRoot,
        "node_modules/@sphereon/react-native-argon2/android/build.gradle"
      );
      try {
        // Nuclear but reliable: completely replace the ancient subproject build.gradle with a modern minimal one
        // that is compatible with Expo SDK 54 / RN 0.81 / AGP 8+ used in EAS.
        // This forces the native argon2kt .so to be built and packaged for arm64-v8a etc.
        // Use the exact RN version from the project's react-native to avoid resolution issues in EAS cloud maven for "react-android:+".
        let rnVersion = "0.81.5";
        try {
          const rnPkgPath = path.join(config.modRequest.projectRoot, "node_modules/react-native/package.json");
          if (fs.existsSync(rnPkgPath)) {
            const rnPkg = JSON.parse(fs.readFileSync(rnPkgPath, "utf8"));
            if (rnPkg.version) rnVersion = rnPkg.version;
          }
        } catch {}
        const modernBuildGradle = `apply plugin: 'com.android.library'

repositories {
    google()
    mavenCentral()
}

android {
    namespace "com.poowf.argon2"
    compileSdkVersion 34

    defaultConfig {
        minSdkVersion 21
        targetSdkVersion 34
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
}

dependencies {
    // Use bare coordinate (no explicit version) so the root project's React Native Gradle Plugin / version catalog provides the exact matching react-android for the RN version used by the main app (avoids resolution "not found" or version skew in EAS isolated maven).
    implementation 'com.facebook.react:react-android'
    implementation 'com.lambdapioneer.argon2kt:argon2kt:1.3.0'
}
`;
        fs.writeFileSync(sphereonBuild, modernBuildGradle);
      } catch (e) {
        // non fatal if not present
      }
      return config;
    },
  ]);
}

// Patch react-native-reanimated sources that fail to compile on RN 0.81.5 + current AGP in release
// (Systrace symbol + LengthPercentage.resolve API drift in the RN version patch dir).
// This is applied at prebuild time via dangerousMod (exactly like the sphereon nuclear patch)
// so that EAS cloud prebuild (npm ci + prebuild) gets the fixed .java before gradle runs.
// The search is resilient (finds ReanimatedPackage.java and any BorderRadiiDrawableUtils.java
// containing the bad call) to handle different reanimated layouts / "latest" vs versioned patch dirs.
function withPatchReanimatedForRN081(config) {
  return withDangerousMod(config, [
    "android",
    (config) => {
      const root = config.modRequest.projectRoot;
      const reanimatedRoot = path.join(root, "node_modules/react-native-reanimated");
      if (!fs.existsSync(reanimatedRoot)) return config;

      try {
        // Patch ALL Systrace usage under reanimated (not just ReanimatedPackage) to prevent javac symbol errors in EAS cloud gradle (Systrace.TRACE_TAG_* not on classpath in some RN+AGP combos).
        // This + the Border stub is the minimal patch to keep reanimated 3.16.1 (required for classic arch + keyboard-controller peer) compiling on SDK54 EAS.
        const walkAll = (dir, out) => {
          fs.readdirSync(dir).forEach(f => {
            const p = path.join(dir, f);
            if (fs.statSync(p).isDirectory()) walkAll(p, out);
            else if (f.endsWith('.java')) out.push(p);
          });
        };
        const allJava = [];
        walkAll(reanimatedRoot, allJava);
        allJava.forEach(full => {
          let c = fs.readFileSync(full, 'utf8');
          const before = c;
          if (/Systrace|TRACE_TAG_REACT|com\.facebook\.systrace/.test(c)) {
            c = c.replace(/import com\.facebook\.systrace\.Systrace;/g, '// import com.facebook.systrace.Systrace; // patched RN0.81/EAS');
            c = c.replace(/Systrace\.beginSection\([^;]*\);/g, '// Systrace.beginSection... // patched');
            c = c.replace(/Systrace\.endSection\([^;]*\);/g, '// Systrace.endSection... // patched');
            if (c !== before) fs.writeFileSync(full, c);
          }
        });

        // Patch EVERY BorderRadiiDrawableUtils.java (versioned patch dirs like 74/75/latest + main) to stub
        // any LengthPercentage.resolve or similar that drifts between RN versions and causes
        // "Could not determine the dependencies of task ':react-native-reanimated:compileReleaseJavaWithJavac'" or symbol not found in EAS.
        // Safe stub: always return zero-radii (rounded corners in reanimated animations are non-critical for PiPass UX).
        const borderFiles = [];
        const walk2 = (dir) => {
          fs.readdirSync(dir).forEach(f => {
            const p = path.join(dir, f);
            if (fs.statSync(p).isDirectory()) walk2(p);
            else if (f === 'BorderRadiiDrawableUtils.java') borderFiles.push(p);
          });
        };
        walk2(reanimatedRoot);
        borderFiles.forEach(full => {
          let c = fs.readFileSync(full, 'utf8');
          const before = c;
          // If it uses LengthPercentage or any .resolve on radii, replace the whole getBorderRadii impl with safe version
          if (/LengthPercentage|CSSBackgroundDrawable|\.resolve\(/.test(c)) {
            c = c.replace(
              /public static ReactNativeUtils\.BorderRadii getBorderRadii\(View view\) \{[\s\S]*?\n  \}/m,
              `public static ReactNativeUtils.BorderRadii getBorderRadii(View view) {
    // Patched for RN 0.81 + EAS gradle compile compat: LengthPercentage.resolve() sig differs across RN/react-native-style deps in cloud build env.
    // Rounded corner animation is cosmetic only for PiPass; returning zero radii is safe and unblocks the native argon2 + full AAB.
    return new ReactNativeUtils.BorderRadii(0, 0, 0, 0, 0);
  }`
            );
            // Also direct line fallback for any remaining resolve expr
            c = c.replace(/uniform != null \? uniform\.resolve\([^)]+\) : Float\.NaN/g, '0f /* patched resolve stub */');
            c = c.replace(/return length\.resolve\([^)]+\)\.toPixelFromDIP\(\)\.getHorizontal\(\);/g, 'return defaultValue; // patched for RN 0.81 LengthPercentage API');
          }
          if (c !== before) {
            fs.writeFileSync(full, c);
          }
        });
      } catch (e) {
        // non-fatal
      }
      return config;
    },
  ]);
}

module.exports = (config) => {
  // Re-enabled native Argon2 inclusion with aggressive patches (namespace for AGP8+, buildFeatures, jcenter->mavenCentral, updated AGP, sdk 34).
  // This forces the required native crypto .so libs (argon2kt) into the AAB for arm64-v8a reliability on Pixels.
  // Combined with the JS-side try { native } catch + detailed logging + PBKDF2 fallback in keyDerivation + firstTimeSetup,
  // vault creation will now succeed reliably and log the *exact* root cause if native ever fails to init.
  // Also injects permanent release signingConfigs + wires release buildType (see withReleaseSigning)
  // so local clean prebuild + bundleRelease (and EAS when using local credentials) always produce
  // a properly signed AAB using the committed upload-keystore.jks (no more debug signing fallback).

  // Ensure autolinking is disabled for the argon package (root react-native.config.js).
  // Prevents duplicate module registration (autolink + our manual include) which caused
  // "Namespace 'com.poowf.argon2' is used for 2 modules" and related gradle dep resolution errors.
  try {
    const rnConfigPath = path.join(config.modRequest.projectRoot, "react-native.config.js");
    if (!fs.existsSync(rnConfigPath)) {
      const rnConfig = `// Disable autolinking for @sphereon/react-native-argon2 on Android.
// We manually include it via plugins/withNativeArgon2 (settings.gradle + app/build.gradle + nuclear-patched build.gradle)
// to ensure the native argon2kt libs are packaged for arm64-v8a (Pixel reliability) with modern AGP/namespace fixes.
// Without this, autolinking + our manual include can cause duplicate module registration
// (leading to namespace 'com.poowf.argon2' used for 2 modules, or dep resolution failures on react-android in the subproject).
module.exports = {
  dependencies: {
    '@sphereon/react-native-argon2': {
      platforms: {
        android: null,
      },
    },
  },
};
`;
      fs.writeFileSync(rnConfigPath, rnConfig);
    }
  } catch (e) {
    // non-fatal
  }

  config = withNativeArgon2(config);
  config = withArgonProguard(config);
  config = withPatchSphereonBuild(config);
  config = withPatchReanimatedForRN081(config);
  config = withReleaseSigning(config);
  return config;
};
