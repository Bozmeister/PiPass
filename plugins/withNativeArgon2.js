const {
  withSettingsGradle,
  withAppBuildGradle,
  withDangerousMod,
  withMainApplication,
} = require("@expo/config-plugins");
const fs = require("fs");
const path = require("path");

const LOCAL_PROJECT = ":pipass-argon2";
const LOCAL_DIR = "../modules/pipass-argon2/android";

function withNativeArgon2(config) {
  // Gradle include + PackageList registration come from Expo/RN
  // autolinking of modules/pipass-argon2 (package.json + react-native.config.js).
  // This plugin only strips leftover Sphereon includes so they cannot
  // collide with the first-party module.
  config = withArgonSettingsGradle(config);
  return config;
}

/**
 * Register the first-party Android module. Autolinking is not used for
 * @sphereon/react-native-argon2 on Android (see react-native.config.js).
 * JS still reads NativeModules.RNArgon2 (PipassArgon2Module.getName()).
 */
function withArgonMainApplicationPackage(config) {
  return withMainApplication(config, (config) => {
    let contents = config.modResults.contents;
    if (contents.includes("PipassArgon2Package")) {
      return config;
    }

    // Drop a previous Sphereon registration if a rebuild is incremental.
    contents = contents.replace(/\nimport com\.poowf\.argon2\.RNArgon2Package/g, "");
    contents = contents.replace(
      /\n\s*\/\/ Manual register:[^\n]*\n\s*add\(RNArgon2Package\(\)\)/g,
      "",
    );
    contents = contents.replace(
      /\n\s*\/\/ Manual register:[^\n]*\n\s*packages\.add\(new RNArgon2Package\(\)\);/g,
      "",
    );

    // Kotlin (Expo SDK 54 default)
    if (contents.includes("PackageList(this).packages")) {
      if (!contents.includes("import com.pipass.argon2.PipassArgon2Package")) {
        if (contents.includes("import expo.modules.ReactNativeHostWrapper")) {
          contents = contents.replace(
            "import expo.modules.ReactNativeHostWrapper",
            "import expo.modules.ReactNativeHostWrapper\nimport com.pipass.argon2.PipassArgon2Package",
          );
        } else if (contents.includes("import com.facebook.react.PackageList")) {
          contents = contents.replace(
            "import com.facebook.react.PackageList",
            "import com.facebook.react.PackageList\nimport com.pipass.argon2.PipassArgon2Package",
          );
        }
      }
      contents = contents.replace(
        /(PackageList\(this\)\.packages\.apply\s*\{)/,
        `$1\n              // First-party Android Argon2 (modules/pipass-argon2)\n              add(PipassArgon2Package())`,
      );
    } else if (contents.includes("new PackageList(this).getPackages()")) {
      if (!contents.includes("import com.pipass.argon2.PipassArgon2Package")) {
        contents = contents.replace(
          "import com.facebook.react.PackageList;",
          "import com.facebook.react.PackageList;\nimport com.pipass.argon2.PipassArgon2Package;",
        );
      }
      contents = contents.replace(
        /(List<ReactPackage> packages = new PackageList\(this\)\.getPackages\(\);)/,
        `$1\n              // First-party Android Argon2 (modules/pipass-argon2)\n              packages.add(new PipassArgon2Package());`,
      );
    }

    config.modResults.contents = contents;
    return config;
  });
}

function withArgonSettingsGradle(config) {
  return withSettingsGradle(config, (config) => {
    let contents = config.modResults.contents;

    // Drop leftover Sphereon includes only. Do not re-add :pipass-argon2
    // here — Expo autolinking of modules/pipass-argon2 owns that include.
    contents = contents.replace(
      /include\s+['"]:@sphereon_react-native-argon2['"][^\n]*\n?(?:project\(['"]:@sphereon_react-native-argon2['"]\)\.projectDir\s*=\s*new File\([^\n]+\)[^\n]*\n?)?/gi,
      "",
    );

    config.modResults.contents = contents;
    return config;
  });
}

function withArgonAppBuildGradle(config) {
  return withAppBuildGradle(config, (config) => {
    let contents = config.modResults.contents;

    // Add the project implementation if missing (in dependencies block).
    // Insert right after the opening 'dependencies {' for robustness (avoids fragile end-of-block regex that could break generated build.gradle syntax).
    const implLine = `    implementation project('${LOCAL_PROJECT}')`;
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

const RELEASE_SIGNING_LOADER_MARKER = "pipassResolvedStoreFile";
const RELEASE_SIGNING_CONFIG_MARKER = "pipass-signingConfigs-release";
const RELEASE_SIGNING_BEGIN = "// BEGIN pipass-release-signing";
const RELEASE_SIGNING_END = "// END pipass-release-signing";

const RELEASE_SIGNING_LOADER = `
${RELEASE_SIGNING_BEGIN}
// Secrets from android/app/keystore.properties or PIPASS_UPLOAD_* — never hardcoded.
def pipassTrimSigningValue(value) {
    if (value == null) return ""
    def text = value.toString().trim()
    if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
        return text.substring(1, text.length() - 1).trim()
    }
    return text
}
def pipassFirstNonEmpty(Object... values) {
    for (value in values) {
        def text = pipassTrimSigningValue(value)
        if (text.length() > 0) return text
    }
    return ""
}
def pipassReadSigningMap(File propsFile) {
    def map = [:]
    def text = propsFile.getText("UTF-8")
    if (text.startsWith("\\uFEFF")) {
        text = text.substring(1)
    }
    text.eachLine { raw ->
        def line = raw.trim()
        if (line.length() == 0 || line.startsWith("#") || line.startsWith("!")) return
        def eq = line.indexOf("=")
        def colon = line.indexOf(":")
        def sep = -1
        if (eq >= 0 && (colon < 0 || eq < colon)) sep = eq
        else if (colon >= 0) sep = colon
        if (sep < 0) return
        def key = line.substring(0, sep).trim().toLowerCase().replace("_", "").replace("-", "")
        def val = line.substring(sep + 1).trim()
        if (key.length() > 0) map[key] = val
    }
    return map
}
def pipassKeystorePropertiesFile = [
    file("keystore.properties"),
    file("\${projectDir}/keystore.properties"),
    rootProject.file("app/keystore.properties"),
    rootProject.file("keystore.properties"),
].find { it != null && it.isFile() }
def pipassSigningMap = [:]
if (pipassKeystorePropertiesFile != null) {
    pipassSigningMap = pipassReadSigningMap(pipassKeystorePropertiesFile)
    logger.lifecycle("[pipass] loaded signing properties from " + pipassKeystorePropertiesFile.absolutePath + " keys=" + pipassSigningMap.keySet())
} else {
    logger.lifecycle("[pipass] keystore.properties not found next to the app module or android/")
}
def pipassStorePassword = pipassFirstNonEmpty(
    pipassSigningMap["storepassword"],
    System.getenv("PIPASS_UPLOAD_STORE_PASSWORD")
)
def pipassKeyPassword = pipassFirstNonEmpty(
    pipassSigningMap["keypassword"],
    System.getenv("PIPASS_UPLOAD_KEY_PASSWORD")
)
def pipassKeyAlias = pipassFirstNonEmpty(
    pipassSigningMap["keyalias"],
    System.getenv("PIPASS_UPLOAD_KEY_ALIAS"),
    "upload"
)
def pipassStoreFileName = pipassFirstNonEmpty(
    pipassSigningMap["storefile"],
    System.getenv("PIPASS_UPLOAD_STORE_FILE"),
    "upload-keystore.jks"
)
def pipassStoreFileCandidates = []
if (pipassStoreFileName.length() > 0) {
    def named = new File(pipassStoreFileName)
    if (named.isAbsolute()) {
        pipassStoreFileCandidates.add(named)
    }
    pipassStoreFileCandidates.add(file(pipassStoreFileName))
    pipassStoreFileCandidates.add(file("\${projectDir}/" + named.name))
    pipassStoreFileCandidates.add(rootProject.file("app/" + named.name))
    pipassStoreFileCandidates.add(rootProject.file(pipassStoreFileName))
}
def ${RELEASE_SIGNING_LOADER_MARKER} = pipassStoreFileCandidates.find { it != null && it.isFile() }
if (${RELEASE_SIGNING_LOADER_MARKER} != null) {
    ${RELEASE_SIGNING_LOADER_MARKER} = ${RELEASE_SIGNING_LOADER_MARKER}.absoluteFile
    logger.lifecycle("[pipass] release keystore " + ${RELEASE_SIGNING_LOADER_MARKER})
}
def pipassReleaseSigningConfigured = (pipassStorePassword.length() > 0) && (pipassKeyPassword.length() > 0) && (${RELEASE_SIGNING_LOADER_MARKER} != null)
logger.lifecycle("[pipass] release signing configured=" + pipassReleaseSigningConfigured + " storePassword=" + (pipassStorePassword.length() > 0) + " keyPassword=" + (pipassKeyPassword.length() > 0) + " alias=" + (pipassKeyAlias.length() > 0) + " storeFile=" + (${RELEASE_SIGNING_LOADER_MARKER} != null))
gradle.taskGraph.whenReady { graph ->
    def signingRelease = graph.allTasks.any { it.name.toLowerCase().contains("signrelease") }
    // EAS fallback: eas-build.gradle fills signingConfigs.release from credentials.json
    // before this hook. A local release with no keystore and no injected store file still fails.
    def easInjectedStoreFile = null
    try {
        easInjectedStoreFile = project.android.signingConfigs.release.storeFile
    } catch (Exception ignored) {
        easInjectedStoreFile = null
    }
    if (signingRelease && !pipassReleaseSigningConfigured && easInjectedStoreFile == null) {
        throw new GradleException(
            "Release signing is not configured (storePassword=" + (pipassStorePassword.length() > 0) + ", keyPassword=" + (pipassKeyPassword.length() > 0) + ", storeFile=" + (${RELEASE_SIGNING_LOADER_MARKER} != null) + "). Put storePassword/keyPassword/keyAlias/storeFile in android/app/keystore.properties (or set PIPASS_UPLOAD_*)."
        )
    }
}
${RELEASE_SIGNING_END}

`;

const RELEASE_SIGNING_CONFIG_BLOCK = `        release {
            // ${RELEASE_SIGNING_CONFIG_MARKER}
            // Local builds use keystore.properties or PIPASS_UPLOAD_*.
            // When those are absent, leave this empty so EAS eas-build.gradle can fill it.
            if (pipassReleaseSigningConfigured) {
                storeFile ${RELEASE_SIGNING_LOADER_MARKER}
                storePassword pipassStorePassword
                keyAlias pipassKeyAlias
                keyPassword pipassKeyPassword
            }
        }
`;

/**
 * Replace the signingConfigs.release block that carries the marker.
 * A later prebuild must refresh an older block, not leave it in place.
 */
function replaceMarkedReleaseBlock(contents, replacement) {
  const marker = `// ${RELEASE_SIGNING_CONFIG_MARKER}`;
  const markerAt = contents.indexOf(marker);
  if (markerAt < 0) return contents;
  const releaseAt = contents.lastIndexOf("release", markerAt);
  const open = contents.indexOf("{", releaseAt);
  if (releaseAt < 0 || open < 0) return contents;
  let depth = 0;
  for (let i = open; i < contents.length; i++) {
    if (contents[i] === "{") depth += 1;
    else if (contents[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        return contents.slice(0, releaseAt) + replacement.trim() + contents.slice(i + 1);
      }
    }
  }
  return contents;
}

/**
 * Ensure signingConfigs.release exists and buildTypes.release points at it.
 * Local secrets come from keystore.properties / PIPASS_UPLOAD_* — never hardcoded.
 * When those are absent the release block stays empty so EAS eas-build.gradle
 * can inject the remote keystore. Exported for unit tests.
 */
function applyReleaseSigningToGradle(contents) {
  let next = contents;

  next = next.replace(
    /storePassword\s+['"]PiPass2026!['"]/g,
    "storePassword pipassStorePassword",
  );
  next = next.replace(
    /keyPassword\s+['"]PiPass2026!['"]/g,
    "keyPassword pipassKeyPassword",
  );

  // Replace any previous loader (old relative-path version or this block).
  next = next.replace(
    /\n\/\/ BEGIN pipass-release-signing[\s\S]*?\/\/ END pipass-release-signing\n/,
    "\n",
  );
  next = next.replace(
    /\n\/\/ Release signing secrets:[\s\S]*?def pipassReleaseSigningConfigured = [^\n]+\n/,
    "\n",
  );

  if (!next.includes(RELEASE_SIGNING_BEGIN)) {
    if (next.includes("\nandroid {")) {
      next = next.replace("\nandroid {", `${RELEASE_SIGNING_LOADER}android {`);
    } else {
      next = RELEASE_SIGNING_LOADER + next;
    }
  }

  if (next.includes(RELEASE_SIGNING_CONFIG_MARKER)) {
    next = replaceMarkedReleaseBlock(next, RELEASE_SIGNING_CONFIG_BLOCK);
  }

  if (!next.includes(RELEASE_SIGNING_CONFIG_MARKER)) {
    const hardcodedRelease =
      /release\s*\{\s*storeFile file\(['"]upload-keystore\.jks['"]\)\s*storePassword ['"][^'"]*['"]\s*keyAlias ['"][^'"]*['"]\s*keyPassword ['"][^'"]*['"]\s*\}/m;
    if (hardcodedRelease.test(next)) {
      next = next.replace(hardcodedRelease, RELEASE_SIGNING_CONFIG_BLOCK.trim());
    } else {
      const inserted = next.replace(
        /(signingConfigs\s*\{[\s\S]*?debug\s*\{[\s\S]*?\}\s*)/m,
        `$1${RELEASE_SIGNING_CONFIG_BLOCK}`,
      );
      if (inserted === next) {
        throw new Error(
          "[withNativeArgon2] Could not insert signingConfigs.release (no signingConfigs.debug block).",
        );
      }
      next = inserted;
    }
  }

  if (next.includes(RELEASE_SIGNING_CONFIG_MARKER)) {
    next = next.replace(
      /(buildTypes\s*\{[\s\S]*?\brelease\s*\{[\s\S]*?)signingConfig signingConfigs\.(?:debug|release)\b/,
      "$1signingConfig signingConfigs.release",
    );
  }

  return next;
}

function withReleaseSigning(config) {
  return withAppBuildGradle(config, (config) => {
    config.modResults.contents = applyReleaseSigningToGradle(
      config.modResults.contents,
    );
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
      const keep = "# Native cryptography (first-party pipass-argon2 + argon2kt)\n-keep class com.pipass.argon2.** { *; }\n-keep class com.lambdapioneer.argon2kt.** { *; }";
      if (!contents.includes("com.pipass.argon2")) {
        contents = contents.trimEnd() + "\n\n" + keep + "\n";
        fs.writeFileSync(proguardPath, contents);
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
          // Nuclear stub: any BorderRadiiDrawableUtils that touches LengthPercentage / resolve
          // must be fully replaced. Partial method replacement leaves helper methods like
          // getRadiusForCorner() which still call resolve() with the wrong RN 0.81 signature
          // and fail compileReleaseJavaWithJavac (even if getBorderRadii itself is stubbed).
          if (/LengthPercentage|CSSBackgroundDrawable|\.resolve\(/.test(c)) {
            const stub = `package com.swmansion.reanimated;

import android.view.View;

public class BorderRadiiDrawableUtils {
  public static ReactNativeUtils.BorderRadii getBorderRadii(View view) {
    // Patched for RN 0.81 + AGP compile compat: LengthPercentage.resolve() signature
    // differs across RN versions. Rounded-corner animation is cosmetic for PiPass.
    return new ReactNativeUtils.BorderRadii(0, 0, 0, 0, 0);
  }
}
`;
            if (c !== stub) {
              fs.writeFileSync(full, stub);
            }
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
  // Argon2 strategy (Android): first-party module at modules/pipass-argon2
  // (argon2kt). JS never requires @sphereon/react-native-argon2.
  // iOS: Sphereon remains autolinked; JS prefers hash-wasm there because
  // CatCrypto treats salt as a UTF-8 string, not hex-decoded bytes.
  // Fallback chain is in crypto/keyDerivation.ts (native → wasm → PBKDF2).
  //
  // Also injects release signingConfigs (keystore.properties / PIPASS_UPLOAD_*)
  // and RN 0.81 reanimated compile stubs.

  try {
    const rnConfigPath = path.join(config.modRequest.projectRoot, "react-native.config.js");
    if (!fs.existsSync(rnConfigPath)) {
      const rnConfig = `// Android Argon2 is the first-party modules/pipass-argon2 project.
// Disable Sphereon autolink on Android so it cannot register a second RNArgon2.
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
  config = withPatchReanimatedForRN081(config);
  config = withReleaseSigning(config);
  return config;
};

module.exports.applyReleaseSigningToGradle = applyReleaseSigningToGradle;
