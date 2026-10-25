const { withAndroidManifest } = require("@expo/config-plugins");

/**
 * Force android:allowBackup="false" on every prebuild.
 * tools:replace ensures dependency manifests cannot re-enable backup.
 */
function withDisallowBackup(config) {
  return withAndroidManifest(config, (config) => {
    const manifest = config.modResults.manifest;
    if (!manifest.$) {
      manifest.$ = {};
    }
    if (!manifest.$["xmlns:tools"]) {
      manifest.$["xmlns:tools"] = "http://schemas.android.com/tools";
    }

    const application = manifest.application?.[0];
    if (!application) {
      return config;
    }
    if (!application.$) {
      application.$ = {};
    }

    application.$["android:allowBackup"] = "false";

    const existingReplace = application.$["tools:replace"];
    if (!existingReplace) {
      application.$["tools:replace"] = "android:allowBackup";
    } else {
      const parts = String(existingReplace)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (!parts.includes("android:allowBackup")) {
        parts.push("android:allowBackup");
      }
      application.$["tools:replace"] = parts.join(",");
    }

    return config;
  });
}

module.exports = withDisallowBackup;
