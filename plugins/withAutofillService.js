const { withAndroidManifest, withDangerousMod, withAppBuildGradle } = require("@expo/config-plugins");
const path = require("path");
const fs = require("fs");

const AUTOFILL_PACKAGE = "com.pipass.autofill";
const AUTOFILL_SERVICE_CLASS = "PiPassAutofillService";
const AUTOFILL_FQCN = `${AUTOFILL_PACKAGE}.${AUTOFILL_SERVICE_CLASS}`;
const AUTOFILL_PACKAGE_PATH = AUTOFILL_PACKAGE.replace(/\./g, path.sep);

function withAutofillService(config) {
  config = withAutofillManifest(config);
  config = withAutofillResources(config);
  config = withAutofillKotlinSource(config);
  config = withAutofillDependencies(config);
  config = withAutofillProguardRules(config);
  return config;
}

function withAutofillManifest(config) {
  return withAndroidManifest(config, (config) => {
    const manifest = config.modResults;
    const application = manifest.manifest.application[0];

    if (!application.service) {
      application.service = [];
    }

    const existingIndex = application.service.findIndex(
      (s) => s.$["android:name"] === AUTOFILL_FQCN
    );

    if (existingIndex !== -1) {
      application.service.splice(existingIndex, 1);
    }

    application.service.push({
      $: {
        "android:name": AUTOFILL_FQCN,
        "android:label": "PiPass Autofill",
        "android:exported": "true",
        "android:permission": "android.permission.BIND_AUTOFILL_SERVICE",
      },
      "intent-filter": [
        {
          action: [
            {
              $: {
                "android:name": "android.service.autofill.AutofillService",
              },
            },
          ],
        },
      ],
      "meta-data": [
        {
          $: {
            "android:name": "android.autofill",
            "android:resource": "@xml/autofill_service_config",
          },
        },
      ],
    });

    return config;
  });
}

function withAutofillResources(config) {
  return withDangerousMod(config, [
    "android",
    async (config) => {
      const projectRoot = config.modRequest.projectRoot;
      const resXmlDir = path.join(
        config.modRequest.platformProjectRoot,
        "app",
        "src",
        "main",
        "res",
        "xml"
      );

      fs.mkdirSync(resXmlDir, { recursive: true });

      const sourceXml = path.join(
        projectRoot,
        "android",
        "app",
        "src",
        "main",
        "res",
        "xml",
        "autofill_service_config.xml"
      );

      const destXml = path.join(resXmlDir, "autofill_service_config.xml");

      if (fs.existsSync(sourceXml) && sourceXml !== destXml) {
        fs.copyFileSync(sourceXml, destXml);
      } else if (!fs.existsSync(destXml)) {
        fs.writeFileSync(
          destXml,
          '<?xml version="1.0" encoding="utf-8"?>\n<autofill-service xmlns:android="http://schemas.android.com/apk/res/android"\n    android:settingsActivity=""\n    android:supportsInlineSuggestions="true" />\n'
        );
      }

      return config;
    },
  ]);
}

function withAutofillKotlinSource(config) {
  return withDangerousMod(config, [
    "android",
    async (config) => {
      const projectRoot = config.modRequest.projectRoot;
      const platformRoot = config.modRequest.platformProjectRoot;

      const sourceDir = path.join(
        projectRoot,
        "android",
        "app",
        "src",
        "main",
        "java",
        AUTOFILL_PACKAGE_PATH
      );

      const destDir = path.join(
        platformRoot,
        "app",
        "src",
        "main",
        "java",
        AUTOFILL_PACKAGE_PATH
      );

      if (sourceDir === destDir) return config;

      if (!fs.existsSync(sourceDir)) {
        throw new Error(
          `[withAutofillService] Kotlin source directory not found: ${sourceDir}`
        );
      }

      const files = fs.readdirSync(sourceDir).filter(
        (f) => f.endsWith(".kt") || f.endsWith(".java")
      );

      if (files.length === 0) {
        throw new Error(
          `[withAutofillService] No Kotlin/Java files found in: ${sourceDir}`
        );
      }

      const hasService = files.some((f) => f === `${AUTOFILL_SERVICE_CLASS}.kt`);
      if (!hasService) {
        throw new Error(
          `[withAutofillService] ${AUTOFILL_SERVICE_CLASS}.kt not found in: ${sourceDir}`
        );
      }

      fs.mkdirSync(destDir, { recursive: true });

      for (const file of files) {
        fs.copyFileSync(
          path.join(sourceDir, file),
          path.join(destDir, file)
        );
      }

      return config;
    },
  ]);
}

function withAutofillDependencies(config) {
  return withAppBuildGradle(config, (config) => {
    const deps = [
      "implementation 'androidx.biometric:biometric:1.1.0'",
      "implementation 'androidx.security:security-crypto:1.1.0-alpha06'",
    ];

    let contents = config.modResults.contents;

    for (const dep of deps) {
      if (!contents.includes(dep)) {
        contents = contents.replace(
          /dependencies\s*\{/,
          `dependencies {\n    ${dep}`
        );
      }
    }

    config.modResults.contents = contents;
    return config;
  });
}

function withAutofillProguardRules(config) {
  return withDangerousMod(config, [
    "android",
    async (config) => {
      const proguardPath = path.join(
        config.modRequest.platformProjectRoot,
        "app",
        "proguard-rules.pro"
      );

      const marker = "# --- PiPass Autofill Service ---";

      const rules = [
        marker,
        `-keep class ${AUTOFILL_FQCN} { *; }`,
        `-keep class ${AUTOFILL_PACKAGE}.CryptoHelper { *; }`,
        `-keepclassmembers class ${AUTOFILL_FQCN} {`,
        "    public void onFillRequest(...);",
        "    public void onSaveRequest(...);",
        "}",
        "# --- End PiPass Autofill ---",
        "",
      ].join("\n");

      let existing = "";
      if (fs.existsSync(proguardPath)) {
        existing = fs.readFileSync(proguardPath, "utf8");
      }

      if (!existing.includes(marker)) {
        fs.writeFileSync(proguardPath, existing + "\n" + rules);
      }

      return config;
    },
  ]);
}

module.exports = withAutofillService;
