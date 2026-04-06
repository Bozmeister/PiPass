const { withAndroidManifest, withDangerousMod, withAppBuildGradle } = require("@expo/config-plugins");
const path = require("path");
const fs = require("fs");

function withAutofillService(config) {
  config = withAutofillManifest(config);
  config = withAutofillResources(config);
  config = withAutofillKotlinSource(config);
  config = withAutofillDependencies(config);
  return config;
}

function withAutofillManifest(config) {
  return withAndroidManifest(config, (config) => {
    const manifest = config.modResults;
    const application = manifest.manifest.application[0];

    if (!application.service) {
      application.service = [];
    }

    const serviceExists = application.service.some(
      (s) =>
        s.$["android:name"] === "com.pipass.autofill.PiPassAutofillService"
    );

    if (!serviceExists) {
      application.service.push({
        $: {
          "android:name": "com.pipass.autofill.PiPassAutofillService",
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
    }

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
          '<?xml version="1.0" encoding="utf-8"?>\n<autofill-service xmlns:android="http://schemas.android.com/apk/res/android"\n    android:settingsActivity="" />\n'
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
        "com",
        "pipass",
        "autofill"
      );

      const destDir = path.join(
        platformRoot,
        "app",
        "src",
        "main",
        "java",
        "com",
        "pipass",
        "autofill"
      );

      if (sourceDir === destDir) return config;

      if (fs.existsSync(sourceDir)) {
        fs.mkdirSync(destDir, { recursive: true });

        const files = fs.readdirSync(sourceDir);
        for (const file of files) {
          if (file.endsWith(".kt") || file.endsWith(".java")) {
            fs.copyFileSync(
              path.join(sourceDir, file),
              path.join(destDir, file)
            );
          }
        }
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

module.exports = withAutofillService;
