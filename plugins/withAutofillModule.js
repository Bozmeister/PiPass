const { withMainApplication } = require("@expo/config-plugins");

const PACKAGE_FQCN = "com.pipass.app.autofill.PiPassAutofillPackage";
const IMPORT_LINE = `import ${PACKAGE_FQCN}`;
const ADD_LINE = "add(PiPassAutofillPackage())";

/**
 * Patches MainApplication.kt to register PiPassAutofillPackage with React
 * Native's package list. Idempotent — re-running prebuild is safe.
 */
function withAutofillModule(config) {
  return withMainApplication(config, (config) => {
    let contents = config.modResults.contents;

    if (!contents.includes(IMPORT_LINE)) {
      // Insert our import after the last existing `import ` line.
      const lines = contents.split("\n");
      let lastImportIdx = -1;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("import ")) lastImportIdx = i;
      }
      if (lastImportIdx === -1) {
        throw new Error(
          "[withAutofillModule] No import lines found in MainApplication.kt"
        );
      }
      lines.splice(lastImportIdx + 1, 0, IMPORT_LINE);
      contents = lines.join("\n");
    }

    if (!contents.includes(ADD_LINE)) {
      // Insert add(...) inside the `apply { ... }` block of getPackages().
      // Match the comment line scaffolded by Expo and append our add() above
      // it so we sit before the trailing `}`.
      const marker =
        "// Packages that cannot be autolinked yet can be added manually here, for example:";
      if (contents.includes(marker)) {
        contents = contents.replace(
          marker,
          `add(${"PiPassAutofillPackage"}())\n              ${marker}`
        );
      } else {
        // Fallback: insert into the apply block for getPackages.
        contents = contents.replace(
          /PackageList\(this\)\.packages\.apply\s*\{/,
          `PackageList(this).packages.apply {\n              ${ADD_LINE}`
        );
      }
    }

    config.modResults.contents = contents;
    return config;
  });
}

module.exports = withAutofillModule;
