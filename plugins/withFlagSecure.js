const { withAppBuildGradle, withMainActivity } = require("@expo/config-plugins");

const MARKER_START = "// --- PiPass FLAG_SECURE ---";
const MARKER_END = "// --- End PiPass FLAG_SECURE ---";

function withFlagSecure(config) {
  config = withFlagSecureBuildConfig(config);
  config = withFlagSecureMainActivity(config);
  return config;
}

function findBuildTypesBlock(contents) {
  const match = /\bbuildTypes\s*\{/.exec(contents);
  if (!match) return null;

  const openIdx = match.index + match[0].length;
  let depth = 1;
  for (let i = openIdx; i < contents.length; i++) {
    if (contents[i] === "{") depth++;
    if (contents[i] === "}") depth--;
    if (depth === 0) {
      return { start: match.index, end: i + 1, body: contents.slice(match.index, i + 1) };
    }
  }
  return null;
}

function findNamedBlock(blockBody, name) {
  const regex = new RegExp(`\\b${name}\\s*\\{`);
  const match = regex.exec(blockBody);
  if (!match) return null;

  const openIdx = match.index + match[0].length;
  let depth = 1;
  for (let i = openIdx; i < blockBody.length; i++) {
    if (blockBody[i] === "{") depth++;
    if (blockBody[i] === "}") depth--;
    if (depth === 0) {
      return {
        start: match.index,
        contentStart: openIdx,
        end: i + 1,
        body: blockBody.slice(match.index, i + 1),
      };
    }
  }
  return null;
}

function enforceFieldInBlock(btBody, blockName, requiredValue, pattern, indent) {
  const block = findNamedBlock(btBody, blockName);
  if (!block) return btBody;

  const field = `buildConfigField "boolean", "ALLOW_SCREENSHOTS", "${requiredValue}"`;
  const match = pattern.exec(block.body);

  if (match) {
    if (match[1] !== requiredValue) {
      const wrongField = match[0];
      const blockStart = block.start;
      const wrongIdx = btBody.indexOf(wrongField, blockStart);
      if (wrongIdx !== -1) {
        btBody =
          btBody.slice(0, wrongIdx) + field + btBody.slice(wrongIdx + wrongField.length);
      }
    }
  } else {
    btBody =
      btBody.slice(0, block.contentStart) +
      `\n${indent}${field}` +
      btBody.slice(block.contentStart);
  }

  return btBody;
}

function withFlagSecureBuildConfig(config) {
  return withAppBuildGradle(config, (config) => {
    let contents = config.modResults.contents;

    const btBlock = findBuildTypesBlock(contents);
    if (!btBlock) {
      throw new Error("[withFlagSecure] buildTypes block not found in build.gradle");
    }

    let btBody = btBlock.body;

    const indent = "            ";
    const allowScreenshotsPattern = /buildConfigField\s+"boolean"\s*,\s*"ALLOW_SCREENSHOTS"\s*,\s*"(true|false)"/;

    btBody = enforceFieldInBlock(btBody, "debug", "true", allowScreenshotsPattern, indent);
    btBody = enforceFieldInBlock(btBody, "release", "false", allowScreenshotsPattern, indent);

    contents =
      contents.slice(0, btBlock.start) + btBody + contents.slice(btBlock.end);

    config.modResults.contents = contents;
    return config;
  });
}

function withFlagSecureMainActivity(config) {
  return withMainActivity(config, (config) => {
    let contents = config.modResults.contents;

    if (contents.includes(MARKER_START)) {
      return config;
    }

    const importLine = "import android.view.WindowManager";
    if (!contents.includes(importLine)) {
      contents = contents.replace(
        /^(package .+)$/m,
        `$1\n\n${importLine}`
      );
    }

    const flagSecureSnippet = [
      `        ${MARKER_START}`,
      "        if (!BuildConfig.ALLOW_SCREENSHOTS) {",
      "            window.setFlags(",
      "                WindowManager.LayoutParams.FLAG_SECURE,",
      "                WindowManager.LayoutParams.FLAG_SECURE",
      "            )",
      "        }",
      `        ${MARKER_END}`,
    ].join("\n");

    let inserted = false;

    const hasOnCreate = /override\s+fun\s+onCreate\s*\(/.test(contents);

    if (hasOnCreate) {
      const superPattern = /(super\.onCreate\s*\([^)]*\))/;
      if (superPattern.test(contents)) {
        contents = contents.replace(superPattern, `$1\n${flagSecureSnippet}`);
        inserted = true;
      } else {
        contents = contents.replace(
          /(override\s+fun\s+onCreate\s*\([^)]*\)\s*\{)/,
          `$1\n${flagSecureSnippet}`
        );
        inserted = true;
      }
    }

    if (!inserted) {
      const onCreateBlock = [
        "",
        "    override fun onCreate(savedInstanceState: android.os.Bundle?) {",
        "        super.onCreate(savedInstanceState)",
        flagSecureSnippet,
        "    }",
      ].join("\n");

      contents = contents.replace(
        /(class\s+MainActivity[^{]*\{)/,
        `$1${onCreateBlock}`
      );
    }

    config.modResults.contents = contents;
    return config;
  });
}

module.exports = withFlagSecure;
