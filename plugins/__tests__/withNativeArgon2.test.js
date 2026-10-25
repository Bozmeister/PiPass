/**
 * First-party Argon2 module + plugin: no node_modules mutation.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../..");
const pluginPath = path.join(root, "plugins/withNativeArgon2.js");
const pluginSrc = fs.readFileSync(pluginPath, "utf8");

test("local module has a package.json Expo autolinking can read", () => {
  const pkgPath = path.join(root, "modules/pipass-argon2/package.json");
  assert.ok(fs.existsSync(pkgPath));
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  assert.equal(pkg.name, "pipass-argon2");
  assert.equal(pkg.private, true);
  assert.equal(pkg.main, "index.js");
  assert.ok(fs.existsSync(path.join(root, "modules/pipass-argon2/index.js")));
  assert.ok(
    fs.existsSync(path.join(root, "modules/pipass-argon2/react-native.config.js")),
  );
});

test("vendors a first-party Android Argon2 module", () => {
  const moduleDir = path.join(root, "modules/pipass-argon2/android");
  assert.ok(fs.existsSync(path.join(moduleDir, "build.gradle")));
  assert.ok(
    fs.existsSync(
      path.join(
        moduleDir,
        "src/main/java/com/pipass/argon2/PipassArgon2Module.java",
      ),
    ),
  );
  assert.ok(
    fs.existsSync(
      path.join(
        moduleDir,
        "src/main/java/com/pipass/argon2/PipassArgon2Package.java",
      ),
    ),
  );
  const gradle = fs.readFileSync(path.join(moduleDir, "build.gradle"), "utf8");
  assert.match(gradle, /argon2kt:1\.3\.0/);
  assert.match(gradle, /namespace "com\.pipass\.argon2"/);
});

test("native module rejects non-64-char salt hex (no pad/truncate)", () => {
  const java = fs.readFileSync(
    path.join(
      root,
      "modules/pipass-argon2/android/src/main/java/com/pipass/argon2/PipassArgon2Module.java",
    ),
    "utf8",
  );
  assert.match(java, /\[0-9a-f\]\{64\}/);
  assert.equal(java.includes("BigInteger"), false);
  assert.equal(java.includes("arraycopy"), false);
  assert.match(java, /getName\(\)[\s\S]*return "RNArgon2"/);
});

test("plugin does not overwrite Sphereon files in node_modules", () => {
  assert.equal(pluginSrc.includes("node_modules/@sphereon/react-native-argon2/index.js"), false);
  assert.equal(
    pluginSrc.includes("node_modules/@sphereon/react-native-argon2/android/build.gradle"),
    false,
  );
  assert.equal(pluginSrc.includes("plugins/native-patches/RNArgon2Module.java"), false);
  assert.match(pluginSrc, /modules\/pipass-argon2\/android/);
  assert.match(pluginSrc, /PipassArgon2Package/);
});

test("Android autolink stays disabled for Sphereon", () => {
  const rnConfig = fs.readFileSync(
    path.join(root, "react-native.config.js"),
    "utf8",
  );
  assert.match(rnConfig, /@sphereon\/react-native-argon2/);
  assert.match(rnConfig, /android:\s*null/);
});
