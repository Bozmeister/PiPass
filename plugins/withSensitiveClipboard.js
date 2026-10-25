const { withDangerousMod } = require("@expo/config-plugins");
const fs = require("fs");
const path = require("path");

/**
 * Teach expo-clipboard to honor isSensitive / expirationMs on setStringAsync.
 *
 * Upstream 8.0.8 only accepts inputFormat. Without this patch, JS options
 * are dropped by the native Record and Android/iOS never see:
 *   - Android ClipDescription.EXTRA_IS_SENSITIVE (hides overlay preview)
 *   - iOS UIPasteboard localOnly + expirationDate (no Handoff; OS TTL)
 *
 * Idempotent. Re-applied on every prebuild against node_modules/expo-clipboard.
 */

const ANDROID_OPTIONS_REL =
  "node_modules/expo-clipboard/android/src/main/java/expo/modules/clipboard/ClipboardOptions.kt";
const ANDROID_MODULE_REL =
  "node_modules/expo-clipboard/android/src/main/java/expo/modules/clipboard/ClipboardModule.kt";
const IOS_OPTIONS_REL = "node_modules/expo-clipboard/ios/ClipboardOptions.swift";
const IOS_MODULE_REL = "node_modules/expo-clipboard/ios/ClipboardModule.swift";

const ANDROID_OPTIONS_FIELDS = [
  "  // --- PiPass sensitive clipboard ---",
  "  @Field",
  "  var isSensitive: Boolean = false",
  "",
  "  @Field",
  "  var expirationMs: Double = 0.0",
  "  // --- End PiPass sensitive clipboard ---",
].join("\n");

const ANDROID_SENSITIVE_MARK = [
  "      if (options.isSensitive) {",
  "        val extras = PersistableBundle()",
  "        extras.putBoolean(\"android.content.extra.IS_SENSITIVE\", true)",
  "        clip.description.extras = extras",
  "      }",
].join("\n");

const IOS_OPTIONS_FIELDS = [
  "  // --- PiPass sensitive clipboard ---",
  "  @Field",
  "  var isSensitive: Bool = false",
  "",
  "  @Field",
  "  var expirationMs: Double = 0",
  "  // --- End PiPass sensitive clipboard ---",
].join("\n");

const IOS_SET_STRING_ASYNC = [
  "    AsyncFunction(\"setStringAsync\") { (content: String?, options: SetStringOptions) -> Bool in",
  "      if options.isSensitive {",
  "        var pasteOptions: [UIPasteboard.OptionsKey: Any] = [",
  "          .localOnly: true",
  "        ]",
  "        if options.expirationMs > 0 {",
  "          pasteOptions[.expirationDate] = Date().addingTimeInterval(options.expirationMs / 1000.0)",
  "        }",
  "        let text = content ?? \"\"",
  "        let uti: String",
  "        switch options.inputFormat {",
  "        case .plainText:",
  "          uti = \"public.utf8-plain-text\"",
  "        case .html:",
  "          uti = \"public.html\"",
  "        }",
  "        UIPasteboard.general.setItems([[uti: text]], options: pasteOptions)",
  "      } else {",
  "        switch options.inputFormat {",
  "        case .plainText:",
  "          UIPasteboard.general.string = content",
  "        case .html:",
  "          UIPasteboard.general.html = content",
  "        }",
  "      }",
  "",
  "      return true",
  "    }",
].join("\n");

function patchAndroidOptions(src) {
  if (src.includes("var isSensitive: Boolean")) return src;
  const needle = [
    "internal class SetStringOptions : Record {",
    "  @Field",
    "  var inputFormat: StringFormat = StringFormat.PLAIN",
    "}",
  ].join("\n");
  if (!src.includes(needle)) {
    throw new Error("[withSensitiveClipboard] SetStringOptions block not found in ClipboardOptions.kt");
  }
  const replacement = [
    "internal class SetStringOptions : Record {",
    "  @Field",
    "  var inputFormat: StringFormat = StringFormat.PLAIN",
    "",
    ANDROID_OPTIONS_FIELDS,
    "}",
  ].join("\n");
  return src.replace(needle, replacement);
}

function patchAndroidModule(src) {
  let next = src;
  if (!next.includes("import android.os.PersistableBundle")) {
    if (!next.includes("import android.os.Build")) {
      throw new Error("[withSensitiveClipboard] android.os.Build import not found in ClipboardModule.kt");
    }
    next = next.replace(
      "import android.os.Build",
      "import android.os.Build\nimport android.os.PersistableBundle",
    );
  }
  if (next.includes("android.content.extra.IS_SENSITIVE")) return next;

  const needle = [
    "        }",
    "      }",
    "      clipboardManager.setPrimaryClip(clip)",
    "      return@AsyncFunction true",
    "    }",
  ].join("\n");
  if (!next.includes(needle)) {
    throw new Error("[withSensitiveClipboard] setStringAsync clip write not found in ClipboardModule.kt");
  }
  const replacement = [
    "        }",
    "      }",
    ANDROID_SENSITIVE_MARK,
    "      clipboardManager.setPrimaryClip(clip)",
    "      return@AsyncFunction true",
    "    }",
  ].join("\n");
  return next.replace(needle, replacement);
}

function patchIosOptions(src) {
  if (src.includes("var isSensitive: Bool")) return src;
  const needle = [
    "internal struct SetStringOptions: Record {",
    "  @Field",
    "  var inputFormat: StringFormat = .plainText",
    "}",
  ].join("\n");
  if (!src.includes(needle)) {
    throw new Error("[withSensitiveClipboard] SetStringOptions block not found in ClipboardOptions.swift");
  }
  const replacement = [
    "internal struct SetStringOptions: Record {",
    "  @Field",
    "  var inputFormat: StringFormat = .plainText",
    "",
    IOS_OPTIONS_FIELDS,
    "}",
  ].join("\n");
  return src.replace(needle, replacement);
}

function patchIosModule(src) {
  if (src.includes("UIPasteboard.OptionsKey") && src.includes("options.isSensitive")) {
    return src;
  }
  const needle = [
    "    AsyncFunction(\"setStringAsync\") { (content: String?, options: SetStringOptions) -> Bool in",
    "      switch options.inputFormat {",
    "      case .plainText:",
    "        UIPasteboard.general.string = content",
    "      case .html:",
    "        UIPasteboard.general.html = content",
    "      }",
    "",
    "      return true",
    "    }",
  ].join("\n");
  if (!src.includes(needle)) {
    throw new Error("[withSensitiveClipboard] setStringAsync block not found in ClipboardModule.swift");
  }
  return src.replace(needle, IOS_SET_STRING_ASYNC);
}

function writePatched(filePath, transform) {
  if (!fs.existsSync(filePath)) {
    console.warn("[withSensitiveClipboard] missing", filePath);
    return;
  }
  const original = fs.readFileSync(filePath, "utf8");
  const patched = transform(original);
  if (patched !== original) {
    fs.writeFileSync(filePath, patched);
  }
}

function applyAndroid(config) {
  const root = config.modRequest.projectRoot;
  writePatched(path.join(root, ANDROID_OPTIONS_REL), patchAndroidOptions);
  writePatched(path.join(root, ANDROID_MODULE_REL), patchAndroidModule);
  return config;
}

function applyIos(config) {
  const root = config.modRequest.projectRoot;
  writePatched(path.join(root, IOS_OPTIONS_REL), patchIosOptions);
  writePatched(path.join(root, IOS_MODULE_REL), patchIosModule);
  return config;
}

function withSensitiveClipboard(config) {
  config = withDangerousMod(config, ["android", applyAndroid]);
  config = withDangerousMod(config, ["ios", applyIos]);
  return config;
}

module.exports = withSensitiveClipboard;
module.exports.patchAndroidOptions = patchAndroidOptions;
module.exports.patchAndroidModule = patchAndroidModule;
module.exports.patchIosOptions = patchIosOptions;
module.exports.patchIosModule = patchIosModule;
