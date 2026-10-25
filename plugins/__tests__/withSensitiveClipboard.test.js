/**
 * expo-clipboard native sensitive-flag patch (P11).
 */
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  patchAndroidOptions,
  patchAndroidModule,
  patchIosOptions,
  patchIosModule,
} = require("../withSensitiveClipboard");

const ANDROID_OPTIONS = `internal class SetStringOptions : Record {
  @Field
  var inputFormat: StringFormat = StringFormat.PLAIN
}
`;

const ANDROID_MODULE = `import android.os.Build
import android.util.Log

    AsyncFunction("setStringAsync") { content: String, options: SetStringOptions ->
      val clip = when (options.inputFormat) {
        StringFormat.PLAIN -> ClipData.newPlainText(null, content)
        StringFormat.HTML -> {
          // HTML clip requires complementary plain text content
          val plainText = plainTextFromHtml(content)
          ClipData.newHtmlText(null, plainText, content)
        }
      }
      clipboardManager.setPrimaryClip(clip)
      return@AsyncFunction true
    }
`;

const IOS_OPTIONS = `internal struct SetStringOptions: Record {
  @Field
  var inputFormat: StringFormat = .plainText
}
`;

const IOS_MODULE = `    AsyncFunction("setStringAsync") { (content: String?, options: SetStringOptions) -> Bool in
      switch options.inputFormat {
      case .plainText:
        UIPasteboard.general.string = content
      case .html:
        UIPasteboard.general.html = content
      }

      return true
    }
`;

test("Android SetStringOptions gains isSensitive and expirationMs", () => {
  const patched = patchAndroidOptions(ANDROID_OPTIONS);
  assert.match(patched, /var isSensitive: Boolean = false/);
  assert.match(patched, /var expirationMs: Double = 0\.0/);
  assert.equal(patchAndroidOptions(patched), patched);
});

test("Android setStringAsync marks ClipDescription EXTRA_IS_SENSITIVE", () => {
  const patched = patchAndroidModule(ANDROID_MODULE);
  assert.match(patched, /import android\.os\.PersistableBundle/);
  assert.match(patched, /android\.content\.extra\.IS_SENSITIVE/);
  assert.match(patched, /if \(options\.isSensitive\)/);
  assert.equal(patchAndroidModule(patched), patched);
});

test("iOS SetStringOptions gains isSensitive and expirationMs", () => {
  const patched = patchIosOptions(IOS_OPTIONS);
  assert.match(patched, /var isSensitive: Bool = false/);
  assert.match(patched, /var expirationMs: Double = 0/);
  assert.equal(patchIosOptions(patched), patched);
});

test("iOS setStringAsync uses localOnly and expirationDate when sensitive", () => {
  const patched = patchIosModule(IOS_MODULE);
  assert.match(patched, /options\.isSensitive/);
  assert.match(patched, /\.localOnly: true/);
  assert.match(patched, /\.expirationDate/);
  assert.match(patched, /UIPasteboard\.general\.string = content/);
  assert.equal(patchIosModule(patched), patched);
});
