// Android Argon2 is the first-party modules/pipass-argon2 Gradle project
// (see plugins/withNativeArgon2.js). Disable Sphereon autolink on Android
// so it cannot register a second RNArgon2 / duplicate namespace.
// iOS still autolinks Sphereon; JS uses hash-wasm there (salt encoding).
module.exports = {
  dependencies: {
    "@sphereon/react-native-argon2": {
      platforms: {
        android: null,
      },
    },
  },
};
