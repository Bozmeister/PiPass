// Disable autolinking for @sphereon/react-native-argon2 on Android.
// We manually include it via plugins/withNativeArgon2 (settings.gradle + app/build.gradle + nuclear-patched build.gradle)
// to ensure the native argon2kt libs are packaged for arm64-v8a (Pixel reliability) with modern AGP/namespace fixes.
// Without this, autolinking + our manual include can cause duplicate module registration
// (leading to namespace 'com.poowf.argon2' used for 2 modules, or dep resolution failures on react-android in the subproject).
module.exports = {
  dependencies: {
    '@sphereon/react-native-argon2': {
      platforms: {
        android: null,
      },
    },
  },
};
