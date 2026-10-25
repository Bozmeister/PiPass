// Android-only RN library. iOS stays on hash-wasm (see crypto/keyDerivation.ts).
module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: "./android",
        packageImportPath: "import com.pipass.argon2.PipassArgon2Package;",
        packageInstance: "new PipassArgon2Package()",
      },
      ios: null,
    },
  },
};
