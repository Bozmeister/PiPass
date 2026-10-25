/**
 * JS does not call this entry. Vault KDF uses NativeModules.RNArgon2
 * (see crypto/nativeArgon2.ts). This file exists so Expo / RN autolinking
 * has a valid `main`.
 */
module.exports = null;
