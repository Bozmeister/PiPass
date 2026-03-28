export { deriveMasterKey, generateMasterSalt, hashMasterKey } from "./keyDerivation";
export { encryptData, decryptData } from "./encryption";
export { deriveSubkey, deriveEntryKey, generateSaltHex } from "./hkdf";
export {
  wipeBuffer,
  stringToBytes,
  bytesToString,
  hexToBytes,
  bytesToHex,
  generateRandomBytes,
  xorBytes,
  splitKeyIntoShares,
  combineShares,
  wipeShares,
  useKeyBriefly,
} from "./secureMemory";
export type { KeyShares } from "./secureMemory";
export {
  requireFreshBiometric,
  isBiometricFresh,
  invalidateBiometric,
  biometricDecryptGuard,
} from "./biometricGate";
export {
  runIntegrityCheck,
  startPeriodicGuard,
  stopPeriodicGuard,
  setTamperCallback,
  detectDebugger,
  detectEmulator,
  cryptoSelfTest,
} from "./integrityGuard";
export type { IntegrityReport, TamperReason } from "./integrityGuard";
