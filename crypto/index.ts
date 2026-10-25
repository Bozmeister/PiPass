export { deriveMasterKey, generateMasterSalt, hashMasterKey } from "./keyDerivation";
export { createVaultKeyProof, isWellFormedVaultKeyProof } from "./vaultKeyProof";
export {
  encryptData,
  decryptData,
  canonicalizeFieldAad,
  isAuthenticatedCiphertext,
  isLegacyUnsupportedCiphertext,
  isLegacyUnauthenticatedCiphertext,
  CiphertextFormatError,
} from "./encryption";
export type { FieldAad, VaultCipherField } from "./encryption";
export {
  deriveSubkey,
  deriveEntryKey,
  deriveAesGcmKey,
  generateSaltHex,
} from "./hkdf";
export {
  ITEM_WRAP_HKDF_INFO,
  ITEM_KEY_FIELD,
  INTENTDB_ENVELOPE_ENV,
  intentdbEnvelopeEnabled,
  envelopeMigrationAllowed,
  recordHasWrappedItemKey,
  deriveItemWrapKey,
  generateItemKeyHex,
  wrapItemKey,
  unwrapItemKey,
  resolveFieldKey,
  rewrapItemKey,
} from "./itemEnvelope";
export type { EnvelopeRecord, EnvelopeMigrationOptions } from "./itemEnvelope";
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
