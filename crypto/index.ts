export { getPiDigits, extractPiDigits, mapDigitsToCoordinates } from "./pi";
export type { PiCoordinates } from "./pi";
export {
  mandelbrotOrbit,
  compute3x3Grid,
  applyDeterministicJitter,
  computeFullPipeline,
  MAX_ITERATIONS,
} from "./mandelbrot";
export type { OrbitResult, GridPoint } from "./mandelbrot";
export { deriveClusterKey } from "./keyDerivation";
export { encryptData, decryptData } from "./encryption";
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
