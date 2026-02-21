import * as LocalAuthentication from "expo-local-authentication";
import * as Device from "expo-device";
import { Platform } from "react-native";

const STALENESS_MS = 2000;

let lastBiometricTimestamp: number = 0;

export function isBiometricFresh(): boolean {
  return Date.now() - lastBiometricTimestamp < STALENESS_MS;
}

export function invalidateBiometric(): void {
  lastBiometricTimestamp = 0;
}

export async function requireFreshBiometric(): Promise<boolean> {
  if (Platform.OS === "web") {
    lastBiometricTimestamp = Date.now();
    return true;
  }

  if (!Device.isDevice) {
    lastBiometricTimestamp = Date.now();
    return true;
  }

  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  if (!hasHardware) {
    lastBiometricTimestamp = Date.now();
    return true;
  }

  const isEnrolled = await LocalAuthentication.isEnrolledAsync();
  if (!isEnrolled) {
    return false;
  }

  const result = await LocalAuthentication.authenticateAsync({
    promptMessage: "Authenticate to view password",
    fallbackLabel: "",
    disableDeviceFallback: false,
  });

  if (result.success) {
    lastBiometricTimestamp = Date.now();
    return true;
  }

  return false;
}

export async function biometricDecryptGuard<T>(
  operation: () => T
): Promise<T | null> {
  if (isBiometricFresh()) {
    const result = operation();
    return result;
  }

  const authenticated = await requireFreshBiometric();
  if (!authenticated) {
    return null;
  }

  if (!isBiometricFresh()) {
    return null;
  }

  const result = operation();
  invalidateBiometric();
  return result;
}
