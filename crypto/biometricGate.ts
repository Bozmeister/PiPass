import * as LocalAuthentication from "expo-local-authentication";
import * as Device from "expo-device";
import { Platform } from "react-native";

const STALENESS_MS = 2000;

let lastBiometricTimestamp: number = 0;

export type DeviceAuthenticationUnavailableReason =
  | "web"
  | "not-physical-device"
  | "not-enrolled"
  | "probe-failed";

export type DeviceAuthenticationStatus =
  | {
      available: true;
      enrolledLevel: LocalAuthentication.SecurityLevel;
      hasBiometricHardware: boolean;
      supportedTypes: LocalAuthentication.AuthenticationType[];
    }
  | {
      available: false;
      reason: DeviceAuthenticationUnavailableReason;
      canUseDevBypass: boolean;
    };

export async function getDeviceAuthenticationStatus(): Promise<DeviceAuthenticationStatus> {
  if (Platform.OS === "web") {
    return { available: false, reason: "web", canUseDevBypass: __DEV__ };
  }

  if (!Device.isDevice) {
    return {
      available: false,
      reason: "not-physical-device",
      canUseDevBypass: __DEV__,
    };
  }

  try {
    const [enrolledLevel, hasBiometricHardware, supportedTypes] = await Promise.all([
      LocalAuthentication.getEnrolledLevelAsync(),
      LocalAuthentication.hasHardwareAsync(),
      LocalAuthentication.supportedAuthenticationTypesAsync(),
    ]);

    if (enrolledLevel < LocalAuthentication.SecurityLevel.SECRET) {
      return {
        available: false,
        reason: "not-enrolled",
        canUseDevBypass: __DEV__,
      };
    }

    return {
      available: true,
      enrolledLevel,
      hasBiometricHardware,
      supportedTypes,
    };
  } catch {
    return {
      available: false,
      reason: "probe-failed",
      canUseDevBypass: __DEV__,
    };
  }
}

function markDevAuthenticationBypass(): boolean {
  // Development-only convenience for Expo web, simulators, and CI where
  // platform device authentication cannot be shown. Production must never
  // reach this branch because it would silently mark auth as fresh.
  if (!__DEV__) return false;
  lastBiometricTimestamp = Date.now();
  return true;
}

export function isBiometricFresh(): boolean {
  return Date.now() - lastBiometricTimestamp < STALENESS_MS;
}

export function invalidateBiometric(): void {
  lastBiometricTimestamp = 0;
}

export async function requireFreshBiometric(): Promise<boolean> {
  const status = await getDeviceAuthenticationStatus();
  if (!status.available) {
    return status.canUseDevBypass ? markDevAuthenticationBypass() : false;
  }

  try {
    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: status.hasBiometricHardware
        ? "Authenticate to view password"
        : "Authenticate with your device passcode",
      disableDeviceFallback: false,
      fallbackLabel: "Use Passcode",
    });

    if (result.success) {
      lastBiometricTimestamp = Date.now();
      return true;
    }

    return false;
  } catch (err) {
    return false;
  }
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
