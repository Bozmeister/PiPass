import React, { useState, useEffect } from "react";
import { View, Text, Pressable } from "react-native";
import * as LocalAuthentication from "expo-local-authentication";
import { Ionicons } from "@expo/vector-icons";
import PipassLoader from "../components/PipassLoader";
import {
  getDeviceAuthenticationStatus,
  type DeviceAuthenticationStatus,
} from "../crypto/biometricGate";

interface AuthScreenProps {
  onAuthenticated: () => void;
}

export default function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const [biometricType, setBiometricType] = useState<string>("Device authentication");
  const [canUseDevBypass, setCanUseDevBypass] = useState(false);
  // T006 — show the boot loader on first mount; the loader sits on
  // top of the live AuthScreen and crossfades out, so biometric prompt
  // wiring continues underneath without delay.
  const [loaderDone, setLoaderDone] = useState(false);

  useEffect(() => {
    checkBiometricSupport().catch(() => {
      setError("Failed to check biometric support. Tap to retry.");
      setChecking(false);
    });
  }, []);

  async function checkBiometricSupport() {
    setChecking(true);
    setCanUseDevBypass(false);

    const status = await getDeviceAuthenticationStatus();
    if (!status.available) {
      setError(messageForUnavailableAuth(status));
      setCanUseDevBypass(status.canUseDevBypass);
      setChecking(false);
      return;
    }

    if (status.supportedTypes.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION)) {
      setBiometricType("Face ID");
    } else if (status.supportedTypes.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)) {
      setBiometricType("Fingerprint");
    } else {
      setBiometricType("Device passcode");
    }

    setChecking(false);
    await authenticate();
  }

  async function authenticate() {
    const status = await getDeviceAuthenticationStatus();
    if (!status.available) {
      if (status.canUseDevBypass) {
        // Development-only convenience for Expo web, simulators, and CI.
        // Production builds fail closed here and never call onAuthenticated.
        setCanUseDevBypass(true);
        setError(messageForUnavailableAuth(status));
        return;
      }
      setCanUseDevBypass(false);
      setError(messageForUnavailableAuth(status));
      return;
    }

    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: status.hasBiometricHardware
          ? "Use biometrics or passcode to unlock PiPass"
          : "Use your device passcode to unlock PiPass",
        disableDeviceFallback: false,
        fallbackLabel: "Use Passcode",
      });

      if (result.success) {
        onAuthenticated();
      } else {
        if (result.error === "user_cancel") {
          setError("Authentication cancelled. Tap to try again.");
        } else {
          setError("Authentication failed. Tap to try again.");
        }
      }
    } catch (err) {
      setError("Authentication error. Tap to try again.");
    }
  }

  function handleDevBypass() {
    // This is intentionally limited to development builds. It keeps local
    // Expo web/simulator testing usable without creating a production bypass.
    if (__DEV__ && canUseDevBypass) {
      onAuthenticated();
    }
  }

  function handleRetry() {
    setError(null);
    if (canUseDevBypass) {
      handleDevBypass();
      return;
    }
    void authenticate();
  }

  function messageForUnavailableAuth(
    status: Extract<DeviceAuthenticationStatus, { available: false }>,
  ): string {
    const devSuffix = status.canUseDevBypass
      ? " Tap to bypass for local development only."
      : "";

    if (status.reason === "web") {
      return `PiPass requires device authentication. Web unlock is unavailable in production.${devSuffix}`;
    }
    if (status.reason === "not-physical-device") {
      return `PiPass requires a physical device with secure local authentication.${devSuffix}`;
    }
    if (status.reason === "not-enrolled") {
      return `Set up a device passcode, Face ID, or fingerprint before unlocking PiPass.${devSuffix}`;
    }
    return `PiPass could not verify secure local authentication. Restart the app and try again.${devSuffix}`;
  }

  // The loader sits on TOP of whatever auth UI is appropriate. While
  // it crossfades out the underlying screen is already mounted —
  // biometric checks have started and any error is already visible
  // the moment the loader clears.
  const baseScreen = checking ? (
    <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
      <Text style={{ color: "#fff", fontSize: 16 }}>Checking biometric support...</Text>
    </View>
  ) : (
    <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000", padding: 24 }}>
      <Ionicons name="lock-closed" size={64} color="#fff" />
      <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold", marginTop: 24 }}>PiPass</Text>
      <Text style={{ color: "#aaa", fontSize: 14, marginTop: 8, textAlign: "center" }}>
        {biometricType} required to access vault
      </Text>

      {error && (
        <Text style={{ color: "#ff6b6b", fontSize: 14, marginTop: 16, textAlign: "center" }}>
          {error}
        </Text>
      )}

      <Pressable
        onPress={handleRetry}
        style={{ marginTop: 32, paddingVertical: 14, paddingHorizontal: 32, backgroundColor: "#333", borderRadius: 8 }}
      >
        <Text style={{ color: "#fff", fontSize: 16 }}>
          {canUseDevBypass ? "Bypass for Local Development" : error ? "Try Again" : `Authenticate with ${biometricType}`}
        </Text>
      </Pressable>
    </View>
  );

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      {baseScreen}
      {!loaderDone && <PipassLoader onComplete={() => setLoaderDone(true)} />}
    </View>
  );
}
