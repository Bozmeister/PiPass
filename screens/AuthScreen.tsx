import React, { useState, useEffect } from "react";
import { View, Text, Pressable, Platform } from "react-native";
import * as LocalAuthentication from "expo-local-authentication";
import * as Device from "expo-device";
import { Ionicons } from "@expo/vector-icons";

interface AuthScreenProps {
  onAuthenticated: () => void;
}

export default function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const [biometricType, setBiometricType] = useState<string>("Biometric");

  useEffect(() => {
    checkBiometricSupport();
  }, []);

  async function checkBiometricSupport() {
    setChecking(true);

    if (Platform.OS === "web") {
      setError("Biometric authentication is not available on web. Tap to bypass for testing.");
      setChecking(false);
      return;
    }

    const isDevice = Device.isDevice;
    if (!isDevice) {
      setError("Biometric authentication requires a physical device. Tap to bypass for testing.");
      setChecking(false);
      return;
    }

    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    if (!hasHardware) {
      setError("No biometric hardware found. Tap to bypass for testing.");
      setChecking(false);
      return;
    }

    const isEnrolled = await LocalAuthentication.isEnrolledAsync();
    if (!isEnrolled) {
      setError("No biometrics enrolled on this device. Please set up Face ID or fingerprint in Settings.");
      setChecking(false);
      return;
    }

    const supportedTypes = await LocalAuthentication.supportedAuthenticationTypesAsync();
    if (supportedTypes.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION)) {
      setBiometricType("Face ID");
    } else if (supportedTypes.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)) {
      setBiometricType("Fingerprint");
    }

    setChecking(false);
    authenticate();
  }

  async function authenticate() {
    if (Platform.OS === "web") {
      onAuthenticated();
      return;
    }

    try {
      const hasHardware = await LocalAuthentication.hasHardwareAsync();
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: hasHardware
          ? "Use biometrics to unlock PiPass"
          : "Authenticate to access PiPass vault",
        fallbackLabel: "",
        disableDeviceFallback: false,
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

  function handleRetry() {
    setError(null);
    if (Platform.OS === "web" || !Device.isDevice) {
      onAuthenticated();
      return;
    }
    authenticate();
  }

  if (checking) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <Text style={{ color: "#fff", fontSize: 16 }}>Checking biometric support...</Text>
      </View>
    );
  }

  return (
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
          {error ? "Try Again" : `Authenticate with ${biometricType}`}
        </Text>
      </Pressable>
    </View>
  );
}
