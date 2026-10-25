// template
import "react-native-get-random-values";
import { QueryClientProvider } from "@tanstack/react-query";
import { Stack } from "expo-router";
import * as SplashScreen from "expo-splash-screen";
import React, { useEffect } from "react";
import { Platform } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { KeyboardProvider } from "react-native-keyboard-controller";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { queryClient } from "@/lib/query-client";
import { SecurityProvider } from "@/context/SecurityContext";
import { useScreenCaptureProtection } from "@/lib/screenCaptureProtection";
import { purgeLegacyWebVaultStorage } from "@/lib/webVaultPolicy";
import WebVaultDisabledScreen from "@/screens/WebVaultDisabledScreen";

// Prevent the splash screen from auto-hiding before asset loading is complete.
SplashScreen.preventAutoHideAsync();

function RootLayoutNav() {
  return (
    <Stack screenOptions={{ headerBackTitle: "Back" }}>
      <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
      <Stack.Screen name="debug" options={{ headerShown: false }} />
    </Stack>
  );
}

function WebAppDisabledRoot() {
  useEffect(() => {
    purgeLegacyWebVaultStorage();
    SplashScreen.hideAsync();
  }, []);

  return (
    <ErrorBoundary>
      <SafeAreaProvider>
        <WebVaultDisabledScreen />
      </SafeAreaProvider>
    </ErrorBoundary>
  );
}

function NativeRootLayout() {
  // Block screenshots/recording for unlock, setup, vault, notes, settings (native production).
  useScreenCaptureProtection();

  useEffect(() => {
    SplashScreen.hideAsync();
  }, []);

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <SecurityProvider>
          <GestureHandlerRootView>
            <KeyboardProvider>
              <RootLayoutNav />
            </KeyboardProvider>
          </GestureHandlerRootView>
        </SecurityProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default function RootLayout() {
  if (Platform.OS === "web") {
    return <WebAppDisabledRoot />;
  }
  return <NativeRootLayout />;
}
