import React, { useState, useEffect } from "react";
import { View, ActivityIndicator } from "react-native";
import AuthScreen from "../../screens/AuthScreen";
import SeedSetupScreen from "../../screens/SeedSetupScreen";
import VaultScreen from "../../screens/VaultScreen";
import { getPiSeed, savePiSeed, getSecurityProfile, saveSecurityProfile } from "../../workers/storageWorker";

export default function HomeScreen() {
  const [authenticated, setAuthenticated] = useState(false);
  const [piSeed, setPiSeed] = useState<number | null>(null);
  const [iterations, setIterations] = useState<number>(100000);
  const [checkingSeed, setCheckingSeed] = useState(true);

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    const [saved, profile] = await Promise.all([getPiSeed(), getSecurityProfile()]);
    setPiSeed(saved);
    setIterations(profile);
    setCheckingSeed(false);
  }

  async function handleSeedSet(seed: number, iters: number) {
    await Promise.all([savePiSeed(seed), saveSecurityProfile(iters)]);
    setPiSeed(seed);
    setIterations(iters);
  }

  async function handleIterationsChange(iters: number) {
    await saveSecurityProfile(iters);
    setIterations(iters);
  }

  function handleLock() {
    setAuthenticated(false);
  }

  if (checkingSeed) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <ActivityIndicator size="large" color="#fff" />
      </View>
    );
  }

  if (!authenticated) {
    return <AuthScreen onAuthenticated={() => setAuthenticated(true)} />;
  }

  if (piSeed === null) {
    return <SeedSetupScreen onSeedSet={handleSeedSet} />;
  }

  return (
    <VaultScreen
      piSeed={piSeed}
      iterations={iterations}
      onLock={handleLock}
      onIterationsChange={handleIterationsChange}
    />
  );
}
