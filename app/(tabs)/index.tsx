import React, { useState, useEffect } from "react";
import { View, ActivityIndicator } from "react-native";
import AuthScreen from "../../screens/AuthScreen";
import SeedSetupScreen from "../../screens/SeedSetupScreen";
import VaultScreen from "../../screens/VaultScreen";
import { getPiSeed, savePiSeed } from "../../workers/storageWorker";

export default function HomeScreen() {
  const [authenticated, setAuthenticated] = useState(false);
  const [piSeed, setPiSeed] = useState<number | null>(null);
  const [checkingSeed, setCheckingSeed] = useState(true);

  useEffect(() => {
    loadSeed();
  }, []);

  async function loadSeed() {
    const saved = await getPiSeed();
    setPiSeed(saved);
    setCheckingSeed(false);
  }

  async function handleSeedSet(seed: number) {
    await savePiSeed(seed);
    setPiSeed(seed);
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

  return <VaultScreen piSeed={piSeed} onLock={handleLock} />;
}
