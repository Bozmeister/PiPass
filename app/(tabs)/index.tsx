//index.tsx

import React, { useState, useEffect } from "react";
import AuthScreen from "../../screens/AuthScreen";
import SeedSetupScreen from "../../screens/SeedSetupScreen";
import VaultScreen from "../../screens/VaultScreen";
import { 
  getPiSeed, 
  getSecurityProfile, 
  savePiSeed, 
  saveSecurityProfile 
} from "../../workers/storageWorker";

export default function HomeScreen() {
  const [authenticated, setAuthenticated] = useState(false);
  const [piSeed, setPiSeed] = useState<number | null>(null);
  const [iterations, setIterations] = useState<number>(25000);  // Default Balanced

  useEffect(() => {
    (async () => {
      const savedSeed = await getPiSeed();
      let savedProfile = await getSecurityProfile();
      
      if (savedSeed) setPiSeed(savedSeed);
      
      // Force positive iterations
      if (!savedProfile || savedProfile <= 0) {
        savedProfile = 25000;
        await saveSecurityProfile(savedProfile);
      }
      setIterations(savedProfile);
      
      console.log("HomeScreen loaded iterations:", savedProfile);
    })();
  }, []);

  if (!authenticated) {
    return <AuthScreen onAuthenticated={() => setAuthenticated(true)} />;
  }

  if (piSeed === null) {
    return (
      <SeedSetupScreen onSeedSet={async (seed, iters) => {
        let validIters = iters;
        if (!validIters || validIters <= 0) validIters = 25000;
        await savePiSeed(seed);
        await saveSecurityProfile(validIters);
        setPiSeed(seed);
        setIterations(validIters);
      }} />
    );
  }

  return (
    <VaultScreen
      piSeed={piSeed}
      iterations={iterations}
      onLock={() => setAuthenticated(false)}
      onIterationsChange={async (iters) => {
        let validIters = iters;
        if (!validIters || validIters <= 0) validIters = 25000;
        await saveSecurityProfile(validIters);
        setIterations(validIters);
      }}
      onReset={() => {
        setPiSeed(null);
        setAuthenticated(false);
      }}
    />
  );
}