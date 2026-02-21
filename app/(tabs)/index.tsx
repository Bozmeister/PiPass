import React, { useState } from "react";
import AuthScreen from "../../screens/AuthScreen";
import VaultScreen from "../../screens/VaultScreen";

export default function HomeScreen() {
  const [authenticated, setAuthenticated] = useState(false);

  if (!authenticated) {
    return <AuthScreen onAuthenticated={() => setAuthenticated(true)} />;
  }

  return <VaultScreen />;
}
