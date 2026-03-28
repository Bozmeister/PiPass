import React, { useState, useEffect, useRef } from "react";
import { View, Text, TextInput, Pressable, Platform, Alert, ActivityIndicator, ScrollView } from "react-native";
import { KeyboardAvoidingView } from "react-native-keyboard-controller";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_ERROR, INPUT_BORDER_FOCUS } from "../../styles/inputTheme";
import AuthScreen from "../../screens/AuthScreen";
import SeedSetupScreen from "../../screens/SeedSetupScreen";
import VaultScreen from "../../screens/VaultScreen";
import {
  isVaultInitialized,
  setVaultInitialized,
  getMasterSalt,
  saveMasterSalt,
  getMasterKeyHash,
  saveMasterKeyHash,
  getSecurityProfile,
  saveSecurityProfile,
  destroyAllData,
  saveRecoveryKeyHash,
} from "../../workers/storageWorker";
import { generateMasterSalt, hashMasterKey } from "../../crypto/keyDerivation";
import { deriveMasterKeyShares } from "../../workers/vaultWorker";
import { KeyShares, wipeShares, combineShares } from "../../crypto/secureMemory";
import {
  runIntegrityCheck,
  setTamperCallback,
  startPeriodicGuard,
  stopPeriodicGuard,
} from "../../crypto/integrityGuard";
import {
  generateRecoveryKey,
  formatRecoveryKey,
  hashRecoveryKey,
} from "../../crypto/recoveryKey";
import RecoveryKeyModal from "../../components/RecoveryKeyModal";

export default function HomeScreen() {
  const [authenticated, setAuthenticated] = useState(false);
  const [vaultExists, setVaultExists] = useState<boolean | null>(null);
  const [iterations, setIterations] = useState<number>(100000);
  const [keyShares, setKeyShares] = useState<KeyShares | null>(null);
  const [masterSalt, setMasterSaltState] = useState<string | null>(null);
  const [tamperLocked, setTamperLocked] = useState(false);
  const [pendingRecoveryKey, setPendingRecoveryKey] = useState<string | null>(null);
  const [pendingRecoveryRawHex, setPendingRecoveryRawHex] = useState<string>("");
  const [pendingSetupShares, setPendingSetupShares] = useState<KeyShares | null>(null);
  const [vaultLocked, setVaultLocked] = useState(false);
  const lockedSharesRef = useRef<KeyShares | null>(null);
  const keySharesRef = useRef<KeyShares | null>(null);

  useEffect(() => {
    keySharesRef.current = keyShares;
  }, [keyShares]);

  useEffect(() => {
    setTamperCallback(() => {
      if (keySharesRef.current) {
        wipeShares(keySharesRef.current);
      }
      setKeyShares(null);
      setAuthenticated(false);
      setTamperLocked(true);
    });

    const report = runIntegrityCheck();
    if (report.tampered && !__DEV__) {
      setTamperLocked(true);
      return;
    }

    startPeriodicGuard(30000);

    return () => {
      stopPeriodicGuard();
    };
  }, []);

  useEffect(() => {
    (async () => {
      const exists = await isVaultInitialized();
      setVaultExists(exists);
      if (exists) {
        const savedProfile = await getSecurityProfile();
        setIterations(Math.max(savedProfile || 100000, 3));
        const salt = await getMasterSalt();
        setMasterSaltState(salt);
      }
    })();
  }, []);

  if (tamperLocked) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000", padding: 24 }}>
        <Ionicons name="warning" size={64} color="#ef4444" />
        <Text style={{ color: "#ef4444", fontSize: 22, fontWeight: "bold" as const, marginTop: 20, textAlign: "center" }}>
          Security Alert
        </Text>
        <Text style={{ color: "#aaa", fontSize: 14, marginTop: 12, textAlign: "center", lineHeight: 20 }}>
          A potential security threat was detected. The vault has been locked to protect your data. Please restart the app in a secure environment.
        </Text>
      </View>
    );
  }

  if (!authenticated) {
    return <AuthScreen onAuthenticated={() => setAuthenticated(true)} />;
  }

  if (vaultExists === null) return null;

  if (pendingRecoveryKey !== null) {
    return (
      <RecoveryKeyModal
        visible={true}
        formattedKey={pendingRecoveryKey}
        rawKeyHex={pendingRecoveryRawHex}
        onConfirm={async () => {
          await setVaultInitialized(true);
          setPendingRecoveryKey(null);
          setPendingRecoveryRawHex("");
          setVaultExists(true);
          if (pendingSetupShares) {
            setKeyShares(pendingSetupShares);
            setPendingSetupShares(null);
          }
        }}
      />
    );
  }

  if (!vaultExists) {
    return (
      <SeedSetupScreen onSetup={async (password, iters) => {
        const validIters = Math.max(iters || 100000, 3);
        const salt = generateMasterSalt();

        const shares = await deriveMasterKeyShares(password, salt, validIters);
        const keyHex = combineShares(shares);
        const keyHash = hashMasterKey(keyHex);

        const rawKey = generateRecoveryKey();
        const keyHashRecovery = hashRecoveryKey(rawKey);

        await saveMasterSalt(salt);
        await saveMasterKeyHash(keyHash);
        await saveSecurityProfile(validIters);
        await saveRecoveryKeyHash(keyHashRecovery);

        setMasterSaltState(salt);
        setIterations(validIters);
        setPendingSetupShares(shares);
        setPendingRecoveryRawHex(rawKey);
        setPendingRecoveryKey(formatRecoveryKey(rawKey));
      }} />
    );
  }

  if (!keyShares && !vaultLocked) {
    return (
      <UnlockScreen
        salt={masterSalt!}
        iterations={iterations}
        onUnlocked={(shares) => setKeyShares(shares)}
        onReset={() => {
          setVaultExists(false);
          setKeyShares(null);
        }}
      />
    );
  }

  return (
    <>
      {(keyShares || vaultLocked) && (
        <VaultScreen
          keyShares={keyShares}
          iterations={iterations}
          locked={vaultLocked}
          onLock={() => {
            if (keyShares) {
              lockedSharesRef.current = keyShares;
            }
            setKeyShares(null);
            setVaultLocked(true);
          }}
          onIterationsChange={async (iters) => {
            const validIters = Math.max(iters || 100000, 3);
            await saveSecurityProfile(validIters);
            setIterations(validIters);
          }}
          onReset={() => {
            lockedSharesRef.current = null;
            if (keyShares) wipeShares(keyShares);
            setKeyShares(null);
            setVaultLocked(false);
            setVaultExists(false);
            setAuthenticated(false);
          }}
        />
      )}
      {vaultLocked && (
        <View style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, zIndex: 100 }}>
          <UnlockScreen
            salt={masterSalt!}
            iterations={iterations}
            onUnlocked={(newShares) => {
              if (lockedSharesRef.current) {
                wipeShares(lockedSharesRef.current);
                lockedSharesRef.current = null;
              }
              setKeyShares(newShares);
              setVaultLocked(false);
            }}
            onReset={() => {
              if (lockedSharesRef.current) {
                wipeShares(lockedSharesRef.current);
                lockedSharesRef.current = null;
              }
              setKeyShares(null);
              setVaultLocked(false);
              setVaultExists(false);
              setAuthenticated(false);
            }}
          />
        </View>
      )}
    </>
  );
}

function UnlockScreen({ salt, iterations, onUnlocked, onReset }: {
  salt: string;
  iterations: number;
  onUnlocked: (shares: KeyShares) => void;
  onReset: () => void;
}) {
  const insets = useSafeAreaInsets();
  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [focused, setFocused] = useState(false);
  const webTopInset = Platform.OS === "web" ? 67 : 0;

  async function handleUnlock() {
    if (!password.trim() || unlocking) return;
    setUnlocking(true);
    setError(null);

    try {
      const shares = await deriveMasterKeyShares(password, salt, iterations);
      const keyHex = combineShares(shares);
      const keyHash = hashMasterKey(keyHex);
      const storedHash = await getMasterKeyHash();

      if (storedHash && keyHash !== storedHash) {
        wipeShares(shares);
        setError("Incorrect password. Please try again.");
        setUnlocking(false);
        return;
      }

      onUnlocked(shares);
    } catch (err) {
      setError("Failed to derive key. Please try again.");
    }
    setUnlocking(false);
  }

  return (
    <KeyboardAvoidingView
      style={{ flex: 1, backgroundColor: "#000" }}
      behavior="padding"
      keyboardVerticalOffset={0}
    >
      <ScrollView
        contentContainerStyle={{ flexGrow: 1, justifyContent: "center", alignItems: "center", padding: 24, paddingTop: insets.top + webTopInset }}
        keyboardShouldPersistTaps="handled"
      >
        <Ionicons name="lock-closed" size={64} color="#4CAF50" />
        <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold" as const, marginTop: 24 }}>
          Unlock Vault
        </Text>
        <Text style={{ color: "#aaa", fontSize: 14, marginTop: 8, textAlign: "center" }}>
          Enter your master password to access your vault
        </Text>

        <View style={{
          flexDirection: "row", alignItems: "center",
          backgroundColor: INPUT_BG, borderRadius: 8, marginTop: 32, width: "100%",
          borderWidth: 1, borderColor: error ? INPUT_BORDER_ERROR : (focused ? INPUT_BORDER_FOCUS : INPUT_BORDER),
        }}>
          <TextInput
            value={password}
            onChangeText={(t) => { setPassword(t); setError(null); }}
            onSubmitEditing={handleUnlock}
            placeholder="Master password"
            placeholderTextColor={INPUT_PLACEHOLDER}
            secureTextEntry={!showPassword}
            autoCapitalize="none"
            autoCorrect={false}
            textContentType="none"
            autoComplete="off"
            returnKeyType="go"
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            style={{ color: INPUT_TEXT, fontSize: 18, padding: 16, flex: 1 }}
            testID="unlock-password-input"
          />
          <Pressable onPress={() => setShowPassword(!showPassword)} style={{ padding: 16 }}>
            <Ionicons name={showPassword ? "eye-off-outline" : "eye-outline"} size={20} color="#888" />
          </Pressable>
        </View>

        {error && (
          <Text style={{ color: "#ff4444", fontSize: 14, marginTop: 8 }}>{error}</Text>
        )}

        <Pressable
          onPress={handleUnlock}
          disabled={!password.trim() || unlocking}
          style={{
            backgroundColor: password.trim() && !unlocking ? "#4CAF50" : "#333",
            paddingVertical: 16, paddingHorizontal: 48, borderRadius: 8, marginTop: 24, width: "100%", alignItems: "center",
          }}
          testID="unlock-button"
        >
          {unlocking ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Unlock</Text>
          )}
        </Pressable>

        <Pressable
          onPress={async () => {
            const msg = "This will erase all vault data. This cannot be undone.";
            if (Platform.OS === "web") {
              if (confirm(msg)) {
                destroyAllData().then(() => onReset());
              }
            } else {
              Alert.alert("Reset Vault", msg, [
                { text: "Cancel", style: "cancel" },
                { text: "Reset", style: "destructive", onPress: async () => {
                  await destroyAllData();
                  onReset();
                }},
              ]);
            }
          }}
          style={{ marginTop: 32 }}
        >
          <Text style={{ color: "#666", fontSize: 14 }}>Forgot password? Reset vault</Text>
        </Pressable>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}
