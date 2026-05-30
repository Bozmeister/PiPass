import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { View, Text, TextInput, Pressable, Platform, ActivityIndicator, ScrollView, Alert } from "react-native";
import { KeyboardAvoidingView } from "react-native-keyboard-controller";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_ERROR, INPUT_BORDER_FOCUS } from "../../styles/inputTheme";
import AuthScreen from "../../screens/AuthScreen";
import SeedSetupScreen, { type StagedBackupSelection } from "../../screens/SeedSetupScreen";
import VaultScreen from "../../screens/VaultScreen";
import {
  getMasterSalt,
  getMasterKeyHash,
  getKdfMetadataState,
  saveKdfMetadata,
  getSecurityProfile,
  saveSecurityProfile,
  destroyAllData,
  clearMasterKeySecurely,
  storeMasterKeySecurely,
} from "../../workers/storageWorker";
import { readPlatformItem, writePlatformItem, deletePlatformItem } from "../../lib/platformStorage";
import {
  deriveMasterKeyWithArgon2id,
  generateMasterSalt,
  hashMasterKey,
  planUnlockKdfDerivation,
} from "../../crypto/keyDerivation";
import { deriveMasterKeyShares } from "../../workers/vaultWorker";
import { KeyShares, wipeShares, combineShares, splitKeyIntoShares } from "../../crypto/secureMemory";
import { performCurrentUnlockVerification } from "../../lib/currentUnlock";
import {
  prepareFirstTimeVaultSetup,
  type PreparedFirstTimeVaultSetupResult,
} from "../../lib/firstTimeSetup";
import {
  prepareRuntimeStagedBackupCommitContext,
  prepareSetupImportCommitFromRuntimeState,
} from "../../lib/runtimeSetupImportCommit";
import {
  runIntegrityCheck,
  setTamperCallback,
  startPeriodicGuard,
  stopPeriodicGuard,
} from "../../crypto/integrityGuard";
import { requireFreshBiometric } from "../../crypto/biometricGate";
import {
  generateRecoveryKey,
  formatRecoveryKey,
  hashRecoveryKey,
} from "../../crypto/recoveryKey";
import RecoveryKeyModal from "../../components/RecoveryKeyModal";
import NuclearResetModal from "../../components/NuclearResetModal";
import {
  confirmStartupRepairDecision,
  readAndDecideStartupRepairState,
  type StartupRepairDecision,
} from "../../lib/startupRepairDecision";
import {
  buildSetupImportCommitPlan,
  SETUP_IMPORT_STORAGE_KEYS,
} from "../../lib/setupImportCommitPlan";
import { executeSetupImportCommitPlan } from "../../lib/setupImportCommitExecutor";
import { computeStagedBackupPreflightStatus } from "../../lib/stagedBackupBridgeStatus";

const startupSnapshotDriver = {
  getItem: readPlatformItem,
};

const startupRepairStorageDriver = {
  deleteItem: async (key: string) => {
    if (key === SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey) {
      await clearMasterKeySecurely();
      return;
    }
    await deletePlatformItem(key);
  },
};

const setupCommitStorageDriver = {
  getItem: async (key: string) => {
    if (key === SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey) {
      return null;
    }
    return await readPlatformItem(key);
  },
  setItem: async (key: string, value: string) => {
    if (key === SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey) {
      await storeMasterKeySecurely(value);
      return;
    }
    await writePlatformItem(key, value);
  },
  deleteItem: async (key: string) => {
    if (key === SETUP_IMPORT_STORAGE_KEYS.cachedMasterKey) {
      await clearMasterKeySecurely();
      return;
    }
    await deletePlatformItem(key);
  },
};

export default function HomeScreen() {
  const [authenticated, setAuthenticated] = useState(false);
  const [vaultExists, setVaultExists] = useState<boolean | null>(null);
  const [startupDecision, setStartupDecision] = useState<StartupRepairDecision | null>(null);
  const [checkingStartupState, setCheckingStartupState] = useState(false);
  const [repairingStartupState, setRepairingStartupState] = useState(false);
  const [startupRepairError, setStartupRepairError] = useState<string | null>(null);
  const [iterations, setIterations] = useState<number>(100000);
  const [keyShares, setKeyShares] = useState<KeyShares | null>(null);
  const [masterSalt, setMasterSaltState] = useState<string | null>(null);
  const [tamperLocked, setTamperLocked] = useState(false);
  const [pendingRecoveryKey, setPendingRecoveryKey] = useState<string | null>(null);
  const [pendingRecoveryRawHex, setPendingRecoveryRawHex] = useState<string>("");
  const [pendingSetupShares, setPendingSetupShares] = useState<KeyShares | null>(null);
  const [stagedSetupBackup, setStagedSetupBackup] = useState<StagedBackupSelection | null>(null);
  const [committingSetup, setCommittingSetup] = useState(false);
  const [vaultLocked, setVaultLocked] = useState(false);
  const [showUnlockNuclearReset, setShowUnlockNuclearReset] = useState(false);
  const lockedSharesRef = useRef<KeyShares | null>(null);
  const keySharesRef = useRef<KeyShares | null>(null);
  const pendingSetupSharesRef = useRef<KeyShares | null>(null);
  const pendingSetupCommitRef = useRef<PreparedFirstTimeVaultSetupResult | null>(null);
  const committingSetupRef = useRef(false);

  const stagedBackupBridgeStatus = useMemo(
    () => computeStagedBackupPreflightStatus({
      stagedBackup: stagedSetupBackup?.backup ?? null,
    }),
    [stagedSetupBackup],
  );

  useEffect(() => {
    keySharesRef.current = keyShares;
  }, [keyShares]);

  useEffect(() => {
    pendingSetupSharesRef.current = pendingSetupShares;
  }, [pendingSetupShares]);

  const clearPendingSetupState = useCallback((shouldWipeShares: boolean) => {
    if (shouldWipeShares && pendingSetupSharesRef.current) {
      wipeShares(pendingSetupSharesRef.current);
    }
    pendingSetupSharesRef.current = null;
    pendingSetupCommitRef.current = null;
    committingSetupRef.current = false;
    setPendingSetupShares(null);
    setPendingRecoveryKey(null);
    setPendingRecoveryRawHex("");
    setCommittingSetup(false);
  }, []);

  useEffect(() => {
    setTamperCallback(() => {
      if (keySharesRef.current) {
        wipeShares(keySharesRef.current);
      }
      if (pendingSetupSharesRef.current) {
        wipeShares(pendingSetupSharesRef.current);
      }
      pendingSetupSharesRef.current = null;
      pendingSetupCommitRef.current = null;
      committingSetupRef.current = false;
      setKeyShares(null);
      setPendingSetupShares(null);
      setPendingRecoveryKey(null);
      setPendingRecoveryRawHex("");
      setAuthenticated(false);
      setStagedSetupBackup(null);
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

  const runStartupRepairDecision = useCallback(async () => {
    setCheckingStartupState(true);
    setStartupRepairError(null);
    setVaultExists(null);

    try {
      const decision = await readAndDecideStartupRepairState(startupSnapshotDriver);
      setStartupDecision(decision);

      if (decision.route === "setup") {
        setMasterSaltState(null);
        setVaultExists(false);
      } else if (decision.route === "unlock") {
        setStagedSetupBackup(null);
        const savedProfile = await getSecurityProfile();
        setIterations(Math.max(savedProfile || 100000, 3));
        const salt = await getMasterSalt();
        setMasterSaltState(salt);
        setVaultExists(true);
      }
    } catch {
      setStartupDecision({
        route: "safe-error",
        classification: "read-failed",
        repairPlan: null,
        state: null,
        message: "PiPass could not inspect local setup state safely.",
        reason: "snapshot-read-failed",
        failedKey: "startup-state",
      });
    } finally {
      setCheckingStartupState(false);
    }
  }, []);

  useEffect(() => {
    if (!authenticated) {
      setVaultExists(null);
      setStartupDecision(null);
      setStartupRepairError(null);
      setStagedSetupBackup(null);
      clearPendingSetupState(true);
      return;
    }

    void runStartupRepairDecision();
  }, [authenticated, clearPendingSetupState, runStartupRepairDecision]);

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

  if (checkingStartupState || startupDecision === null) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <ActivityIndicator color="#4CAF50" />
      </View>
    );
  }

  if (startupDecision.route === "repair-prompt") {
    return (
      <StartupRepairSurface
        containerTestID="startup-repair-prompt"
        titleTestID="startup-repair-title"
        messageTestID="startup-repair-message"
        primaryTestID="startup-repair-confirm"
        secondaryTestID="startup-repair-cancel"
        accessibilityLabel="Startup repair prompt"
        icon="construct-outline"
        title="Setup Was Interrupted"
        message="PiPass found an unfinished setup or backup restore. To continue safely, clear the incomplete local setup data and start setup again."
        primaryLabel="Clear incomplete setup"
        secondaryLabel="Not now"
        busy={repairingStartupState}
        error={startupRepairError}
        onSecondary={() => setAuthenticated(false)}
        onPrimary={async () => {
          if (repairingStartupState) return;
          setRepairingStartupState(true);
          setStartupRepairError(null);
          const result = await confirmStartupRepairDecision(
            startupDecision,
            startupRepairStorageDriver,
          );
          setRepairingStartupState(false);
          if (result.success) {
            await runStartupRepairDecision();
          } else {
            setStartupRepairError("PiPass could not clear incomplete setup data safely. Restart the app and try again.");
          }
        }}
      />
    );
  }

  if (startupDecision.route === "manual-repair") {
    return (
      <StartupRepairSurface
        containerTestID="startup-repair-manual"
        titleTestID="startup-repair-manual-title"
        messageTestID="startup-repair-manual-message"
        accessibilityLabel="Manual startup repair required"
        icon="warning-outline"
        title="Manual Repair Needed"
        message="PiPass found local vault state that needs manual repair. Your initialized vault data was not cleared automatically."
      />
    );
  }

  if (startupDecision.route === "safe-error") {
    return (
      <StartupRepairSurface
        containerTestID="startup-repair-safe-error"
        titleTestID="startup-repair-safe-error-title"
        messageTestID="startup-repair-safe-error-message"
        accessibilityLabel="Startup repair check failed"
        icon="alert-circle-outline"
        title="Setup Check Failed"
        message="PiPass could not check local setup state safely. Restart the app and try again."
      />
    );
  }

  if (vaultExists === null) return null;

  if (pendingRecoveryKey !== null) {
    return (
      <RecoveryKeyModal
        visible={true}
        formattedKey={pendingRecoveryKey}
        rawKeyHex={pendingRecoveryRawHex}
        onConfirm={async () => {
          if (committingSetupRef.current || committingSetup) return;
          const pendingSetup = pendingSetupCommitRef.current;
          if (!pendingSetup || !pendingSetupShares) {
            const message = "PiPass could not complete setup safely. Please restart setup and try again.";
            if (Platform.OS === "web") { alert(message); } else { Alert.alert("Setup Failed", message); }
            clearPendingSetupState(true);
            setVaultExists(false);
            return;
          }

          committingSetupRef.current = true;
          setCommittingSetup(true);
          let result: Awaited<ReturnType<typeof prepareSetupImportCommitFromRuntimeState>>;
          try {
            const setupMetadata = {
              masterSalt: pendingSetup.salt,
              masterHash: pendingSetup.masterHash,
              securityProfile: pendingSetup.iterations,
              kdfMetadata: pendingSetup.kdfMetadata,
              recoveryKeyHash: pendingSetup.recoveryKeyHash,
            };
            const stagedCommitContext = await prepareRuntimeStagedBackupCommitContext({
              setupMetadata,
              stagedBackup: stagedSetupBackup?.backup ?? null,
              keyShares: pendingSetupShares,
              masterKeyHex: pendingSetup.masterKeyHex,
              deviceUUID: await readPlatformItem("deviceUUID"),
            });
            result = await prepareSetupImportCommitFromRuntimeState({
              setupMetadata,
              stagedBackup: stagedSetupBackup?.backup ?? null,
              backupVerifier: stagedCommitContext.backupVerifier,
              eligibilityInput: stagedCommitContext.eligibilityInput,
              sharedVaultBlob: stagedCommitContext.sharedVaultBlob,
              includeCachedMasterKey: true,
              cachedMasterKeyReference: pendingSetup.masterKeyHex,
              dependencies: {
                classifyCompatibility: stagedCommitContext.classifyCompatibility,
                verifySentinel: stagedCommitContext.verifySentinel,
                verifyDecryptability: stagedCommitContext.verifyDecryptability,
                buildPlan: buildSetupImportCommitPlan,
                executePlan: async (plan) => executeSetupImportCommitPlan(plan, setupCommitStorageDriver),
              },
            });
          } catch {
            result = {
              ok: false,
              stage: "eligibility",
              reason: "runtime-commit-preparation-failed",
              eligibility: {
                status: "blocked",
                reason: "decryptability-not-run",
                importCommitEnabled: false,
                setupOnlyAllowed: false,
                canAttemptImport: false,
                requiresClearOrDismiss: true,
                safeTitle: "Setup failed",
                safeMessage: "PiPass could not prepare setup safely.",
                warnings: [],
              },
              recordsIncluded: false,
              activeSharesPublished: false,
              warnings: [],
            };
          }
          committingSetupRef.current = false;
          setCommittingSetup(false);

          if (!result.ok) {
            const message = "PiPass could not finish creating your vault safely. No vault was initialized. Please try setup again.";
            if (Platform.OS === "web") { alert(message); } else { Alert.alert("Setup Failed", message); }
            setStagedSetupBackup(null);
            clearPendingSetupState(true);
            setVaultExists(false);
            return;
          }

          setMasterSaltState(pendingSetup.salt);
          setIterations(pendingSetup.iterations);
          setStagedSetupBackup(null);
          pendingSetupCommitRef.current = null;
          pendingSetupSharesRef.current = null;
          setPendingSetupShares(null);
          setPendingRecoveryKey(null);
          setPendingRecoveryRawHex("");
          setVaultExists(true);
          setKeyShares(pendingSetupShares);
        }}
      />
    );
  }

  if (!vaultExists) {
    return (
      <SeedSetupScreen
        onStagedBackupChange={setStagedSetupBackup}
        stagedBackupBridgeStatus={stagedBackupBridgeStatus}
        onSetup={async (password, iters) => {
          clearPendingSetupState(true);
          const setup = await prepareFirstTimeVaultSetup(
            { password, iterations: iters },
            {
              generateMasterSalt,
              deriveMasterKeyWithArgon2id,
              splitKeyIntoShares,
              hashMasterKey,
              generateRecoveryKey,
              hashRecoveryKey,
            },
          );

          pendingSetupCommitRef.current = setup;
          setPendingSetupShares(setup.shares);
          setPendingRecoveryRawHex(setup.rawRecoveryKeyHex);
          setPendingRecoveryKey(formatRecoveryKey(setup.rawRecoveryKeyHex));
        }}
      />
    );
  }

  if (!keyShares && !vaultLocked) {
    return (
      <>
        <UnlockScreen
          salt={masterSalt!}
          iterations={iterations}
          onUnlocked={(shares) => setKeyShares(shares)}
          onRequestNuclearReset={() => setShowUnlockNuclearReset(true)}
        />
        <NuclearResetModal
          visible={showUnlockNuclearReset}
          onClose={() => setShowUnlockNuclearReset(false)}
          onConfirmReset={async () => {
            await destroyAllData();
            setShowUnlockNuclearReset(false);
            setStagedSetupBackup(null);
            clearPendingSetupState(true);
            setVaultExists(false);
            setKeyShares(null);
          }}
          verifyPassword={async (pw) => {
            const salt = await getMasterSalt();
            if (!salt) return false;
            const shares = await deriveMasterKeyShares(pw, salt, iterations);
            const keyHex = combineShares(shares);
            const keyHash = hashMasterKey(keyHex);
            wipeShares(shares);
            const storedHash = await getMasterKeyHash();
            return !!storedHash && keyHash === storedHash;
          }}
          requireBiometric={requireFreshBiometric}
        />
      </>
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
            setStagedSetupBackup(null);
            clearPendingSetupState(true);
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
            onRequestNuclearReset={() => setShowUnlockNuclearReset(true)}
          />
          <NuclearResetModal
            visible={showUnlockNuclearReset}
            onClose={() => setShowUnlockNuclearReset(false)}
            onConfirmReset={async () => {
              if (lockedSharesRef.current) {
                wipeShares(lockedSharesRef.current);
                lockedSharesRef.current = null;
              }
              await destroyAllData();
              setShowUnlockNuclearReset(false);
              setKeyShares(null);
              setVaultLocked(false);
              setVaultExists(false);
              setStagedSetupBackup(null);
              clearPendingSetupState(true);
              setAuthenticated(false);
            }}
            verifyPassword={async (pw) => {
              const salt = await getMasterSalt();
              if (!salt) return false;
              const shares = await deriveMasterKeyShares(pw, salt, iterations);
              const keyHex = combineShares(shares);
              const keyHash = hashMasterKey(keyHex);
              wipeShares(shares);
              const storedHash = await getMasterKeyHash();
              return !!storedHash && keyHash === storedHash;
            }}
            requireBiometric={requireFreshBiometric}
          />
        </View>
      )}
    </>
  );
}

function StartupRepairSurface({
  containerTestID,
  titleTestID,
  messageTestID,
  primaryTestID,
  secondaryTestID,
  accessibilityLabel,
  icon,
  title,
  message,
  primaryLabel,
  secondaryLabel,
  busy = false,
  error = null,
  onPrimary,
  onSecondary,
}: {
  containerTestID: string;
  titleTestID: string;
  messageTestID: string;
  primaryTestID?: string;
  secondaryTestID?: string;
  accessibilityLabel: string;
  icon: React.ComponentProps<typeof Ionicons>["name"];
  title: string;
  message: string;
  primaryLabel?: string;
  secondaryLabel?: string;
  busy?: boolean;
  error?: string | null;
  onPrimary?: () => void | Promise<void>;
  onSecondary?: () => void;
}) {
  const insets = useSafeAreaInsets();
  const webTopInset = Platform.OS === "web" ? 67 : 0;

  return (
    <View
      style={{ flex: 1, backgroundColor: "#000" }}
      testID={containerTestID}
      accessible
      accessibilityLabel={accessibilityLabel}
    >
      <ScrollView
        contentContainerStyle={{
          flexGrow: 1,
          justifyContent: "center",
          alignItems: "center",
          padding: 24,
          paddingTop: insets.top + webTopInset,
        }}
      >
        <Ionicons name={icon} size={64} color="#fbbf24" />
        <Text
          style={{ color: "#fff", fontSize: 24, fontWeight: "bold" as const, marginTop: 24, textAlign: "center" }}
          testID={titleTestID}
          accessibilityRole="header"
        >
          {title}
        </Text>
        <Text
          style={{ color: "#aaa", fontSize: 15, marginTop: 16, textAlign: "center", lineHeight: 22 }}
          testID={messageTestID}
        >
          {message}
        </Text>
        {error && (
          <Text style={{ color: "#ef4444", fontSize: 14, marginTop: 16, textAlign: "center", lineHeight: 20 }}>
            {error}
          </Text>
        )}

        {(primaryLabel || secondaryLabel) && (
          <View style={{ width: "100%", marginTop: 36, gap: 12 }}>
            {primaryLabel && (
              <Pressable
                onPress={onPrimary}
                disabled={busy}
                testID={primaryTestID}
                accessibilityRole="button"
                accessibilityLabel={primaryLabel}
                style={{
                  backgroundColor: "#4CAF50",
                  paddingVertical: 16,
                  borderRadius: 12,
                  alignItems: "center",
                  width: "100%",
                  opacity: busy ? 0.7 : 1,
                }}
              >
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>
                  {busy ? "Clearing..." : primaryLabel}
                </Text>
              </Pressable>
            )}

            {secondaryLabel && (
              <Pressable
                onPress={onSecondary}
                disabled={busy}
                testID={secondaryTestID}
                accessibilityRole="button"
                accessibilityLabel={secondaryLabel}
                style={{
                  backgroundColor: "#1a1a1a",
                  paddingVertical: 16,
                  borderRadius: 12,
                  alignItems: "center",
                  width: "100%",
                  borderWidth: 1,
                  borderColor: "#333",
                  opacity: busy ? 0.7 : 1,
                }}
              >
                <Text style={{ color: "#aaa", fontSize: 16, fontWeight: "600" as const }}>
                  {secondaryLabel}
                </Text>
              </Pressable>
            )}
          </View>
        )}
      </ScrollView>
    </View>
  );
}

function UnlockScreen({ salt, iterations, onUnlocked, onRequestNuclearReset }: {
  salt: string;
  iterations: number;
  onUnlocked: (shares: KeyShares) => void;
  onRequestNuclearReset: () => void;
}) {
  const insets = useSafeAreaInsets();
  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [focused, setFocused] = useState(false);
  const [showForgotInfo, setShowForgotInfo] = useState(false);
  const webTopInset = Platform.OS === "web" ? 67 : 0;

  async function handleUnlock() {
    if (!password.trim() || unlocking) return;
    setUnlocking(true);
    setError(null);

    try {
      const result = await performCurrentUnlockVerification(
        { password, salt, iterations },
        {
          deriveMasterKeyShares,
          combineShares,
          hashMasterKey,
          getMasterKeyHash,
          getKdfMetadataState,
          saveKdfMetadata,
          planUnlockKdfDerivation,
          splitKeyIntoShares,
          storeMasterKeySecurely,
          wipeShares,
        },
      );

      if (!result.ok) {
        if (result.reason === "invalid-kdf-metadata") {
          setError("This vault's local unlock settings look inconsistent. PiPass cannot unlock it safely.");
        } else if (result.reason === "argon2id-unavailable") {
          setError("This device cannot run the required unlock protection right now. Update or restart the app and try again.");
        } else if (result.reason === "kdf-derivation-failed") {
          setError("Failed to derive key. Please try again.");
        } else {
          setError("Incorrect password. Please try again.");
        }
        setUnlocking(false);
        return;
      }

      onUnlocked(result.shares);
    } catch {
      setError("Failed to derive key. Please try again.");
    }
    setUnlocking(false);
  }

  if (showForgotInfo) {
    return (
      <View style={{ flex: 1, backgroundColor: "#000" }}>
        <ScrollView
          contentContainerStyle={{ flexGrow: 1, justifyContent: "center", alignItems: "center", padding: 24, paddingTop: insets.top + webTopInset }}
        >
          <Ionicons name="warning-outline" size={64} color="#fbbf24" />
          <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold" as const, marginTop: 24, textAlign: "center" }}>
            Forgot Your Password?
          </Text>
          <Text style={{ color: "#aaa", fontSize: 15, marginTop: 16, textAlign: "center", lineHeight: 22 }}>
            Your vault is encrypted and cannot be recovered without your password or recovery key.
          </Text>
          <Text style={{ color: "#ef4444", fontSize: 15, marginTop: 12, textAlign: "center", lineHeight: 22, fontWeight: "600" as const }}>
            Resetting will permanently erase all stored data.
          </Text>

          <View style={{ width: "100%", marginTop: 36, gap: 12 }}>
            <Pressable
              onPress={() => setShowForgotInfo(false)}
              style={{
                backgroundColor: "#4CAF50", paddingVertical: 16, borderRadius: 12,
                alignItems: "center", width: "100%",
              }}
            >
              <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
                <Ionicons name="key-outline" size={20} color="#fff" />
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Enter Password Again</Text>
              </View>
            </Pressable>

            <Pressable
              onPress={() => {
                Alert.alert(
                  "Recovery Key Unlock",
                  "Recovery key unlock is not yet available.\n\nFor now, use 'Proceed to Secure Reset' below to create a new vault.\n\nThis will permanently delete all current data.",
                  [{ text: "OK" }]
                );
              }}
              style={{
                backgroundColor: "#1a0808", paddingVertical: 16, borderRadius: 12,
                alignItems: "center", width: "100%", borderWidth: 1, borderColor: "#3a1515",
              }}
            >
              <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
                <Ionicons name="document-text-outline" size={20} color="#ef4444" />
                <Text style={{ color: "#ef4444", fontSize: 16, fontWeight: "600" as const }}>Use Recovery Key (Coming Soon)</Text>
              </View>
              <Text style={{ color: "#666", fontSize: 12, marginTop: 4 }}>Use Nuclear Reset for now</Text>
            </Pressable>

            <Pressable
              onPress={() => {
                setShowForgotInfo(false);
                onRequestNuclearReset();
              }}
              style={{
                backgroundColor: "#1a0808", paddingVertical: 16, borderRadius: 12,
                alignItems: "center", width: "100%", borderWidth: 1, borderColor: "#3a1515",
                marginTop: 8,
              }}
            >
              <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
                <Ionicons name="nuclear-outline" size={20} color="#ef4444" />
                <Text style={{ color: "#ef4444", fontSize: 16, fontWeight: "600" as const }}>Proceed to Secure Reset</Text>
              </View>
              <Text style={{ color: "#666", fontSize: 12, marginTop: 4 }}>This will permanently destroy your vault</Text>
            </Pressable>
          </View>
        </ScrollView>
      </View>
    );
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
          onPress={() => setShowForgotInfo(true)}
          style={{ marginTop: 32 }}
        >
          <Text style={{ color: "#666", fontSize: 14 }}>Forgot your password?</Text>
        </Pressable>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}
