import React, { useState, useEffect, useRef } from "react";
import { 
  View, Text, FlatList, Pressable, Alert, Platform, 
  ActivityIndicator, AppState, Modal, Switch 
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import * as ScreenCapture from "expo-screen-capture";

// Synchronized Imports from Workers
import { 
  VaultEntry, 
  SecureNote, 
  DecryptedVaultEntry,
  encryptVaultEntry,
  decryptVaultEntry,
  deriveMasterKeyShares,
  reEncryptEntry,
  reEncryptSecureNote 
} from "../workers/vaultWorker";

import { 
  getAllEntries, 
  saveEntry, 
  deleteEntry as deleteStoredEntry, 
  destroyAllData, 
  saveSecureNote, 
  getShowKeyprints, 
  saveShowKeyprints 
} from "../workers/storageWorker";

import { KeyShares, wipeShares } from "../crypto/secureMemory";
import { requireFreshBiometric } from "../crypto/biometricGate";
import { sanitizeEntryFields } from "../crypto/hyperbaricSanitizer";

// UI Components
import AddEntryModal from "../components/AddEntryModal";
import EntryDetailModal from "../components/EntryDetailModal";
import SecureNotesModal from "../components/SecureNotesModal";
import FractalKeyprint from "../components/FractalKeyprint";
import KeyprintViewer from "../components/KeyprintViewer";

const AUTO_LOCK_MS = 60000;

const PROFILES = [
  { label: "Balanced", iterations: 25000, time: "~3s", desc: "Fast unlock", color: "#4CAF50", icon: "flash-outline" as const },
  { label: "Fortress", iterations: 100000, time: "~8s", desc: "Recommended", color: "#fbbf24", icon: "shield-checkmark-outline" as const },
  { label: "Deep Vault", iterations: 250000, time: "~20s", desc: "Maximum protection", color: "#ef4444", icon: "lock-closed-outline" as const },
];

interface VaultScreenProps {
  piSeed: number;
  iterations: number;
  onLock: () => void;
  onIterationsChange: (iterations: number) => void;
  onReset: () => void;
}

export default function VaultScreen({ piSeed, iterations, onLock, onIterationsChange, onReset }: VaultScreenProps) {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const keySharesRef = useRef<KeyShares | null>(null);
  const isBiometricActive = useRef(false);

  const [loading, setLoading] = useState(true);
  const [derivingKey, setDerivingKey] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<VaultEntry | null>(null);
  const [decryptedEntry, setDecryptedEntry] = useState<DecryptedVaultEntry | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [secureNotes, setSecureNotes] = useState<SecureNote[]>([]);
  const [showSecureNotes, setShowSecureNotes] = useState(false);
  const [showKeyprints, setShowKeyprints] = useState(true);
  const [showKeyprintViewer, setShowKeyprintViewer] = useState(false);

  const settingsTapCountRef = useRef(0);
  const settingsTapTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lastActivityRef = useRef<number>(Date.now());
  const autoLockTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const selectTokenRef = useRef<number>(0);

  useEffect(() => {
    if (Platform.OS !== "web") ScreenCapture.preventScreenCaptureAsync();
    return () => { if (Platform.OS !== "web") ScreenCapture.allowScreenCaptureAsync(); };
  }, []);

  useEffect(() => {
    initializeVault();
    const appStateSub = AppState.addEventListener("change", (state) => {
      if ((state === "background" || state === "inactive") && !isBiometricActive.current) {
        if (keySharesRef.current) wipeShares(keySharesRef.current);
        keySharesRef.current = null;
        onLock();
      }
    });
    return () => {
      if (autoLockTimerRef.current) clearInterval(autoLockTimerRef.current);
      appStateSub.remove();
      if (keySharesRef.current) wipeShares(keySharesRef.current);
    };
  }, []);

  function resetActivity() { lastActivityRef.current = Date.now(); }

  async function initializeVault() {
    setDerivingKey(true);
    try {
      const safeIterations = Math.max(iterations || 100000, 3);
      if (safeIterations !== iterations) {
        onIterationsChange(safeIterations);
      }

      console.log("Deriving key with iterations:", safeIterations);

      const shares = await deriveMasterKeyShares(piSeed, safeIterations);
      keySharesRef.current = shares;

      const keyprintPref = await getShowKeyprints();
      setShowKeyprints(keyprintPref);

      const stored = await getAllEntries();
      setEntries(stored);

      if (stored.length > 0) {
        try {
          decryptVaultEntry(stored[0], shares);
        } catch {
          Alert.alert("Key Mismatch", "Clear & Start Fresh?", [
            { text: "Clear", style: "destructive", onPress: async () => await destroyAllData() }
          ]);
        }
      }
    } catch (err) {
      console.error("Initialization error:", err);
      Alert.alert("Engine Error", "Failed to initialize vault.", [
        { text: "Try Again", onPress: () => initializeVault() },
        { text: "Wipe Data", style: "destructive", onPress: async () => { await destroyAllData(); onReset(); } },
      ]);
    }
    setDerivingKey(false);
    resetActivity();

    autoLockTimerRef.current = setInterval(() => {
      if (Date.now() - lastActivityRef.current > AUTO_LOCK_MS) onLock();
    }, 5000);
  }

  async function handleAddEntry(entry: any) {
    if (!keySharesRef.current) return;

    const { sanitized, ok, error } = sanitizeEntryFields(entry);
    if (!ok) {
      Alert.alert("Sanitization Error", error || "Input rejected by Hyperbaric Sanitizer.");
      return;
    }

    const encrypted = encryptVaultEntry(sanitized, keySharesRef.current);
    await saveEntry(encrypted);
    const stored = await getAllEntries();
    setEntries(stored);
    setShowAddModal(false);
  }

  async function handleSelectEntry(entry: VaultEntry) {
    if (!keySharesRef.current) return;
    const token = ++selectTokenRef.current;
    setDecrypting(true);
    setSelectedEntry(entry);
    setDecryptedEntry(null);
    try {
      isBiometricActive.current = true;
      const authenticated = await requireFreshBiometric();
      isBiometricActive.current = false;

      if (selectTokenRef.current !== token) return;

      if (!authenticated) {
        setSelectedEntry(null);
        setDecrypting(false);
        return;
      }

      if (!keySharesRef.current) {
        Alert.alert("Vault Locked", "Vault was locked during authentication.");
        setSelectedEntry(null);
        setDecrypting(false);
        return;
      }

      const decrypted = decryptVaultEntry(entry, keySharesRef.current);
      if (selectTokenRef.current !== token) return;
      setDecryptedEntry(decrypted);
    } catch (err) {
      if (selectTokenRef.current === token) {
        Alert.alert("Decryption Error", "Something went wrong.");
        setSelectedEntry(null);
      }
    } finally {
      isBiometricActive.current = false;
      if (selectTokenRef.current === token) setDecrypting(false);
    }
  }

  async function handleDeleteEntry(id: string) {
    await deleteStoredEntry(id);
    setSelectedEntry(null);
    setDecryptedEntry(null);
    const stored = await getAllEntries();
    setEntries(stored);
  }

  function handleCloseDetail() {
    setSelectedEntry(null);
    setDecryptedEntry(null);
  }

  async function handleProfileChange(newIterations: number) {
    if (newIterations === iterations || !keySharesRef.current) return;

    const safeNew = Math.max(newIterations || 100000, 3);

    if (entries.length === 0) {
      await onIterationsChange(safeNew);
      Alert.alert("Profile Updated", `Now using ${PROFILES.find(p => p.iterations === safeNew)?.label}`);
      return;
    }

    setMigrating(true);
    try {
      const oldShares = keySharesRef.current!;
      const newShares = await deriveMasterKeyShares(piSeed, safeNew);

      for (const entry of entries) {
        const reEnc = reEncryptEntry(entry, oldShares, newShares);
        await saveEntry(reEnc);
      }
      for (const note of secureNotes) {
        const reEnc = reEncryptSecureNote(note, oldShares, newShares);
        await saveSecureNote(reEnc);
      }

      wipeShares(oldShares);
      keySharesRef.current = newShares;
      await onIterationsChange(safeNew);
      Alert.alert("Profile Changed", "All entries re-encrypted successfully.");
    } catch (err) {
      Alert.alert("Migration Failed", "Entries remain unchanged.");
    }
    setMigrating(false);
  }

  async function toggleKeyprints(value: boolean) {
    setShowKeyprints(value);
    await saveShowKeyprints(value);
  }

  function handleSettingsIconTap() {
    settingsTapCountRef.current += 1;
    if (settingsTapTimerRef.current) clearTimeout(settingsTapTimerRef.current);
    if (settingsTapCountRef.current >= 7) {
      settingsTapCountRef.current = 0;
      router.push("/debug");
      return;
    }
    settingsTapTimerRef.current = setTimeout(() => {
      settingsTapCountRef.current = 0;
      setShowSettings(true);
    }, 400);
  }

  const renderItem = ({ item }: { item: VaultEntry }) => (
    <Pressable onPress={() => handleSelectEntry(item)} style={{ padding: 16, borderBottomWidth: 1, borderBottomColor: "#222", flexDirection: "row", alignItems: "center" }}>
      {showKeyprints && <FractalKeyprint piSeed={piSeed} size={44} animate={false} />}
      <View style={{ marginLeft: 12, flex: 1 }}>
        <Text style={{ color: "#fff", fontSize: 18 }}>{item.title}</Text>
        <Text style={{ color: "#888" }}>{item.username}</Text>
      </View>
    </Pressable>
  );

  if (derivingKey) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <FractalKeyprint piSeed={piSeed} size={200} />
        <ActivityIndicator size="large" color="#4CAF50" style={{ marginTop: 30 }} />
        <Text style={{ color: "#fff", fontSize: 20, marginTop: 20 }}>Synchronizing Vault Geometry...</Text>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      {/* Header */}
      <View style={{ paddingTop: insets.top, padding: 16, flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
        <Text style={{ color: "#fff", fontSize: 28, fontWeight: "bold" }}>Vault</Text>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 20 }}>
          <Pressable onPress={() => setShowSecureNotes(true)}>
            <Ionicons name="help-circle-outline" size={26} color="#4CAF50" />
          </Pressable>
          <Pressable onPress={handleSettingsIconTap}>
            <Ionicons name="settings-outline" size={24} color="#fff" />
          </Pressable>
          <Pressable onPress={() => setShowAddModal(true)}>
            <Ionicons name="add-circle-outline" size={32} color="#fff" />
          </Pressable>
        </View>
      </View>

      <FlatList
        data={entries}
        keyExtractor={(item) => item.id}
        renderItem={renderItem}
        ListEmptyComponent={
          <View style={{ flex: 1, justifyContent: "center", alignItems: "center", marginTop: 100 }}>
            <FractalKeyprint piSeed={piSeed} size={150} animate={true} />
            <Text style={{ color: "#888", fontSize: 18, marginTop: 30 }}>Empty vault — add something!</Text>
          </View>
        }
      />

      <AddEntryModal visible={showAddModal} onClose={() => setShowAddModal(false)} onSave={handleAddEntry} />

      {selectedEntry && decryptedEntry && (
        <EntryDetailModal
          visible={true}
          entry={selectedEntry}
          decryptedEntry={decryptedEntry}
          decrypting={decrypting}
          piIndex={piSeed}
          onClose={handleCloseDetail}
          onDelete={() => handleDeleteEntry(selectedEntry.id)}
        />
      )}

      {keySharesRef.current && (
        <SecureNotesModal
          visible={showSecureNotes}
          notes={secureNotes}
          keyShares={keySharesRef.current}
          onClose={() => setShowSecureNotes(false)}
          onNotesChanged={() => {}}
          onActivity={resetActivity}
        />
      )}

      <KeyprintViewer visible={showKeyprintViewer} piSeed={piSeed} onClose={() => setShowKeyprintViewer(false)} />

      {/* FULL SETTINGS PANEL */}
      <Modal visible={showSettings} animationType="slide" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.9)", justifyContent: "flex-end" }}>
          <View style={{ backgroundColor: "#111", borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 20, paddingBottom: insets.bottom + 20 }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
              <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold" }}>Settings</Text>
              <Pressable onPress={() => setShowSettings(false)}>
                <Ionicons name="close" size={28} color="#666" />
              </Pressable>
            </View>

            {/* Security Profile */}
            <Text style={{ color: "#aaa", fontSize: 14, marginBottom: 12 }}>Security Profile</Text>
            {PROFILES.map((profile) => (
              <Pressable
                key={profile.iterations}
                onPress={() => handleProfileChange(profile.iterations)}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  backgroundColor: iterations === profile.iterations ? "#1a1a1a" : "#0a0a0a",
                  padding: 16,
                  borderRadius: 12,
                  marginBottom: 8,
                  borderWidth: iterations === profile.iterations ? 2 : 0,
                  borderColor: profile.color,
                }}
              >
                <Ionicons name={profile.icon} size={24} color={profile.color} />
                <View style={{ marginLeft: 16, flex: 1 }}>
                  <Text style={{ color: "#fff", fontSize: 18, fontWeight: "600" }}>{profile.label}</Text>
                  <Text style={{ color: "#888" }}>{profile.desc} • {profile.time}</Text>
                </View>
                {iterations === profile.iterations && <Ionicons name="checkmark-circle" size={24} color={profile.color} />}
              </Pressable>
            ))}

            {/* Show Keyprints Toggle */}
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginTop: 20, paddingVertical: 12 }}>
              <Text style={{ color: "#fff", fontSize: 18 }}>Show Fractal Keyprints</Text>
              <Switch
                value={showKeyprints}
                onValueChange={toggleKeyprints}
                trackColor={{ false: "#333", true: "#00ff9f" }}
                thumbColor={showKeyprints ? "#fff" : "#888"}
              />
            </View>

            {/* Lock Vault */}
            <Pressable onPress={onLock} style={{ backgroundColor: "#1a1a1a", padding: 16, borderRadius: 12, alignItems: "center", marginTop: 30 }}>
              <Ionicons name="lock-closed-outline" size={20} color="#ef4444" style={{ marginBottom: 6 }} />
              <Text style={{ color: "#ef4444", fontWeight: "600", fontSize: 16 }}>Lock Vault Now</Text>
            </Pressable>
          </View>
        </View>
      </Modal>
    </View>
  );
}