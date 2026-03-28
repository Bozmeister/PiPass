import React, { useState, useEffect, useRef } from "react";
import { 
  View, Text, FlatList, Pressable, Alert, Platform, 
  ActivityIndicator, AppState, Modal, Switch, TextInput 
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import * as ScreenCapture from "expo-screen-capture";
import { 
  VaultEntry, 
  SecureNote, 
  DecryptedVaultEntry,
  encryptVaultEntry,
  decryptVaultEntry,
  reEncryptEntry,
  reEncryptSecureNote,
  deriveMasterKeyShares,
} from "../workers/vaultWorker";

import { 
  getAllEntries, 
  saveEntry, 
  deleteEntry as deleteStoredEntry, 
  destroyAllData, 
  saveSecureNote,
  getAllSecureNotes,
  getShowKeyprints, 
  saveShowKeyprints,
  getMasterSalt,
  saveMasterKeyHash,
  saveFractalFingerprint,
  getFractalFingerprint,
  FractalFingerprintRecord,
} from "../workers/storageWorker";

import { KeyShares, wipeShares, combineShares, hexToBytes, wipeBuffer } from "../crypto/secureMemory";
import { hashMasterKey } from "../crypto/keyDerivation";
import { requireFreshBiometric } from "../crypto/biometricGate";
import { sanitizeEntryFields } from "../crypto/hyperbaricSanitizer";
import { deriveFractalSeed } from "../crypto/hkdf";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_FOCUS } from "../styles/inputTheme";

import AddEntryModal from "../components/AddEntryModal";
import EntryDetailModal from "../components/EntryDetailModal";
import SecureNotesModal from "../components/SecureNotesModal";
import FractalKeyprint from "../components/FractalKeyprint";
import KeyprintViewer from "../components/KeyprintViewer";
import FaviconImage from "../components/FaviconImage";

const AUTO_LOCK_MS = 60000;

const PROFILES = [
  { label: "Balanced", iterations: 25000, time: "~3s", desc: "Fast unlock", color: "#4CAF50", icon: "flash-outline" as const },
  { label: "Fortress", iterations: 100000, time: "~8s", desc: "Recommended", color: "#fbbf24", icon: "shield-checkmark-outline" as const },
  { label: "Deep Vault", iterations: 250000, time: "~20s", desc: "Maximum protection", color: "#ef4444", icon: "lock-closed-outline" as const },
];

interface VaultScreenProps {
  keyShares: KeyShares;
  iterations: number;
  onLock: () => void;
  onIterationsChange: (iterations: number) => void;
  onReset: () => void;
}

function deriveVisualSeedFromHkdf(shares: KeyShares): { seedNumber: number; fingerprint: string } {
  const keyHex = combineShares(shares);
  const result = deriveFractalSeed(keyHex);
  const keyBytes = hexToBytes(keyHex);
  wipeBuffer(keyBytes);
  return result;
}

export default function VaultScreen({ keyShares, iterations, onLock, onIterationsChange, onReset }: VaultScreenProps) {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const keySharesRef = useRef<KeyShares>(keyShares);
  const isBiometricActive = useRef(false);

  const [loading, setLoading] = useState(true);
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
  const [pendingProfileIterations, setPendingProfileIterations] = useState<number | null>(null);
  const [profilePassword, setProfilePassword] = useState("");
  const [profilePasswordFocused, setProfilePasswordFocused] = useState(false);

  const settingsTapCountRef = useRef(0);
  const settingsTapTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lastActivityRef = useRef<number>(Date.now());
  const autoLockTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const selectTokenRef = useRef<number>(0);

  const initialFractal = useRef(deriveVisualSeedFromHkdf(keyShares)).current;
  const [fractalSeedNumber, setFractalSeedNumber] = useState(initialFractal.seedNumber);
  const [fractalFingerprint, setFractalFingerprint] = useState(initialFractal.fingerprint);
  const visualSeed = fractalSeedNumber;
  const [fractalTampered, setFractalTampered] = useState(false);

  useEffect(() => {
    keySharesRef.current = keyShares;
  }, [keyShares]);

  useEffect(() => {
    verifyFractalFingerprint(fractalFingerprint);
  }, []);

  function buildFingerprintRecord(fp: string): FractalFingerprintRecord {
    return { fingerprint: fp, iterations, kdf: "argon2id", version: 1 };
  }

  async function verifyFractalFingerprint(currentFingerprint: string) {
    const stored = await getFractalFingerprint();
    if (stored === null) {
      await saveFractalFingerprint(buildFingerprintRecord(currentFingerprint));
    } else if (typeof stored === "string") {
      if (stored !== currentFingerprint) {
        setFractalTampered(true);
      } else {
        await saveFractalFingerprint(buildFingerprintRecord(currentFingerprint));
      }
    } else {
      const current = buildFingerprintRecord(currentFingerprint);
      if (
        stored.fingerprint !== current.fingerprint ||
        stored.iterations !== current.iterations ||
        stored.kdf !== current.kdf ||
        stored.version !== current.version
      ) {
        setFractalTampered(true);
      }
    }
  }

  function refreshFractalFromShares(shares: KeyShares) {
    const result = deriveVisualSeedFromHkdf(shares);
    setFractalSeedNumber(result.seedNumber);
    setFractalFingerprint(result.fingerprint);
    return result;
  }

  useEffect(() => {
    if (Platform.OS !== "web") ScreenCapture.preventScreenCaptureAsync();
    return () => { if (Platform.OS !== "web") ScreenCapture.allowScreenCaptureAsync(); };
  }, []);

  useEffect(() => {
    loadVault();
    const appStateSub = AppState.addEventListener("change", (state) => {
      if ((state === "background" || state === "inactive") && !isBiometricActive.current) {
        onLock();
      }
    });
    return () => {
      if (autoLockTimerRef.current) clearInterval(autoLockTimerRef.current);
      appStateSub.remove();
    };
  }, []);

  function resetActivity() { lastActivityRef.current = Date.now(); }

  async function loadVault() {
    try {
      const keyprintPref = await getShowKeyprints();
      setShowKeyprints(keyprintPref);

      const stored = await getAllEntries();
      setEntries(stored);

      const notes = await getAllSecureNotes();
      setSecureNotes(notes);

      if (stored.length > 0) {
        try {
          decryptVaultEntry(stored[0], keySharesRef.current);
        } catch {
          Alert.alert("Key Mismatch", "The stored entries don't match your current key. Clear & Start Fresh?", [
            { text: "Clear", style: "destructive", onPress: async () => { await destroyAllData(); onReset(); } }
          ]);
        }
      }
    } catch (err) {
      console.error("Vault load error:", err);
      Alert.alert("Error", "Failed to load vault.", [
        { text: "Try Again", onPress: () => loadVault() },
        { text: "Wipe Data", style: "destructive", onPress: async () => { await destroyAllData(); onReset(); } },
      ]);
    }
    setLoading(false);
    resetActivity();

    autoLockTimerRef.current = setInterval(() => {
      if (Date.now() - lastActivityRef.current > AUTO_LOCK_MS) onLock();
    }, 5000);
  }

  async function handleAddEntry(entry: any) {
    if (!keySharesRef.current) return;

    const { sanitized, ok, error } = sanitizeEntryFields(entry);
    if (!ok) {
      Alert.alert("Sanitization Error", error || "Input rejected.");
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
    setPendingProfileIterations(safeNew);
    setProfilePassword("");
  }

  async function confirmProfileChange() {
    if (!pendingProfileIterations || !profilePassword.trim()) return;

    setMigrating(true);
    try {
      const salt = await getMasterSalt();
      if (!salt) throw new Error("No salt found");

      const newShares = await deriveMasterKeyShares(profilePassword, salt, pendingProfileIterations);
      const newKeyHex = combineShares(newShares);
      const newKeyHash = hashMasterKey(newKeyHex);

      await saveMasterKeyHash(newKeyHash);
      await onIterationsChange(pendingProfileIterations);

      const newKeyBytes = hexToBytes(newKeyHex);
      wipeBuffer(newKeyBytes);

      keySharesRef.current = newShares;

      const newFractal = refreshFractalFromShares(newShares);
      await saveFractalFingerprint({ fingerprint: newFractal.fingerprint, iterations: pendingProfileIterations, kdf: "argon2id", version: 1 });
      setFractalTampered(false);

      setPendingProfileIterations(null);
      setProfilePassword("");
      Alert.alert("Profile Updated", `Now using ${PROFILES.find(p => p.iterations === pendingProfileIterations)?.label || "custom"} profile.`);
    } catch (err) {
      Alert.alert("Migration Failed", "Incorrect password or key derivation error. Settings remain unchanged.");
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

  const webTopInset = Platform.OS === "web" ? 67 : 0;

  const renderItem = ({ item }: { item: VaultEntry }) => (
    <Pressable onPress={() => handleSelectEntry(item)} style={{ padding: 16, borderBottomWidth: 1, borderBottomColor: "#222", flexDirection: "row", alignItems: "center" }}>
      {showKeyprints ? (
        <FractalKeyprint seed={visualSeed} size={44} animate={false} />
      ) : (
        <FaviconImage url={item.url} size={32} />
      )}
      <View style={{ marginLeft: 12, flex: 1 }}>
        <Text style={{ color: "#fff", fontSize: 18 }}>{item.title}</Text>
        <Text style={{ color: "#888" }}>{item.username}</Text>
      </View>
    </Pressable>
  );

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <FractalKeyprint seed={visualSeed} size={200} />
        <ActivityIndicator size="large" color="#4CAF50" style={{ marginTop: 30 }} />
        <Text style={{ color: "#fff", fontSize: 20, marginTop: 20 }}>Loading Vault...</Text>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      <View style={{ paddingTop: insets.top + webTopInset, padding: 16, flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
        <Text style={{ color: "#fff", fontSize: 28, fontWeight: "bold" as const }}>Vault</Text>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 20 }}>
          <Pressable onPress={() => setShowSecureNotes(true)}>
            <Ionicons name="document-lock-outline" size={24} color="#4CAF50" />
          </Pressable>
          <Pressable onPress={handleSettingsIconTap}>
            <Ionicons name="settings-outline" size={24} color="#fff" />
          </Pressable>
          <Pressable onPress={() => setShowAddModal(true)}>
            <Ionicons name="add-circle-outline" size={32} color="#fff" />
          </Pressable>
        </View>
      </View>

      {fractalTampered && (
        <View style={{
          backgroundColor: "#3a0a0a",
          borderWidth: 1,
          borderColor: "#ef4444",
          borderRadius: 10,
          marginHorizontal: 16,
          marginBottom: 8,
          padding: 14,
          flexDirection: "row",
          alignItems: "center",
        }}>
          <Ionicons name="warning" size={22} color="#ef4444" style={{ marginRight: 10 }} />
          <View style={{ flex: 1 }}>
            <Text style={{ color: "#ef4444", fontSize: 14, fontWeight: "700" as const }}>
              Fractal Fingerprint Changed
            </Text>
            <Text style={{ color: "#cc8888", fontSize: 12, marginTop: 2 }}>
              Your vault's visual identity has changed unexpectedly. This may indicate key derivation tampering.
            </Text>
          </View>
        </View>
      )}

      <FlatList
        data={entries}
        keyExtractor={(item) => item.id}
        renderItem={renderItem}
        ListEmptyComponent={
          <View style={{ flex: 1, justifyContent: "center", alignItems: "center", marginTop: 100 }}>
            <FractalKeyprint seed={visualSeed} size={150} animate={true} />
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
          visualSeed={visualSeed}
          onClose={handleCloseDetail}
          onDelete={() => handleDeleteEntry(selectedEntry.id)}
        />
      )}

      <SecureNotesModal
        visible={showSecureNotes}
        notes={secureNotes}
        keyShares={keySharesRef.current}
        onClose={() => setShowSecureNotes(false)}
        onNotesChanged={async () => {
          const notes = await getAllSecureNotes();
          setSecureNotes(notes);
        }}
        onActivity={resetActivity}
      />

      <KeyprintViewer visible={showKeyprintViewer} seed={visualSeed} onClose={() => setShowKeyprintViewer(false)} />

      <Modal visible={showSettings} animationType="slide" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.9)", justifyContent: "flex-end" }}>
          <View style={{ backgroundColor: "#111", borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 20, paddingBottom: insets.bottom + 20 }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
              <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold" as const }}>Settings</Text>
              <Pressable onPress={() => setShowSettings(false)}>
                <Ionicons name="close" size={28} color="#666" />
              </Pressable>
            </View>

            <Text style={{ color: "#aaa", fontSize: 14, marginBottom: 12 }}>Security Profile</Text>
            {PROFILES.map((profile) => (
              <Pressable
                key={profile.iterations}
                onPress={() => handleProfileChange(profile.iterations)}
                disabled={migrating}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  backgroundColor: iterations === profile.iterations ? "#1a1a1a" : "#0a0a0a",
                  padding: 16,
                  borderRadius: 12,
                  marginBottom: 8,
                  borderWidth: iterations === profile.iterations ? 2 : 0,
                  borderColor: profile.color,
                  opacity: migrating ? 0.5 : 1,
                }}
              >
                <Ionicons name={profile.icon} size={24} color={profile.color} />
                <View style={{ marginLeft: 16, flex: 1 }}>
                  <Text style={{ color: "#fff", fontSize: 18, fontWeight: "600" as const }}>{profile.label}</Text>
                  <Text style={{ color: "#888" }}>{profile.desc} {profile.time}</Text>
                </View>
                {iterations === profile.iterations && <Ionicons name="checkmark-circle" size={24} color={profile.color} />}
              </Pressable>
            ))}

            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginTop: 20, paddingVertical: 12 }}>
              <Text style={{ color: "#fff", fontSize: 18 }}>Show Fractal Keyprints</Text>
              <Switch
                value={showKeyprints}
                onValueChange={toggleKeyprints}
                trackColor={{ false: "#333", true: "#00ff9f" }}
                thumbColor={showKeyprints ? "#fff" : "#888"}
              />
            </View>

            <Pressable onPress={onLock} style={{ backgroundColor: "#1a1a1a", padding: 16, borderRadius: 12, alignItems: "center", marginTop: 30 }}>
              <Ionicons name="lock-closed-outline" size={20} color="#ef4444" style={{ marginBottom: 6 }} />
              <Text style={{ color: "#ef4444", fontWeight: "600" as const, fontSize: 16 }}>Lock Vault Now</Text>
            </Pressable>
          </View>
        </View>
      </Modal>

      <Modal visible={pendingProfileIterations !== null} animationType="fade" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.9)", justifyContent: "center", alignItems: "center", padding: 24 }}>
          <View style={{ backgroundColor: "#111", borderRadius: 16, padding: 24, width: "100%", maxWidth: 400 }}>
            <Text style={{ color: "#fff", fontSize: 20, fontWeight: "bold" as const, marginBottom: 8 }}>
              Confirm Password
            </Text>
            <Text style={{ color: "#aaa", fontSize: 14, marginBottom: 20 }}>
              Enter your master password to change the security profile. Your key will be re-derived with the new settings.
            </Text>
            <TextInput
              value={profilePassword}
              onChangeText={setProfilePassword}
              placeholder="Master password"
              placeholderTextColor={INPUT_PLACEHOLDER}
              secureTextEntry
              autoCapitalize="none"
              autoCorrect={false}
              onFocus={() => setProfilePasswordFocused(true)}
              onBlur={() => setProfilePasswordFocused(false)}
              style={{ color: INPUT_TEXT, fontSize: 16, padding: 14, backgroundColor: INPUT_BG, borderRadius: 8, borderWidth: 1, borderColor: profilePasswordFocused ? INPUT_BORDER_FOCUS : INPUT_BORDER, marginBottom: 16 }}
              testID="profile-password-input"
            />
            {migrating && (
              <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 16 }}>
                <ActivityIndicator color="#4CAF50" />
                <Text style={{ color: "#aaa", marginLeft: 12, fontSize: 14 }}>Re-deriving key...</Text>
              </View>
            )}
            <View style={{ flexDirection: "row", gap: 12 }}>
              <Pressable
                onPress={() => { setPendingProfileIterations(null); setProfilePassword(""); }}
                disabled={migrating}
                style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: "#1a1a1a", alignItems: "center" }}
              >
                <Text style={{ color: "#aaa", fontSize: 16 }}>Cancel</Text>
              </Pressable>
              <Pressable
                onPress={confirmProfileChange}
                disabled={!profilePassword.trim() || migrating}
                style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: profilePassword.trim() && !migrating ? "#4CAF50" : "#333", alignItems: "center" }}
              >
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Confirm</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}
