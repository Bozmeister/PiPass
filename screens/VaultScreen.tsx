import React, { useState, useEffect, useCallback, useRef } from "react";
import { View, Text, FlatList, Pressable, Alert, Platform, ActivityIndicator, AppState, Modal, ScrollView, TextInput } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import * as FileSystem from "expo-file-system/legacy";
import * as Sharing from "expo-sharing";
import { VaultEntry } from "../workers/vaultWorker";
import {
  encryptVaultEntry,
  decryptVaultEntry,
  deriveMasterKeyShares,
  reEncryptEntry,
  DecryptedVaultEntry,
} from "../workers/vaultWorker";
import { KeyShares, wipeShares } from "../crypto/secureMemory";
import { requireFreshBiometric } from "../crypto/biometricGate";
import {
  getAllEntries,
  saveEntry,
  deleteEntry as deleteStoredEntry,
  clearVault,
  destroyAllData,
} from "../workers/storageWorker";
import AddEntryModal from "../components/AddEntryModal";
import EntryDetailModal from "../components/EntryDetailModal";
import FaviconImage from "../components/FaviconImage";

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
  const [loading, setLoading] = useState(true);
  const [derivingKey, setDerivingKey] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<VaultEntry | null>(null);
  const [decryptedEntry, setDecryptedEntry] = useState<DecryptedVaultEntry | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [migrationProgress, setMigrationProgress] = useState("");
  const [showNukeConfirm, setShowNukeConfirm] = useState(false);
  const [nukeInput, setNukeInput] = useState("");

  const lastActivityRef = useRef<number>(Date.now());
  const autoLockTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    initializeVault();

    autoLockTimerRef.current = setInterval(() => {
      if (Date.now() - lastActivityRef.current > AUTO_LOCK_MS) {
        if (keySharesRef.current) {
          wipeShares(keySharesRef.current);
          keySharesRef.current = null;
        }
        onLock();
      }
    }, 5000);

    const appStateSub = AppState.addEventListener("change", (state) => {
      if (state === "background" || state === "inactive") {
        if (keySharesRef.current) {
          wipeShares(keySharesRef.current);
          keySharesRef.current = null;
        }
        onLock();
      }
    });

    return () => {
      if (autoLockTimerRef.current) clearInterval(autoLockTimerRef.current);
      appStateSub.remove();
      if (keySharesRef.current) {
        wipeShares(keySharesRef.current);
        keySharesRef.current = null;
      }
    };
  }, []);

  function resetActivity() {
    lastActivityRef.current = Date.now();
  }

  function initializeVault() {
    setDerivingKey(true);
    setTimeout(async () => {
      try {
        const shares = deriveMasterKeyShares(piSeed, iterations);
        keySharesRef.current = shares;

        const stored = await getAllEntries();
        setEntries(stored);

        if (stored.length > 0) {
          try {
            decryptVaultEntry(stored[0], shares);
          } catch {
            console.log("Key mismatch with stored profile, trying fallback iterations...");
            const allIterations = [25000, 100000, 250000].filter(i => i !== iterations);
            let found = false;
            for (const fallbackIter of allIterations) {
              try {
                const fallbackShares = deriveMasterKeyShares(piSeed, fallbackIter);
                decryptVaultEntry(stored[0], fallbackShares);
                wipeShares(shares);
                keySharesRef.current = fallbackShares;
                await onIterationsChange(fallbackIter);
                found = true;
                console.log("Recovered with iteration count:", fallbackIter);
                break;
              } catch {
                continue;
              }
            }
            if (!found) {
              console.error("Could not find matching key for stored entries");
            }
          }
        }
      } catch (err) {
        console.error("Failed to derive master key:", err);
      }
      setDerivingKey(false);
    }, 100);
  }

  async function loadEntries() {
    setLoading(true);
    try {
      const stored = await getAllEntries();
      setEntries(stored);
    } catch (err) {
      console.error("Failed to load entries:", err);
    }
    setLoading(false);
  }

  async function handleAddEntry(entry: {
    title: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
  }) {
    resetActivity();
    if (!keySharesRef.current) {
      throw new Error("Vault key not ready. Please restart the app.");
    }

    try {
      const encrypted = encryptVaultEntry(entry, keySharesRef.current);
      await saveEntry(encrypted);
      await loadEntries();
      setShowAddModal(false);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("handleAddEntry failed:", message);
      throw err;
    }
  }

  async function handleProfileChange(newIterations: number) {
    resetActivity();
    if (newIterations === iterations) return;
    if (!keySharesRef.current) return;

    const entryCount = entries.length;
    if (entryCount === 0) {
      onIterationsChange(newIterations);
      const label = PROFILES.find(p => p.iterations === newIterations)?.label || "Updated";
      if (Platform.OS === "web") {
        alert(`Security profile changed to ${label}. Will take effect on next unlock.`);
      } else {
        Alert.alert("Profile Updated", `Security set to ${label}. Will take effect on next unlock.`);
      }
      return;
    }

    const oldShares = keySharesRef.current!;
    try {
      decryptVaultEntry(entries[0], oldShares);
    } catch {
      const msg = "Current key cannot decrypt your entries. Please lock and re-unlock the vault before changing profiles.";
      if (Platform.OS === "web") {
        alert(msg);
      } else {
        Alert.alert("Key Mismatch", msg);
      }
      return;
    }

    setMigrating(true);
    setMigrationProgress("Deriving new key...");

    setTimeout(() => {
      try {
        const newShares = deriveMasterKeyShares(piSeed, newIterations);
        const updatedEntries: VaultEntry[] = [];

        for (let i = 0; i < entries.length; i++) {
          setMigrationProgress(`Re-encrypting ${i + 1} of ${entryCount}...`);
          const reEncrypted = reEncryptEntry(entries[i], oldShares, newShares);
          updatedEntries.push(reEncrypted);
        }

        setMigrationProgress("Saving entries...");

        (async () => {
          try {
            for (const entry of updatedEntries) {
              await saveEntry(entry);
            }
            wipeShares(oldShares);
            keySharesRef.current = newShares;
            await onIterationsChange(newIterations);
            await loadEntries();
            setMigrating(false);
            setMigrationProgress("");
            const label = PROFILES.find(p => p.iterations === newIterations)?.label || "Updated";
            if (Platform.OS === "web") {
              alert(`Migrated ${entryCount} entries to ${label} profile.`);
            } else {
              Alert.alert("Migration Complete", `${entryCount} entries re-encrypted with ${label} profile.`);
            }
          } catch (err) {
            console.error("Migration save failed:", err);
            setMigrating(false);
            setMigrationProgress("");
            if (Platform.OS === "web") {
              alert("Migration failed while saving. Your entries are unchanged.");
            } else {
              Alert.alert("Migration Failed", "Could not save re-encrypted entries. Your vault is unchanged.");
            }
          }
        })();
      } catch (err) {
        console.error("Migration failed:", err);
        setMigrating(false);
        setMigrationProgress("");
        const errMsg = err instanceof Error ? err.message : "Unknown error";
        if (Platform.OS === "web") {
          alert("Migration failed: " + errMsg);
        } else {
          Alert.alert("Migration Failed", errMsg);
        }
      }
    }, 100);
  }

  async function handleDeleteEntry(id: string) {
    const doDelete = async () => {
      await deleteStoredEntry(id);
      await loadEntries();
      setSelectedEntry(null);
      setDecryptedEntry(null);
    };

    if (Platform.OS === "web") {
      if (confirm("Delete this entry?")) {
        await doDelete();
      }
    } else {
      Alert.alert("Delete Entry", "Are you sure you want to delete this entry?", [
        { text: "Cancel", style: "cancel" },
        { text: "Delete", style: "destructive", onPress: doDelete },
      ]);
    }
  }

  async function handleSelectEntry(entry: VaultEntry) {
    resetActivity();
    if (!keySharesRef.current) return;

    setSelectedEntry(entry);
    setDecryptedEntry(null);
    setDecrypting(true);

    try {
      const bioResult = await requireFreshBiometric();
      console.log("[VaultScreen] biometric result:", bioResult);
      if (!bioResult) {
        setDecrypting(false);
        if (Platform.OS === "web") {
          alert("Authentication required to view passwords.");
        } else {
          Alert.alert("Authentication Required", "Biometric verification failed. Cannot decrypt entry.");
        }
        return;
      }

      const decrypted = decryptVaultEntry(entry, keySharesRef.current);
      setDecryptedEntry(decrypted);
    } catch (err: any) {
      console.error("Decryption failed:", err);
      setDecryptedEntry(null);
      const msg = err?.message || "Unknown error";
      if (Platform.OS === "web") {
        alert("Decryption error: " + msg);
      } else {
        Alert.alert("Decryption Error", msg);
      }
    }
    setDecrypting(false);
  }

  function handleCloseDetail() {
    setSelectedEntry(null);
    setDecryptedEntry(null);
  }

  const webTopInset = Platform.OS === "web" ? 67 : 0;

  const renderItem = useCallback(
    ({ item }: { item: VaultEntry }) => (
      <Pressable
        onPress={() => handleSelectEntry(item)}
        style={{
          paddingVertical: 14,
          paddingHorizontal: 16,
          borderBottomWidth: 1,
          borderBottomColor: "#222",
          flexDirection: "row",
          alignItems: "center",
        }}
      >
        <FaviconImage url={item.url} size={28} />
        <View style={{ marginLeft: 12, flex: 1 }}>
          <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" }}>{item.title}</Text>
          <Text style={{ color: "#888", fontSize: 13, marginTop: 2 }}>{item.username}</Text>
        </View>
        <Ionicons name="chevron-forward" size={18} color="#555" />
      </Pressable>
    ),
    []
  );

  if (derivingKey) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <ActivityIndicator size="large" color="#fff" />
        <Text style={{ color: "#fff", fontSize: 16, marginTop: 16 }}>Synchronizing Vault Geometry...</Text>
        <Text style={{ color: "#888", fontSize: 12, marginTop: 8, textAlign: "center", paddingHorizontal: 32 }}>
          Initializing entropy shards
        </Text>
      </View>
    );
  }

  if (migrating) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <ActivityIndicator size="large" color="#fbbf24" />
        <Text style={{ color: "#fff", fontSize: 16, marginTop: 16 }}>Migrating Vault...</Text>
        <Text style={{ color: "#888", fontSize: 13, marginTop: 8, textAlign: "center", paddingHorizontal: 32 }}>
          {migrationProgress}
        </Text>
        <Text style={{ color: "#666", fontSize: 11, marginTop: 12, textAlign: "center", paddingHorizontal: 40 }}>
          Do not close the app. Your entries are being re-encrypted with the new security profile.
        </Text>
      </View>
    );
  }

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <Text style={{ color: "#fff", fontSize: 16 }}>Loading vault...</Text>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      <View
        style={{
          paddingTop: insets.top + webTopInset,
          paddingHorizontal: 16,
          paddingBottom: 12,
          flexDirection: "row",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Pressable
          onLongPress={() => router.push("/debug")}
          delayLongPress={600}
          hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
          testID="vault-title"
          style={{ paddingVertical: 4, paddingRight: 16 }}
        >
          <Text style={{ color: "#fff", fontSize: 28, fontWeight: "bold" }}>Vault</Text>
        </Pressable>
        <View style={{ flexDirection: "row", alignItems: "center" }}>
          <Pressable onPress={() => setShowSettings(true)} testID="settings-button" style={{ marginRight: 16 }}>
            <Ionicons name="settings-outline" size={24} color="#fff" />
          </Pressable>
          <Pressable onPress={() => setShowAddModal(true)} testID="add-entry-button">
            <Ionicons name="add-circle-outline" size={28} color="#fff" />
          </Pressable>
        </View>
      </View>

      {entries.length === 0 ? (
        <View style={{ flex: 1, justifyContent: "center", alignItems: "center", padding: 32 }}>
          <Ionicons name="shield-checkmark-outline" size={48} color="#555" />
          <Text style={{ color: "#888", fontSize: 16, marginTop: 16, textAlign: "center" }}>
            No entries yet. Tap + to add your first password.
          </Text>
        </View>
      ) : (
        <FlatList
          data={entries}
          keyExtractor={(item) => item.id}
          renderItem={renderItem}
          scrollEnabled={!!entries.length}
          contentContainerStyle={{
            paddingBottom: insets.bottom + (Platform.OS === "web" ? 34 : 0),
          }}
        />
      )}

      <AddEntryModal
        visible={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSave={handleAddEntry}
      />

      {selectedEntry && (
        <EntryDetailModal
          visible={!!selectedEntry}
          entry={selectedEntry}
          decryptedEntry={decryptedEntry}
          decrypting={decrypting}
          piIndex={piSeed}
          onClose={handleCloseDetail}
          onDelete={() => handleDeleteEntry(selectedEntry.id)}
        />
      )}

      <Modal visible={showSettings} animationType="slide" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.85)", justifyContent: "flex-end" }}>
          <View style={{
            backgroundColor: "#111",
            borderTopLeftRadius: 20,
            borderTopRightRadius: 20,
            paddingTop: 16,
            paddingBottom: insets.bottom + (Platform.OS === "web" ? 34 : 16),
            paddingHorizontal: 20,
            maxHeight: "80%",
          }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <Text style={{ color: "#fff", fontSize: 20, fontWeight: "bold" }}>Settings</Text>
              <Pressable onPress={() => setShowSettings(false)} testID="close-settings">
                <Ionicons name="close-circle" size={28} color="#555" />
              </Pressable>
            </View>

            <ScrollView>
              <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 10 }}>
                Security Profile
              </Text>
              <Text style={{ color: "#666", fontSize: 12, marginBottom: 14, lineHeight: 18 }}>
                Controls the number of key-stretching rounds. Higher = slower unlock but harder to brute-force. Changes take effect on next unlock.
              </Text>

              {PROFILES.map((profile) => {
                const selected = iterations === profile.iterations;
                return (
                  <Pressable
                    key={profile.label}
                    onPress={() => {
                      setShowSettings(false);
                      handleProfileChange(profile.iterations);
                    }}
                    style={{
                      flexDirection: "row",
                      alignItems: "center",
                      backgroundColor: selected ? "#1a1a2e" : "#181818",
                      borderRadius: 10,
                      padding: 14,
                      marginBottom: 10,
                      borderWidth: 2,
                      borderColor: selected ? profile.color : "#222",
                    }}
                    testID={`settings-profile-${profile.label.toLowerCase().replace(" ", "-")}`}
                  >
                    <View style={{
                      width: 22,
                      height: 22,
                      borderRadius: 11,
                      borderWidth: 2,
                      borderColor: selected ? profile.color : "#555",
                      alignItems: "center",
                      justifyContent: "center",
                      marginRight: 12,
                    }}>
                      {selected && (
                        <View style={{
                          width: 12,
                          height: 12,
                          borderRadius: 6,
                          backgroundColor: profile.color,
                        }} />
                      )}
                    </View>
                    <Ionicons name={profile.icon} size={20} color={selected ? profile.color : "#666"} style={{ marginRight: 10 }} />
                    <View style={{ flex: 1 }}>
                      <View style={{ flexDirection: "row", alignItems: "center" }}>
                        <Text style={{ color: selected ? "#fff" : "#aaa", fontSize: 15, fontWeight: "700" }}>
                          {profile.label}
                        </Text>
                        {profile.label === "Fortress" && (
                          <View style={{ backgroundColor: "#fbbf2433", borderRadius: 4, paddingHorizontal: 6, paddingVertical: 1, marginLeft: 8 }}>
                            <Text style={{ color: "#fbbf24", fontSize: 10, fontWeight: "700" }}>DEFAULT</Text>
                          </View>
                        )}
                      </View>
                      <Text style={{ color: "#888", fontSize: 12, marginTop: 2 }}>
                        {profile.desc}
                      </Text>
                    </View>
                    <View style={{ alignItems: "flex-end" }}>
                      <Text style={{ color: selected ? profile.color : "#666", fontSize: 13, fontWeight: "600" }}>
                        {profile.time}
                      </Text>
                      <Text style={{ color: "#555", fontSize: 10 }}>
                        {(profile.iterations / 1000).toFixed(0)}k rounds
                      </Text>
                    </View>
                  </Pressable>
                );
              })}

              <Pressable
                onPress={onLock}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  justifyContent: "center",
                  backgroundColor: "#1a1a1a",
                  borderRadius: 10,
                  padding: 14,
                  marginTop: 16,
                  borderWidth: 1,
                  borderColor: "#333",
                }}
                testID="lock-vault-button"
              >
                <Ionicons name="lock-closed-outline" size={18} color="#ef4444" style={{ marginRight: 8 }} />
                <Text style={{ color: "#ef4444", fontSize: 15, fontWeight: "600" }}>Lock Vault</Text>
              </Pressable>

              <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginTop: 24, marginBottom: 10 }}>
                Backup & Recovery
              </Text>

              <Pressable
                onPress={async () => {
                  resetActivity();
                  if (entries.length === 0) {
                    if (Platform.OS === "web") {
                      alert("No entries to export.");
                    } else {
                      Alert.alert("Empty Vault", "There are no entries to export.");
                    }
                    return;
                  }
                  try {
                    const backup = {
                      version: 1,
                      exportedAt: new Date().toISOString(),
                      entries: entries,
                    };
                    const json = JSON.stringify(backup, null, 2);
                    const date = new Date().toISOString().split("T")[0];
                    const filename = `pipass_backup_${date}.vault`;

                    if (Platform.OS === "web") {
                      const blob = new Blob([json], { type: "application/json" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = filename;
                      a.click();
                      URL.revokeObjectURL(url);
                      alert("Backup downloaded.");
                    } else {
                      const path = FileSystem.documentDirectory + filename;
                      await FileSystem.writeAsStringAsync(path, json, { encoding: FileSystem.EncodingType.UTF8 });
                      const canShare = await Sharing.isAvailableAsync();
                      if (canShare) {
                        await Sharing.shareAsync(path, { mimeType: "application/json", dialogTitle: "Export Encrypted Backup" });
                      } else {
                        Alert.alert("Exported", `Backup saved to ${filename}`);
                      }
                    }
                  } catch (err) {
                    console.error("Export failed:", err);
                    if (Platform.OS === "web") {
                      alert("Export failed.");
                    } else {
                      Alert.alert("Export Failed", "Could not create backup file.");
                    }
                  }
                }}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  justifyContent: "center",
                  backgroundColor: "#0a1a1a",
                  borderRadius: 10,
                  padding: 14,
                  borderWidth: 1,
                  borderColor: "#114a4a",
                }}
                testID="export-backup-button"
              >
                <Ionicons name="download-outline" size={18} color="#4CAF50" style={{ marginRight: 8 }} />
                <Text style={{ color: "#4CAF50", fontSize: 15, fontWeight: "600" }}>Export Encrypted Backup</Text>
              </Pressable>

              <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginTop: 24, marginBottom: 10 }}>
                Danger Zone
              </Text>

              <Pressable
                onPress={async () => {
                  resetActivity();
                  const bioResult = await requireFreshBiometric();
                  if (!bioResult) {
                    if (Platform.OS === "web") {
                      alert("Authentication required.");
                    } else {
                      Alert.alert("Authentication Required", "Biometric verification failed.");
                    }
                    return;
                  }
                  setShowSettings(false);
                  setNukeInput("");
                  setShowNukeConfirm(true);
                }}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  justifyContent: "center",
                  backgroundColor: "#2a0a0a",
                  borderRadius: 10,
                  padding: 14,
                  marginTop: 4,
                  borderWidth: 2,
                  borderColor: "#8b0000",
                }}
                testID="nuke-vault-button"
              >
                <Ionicons name="nuclear-outline" size={20} color="#ff3333" style={{ marginRight: 8 }} />
                <Text style={{ color: "#ff3333", fontSize: 15, fontWeight: "800" }}>Destroy All Vault Data</Text>
              </Pressable>
            </ScrollView>
          </View>
        </View>
      </Modal>

      <Modal visible={showNukeConfirm} animationType="fade" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.9)", justifyContent: "center", alignItems: "center", paddingHorizontal: 24 }}>
          <View style={{
            backgroundColor: "#1a0a0a",
            borderRadius: 16,
            padding: 24,
            width: "100%",
            maxWidth: 360,
            borderWidth: 2,
            borderColor: "#8b0000",
          }}>
            <View style={{ alignItems: "center", marginBottom: 16 }}>
              <Ionicons name="warning" size={48} color="#ff3333" />
              <Text style={{ color: "#ff3333", fontSize: 20, fontWeight: "800", marginTop: 12, textAlign: "center" }}>
                PERMANENT DESTRUCTION
              </Text>
            </View>
            <Text style={{ color: "#ccc", fontSize: 14, lineHeight: 20, textAlign: "center", marginBottom: 20 }}>
              This will permanently erase ALL vault entries, your Pi Seed, and all settings. This action cannot be undone. The app will restart from scratch.
            </Text>
            <Text style={{ color: "#888", fontSize: 12, marginBottom: 8 }}>
              Type DELETE to confirm:
            </Text>
            <TextInput
              value={nukeInput}
              onChangeText={setNukeInput}
              placeholder="Type DELETE"
              placeholderTextColor="#555"
              autoCapitalize="characters"
              style={{
                color: "#ff3333",
                fontSize: 18,
                fontWeight: "700",
                backgroundColor: "#0a0a0a",
                borderRadius: 8,
                padding: 14,
                textAlign: "center",
                letterSpacing: 6,
                borderWidth: 1,
                borderColor: nukeInput === "DELETE" ? "#ff3333" : "#333",
                marginBottom: 20,
              }}
              testID="nuke-confirm-input"
            />
            <Pressable
              onPress={async () => {
                if (nukeInput !== "DELETE") return;
                try {
                  if (keySharesRef.current) {
                    wipeShares(keySharesRef.current);
                    keySharesRef.current = null;
                  }
                  await destroyAllData();
                  setShowNukeConfirm(false);
                  onReset();
                } catch (err) {
                  console.error("Nuclear wipe failed:", err);
                }
              }}
              disabled={nukeInput !== "DELETE"}
              style={{
                backgroundColor: nukeInput === "DELETE" ? "#8b0000" : "#333",
                paddingVertical: 14,
                borderRadius: 8,
                alignItems: "center",
                marginBottom: 10,
              }}
              testID="nuke-final-confirm"
            >
              <Text style={{ color: "#fff", fontSize: 16, fontWeight: "800" }}>
                DESTROY EVERYTHING
              </Text>
            </Pressable>
            <Pressable
              onPress={() => { setShowNukeConfirm(false); setNukeInput(""); }}
              style={{ paddingVertical: 10, alignItems: "center" }}
              testID="nuke-cancel"
            >
              <Text style={{ color: "#888", fontSize: 14 }}>Cancel</Text>
            </Pressable>
          </View>
        </View>
      </Modal>
    </View>
  );
}
