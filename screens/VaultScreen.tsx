import React, { useState, useEffect, useCallback, useRef } from "react";
import { View, Text, FlatList, Pressable, Alert, Platform, ActivityIndicator, AppState } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import { VaultEntry } from "../workers/vaultWorker";
import {
  encryptVaultEntry,
  decryptVaultEntry,
  deriveMasterKeyShares,
  DecryptedVaultEntry,
} from "../workers/vaultWorker";
import { KeyShares, wipeShares } from "../crypto/secureMemory";
import { requireFreshBiometric } from "../crypto/biometricGate";
import {
  getAllEntries,
  saveEntry,
  deleteEntry as deleteStoredEntry,
} from "../workers/storageWorker";
import AddEntryModal from "../components/AddEntryModal";
import EntryDetailModal from "../components/EntryDetailModal";
import FaviconImage from "../components/FaviconImage";

const AUTO_LOCK_MS = 60000;

interface VaultScreenProps {
  piSeed: number;
  onLock: () => void;
}

export default function VaultScreen({ piSeed, onLock }: VaultScreenProps) {
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
    try {
      const shares = deriveMasterKeyShares(piSeed);
      keySharesRef.current = shares;
    } catch (err) {
      console.error("Failed to derive master key:", err);
    }
    setDerivingKey(false);
    loadEntries();
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

  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    if (!derivingKey) {
      setElapsedSeconds(0);
      return;
    }
    setElapsedSeconds(0);
    const timer = setInterval(() => {
      setElapsedSeconds((s) => s + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [derivingKey]);

  if (derivingKey) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <ActivityIndicator size="large" color="#fff" />
        <Text style={{ color: "#fff", fontSize: 16, marginTop: 16 }}>Synchronizing Vault Geometry...</Text>
        <Text style={{ color: "#888", fontSize: 12, marginTop: 8, textAlign: "center", paddingHorizontal: 32 }}>
          Initializing entropy shards
        </Text>
        <Text style={{ color: "#fff", fontSize: 14, marginTop: 12 }}>
          {elapsedSeconds}s
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
        <Pressable onLongPress={() => router.push("/debug")} testID="vault-title">
          <Text style={{ color: "#fff", fontSize: 28, fontWeight: "bold" }}>Vault</Text>
        </Pressable>
        <Pressable onPress={() => setShowAddModal(true)} testID="add-entry-button">
          <Ionicons name="add-circle-outline" size={28} color="#fff" />
        </Pressable>
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
    </View>
  );
}
