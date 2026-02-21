import React, { useState, useEffect, useCallback } from "react";
import { View, Text, FlatList, Pressable, Alert, Platform, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { VaultEntry } from "../workers/vaultWorker";
import {
  encryptVaultEntry,
  decryptVaultEntry,
  deriveMasterKey,
  DecryptedVaultEntry,
} from "../workers/vaultWorker";
import {
  getAllEntries,
  saveEntry,
  deleteEntry as deleteStoredEntry,
} from "../workers/storageWorker";
import AddEntryModal from "../components/AddEntryModal";
import EntryDetailModal from "../components/EntryDetailModal";

const DEFAULT_PI_SEED = 42;

export default function VaultScreen() {
  const insets = useSafeAreaInsets();
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [masterKey, setMasterKey] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [derivingKey, setDerivingKey] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<VaultEntry | null>(null);

  useEffect(() => {
    initializeVault();
  }, []);

  async function initializeVault() {
    setDerivingKey(true);
    try {
      const key = await deriveMasterKey(DEFAULT_PI_SEED);
      setMasterKey(key);
    } catch (err) {
      console.error("Failed to derive master key:", err);
    }
    setDerivingKey(false);
    await loadEntries();
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
    if (!masterKey) {
      console.error("handleAddEntry: masterKey is not set");
      throw new Error("Vault key not ready. Please restart the app.");
    }

    try {
      const encrypted = encryptVaultEntry(entry, masterKey);
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

  function getDecryptedEntry(entry: VaultEntry): DecryptedVaultEntry | null {
    if (!masterKey) return null;
    try {
      return decryptVaultEntry(entry, masterKey);
    } catch {
      return null;
    }
  }

  const webTopInset = Platform.OS === "web" ? 67 : 0;

  const renderItem = useCallback(
    ({ item }: { item: VaultEntry }) => (
      <Pressable
        onPress={() => setSelectedEntry(item)}
        style={{
          paddingVertical: 14,
          paddingHorizontal: 16,
          borderBottomWidth: 1,
          borderBottomColor: "#222",
          flexDirection: "row",
          alignItems: "center",
        }}
      >
        <Ionicons name="key-outline" size={20} color="#888" />
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
        <Text style={{ color: "#fff", fontSize: 16, marginTop: 16 }}>Deriving Cluster Key...</Text>
        <Text style={{ color: "#888", fontSize: 12, marginTop: 8, textAlign: "center", paddingHorizontal: 32 }}>
          Computing Mandelbrot orbits from Pi coordinates
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
        <Text style={{ color: "#fff", fontSize: 28, fontWeight: "bold" }}>Vault</Text>
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
          decryptedEntry={getDecryptedEntry(selectedEntry)}
          onClose={() => setSelectedEntry(null)}
          onDelete={() => handleDeleteEntry(selectedEntry.id)}
        />
      )}
    </View>
  );
}
