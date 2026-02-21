import React, { useState, useMemo } from "react";
import { View, Text, Pressable, Modal, ScrollView, Platform, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { VaultEntry, DecryptedVaultEntry } from "../workers/vaultWorker";
import { extractPiDigits, mapDigitsToCoordinates } from "../crypto/pi";
import FractalBackground from "./FractalBackground";

interface EntryDetailModalProps {
  visible: boolean;
  entry: VaultEntry;
  decryptedEntry: DecryptedVaultEntry | null;
  decrypting: boolean;
  piIndex: number;
  onClose: () => void;
  onDelete: () => void;
}

export default function EntryDetailModal({
  visible,
  entry,
  decryptedEntry,
  decrypting,
  piIndex,
  onClose,
  onDelete,
}: EntryDetailModalProps) {
  const insets = useSafeAreaInsets();
  const [showPassword, setShowPassword] = useState(false);

  const password = decryptedEntry?.password || "";
  const notes = decryptedEntry?.notes;

  const fractalCoords = useMemo(() => {
    const digits = extractPiDigits(piIndex, 30);
    const coords = mapDigitsToCoordinates(digits);
    return coords;
  }, [piIndex]);

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "flex-end" }}>
        <View style={{ backgroundColor: "#111", borderTopLeftRadius: 16, borderTopRightRadius: 16, maxHeight: "80%", overflow: "hidden" }}>
          <FractalBackground
            centerX={fractalCoords.x}
            centerY={fractalCoords.y}
            zoom={fractalCoords.zoomFactor}
            piIndex={piIndex}
          />
          <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, borderBottomWidth: 1, borderBottomColor: "#222" }}>
            <Pressable onPress={onClose}>
              <Ionicons name="close" size={24} color="#fff" />
            </Pressable>
            <Text style={{ color: "#fff", fontSize: 17, fontWeight: "600" }}>{entry.title}</Text>
            <Pressable onPress={onDelete}>
              <Ionicons name="trash-outline" size={22} color="#ff6b6b" />
            </Pressable>
          </View>

          <ScrollView
            style={{ padding: 16 }}
            contentContainerStyle={{
              paddingBottom: insets.bottom + (Platform.OS === "web" ? 34 : 0) + 16,
            }}
          >
            <View style={{ marginBottom: 20 }}>
              <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Username</Text>
              <Text style={{ color: "#fff", fontSize: 16 }}>{entry.username}</Text>
            </View>

            <View style={{ marginBottom: 20 }}>
              <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Password</Text>
              {decrypting ? (
                <View style={{ flexDirection: "row", alignItems: "center", paddingVertical: 4 }}>
                  <ActivityIndicator size="small" color="#fff" />
                  <Text style={{ color: "#888", fontSize: 14, marginLeft: 8 }}>Authenticating...</Text>
                </View>
              ) : !decryptedEntry ? (
                <Text style={{ color: "#ff6b6b", fontSize: 14 }}>Authentication required to view password</Text>
              ) : (
                <View style={{ flexDirection: "row", alignItems: "center" }}>
                  <Text style={{ color: "#fff", fontSize: 16, flex: 1 }}>
                    {showPassword ? password : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}
                  </Text>
                  <Pressable onPress={() => setShowPassword(!showPassword)} style={{ padding: 4 }}>
                    <Ionicons name={showPassword ? "eye-off-outline" : "eye-outline"} size={20} color="#888" />
                  </Pressable>
                </View>
              )}
            </View>

            {entry.url && (
              <View style={{ marginBottom: 20 }}>
                <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>URL</Text>
                <Text style={{ color: "#4CAF50", fontSize: 16 }}>{entry.url}</Text>
              </View>
            )}

            {notes && (
              <View style={{ marginBottom: 20 }}>
                <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Notes</Text>
                <Text style={{ color: "#fff", fontSize: 16 }}>{notes}</Text>
              </View>
            )}

            <View style={{ marginBottom: 20 }}>
              <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Created</Text>
              <Text style={{ color: "#fff", fontSize: 14 }}>{new Date(entry.createdAt).toLocaleString()}</Text>
            </View>
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}
