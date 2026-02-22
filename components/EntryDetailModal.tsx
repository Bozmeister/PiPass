import React, { useState, useMemo, useRef, useEffect } from "react";
import { View, Text, Pressable, Modal, ScrollView, Platform, ActivityIndicator, Alert } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Clipboard from "expo-clipboard";
import { VaultEntry, DecryptedVaultEntry } from "../workers/vaultWorker";
import { extractPiDigits, mapDigitsToCoordinates } from "../crypto/pi";
import FractalBackground from "./FractalBackground";

const CLIPBOARD_CLEAR_MS = 30000;

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
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const clipboardTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);
    };
  }, []);

  async function handleCopy(value: string, fieldName: string) {
    try {
      await Clipboard.setStringAsync(value);
      setCopiedField(fieldName);
      setTimeout(() => setCopiedField(null), 2000);

      if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);
      clipboardTimerRef.current = setTimeout(async () => {
        try {
          await Clipboard.setStringAsync("");
        } catch {}
        clipboardTimerRef.current = null;
      }, CLIPBOARD_CLEAR_MS);
    } catch {}
  }

  const displayTitle = decryptedEntry?.title || entry.title;
  const displayUsername = decryptedEntry?.username || entry.username;
  const displayUrl = decryptedEntry?.url || entry.url;
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
            <Text style={{ color: "#fff", fontSize: 17, fontWeight: "600" }}>{displayTitle}</Text>
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
              <View style={{ flexDirection: "row", alignItems: "center" }}>
                <Text style={{ color: "#fff", fontSize: 16, flex: 1 }}>{displayUsername}</Text>
                {decryptedEntry && (
                  <Pressable onPress={() => handleCopy(displayUsername, "username")} style={{ padding: 4 }}>
                    <Ionicons
                      name={copiedField === "username" ? "checkmark-circle" : "copy-outline"}
                      size={18}
                      color={copiedField === "username" ? "#4CAF50" : "#888"}
                    />
                  </Pressable>
                )}
              </View>
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
                  <Pressable onPress={() => handleCopy(password, "password")} style={{ padding: 4, marginRight: 4 }}>
                    <Ionicons
                      name={copiedField === "password" ? "checkmark-circle" : "copy-outline"}
                      size={18}
                      color={copiedField === "password" ? "#4CAF50" : "#888"}
                    />
                  </Pressable>
                  <Pressable onPress={() => setShowPassword(!showPassword)} style={{ padding: 4 }}>
                    <Ionicons name={showPassword ? "eye-off-outline" : "eye-outline"} size={20} color="#888" />
                  </Pressable>
                </View>
              )}
            </View>

            {displayUrl && (
              <View style={{ marginBottom: 20 }}>
                <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>URL</Text>
                <View style={{ flexDirection: "row", alignItems: "center" }}>
                  <Text style={{ color: "#4CAF50", fontSize: 16, flex: 1 }}>{displayUrl}</Text>
                  {decryptedEntry && (
                    <Pressable onPress={() => handleCopy(displayUrl, "url")} style={{ padding: 4 }}>
                      <Ionicons
                        name={copiedField === "url" ? "checkmark-circle" : "copy-outline"}
                        size={18}
                        color={copiedField === "url" ? "#4CAF50" : "#888"}
                      />
                    </Pressable>
                  )}
                </View>
              </View>
            )}

            {notes && (
              <View style={{ marginBottom: 20 }}>
                <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Notes</Text>
                <Text style={{ color: "#fff", fontSize: 16 }}>{notes}</Text>
              </View>
            )}

            {decryptedEntry && (
              <View style={{
                backgroundColor: "#1a1a1a",
                borderRadius: 8,
                padding: 10,
                marginBottom: 20,
                flexDirection: "row",
                alignItems: "center",
              }}>
                <Ionicons name="timer-outline" size={14} color="#888" />
                <Text style={{ color: "#888", fontSize: 11, marginLeft: 6 }}>
                  Clipboard auto-clears 30s after copy
                </Text>
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
