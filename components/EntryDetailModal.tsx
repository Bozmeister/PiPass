import React, { useState, useMemo, useRef, useEffect } from "react";
import { View, Text, Pressable, Modal, ScrollView, Platform, ActivityIndicator, Alert, Image } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Clipboard from "expo-clipboard";
import { VaultEntry, DecryptedVaultEntry } from "../workers/vaultWorker";
import FractalBackground from "./FractalBackground";
import FaviconImage from "./FaviconImage";
import { FractalParams } from "../crypto/hkdf";

const CLIPBOARD_CLEAR_MS = 30000;

interface EntryDetailModalProps {
  visible: boolean;
  entry: VaultEntry;
  decryptedEntry: DecryptedVaultEntry | null;
  decrypting: boolean;
  visualSeed: number;
  fractalParams?: FractalParams;
  onClose: () => void;
  onDelete: () => void;
}

export default function EntryDetailModal({
  visible,
  entry,
  decryptedEntry,
  decrypting,
  visualSeed,
  fractalParams,
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

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "flex-end" }}>
        <View style={{ backgroundColor: "#111", borderTopLeftRadius: 16, borderTopRightRadius: 16, maxHeight: "80%", overflow: "hidden" }}>
          <FractalBackground
            seed={visualSeed}
            fractalParams={fractalParams}
          />
          <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, borderBottomWidth: 1, borderBottomColor: "#222" }}>
            <Pressable onPress={onClose}>
              <Ionicons name="close" size={24} color="#fff" />
            </Pressable>
            <Text style={{ color: "#f0f0f0", fontSize: 17, fontWeight: "600" as const }}>{displayTitle}</Text>
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
              <Text style={{ color: "#999", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 4 }}>Username</Text>
              <View style={{ flexDirection: "row", alignItems: "center" }}>
                <Text style={{ color: "#f0f0f0", fontSize: 16, flex: 1 }}>{displayUsername}</Text>
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
              <Text style={{ color: "#999", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 4 }}>Password</Text>
              {decrypting ? (
                <View style={{ flexDirection: "row", alignItems: "center", paddingVertical: 4 }}>
                  <ActivityIndicator size="small" color="#fff" />
                  <Text style={{ color: "#999", fontSize: 14, marginLeft: 8 }}>Authenticating...</Text>
                </View>
              ) : !decryptedEntry ? (
                <Text style={{ color: "#ff6b6b", fontSize: 14 }}>Authentication required to view password</Text>
              ) : (
                <View style={{ flexDirection: "row", alignItems: "center" }}>
                  <Text style={{ color: "#f0f0f0", fontSize: 16, flex: 1 }}>
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
                <Text style={{ color: "#999", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 4 }}>URL</Text>
                <View style={{ flexDirection: "row", alignItems: "center" }}>
                  <FaviconImage url={displayUrl} size={24} />
                  <Text style={{ color: "#4a90d9", fontSize: 16, flex: 1, marginLeft: 8 }}>{displayUrl}</Text>
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
                <Text style={{ color: "#999", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 4 }}>Notes</Text>
                <Text style={{ color: "#f0f0f0", fontSize: 16 }}>{notes}</Text>
              </View>
            )}

            {decryptedEntry && (
              <View style={{
                backgroundColor: "#1e1e1e",
                borderRadius: 8,
                padding: 10,
                marginBottom: 20,
                flexDirection: "row",
                alignItems: "center",
                borderWidth: 1,
                borderColor: "#3a3a3a",
              }}>
                <Ionicons name="timer-outline" size={14} color="#888" />
                <Text style={{ color: "#999", fontSize: 11, marginLeft: 6 }}>
                  Clipboard auto-clears 30s after copy
                </Text>
              </View>
            )}

            <View style={{ marginBottom: 20 }}>
              <Text style={{ color: "#999", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 4 }}>Created</Text>
              <Text style={{ color: "#f0f0f0", fontSize: 14 }}>{new Date(entry.createdAt).toLocaleString()}</Text>
            </View>
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}
