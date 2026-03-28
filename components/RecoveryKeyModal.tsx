import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  View,
  Text,
  Modal,
  Pressable,
  Platform,
  ScrollView,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Clipboard from "expo-clipboard";

interface RecoveryKeyModalProps {
  visible: boolean;
  formattedKey: string;
  onConfirm: () => void;
}

export default function RecoveryKeyModal({
  visible,
  formattedKey,
  onConfirm,
}: RecoveryKeyModalProps) {
  const insets = useSafeAreaInsets();
  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const webBottomInset = Platform.OS === "web" ? 34 : 0;
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!visible) {
      setSaved(false);
      setCopied(false);
    }
  }, [visible]);

  const handleCopy = useCallback(async () => {
    try {
      await Clipboard.setStringAsync(formattedKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  }, [formattedKey]);

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent={false}>
      <View
        style={{
          flex: 1,
          backgroundColor: "#0a0a0a",
          paddingTop: insets.top + webTopInset,
          paddingBottom: insets.bottom + webBottomInset,
        }}
      >
        <ScrollView
          contentContainerStyle={{
            flexGrow: 1,
            justifyContent: "center",
            paddingHorizontal: 24,
            paddingVertical: 20,
          }}
          keyboardShouldPersistTaps="handled"
        >
          <View style={{ alignItems: "center", marginBottom: 24 }}>
            <Ionicons name="key" size={56} color="#4CAF50" />
            <Text
              style={{
                color: "#fff",
                fontSize: 22,
                fontWeight: "bold" as const,
                marginTop: 16,
                textAlign: "center",
              }}
            >
              Recovery Key
            </Text>
          </View>

          <View
            style={{
              backgroundColor: "#1a0808",
              padding: 16,
              borderRadius: 12,
              borderWidth: 1,
              borderColor: "#ef4444",
              marginBottom: 16,
            }}
          >
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 8 }}>
              <Ionicons name="warning" size={18} color="#ef4444" />
              <Text style={{ color: "#ef4444", fontSize: 14, fontWeight: "600" as const, marginLeft: 8 }}>
                Save this key now
              </Text>
            </View>
            <Text style={{ color: "#ccc", fontSize: 13, lineHeight: 20 }}>
              This key is the ONLY way to recover your vault if you forget your password. It will not be shown again.
            </Text>
          </View>

          <View
            style={{
              backgroundColor: "#111",
              padding: 20,
              borderRadius: 12,
              borderWidth: 1,
              borderColor: "#333",
              marginBottom: 16,
            }}
          >
            <Text
              selectable
              style={{
                color: "#4CAF50",
                fontSize: 16,
                fontWeight: "600" as const,
                textAlign: "center",
                lineHeight: 28,
                fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
                letterSpacing: 1,
              }}
            >
              {formattedKey}
            </Text>
          </View>

          <Pressable
            onPress={handleCopy}
            style={{
              flexDirection: "row",
              alignItems: "center",
              justifyContent: "center",
              backgroundColor: "#1a1a1a",
              padding: 14,
              borderRadius: 8,
              marginBottom: 24,
              gap: 8,
            }}
          >
            <Ionicons name={copied ? "checkmark" : "copy-outline"} size={18} color={copied ? "#4CAF50" : "#aaa"} />
            <Text style={{ color: copied ? "#4CAF50" : "#aaa", fontSize: 14 }}>
              {copied ? "Copied!" : "Copy to clipboard"}
            </Text>
          </Pressable>

          <Pressable
            onPress={() => setSaved(!saved)}
            style={{
              flexDirection: "row",
              alignItems: "center",
              paddingVertical: 12,
              paddingHorizontal: 4,
            }}
          >
            <View
              style={{
                width: 24,
                height: 24,
                borderRadius: 4,
                borderWidth: 2,
                borderColor: saved ? "#4CAF50" : "#555",
                backgroundColor: saved ? "#4CAF50" : "transparent",
                alignItems: "center",
                justifyContent: "center",
                marginRight: 12,
              }}
            >
              {saved && <Ionicons name="checkmark" size={16} color="#fff" />}
            </View>
            <Text style={{ color: "#ccc", fontSize: 15, flex: 1 }}>
              I have saved this recovery key in a safe place
            </Text>
          </Pressable>

          <Pressable
            onPress={onConfirm}
            disabled={!saved}
            style={{
              backgroundColor: saved ? "#4CAF50" : "#333",
              padding: 16,
              borderRadius: 12,
              alignItems: "center",
              marginTop: 20,
              opacity: saved ? 1 : 0.5,
            }}
          >
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>
              Continue to Vault
            </Text>
          </Pressable>
        </ScrollView>
      </View>
    </Modal>
  );
}
