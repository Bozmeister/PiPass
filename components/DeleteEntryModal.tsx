import React, { useState, useEffect } from "react";
import { View, Text, Modal, Pressable, TextInput, Platform } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_FOCUS } from "../styles/inputTheme";

interface DeleteEntryModalProps {
  visible: boolean;
  entryTitle: string;
  onConfirmDelete: () => void;
  onCancel: () => void;
  onActivity?: () => void;
}

export default function DeleteEntryModal({
  visible,
  entryTitle,
  onConfirmDelete,
  onCancel,
  onActivity,
}: DeleteEntryModalProps) {
  const insets = useSafeAreaInsets();
  const [confirmText, setConfirmText] = useState("");
  const [inputFocused, setInputFocused] = useState(false);

  useEffect(() => {
    if (!visible) {
      setConfirmText("");
      setInputFocused(false);
    }
  }, [visible]);

  const canDelete = confirmText === "DELETE";

  function handleCancel() {
    setConfirmText("");
    onCancel();
  }

  function handleDelete() {
    if (!canDelete) return;
    setConfirmText("");
    onConfirmDelete();
  }

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent statusBarTranslucent>
      <View
        style={{
          flex: 1,
          backgroundColor: "rgba(0,0,0,0.92)",
          justifyContent: "center",
          alignItems: "center",
          padding: 24,
        }}
        onTouchStart={onActivity}
        onTouchMove={onActivity}
      >
        <View
          style={{
            backgroundColor: "#111",
            borderRadius: 16,
            padding: 24,
            width: "100%",
            maxWidth: 400,
            borderWidth: 1,
            borderColor: "#2a1515",
          }}
        >
          <View style={{ alignItems: "center", marginBottom: 20 }}>
            <View
              style={{
                width: 48,
                height: 48,
                borderRadius: 24,
                backgroundColor: "#2a0a0a",
                justifyContent: "center",
                alignItems: "center",
                marginBottom: 12,
              }}
            >
              <Ionicons name="trash" size={24} color="#ef4444" />
            </View>
            <Text
              style={{
                color: "#fff",
                fontSize: 20,
                fontWeight: "bold" as const,
                textAlign: "center",
              }}
            >
              Delete Vault Entry
            </Text>
          </View>

          <Text
            style={{
              color: "#ef4444",
              fontSize: 14,
              fontWeight: "600" as const,
              textAlign: "center",
              marginBottom: 8,
            }}
          >
            This action cannot be undone.
          </Text>

          <Text
            style={{
              color: "#aaa",
              fontSize: 14,
              textAlign: "center",
              marginBottom: 4,
            }}
          >
            You are about to permanently delete:
          </Text>
          <Text
            style={{
              color: "#fff",
              fontSize: 16,
              fontWeight: "600" as const,
              textAlign: "center",
              marginBottom: 20,
            }}
          >
            {entryTitle}
          </Text>

          <Text
            style={{
              color: "#aaa",
              fontSize: 14,
              marginBottom: 8,
            }}
          >
            Type <Text style={{ color: "#ef4444", fontWeight: "700" as const }}>DELETE</Text> to confirm:
          </Text>

          <TextInput
            value={confirmText}
            onChangeText={setConfirmText}
            placeholder="Type DELETE"
            placeholderTextColor={INPUT_PLACEHOLDER}
            autoCapitalize="characters"
            autoCorrect={false}
            onFocus={() => setInputFocused(true)}
            onBlur={() => setInputFocused(false)}
            style={{
              color: INPUT_TEXT,
              fontSize: 16,
              padding: 14,
              backgroundColor: INPUT_BG,
              borderRadius: 8,
              borderWidth: 1,
              borderColor: canDelete ? "#ef4444" : inputFocused ? INPUT_BORDER_FOCUS : INPUT_BORDER,
              marginBottom: 20,
              textAlign: "center",
              letterSpacing: 4,
              fontWeight: "700" as const,
            }}
            testID="delete-confirm-input"
          />

          <View style={{ flexDirection: "row", gap: 12 }}>
            <Pressable
              onPress={handleCancel}
              style={{
                flex: 1,
                padding: 14,
                borderRadius: 8,
                backgroundColor: "#1a1a1a",
                alignItems: "center",
              }}
            >
              <Text style={{ color: "#aaa", fontSize: 16 }}>Cancel</Text>
            </Pressable>
            <Pressable
              onPress={handleDelete}
              disabled={!canDelete}
              style={{
                flex: 1,
                padding: 14,
                borderRadius: 8,
                backgroundColor: canDelete ? "#ef4444" : "#333",
                alignItems: "center",
              }}
            >
              <Text
                style={{
                  color: canDelete ? "#fff" : "#666",
                  fontSize: 16,
                  fontWeight: "600" as const,
                }}
              >
                Permanently Delete
              </Text>
            </Pressable>
          </View>
        </View>
      </View>
    </Modal>
  );
}
