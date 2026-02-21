import React, { useState } from "react";
import { View, Text, TextInput, Pressable, Modal, ScrollView, Platform, KeyboardAvoidingView } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";

interface AddEntryModalProps {
  visible: boolean;
  onClose: () => void;
  onSave: (entry: {
    title: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
  }) => void;
}

export default function AddEntryModal({ visible, onClose, onSave }: AddEntryModalProps) {
  const insets = useSafeAreaInsets();
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [notes, setNotes] = useState("");

  function handleSave() {
    if (!title.trim() || !username.trim() || !password.trim()) return;

    onSave({
      title: title.trim(),
      username: username.trim(),
      password: password.trim(),
      url: url.trim() || undefined,
      notes: notes.trim() || undefined,
    });

    setTitle("");
    setUsername("");
    setPassword("");
    setUrl("");
    setNotes("");
  }

  const isValid = title.trim() && username.trim() && password.trim();

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <KeyboardAvoidingView
        style={{ flex: 1 }}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        keyboardVerticalOffset={0}
      >
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "flex-end" }}>
          <View style={{ backgroundColor: "#111", borderTopLeftRadius: 16, borderTopRightRadius: 16, maxHeight: "90%" }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, borderBottomWidth: 1, borderBottomColor: "#222" }}>
              <Pressable onPress={onClose}>
                <Ionicons name="close" size={24} color="#fff" />
              </Pressable>
              <Text style={{ color: "#fff", fontSize: 17, fontWeight: "600" }}>Add Entry</Text>
              <Pressable onPress={handleSave} disabled={!isValid}>
                <Text style={{ color: isValid ? "#4CAF50" : "#555", fontSize: 16, fontWeight: "600" }}>Save</Text>
              </Pressable>
            </View>

            <ScrollView style={{ padding: 16 }} contentContainerStyle={{ paddingBottom: insets.bottom + (Platform.OS === "web" ? 34 : 0) + 16 }} keyboardShouldPersistTaps="handled">
              <Text style={{ color: "#888", fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>Title *</Text>
              <TextInput
                value={title}
                onChangeText={setTitle}
                placeholder="e.g. Gmail"
                placeholderTextColor="#555"
                style={{ color: "#fff", fontSize: 16, backgroundColor: "#1a1a1a", borderRadius: 8, padding: 12, marginBottom: 16 }}
                testID="title-input"
              />

              <Text style={{ color: "#888", fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>Username *</Text>
              <TextInput
                value={username}
                onChangeText={setUsername}
                placeholder="e.g. user@email.com"
                placeholderTextColor="#555"
                autoCapitalize="none"
                style={{ color: "#fff", fontSize: 16, backgroundColor: "#1a1a1a", borderRadius: 8, padding: 12, marginBottom: 16 }}
                testID="username-input"
              />

              <Text style={{ color: "#888", fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>Password *</Text>
              <TextInput
                value={password}
                onChangeText={setPassword}
                placeholder="Enter password"
                placeholderTextColor="#555"
                secureTextEntry
                autoCapitalize="none"
                style={{ color: "#fff", fontSize: 16, backgroundColor: "#1a1a1a", borderRadius: 8, padding: 12, marginBottom: 16 }}
                testID="password-input"
              />

              <Text style={{ color: "#888", fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>URL</Text>
              <TextInput
                value={url}
                onChangeText={setUrl}
                placeholder="e.g. https://gmail.com"
                placeholderTextColor="#555"
                autoCapitalize="none"
                keyboardType="url"
                style={{ color: "#fff", fontSize: 16, backgroundColor: "#1a1a1a", borderRadius: 8, padding: 12, marginBottom: 16 }}
              />

              <Text style={{ color: "#888", fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>Notes</Text>
              <TextInput
                value={notes}
                onChangeText={setNotes}
                placeholder="Optional notes"
                placeholderTextColor="#555"
                multiline
                numberOfLines={3}
                style={{ color: "#fff", fontSize: 16, backgroundColor: "#1a1a1a", borderRadius: 8, padding: 12, marginBottom: 16, minHeight: 80, textAlignVertical: "top" }}
              />
            </ScrollView>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}
