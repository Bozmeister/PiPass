import React, { useState } from "react";
import { View, Text, TextInput, Pressable, Modal, ScrollView, Platform, KeyboardAvoidingView, Alert, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Clipboard from "expo-clipboard";
import { SecureNote, DecryptedSecureNote, encryptSecureNote, decryptSecureNote } from "../workers/vaultWorker";
import { saveSecureNote, deleteSecureNote } from "../workers/storageWorker";
import { KeyShares } from "../crypto/secureMemory";
import { requireFreshBiometric } from "../crypto/biometricGate";
import { sanitizeInput } from "../utils/watchman";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_FOCUS, LABEL_COLOR } from "../styles/inputTheme";

const CLIPBOARD_CLEAR_MS = 30000;

interface SecureNotesModalProps {
  visible: boolean;
  notes: SecureNote[];
  keyShares: KeyShares | null;
  onClose: () => void;
  onNotesChanged: () => void;
  onActivity: () => void;
}

export default function SecureNotesModal({ visible, notes, keyShares, onClose, onNotesChanged, onActivity }: SecureNotesModalProps) {
  const insets = useSafeAreaInsets();
  const [view, setView] = useState<"list" | "add" | "detail">("list");
  const [label, setLabel] = useState("");
  const [content, setContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [selectedNote, setSelectedNote] = useState<SecureNote | null>(null);
  const [decryptedNote, setDecryptedNote] = useState<DecryptedSecureNote | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [copiedField, setCopiedField] = useState(false);
  const [focusedField, setFocusedField] = useState<string | null>(null);
  const clipboardTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const copyFeedbackTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  React.useEffect(() => {
    return () => {
      if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);
      if (copyFeedbackTimerRef.current) clearTimeout(copyFeedbackTimerRef.current);
    };
  }, []);

  function resetView() {
    setView("list");
    setLabel("");
    setContent("");
    setSelectedNote(null);
    setDecryptedNote(null);
    setSaving(false);
    setDecrypting(false);
    setCopiedField(false);
  }

  function handleClose() {
    resetView();
    onClose();
  }

  async function handleSave() {
    onActivity();
    if (!label.trim() || !content.trim() || !keyShares || saving) return;
    setSaving(true);
    try {
      const bioResult = await requireFreshBiometric();
      if (!bioResult) {
        setSaving(false);
        const msg = "Authentication required to save secure notes.";
        if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Authentication Required", msg); }
        return;
      }
      const encrypted = encryptSecureNote({ label: label.trim(), content: content.trim() }, keyShares);
      await saveSecureNote(encrypted);
      onNotesChanged();
      setLabel("");
      setContent("");
      setView("list");
      if (Platform.OS === "web") { alert("Secure note saved."); } else { Alert.alert("Saved", "Secure note encrypted and stored."); }
    } catch (err) {
      const msg = "Failed to save note.";
      if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Error", msg); }
    } finally {
      setSaving(false);
    }
  }

  async function handleSelect(note: SecureNote) {
    onActivity();
    if (!keyShares) return;
    setSelectedNote(note);
    setDecryptedNote(null);
    setDecrypting(true);
    setView("detail");

    try {
      const bioResult = await requireFreshBiometric();
      if (!bioResult) {
        setDecrypting(false);
        const msg = "Authentication required to view secure notes.";
        if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Authentication Required", msg); }
        return;
      }
      const decrypted = decryptSecureNote(note, keyShares);
      setDecryptedNote(decrypted);
    } catch (err) {
      setDecryptedNote(null);
      const msg = "Failed to decrypt note.";
      if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Error", msg); }
    }
    setDecrypting(false);
  }

  async function handleDelete(id: string) {
    onActivity();
    const doDelete = async () => {
      try {
        await deleteSecureNote(id);
        onNotesChanged();
        setView("list");
        setSelectedNote(null);
        setDecryptedNote(null);
      } catch {
        const msg = "Failed to delete note.";
        if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Error", msg); }
      }
    };

    if (Platform.OS === "web") {
      if (confirm("Delete this secure note?")) { await doDelete(); }
    } else {
      Alert.alert("Delete Note", "Are you sure you want to delete this secure note?", [
        { text: "Cancel", style: "cancel" },
        { text: "Delete", style: "destructive", onPress: doDelete },
      ]);
    }
  }

  async function handleCopy(value: string) {
    try {
      await Clipboard.setStringAsync(value);
      setCopiedField(true);
      if (copyFeedbackTimerRef.current) clearTimeout(copyFeedbackTimerRef.current);
      copyFeedbackTimerRef.current = setTimeout(() => { setCopiedField(false); copyFeedbackTimerRef.current = null; }, 2000);
      if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);
      clipboardTimerRef.current = setTimeout(async () => {
        try { await Clipboard.setStringAsync(""); } catch {}
        clipboardTimerRef.current = null;
      }, CLIPBOARD_CLEAR_MS);
    } catch {}
  }

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <KeyboardAvoidingView
        style={{ flex: 1 }}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        keyboardVerticalOffset={0}
      >
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.85)", justifyContent: "flex-end" }}>
          <View style={{
            backgroundColor: "#111",
            borderTopLeftRadius: 20,
            borderTopRightRadius: 20,
            paddingTop: 16,
            paddingBottom: insets.bottom + (Platform.OS === "web" ? 34 : 16),
            paddingHorizontal: 20,
            maxHeight: "85%",
          }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              {view !== "list" ? (
                <Pressable onPress={() => { setView("list"); setSelectedNote(null); setDecryptedNote(null); }} testID="notes-back-button">
                  <Ionicons name="arrow-back" size={24} color="#fff" />
                </Pressable>
              ) : (
                <View style={{ width: 24 }} />
              )}
              <Text style={{ color: "#fff", fontSize: 18, fontWeight: "bold" }}>
                {view === "add" ? "New Secure Note" : view === "detail" ? "Secure Note" : "Secure Notes"}
              </Text>
              <Pressable onPress={handleClose} testID="close-notes-modal">
                <Ionicons name="close-circle" size={28} color="#555" />
              </Pressable>
            </View>

            {view === "list" && (
              <ScrollView>
                <View style={{
                  flexDirection: "row",
                  alignItems: "center",
                  backgroundColor: "#0a1a1a",
                  borderRadius: 8,
                  padding: 12,
                  marginBottom: 16,
                  borderWidth: 1,
                  borderColor: "#114a4a",
                }}>
                  <Ionicons name="shield-checkmark" size={16} color="#4CAF50" />
                  <Text style={{ color: "#aaa", fontSize: 12, marginLeft: 8, flex: 1, lineHeight: 16 }}>
                    Store sensitive data like crypto seed phrases, Wi-Fi keys, or safe combinations. Encrypted with your vault key.
                  </Text>
                </View>

                {notes.length === 0 ? (
                  <View style={{ alignItems: "center", paddingVertical: 40 }}>
                    <Ionicons name="document-lock-outline" size={40} color="#444" />
                    <Text style={{ color: "#666", fontSize: 14, marginTop: 12 }}>No secure notes yet</Text>
                  </View>
                ) : (
                  notes.map((note) => (
                    <Pressable
                      key={note.id}
                      onPress={() => handleSelect(note)}
                      style={{
                        flexDirection: "row",
                        alignItems: "center",
                        backgroundColor: "#1a1a1a",
                        borderRadius: 10,
                        padding: 14,
                        marginBottom: 8,
                        borderWidth: 1,
                        borderColor: "#222",
                      }}
                      testID={`note-item-${note.id}`}
                    >
                      <Ionicons name="document-text-outline" size={20} color="#4CAF50" style={{ marginRight: 12 }} />
                      <View style={{ flex: 1 }}>
                        <Text style={{ color: "#fff", fontSize: 15, fontWeight: "600" }}>{note.label}</Text>
                        <Text style={{ color: "#666", fontSize: 11, marginTop: 2 }}>
                          {new Date(note.createdAt).toLocaleDateString()}
                        </Text>
                      </View>
                      <Ionicons name="chevron-forward" size={18} color="#555" />
                    </Pressable>
                  ))
                )}

                <Pressable
                  onPress={() => { onActivity(); setView("add"); }}
                  style={{
                    flexDirection: "row",
                    alignItems: "center",
                    justifyContent: "center",
                    backgroundColor: "#4CAF50",
                    borderRadius: 10,
                    padding: 14,
                    marginTop: 16,
                  }}
                  testID="add-note-button"
                >
                  <Ionicons name="add" size={20} color="#fff" style={{ marginRight: 6 }} />
                  <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}>Add Secure Note</Text>
                </Pressable>
              </ScrollView>
            )}

            {view === "add" && (
              <ScrollView keyboardShouldPersistTaps="handled">
                <Text style={{ color: LABEL_COLOR, fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>Label *</Text>
                <TextInput
                  value={label}
                  onChangeText={(t) => setLabel(sanitizeInput(t, "title"))}
                  placeholder="e.g. Bitcoin Wallet Seed"
                  placeholderTextColor={INPUT_PLACEHOLDER}
                  autoCorrect={false}
                  onFocus={() => setFocusedField("label")}
                  onBlur={() => setFocusedField(null)}
                  style={{ color: INPUT_TEXT, fontSize: 16, backgroundColor: INPUT_BG, borderRadius: 8, padding: 12, marginBottom: 16, borderWidth: 1, borderColor: focusedField === "label" ? INPUT_BORDER_FOCUS : INPUT_BORDER }}
                  testID="note-label-input"
                />

                <Text style={{ color: LABEL_COLOR, fontSize: 12, marginBottom: 6, textTransform: "uppercase" }}>Secret Content *</Text>
                <TextInput
                  value={content}
                  onChangeText={setContent}
                  placeholder="Enter your sensitive data..."
                  placeholderTextColor={INPUT_PLACEHOLDER}
                  multiline
                  numberOfLines={6}
                  secureTextEntry={false}
                  autoCorrect={false}
                  autoCapitalize="none"
                  onFocus={() => setFocusedField("content")}
                  onBlur={() => setFocusedField(null)}
                  style={{
                    color: INPUT_TEXT,
                    fontSize: 16,
                    backgroundColor: INPUT_BG,
                    borderRadius: 8,
                    padding: 12,
                    marginBottom: 16,
                    minHeight: 140,
                    textAlignVertical: "top",
                    borderWidth: 1,
                    borderColor: focusedField === "content" ? INPUT_BORDER_FOCUS : INPUT_BORDER,
                  }}
                  testID="note-content-input"
                />

                <View style={{
                  backgroundColor: "#1a1a0a",
                  borderWidth: 1,
                  borderColor: "#444400",
                  borderRadius: 8,
                  padding: 10,
                  marginBottom: 16,
                  flexDirection: "row",
                  alignItems: "center",
                }}>
                  <Ionicons name="lock-closed" size={14} color="#fbbf24" />
                  <Text style={{ color: "#aaa", fontSize: 11, marginLeft: 6 }}>
                    Content will be encrypted with your vault key before storage
                  </Text>
                </View>

                <Pressable
                  onPress={handleSave}
                  disabled={!label.trim() || !content.trim() || saving}
                  style={{
                    backgroundColor: label.trim() && content.trim() && !saving ? "#4CAF50" : "#333",
                    paddingVertical: 14,
                    borderRadius: 8,
                    alignItems: "center",
                  }}
                  testID="save-note-button"
                >
                  <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700" }}>
                    {saving ? "Encrypting..." : "Encrypt & Save"}
                  </Text>
                </Pressable>
              </ScrollView>
            )}

            {view === "detail" && selectedNote && (
              <ScrollView>
                {decrypting ? (
                  <View style={{ alignItems: "center", paddingVertical: 40 }}>
                    <ActivityIndicator size="large" color="#4CAF50" />
                    <Text style={{ color: "#888", fontSize: 14, marginTop: 12 }}>Authenticating...</Text>
                  </View>
                ) : !decryptedNote ? (
                  <View style={{ alignItems: "center", paddingVertical: 40 }}>
                    <Ionicons name="lock-closed" size={40} color="#ff6b6b" />
                    <Text style={{ color: "#ff6b6b", fontSize: 14, marginTop: 12 }}>Authentication required to view content</Text>
                  </View>
                ) : (
                  <>
                    <View style={{ marginBottom: 16 }}>
                      <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Label</Text>
                      <Text style={{ color: "#fff", fontSize: 18, fontWeight: "700" }}>{decryptedNote.label}</Text>
                    </View>

                    <View style={{ marginBottom: 16 }}>
                      <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                        <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase" }}>Secret Content</Text>
                        <Pressable onPress={() => handleCopy(decryptedNote.content)} style={{ padding: 4 }} testID="copy-note-content">
                          <Ionicons
                            name={copiedField ? "checkmark-circle" : "copy-outline"}
                            size={18}
                            color={copiedField ? "#4CAF50" : "#888"}
                          />
                        </Pressable>
                      </View>
                      <View style={{
                        backgroundColor: "#1a1a1a",
                        borderRadius: 8,
                        padding: 14,
                        borderWidth: 1,
                        borderColor: "#333",
                      }}>
                        <Text style={{ color: "#fff", fontSize: 15, lineHeight: 22 }} selectable>
                          {decryptedNote.content}
                        </Text>
                      </View>
                    </View>

                    <View style={{
                      backgroundColor: "#1a1a1a",
                      borderRadius: 8,
                      padding: 10,
                      marginBottom: 16,
                      flexDirection: "row",
                      alignItems: "center",
                    }}>
                      <Ionicons name="timer-outline" size={14} color="#888" />
                      <Text style={{ color: "#888", fontSize: 11, marginLeft: 6 }}>
                        Clipboard auto-clears 30s after copy
                      </Text>
                    </View>

                    <View style={{ marginBottom: 20 }}>
                      <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>Created</Text>
                      <Text style={{ color: "#aaa", fontSize: 13 }}>{new Date(decryptedNote.createdAt).toLocaleString()}</Text>
                    </View>
                  </>
                )}

                <Pressable
                  onPress={() => handleDelete(selectedNote.id)}
                  style={{
                    flexDirection: "row",
                    alignItems: "center",
                    justifyContent: "center",
                    backgroundColor: "#1a0a0a",
                    borderRadius: 10,
                    padding: 14,
                    marginTop: 8,
                    borderWidth: 1,
                    borderColor: "#4a1111",
                  }}
                  testID="delete-note-button"
                >
                  <Ionicons name="trash-outline" size={18} color="#ef4444" style={{ marginRight: 8 }} />
                  <Text style={{ color: "#ef4444", fontSize: 15, fontWeight: "600" }}>Delete Note</Text>
                </Pressable>
              </ScrollView>
            )}
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}
