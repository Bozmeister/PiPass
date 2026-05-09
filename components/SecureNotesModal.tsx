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
  // Suppresses the parent's AppState=inactive auto-lock while a
  // biometric prompt is on screen. Without this, iOS sends the app
  // to "inactive" during the prompt, the vault locks, this modal
  // unmounts, and the user gets sent back to the unlock screen and
  // loses the selected note. Mirrors VaultScreen.handleSelectEntry.
  onBiometricActiveChange?: (active: boolean) => void;
  // Reads the parent's "last user activity" timestamp (ms epoch).
  // If the user was active within RECENT_ACTIVITY_MS, the per-note
  // biometric prompt is skipped — the vault is already unlocked
  // and the user is demonstrably present, so requiring a second
  // gate is friction without security benefit.
  getLastActivityMs?: () => number;
}

const RECENT_ACTIVITY_MS = 30000;

// Safe DEV-only error categorisation. Returns a label that contains
// NO secret material — only the shape of the failure, useful when a
// user reports "Failed to decrypt note" on a real device. Production
// builds skip this entirely (gated by __DEV__ at the call site).
function categoriseDecryptError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes("Authentication failed")) return "MAC_FAIL";
  if (msg.includes("Invalid ciphertext format")) return "FORMAT_INVALID";
  if (msg.includes("Decryption failed")) return "DECRYPT_EMPTY";
  if (msg.includes("undefined") || msg.includes("null")) return "MISSING_FIELD";
  return "OTHER";
}

export default function SecureNotesModal({ visible, notes, keyShares, onClose, onNotesChanged, onActivity, onBiometricActiveChange, getLastActivityMs }: SecureNotesModalProps) {
  const insets = useSafeAreaInsets();
  const [view, setView] = useState<"list" | "add" | "detail">("list");
  const [label, setLabel] = useState("");
  const [content, setContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [selectedNote, setSelectedNote] = useState<SecureNote | null>(null);
  const [decryptedNote, setDecryptedNote] = useState<DecryptedSecureNote | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState<string | null>(null);
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
    setDecryptError(null);
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
      onBiometricActiveChange?.(true);
      let bioResult: boolean;
      try {
        bioResult = await requireFreshBiometric();
      } finally {
        onBiometricActiveChange?.(false);
      }
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
    setDecryptError(null);
    setDecrypting(true);
    setView("detail");

    try {
      // Skip biometric step-up if the user was active within the
      // last RECENT_ACTIVITY_MS — vault is already unlocked and
      // the user is demonstrably present. Tapping a note IS the
      // activity registration, so this resolves true on every
      // normal in-session note open.
      const lastActivity = getLastActivityMs?.() ?? 0;
      const recentlyActive = lastActivity > 0 && Date.now() - lastActivity < RECENT_ACTIVITY_MS;

      if (!recentlyActive) {
        onBiometricActiveChange?.(true);
        let bioResult: boolean;
        try {
          bioResult = await requireFreshBiometric();
        } finally {
          onBiometricActiveChange?.(false);
        }
        if (!bioResult) {
          setDecrypting(false);
          const msg = "Authentication required to view secure notes.";
          if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Authentication Required", msg); }
          return;
        }
      }

      // Re-check keyShares after the (possibly skipped) await — if
      // the vault locked while we were prompting, abort cleanly
      // rather than crashing in decryptSecureNote.
      if (!keyShares) {
        setDecrypting(false);
        return;
      }
      const decrypted = decryptSecureNote(note, keyShares);
      setDecryptedNote(decrypted);
    } catch (err) {
      // DEV-only diagnostics. Logs ONLY the failure category and the
      // SHAPE of the offending note (presence flags + ciphertext
      // segment count) — never plaintext, never ciphertext, never
      // keys, never the note id (which can be mildly identifying).
      // Production builds skip this entirely.
      if (__DEV__) {
        const category = categoriseDecryptError(err);
        const contentParts = typeof note.encryptedContent === "string"
          ? note.encryptedContent.split(":").length
          : 0;
        const labelParts = typeof note.encryptedLabel === "string"
          ? note.encryptedLabel.split(":").length
          : 0;
        // eslint-disable-next-line no-console
        console.log("[SecureNote.decrypt]", {
          category,
          hasKeyShares: !!keyShares,
          hasSalt: !!note.salt,
          hasEncryptedLabel: !!note.encryptedLabel,
          hasEncryptedContent: !!note.encryptedContent,
          hasPlaintextLabelFallback: !!note.label,
          contentSegmentCount: contentParts,
          labelSegmentCount: labelParts,
        });
      }
      setDecryptedNote(null);
      // Surface a clear failure state in the detail view itself
      // (handled by the !decryptedNote && decryptError branch
      // below) instead of an Alert + misleading "Authentication
      // required" UI. The user keeps the note selected and can
      // retry without re-tapping from the list.
      setDecryptError(categoriseDecryptError(err));
    }
    setDecrypting(false);
  }

  async function handleRetryDecrypt() {
    if (!selectedNote) return;
    await handleSelect(selectedNote);
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
                ) : !decryptedNote && decryptError ? (
                  // Explicit decryption-failure state. Replaces the
                  // earlier "Authentication required to view content"
                  // placeholder, which was misleading (the user HAD
                  // already authenticated) and dangerous when paired
                  // with a prominent Delete button as the only next
                  // action. Now: clear cause, explicit Retry, and the
                  // Delete button below is hidden so the user cannot
                  // destroy a possibly-recoverable note in one tap.
                  <View style={{ alignItems: "center", paddingVertical: 32 }}>
                    <Ionicons name="alert-circle" size={40} color="#fbbf24" />
                    <Text style={{ color: "#fbbf24", fontSize: 16, fontWeight: "700", marginTop: 12 }}>
                      Couldn&apos;t decrypt this note
                    </Text>
                    <Text style={{ color: "#aaa", fontSize: 13, marginTop: 8, textAlign: "center", paddingHorizontal: 12, lineHeight: 18 }}>
                      Your data is still safely stored. This usually means the
                      vault key briefly went out of sync. Try again — or lock
                      and unlock the vault and reopen this note.
                    </Text>
                    {__DEV__ && (
                      <Text style={{ color: "#666", fontSize: 11, marginTop: 8, fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace" }}>
                        dev:{decryptError}
                      </Text>
                    )}
                    <Pressable
                      onPress={handleRetryDecrypt}
                      style={{
                        marginTop: 20,
                        backgroundColor: "#4CAF50",
                        paddingVertical: 12,
                        paddingHorizontal: 24,
                        borderRadius: 8,
                      }}
                      testID="retry-decrypt-button"
                    >
                      <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}>Try Again</Text>
                    </Pressable>
                  </View>
                ) : !decryptedNote ? (
                  // Cancelled/declined biometric — no decrypt was attempted.
                  // Distinct from the failure state above.
                  <View style={{ alignItems: "center", paddingVertical: 40 }}>
                    <Ionicons name="lock-closed" size={40} color="#888" />
                    <Text style={{ color: "#aaa", fontSize: 14, marginTop: 12, textAlign: "center", paddingHorizontal: 12 }}>
                      Authentication cancelled. Tap the note again to view its contents.
                    </Text>
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

                {/* Delete is hidden in the decrypt-failure state.
                    Offering it as the only next action after a
                    transient decrypt error invites the user to
                    destroy a recoverable note. It re-appears once
                    decryption succeeds. */}
                {!decryptError && (
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
                )}
              </ScrollView>
            )}
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}
