import React, { useState, useEffect, useCallback, useRef } from "react";
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
import { splitSecret, formatShare, ShamirShare } from "../crypto/shamir";

interface RecoveryKeyModalProps {
  visible: boolean;
  formattedKey: string;
  rawKeyHex: string;
  onConfirm: () => void;
}

type Mode = "choose" | "standard" | "split-view";

export default function RecoveryKeyModal({
  visible,
  formattedKey,
  rawKeyHex,
  onConfirm,
}: RecoveryKeyModalProps) {
  const insets = useSafeAreaInsets();
  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const webBottomInset = Platform.OS === "web" ? 34 : 0;

  const [mode, setMode] = useState<Mode>("choose");
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [shares, setShares] = useState<ShamirShare[]>([]);
  const [currentShareIdx, setCurrentShareIdx] = useState(0);
  const [sharesSaved, setSharesSaved] = useState<boolean[]>([]);
  const [shareCopied, setShareCopied] = useState(false);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!visible) {
      setMode("choose");
      setSaved(false);
      setCopied(false);
      setShares([]);
      setCurrentShareIdx(0);
      setSharesSaved([]);
      setShareCopied(false);
      if (copyTimerRef.current) { clearTimeout(copyTimerRef.current); copyTimerRef.current = null; }
    }
  }, [visible]);

  const cleanupShares = useCallback(() => {
    setShares([]);
    setSharesSaved([]);
    setCurrentShareIdx(0);
    setShareCopied(false);
  }, []);

  const handleCopy = useCallback(async (text: string, setSt: (v: boolean) => void) => {
    try {
      await Clipboard.setStringAsync(text);
      setSt(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => { setSt(false); copyTimerRef.current = null; }, 2000);
    } catch {}
  }, []);

  const handleSplitKey = useCallback(() => {
    const generated = splitSecret(rawKeyHex, 3, 2);
    setShares(generated);
    setSharesSaved(new Array(generated.length).fill(false));
    setCurrentShareIdx(0);
    setMode("split-view");
  }, [rawKeyHex]);

  const markShareSaved = useCallback((idx: number) => {
    setSharesSaved((prev) => {
      const next = [...prev];
      next[idx] = !next[idx];
      return next;
    });
  }, []);

  const allSharesSaved = sharesSaved.length > 0 && sharesSaved.every(Boolean);

  if (!visible) return null;

  const containerStyle = {
    flex: 1,
    backgroundColor: "#0a0a0a",
    paddingTop: insets.top + webTopInset,
    paddingBottom: insets.bottom + webBottomInset,
  };

  const scrollContent = {
    flexGrow: 1,
    justifyContent: "center" as const,
    paddingHorizontal: 24,
    paddingVertical: 20,
  };

  if (mode === "choose") {
    return (
      <Modal visible={visible} animationType="fade" transparent={false}>
        <View style={containerStyle}>
          <ScrollView contentContainerStyle={scrollContent} keyboardShouldPersistTaps="handled">
            <View style={{ alignItems: "center", marginBottom: 32 }}>
              <Ionicons name="key" size={56} color="#4CAF50" />
              <Text style={{ color: "#fff", fontSize: 22, fontWeight: "bold" as const, marginTop: 16, textAlign: "center" }}>
                Recovery Key Setup
              </Text>
              <Text style={{ color: "#888", fontSize: 14, textAlign: "center", marginTop: 8, lineHeight: 20 }}>
                Choose how to store your recovery key
              </Text>
            </View>

            <Pressable
              onPress={() => setMode("standard")}
              style={{
                backgroundColor: "#111",
                padding: 20,
                borderRadius: 12,
                borderWidth: 1,
                borderColor: "#333",
                marginBottom: 16,
              }}
            >
              <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 8 }}>
                <Ionicons name="key-outline" size={24} color="#4CAF50" />
                <Text style={{ color: "#fff", fontSize: 18, fontWeight: "600" as const, marginLeft: 12 }}>
                  Standard Recovery Key
                </Text>
              </View>
              <Text style={{ color: "#888", fontSize: 13, lineHeight: 20 }}>
                A single key you store in one safe location. Simple and straightforward.
              </Text>
            </Pressable>

            <Pressable
              onPress={handleSplitKey}
              style={{
                backgroundColor: "#111",
                padding: 20,
                borderRadius: 12,
                borderWidth: 1,
                borderColor: "#333",
              }}
            >
              <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 8 }}>
                <Ionicons name="git-branch-outline" size={24} color="#4a90d9" />
                <Text style={{ color: "#fff", fontSize: 18, fontWeight: "600" as const, marginLeft: 12 }}>
                  Advanced: Split Key (2-of-3)
                </Text>
              </View>
              <Text style={{ color: "#888", fontSize: 13, lineHeight: 20 }}>
                Split into 3 shares. Any 2 shares can reconstruct your key. Store each share in a different location for added security.
              </Text>
            </Pressable>
          </ScrollView>
        </View>
      </Modal>
    );
  }

  if (mode === "standard") {
    return (
      <Modal visible={visible} animationType="fade" transparent={false}>
        <View style={containerStyle}>
          <ScrollView contentContainerStyle={scrollContent} keyboardShouldPersistTaps="handled">
            <View style={{ alignItems: "center", marginBottom: 24 }}>
              <Ionicons name="key" size={56} color="#4CAF50" />
              <Text style={{ color: "#fff", fontSize: 22, fontWeight: "bold" as const, marginTop: 16, textAlign: "center" }}>
                Recovery Key
              </Text>
            </View>

            <View style={{ backgroundColor: "#1a0808", padding: 16, borderRadius: 12, borderWidth: 1, borderColor: "#ef4444", marginBottom: 16 }}>
              <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 8 }}>
                <Ionicons name="warning" size={18} color="#ef4444" />
                <Text style={{ color: "#ef4444", fontSize: 14, fontWeight: "600" as const, marginLeft: 8 }}>Save this key now</Text>
              </View>
              <Text style={{ color: "#ccc", fontSize: 13, lineHeight: 20 }}>
                This key is the ONLY way to recover your vault if you forget your password. It will not be shown again.
              </Text>
            </View>

            <View style={{ backgroundColor: "#111", padding: 20, borderRadius: 12, borderWidth: 1, borderColor: "#333", marginBottom: 16 }}>
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
              onPress={() => handleCopy(formattedKey, setCopied)}
              style={{ flexDirection: "row", alignItems: "center", justifyContent: "center", backgroundColor: "#1a1a1a", padding: 14, borderRadius: 8, marginBottom: 24, gap: 8 }}
            >
              <Ionicons name={copied ? "checkmark" : "copy-outline"} size={18} color={copied ? "#4CAF50" : "#aaa"} />
              <Text style={{ color: copied ? "#4CAF50" : "#aaa", fontSize: 14 }}>{copied ? "Copied!" : "Copy to clipboard"}</Text>
            </Pressable>

            <Pressable onPress={() => setSaved(!saved)} style={{ flexDirection: "row", alignItems: "center", paddingVertical: 12, paddingHorizontal: 4 }}>
              <View style={{ width: 24, height: 24, borderRadius: 4, borderWidth: 2, borderColor: saved ? "#4CAF50" : "#555", backgroundColor: saved ? "#4CAF50" : "transparent", alignItems: "center", justifyContent: "center", marginRight: 12 }}>
                {saved && <Ionicons name="checkmark" size={16} color="#fff" />}
              </View>
              <Text style={{ color: "#ccc", fontSize: 15, flex: 1 }}>I have saved this recovery key in a safe place</Text>
            </Pressable>

            <Pressable
              onPress={onConfirm}
              disabled={!saved}
              style={{ backgroundColor: saved ? "#4CAF50" : "#333", padding: 16, borderRadius: 12, alignItems: "center", marginTop: 20, opacity: saved ? 1 : 0.5 }}
            >
              <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Continue to Vault</Text>
            </Pressable>

            <Pressable onPress={() => { setMode("choose"); setSaved(false); setCopied(false); }} style={{ alignItems: "center", marginTop: 16, padding: 8 }}>
              <Text style={{ color: "#666", fontSize: 14 }}>Back to options</Text>
            </Pressable>
          </ScrollView>
        </View>
      </Modal>
    );
  }

  const currentShare = shares[currentShareIdx];
  const currentFormatted = currentShare ? formatShare(currentShare) : "";
  const isLastShare = currentShareIdx === shares.length - 1;

  return (
    <Modal visible={visible} animationType="fade" transparent={false}>
      <View style={containerStyle}>
        <ScrollView contentContainerStyle={scrollContent} keyboardShouldPersistTaps="handled">
          <View style={{ alignItems: "center", marginBottom: 24 }}>
            <Ionicons name="git-branch-outline" size={56} color="#4a90d9" />
            <Text style={{ color: "#fff", fontSize: 22, fontWeight: "bold" as const, marginTop: 16, textAlign: "center" }}>
              Share {currentShareIdx + 1} of {shares.length}
            </Text>
            <Text style={{ color: "#888", fontSize: 13, textAlign: "center", marginTop: 8 }}>
              Any 2 of 3 shares can recover your vault
            </Text>
          </View>

          <View style={{ backgroundColor: "#0d1a2e", padding: 16, borderRadius: 12, borderWidth: 1, borderColor: "#1a3a6e", marginBottom: 16 }}>
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 8 }}>
              <Ionicons name="information-circle" size={18} color="#4a90d9" />
              <Text style={{ color: "#4a90d9", fontSize: 14, fontWeight: "600" as const, marginLeft: 8 }}>
                Store this share separately
              </Text>
            </View>
            <Text style={{ color: "#aac", fontSize: 13, lineHeight: 20 }}>
              Each share should be kept in a different secure location. A single share cannot recover your vault.
            </Text>
          </View>

          <View style={{ backgroundColor: "#111", padding: 20, borderRadius: 12, borderWidth: 1, borderColor: "#333", marginBottom: 16 }}>
            <Text
              selectable
              style={{
                color: "#4a90d9",
                fontSize: 14,
                fontWeight: "600" as const,
                textAlign: "center",
                lineHeight: 24,
                fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
                letterSpacing: 0.5,
              }}
            >
              {currentFormatted}
            </Text>
          </View>

          <Pressable
            onPress={() => handleCopy(currentFormatted, setShareCopied)}
            style={{ flexDirection: "row", alignItems: "center", justifyContent: "center", backgroundColor: "#1a1a1a", padding: 14, borderRadius: 8, marginBottom: 16, gap: 8 }}
          >
            <Ionicons name={shareCopied ? "checkmark" : "copy-outline"} size={18} color={shareCopied ? "#4a90d9" : "#aaa"} />
            <Text style={{ color: shareCopied ? "#4a90d9" : "#aaa", fontSize: 14 }}>{shareCopied ? "Copied!" : "Copy share"}</Text>
          </Pressable>

          <Pressable onPress={() => markShareSaved(currentShareIdx)} style={{ flexDirection: "row", alignItems: "center", paddingVertical: 12, paddingHorizontal: 4 }}>
            <View style={{ width: 24, height: 24, borderRadius: 4, borderWidth: 2, borderColor: sharesSaved[currentShareIdx] ? "#4a90d9" : "#555", backgroundColor: sharesSaved[currentShareIdx] ? "#4a90d9" : "transparent", alignItems: "center", justifyContent: "center", marginRight: 12 }}>
              {sharesSaved[currentShareIdx] && <Ionicons name="checkmark" size={16} color="#fff" />}
            </View>
            <Text style={{ color: "#ccc", fontSize: 15, flex: 1 }}>I have saved Share {currentShareIdx + 1}</Text>
          </Pressable>

          <View style={{ flexDirection: "row", marginTop: 20, gap: 12 }}>
            <Pressable
              onPress={() => { setCurrentShareIdx((i) => Math.max(0, i - 1)); setShareCopied(false); }}
              disabled={currentShareIdx === 0}
              style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: currentShareIdx > 0 ? "#1a1a1a" : "#0d0d0d", alignItems: "center", opacity: currentShareIdx > 0 ? 1 : 0.3 }}
            >
              <Text style={{ color: "#aaa", fontSize: 16 }}>Previous</Text>
            </Pressable>

            {isLastShare ? (
              <Pressable
                onPress={() => { cleanupShares(); onConfirm(); }}
                disabled={!allSharesSaved}
                style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: allSharesSaved ? "#4CAF50" : "#333", alignItems: "center", opacity: allSharesSaved ? 1 : 0.5 }}
              >
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Continue to Vault</Text>
              </Pressable>
            ) : (
              <Pressable
                onPress={() => { setCurrentShareIdx((i) => i + 1); setShareCopied(false); }}
                disabled={!sharesSaved[currentShareIdx]}
                style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: sharesSaved[currentShareIdx] ? "#4a90d9" : "#333", alignItems: "center", opacity: sharesSaved[currentShareIdx] ? 1 : 0.5 }}
              >
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Next Share</Text>
              </Pressable>
            )}
          </View>

          <View style={{ flexDirection: "row", justifyContent: "center", marginTop: 16, gap: 8 }}>
            {shares.map((_, i) => (
              <View
                key={i}
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 5,
                  backgroundColor: i === currentShareIdx ? "#4a90d9" : sharesSaved[i] ? "#4a90d950" : "#333",
                }}
              />
            ))}
          </View>

          <Pressable onPress={() => { setMode("choose"); setShares([]); setSharesSaved([]); setCurrentShareIdx(0); }} style={{ alignItems: "center", marginTop: 16, padding: 8 }}>
            <Text style={{ color: "#666", fontSize: 14 }}>Back to options</Text>
          </Pressable>
        </ScrollView>
      </View>
    </Modal>
  );
}
