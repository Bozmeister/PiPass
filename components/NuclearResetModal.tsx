import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  View,
  Text,
  Modal,
  Pressable,
  TextInput,
  Platform,
  ActivityIndicator,
  KeyboardAvoidingView,
  ScrollView,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import {
  INPUT_BG,
  INPUT_TEXT,
  INPUT_PLACEHOLDER,
  INPUT_BORDER,
  INPUT_BORDER_FOCUS,
  INPUT_BORDER_ERROR,
} from "../styles/inputTheme";

const CONFIRMATION_PHRASE = "DELETE MY VAULT";
const COUNTDOWN_SECONDS = 10;

interface NuclearResetModalProps {
  visible: boolean;
  onClose: () => void;
  onConfirmReset: () => Promise<void>;
  verifyPassword: (password: string) => Promise<boolean>;
  requireBiometric?: () => Promise<boolean>;
}

type Step = "warning" | "password" | "phrase" | "countdown";

export default function NuclearResetModal({
  visible,
  onClose,
  onConfirmReset,
  verifyPassword,
  requireBiometric,
}: NuclearResetModalProps) {
  const insets = useSafeAreaInsets();
  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const webBottomInset = Platform.OS === "web" ? 34 : 0;

  const [step, setStep] = useState<Step>("warning");
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [passwordFocused, setPasswordFocused] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [phrase, setPhrase] = useState("");
  const [phraseFocused, setPhraseFocused] = useState(false);
  const [countdown, setCountdown] = useState(COUNTDOWN_SECONDS);
  const [executing, setExecuting] = useState(false);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const executingRef = useRef(false);
  const verifyingRef = useRef(false);
  const sessionRef = useRef(0);

  const resetState = useCallback(() => {
    setStep("warning");
    setPassword("");
    setPasswordError("");
    setVerifying(false);
    setPhrase("");
    setCountdown(COUNTDOWN_SECONDS);
    setExecuting(false);
    executingRef.current = false;
    verifyingRef.current = false;
    sessionRef.current += 1;
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
      countdownRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!visible) resetState();
  }, [visible, resetState]);

  useEffect(() => {
    if (step === "countdown" && countdown > 0) {
      countdownRef.current = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            if (countdownRef.current) clearInterval(countdownRef.current);
            countdownRef.current = null;
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => {
        if (countdownRef.current) {
          clearInterval(countdownRef.current);
          countdownRef.current = null;
        }
      };
    }
  }, [step]);

  const handleClose = () => {
    if (executing) return;
    onClose();
  };

  const handlePasswordSubmit = async () => {
    if (!password.trim() || verifyingRef.current) return;
    verifyingRef.current = true;
    setVerifying(true);
    setPasswordError("");
    const token = sessionRef.current;
    try {
      const valid = await verifyPassword(password);
      if (token !== sessionRef.current) return;
      if (valid) {
        setStep("phrase");
      } else {
        setPasswordError("Incorrect password");
      }
    } catch {
      if (token !== sessionRef.current) return;
      setPasswordError("Verification failed");
    }
    verifyingRef.current = false;
    setVerifying(false);
  };

  const handlePhraseSubmit = () => {
    if (phrase !== CONFIRMATION_PHRASE) return;
    setCountdown(COUNTDOWN_SECONDS);
    setStep("countdown");
  };

  const handleFinalConfirm = async () => {
    if (countdown > 0 || executingRef.current) return;
    executingRef.current = true;
    setExecuting(true);
    try {
      if (requireBiometric) {
        const bioResult = await requireBiometric();
        if (!bioResult) {
          setExecuting(false);
          executingRef.current = false;
          return;
        }
      }
      await onConfirmReset();
    } catch {
      setExecuting(false);
      executingRef.current = false;
    }
  };

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
        {!executing && (
          <View style={{ flexDirection: "row", justifyContent: "flex-end", paddingHorizontal: 16, paddingTop: 8 }}>
            <Pressable onPress={handleClose} hitSlop={16}>
              <Ionicons name="close" size={28} color="#666" />
            </Pressable>
          </View>
        )}

        <KeyboardAvoidingView
          style={{ flex: 1 }}
          behavior={Platform.OS === "ios" ? "padding" : "height"}
        >
        <ScrollView
          contentContainerStyle={{ flexGrow: 1, justifyContent: "center", paddingHorizontal: 24 }}
          keyboardShouldPersistTaps="handled"
          bounces={false}
        >
          {step === "warning" && (
            <View style={{ alignItems: "center" }}>
              <Ionicons name="nuclear-outline" size={64} color="#ef4444" />
              <Text style={{ color: "#ef4444", fontSize: 24, fontWeight: "bold" as const, marginTop: 20, textAlign: "center" }}>
                Nuclear Reset
              </Text>
              <Text style={{ color: "#ccc", fontSize: 16, textAlign: "center", marginTop: 16, lineHeight: 24 }}>
                This action permanently deletes all vault data and cannot be undone.
              </Text>
              <Text style={{ color: "#888", fontSize: 14, textAlign: "center", marginTop: 12, lineHeight: 20 }}>
                All passwords, secure notes, and encryption keys will be destroyed. You will need to set up PiPass from scratch.
              </Text>

              <Pressable
                onPress={() => setStep("password")}
                style={{ backgroundColor: "#2a1010", paddingVertical: 16, paddingHorizontal: 32, borderRadius: 12, marginTop: 40, borderWidth: 1, borderColor: "#ef4444" }}
              >
                <Text style={{ color: "#ef4444", fontSize: 16, fontWeight: "600" as const }}>I understand, continue</Text>
              </Pressable>

              <Pressable onPress={handleClose} style={{ marginTop: 20, padding: 12 }}>
                <Text style={{ color: "#666", fontSize: 16 }}>Cancel</Text>
              </Pressable>
            </View>
          )}

          {step === "password" && (
            <View>
              <View style={{ alignItems: "center", marginBottom: 32 }}>
                <Ionicons name="lock-closed" size={48} color="#ef4444" />
                <Text style={{ color: "#fff", fontSize: 20, fontWeight: "bold" as const, marginTop: 16 }}>
                  Verify Identity
                </Text>
                <Text style={{ color: "#888", fontSize: 14, textAlign: "center", marginTop: 8 }}>
                  Enter your master password to proceed
                </Text>
              </View>

              <TextInput
                value={password}
                onChangeText={(t) => { setPassword(t); setPasswordError(""); }}
                placeholder="Master password"
                placeholderTextColor={INPUT_PLACEHOLDER}
                secureTextEntry
                autoCapitalize="none"
                autoCorrect={false}
                editable={!verifying}
                onFocus={() => setPasswordFocused(true)}
                onBlur={() => setPasswordFocused(false)}
                onSubmitEditing={handlePasswordSubmit}
                style={{
                  color: INPUT_TEXT,
                  fontSize: 16,
                  padding: 14,
                  backgroundColor: INPUT_BG,
                  borderRadius: 8,
                  borderWidth: 1,
                  borderColor: passwordError ? INPUT_BORDER_ERROR : passwordFocused ? INPUT_BORDER_FOCUS : INPUT_BORDER,
                }}
                testID="nuclear-password-input"
              />

              {passwordError ? (
                <Text style={{ color: INPUT_BORDER_ERROR, fontSize: 14, marginTop: 8 }}>{passwordError}</Text>
              ) : null}

              <View style={{ flexDirection: "row", gap: 12, marginTop: 24 }}>
                <Pressable
                  onPress={handleClose}
                  disabled={verifying}
                  style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: "#1a1a1a", alignItems: "center" }}
                >
                  <Text style={{ color: "#aaa", fontSize: 16 }}>Cancel</Text>
                </Pressable>
                <Pressable
                  onPress={handlePasswordSubmit}
                  disabled={!password.trim() || verifying}
                  style={{
                    flex: 1,
                    padding: 14,
                    borderRadius: 8,
                    backgroundColor: password.trim() && !verifying ? "#ef4444" : "#333",
                    alignItems: "center",
                    flexDirection: "row",
                    justifyContent: "center",
                    gap: 8,
                  }}
                >
                  {verifying && <ActivityIndicator size="small" color="#fff" />}
                  <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Verify</Text>
                </Pressable>
              </View>
            </View>
          )}

          {step === "phrase" && (
            <View>
              <View style={{ alignItems: "center", marginBottom: 32 }}>
                <Ionicons name="warning" size={48} color="#ef4444" />
                <Text style={{ color: "#fff", fontSize: 20, fontWeight: "bold" as const, marginTop: 16 }}>
                  Final Confirmation
                </Text>
                <Text style={{ color: "#888", fontSize: 14, textAlign: "center", marginTop: 8 }}>
                  Type the exact phrase below to continue
                </Text>
              </View>

              <View style={{ backgroundColor: "#1a1010", padding: 16, borderRadius: 8, marginBottom: 16, borderWidth: 1, borderColor: "#3a1515" }}>
                <Text style={{ color: "#ef4444", fontSize: 18, fontWeight: "bold" as const, textAlign: "center", fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace" }}>
                  {CONFIRMATION_PHRASE}
                </Text>
              </View>

              <TextInput
                value={phrase}
                onChangeText={setPhrase}
                placeholder="Type confirmation phrase"
                placeholderTextColor={INPUT_PLACEHOLDER}
                autoCapitalize="characters"
                autoCorrect={false}
                onFocus={() => setPhraseFocused(true)}
                onBlur={() => setPhraseFocused(false)}
                onSubmitEditing={handlePhraseSubmit}
                style={{
                  color: INPUT_TEXT,
                  fontSize: 16,
                  padding: 14,
                  backgroundColor: INPUT_BG,
                  borderRadius: 8,
                  borderWidth: 1,
                  borderColor: phrase === CONFIRMATION_PHRASE
                    ? "#ef4444"
                    : phraseFocused
                    ? INPUT_BORDER_FOCUS
                    : INPUT_BORDER,
                }}
                testID="nuclear-phrase-input"
              />

              <View style={{ flexDirection: "row", gap: 12, marginTop: 24 }}>
                <Pressable
                  onPress={handleClose}
                  style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: "#1a1a1a", alignItems: "center" }}
                >
                  <Text style={{ color: "#aaa", fontSize: 16 }}>Cancel</Text>
                </Pressable>
                <Pressable
                  onPress={handlePhraseSubmit}
                  disabled={phrase !== CONFIRMATION_PHRASE}
                  style={{
                    flex: 1,
                    padding: 14,
                    borderRadius: 8,
                    backgroundColor: phrase === CONFIRMATION_PHRASE ? "#ef4444" : "#333",
                    alignItems: "center",
                  }}
                >
                  <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Continue</Text>
                </Pressable>
              </View>
            </View>
          )}

          {step === "countdown" && (
            <View style={{ alignItems: "center" }}>
              {executing ? (
                <>
                  <ActivityIndicator size="large" color="#ef4444" />
                  <Text style={{ color: "#ef4444", fontSize: 20, fontWeight: "bold" as const, marginTop: 24 }}>
                    Destroying vault data...
                  </Text>
                </>
              ) : (
                <>
                  <Ionicons name="skull-outline" size={64} color="#ef4444" />
                  <Text style={{ color: "#ef4444", fontSize: 24, fontWeight: "bold" as const, marginTop: 20 }}>
                    Point of No Return
                  </Text>
                  <Text style={{ color: "#888", fontSize: 14, textAlign: "center", marginTop: 12, lineHeight: 20 }}>
                    {countdown > 0
                      ? `Button will be enabled in ${countdown} second${countdown !== 1 ? "s" : ""}`
                      : "You may now execute the nuclear reset"}
                  </Text>

                  <Pressable
                    onPress={handleFinalConfirm}
                    disabled={countdown > 0}
                    style={{
                      backgroundColor: countdown > 0 ? "#1a1a1a" : "#ef4444",
                      paddingVertical: 18,
                      paddingHorizontal: 40,
                      borderRadius: 12,
                      marginTop: 40,
                      borderWidth: countdown > 0 ? 1 : 0,
                      borderColor: "#333",
                      opacity: countdown > 0 ? 0.5 : 1,
                    }}
                    testID="nuclear-final-button"
                  >
                    <Text style={{ color: countdown > 0 ? "#666" : "#fff", fontSize: 18, fontWeight: "bold" as const }}>
                      {countdown > 0 ? `Wait ${countdown}s` : "Destroy Everything"}
                    </Text>
                  </Pressable>

                  <Pressable onPress={handleClose} style={{ marginTop: 24, padding: 12 }}>
                    <Text style={{ color: "#666", fontSize: 16 }}>Cancel</Text>
                  </Pressable>
                </>
              )}
            </View>
          )}
        </ScrollView>
        </KeyboardAvoidingView>
      </View>
    </Modal>
  );
}
