import React, { useState, useRef } from "react";
import { View, Text, TextInput, Pressable, Platform, ScrollView, Keyboard, KeyboardAvoidingView, Alert, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as DocumentPicker from "expo-document-picker";
import * as FileSystem from "expo-file-system/legacy";
import { parsePipassBackup, type BackupStageResult } from "../lib/backupSchema";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_ERROR, INPUT_BORDER_FOCUS, INPUT_BORDER_SUCCESS, LABEL_COLOR } from "../styles/inputTheme";

const PROFILES = [
  { label: "Balanced", iterations: 25000, time: "~3s", desc: "Fast unlock", color: "#4CAF50", icon: "flash-outline" as const },
  { label: "Fortress", iterations: 100000, time: "~8s", desc: "Recommended", color: "#fbbf24", icon: "shield-checkmark-outline" as const },
  { label: "Deep Vault", iterations: 250000, time: "~20s", desc: "Maximum protection", color: "#ef4444", icon: "lock-closed-outline" as const },
];

const MIN_PASSWORD_LENGTH = 8;

export interface StagedBackupSummary {
  entries: number;
  secureNotes: number;
  warnings: string[];
}

export interface StagedBackupSelection {
  backup: BackupStageResult;
  summary: StagedBackupSummary;
}

interface SeedSetupScreenProps {
  onSetup: (password: string, iterations: number) => Promise<void> | void;
  onStagedBackupChange?: (selection: StagedBackupSelection | null) => void;
}

export default function SeedSetupScreen({ onSetup, onStagedBackupChange }: SeedSetupScreenProps) {
  const insets = useSafeAreaInsets();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [selectedProfile, setSelectedProfile] = useState(1);
  const [importing, setImporting] = useState(false);
  const [stagedBackupSummary, setStagedBackupSummary] = useState<StagedBackupSummary | null>(null);
  const [backupStageError, setBackupStageError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [setupError, setSetupError] = useState<string | null>(null);
  const [settingUp, setSettingUp] = useState(false);
  const passwordRef = useRef<TextInput>(null);
  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const [focusedField, setFocusedField] = useState<string | null>(null);

  const passwordsMatch = password === confirmPassword;
  const showMismatch = confirmPassword.length > 0 && !passwordsMatch;
  const passwordStrong = password.length >= MIN_PASSWORD_LENGTH;
  const isValid = passwordStrong && passwordsMatch && confirmPassword.length > 0;

  async function handleImport() {
    try {
      let json: string | null = null;

      if (Platform.OS === "web") {
        json = await new Promise<string | null>((resolve) => {
          const input = document.createElement("input");
          input.type = "file";
          input.accept = ".vault,.json";
          input.onchange = (e: any) => {
            const file = e.target.files?.[0];
            if (!file) { resolve(null); return; }
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result as string);
            reader.onerror = () => resolve(null);
            reader.readAsText(file);
          };
          input.click();
        });
      } else {
        const result = await DocumentPicker.getDocumentAsync({ type: "*/*", copyToCacheDirectory: true });
        if (result.canceled || !result.assets?.[0]) return;
        json = await FileSystem.readAsStringAsync(result.assets[0].uri, { encoding: FileSystem.EncodingType.UTF8 });
      }

      if (!json) return;

      setImporting(true);
      setBackupStageError(null);

      const staged = parsePipassBackup(json);
      if (!staged.ok) {
        setStagedBackupSummary(null);
        onStagedBackupChange?.(null);
        const msg = "This file is not a supported PiPass backup. Nothing was imported.";
        setBackupStageError(msg);
        if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Backup Not Supported", msg); }
        return;
      }

      const summary = {
        entries: staged.backup.counts.entries,
        secureNotes: staged.backup.counts.secureNotes,
        warnings: staged.backup.warnings,
      };
      setStagedBackupSummary(summary);
      onStagedBackupChange?.({ backup: staged.backup, summary });

      const msg = `Backup validated: ${summary.entries} entries, ${summary.secureNotes} secure notes. Import commit will be enabled in a future step.`;
      if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Backup Validated", msg); }
    } catch {
      const msg = "Could not read the backup file. Make sure it's a valid .vault file.";
      setStagedBackupSummary(null);
      onStagedBackupChange?.(null);
      setBackupStageError(msg);
      if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Import Failed", msg); }
    } finally {
      setImporting(false);
    }
  }

  async function handleConfirm() {
    if (!isValid || settingUp) return;
    Keyboard.dismiss();
    setSetupError(null);
    setSettingUp(true);
    try {
      await onSetup(password, PROFILES[selectedProfile].iterations);
    } catch {
      setSetupError("PiPass could not start its secure key-derivation engine on this device. Your vault has not been created or changed. Please restart the app, update the app, or try again later.");
    } finally {
      setSettingUp(false);
    }
  }

  return (
    <KeyboardAvoidingView
      style={{ flex: 1, backgroundColor: "#000" }}
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      keyboardVerticalOffset={0}
    >
      <Pressable style={{ flex: 1 }} onPress={Keyboard.dismiss}>
        <ScrollView
          contentContainerStyle={{
            flexGrow: 1,
            paddingTop: insets.top + webTopInset + 24,
            paddingHorizontal: 24,
            paddingBottom: insets.bottom + 24,
          }}
          keyboardShouldPersistTaps="handled"
        >
          <View style={{ alignItems: "center", marginBottom: 32 }}>
            <Ionicons name="shield-checkmark" size={48} color="#4CAF50" />
            <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold" as const, marginTop: 16 }}>
              Create Master Password
            </Text>
            <Text style={{ color: "#aaa", fontSize: 14, textAlign: "center", marginTop: 8, lineHeight: 20 }}>
              Your master password protects your entire vault. Choose a strong, unique password that you can remember.
            </Text>
          </View>

          <Text style={{ color: LABEL_COLOR, fontSize: 12, textTransform: "uppercase" as const, marginBottom: 6 }}>
            Master Password
          </Text>
          <View style={{ flexDirection: "row", alignItems: "center", backgroundColor: INPUT_BG, borderRadius: 8, marginBottom: 4, borderWidth: 1, borderColor: password.length > 0 ? (passwordStrong ? INPUT_BORDER_SUCCESS : INPUT_BORDER_ERROR) : (focusedField === "password" ? INPUT_BORDER_FOCUS : INPUT_BORDER) }}>
            <TextInput
              ref={passwordRef}
              value={password}
              onChangeText={setPassword}
              placeholder="Enter master password"
              placeholderTextColor={INPUT_PLACEHOLDER}
              secureTextEntry={!showPassword}
              autoCapitalize="none"
              autoCorrect={false}
              textContentType="none"
              autoComplete="off"
              onFocus={() => setFocusedField("password")}
              onBlur={() => setFocusedField(null)}
              style={{ color: INPUT_TEXT, fontSize: 18, padding: 16, flex: 1 }}
              testID="password-input"
            />
            <Pressable onPress={() => setShowPassword(!showPassword)} style={{ padding: 16 }}>
              <Ionicons name={showPassword ? "eye-off-outline" : "eye-outline"} size={20} color="#888" />
            </Pressable>
          </View>
          {password.length > 0 && !passwordStrong && (
            <Text style={{ color: "#ff4444", fontSize: 12, marginBottom: 12 }}>
              Minimum {MIN_PASSWORD_LENGTH} characters required
            </Text>
          )}
          {passwordStrong && (
            <Text style={{ color: "#4CAF50", fontSize: 12, marginBottom: 12 }}>
              Password strength: Good
            </Text>
          )}
          {!password.length && <View style={{ height: 12, marginBottom: 12 }} />}

          <Text style={{ color: LABEL_COLOR, fontSize: 12, textTransform: "uppercase" as const, marginBottom: 6 }}>
            Confirm Password
          </Text>
          <TextInput
            value={confirmPassword}
            onChangeText={setConfirmPassword}
            placeholder="Re-enter master password"
            placeholderTextColor={INPUT_PLACEHOLDER}
            secureTextEntry={!showPassword}
            autoCapitalize="none"
            autoCorrect={false}
            textContentType="none"
            autoComplete="off"
            onFocus={() => setFocusedField("confirm")}
            onBlur={() => setFocusedField(null)}
            style={{
              color: INPUT_TEXT,
              fontSize: 18,
              backgroundColor: INPUT_BG,
              borderRadius: 8,
              padding: 16,
              marginBottom: showMismatch ? 4 : 16,
              borderWidth: 1,
              borderColor: showMismatch ? INPUT_BORDER_ERROR : confirmPassword.length > 0 && passwordsMatch ? INPUT_BORDER_SUCCESS : (focusedField === "confirm" ? INPUT_BORDER_FOCUS : INPUT_BORDER),
            }}
            testID="confirm-password-input"
          />
          {showMismatch && (
            <Text style={{ color: "#ff4444", fontSize: 12, marginBottom: 16 }}>
              Passwords do not match
            </Text>
          )}

          <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 10, marginTop: 8 }}>
            Security Profile
          </Text>
          {PROFILES.map((profile, idx) => {
            const selected = idx === selectedProfile;
            return (
              <Pressable
                key={profile.label}
                onPress={() => setSelectedProfile(idx)}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  backgroundColor: selected ? "#1a1a2e" : "#111",
                  borderRadius: 10,
                  padding: 14,
                  marginBottom: 10,
                  borderWidth: 2,
                  borderColor: selected ? profile.color : "#222",
                }}
                testID={`profile-${profile.label.toLowerCase().replace(" ", "-")}`}
              >
                <View style={{
                  width: 22, height: 22, borderRadius: 11,
                  borderWidth: 2, borderColor: selected ? profile.color : "#555",
                  alignItems: "center", justifyContent: "center", marginRight: 12,
                }}>
                  {selected && (
                    <View style={{ width: 12, height: 12, borderRadius: 6, backgroundColor: profile.color }} />
                  )}
                </View>
                <Ionicons name={profile.icon} size={20} color={selected ? profile.color : "#666"} style={{ marginRight: 10 }} />
                <View style={{ flex: 1 }}>
                  <View style={{ flexDirection: "row", alignItems: "center" }}>
                    <Text style={{ color: selected ? "#fff" : "#aaa", fontSize: 15, fontWeight: "700" as const }}>
                      {profile.label}
                    </Text>
                    {profile.label === "Fortress" && (
                      <View style={{ backgroundColor: "#fbbf2433", borderRadius: 4, paddingHorizontal: 6, paddingVertical: 1, marginLeft: 8 }}>
                        <Text style={{ color: "#fbbf24", fontSize: 10, fontWeight: "700" as const }}>DEFAULT</Text>
                      </View>
                    )}
                  </View>
                  <Text style={{ color: "#888", fontSize: 12, marginTop: 2 }}>{profile.desc}</Text>
                </View>
                <View style={{ alignItems: "flex-end" }}>
                  <Text style={{ color: selected ? profile.color : "#666", fontSize: 13, fontWeight: "600" as const }}>
                    {profile.time}
                  </Text>
                  <Text style={{ color: "#555", fontSize: 10 }}>
                    {(profile.iterations / 1000).toFixed(0)}k rounds
                  </Text>
                </View>
              </Pressable>
            );
          })}

          <View style={{
            backgroundColor: "#1a1a0a", borderWidth: 1, borderColor: "#444400",
            borderRadius: 8, padding: 12, marginTop: 14, marginBottom: 24,
          }}>
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 4 }}>
              <Ionicons name="warning-outline" size={16} color="#fbbf24" />
              <Text style={{ color: "#fbbf24", fontSize: 13, fontWeight: "600" as const, marginLeft: 6 }}>
                Zero-Knowledge Security
              </Text>
            </View>
            <Text style={{ color: "#aaa", fontSize: 12, lineHeight: 18 }}>
              Your master password is never stored. All encryption happens on your device. If you forget your password, your vault cannot be recovered.
            </Text>
          </View>

          <Pressable
            onPress={handleConfirm}
            disabled={!isValid || settingUp}
            style={{
              backgroundColor: isValid && !settingUp ? "#4CAF50" : "#333",
              paddingVertical: 16, borderRadius: 8, alignItems: "center",
            }}
            testID="confirm-setup-button"
          >
            {settingUp ? (
              <ActivityIndicator size="small" color="#fff" />
            ) : (
              <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700" as const }}>
                Create Vault
              </Text>
            )}
          </Pressable>
          {setupError && (
            <Text style={{ color: "#ef4444", fontSize: 13, lineHeight: 18, marginTop: 12, textAlign: "center" }}>
              {setupError}
            </Text>
          )}

          <View style={{ marginTop: 32, borderTopWidth: 1, borderTopColor: "#222", paddingTop: 24 }}>
            <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase" as const, marginBottom: 10 }}>
              Restore From Backup
            </Text>
            <Pressable
              onPress={handleImport}
              disabled={importing}
              style={{
                flexDirection: "row", alignItems: "center", justifyContent: "center",
                backgroundColor: "#0a1a1a", borderRadius: 10, padding: 14,
                borderWidth: 1, borderColor: "#114a4a",
              }}
              testID="import-backup-button"
            >
              {importing ? (
                <ActivityIndicator size="small" color="#4CAF50" />
              ) : (
                <>
                  <Ionicons name="cloud-upload-outline" size={18} color="#4CAF50" style={{ marginRight: 8 }} />
                  <Text style={{ color: "#4CAF50", fontSize: 15, fontWeight: "600" as const }}>
                    {stagedBackupSummary ? "Backup Validated" : "Validate .vault Backup"}
                  </Text>
                </>
              )}
            </Pressable>
            {stagedBackupSummary && (
              <View style={{ backgroundColor: "#0f1a0f", borderWidth: 1, borderColor: "#214d21", borderRadius: 8, padding: 12, marginTop: 12 }}>
                <Text style={{ color: "#4CAF50", fontSize: 13, fontWeight: "700" as const, marginBottom: 4 }}>
                  Backup validated
                </Text>
                <Text style={{ color: "#aaa", fontSize: 12, lineHeight: 18 }}>
                  {stagedBackupSummary.entries} entries and {stagedBackupSummary.secureNotes} secure notes were staged in memory only. Import commit will be enabled in a future step.
                </Text>
                {stagedBackupSummary.warnings.length > 0 && (
                  <Text style={{ color: "#fbbf24", fontSize: 12, lineHeight: 18, marginTop: 8 }}>
                    This encrypted backup still requires future compatibility verification before it can be imported.
                  </Text>
                )}
                <Pressable
                  onPress={() => {
                    setStagedBackupSummary(null);
                    setBackupStageError(null);
                    onStagedBackupChange?.(null);
                  }}
                  style={{ marginTop: 10, alignSelf: "flex-start", paddingVertical: 6, paddingHorizontal: 8 }}
                  testID="clear-staged-backup-button"
                >
                  <Text style={{ color: "#aaa", fontSize: 12, fontWeight: "600" as const }}>
                    Clear selected backup
                  </Text>
                </Pressable>
              </View>
            )}
            {backupStageError && (
              <Text style={{ color: "#ef4444", fontSize: 12, lineHeight: 18, marginTop: 10 }}>
                {backupStageError}
              </Text>
            )}
          </View>
        </ScrollView>
      </Pressable>
    </KeyboardAvoidingView>
  );
}
