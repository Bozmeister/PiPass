import React, { useState, useRef } from "react";
import { View, Text, TextInput, Pressable, Platform, ScrollView, Keyboard, KeyboardAvoidingView, Alert, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as ExpoCrypto from "expo-crypto";
import * as DocumentPicker from "expo-document-picker";
import * as FileSystem from "expo-file-system/legacy";
import { saveEntry } from "../workers/storageWorker";

const PROFILES = [
  { label: "Balanced", iterations: 25000, time: "~3s", desc: "Fast unlock", color: "#4CAF50", icon: "flash-outline" as const },
  { label: "Fortress", iterations: 100000, time: "~8s", desc: "Recommended", color: "#fbbf24", icon: "shield-checkmark-outline" as const },
  { label: "Deep Vault", iterations: 250000, time: "~20s", desc: "Maximum protection", color: "#ef4444", icon: "lock-closed-outline" as const },
];

interface SeedSetupScreenProps {
  onSeedSet: (seed: number, iterations: number) => void;
}

export default function SeedSetupScreen({ onSeedSet }: SeedSetupScreenProps) {
  const insets = useSafeAreaInsets();
  const [seedInput, setSeedInput] = useState("");
  const [selectedProfile, setSelectedProfile] = useState(1);
  const [importing, setImporting] = useState(false);
  const [importedCount, setImportedCount] = useState<number | null>(null);
  const inputRef = useRef<TextInput>(null);
  const webTopInset = Platform.OS === "web" ? 67 : 0;

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

      const backup = JSON.parse(json);
      if (!backup.version || !Array.isArray(backup.entries)) {
        const msg = "This file doesn't appear to be a valid PiPass backup.";
        if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Invalid File", msg); }
        return;
      }

      setImporting(true);
      let count = 0;
      for (const entry of backup.entries) {
        if (entry.id && entry.title) {
          await saveEntry(entry);
          count++;
        }
      }
      setImportedCount(count);
      setImporting(false);

      const msg = `Successfully imported ${count} entries. Set your Pi Seed and security profile to unlock the vault.`;
      if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Import Complete", msg); }
    } catch (err) {
      setImporting(false);
      console.error("Import failed:", err);
      const msg = "Could not read the backup file. Make sure it's a valid .vault file.";
      if (Platform.OS === "web") { alert(msg); } else { Alert.alert("Import Failed", msg); }
    }
  }

  function handleRandomSeed() {
    const bytes = ExpoCrypto.getRandomBytes(4);
    const val = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    const seed = val % 999000 + 1000;
    setSeedInput(seed.toString());
    Keyboard.dismiss();
  }

  function handleConfirm() {
    const seed = parseInt(seedInput, 10);
    if (isNaN(seed) || seed < 0 || seed > 999999) return;
    Keyboard.dismiss();
    onSeedSet(seed, PROFILES[selectedProfile].iterations);
  }

  const seedValue = parseInt(seedInput, 10);
  const isValid = !isNaN(seedValue) && seedValue >= 0 && seedValue <= 999999 && seedInput.trim().length > 0;

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
            <Ionicons name="key" size={48} color="#4CAF50" />
            <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold", marginTop: 16 }}>
              Set Your Pi Seed
            </Text>
            <Text style={{ color: "#aaa", fontSize: 14, textAlign: "center", marginTop: 8, lineHeight: 20 }}>
              Choose a secret number (0-999999). This number determines where in Pi your encryption key starts. Keep it private — it's part of your vault's security.
            </Text>
          </View>

          <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 6 }}>
            Pi Seed Index
          </Text>
          <TextInput
            ref={inputRef}
            value={seedInput}
            onChangeText={setSeedInput}
            onSubmitEditing={handleConfirm}
            returnKeyType="done"
            keyboardType="number-pad"
            placeholder="Enter a number (0-999999)"
            placeholderTextColor="#555"
            maxLength={6}
            style={{
              color: "#fff",
              fontSize: 24,
              backgroundColor: "#1a1a1a",
              borderRadius: 8,
              padding: 16,
              marginBottom: 12,
              textAlign: "center",
              letterSpacing: 4,
              borderWidth: 1,
              borderColor: isValid ? "#4CAF50" : "#333",
            }}
            testID="seed-input"
          />

          <Pressable
            onPress={handleRandomSeed}
            style={{
              flexDirection: "row",
              alignItems: "center",
              justifyContent: "center",
              paddingVertical: 12,
              marginBottom: 24,
            }}
            testID="random-seed-button"
          >
            <Ionicons name="dice-outline" size={18} color="#4CAF50" />
            <Text style={{ color: "#4CAF50", fontSize: 14, fontWeight: "600", marginLeft: 8 }}>
              Generate Random Seed
            </Text>
          </Pressable>

          <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 10 }}>
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
                  width: 22,
                  height: 22,
                  borderRadius: 11,
                  borderWidth: 2,
                  borderColor: selected ? profile.color : "#555",
                  alignItems: "center",
                  justifyContent: "center",
                  marginRight: 12,
                }}>
                  {selected && (
                    <View style={{
                      width: 12,
                      height: 12,
                      borderRadius: 6,
                      backgroundColor: profile.color,
                    }} />
                  )}
                </View>
                <Ionicons name={profile.icon} size={20} color={selected ? profile.color : "#666"} style={{ marginRight: 10 }} />
                <View style={{ flex: 1 }}>
                  <View style={{ flexDirection: "row", alignItems: "center" }}>
                    <Text style={{ color: selected ? "#fff" : "#aaa", fontSize: 15, fontWeight: "700" }}>
                      {profile.label}
                    </Text>
                    {profile.label === "Fortress" && (
                      <View style={{ backgroundColor: "#fbbf2433", borderRadius: 4, paddingHorizontal: 6, paddingVertical: 1, marginLeft: 8 }}>
                        <Text style={{ color: "#fbbf24", fontSize: 10, fontWeight: "700" }}>DEFAULT</Text>
                      </View>
                    )}
                  </View>
                  <Text style={{ color: "#888", fontSize: 12, marginTop: 2 }}>
                    {profile.desc}
                  </Text>
                </View>
                <View style={{ alignItems: "flex-end" }}>
                  <Text style={{ color: selected ? profile.color : "#666", fontSize: 13, fontWeight: "600" }}>
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
            backgroundColor: "#1a1a0a",
            borderWidth: 1,
            borderColor: "#444400",
            borderRadius: 8,
            padding: 12,
            marginTop: 14,
            marginBottom: 24,
          }}>
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 4 }}>
              <Ionicons name="warning-outline" size={16} color="#fbbf24" />
              <Text style={{ color: "#fbbf24", fontSize: 13, fontWeight: "600", marginLeft: 6 }}>
                Remember This Number
              </Text>
            </View>
            <Text style={{ color: "#aaa", fontSize: 12, lineHeight: 18 }}>
              This number is the heart of your vault. If you lose it, your passwords cannot be recovered.
            </Text>
          </View>

          <Pressable
            onPress={handleConfirm}
            disabled={!isValid}
            style={{
              backgroundColor: isValid ? "#4CAF50" : "#333",
              paddingVertical: 16,
              borderRadius: 8,
              alignItems: "center",
            }}
            testID="confirm-seed-button"
          >
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700" }}>
              {importedCount !== null ? `Set Seed & Restore ${importedCount} Entries` : "Set Seed & Create Vault"}
            </Text>
          </Pressable>

          <View style={{ marginTop: 32, borderTopWidth: 1, borderTopColor: "#222", paddingTop: 24 }}>
            <Text style={{ color: "#888", fontSize: 12, textTransform: "uppercase", marginBottom: 10 }}>
              Restore From Backup
            </Text>
            <Pressable
              onPress={handleImport}
              disabled={importing}
              style={{
                flexDirection: "row",
                alignItems: "center",
                justifyContent: "center",
                backgroundColor: "#0a1a1a",
                borderRadius: 10,
                padding: 14,
                borderWidth: 1,
                borderColor: "#114a4a",
              }}
              testID="import-backup-button"
            >
              {importing ? (
                <ActivityIndicator size="small" color="#4CAF50" />
              ) : (
                <>
                  <Ionicons name="cloud-upload-outline" size={18} color="#4CAF50" style={{ marginRight: 8 }} />
                  <Text style={{ color: "#4CAF50", fontSize: 15, fontWeight: "600" }}>
                    {importedCount !== null ? `${importedCount} Entries Loaded` : "Import .vault Backup"}
                  </Text>
                </>
              )}
            </Pressable>
            <Text style={{ color: "#666", fontSize: 11, textAlign: "center", marginTop: 8, lineHeight: 16 }}>
              Import a previously exported PiPass backup file. You must use the same Pi Seed and security profile that created the original vault.
            </Text>
          </View>
        </ScrollView>
      </Pressable>
    </KeyboardAvoidingView>
  );
}
