import React, { useState, useRef } from "react";
import { View, Text, TextInput, Pressable, Platform, ScrollView, Keyboard, KeyboardAvoidingView } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as ExpoCrypto from "expo-crypto";

interface SeedSetupScreenProps {
  onSeedSet: (seed: number) => void;
}

export default function SeedSetupScreen({ onSeedSet }: SeedSetupScreenProps) {
  const insets = useSafeAreaInsets();
  const [seedInput, setSeedInput] = useState("");
  const inputRef = useRef<TextInput>(null);
  const webTopInset = Platform.OS === "web" ? 67 : 0;

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
    onSeedSet(seed);
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

          <View style={{
            backgroundColor: "#1a1a0a",
            borderWidth: 1,
            borderColor: "#444400",
            borderRadius: 8,
            padding: 12,
            marginBottom: 24,
          }}>
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 4 }}>
              <Ionicons name="warning-outline" size={16} color="#fbbf24" />
              <Text style={{ color: "#fbbf24", fontSize: 13, fontWeight: "600", marginLeft: 6 }}>
                Remember This Number
              </Text>
            </View>
            <Text style={{ color: "#aaa", fontSize: 12, lineHeight: 18 }}>
              Your Pi seed cannot be recovered. If you forget it, your encrypted passwords will be permanently inaccessible.
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
              Set Seed & Create Vault
            </Text>
          </Pressable>
        </ScrollView>
      </Pressable>
    </KeyboardAvoidingView>
  );
}
