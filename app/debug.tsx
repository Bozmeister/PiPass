import React from "react";
import { View, Text, Pressable, Platform } from "react-native";
import { useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";

export default function DebugScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();

  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const webBottomInset = Platform.OS === "web" ? 34 : 0;

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      <View
        style={{
          paddingTop: insets.top + webTopInset,
          paddingHorizontal: 16,
          paddingBottom: 12,
          flexDirection: "row",
          alignItems: "center",
        }}
      >
        <Pressable onPress={() => router.back()} style={{ marginRight: 12 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </Pressable>
        <Text style={{ color: "#fff", fontSize: 22, fontWeight: "bold" }}>
          Entropy Engine
        </Text>
      </View>

      <View
        style={{
          flex: 1,
          justifyContent: "center",
          alignItems: "center",
          paddingHorizontal: 16,
          paddingBottom: insets.bottom + webBottomInset,
        }}
      >
        <Text
          style={{
            color: "#fff",
            fontSize: 24,
            fontWeight: "600",
            marginBottom: 8,
          }}
        >
          v1.0.0
        </Text>
        <Text style={{ color: "#888", fontSize: 14 }}>
          All systems nominal
        </Text>
      </View>
    </View>
  );
}
