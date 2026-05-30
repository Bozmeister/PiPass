import React from "react";
import { View } from "react-native";
import { Ionicons } from "@expo/vector-icons";

interface FaviconImageProps {
  url?: string;
  size?: number;
}

export default function FaviconImage({ size = 28 }: FaviconImageProps) {
  // Privacy: always show local globe fallback. No network calls.
  return (
    <View
      style={{
        width: size,
        height: size,
        borderRadius: 6,
        backgroundColor: "#222",
        justifyContent: "center",
        alignItems: "center",
      }}
    >
      <Ionicons name="globe-outline" size={size * 0.6} color="#666" />
    </View>
  );
}
