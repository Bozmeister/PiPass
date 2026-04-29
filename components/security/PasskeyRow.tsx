import React from "react";
import { View, Text, Pressable, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { type PasskeyItem, relativeTime } from "./api";

// One row in the passkeys list (T004). Shows the device name (or a
// fallback) and last-used relative time, with a Revoke action.
// Reuses the same row visual language as DeviceRow for consistency.

export default function PasskeyRow({
  passkey,
  pending,
  onRevoke,
}: {
  passkey: PasskeyItem;
  pending: boolean;
  onRevoke: () => void;
}) {
  const name =
    passkey.deviceName && passkey.deviceName.trim().length > 0
      ? passkey.deviceName
      : "Unnamed passkey";
  const subtitle = passkey.lastUsedAt
    ? `last used ${relativeTime(passkey.lastUsedAt)}`
    : `added ${relativeTime(passkey.createdAt)}`;

  return (
    <View
      style={{
        backgroundColor: "#0f0f0f",
        borderRadius: 12,
        padding: 14,
        borderWidth: 1,
        borderColor: "#1a1a1a",
        flexDirection: "row",
        alignItems: "center",
        gap: 12,
      }}
    >
      <Ionicons name="key-outline" size={22} color="#00ff9f" />
      <View style={{ flex: 1 }}>
        <Text
          style={{ color: "#fff", fontSize: 15, fontWeight: "600" as const }}
          numberOfLines={1}
        >
          {name}
        </Text>
        <Text style={{ color: "#666", fontSize: 12, marginTop: 4 }}>{subtitle}</Text>
      </View>
      <Pressable
        onPress={onRevoke}
        disabled={pending}
        accessibilityRole="button"
        accessibilityLabel="Revoke passkey"
        style={({ pressed }) => ({
          paddingHorizontal: 12,
          paddingVertical: 8,
          borderRadius: 8,
          backgroundColor: pending ? "#1a1a1a" : pressed ? "#2a1a1a" : "#1a1010",
          minWidth: 80,
          alignItems: "center",
          opacity: pending ? 0.6 : 1,
        })}
      >
        {pending ? (
          <ActivityIndicator size="small" color="#888" />
        ) : (
          <Text style={{ color: "#ef4444", fontSize: 12, fontWeight: "600" as const }}>
            Revoke
          </Text>
        )}
      </Pressable>
    </View>
  );
}
