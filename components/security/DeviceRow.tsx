import React from "react";
import { View, Text, Pressable, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { type DeviceItem, relativeTime } from "./api";

// One row in the devices list (T003). Shows the user-supplied label
// (or a fallback), trust badge, last-seen relative time, and a
// trust/revoke-trust action button. Action button is disabled while
// `pending` so the user can't double-tap during the optimistic
// update window.

export default function DeviceRow({
  device,
  pending,
  onTrust,
  onRevoke,
}: {
  device: DeviceItem;
  pending: boolean;
  onTrust: () => void;
  onRevoke: () => void;
}) {
  const label = device.label && device.label.trim().length > 0 ? device.label : "Unnamed device";
  const trusted = device.trusted === true;

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
      <Ionicons
        name={trusted ? "phone-portrait" : "help-circle-outline"}
        size={22}
        color={trusted ? "#22c55e" : "#888"}
      />
      <View style={{ flex: 1 }}>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
          <Text
            style={{ color: "#fff", fontSize: 15, fontWeight: "600" as const, flexShrink: 1 }}
            numberOfLines={1}
          >
            {label}
          </Text>
          <View
            style={{
              paddingHorizontal: 8,
              paddingVertical: 2,
              borderRadius: 10,
              backgroundColor: trusted ? "#0a1a10" : "#1a1208",
              borderWidth: 1,
              borderColor: trusted ? "#143a25" : "#3a2510",
            }}
          >
            <Text style={{ color: trusted ? "#22c55e" : "#eab308", fontSize: 10, fontWeight: "600" as const }}>
              {trusted ? "TRUSTED" : "UNTRUSTED"}
            </Text>
          </View>
        </View>
        <Text style={{ color: "#666", fontSize: 12, marginTop: 4 }}>
          last seen {relativeTime(device.lastSeenAt)}
        </Text>
      </View>
      <Pressable
        onPress={trusted ? onRevoke : onTrust}
        disabled={pending}
        accessibilityRole="button"
        accessibilityLabel={trusted ? "Revoke trust" : "Trust device"}
        style={({ pressed }) => ({
          paddingHorizontal: 12,
          paddingVertical: 8,
          borderRadius: 8,
          backgroundColor: pending
            ? "#1a1a1a"
            : trusted
              ? pressed
                ? "#2a1a1a"
                : "#1a1010"
              : pressed
                ? "#0a2a1a"
                : "#0a1a10",
          minWidth: 80,
          alignItems: "center",
          opacity: pending ? 0.6 : 1,
        })}
      >
        {pending ? (
          <ActivityIndicator size="small" color="#888" />
        ) : (
          <Text
            style={{
              color: trusted ? "#ef4444" : "#22c55e",
              fontSize: 12,
              fontWeight: "600" as const,
            }}
          >
            {trusted ? "Revoke" : "Trust"}
          </Text>
        )}
      </Pressable>
    </View>
  );
}
