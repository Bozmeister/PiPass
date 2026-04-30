import React from "react";
import { View, Text, Pressable, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";

// Recovery-mode banner (T006). Shows a warning + an Acknowledge action
// when the server reports recoveryMode === true. Dismissing calls
// /api/vault/recovery/acknowledge — the spec's name is "/api/security/
// acknowledge" but the actual route is the recovery one (constraint:
// don't modify backend APIs). The button is disabled while the call
// is in flight to prevent double-acks.
//
// Stateless: the parent owns the mutation state and passes back
// `acknowledging` / `onAcknowledge`. That keeps the banner reusable
// (e.g. a future "remind me later" variant only needs new props).

export default function RecoveryBanner({
  acknowledging,
  onAcknowledge,
}: {
  acknowledging: boolean;
  onAcknowledge: () => void;
}) {
  return (
    <View
      style={{
        backgroundColor: "#1a0808",
        borderRadius: 12,
        padding: 14,
        borderWidth: 1,
        borderColor: "#3a1515",
        flexDirection: "row",
        alignItems: "center",
        gap: 12,
      }}
    >
      <Ionicons name="warning" size={22} color="#ef4444" />
      <View style={{ flex: 1 }}>
        <Text style={{ color: "#fff", fontSize: 14, fontWeight: "600" as const, marginBottom: 2 }}>
          Suspicious activity detected
        </Text>
        <Text style={{ color: "#aaa", fontSize: 12, lineHeight: 16 }}>
          Some actions are restricted until you confirm you&apos;ve reviewed it.
        </Text>
      </View>
      <Pressable
        onPress={onAcknowledge}
        disabled={acknowledging}
        accessibilityRole="button"
        accessibilityLabel="Acknowledge recovery mode"
        style={({ pressed }) => ({
          paddingHorizontal: 14,
          paddingVertical: 8,
          borderRadius: 8,
          backgroundColor: acknowledging ? "#2a1010" : pressed ? "#5a1f1f" : "#3a1515",
          opacity: acknowledging ? 0.6 : 1,
        })}
      >
        {acknowledging ? (
          <ActivityIndicator size="small" color="#ef4444" />
        ) : (
          <Text style={{ color: "#ef4444", fontSize: 13, fontWeight: "600" as const }}>
            Acknowledge
          </Text>
        )}
      </Pressable>
    </View>
  );
}
