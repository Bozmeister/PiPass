import React from "react";
import { View, Text, Pressable, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { type HoneytokenItem, relativeTime } from "./api";

// T003 / T008 — Single honeytoken row in the management screen.
//
// Display rules from the spec:
//   - show: label, tokenType, active, triggerCount, triggeredAt, createdAt
//   - DO NOT display markerHash (server projection already omits it,
//     this is a defense-in-depth visual rule)
//   - "active" + "triggered" map to two visual states; both pieces
//     of state are independent (a disabled honeytoken can still
//     have a non-zero historical triggerCount and that's the
//     point — the user wants to see what got hit even after they
//     disabled it)
//
// Calm UX wording per T008: never alarming language on the row
// itself. The Security Dashboard surfaces the "vault entered
// protective monitoring mode" line, not this list.

interface HoneytokenRowProps {
  item: HoneytokenItem;
  onDisable: () => void;
  pending: boolean;
}

export default function HoneytokenRow({ item, onDisable, pending }: HoneytokenRowProps) {
  const triggered = item.triggerCount > 0;

  // Outline color encodes state at a glance:
  //   red   = active and has been touched (a real signal)
  //   green = active and clean (the steady state)
  //   gray  = disabled (still listed for history)
  const accent = !item.active
    ? "#3a3a3a"
    : triggered
    ? "#ef4444"
    : "#1a3a1a";

  return (
    <View
      style={{
        backgroundColor: "#0f0f0f",
        borderRadius: 12,
        borderWidth: 1,
        borderColor: accent,
        padding: 14,
        gap: 8,
      }}
    >
      <View style={{ flexDirection: "row", alignItems: "center" }}>
        <Ionicons
          name={
            !item.active
              ? "pause-circle-outline"
              : triggered
              ? "alert-circle"
              : "shield-checkmark-outline"
          }
          size={18}
          color={!item.active ? "#777" : triggered ? "#ef4444" : "#22c55e"}
        />
        <Text
          numberOfLines={1}
          style={{
            color: "#fff",
            fontSize: 15,
            fontWeight: "600" as const,
            marginLeft: 8,
            flex: 1,
          }}
        >
          {item.label}
        </Text>
        {/* tokenType chip — short, lowercase, since users don't need
            it shouted at them; mainly here to disambiguate when we
            later add url/note/credential variants. */}
        <View
          style={{
            paddingHorizontal: 8,
            paddingVertical: 3,
            borderRadius: 6,
            backgroundColor: "#1a1a1a",
          }}
        >
          <Text style={{ color: "#888", fontSize: 11 }}>{item.tokenType}</Text>
        </View>
      </View>

      <View style={{ flexDirection: "row", alignItems: "center", gap: 16 }}>
        <View>
          <Text style={{ color: "#666", fontSize: 11, textTransform: "uppercase" as const }}>
            Status
          </Text>
          <Text
            style={{
              color: item.active ? "#22c55e" : "#777",
              fontSize: 13,
              fontWeight: "500" as const,
              marginTop: 2,
            }}
          >
            {item.active ? "Active" : "Disabled"}
          </Text>
        </View>
        <View>
          <Text style={{ color: "#666", fontSize: 11, textTransform: "uppercase" as const }}>
            Triggers
          </Text>
          <Text
            style={{
              color: triggered ? "#ef4444" : "#aaa",
              fontSize: 13,
              fontWeight: "500" as const,
              marginTop: 2,
            }}
          >
            {item.triggerCount}
          </Text>
        </View>
        <View style={{ flex: 1 }}>
          <Text style={{ color: "#666", fontSize: 11, textTransform: "uppercase" as const }}>
            {item.triggeredAt ? "Last triggered" : "Created"}
          </Text>
          <Text style={{ color: "#aaa", fontSize: 13, marginTop: 2 }}>
            {item.triggeredAt
              ? relativeTime(item.triggeredAt)
              : relativeTime(item.createdAt)}
          </Text>
        </View>
      </View>

      {item.active ? (
        <Pressable
          onPress={onDisable}
          disabled={pending}
          accessibilityRole="button"
          accessibilityLabel={`Disable decoy ${item.label}`}
          style={{
            alignSelf: "flex-end",
            paddingHorizontal: 14,
            paddingVertical: 8,
            borderRadius: 8,
            backgroundColor: pending ? "#222" : "#1a1a1a",
            borderWidth: 1,
            borderColor: "#333",
            flexDirection: "row",
            alignItems: "center",
            gap: 6,
            opacity: pending ? 0.6 : 1,
          }}
        >
          {pending ? (
            <ActivityIndicator size="small" color="#888" />
          ) : (
            <Ionicons name="pause-outline" size={14} color="#aaa" />
          )}
          <Text style={{ color: "#aaa", fontSize: 13 }}>
            {pending ? "Disabling…" : "Disable"}
          </Text>
        </Pressable>
      ) : null}
    </View>
  );
}
