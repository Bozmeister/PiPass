import React from "react";
import { View, Text } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { LEVEL_COLORS, type SecurityLevel } from "./api";
import ThreatCanary from "./ThreatCanary";

// Top-of-dashboard status block. Shows the human-readable security
// level (normal/elevated/high/critical), a one-line subtitle, the
// threat canary bar, and a small "recent anomaly" indicator when set.
//
// Fail-open per spec: any missing field collapses to the safest
// default ("normal" level, threatLevel 0, no anomaly). The screen
// passes whatever the server returned, and this component never
// throws on undefined.

const LEVEL_LABELS: Record<SecurityLevel, string> = {
  normal: "Normal",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

const LEVEL_SUBTITLES: Record<SecurityLevel, string> = {
  normal: "Your account looks healthy.",
  elevated: "Some signals warrant a closer look.",
  high: "Step-up authentication will be required for sensitive actions.",
  critical: "Sensitive actions are restricted until you respond.",
};

const LEVEL_ICONS: Record<SecurityLevel, keyof typeof Ionicons.glyphMap> = {
  normal: "shield-checkmark",
  elevated: "shield-half",
  high: "warning",
  critical: "alert-circle",
};

export default function SecurityStatus({
  level,
  threatLevel,
  hasRecentAnomalies,
}: {
  level?: SecurityLevel;
  threatLevel?: number;
  hasRecentAnomalies?: boolean;
}) {
  const safeLevel: SecurityLevel = level ?? "normal";
  const safeThreat = typeof threatLevel === "number" ? threatLevel : 0;
  const color = LEVEL_COLORS[safeLevel];

  return (
    <View
      style={{
        backgroundColor: "#0f0f0f",
        borderRadius: 16,
        padding: 16,
        borderWidth: 1,
        borderColor: "#1a1a1a",
      }}
    >
      <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 4 }}>
        <Ionicons name={LEVEL_ICONS[safeLevel]} size={20} color={color} />
        <Text
          style={{
            color,
            fontSize: 18,
            fontWeight: "700" as const,
            marginLeft: 8,
          }}
        >
          {LEVEL_LABELS[safeLevel]}
        </Text>
        {hasRecentAnomalies ? (
          <View
            style={{
              marginLeft: "auto",
              flexDirection: "row",
              alignItems: "center",
              backgroundColor: "#1a1208",
              paddingHorizontal: 8,
              paddingVertical: 4,
              borderRadius: 12,
              borderWidth: 1,
              borderColor: "#3a2510",
            }}
          >
            <Ionicons name="pulse" size={12} color="#f97316" />
            <Text style={{ color: "#f97316", fontSize: 11, marginLeft: 4 }}>recent anomaly</Text>
          </View>
        ) : null}
      </View>
      <Text style={{ color: "#888", fontSize: 13, lineHeight: 18, marginBottom: 16 }}>
        {LEVEL_SUBTITLES[safeLevel]}
      </Text>
      <ThreatCanary level={safeThreat} />
    </View>
  );
}
