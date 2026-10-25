import React, { useEffect } from "react";
import { View, Text, ScrollView } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import {
  purgeLegacyWebVaultStorage,
  WEB_VAULT_DISABLED_DETAIL,
  WEB_VAULT_DISABLED_MESSAGE,
  WEB_VAULT_DISABLED_TITLE,
} from "../lib/webVaultPolicy";

export default function WebVaultDisabledScreen() {
  const insets = useSafeAreaInsets();

  useEffect(() => {
    purgeLegacyWebVaultStorage();
  }, []);

  return (
    <View
      style={{ flex: 1, backgroundColor: "#000" }}
      testID="web-vault-disabled"
      accessible
      accessibilityLabel="PiPass is not available in a web browser"
    >
      <ScrollView
        contentContainerStyle={{
          flexGrow: 1,
          justifyContent: "center",
          alignItems: "center",
          paddingHorizontal: 28,
          paddingTop: insets.top + 48,
          paddingBottom: insets.bottom + 48,
        }}
      >
        <Ionicons name="phone-portrait-outline" size={64} color="#4CAF50" />
        <Text
          style={{
            color: "#fff",
            fontSize: 24,
            fontWeight: "700",
            marginTop: 24,
            textAlign: "center",
          }}
          testID="web-vault-disabled-title"
          accessibilityRole="header"
        >
          {WEB_VAULT_DISABLED_TITLE}
        </Text>
        <Text
          style={{
            color: "#d0d0d0",
            fontSize: 16,
            marginTop: 16,
            textAlign: "center",
            lineHeight: 24,
          }}
          testID="web-vault-disabled-message"
        >
          {WEB_VAULT_DISABLED_MESSAGE}
        </Text>
        <Text
          style={{
            color: "#999",
            fontSize: 14,
            marginTop: 16,
            textAlign: "center",
            lineHeight: 22,
            maxWidth: 420,
          }}
          testID="web-vault-disabled-detail"
        >
          {WEB_VAULT_DISABLED_DETAIL}
        </Text>
      </ScrollView>
    </View>
  );
}
