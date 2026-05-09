import React, { useEffect, useRef } from "react";
import { Animated, Platform, Pressable, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";

interface ThemedToastProps {
  visible: boolean;
  message: string;
  onHide: () => void;
  durationMs?: number;
  iconName?: React.ComponentProps<typeof Ionicons>["name"];
  iconColor?: string;
}

export default function ThemedToast({
  visible,
  message,
  onHide,
  durationMs = 2400,
  iconName = "checkmark-circle",
  iconColor = "#4CAF50",
}: ThemedToastProps) {
  const insets = useSafeAreaInsets();
  const opacity = useRef(new Animated.Value(0)).current;
  const translateY = useRef(new Animated.Value(20)).current;
  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (visible) {
      Animated.parallel([
        Animated.timing(opacity, { toValue: 1, duration: 180, useNativeDriver: true }),
        Animated.timing(translateY, { toValue: 0, duration: 220, useNativeDriver: true }),
      ]).start();
      if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
      hideTimerRef.current = setTimeout(() => {
        Animated.parallel([
          Animated.timing(opacity, { toValue: 0, duration: 180, useNativeDriver: true }),
          Animated.timing(translateY, { toValue: 20, duration: 200, useNativeDriver: true }),
        ]).start(() => onHide());
      }, durationMs);
    } else {
      opacity.setValue(0);
      translateY.setValue(20);
    }
    return () => {
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
        hideTimerRef.current = null;
      }
    };
  }, [visible, durationMs, onHide, opacity, translateY]);

  if (!visible) return null;

  const bottom = insets.bottom + (Platform.OS === "web" ? 34 : 0) + 24;

  return (
    <Animated.View
      pointerEvents="box-none"
      style={{
        position: "absolute",
        left: 16,
        right: 16,
        bottom,
        opacity,
        transform: [{ translateY }],
        zIndex: 9999,
        elevation: 9999,
      }}
    >
      <Pressable
        onPress={onHide}
        accessibilityRole="alert"
        accessibilityLabel={message}
        style={{
          flexDirection: "row",
          alignItems: "center",
          backgroundColor: "rgba(20,20,22,0.96)",
          borderRadius: 14,
          paddingVertical: 14,
          paddingHorizontal: 16,
          borderWidth: 1,
          borderColor: "#2a2a2e",
          shadowColor: "#000",
          shadowOpacity: 0.4,
          shadowRadius: 16,
          shadowOffset: { width: 0, height: 6 },
        }}
      >
        <Ionicons name={iconName} size={20} color={iconColor} style={{ marginRight: 12 }} />
        <View style={{ flex: 1 }}>
          <Text style={{ color: "#f5f5f7", fontSize: 15, fontWeight: "600" as const }}>{message}</Text>
        </View>
      </Pressable>
    </Animated.View>
  );
}
