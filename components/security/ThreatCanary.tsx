import React, { useEffect, useRef } from "react";
import { Animated, Easing, View, Text } from "react-native";

// Visual canary (T007). Maps a 0–100 threatLevel into a band-colored
// horizontal bar with a subtle pulse animation that gets faster /
// punchier as the level rises. Deliberately understated — it lives at
// the top of the dashboard and must not become a visual nuisance.
//
// Bands:
//   0–30   → calm green, slow pulse (4s)
//   30–60  → yellow, moderate pulse (2s)
//   60–90  → orange, fast pulse (1s)
//   90–100 → red, fast pulse with extra opacity range
//
// Animation strategy: a single Animated.Value that loops between 0
// and 1, mapped to opacity 0.5..1.0. We use `useNativeDriver: true`
// so the worklet runs on the UI thread; on web Reanimated falls
// back to JS driver, which is still fine for an opacity tween.

export type ThreatBand = "calm" | "yellow" | "orange" | "red";

function bandFor(level: number): { band: ThreatBand; color: string; period: number; minOpacity: number } {
  if (level >= 90) return { band: "red", color: "#ef4444", period: 900, minOpacity: 0.35 };
  if (level >= 60) return { band: "orange", color: "#f97316", period: 1100, minOpacity: 0.55 };
  if (level >= 30) return { band: "yellow", color: "#eab308", period: 2000, minOpacity: 0.7 };
  return { band: "calm", color: "#22c55e", period: 4000, minOpacity: 0.8 };
}

export default function ThreatCanary({ level }: { level: number }) {
  // Clamp defensively so a future server bug producing 1000 doesn't
  // produce a 1000% width or break the band logic.
  const clamped = Math.max(0, Math.min(100, Math.round(level)));
  const { color, period, minOpacity } = bandFor(clamped);
  const pulse = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    pulse.setValue(0);
    const loop = Animated.loop(
      Animated.sequence([
        Animated.timing(pulse, {
          toValue: 1,
          duration: period / 2,
          easing: Easing.inOut(Easing.sin),
          useNativeDriver: true,
        }),
        Animated.timing(pulse, {
          toValue: 0,
          duration: period / 2,
          easing: Easing.inOut(Easing.sin),
          useNativeDriver: true,
        }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [period, pulse]);

  const opacity = pulse.interpolate({
    inputRange: [0, 1],
    outputRange: [minOpacity, 1],
  });

  return (
    <View>
      <View style={{ flexDirection: "row", justifyContent: "space-between", marginBottom: 8 }}>
        <Text style={{ color: "#aaa", fontSize: 12, letterSpacing: 0.5 }}>THREAT LEVEL</Text>
        <Text style={{ color: "#fff", fontSize: 12, fontWeight: "600" as const }}>{clamped}</Text>
      </View>
      <View style={{ height: 8, backgroundColor: "#1a1a1a", borderRadius: 4, overflow: "hidden" }}>
        <Animated.View
          style={{
            height: "100%",
            width: `${clamped}%`,
            backgroundColor: color,
            opacity,
            borderRadius: 4,
          }}
        />
      </View>
    </View>
  );
}
