import React, { useEffect, useRef, useMemo } from "react";
import { View, Animated, Pressable, Image } from "react-native";
import { generateFractalDataUri } from "../utils/fractalKeyprint";

interface FractalKeyprintProps {
  piSeed: number;
  size?: number;
  onPress?: () => void;
  animate?: boolean;
}

export default function FractalKeyprint({
  piSeed,
  size = 96,
  onPress,
  animate = true,
}: FractalKeyprintProps) {
  const pulseAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    if (!animate) return;
    const animation = Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.03,
          duration: 2000,
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 1.0,
          duration: 2000,
          useNativeDriver: true,
        }),
      ])
    );
    animation.start();
    return () => animation.stop();
  }, [animate]);

  const dataUri = useMemo(() => generateFractalDataUri(piSeed, size * 2, 48, 300), [piSeed, size]);

  const imageContent = (
    <Animated.View
      style={{
        width: size,
        height: size,
        borderRadius: size / 2,
        overflow: "hidden",
        transform: [{ scale: pulseAnim }],
        borderWidth: 1.5,
        borderColor: "#1a3a1a",
      }}
    >
      <Image
        source={{ uri: dataUri }}
        style={{ width: size, height: size }}
        resizeMode="cover"
      />
      <View
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          borderRadius: size / 2,
          borderWidth: 1,
          borderColor: "rgba(76, 175, 80, 0.3)",
        }}
      />
    </Animated.View>
  );

  if (onPress) {
    return (
      <Pressable onPress={onPress} testID="fractal-keyprint-thumb">
        {imageContent}
      </Pressable>
    );
  }

  return imageContent;
}
