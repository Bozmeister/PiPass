import React, { useEffect, useRef, useMemo } from "react";
import { View, Animated, Pressable, Image } from "react-native";
import { generateFractalDataUri } from "../utils/fractalKeyprint";
import { FractalParams } from "../crypto/hkdf";

interface FractalKeyprintProps {
  seed: number;
  size?: number;
  onPress?: () => void;
  animate?: boolean;
  fractalParams?: FractalParams;
}

export default function FractalKeyprint({
  seed,
  size = 96,
  onPress,
  animate = true,
  fractalParams,
}: FractalKeyprintProps) {
  const pulseAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    if (!animate) return;
    const animation = Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.04,
          duration: 1800,
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 1.0,
          duration: 1800,
          useNativeDriver: true,
        }),
      ])
    );
    animation.start();
    return () => animation.stop();
  }, [animate, pulseAnim]);

  const dataUri = useMemo(() => generateFractalDataUri(seed, size * 2, 48, 300, fractalParams), [seed, size, fractalParams]);

  const imageContent = (
    <Animated.View
      style={{
        width: size,
        height: size,
        borderRadius: size / 2,
        overflow: "hidden",
        transform: [{ scale: pulseAnim }],
        borderWidth: 3,
        borderColor: "#00ff9f",
        shadowColor: "#00ff9f",
        shadowOffset: { width: 0, height: 0 },
        shadowOpacity: 0.8,
        shadowRadius: 12,
        elevation: 10,
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
          borderWidth: 2,
          borderColor: "rgba(0, 255, 159, 0.65)",
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
