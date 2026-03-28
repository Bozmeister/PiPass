import React, { useEffect, useRef, useMemo } from "react";
import { View, Modal, Animated, useWindowDimensions } from "react-native";
import { SvgXml } from "react-native-svg";
import { FractalParams } from "../crypto/hkdf";
import { generateFractalSvg, VIEWER_RESOLUTION } from "../utils/fractalKeyprint";

interface FractalFullscreenViewerProps {
  visible: boolean;
  onClose: () => void;
  seed: number;
  fractalParams?: FractalParams;
}

const FULLSCREEN_MAX_ITER = 400;

export default function FractalFullscreenViewer({
  visible,
  onClose,
  seed,
  fractalParams,
}: FractalFullscreenViewerProps) {
  const pulseAnim = useRef(new Animated.Value(1)).current;
  const { width: screenWidth, height: screenHeight } = useWindowDimensions();
  const ringSize = Math.min(screenWidth, screenHeight) * 0.85;

  useEffect(() => {
    if (!visible) {
      pulseAnim.setValue(1);
      return;
    }
    const animation = Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.03,
          duration: 2000,
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 0.97,
          duration: 2000,
          useNativeDriver: true,
        }),
      ])
    );
    animation.start();
    return () => animation.stop();
  }, [visible]);

  const svgXml = useMemo(
    () => (visible ? generateFractalSvg(seed, ringSize, VIEWER_RESOLUTION, FULLSCREEN_MAX_ITER, fractalParams) : ""),
    [visible, seed, ringSize, fractalParams]
  );

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent={false} statusBarTranslucent>
      <View onTouchStart={onClose} style={{ flex: 1, backgroundColor: "#000", justifyContent: "center", alignItems: "center" }}>
        <Animated.View
          style={{
            width: ringSize,
            height: ringSize,
            borderRadius: ringSize / 2,
            overflow: "hidden",
            transform: [{ scale: pulseAnim }],
            borderWidth: 4,
            borderColor: "#00ff9f",
            shadowColor: "#00ff9f",
            shadowOffset: { width: 0, height: 0 },
            shadowOpacity: 0.9,
            shadowRadius: 30,
            elevation: 20,
          }}
        >
          <SvgXml xml={svgXml} width={ringSize} height={ringSize} />
          <View
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              borderRadius: ringSize / 2,
              borderWidth: 3,
              borderColor: "rgba(0, 255, 159, 0.65)",
            }}
          />
        </Animated.View>
      </View>
    </Modal>
  );
}
