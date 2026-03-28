import React, { useEffect, useRef, useMemo } from "react";
import { View, Modal, Animated, Dimensions, useWindowDimensions } from "react-native";
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
  const displaySize = Math.min(screenWidth, screenHeight);

  useEffect(() => {
    if (!visible) {
      pulseAnim.setValue(1);
      return;
    }
    const animation = Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.02,
          duration: 1500,
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 0.98,
          duration: 1500,
          useNativeDriver: true,
        }),
      ])
    );
    animation.start();
    return () => animation.stop();
  }, [visible]);

  const svgXml = useMemo(
    () => (visible ? generateFractalSvg(seed, displaySize, VIEWER_RESOLUTION, FULLSCREEN_MAX_ITER, fractalParams) : ""),
    [visible, seed, displaySize, fractalParams]
  );

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent={false} statusBarTranslucent>
      <View onTouchStart={onClose} style={{ flex: 1, backgroundColor: "#000", justifyContent: "center", alignItems: "center" }}>
        <Animated.View style={{ transform: [{ scale: pulseAnim }] }}>
          <SvgXml xml={svgXml} width={displaySize} height={displaySize} />
        </Animated.View>
      </View>
    </Modal>
  );
}
