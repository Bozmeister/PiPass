import React from "react";
import { View, Modal, useWindowDimensions } from "react-native";
import { FractalParams } from "../crypto/hkdf";
import AnimatedFractalView from "./AnimatedFractalView";

interface FractalFullscreenViewerProps {
  visible: boolean;
  onClose: () => void;
  seed: number;
  fractalParams?: FractalParams;
}

export default function FractalFullscreenViewer({
  visible,
  onClose,
  seed,
  fractalParams,
}: FractalFullscreenViewerProps) {
  const { width: screenWidth, height: screenHeight } = useWindowDimensions();
  const ringSize = Math.min(screenWidth, screenHeight) * 0.88;

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent={false} statusBarTranslucent>
      <View
        onTouchStart={onClose}
        style={{
          flex: 1,
          backgroundColor: "#000",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <View
          style={{
            width: ringSize,
            height: ringSize,
            borderRadius: ringSize / 2,
            overflow: "hidden",
            borderWidth: 3,
            borderColor: "#00ff9f",
            shadowColor: "#00ff9f",
            shadowOffset: { width: 0, height: 0 },
            shadowOpacity: 0.9,
            shadowRadius: 25,
            elevation: 20,
          }}
        >
          <AnimatedFractalView
            seed={seed}
            fractalParams={fractalParams}
            size={ringSize}
          />
          <View
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              borderRadius: ringSize / 2,
              borderWidth: 2,
              borderColor: "rgba(0, 255, 159, 0.5)",
            }}
          />
        </View>
      </View>
    </Modal>
  );
}
