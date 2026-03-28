import React, { useEffect, useRef, useMemo } from "react";
import { View, Modal, Animated } from "react-native";
import { FractalParams } from "../crypto/hkdf";
import { computeFractalGrid } from "../utils/fractalKeyprint";

export type FractalColorMode = "green" | "rainbow" | "custom";

interface FractalFullscreenViewerProps {
  visible: boolean;
  onClose: () => void;
  seed: number;
  fractalParams?: FractalParams;
  colorMode?: FractalColorMode;
  baseColor?: string;
}

const RESOLUTION = 120;
const MAX_ITER = 500;

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 60) { r = c; g = x; }
  else if (h < 120) { r = x; g = c; }
  else if (h < 180) { g = c; b = x; }
  else if (h < 240) { g = x; b = c; }
  else if (h < 300) { r = x; b = c; }
  else { r = c; b = x; }
  return [Math.floor((r + m) * 255), Math.floor((g + m) * 255), Math.floor((b + m) * 255)];
}

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [
    parseInt(h.substring(0, 2), 16) || 0,
    parseInt(h.substring(2, 4), 16) || 0,
    parseInt(h.substring(4, 6), 16) || 0,
  ];
}

function toHex(n: number): string {
  return Math.min(255, Math.max(0, n)).toString(16).padStart(2, "0");
}

function colorForIter(t: number, maxIter: number, mode: FractalColorMode, baseColor?: string): string {
  if (t >= maxIter) return "#000000";
  const norm = t / maxIter;

  if (mode === "rainbow") {
    const hue = norm * 360;
    const sat = 0.85;
    const light = 0.35 + norm * 0.3;
    const [r, g, b] = hslToRgb(hue, sat, light);
    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
  }

  if (mode === "custom" && baseColor) {
    const [br, bg, bb] = hexToRgb(baseColor);
    const intensity = Math.pow(norm, 0.3);
    return `#${toHex(Math.floor(br * intensity))}${toHex(Math.floor(bg * intensity))}${toHex(Math.floor(bb * intensity))}`;
  }

  const intensity = Math.pow(norm, 0.22);
  let r = Math.floor(intensity * 40);
  let g = Math.floor(180 + intensity * 75);
  let b = 255;
  if (Math.floor(t) % 6 === 0) {
    r = Math.floor(220 + intensity * 35);
    g = Math.floor(60 + intensity * 80);
    b = 255;
  }
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function buildSvg(seed: number, size: number, fractalParams?: FractalParams, colorMode: FractalColorMode = "green", baseColor?: string): string {
  const grid = computeFractalGrid(seed, RESOLUTION, MAX_ITER, fractalParams);
  const cellSize = size / RESOLUTION;
  let rects = "";
  for (let row = 0; row < RESOLUTION; row++) {
    for (let col = 0; col < RESOLUTION; col++) {
      const color = colorForIter(grid.escapeGrid[row][col], grid.maxIter, colorMode, baseColor);
      if (color !== "#000000") {
        rects += `<rect x="${(col * cellSize).toFixed(1)}" y="${(row * cellSize).toFixed(1)}" width="${(cellSize + 0.5).toFixed(1)}" height="${(cellSize + 0.5).toFixed(1)}" fill="${color}"/>`;
      }
    }
  }
  return `data:image/svg+xml;utf8,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"><rect width="${size}" height="${size}" fill="#000"/>${rects}</svg>`)}`;
}

export default function FractalFullscreenViewer({
  visible,
  onClose,
  seed,
  fractalParams,
  colorMode = "green",
  baseColor,
}: FractalFullscreenViewerProps) {
  const pulseAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    if (!visible) return;
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

  const dataUri = useMemo(
    () => (visible ? buildSvg(seed, 800, fractalParams, colorMode, baseColor) : ""),
    [visible, seed, fractalParams, colorMode, baseColor]
  );

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent={false} statusBarTranslucent>
      <View onTouchStart={onClose} style={{ flex: 1, backgroundColor: "#000" }}>
        <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
          <Animated.Image
            source={{ uri: dataUri }}
            style={{
              width: "100%",
              aspectRatio: 1,
              transform: [{ scale: pulseAnim }],
            }}
            resizeMode="contain"
          />
        </View>
      </View>
    </Modal>
  );
}
