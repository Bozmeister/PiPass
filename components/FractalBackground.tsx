import React, { useMemo } from "react";
import { View } from "react-native";
import Svg, { Rect } from "react-native-svg";

const GRID_W = 80;
const GRID_H = 80;
const MAX_ITER = 50;

interface FractalBackgroundProps {
  centerX: number;
  centerY: number;
  zoom: number;
  seed: number;
}

interface CacheEntry {
  seed: number;
  pixels: number[];
}

function computeMandelbrotGrid(
  cx: number,
  cy: number,
  zoom: number
): number[] {
  const pixels = new Array(GRID_W * GRID_H);
  const scale = 4.0 / zoom;
  const xMin = cx - scale / 2;
  const yMin = cy - scale / 2;
  const dx = scale / GRID_W;
  const dy = scale / GRID_H;

  for (let py = 0; py < GRID_H; py++) {
    const ci = yMin + py * dy;
    for (let px = 0; px < GRID_W; px++) {
      const cr = xMin + px * dx;
      let zr = 0;
      let zi = 0;
      let iter = 0;
      while (iter < MAX_ITER && zr * zr + zi * zi <= 4) {
        const tmp = zr * zr - zi * zi + cr;
        zi = 2 * zr * zi + ci;
        zr = tmp;
        iter++;
      }
      pixels[py * GRID_W + px] = iter;
    }
  }
  return pixels;
}

function iterToColor(iter: number): string {
  if (iter >= MAX_ITER) {
    return "#000000";
  }
  const t = iter / MAX_ITER;
  const g = Math.floor(255 * t);
  const r = Math.floor(57 * t);
  const b = Math.floor(20 * t);
  const rh = r.toString(16).padStart(2, "0");
  const gh = g.toString(16).padStart(2, "0");
  const bh = b.toString(16).padStart(2, "0");
  return `#${rh}${gh}${bh}`;
}

const cacheRef: { current: CacheEntry | null } = { current: null };

export default function FractalBackground({
  centerX,
  centerY,
  zoom,
  seed,
}: FractalBackgroundProps) {
  const pixels = useMemo(() => {
    if (cacheRef.current && cacheRef.current.seed === seed) {
      return cacheRef.current.pixels;
    }
    const result = computeMandelbrotGrid(centerX, centerY, zoom);
    cacheRef.current = { seed, pixels: result };
    return result;
  }, [seed, centerX, centerY, zoom]);

  const cellW = 100 / GRID_W;
  const cellH = 100 / GRID_H;

  const rects = useMemo(() => {
    const elements: React.ReactElement[] = [];
    for (let y = 0; y < GRID_H; y++) {
      for (let x = 0; x < GRID_W; x++) {
        const iter = pixels[y * GRID_W + x];
        const color = iterToColor(iter);
        if (color !== "#000000") {
          elements.push(
            <Rect
              key={y * GRID_W + x}
              x={`${x * cellW}%`}
              y={`${y * cellH}%`}
              width={`${cellW + 0.2}%`}
              height={`${cellH + 0.2}%`}
              fill={color}
            />
          );
        }
      }
    }
    return elements;
  }, [pixels, cellW, cellH]);

  return (
    <View
      pointerEvents="none"
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        opacity: 0.08,
      }}
    >
      <Svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid slice">
        <Rect x="0" y="0" width="100" height="100" fill="#000000" />
        {rects}
      </Svg>
    </View>
  );
}
