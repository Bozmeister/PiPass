import CryptoJS from "crypto-js";
import * as Device from "expo-device";
import { Platform } from "react-native";
import { extractPiDigits, mapDigitsToCoordinates } from "./pi";
import { computeFullPipeline, GridPoint } from "./mandelbrot";

function getDeviceIdentifier(): string {
  if (Platform.OS === "web") {
    return "web-device-" + (navigator.userAgent || "unknown");
  }

  const parts: string[] = [];
  if (Device.osBuildId) parts.push(Device.osBuildId);
  if (Device.osInternalBuildId) parts.push(Device.osInternalBuildId);
  if (Device.modelName) parts.push(Device.modelName);
  if (Device.brand) parts.push(Device.brand);

  return parts.length > 0 ? parts.join("-") : "unknown-device";
}

function serializeOrbits(grid: GridPoint[]): string {
  const orbits = grid.map((point) => ({
    r: point.row,
    c: point.col,
    cr: point.cReal,
    ci: point.cImag,
    iter: point.result.iterations,
    esc: point.result.escaped,
    orbit: point.result.orbit.map((z) => [
      Math.round(z.re * 1e12) / 1e12,
      Math.round(z.im * 1e12) / 1e12,
    ]),
  }));
  return JSON.stringify(orbits);
}

export function deriveClusterKey(userPiSeed: number, iterations: number = 100000): string {
  const finalIterations = Math.max(iterations || 100000, 3);
  const digits30 = extractPiDigits(userPiSeed, 30);

  const coords = mapDigitsToCoordinates(digits30);

  const grid = computeFullPipeline(
    coords.x,
    coords.y,
    coords.zoomFactor,
    coords.jitterDigits
  );

  const orbitData = serializeOrbits(grid);
  const deviceId = getDeviceIdentifier();
  const seedStr = userPiSeed.toString();

  const hashInput = orbitData + deviceId + seedStr;
  const initialHash = CryptoJS.SHA256(hashInput).toString(CryptoJS.enc.Hex);

  const salt = CryptoJS.SHA256(deviceId + seedStr).toString(CryptoJS.enc.Hex);
  const stretched = CryptoJS.PBKDF2(initialHash, salt, {
    keySize: 256 / 32,
    iterations: finalIterations,
    hasher: CryptoJS.algo.SHA256,
  });

  return stretched.toString(CryptoJS.enc.Hex);
}
