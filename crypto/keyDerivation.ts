import CryptoJS from "crypto-js";
import * as Device from "expo-device";
import { Platform } from "react-native";
import { loadPiDigits, extractPiDigits, mapDigitsToCoordinates } from "./pi";
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

export async function deriveClusterKey(userPiSeed: number): Promise<string> {
  const piString = await loadPiDigits();

  const digits30 = extractPiDigits(piString, userPiSeed, 30);

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
  const clusterKey = CryptoJS.SHA256(hashInput).toString(CryptoJS.enc.Hex);

  return clusterKey;
}

export function deriveClusterKeySync(
  piString: string,
  userPiSeed: number
): string {
  const digits30 = extractPiDigits(piString, userPiSeed, 30);

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
  const clusterKey = CryptoJS.SHA256(hashInput).toString(CryptoJS.enc.Hex);

  return clusterKey;
}
