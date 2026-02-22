import React, { useState } from "react";
import {
  View,
  Text,
  TextInput,
  Pressable,
  ScrollView,
  Platform,
  ActivityIndicator,
  Alert,
} from "react-native";
import { useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";
import { extractPiDigits, mapDigitsToCoordinates } from "../crypto/pi";
import { computeFullPipeline } from "../crypto/mandelbrot";
import { deriveClusterKey } from "../crypto/keyDerivation";
import { requireFreshBiometric } from "../crypto/biometricGate";
import { getPiSeed } from "../workers/storageWorker";

interface TestResult {
  piIndex: number;
  hash: string;
  timeMs: number;
  coordinates: { x: number; y: number; zoomFactor: number };
  gridPoints: {
    row: number;
    col: number;
    cReal: number;
    cImag: number;
    escapeTime: number;
    escaped: boolean;
    finalOrbitRe: number;
    finalOrbitIm: number;
  }[];
}

function runDerivation(piIndex: number): TestResult {
  const start = Date.now();
  const hash = deriveClusterKey(piIndex);
  const timeMs = Date.now() - start;

  const digits30 = extractPiDigits(piIndex, 30);
  const coords = mapDigitsToCoordinates(digits30);
  const grid = computeFullPipeline(
    coords.x,
    coords.y,
    coords.zoomFactor,
    coords.jitterDigits
  );

  const gridPoints = grid.map((pt) => {
    const lastOrbit = pt.result.orbit[pt.result.orbit.length - 1];
    return {
      row: pt.row,
      col: pt.col,
      cReal: pt.cReal,
      cImag: pt.cImag,
      escapeTime: pt.result.iterations,
      escaped: pt.result.escaped,
      finalOrbitRe: lastOrbit.re,
      finalOrbitIm: lastOrbit.im,
    };
  });

  return {
    piIndex,
    hash,
    timeMs,
    coordinates: { x: coords.x, y: coords.y, zoomFactor: coords.zoomFactor },
    gridPoints,
  };
}

export default function DebugScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const [piIndex, setPiIndex] = useState("500");
  const [running, setRunning] = useState(false);
  const [result1, setResult1] = useState<TestResult | null>(null);
  const [result2, setResult2] = useState<TestResult | null>(null);
  const [sensitivityResult, setSensitivityResult] = useState<TestResult | null>(null);
  const [determinismPass, setDeterminismPass] = useState<boolean | null>(null);
  const [sensitivityPass, setSensitivityPass] = useState<boolean | null>(null);
  const [revealedSeed, setRevealedSeed] = useState<string | null>(null);
  const [revealingSeeed, setRevealingSeed] = useState(false);

  const webTopInset = Platform.OS === "web" ? 67 : 0;

  async function handleRevealSeed() {
    setRevealingSeed(true);
    try {
      const bioResult = await requireFreshBiometric();
      if (!bioResult) {
        if (Platform.OS === "web") {
          alert("Authentication required to reveal your seed.");
        } else {
          Alert.alert("Authentication Required", "Biometric verification failed.");
        }
        setRevealingSeed(false);
        return;
      }
      const seed = await getPiSeed();
      if (seed !== null) {
        setRevealedSeed(seed.toString());
        setTimeout(() => setRevealedSeed(null), 10000);
      } else {
        if (Platform.OS === "web") {
          alert("No seed found. Set up your vault first.");
        } else {
          Alert.alert("No Seed", "No Pi seed has been configured yet.");
        }
      }
    } catch (err) {
      console.error("Failed to reveal seed:", err);
    }
    setRevealingSeed(false);
  }

  function handleRunTests() {
    const idx = parseInt(piIndex, 10);
    if (isNaN(idx) || idx < 0) return;

    setRunning(true);
    setResult1(null);
    setResult2(null);
    setSensitivityResult(null);
    setDeterminismPass(null);
    setSensitivityPass(null);

    setTimeout(() => {
      const r1 = runDerivation(idx);
      console.log("=== DERIVATION RUN 1 (Pi Index: " + idx + ") ===");
      console.log("Hash:", r1.hash);
      console.log("Time:", r1.timeMs + "ms");
      console.log("Coordinates:", JSON.stringify(r1.coordinates));
      r1.gridPoints.forEach((pt) => {
        console.log(
          `  Grid[${pt.row},${pt.col}] c=(${pt.cReal.toFixed(12)}, ${pt.cImag.toFixed(12)}) ` +
          `EscapeTime=${pt.escapeTime} Escaped=${pt.escaped} ` +
          `FinalOrbit=(${pt.finalOrbitRe.toFixed(12)}, ${pt.finalOrbitIm.toFixed(12)})`
        );
      });

      const r2 = runDerivation(idx);
      console.log("\n=== DERIVATION RUN 2 (Pi Index: " + idx + ") ===");
      console.log("Hash:", r2.hash);
      console.log("Time:", r2.timeMs + "ms");

      const detPass = r1.hash === r2.hash;
      console.log("\n=== DETERMINISM TEST ===");
      console.log("Run 1 Hash:", r1.hash);
      console.log("Run 2 Hash:", r2.hash);
      console.log("Match:", detPass ? "PASS" : "FAIL");

      const nextIdx = idx + 1;
      const r3 = runDerivation(nextIdx);
      console.log("\n=== SENSITIVITY TEST (Pi Index: " + nextIdx + ") ===");
      console.log("Hash:", r3.hash);
      console.log("Time:", r3.timeMs + "ms");
      console.log("Coordinates:", JSON.stringify(r3.coordinates));
      r3.gridPoints.forEach((pt) => {
        console.log(
          `  Grid[${pt.row},${pt.col}] c=(${pt.cReal.toFixed(12)}, ${pt.cImag.toFixed(12)}) ` +
          `EscapeTime=${pt.escapeTime} Escaped=${pt.escaped} ` +
          `FinalOrbit=(${pt.finalOrbitRe.toFixed(12)}, ${pt.finalOrbitIm.toFixed(12)})`
        );
      });

      const senPass = r1.hash !== r3.hash;
      console.log("\n=== SENSITIVITY RESULT ===");
      console.log("Index " + idx + ":", r1.hash);
      console.log("Index " + nextIdx + ":", r3.hash);
      console.log("Different:", senPass ? "PASS" : "FAIL");

      setResult1(r1);
      setResult2(r2);
      setSensitivityResult(r3);
      setDeterminismPass(detPass);
      setSensitivityPass(senPass);
      setRunning(false);
    }, 50);
  }

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      <View
        style={{
          paddingTop: insets.top + webTopInset,
          paddingHorizontal: 16,
          paddingBottom: 12,
          flexDirection: "row",
          alignItems: "center",
        }}
      >
        <Pressable onPress={() => router.back()} style={{ marginRight: 12 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </Pressable>
        <Text style={{ color: "#fff", fontSize: 22, fontWeight: "bold" }}>
          Entropy Engine Debug
        </Text>
      </View>

      <ScrollView
        style={{ flex: 1, paddingHorizontal: 16 }}
        contentContainerStyle={{
          paddingBottom: insets.bottom + (Platform.OS === "web" ? 34 : 0) + 24,
        }}
      >
        <View style={{
          backgroundColor: "#111",
          borderRadius: 8,
          padding: 12,
          marginBottom: 20,
          borderWidth: 1,
          borderColor: "#333",
        }}>
          <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 8 }}>
            <Ionicons name="eye-outline" size={18} color="#fbbf24" />
            <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700", marginLeft: 8 }}>
              Your Pi Seed
            </Text>
          </View>
          {revealedSeed !== null ? (
            <View style={{
              backgroundColor: "#1a1a0a",
              borderWidth: 1,
              borderColor: "#444400",
              borderRadius: 8,
              padding: 12,
              alignItems: "center",
            }}>
              <Text style={{ color: "#fbbf24", fontSize: 28, fontWeight: "bold", letterSpacing: 4, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                {revealedSeed}
              </Text>
              <Text style={{ color: "#888", fontSize: 11, marginTop: 6 }}>
                Auto-hides in 10 seconds
              </Text>
            </View>
          ) : (
            <Pressable
              onPress={handleRevealSeed}
              disabled={revealingSeeed}
              style={{
                backgroundColor: revealingSeeed ? "#333" : "#1a1a2e",
                paddingVertical: 12,
                borderRadius: 8,
                alignItems: "center",
                borderWidth: 1,
                borderColor: "#334",
              }}
              testID="reveal-seed-button"
            >
              {revealingSeeed ? (
                <View style={{ flexDirection: "row", alignItems: "center" }}>
                  <ActivityIndicator size="small" color="#fff" />
                  <Text style={{ color: "#fff", fontSize: 14, marginLeft: 8 }}>Authenticating...</Text>
                </View>
              ) : (
                <View style={{ flexDirection: "row", alignItems: "center" }}>
                  <Ionicons name="finger-print-outline" size={18} color="#fbbf24" />
                  <Text style={{ color: "#fbbf24", fontSize: 14, fontWeight: "600", marginLeft: 8 }}>
                    Reveal Seed (Biometric Required)
                  </Text>
                </View>
              )}
            </Pressable>
          )}
        </View>

        <Text style={{ color: "#888", fontSize: 13, marginBottom: 12 }}>
          Tests determinism (same input = same hash) and sensitivity (different
          input = different hash) of the Entropy Engine key derivation.
        </Text>

        <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 16 }}>
          <Text style={{ color: "#fff", fontSize: 15, marginRight: 12 }}>Pi Index:</Text>
          <TextInput
            value={piIndex}
            onChangeText={setPiIndex}
            keyboardType="number-pad"
            style={{
              flex: 1,
              backgroundColor: "#1a1a1a",
              color: "#fff",
              fontSize: 16,
              paddingHorizontal: 12,
              paddingVertical: 10,
              borderRadius: 8,
              borderWidth: 1,
              borderColor: "#333",
            }}
            testID="pi-index-input"
          />
        </View>

        <Pressable
          onPress={handleRunTests}
          disabled={running}
          style={{
            backgroundColor: running ? "#333" : "#2563eb",
            paddingVertical: 14,
            borderRadius: 8,
            alignItems: "center",
            marginBottom: 20,
          }}
          testID="run-tests-button"
        >
          {running ? (
            <View style={{ flexDirection: "row", alignItems: "center" }}>
              <ActivityIndicator size="small" color="#fff" />
              <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600", marginLeft: 8 }}>
                Computing...
              </Text>
            </View>
          ) : (
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" }}>
              Run Tests
            </Text>
          )}
        </Pressable>

        {determinismPass !== null && (
          <View
            style={{
              backgroundColor: determinismPass ? "#0a2e0a" : "#2e0a0a",
              borderWidth: 1,
              borderColor: determinismPass ? "#22c55e" : "#ef4444",
              borderRadius: 8,
              padding: 12,
              marginBottom: 12,
            }}
          >
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 6 }}>
              <Ionicons
                name={determinismPass ? "checkmark-circle" : "close-circle"}
                size={20}
                color={determinismPass ? "#22c55e" : "#ef4444"}
              />
              <Text
                style={{
                  color: determinismPass ? "#22c55e" : "#ef4444",
                  fontSize: 15,
                  fontWeight: "700",
                  marginLeft: 8,
                }}
              >
                Determinism: {determinismPass ? "PASS" : "FAIL"}
              </Text>
            </View>
            <Text style={{ color: "#aaa", fontSize: 11, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
              Run 1: {result1?.hash}
            </Text>
            <Text style={{ color: "#aaa", fontSize: 11, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
              Run 2: {result2?.hash}
            </Text>
          </View>
        )}

        {sensitivityPass !== null && (
          <View
            style={{
              backgroundColor: sensitivityPass ? "#0a2e0a" : "#2e0a0a",
              borderWidth: 1,
              borderColor: sensitivityPass ? "#22c55e" : "#ef4444",
              borderRadius: 8,
              padding: 12,
              marginBottom: 16,
            }}
          >
            <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 6 }}>
              <Ionicons
                name={sensitivityPass ? "checkmark-circle" : "close-circle"}
                size={20}
                color={sensitivityPass ? "#22c55e" : "#ef4444"}
              />
              <Text
                style={{
                  color: sensitivityPass ? "#22c55e" : "#ef4444",
                  fontSize: 15,
                  fontWeight: "700",
                  marginLeft: 8,
                }}
              >
                Sensitivity: {sensitivityPass ? "PASS" : "FAIL"}
              </Text>
            </View>
            <Text style={{ color: "#aaa", fontSize: 11, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
              Index {result1?.piIndex}: {result1?.hash}
            </Text>
            <Text style={{ color: "#aaa", fontSize: 11, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
              Index {sensitivityResult?.piIndex}: {sensitivityResult?.hash}
            </Text>
          </View>
        )}

        {result1 && (
          <View style={{ marginBottom: 16 }}>
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700", marginBottom: 8 }}>
              Run Details (Index {result1.piIndex})
            </Text>
            <Text style={{ color: "#888", fontSize: 12, marginBottom: 4 }}>
              Computed in {result1.timeMs}ms
            </Text>

            <View
              style={{
                backgroundColor: "#111",
                borderRadius: 8,
                padding: 12,
                marginBottom: 8,
              }}
            >
              <Text style={{ color: "#4CAF50", fontSize: 13, fontWeight: "600", marginBottom: 6 }}>
                Mandelbrot Coordinates
              </Text>
              <Text style={{ color: "#ccc", fontSize: 12, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                X: {result1.coordinates.x.toFixed(12)}
              </Text>
              <Text style={{ color: "#ccc", fontSize: 12, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                Y: {result1.coordinates.y.toFixed(12)}
              </Text>
              <Text style={{ color: "#ccc", fontSize: 12, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                Zoom: {result1.coordinates.zoomFactor.toExponential(4)}
              </Text>
            </View>

            <View style={{ backgroundColor: "#111", borderRadius: 8, padding: 12 }}>
              <Text style={{ color: "#4CAF50", fontSize: 13, fontWeight: "600", marginBottom: 6 }}>
                3x3 Grid — Escape Times & Final Orbits
              </Text>
              {result1.gridPoints.map((pt, i) => (
                <View
                  key={i}
                  style={{
                    marginBottom: 6,
                    paddingBottom: 6,
                    borderBottomWidth: i < 8 ? 1 : 0,
                    borderBottomColor: "#222",
                  }}
                >
                  <Text style={{ color: "#fff", fontSize: 12, fontWeight: "600" }}>
                    [{pt.row},{pt.col}] c=({pt.cReal.toFixed(8)}, {pt.cImag.toFixed(8)})
                  </Text>
                  <Text style={{ color: pt.escaped ? "#fbbf24" : "#ef4444", fontSize: 11 }}>
                    Escape Time: {pt.escapeTime} | {pt.escaped ? "Escaped" : "Bounded"}
                  </Text>
                  <Text style={{ color: "#888", fontSize: 11, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                    Final Z: ({pt.finalOrbitRe.toFixed(10)}, {pt.finalOrbitIm.toFixed(10)})
                  </Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {sensitivityResult && (
          <View style={{ marginBottom: 16 }}>
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700", marginBottom: 8 }}>
              Sensitivity Run (Index {sensitivityResult.piIndex})
            </Text>
            <Text style={{ color: "#888", fontSize: 12, marginBottom: 4 }}>
              Computed in {sensitivityResult.timeMs}ms
            </Text>

            <View
              style={{
                backgroundColor: "#111",
                borderRadius: 8,
                padding: 12,
                marginBottom: 8,
              }}
            >
              <Text style={{ color: "#4CAF50", fontSize: 13, fontWeight: "600", marginBottom: 6 }}>
                Mandelbrot Coordinates
              </Text>
              <Text style={{ color: "#ccc", fontSize: 12, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                X: {sensitivityResult.coordinates.x.toFixed(12)}
              </Text>
              <Text style={{ color: "#ccc", fontSize: 12, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                Y: {sensitivityResult.coordinates.y.toFixed(12)}
              </Text>
              <Text style={{ color: "#ccc", fontSize: 12, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                Zoom: {sensitivityResult.coordinates.zoomFactor.toExponential(4)}
              </Text>
            </View>

            <View style={{ backgroundColor: "#111", borderRadius: 8, padding: 12 }}>
              <Text style={{ color: "#4CAF50", fontSize: 13, fontWeight: "600", marginBottom: 6 }}>
                3x3 Grid — Escape Times & Final Orbits
              </Text>
              {sensitivityResult.gridPoints.map((pt, i) => (
                <View
                  key={i}
                  style={{
                    marginBottom: 6,
                    paddingBottom: 6,
                    borderBottomWidth: i < 8 ? 1 : 0,
                    borderBottomColor: "#222",
                  }}
                >
                  <Text style={{ color: "#fff", fontSize: 12, fontWeight: "600" }}>
                    [{pt.row},{pt.col}] c=({pt.cReal.toFixed(8)}, {pt.cImag.toFixed(8)})
                  </Text>
                  <Text style={{ color: pt.escaped ? "#fbbf24" : "#ef4444", fontSize: 11 }}>
                    Escape Time: {pt.escapeTime} | {pt.escaped ? "Escaped" : "Bounded"}
                  </Text>
                  <Text style={{ color: "#888", fontSize: 11, fontFamily: Platform.OS === "web" ? "monospace" : undefined }}>
                    Final Z: ({pt.finalOrbitRe.toFixed(10)}, {pt.finalOrbitIm.toFixed(10)})
                  </Text>
                </View>
              ))}
            </View>
          </View>
        )}
      </ScrollView>
    </View>
  );
}
