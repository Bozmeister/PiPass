import React, { useMemo } from "react";
import {
  View,
  Text,
  Modal,
  Pressable,
  ScrollView,
  Platform,
  Image,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import {
  generateFractalDataUri,
  getGridPointData,
} from "../utils/fractalKeyprint";

interface KeyprintViewerProps {
  visible: boolean;
  seed: number;
  onClose: () => void;
}

export default function KeyprintViewer({
  visible,
  seed,
  onClose,
}: KeyprintViewerProps) {
  const insets = useSafeAreaInsets();
  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const webBottomInset = Platform.OS === "web" ? 34 : 0;

  const fractalUri = useMemo(
    () => (visible ? generateFractalDataUri(seed, 600, 96, 500) : ""),
    [visible, seed]
  );

  const gridData = useMemo(
    () => (visible ? getGridPointData(seed) : null),
    [visible, seed]
  );

  if (!visible) return null;

  return (
    <Modal visible={visible} animationType="fade" transparent={false}>
      <View style={{ flex: 1, backgroundColor: "#000" }}>
        <ScrollView
          contentContainerStyle={{
            paddingTop: insets.top + webTopInset + 12,
            paddingBottom: insets.bottom + webBottomInset + 24,
            paddingHorizontal: 20,
            alignItems: "center",
          }}
        >
          <Text
            style={{
              color: "#4CAF50",
              fontSize: 13,
              fontWeight: "700" as const,
              letterSpacing: 3,
              textTransform: "uppercase" as const,
              marginBottom: 20,
            }}
          >
            Fractal Keyprint
          </Text>

          <View
            style={{
              width: 280,
              height: 280,
              borderRadius: 140,
              overflow: "hidden",
              borderWidth: 2,
              borderColor: "#1a3a1a",
              marginBottom: 20,
            }}
          >
            <Image
              source={{ uri: fractalUri }}
              style={{ width: 280, height: 280 }}
              resizeMode="cover"
            />
            <View
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                borderRadius: 140,
                borderWidth: 2,
                borderColor: "rgba(76, 175, 80, 0.25)",
              }}
            />
          </View>

          <Text
            style={{
              color: "#4CAF50",
              fontSize: 13,
              fontWeight: "500" as const,
              textAlign: "center",
              fontStyle: "italic" as const,
              paddingHorizontal: 24,
              marginBottom: 24,
              lineHeight: 20,
            }}
          >
            Your unique vault fingerprint — derived from your master key.
          </Text>

          {gridData && (
            <View style={{ width: "100%", marginBottom: 24 }}>
              <Text
                style={{
                  color: "#888",
                  fontSize: 11,
                  textTransform: "uppercase" as const,
                  letterSpacing: 2,
                  marginBottom: 12,
                }}
              >
                Fractal Coordinates
              </Text>
              <View
                style={{
                  backgroundColor: "#0a0a0a",
                  borderRadius: 10,
                  padding: 14,
                  borderWidth: 1,
                  borderColor: "#1a2a1a",
                  marginBottom: 16,
                }}
              >
                <CoordRow label="X" value={gridData.coordinates.x.toFixed(12)} />
                <CoordRow label="Y" value={gridData.coordinates.y.toFixed(12)} />
                <CoordRow
                  label="Zoom"
                  value={gridData.coordinates.zoomFactor.toExponential(4)}
                />
              </View>

              <Text
                style={{
                  color: "#888",
                  fontSize: 11,
                  textTransform: "uppercase" as const,
                  letterSpacing: 2,
                  marginBottom: 12,
                }}
              >
                3x3 Orbit Grid
              </Text>
              {gridData.points.map((pt, i) => (
                <View
                  key={i}
                  style={{
                    backgroundColor: "#0a0a0a",
                    borderRadius: 8,
                    padding: 12,
                    marginBottom: 6,
                    borderWidth: 1,
                    borderColor: "#1a1a1a",
                    flexDirection: "row",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <View style={{ flex: 1 }}>
                    <Text
                      style={{
                        color: "#fff",
                        fontSize: 12,
                        fontWeight: "600" as const,
                        fontFamily:
                          Platform.OS === "web" ? "monospace" : undefined,
                      }}
                    >
                      [{pt.row},{pt.col}]
                    </Text>
                    <Text
                      style={{
                        color: "#666",
                        fontSize: 10,
                        marginTop: 2,
                        fontFamily:
                          Platform.OS === "web" ? "monospace" : undefined,
                      }}
                    >
                      c=({pt.cReal.toFixed(8)}, {pt.cImag.toFixed(8)})
                    </Text>
                  </View>
                  <View style={{ alignItems: "flex-end" }}>
                    <Text
                      style={{
                        color: pt.escaped ? "#4CAF50" : "#ef4444",
                        fontSize: 13,
                        fontWeight: "700" as const,
                      }}
                    >
                      {pt.escapeTime}
                    </Text>
                    <Text
                      style={{
                        color: pt.escaped ? "#2d6e30" : "#8b2020",
                        fontSize: 9,
                        marginTop: 1,
                      }}
                    >
                      {pt.escaped ? "ESCAPED" : "BOUNDED"}
                    </Text>
                  </View>
                </View>
              ))}
            </View>
          )}

          <Pressable
            onPress={onClose}
            style={{
              flexDirection: "row",
              alignItems: "center",
              justifyContent: "center",
              backgroundColor: "#1a0a0a",
              borderRadius: 12,
              paddingVertical: 16,
              paddingHorizontal: 32,
              borderWidth: 1,
              borderColor: "#3a1a1a",
              width: "100%",
              marginTop: 8,
            }}
            testID="close-keyprint-viewer"
          >
            <Ionicons
              name="lock-closed"
              size={18}
              color="#ef4444"
              style={{ marginRight: 10 }}
            />
            <Text style={{ color: "#ef4444", fontSize: 15, fontWeight: "700" as const }}>
              Close Vault View
            </Text>
          </Pressable>
        </ScrollView>
      </View>
    </Modal>
  );
}

function CoordRow({ label, value }: { label: string; value: string }) {
  return (
    <View
      style={{
        flexDirection: "row",
        justifyContent: "space-between",
        paddingVertical: 4,
      }}
    >
      <Text style={{ color: "#4CAF50", fontSize: 12, fontWeight: "600" as const }}>
        {label}
      </Text>
      <Text
        style={{
          color: "#ccc",
          fontSize: 12,
          fontFamily: Platform.OS === "web" ? "monospace" : undefined,
        }}
      >
        {value}
      </Text>
    </View>
  );
}
