import React, { useMemo } from "react";
import { View, Platform, ViewStyle } from "react-native";
import { WebView } from "react-native-webview";
import { FractalParams, DEFAULT_FRACTAL_PARAMS } from "../crypto/hkdf";
import { generateAnimatedFractalHTML } from "../utils/animatedFractalCanvas";

interface AnimatedFractalViewProps {
  seed: number;
  fractalParams?: FractalParams;
  size: number;
  style?: ViewStyle;
}

export default function AnimatedFractalView({
  seed,
  fractalParams,
  size,
  style,
}: AnimatedFractalViewProps) {
  const params = fractalParams || DEFAULT_FRACTAL_PARAMS;

  const html = useMemo(
    () => generateAnimatedFractalHTML(seed, params.cx, params.cy, params.zoom, params.maxIterations),
    [seed, params.cx, params.cy, params.zoom, params.maxIterations]
  );

  if (Platform.OS === "web") {
    return (
      <View
        style={[
          {
            width: size,
            height: size,
            borderRadius: size / 2,
            overflow: "hidden",
          },
          style,
        ]}
      >
        <iframe
          srcDoc={html}
          style={{
            width: size,
            height: size,
            border: "none",
            borderRadius: size / 2,
          }}
          scrolling="no"
        />
      </View>
    );
  }

  return (
    <View
      style={[
        {
          width: size,
          height: size,
          borderRadius: size / 2,
          overflow: "hidden",
        },
        style,
      ]}
    >
      <WebView
        source={{ html }}
        style={{ width: size, height: size, backgroundColor: "transparent" }}
        scrollEnabled={false}
        bounces={false}
        javaScriptEnabled={true}
        domStorageEnabled={false}
        allowsInlineMediaPlayback={true}
        mediaPlaybackRequiresUserAction={false}
        originWhitelist={["about:blank"]}
      />
    </View>
  );
}
