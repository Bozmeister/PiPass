import React, { useMemo, useRef, useEffect, useCallback } from "react";
import { View, Platform, ViewStyle, AppState, AppStateStatus } from "react-native";
import { WebView } from "react-native-webview";
import { FractalParams, DEFAULT_FRACTAL_PARAMS } from "../crypto/hkdf";
import { generateAnimatedFractalHTML } from "../utils/animatedFractalCanvas";

interface AnimatedFractalViewProps {
  seed: number;
  fractalParams?: FractalParams;
  size: number;
  style?: ViewStyle;
}

function NativeAnimatedFractal({
  html,
  size,
  style,
}: {
  html: string;
  size: number;
  style?: ViewStyle;
}) {
  const webViewRef = useRef<WebView>(null);

  const sendCommand = useCallback((cmd: string) => {
    webViewRef.current?.injectJavaScript(`if(window.__fractal)window.__fractal.${cmd}();true;`);
  }, []);

  useEffect(() => {
    return () => {
      sendCommand("pause");
    };
  }, [sendCommand]);

  useEffect(() => {
    const handleAppState = (nextState: AppStateStatus) => {
      sendCommand(nextState === "active" ? "resume" : "pause");
    };
    const sub = AppState.addEventListener("change", handleAppState);
    return () => sub.remove();
  }, [sendCommand]);

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
        ref={webViewRef}
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

function WebAnimatedFractal({
  html,
  size,
  style,
}: {
  html: string;
  size: number;
  style?: ViewStyle;
}) {
  const containerRef = useRef<View>(null);
  const iframeElRef = useRef<HTMLIFrameElement | null>(null);

  useEffect(() => {
    return () => {
      try {
        iframeElRef.current?.contentWindow?.postMessage("pause", "*");
      } catch {}
    };
  }, []);

  const setIframeRef = useCallback((node: HTMLIFrameElement | null) => {
    iframeElRef.current = node;
  }, []);

  return (
    <View
      ref={containerRef}
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
      {/* @ts-ignore: iframe is valid in RN Web */}
      <iframe
        ref={setIframeRef}
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
    return <WebAnimatedFractal html={html} size={size} style={style} />;
  }

  return <NativeAnimatedFractal html={html} size={size} style={style} />;
}
