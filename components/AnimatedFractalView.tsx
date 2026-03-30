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

export default function AnimatedFractalView({
  seed,
  fractalParams,
  size,
  style,
}: AnimatedFractalViewProps) {
  const params = fractalParams || DEFAULT_FRACTAL_PARAMS;
  const webViewRef = useRef<WebView>(null);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);

  const html = useMemo(
    () => generateAnimatedFractalHTML(seed, params.cx, params.cy, params.zoom, params.maxIterations),
    [seed, params.cx, params.cy, params.zoom, params.maxIterations]
  );

  const sendMessage = useCallback((msg: string) => {
    if (Platform.OS === "web") {
      iframeRef.current?.contentWindow?.postMessage(msg, "*");
    } else {
      webViewRef.current?.injectJavaScript(`window.postMessage('${msg}','*');true;`);
    }
  }, []);

  useEffect(() => {
    sendMessage("resume");
    return () => {
      sendMessage("pause");
    };
  }, [sendMessage]);

  useEffect(() => {
    const handleAppState = (nextState: AppStateStatus) => {
      if (nextState === "active") {
        sendMessage("resume");
      } else {
        sendMessage("pause");
      }
    };
    const sub = AppState.addEventListener("change", handleAppState);
    return () => sub.remove();
  }, [sendMessage]);

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
          ref={iframeRef as any}
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
