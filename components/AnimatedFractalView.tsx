import React, { useMemo, useRef, useEffect, useCallback } from "react";
import { View, Platform, ViewStyle, AppState, AppStateStatus } from "react-native";
import { WebView } from "react-native-webview";
import { FractalParams, DEFAULT_FRACTAL_PARAMS } from "../crypto/hkdf";
import { generateAnimatedFractalHTML } from "../utils/animatedFractalCanvas";
import { DEFAULT_SECURITY_STATE, type SecurityState } from "../context/SecurityContext";

interface AnimatedFractalViewProps {
  seed: number;
  fractalParams?: FractalParams;
  size: number;
  style?: ViewStyle;
  // T002 — Optional, fully backwards compatible. When omitted the
  // fractal renders exactly as before.
  securityState?: SecurityState;
}

// T009 — Throttle. The host can change SecurityState arbitrarily
// often (React renders, query refetches, etc.); we cap pushes to
// the WebView at 10/sec. The latest payload always wins — if the
// throttle is active when a new payload arrives we just remember it,
// and the trailing-edge timer flushes the most recent one.
const SECURITY_PUSH_INTERVAL_MS = 100;

// JSON-safe slice of SecurityState we actually send into the JS layer.
type SecurityWirePayload = {
  securityLevel: SecurityState["securityLevel"];
  threatLevel: number;
  recoveryMode: boolean;
  hasRecentAnomalies: boolean;
  isNewDevice: boolean;
};

function toWire(s: SecurityState | undefined): SecurityWirePayload {
  const safe = s ?? DEFAULT_SECURITY_STATE;
  return {
    securityLevel: safe.securityLevel,
    threatLevel: safe.threatLevel,
    recoveryMode: safe.recoveryMode,
    hasRecentAnomalies: safe.hasRecentAnomalies,
    isNewDevice: safe.isNewDevice,
  };
}

function payloadEquals(a: SecurityWirePayload, b: SecurityWirePayload): boolean {
  return (
    a.securityLevel === b.securityLevel &&
    a.threatLevel === b.threatLevel &&
    a.recoveryMode === b.recoveryMode &&
    a.hasRecentAnomalies === b.hasRecentAnomalies &&
    a.isNewDevice === b.isNewDevice
  );
}

function NativeAnimatedFractal({
  html,
  size,
  style,
  securityState,
}: {
  html: string;
  size: number;
  style?: ViewStyle;
  securityState?: SecurityState;
}) {
  const webViewRef = useRef<WebView>(null);
  const readyRef = useRef(false);
  const pendingRef = useRef<SecurityWirePayload | null>(null);
  const lastSentRef = useRef<SecurityWirePayload | null>(null);
  const lastSentAtRef = useRef(0);
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const sendCommand = useCallback((cmd: string) => {
    webViewRef.current?.injectJavaScript(`if(window.__fractal)window.__fractal.${cmd}();true;`);
  }, []);

  const pushSecurity = useCallback((payload: SecurityWirePayload) => {
    // FAIL-OPEN: any error in the bridge is swallowed — the fractal
    // keeps animating with whatever target it last had.
    try {
      const json = JSON.stringify(payload);
      webViewRef.current?.injectJavaScript(
        `if(window.__fractal&&window.__fractal.setSecurity){try{window.__fractal.setSecurity(${json});}catch(e){}}true;`,
      );
      lastSentRef.current = payload;
      lastSentAtRef.current = Date.now();
    } catch {}
  }, []);

  const scheduleFlush = useCallback(() => {
    if (flushTimerRef.current) return;
    const delay = Math.max(
      0,
      SECURITY_PUSH_INTERVAL_MS - (Date.now() - lastSentAtRef.current),
    );
    flushTimerRef.current = setTimeout(() => {
      flushTimerRef.current = null;
      const next = pendingRef.current;
      pendingRef.current = null;
      if (next && readyRef.current) {
        pushSecurity(next);
      }
    }, delay);
  }, [pushSecurity]);

  // Watch securityState; collapse rapid changes into one push per
  // SECURITY_PUSH_INTERVAL_MS window.
  useEffect(() => {
    const next = toWire(securityState);
    if (lastSentRef.current && payloadEquals(lastSentRef.current, next)) {
      pendingRef.current = null;
      return;
    }
    pendingRef.current = next;
    if (!readyRef.current) return;
    const sinceLast = Date.now() - lastSentAtRef.current;
    if (sinceLast >= SECURITY_PUSH_INTERVAL_MS && !flushTimerRef.current) {
      // Send immediately on the leading edge.
      pendingRef.current = null;
      pushSecurity(next);
    } else {
      scheduleFlush();
    }
  }, [securityState, pushSecurity, scheduleFlush]);

  useEffect(() => {
    return () => {
      sendCommand("pause");
      if (flushTimerRef.current) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
    };
  }, [sendCommand]);

  useEffect(() => {
    const handleAppState = (nextState: AppStateStatus) => {
      sendCommand(nextState === "active" ? "resume" : "pause");
    };
    const sub = AppState.addEventListener("change", handleAppState);
    return () => sub.remove();
  }, [sendCommand]);

  // When the WebView finishes loading, mark ready and push the
  // current target so the very first frame already reflects state.
  const onLoadEnd = useCallback(() => {
    readyRef.current = true;
    const initial = pendingRef.current ?? toWire(securityState);
    pendingRef.current = null;
    pushSecurity(initial);
  }, [pushSecurity, securityState]);

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
        onLoadEnd={onLoadEnd}
      />
    </View>
  );
}

function WebAnimatedFractal({
  html,
  size,
  style,
  securityState,
}: {
  html: string;
  size: number;
  style?: ViewStyle;
  securityState?: SecurityState;
}) {
  const containerRef = useRef<View>(null);
  const iframeElRef = useRef<HTMLIFrameElement | null>(null);
  const readyRef = useRef(false);
  const pendingRef = useRef<SecurityWirePayload | null>(null);
  const lastSentRef = useRef<SecurityWirePayload | null>(null);
  const lastSentAtRef = useRef(0);
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const pushSecurity = useCallback((payload: SecurityWirePayload) => {
    try {
      iframeElRef.current?.contentWindow?.postMessage(
        { type: "security", payload },
        "*",
      );
      lastSentRef.current = payload;
      lastSentAtRef.current = Date.now();
    } catch {}
  }, []);

  const scheduleFlush = useCallback(() => {
    if (flushTimerRef.current) return;
    const delay = Math.max(
      0,
      SECURITY_PUSH_INTERVAL_MS - (Date.now() - lastSentAtRef.current),
    );
    flushTimerRef.current = setTimeout(() => {
      flushTimerRef.current = null;
      const next = pendingRef.current;
      pendingRef.current = null;
      if (next && readyRef.current) {
        pushSecurity(next);
      }
    }, delay);
  }, [pushSecurity]);

  useEffect(() => {
    const next = toWire(securityState);
    if (lastSentRef.current && payloadEquals(lastSentRef.current, next)) {
      pendingRef.current = null;
      return;
    }
    pendingRef.current = next;
    if (!readyRef.current) return;
    const sinceLast = Date.now() - lastSentAtRef.current;
    if (sinceLast >= SECURITY_PUSH_INTERVAL_MS && !flushTimerRef.current) {
      pendingRef.current = null;
      pushSecurity(next);
    } else {
      scheduleFlush();
    }
  }, [securityState, pushSecurity, scheduleFlush]);

  useEffect(() => {
    return () => {
      try {
        iframeElRef.current?.contentWindow?.postMessage("pause", "*");
      } catch {}
      if (flushTimerRef.current) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
    };
  }, []);

  const setIframeRef = useCallback((node: HTMLIFrameElement | null) => {
    iframeElRef.current = node;
  }, []);

  const onIframeLoad = useCallback(() => {
    readyRef.current = true;
    const initial = pendingRef.current ?? toWire(securityState);
    pendingRef.current = null;
    pushSecurity(initial);
  }, [pushSecurity, securityState]);

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
        onLoad={onIframeLoad}
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
  securityState,
}: AnimatedFractalViewProps) {
  const params = fractalParams || DEFAULT_FRACTAL_PARAMS;

  // T009 — HTML is memoized on stable inputs ONLY. SecurityState is
  // intentionally NOT in the dep list because the WebView is meant
  // to be live-mutated via setSecurity, never re-mounted on state.
  const html = useMemo(
    () => generateAnimatedFractalHTML(seed, params.cx, params.cy, params.zoom, params.maxIterations),
    [seed, params.cx, params.cy, params.zoom, params.maxIterations]
  );

  if (Platform.OS === "web") {
    return <WebAnimatedFractal html={html} size={size} style={style} securityState={securityState} />;
  }

  return <NativeAnimatedFractal html={html} size={size} style={style} securityState={securityState} />;
}
