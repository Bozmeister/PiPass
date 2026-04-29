import React, { useEffect, useRef } from "react";
import { Animated, Easing, Platform, Text, View, useWindowDimensions } from "react-native";
import AnimatedFractalView from "./AnimatedFractalView";
import { DEFAULT_FRACTAL_PARAMS } from "../crypto/hkdf";

// T006 — Login/boot loader.
//
// Sequence:
//   1. Fade in   (1s):  fractal opacity 0→1, "PiPass" overlay 0→1
//   2. Hold      (1s):  full intensity
//   3. Dissolve  (700ms): "PiPass" fades out + slight scale-up
//   4. Crossfade (600ms): whole loader fades to 0 → onComplete → unmount
//
// Total: ~3.3s. `onComplete` is fired ONLY after the 600ms crossfade
// finishes so the host can keep the loader mounted for the entire
// fade. (The host is expected to render its UI underneath the loader
// from the start — the loader is `position: absolute` over the host.)
// Calling onComplete during the fade would let the host unmount us
// mid-animation, producing a hard black-frame jump.
//
// FAIL-OPEN: if the animation primitives throw (extremely rare on
// RN Animated), a backstop timer fires `onComplete` so the host UI
// cannot get stranded under the loader.

const STAGE_FADE_IN_MS = 1000;
const STAGE_HOLD_MS = 1000;
const STAGE_DISSOLVE_MS = 700;
const STAGE_CROSSFADE_MS = 600;
const TOTAL_BEFORE_COMPLETE = STAGE_FADE_IN_MS + STAGE_HOLD_MS + STAGE_DISSOLVE_MS;

// A stable seed for the loader. The loader runs BEFORE the user's
// vault is unlocked, so we cannot use the per-user fractal seed.
// This 7-digit constant produces a pleasing, deterministic shape.
const LOADER_SEED = 5040521;

interface PipassLoaderProps {
  onComplete: () => void;
}

export default function PipassLoader({ onComplete }: PipassLoaderProps) {
  const { width, height } = useWindowDimensions();
  const ringSize = Math.min(width, height) * 0.78;

  const fractalOpacity = useRef(new Animated.Value(0)).current;
  const textOpacity = useRef(new Animated.Value(0)).current;
  const textScale = useRef(new Animated.Value(0.92)).current;
  const containerOpacity = useRef(new Animated.Value(1)).current;

  const completedRef = useRef(false);
  const safeComplete = () => {
    if (completedRef.current) return;
    completedRef.current = true;
    onComplete();
  };

  useEffect(() => {
    // Fade in fractal + text in parallel.
    Animated.parallel([
      Animated.timing(fractalOpacity, {
        toValue: 1,
        duration: STAGE_FADE_IN_MS,
        easing: Easing.out(Easing.cubic),
        useNativeDriver: true,
      }),
      Animated.sequence([
        Animated.delay(200),
        Animated.parallel([
          Animated.timing(textOpacity, {
            toValue: 1,
            duration: STAGE_FADE_IN_MS - 200,
            easing: Easing.out(Easing.cubic),
            useNativeDriver: true,
          }),
          Animated.timing(textScale, {
            toValue: 1,
            duration: STAGE_FADE_IN_MS - 200,
            easing: Easing.out(Easing.cubic),
            useNativeDriver: true,
          }),
        ]),
      ]),
    ]).start();

    // Schedule the dissolve + crossfade as timers so we don't block
    // on Animated callbacks (which can drop on background).
    const dissolveTimer = setTimeout(() => {
      Animated.parallel([
        Animated.timing(textOpacity, {
          toValue: 0,
          duration: STAGE_DISSOLVE_MS,
          easing: Easing.in(Easing.cubic),
          useNativeDriver: true,
        }),
        Animated.timing(textScale, {
          toValue: 1.08,
          duration: STAGE_DISSOLVE_MS,
          easing: Easing.out(Easing.cubic),
          useNativeDriver: true,
        }),
      ]).start();
    }, STAGE_FADE_IN_MS + STAGE_HOLD_MS);

    const crossfadeTimer = setTimeout(() => {
      Animated.timing(containerOpacity, {
        toValue: 0,
        duration: STAGE_CROSSFADE_MS,
        easing: Easing.in(Easing.cubic),
        useNativeDriver: true,
      }).start(({ finished }) => {
        // Only call onComplete after the fade actually finishes so
        // the host doesn't yank us mid-animation. `finished` is false
        // if the animation was interrupted (e.g. by unmount) — in
        // that case the cleanup below has already run, so this is a
        // no-op.
        if (finished) safeComplete();
      });
    }, TOTAL_BEFORE_COMPLETE);

    // Defensive backstop: if the Animated callback never fires (rare
    // on background, app suspension, etc.), force completion so the
    // user is never stuck on a black screen.
    const backstop = setTimeout(safeComplete, TOTAL_BEFORE_COMPLETE + STAGE_CROSSFADE_MS + 1500);

    return () => {
      clearTimeout(dissolveTimer);
      clearTimeout(crossfadeTimer);
      clearTimeout(backstop);
    };
  }, []);

  return (
    <Animated.View
      pointerEvents="none"
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "#000",
        justifyContent: "center",
        alignItems: "center",
        opacity: containerOpacity,
        zIndex: 999,
      }}
    >
      <Animated.View style={{ opacity: fractalOpacity }}>
        <View
          style={{
            width: ringSize,
            height: ringSize,
            borderRadius: ringSize / 2,
            overflow: "hidden",
            borderWidth: 2,
            borderColor: "rgba(0,255,159,0.55)",
            ...(Platform.OS === "web"
              ? {
                  // Web: simulate the native shadow with boxShadow.
                  boxShadow: "0 0 50px rgba(0,255,159,0.45)",
                }
              : {
                  shadowColor: "#00ff9f",
                  shadowOffset: { width: 0, height: 0 },
                  shadowOpacity: 0.65,
                  shadowRadius: 30,
                  elevation: 20,
                }),
          }}
        >
          <AnimatedFractalView
            seed={LOADER_SEED}
            fractalParams={DEFAULT_FRACTAL_PARAMS}
            size={ringSize}
          />
        </View>
      </Animated.View>

      <Animated.View
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          justifyContent: "center",
          alignItems: "center",
          opacity: textOpacity,
          transform: [{ scale: textScale }],
        }}
      >
        <Text
          style={{
            color: "#fff",
            fontSize: 44,
            fontWeight: "700" as const,
            letterSpacing: 4,
            textShadowColor: "rgba(0,255,159,0.6)",
            textShadowOffset: { width: 0, height: 0 },
            textShadowRadius: 12,
          }}
        >
          PiPass
        </Text>
      </Animated.View>
    </Animated.View>
  );
}
