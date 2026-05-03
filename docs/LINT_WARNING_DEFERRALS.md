# Lint Warning Deferrals

## 1. Purpose

This document records the remaining intentional ESLint warnings after Prompt 027 reduced the lint baseline from 15 warnings to 2 warnings.

These warnings are not ignored forever. They are deferred because the obvious mechanical fixes touch hook dependency arrays in timer and animation code, where changing dependencies can change runtime behavior.

This is documentation only. It does not add eslint-disable comments, change hooks, change timers, change animations, change tests, or change runtime behavior.

## 2. Current Baseline

Current expected check baseline after Prompt 027:

- `npm run lint` passes with 0 errors and 2 warnings
- `npm run typecheck` passes
- `npm test` passes 50/50

## 3. Deferred Warnings

| File | Warning | Deferred because |
| --- | --- | --- |
| `components/NuclearResetModal.tsx` | `React Hook useEffect has a missing dependency: countdown` | The countdown interval lifecycle is part of the nuclear reset confirmation flow. Adding `countdown` mechanically could restart or alter the interval behavior and change reset timing. |
| `components/PipassLoader.tsx` | `React Hook useEffect has missing dependencies: containerOpacity, fractalOpacity, safeComplete, textOpacity, and textScale` | The boot loader effect owns a staged animation sequence. Adding dependencies mechanically could restart the animation, change completion timing, or alter unmount behavior. |

## 4. Why Not Auto-Fix

Hook dependency auto-fixes are safe only when the effect is a pure synchronization of state with props or stable values.

These two effects are different:

- `NuclearResetModal` starts and clears an interval based on modal step and countdown state.
- `PipassLoader` schedules several animation stages and a defensive completion backstop.

In both cases, a dependency-array change can change when cleanup runs, when timers restart, or when animation callbacks fire. That needs manual review and visual verification, not a mechanical lint cleanup.

## 5. Future Review Checklist

Before removing these warnings, a future prompt should:

- inspect each hook manually and describe the intended lifecycle
- verify whether dependencies can be made stable with refs or callbacks without changing behavior
- visually test the nuclear reset countdown from open through final button enablement
- verify closing or resetting the nuclear reset modal cancels countdown timers correctly
- visually test the boot loader animation from mount through completion
- verify the loader does not restart unexpectedly on resize, re-render, or parent state changes
- run `npm run lint`
- run `npm run typecheck`
- run `npm test`

## 6. Exit Criteria For Removing The Warnings

The warnings can be removed when:

- the hook dependency arrays satisfy ESLint without broad rule suppression
- no global eslint rule is disabled
- no local eslint-disable comment is added unless it has a narrow, behavior-specific explanation
- the nuclear reset countdown behavior is unchanged under manual review
- the boot loader animation behavior is unchanged under manual review
- lint, typecheck, and tests still pass

