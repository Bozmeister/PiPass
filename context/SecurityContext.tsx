import React, { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { securityApi, type SecurityLevel } from "../components/security/api";
import { getCredentials } from "../lib/credentials";

// T001 — Global, fail-open security state.
//
// This context is the single source of truth for the Reactive Security
// Layer (T001-T010). It does NOT own any auth or crypto logic — it
// just observes the same /api/vault/audit + /api/security/devices
// endpoints the dashboard already calls (so they share React Query
// caches; no extra network traffic).
//
// Fail-open contract (T010): every consumer can rely on a sane
// default — `normal`, threatLevel 0, all booleans false — whenever:
//   - the user has no credentials yet (auth/setup screens)
//   - the network is offline
//   - the server returns a malformed payload
//   - the queries are still loading
//
// The fractal layer reads from `useSecurityState()`. Anything that
// renders before the provider mounts (or outside it) gets the same
// defaults via `useSecurityState()`'s fallback path.

export type SecurityState = {
  securityLevel: SecurityLevel;
  threatLevel: number;
  recoveryMode: boolean;
  hasRecentAnomalies: boolean;
  isNewDevice: boolean;
  // Last anomaly timestamp surfaced by the audit endpoint, used by
  // the dashboard's Activity row. `null` when there's no anomaly.
  lastAnomalyAt: number | null;
};

export const DEFAULT_SECURITY_STATE: SecurityState = {
  securityLevel: "normal",
  threatLevel: 0,
  recoveryMode: false,
  hasRecentAnomalies: false,
  isNewDevice: false,
  lastAnomalyAt: null,
};

const SecurityContext = createContext<SecurityState>(DEFAULT_SECURITY_STATE);

// "Recently first-seen" window for new-device detection. A device
// that has been on the account for a week is no longer "new" even
// if the user hasn't trusted it yet — at that point the warning
// would be visual noise, not an alert.
const NEW_DEVICE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// Anomaly action prefixes used by the server's audit log. We only
// scan the most recent few entries since the audit response is
// already capped server-side.
const ANOMALY_ACTION_PREFIXES = [
  "ip_threat_detected",
  "anomaly_",
  "soft_lock",
  "device_untrusted",
  "totp_failed",
  "passkey_failed",
  "login_failed",
] as const;

function isAnomalyAction(action: string | undefined): boolean {
  if (!action) return false;
  for (const p of ANOMALY_ACTION_PREFIXES) {
    if (action.startsWith(p)) return true;
  }
  return false;
}

function useHasCredentials(): boolean {
  // Credentials are stored in SecureStore; getCredentials is async,
  // so we sample on mount and on a slow polling interval. This keeps
  // the provider zero-cost on screens where the user is unauthed
  // (we don't fire the audit query until creds are present).
  const [hasCreds, setHasCreds] = useState(false);
  useEffect(() => {
    let cancelled = false;
    async function check() {
      try {
        const c = await getCredentials();
        if (!cancelled) setHasCreds(!!c);
      } catch {
        if (!cancelled) setHasCreds(false);
      }
    }
    check();
    const id = setInterval(check, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);
  return hasCreds;
}

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  const enabled = useHasCredentials();

  // Re-use the same query keys the dashboard uses so the two screens
  // share a single cache entry. retry:false matches the project
  // default; on a transient 500 we just keep the previous (or
  // default) data and let the next tick try again.
  const auditQ = useQuery({
    queryKey: ["/api/vault/audit"] as const,
    queryFn: securityApi.fetchAudit,
    enabled,
    retry: false,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  });
  const devicesQ = useQuery({
    queryKey: ["/api/security/devices"] as const,
    queryFn: securityApi.fetchDevices,
    enabled,
    retry: false,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  });

  const value = useMemo<SecurityState>(() => {
    const audit = auditQ.data;
    const devices = devicesQ.data?.devices ?? [];
    const now = Date.now();

    // isNewDevice: any untrusted device first seen in the past week
    // is treated as "there is currently a new device on the account",
    // which is the correct UX trigger — the user has just signed in
    // somewhere unfamiliar and the fractal should hint at it.
    const isNewDevice = devices.some(
      (d) => !d.trusted && now - d.firstSeenAt < NEW_DEVICE_WINDOW_MS,
    );

    let lastAnomalyAt: number | null = null;
    if (audit?.entries) {
      for (const e of audit.entries) {
        if (isAnomalyAction(e.action)) {
          if (lastAnomalyAt === null || e.createdAt > lastAnomalyAt) {
            lastAnomalyAt = e.createdAt;
          }
        }
      }
    }

    // Defensive clamping — a future server bug returning 1000 must
    // not break the fractal's intensity math (which expects 0..1).
    const rawThreat = audit?.threatLevel;
    const threatLevel =
      typeof rawThreat === "number" && Number.isFinite(rawThreat)
        ? Math.max(0, Math.min(100, rawThreat))
        : 0;

    return {
      securityLevel: audit?.securityLevel ?? "normal",
      threatLevel,
      recoveryMode: !!audit?.recoveryMode,
      hasRecentAnomalies: !!audit?.hasRecentAnomalies,
      isNewDevice,
      lastAnomalyAt,
    };
  }, [auditQ.data, devicesQ.data]);

  return <SecurityContext.Provider value={value}>{children}</SecurityContext.Provider>;
}

// Consumer hook. Always returns a valid SecurityState — when used
// outside the provider (e.g. on the auth screen before it mounts),
// returns DEFAULT_SECURITY_STATE so the fractal still renders cleanly.
export function useSecurityState(): SecurityState {
  return useContext(SecurityContext);
}

// Cheap reference-stable comparator. The fractal layer uses this to
// decide whether to re-push state into the WebView (avoiding the
// 10/sec throttle eating noop changes).
export function securityStateEquals(a: SecurityState, b: SecurityState): boolean {
  return (
    a.securityLevel === b.securityLevel &&
    a.threatLevel === b.threatLevel &&
    a.recoveryMode === b.recoveryMode &&
    a.hasRecentAnomalies === b.hasRecentAnomalies &&
    a.isNewDevice === b.isNewDevice
  );
}
