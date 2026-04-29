import { fetch } from "expo/fetch";
import { getApiUrl } from "../../lib/query-client";
import { getCredentials } from "../../lib/credentials";

// Local fetch helper for the security dashboard.
//
// DELIBERATELY DOES NOT use `authedApiRequest` from lib/query-client.ts:
// that helper wipes credentials and throws AuthRequiredError on every 401.
// The new step-up-gated endpoints (device trust/revoke, passkey revoke)
// can return 401 with reason="totp" or reason="passkey" meaning "you are
// authenticated but this action needs an extra factor right now" — losing
// the user's session in that case would be incorrect (and a bad UX
// regression). Instead we surface a typed error the screen can present
// as an actionable message.
//
// The fetch helper is otherwise the same shape: legacy x-user-id +
// x-auth-hash auth (all the existing app uses), credentials: omit so we
// never accidentally send cookies, JSON request/response.

export type SecurityLevel = "normal" | "elevated" | "high" | "critical";

export type AuditEntry = {
  id: string;
  action: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: number;
};

export type AuditResponse = {
  entries: AuditEntry[];
  hasRecentAnomalies: boolean;
  // Additive fields — older servers may omit them; the screen treats
  // missing as "normal / 0 / false" per fail-open spec.
  securityLevel?: SecurityLevel;
  threatLevel?: number;
  recoveryMode?: boolean;
};

export type DeviceItem = {
  fingerprint: string;
  label: string | null;
  trusted: boolean;
  firstSeenAt: number;
  lastSeenAt: number;
};

export type PasskeyItem = {
  id: string;
  deviceName: string | null;
  createdAt: number;
  lastUsedAt: number | null;
};

// Typed error so the screen can branch:
//   - `kind: "step-up"` → show "verify your second factor" hint
//   - `kind: "auth"`    → user actually needs to re-login
//   - `kind: "rate"`    → show "slow down" hint
//   - `kind: "generic"` → fall back to "Action failed. Please try again."
export type SecurityApiErrorKind = "step-up" | "auth" | "rate" | "generic";
export class SecurityApiError extends Error {
  kind: SecurityApiErrorKind;
  status: number;
  reason?: string;
  constructor(kind: SecurityApiErrorKind, status: number, reason?: string) {
    super(`security-api ${kind} (${status})`);
    this.kind = kind;
    this.status = status;
    this.reason = reason;
  }
}

async function securityFetch<T>(
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<T> {
  const creds = await getCredentials();
  if (!creds) {
    throw new SecurityApiError("auth", 401);
  }
  const url = new URL(path, getApiUrl());
  const headers: Record<string, string> = {
    "x-user-id": creds.userId,
    "x-auth-hash": creds.authHash,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(url.toString(), {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: "omit",
  });

  if (res.status === 401) {
    // Distinguish "step-up needed" (auth ok, factor missing) from
    // "auth failed" (creds wrong) by inspecting the error body. The
    // server returns { error: "Step-up authentication required",
    // reason: "totp" | "passkey" } for the former. Anything else at
    // 401 is a real auth failure — but we still DON'T wipe creds
    // here; the caller decides whether to log out (existing
    // authedApiRequest will eventually catch up on the next vault
    // sync if creds are truly bad).
    let reason: string | undefined;
    try {
      const j = (await res.clone().json()) as { error?: string; reason?: string };
      if (
        typeof j.error === "string" &&
        j.error.toLowerCase().includes("step-up")
      ) {
        throw new SecurityApiError("step-up", 401, j.reason);
      }
      reason = j.reason;
    } catch (e) {
      if (e instanceof SecurityApiError) throw e;
    }
    throw new SecurityApiError("auth", 401, reason);
  }
  if (res.status === 429) {
    throw new SecurityApiError("rate", 429);
  }
  if (!res.ok) {
    throw new SecurityApiError("generic", res.status);
  }
  // 204 No Content tolerance — none of these endpoints return it
  // today but a future server change must not crash the screen.
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const securityApi = {
  fetchAudit: () => securityFetch<AuditResponse>("GET", "/api/vault/audit"),
  fetchDevices: () =>
    securityFetch<{ devices: DeviceItem[] }>("GET", "/api/security/devices"),
  fetchPasskeys: () =>
    securityFetch<{ passkeys: PasskeyItem[] }>("GET", "/api/passkeys"),
  trustDevice: (fingerprint: string) =>
    securityFetch<{ success: boolean; changed: boolean }>(
      "POST",
      "/api/security/device/trust",
      { fingerprint },
    ),
  revokeDeviceTrust: (fingerprint: string) =>
    securityFetch<{ success: boolean; changed: boolean }>(
      "POST",
      "/api/security/device/revoke",
      { fingerprint },
    ),
  relabelDevice: (fingerprint: string, label: string) =>
    securityFetch<{ success: boolean; changed: boolean }>(
      "POST",
      "/api/security/device/label",
      { fingerprint, label },
    ),
  revokePasskey: (passkeyId: string) =>
    securityFetch<{ success: boolean; changed: boolean }>(
      "POST",
      "/api/passkeys/revoke",
      { passkeyId },
    ),
  // Spec calls this "/api/security/acknowledge" but the actual server
  // endpoint is /api/vault/recovery/acknowledge — using the real one
  // since the constraint forbids backend changes.
  acknowledgeRecovery: () =>
    securityFetch<{ success: boolean }>(
      "POST",
      "/api/vault/recovery/acknowledge",
    ),
};

// Simple "5 min ago" relative formatter. Pure, side-effect-free,
// not localized — sufficient for the dashboard. Returns "just now"
// for under a minute, then m/h/d. Past only — future timestamps
// (clock skew) collapse to "just now".
export function relativeTime(ts: number, now: number = Date.now()): string {
  const delta = Math.max(0, Math.floor((now - ts) / 1000));
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)} min ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)} hr ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

// Maps the four canonical security levels to the spec's color palette.
// Centralized so SecurityStatus, ThreatCanary, and any future caller
// stay in lock-step.
export const LEVEL_COLORS: Record<SecurityLevel, string> = {
  normal: "#22c55e",
  elevated: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
};
