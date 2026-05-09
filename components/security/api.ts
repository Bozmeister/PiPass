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

// T003 — Honeytoken/decoy management. Mirrors the server-side
// HoneytokenListItem shape (server/storage.ts) which deliberately
// EXCLUDES markerHash from the projection — the spec forbids ever
// displaying it client-side. The four allowed token types come
// from HONEYTOKEN_TOKEN_TYPES in shared/schema.ts; the client only
// creates "vault_entry" decoys today, but typing the union keeps
// us forward-compatible.
export type HoneytokenTokenType = "vault_entry" | "url" | "note" | "credential";

export type HoneytokenItem = {
  id: string;
  label: string;
  tokenType: HoneytokenTokenType;
  active: boolean;
  createdAt: number;
  triggeredAt: number | null;
  triggerCount: number;
};

// T004 — Trigger context strings (spec §T004). Backend clips the
// value to 1-128 chars via HONEYTOKEN_TRIGGER_BODY zod schema,
// but typing the union keeps callers honest.
export type HoneytokenTriggerContext =
  | "view"
  | "copy_password"
  | "copy_username"
  | "copy_url"
  | "autofill"
  | "export";

// Server response shapes. `triggered: false` is returned when the
// markerHash doesn't match any active honeytoken (T007 — spec
// requires this to be silent, no crash).
export type HoneytokenTriggerResponse = {
  success: boolean;
  triggered: boolean;
  triggerCount?: number;
  softLockedUntil?: number;
};

// Typed error so the screen can branch:
//   - `kind: "step-up"` → show "verify your second factor" hint
//   - `kind: "auth"`    → user actually needs to re-login
//   - `kind: "rate"`    → show "slow down" hint
//   - `kind: "generic"` → fall back to "Action failed. Please try again."
export type SecurityApiErrorKind =
  | "step-up"
  | "auth"
  | "no-creds"
  | "rate"
  | "generic";
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
    // Distinct from "auth" (server-rejected creds): the device has no
    // backend credentials at all. The local vault may still be unlocked
    // and fully usable — only backend-only features (security dashboard,
    // decoys) are unavailable. The UI uses this to show an honest
    // "not signed in to backend" message instead of the misleading
    // "session expired" copy.
    throw new SecurityApiError("no-creds", 401);
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

  // T003 — Honeytoken management endpoints. The four routes were
  // built in the prior backend task (server/routes.ts ~4523-4806);
  // this client just consumes them.
  //
  // create:   POST /api/security/honeytokens
  //           body { label, tokenType, markerHash } → 201 { honeytoken }
  //           or 409 if markerHash collides with an existing row
  // disable:  POST /api/security/honeytokens/disable
  //           body { id } → 200 { success, changed }
  //           may return 401 with reason="totp"|"passkey" if the
  //           user has TOTP/passkey enrolled — surfaces as a typed
  //           SecurityApiError("step-up") via the shared 401 path
  // trigger:  POST /api/security/honeytokens/trigger
  //           body { markerHash, context? } → 200 { success, triggered, ... }
  //           Returns triggered:false (no audit) for unknown hashes
  //           per T007
  fetchHoneytokens: () =>
    securityFetch<{ honeytokens: HoneytokenItem[] }>(
      "GET",
      "/api/security/honeytokens",
    ),
  createHoneytoken: (input: {
    label: string;
    tokenType: HoneytokenTokenType;
    markerHash: string;
  }) =>
    securityFetch<{ honeytoken: HoneytokenItem }>(
      "POST",
      "/api/security/honeytokens",
      input,
    ),
  disableHoneytoken: (id: string) =>
    securityFetch<{ success: boolean; changed: boolean }>(
      "POST",
      "/api/security/honeytokens/disable",
      { id },
    ),
  triggerHoneytoken: (input: {
    markerHash: string;
    context?: HoneytokenTriggerContext;
  }) =>
    securityFetch<HoneytokenTriggerResponse>(
      "POST",
      "/api/security/honeytokens/trigger",
      input,
    ),
};

// Surfaces the special 409 case from createHoneytoken so callers
// can distinguish "marker collision, retry with a fresh marker"
// from a generic failure. The server returns a JSON body
// { error: "...", code: "marker_conflict" } with status 409 —
// here we just expose the status code via SecurityApiError.status.
export function isMarkerConflict(err: unknown): boolean {
  return err instanceof SecurityApiError && err.status === 409;
}

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
