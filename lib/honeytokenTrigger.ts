import { securityApi, type HoneytokenTriggerContext, type HoneytokenTriggerResponse } from "../components/security/api";
import { queryClient } from "./query-client";
import { hashHoneytokenMarker } from "./honeytokenMarker";

// T004 — Fire-and-forget honeytoken trigger.
//
// Called on view / copy / autofill / export of a decoy vault entry.
// Strict requirements from the spec:
//   - MUST be fire-and-forget — never blocks the UI
//   - MUST NOT throw to the caller (UI code wraps user actions, a
//     network failure inside the trigger should not break the user
//     interaction it was attached to)
//   - MUST NOT reveal to the user immediately that the entry was
//     a decoy (no toast, no alert) — the only visible side-effect
//     is that the SecurityContext / Security Dashboard updates
//     after the next /api/vault/audit refresh
//   - MUST NOT send the plaintext marker — only SHA-256(marker)
//
// Dedup: opening a decoy entry triggers BOTH "view" and (if the
// user immediately copies the password) "copy_password" within the
// same second. We dedupe by (markerHash, context) within a short
// window so the user's natural scroll-then-copy doesn't double-bill
// against the backend's 30/min rate limit.

const DEDUP_WINDOW_MS = 4000;

// Map of "<markerHash>:<context>" -> last sent timestamp.
// In-memory only; cleared on app restart, which is fine — the
// purpose is to suppress micro-bursts, not enforce policy.
const recentSends = new Map<string, number>();

// Pruning: bound the map so a long-lived session can't accumulate
// entries indefinitely. Called opportunistically before each insert.
function prune(now: number) {
  if (recentSends.size < 200) return;
  for (const [k, ts] of recentSends.entries()) {
    if (now - ts > DEDUP_WINDOW_MS * 4) recentSends.delete(k);
  }
}

// The public entry point. `marker` is the plaintext marker decrypted
// from the vault entry; we hash it here so callers never have to
// touch crypto-js directly. `context` is one of the spec-defined
// strings — passed through to the backend (where it's clipped to
// 1-128 chars by the HONEYTOKEN_TRIGGER_BODY zod schema).
//
// Returns void synchronously. Internal Promise is detached. Errors
// are swallowed silently because a failed trigger MUST NOT degrade
// the user-facing action that fired it.
export function fireHoneytokenTrigger(
  marker: string,
  context: HoneytokenTriggerContext,
): void {
  // Cheap defence: caller bug or future schema drift should not
  // produce a network call with a bad body. Bail without throwing.
  if (typeof marker !== "string" || marker.length === 0) return;

  let markerHash: string;
  try {
    markerHash = hashHoneytokenMarker(marker);
  } catch {
    return;
  }

  const now = Date.now();
  const key = `${markerHash}:${context}`;
  const last = recentSends.get(key);
  if (last !== undefined && now - last < DEDUP_WINDOW_MS) {
    // Already fired this exact (marker, context) very recently —
    // skip to respect the backend rate limit and avoid double
    // counting in the user's mind.
    return;
  }
  prune(now);
  recentSends.set(key, now);

  // Detached promise. We deliberately do NOT await this in the
  // caller; void the return value so an accidental `await` in the
  // future is loud rather than silent.
  void (async () => {
    let result: HoneytokenTriggerResponse | null = null;
    try {
      result = await securityApi.triggerHoneytoken({ markerHash, context });
    } catch {
      // Swallow — the spec is explicit that the trigger is
      // fire-and-forget and a network/auth failure must not bubble
      // up to the calling UI flow.
      return;
    }

    // T005 — On a real trigger, refresh the security state so the
    // fractal canary and Security Dashboard pick up the new
    // threatLevel / softLockedUntil from the next /api/vault/audit.
    // We don't block on this; React Query will refetch in the
    // background and any subscribed screens re-render.
    if (result?.triggered) {
      try {
        queryClient.invalidateQueries({ queryKey: ["/api/vault/audit"] });
      } catch {
        // queryClient should always be available, but if it isn't
        // there's nothing useful to do here.
      }
    }
  })();
}

// Test seam — used by tests that want to exercise the dedup path
// without waiting for the real timeout. Not exported in the app's
// public surface; only for direct import in __tests__.
export function _resetHoneytokenTriggerDedupForTests(): void {
  recentSends.clear();
}
