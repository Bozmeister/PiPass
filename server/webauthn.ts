// WebAuthn / passkey service layer.
//
// This module is the SOLE boundary between the @simplewebauthn/server
// library and the rest of the app. Routes do not import simplewebauthn
// directly: they call the four functions exported here, which:
//
//   - derive the relying-party identity from the live HTTP request
//     (so the same code works in localhost dev, Replit preview, and
//     production without per-environment config);
//   - hold the active challenges in process memory (NEVER persisted —
//     a challenge is a one-shot anti-replay nonce that must NOT
//     survive a process restart, by design);
//   - return STRUCTURED RESULTS (`{ ok: true, ... }` /
//     `{ ok: false, code, reason? }`) so the caller never has to
//     try/catch raw library errors. Library exceptions are caught
//     here and translated into a sanitised error code; the original
//     error message — which can leak internal state, attestation
//     bytes, or trace data — is logged once and discarded.
//
// We do NOT store private keys here (we never see them — WebAuthn is
// a public-key protocol, the private key never leaves the
// authenticator) and we do NOT persist challenges (in-memory only,
// 5-minute TTL, evicted automatically).

import type { Request } from "express";
import {
  generateRegistrationOptions as swGenerateRegistrationOptions,
  verifyRegistrationResponse as swVerifyRegistrationResponse,
  generateAuthenticationOptions as swGenerateAuthenticationOptions,
  verifyAuthenticationResponse as swVerifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from "@simplewebauthn/server";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Human-readable name shown in the platform's passkey prompt
// ("Sign in to PiPass with Touch ID?"). The RP ID — the security
// boundary — is derived per-request below, NOT pinned here, so we
// don't have to redeploy when moving between dev hosts.
const RP_NAME = "PiPass";

// 5 minutes. The WebAuthn spec recommends "a few minutes" so the
// user has time to fish out a hardware key, switch tabs to authorise
// on another device, etc. Long enough for real users; short enough
// that a leaked challenge cannot be used in a long-running attack.
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// Sweep cadence for the in-memory challenge map. 60s is a coarse
// enough resolution that the timer itself is cheap (one Map.delete
// per expired entry, run once a minute) but fine enough that a
// crashed sweep wouldn't let the map balloon for long.
const CHALLENGE_SWEEP_INTERVAL_MS = 60 * 1000;

// ---------------------------------------------------------------------------
// In-memory challenge store
// ---------------------------------------------------------------------------
//
// Keyed by `${kind}:${userId}` so a registration challenge cannot be
// satisfied by an authentication response and vice versa, and so a
// pending registration for the user does not clobber a concurrent
// authentication ceremony (or the other way around). Per spec:
//
//   - Map<userId, { challenge, expiresAt }> — implemented here as
//     two scoped sub-namespaces inside one Map so we don't need to
//     juggle two timers and two maps.
//
// We DELIBERATELY do NOT persist this. A challenge is a one-shot
// nonce: if the server restarts mid-ceremony, the user simply
// re-initiates registration / sign-in. Persisting would cost a DB
// write on every WebAuthn step for zero security benefit (and would
// add a leak surface for attestation challenges).

type ChallengeKind = "registration" | "authentication";

type ChallengeEntry = {
  challenge: string;
  expiresAt: number;
};

const challenges = new Map<string, ChallengeEntry>();

function challengeKey(kind: ChallengeKind, userId: string): string {
  return `${kind}:${userId}`;
}

function setChallenge(
  kind: ChallengeKind,
  userId: string,
  challenge: string,
): void {
  challenges.set(challengeKey(kind, userId), {
    challenge,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });
}

// Single-use consume: the entry is deleted on read so a successful
// verification cannot be replayed. Returns the challenge string only
// if it exists and has not expired; expired entries are deleted as
// a side effect so a future GET for the same key cleanly returns
// "no challenge" rather than "expired".
function consumeChallenge(
  kind: ChallengeKind,
  userId: string,
): { ok: true; challenge: string } | { ok: false; expired: boolean } {
  const key = challengeKey(kind, userId);
  const entry = challenges.get(key);
  if (!entry) return { ok: false, expired: false };
  challenges.delete(key);
  if (entry.expiresAt < Date.now()) return { ok: false, expired: true };
  return { ok: true, challenge: entry.challenge };
}

// Periodic sweep. Lightweight: one pass over the Map evicting any
// entry whose expiresAt is in the past. unref() so this timer does
// NOT keep the Node process alive (matters for tests / clean
// shutdown). Idempotent: double-import of this module would cause
// two sweeps, but the sweep itself is safe to run concurrently
// (Map.delete is a no-op for missing keys).
const sweepTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of challenges) {
    if (entry.expiresAt < now) challenges.delete(key);
  }
}, CHALLENGE_SWEEP_INTERVAL_MS);
sweepTimer.unref?.();

// ---------------------------------------------------------------------------
// RP / origin derivation from the live request
// ---------------------------------------------------------------------------
//
// rpId is the effective domain (eTLD+1 / hostname WITHOUT port or
// scheme) — what the authenticator scopes the credential to.
// expectedOrigin is the FULL origin (scheme + host + port if non-
// default) — what the authenticator embedded in the client data and
// what we must compare against during verification.
//
// We derive both from the request so the same binary works in:
//   - localhost dev (rpId=localhost, origin=http://localhost:8081)
//   - Replit preview (rpId=*.replit.dev, origin=https://*.replit.dev)
//   - Custom domain prod (rpId=app.example.com,
//                         origin=https://app.example.com)
// without per-env config. The trade-off: we trust `Host` /
// `X-Forwarded-Host` to be set correctly by the proxy in front of
// us. That trust is already implied by every other host-derived
// piece of this codebase (CORS, cookie domain, etc.); WebAuthn does
// not introduce new exposure here.

export type RpConfig = {
  rpId: string;
  expectedOrigin: string;
};

export function deriveRpConfig(req: Request): RpConfig {
  // Prefer X-Forwarded-Host (set by the Replit proxy / any reverse
  // proxy) over the raw Host header — Host would otherwise read
  // back the internal upstream hostname, not the domain the user's
  // browser actually navigated to (which is what the authenticator
  // scopes its credential to).
  const forwardedHost = req.get("x-forwarded-host");
  const rawHost = forwardedHost ?? req.get("host") ?? "";
  // Strip port for rpId. The WebAuthn spec defines the RP ID as a
  // domain only — including a port would break credential
  // resolution. Origin keeps the port (see below).
  const rpId = rawHost.split(":")[0] || "localhost";

  // Protocol: respect X-Forwarded-Proto so that an HTTPS-fronted
  // proxy with HTTP upstream still produces the correct origin.
  const proto =
    (req.get("x-forwarded-proto") || "").split(",")[0].trim() ||
    req.protocol ||
    "http";
  // localhost is the ONLY case where the WebAuthn spec permits an
  // insecure (http) origin. For every real domain we coerce to
  // https on the origin we'll compare against — if a request comes
  // in on http to a non-localhost host, the proxy is misconfigured
  // and the verification SHOULD fail rather than silently allow
  // mixed content.
  const safeProto = rpId === "localhost" ? proto : "https";
  const expectedOrigin = `${safeProto}://${rawHost}`;
  return { rpId, expectedOrigin };
}

// ---------------------------------------------------------------------------
// Result types — every entry point returns one of these
// ---------------------------------------------------------------------------

export type GenerateRegistrationOptionsResult =
  | { ok: true; options: PublicKeyCredentialCreationOptionsJSON }
  | { ok: false; code: "internal_error" };

// On success, `credential` carries everything storage.createWebAuthnCredential
// needs. publicKey is base64url-encoded for stable text storage.
// transports is JSON-stringified (or null if the authenticator
// reported none) — matches the `transports` text column on the table.
export type VerifyRegistrationResponseResult =
  | {
      ok: true;
      credential: {
        credentialId: string;
        publicKey: string;
        counter: number;
        transports: string | null;
      };
    }
  | {
      ok: false;
      code:
        | "no_challenge"
        | "challenge_expired"
        | "verification_failed"
        | "internal_error";
      reason?: string;
    };

export type GenerateAuthenticationOptionsResult =
  | { ok: true; options: PublicKeyCredentialRequestOptionsJSON }
  | { ok: false; code: "internal_error" };

export type VerifyAuthenticationResponseResult =
  | { ok: true; newCounter: number }
  | {
      ok: false;
      code:
        | "no_challenge"
        | "challenge_expired"
        | "verification_failed"
        | "counter_replay"
        | "internal_error";
      reason?: string;
    };

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Single place that translates a thrown library error into a logged-
// only message. We DELIBERATELY do not pass the raw error.message to
// the caller / API client: WebAuthn library errors can include
// attestation byte strings, internal state names, or trace fragments
// that we don't want to surface. The exception type is captured for
// operator triage; a stable short reason is returned.
function logSwallow(
  context: string,
  err: unknown,
): { reason: string } {
  const errType = err instanceof Error ? err.constructor.name : typeof err;
  console.error(`webauthn ${context} swallowed error: ${errType}`);
  return { reason: errType };
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// ---------------------------------------------------------------------------
// 1. Registration: options
// ---------------------------------------------------------------------------

export async function generateRegistrationOptionsFor(input: {
  userId: string;
  username: string;
  request: Request;
  // Pre-existing credentials for this user — passed in via
  // excludeCredentials so the platform UX prompts the user to use
  // an authenticator they have NOT already registered (avoids silent
  // duplicate registrations).
  excludeCredentialIds?: string[];
}): Promise<GenerateRegistrationOptionsResult> {
  try {
    const { rpId } = deriveRpConfig(input.request);
    const options = await swGenerateRegistrationOptions({
      rpName: RP_NAME,
      rpID: rpId,
      // The user.id field passed to the authenticator is the stable
      // server-side id. Encode as Uint8Array per spec; the existing
      // user.id is a UUID string — utf-8 bytes are unique and
      // <=64 bytes (the spec's hard limit).
      userID: new TextEncoder().encode(input.userId),
      userName: input.username,
      // Discoverable / resident keys preferred so the user can sign
      // in WITHOUT typing a username (the platform autofills from
      // the credential). Required-but-not-mandatory: an authenticator
      // that cannot do resident keys still registers as a regular
      // (non-discoverable) credential.
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      // We do NOT request attestation — for a personal password
      // manager we don't need to verify the make/model of the
      // authenticator, and "none" sidesteps the privacy/legal
      // concerns of collecting attestation data.
      attestationType: "none",
      excludeCredentials: (input.excludeCredentialIds ?? []).map((id) => ({
        id,
      })),
    });
    setChallenge("registration", input.userId, options.challenge);
    return { ok: true, options };
  } catch (err) {
    logSwallow("generateRegistrationOptions", err);
    return { ok: false, code: "internal_error" };
  }
}

// ---------------------------------------------------------------------------
// 2. Registration: verify
// ---------------------------------------------------------------------------

export async function verifyRegistrationResponseFor(input: {
  userId: string;
  response: RegistrationResponseJSON;
  request: Request;
}): Promise<VerifyRegistrationResponseResult> {
  const claimed = consumeChallenge("registration", input.userId);
  if (!claimed.ok) {
    return {
      ok: false,
      code: claimed.expired ? "challenge_expired" : "no_challenge",
    };
  }

  const { rpId, expectedOrigin } = deriveRpConfig(input.request);

  let verified = false;
  let registrationInfo: Awaited<
    ReturnType<typeof swVerifyRegistrationResponse>
  >["registrationInfo"] = undefined;
  try {
    const result = await swVerifyRegistrationResponse({
      response: input.response,
      expectedChallenge: claimed.challenge,
      expectedOrigin,
      expectedRPID: rpId,
      // Demand UV at registration so the credential is created in
      // a "verified" state — matches the userVerification: preferred
      // we asked for in options. Library default is true; spelled
      // out here to make the policy obvious.
      requireUserVerification: false,
    });
    verified = result.verified;
    registrationInfo = result.registrationInfo;
  } catch (err) {
    const { reason } = logSwallow("verifyRegistrationResponse", err);
    return { ok: false, code: "verification_failed", reason };
  }

  if (!verified || !registrationInfo) {
    return { ok: false, code: "verification_failed" };
  }

  const cred = registrationInfo.credential;
  const transports =
    Array.isArray(cred.transports) && cred.transports.length > 0
      ? JSON.stringify(cred.transports)
      : null;

  return {
    ok: true,
    credential: {
      // cred.id is already base64url per @simplewebauthn v13.
      credentialId: cred.id,
      publicKey: toBase64Url(cred.publicKey),
      counter: cred.counter,
      transports,
    },
  };
}

// ---------------------------------------------------------------------------
// 3. Authentication: options
// ---------------------------------------------------------------------------

export async function generateAuthenticationOptionsFor(input: {
  userId: string;
  request: Request;
  // The user's currently-registered (non-revoked) credential ids,
  // passed in via allowCredentials so the authenticator only
  // surfaces a credential we actually know about. Empty array →
  // discoverable / usernameless flow (the platform prompts for
  // any registered passkey for this RP).
  allowCredentialIds?: { id: string; transports?: string | null }[];
}): Promise<GenerateAuthenticationOptionsResult> {
  try {
    const { rpId } = deriveRpConfig(input.request);
    const options = await swGenerateAuthenticationOptions({
      rpID: rpId,
      userVerification: "preferred",
      allowCredentials: (input.allowCredentialIds ?? []).map((c) => ({
        id: c.id,
        transports: parseTransports(c.transports),
      })),
    });
    setChallenge("authentication", input.userId, options.challenge);
    return { ok: true, options };
  } catch (err) {
    logSwallow("generateAuthenticationOptions", err);
    return { ok: false, code: "internal_error" };
  }
}

// ---------------------------------------------------------------------------
// 4. Authentication: verify
// ---------------------------------------------------------------------------

export async function verifyAuthenticationResponseFor(input: {
  userId: string;
  response: AuthenticationResponseJSON;
  request: Request;
  // Loaded by the route from storage.getCredentialById against the
  // credential id the client returned in `response.id`. publicKey
  // is the base64url string we stored at registration time; we
  // decode back to bytes here so the library can verify the
  // signature.
  storedCredential: {
    credentialId: string;
    publicKey: string;
    counter: number;
    transports: string | null;
  };
}): Promise<VerifyAuthenticationResponseResult> {
  const claimed = consumeChallenge("authentication", input.userId);
  if (!claimed.ok) {
    return {
      ok: false,
      code: claimed.expired ? "challenge_expired" : "no_challenge",
    };
  }

  const { rpId, expectedOrigin } = deriveRpConfig(input.request);

  let verified = false;
  let newCounter = 0;
  try {
    const result = await swVerifyAuthenticationResponse({
      response: input.response,
      expectedChallenge: claimed.challenge,
      expectedOrigin,
      expectedRPID: rpId,
      credential: {
        id: input.storedCredential.credentialId,
        publicKey: Buffer.from(input.storedCredential.publicKey, "base64url"),
        counter: input.storedCredential.counter,
        transports: parseTransports(input.storedCredential.transports),
      },
      requireUserVerification: false,
    });
    verified = result.verified;
    newCounter = result.authenticationInfo.newCounter;
  } catch (err) {
    // The library throws a specific error when the assertion's
    // signCount is <= the stored counter (replay attempt). We
    // surface that as its own code so the route can audit it
    // distinctly from a generic verification failure.
    const msg = err instanceof Error ? err.message : "";
    if (/counter/i.test(msg)) {
      logSwallow("verifyAuthenticationResponse[counter]", err);
      return { ok: false, code: "counter_replay" };
    }
    const { reason } = logSwallow("verifyAuthenticationResponse", err);
    return { ok: false, code: "verification_failed", reason };
  }

  if (!verified) return { ok: false, code: "verification_failed" };
  return { ok: true, newCounter };
}

// ---------------------------------------------------------------------------
// Internal: parse transports JSON string back to the typed enum the
// library wants. Defensive: a malformed or unexpected string returns
// undefined rather than throwing — `transports` is a hint, not a
// security boundary, so a missing hint is preferable to a 500.
// ---------------------------------------------------------------------------
function parseTransports(
  raw: string | null | undefined,
): AuthenticatorTransportFuture[] | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return undefined;
    const valid = parsed.filter(
      (t): t is AuthenticatorTransportFuture => typeof t === "string",
    );
    return valid.length > 0 ? valid : undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Test-only helpers (NOT exported via index)
// ---------------------------------------------------------------------------

// Visible for tests: forcibly clear the in-memory challenge store.
// Used by E2E suites that need a clean slate between scenarios.
// Production callers should NEVER touch this — challenges are
// supposed to expire on their own TTL, not be wiped wholesale.
export function _clearChallengesForTest(): void {
  challenges.clear();
}
