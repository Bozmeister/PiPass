import type { Request } from "express";
import type { ZodIssue, ZodSchema } from "zod";
import {
  registerSchema,
  loginSchema,
  vaultSyncSchema,
  vaultRestoreSchema,
  usernameParamSchema,
  userIdHeaderSchema,
  authHashHeaderSchema,
  sessionTokenHeaderSchema,
  totpVerifySchema,
  totpLoginSchema,
  passkeyRegisterStartSchema,
  passkeyRegisterFinishSchema,
  passkeyLoginStartSchema,
  passkeyLoginFinishSchema,
  type RegisterInput,
  type LoginInput,
  type VaultSyncInput,
  type TotpVerifyInput,
  type TotpLoginInput,
  type PasskeyRegisterStartInput,
  type PasskeyRegisterFinishInput,
  type PasskeyLoginStartInput,
  type PasskeyLoginFinishInput,
} from "../shared/schema";
import type { z } from "zod";

export type {
  RegisterInput,
  LoginInput,
  VaultSyncInput,
  TotpVerifyInput,
  TotpLoginInput,
  PasskeyRegisterStartInput,
  PasskeyRegisterFinishInput,
  PasskeyLoginStartInput,
  PasskeyLoginFinishInput,
};
export type VaultRestoreInput = z.infer<typeof vaultRestoreSchema>;

export type Result<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

const FIELD_LABEL: Record<string, string> = {
  username: "username",
  authHash: "authHash",
  salt: "salt",
  iterations: "iterations",
  encryptedBlob: "blob",
  version: "version",
  // TOTP fields. Surfacing the exact name in the 400 error is fine here:
  // both `token` and `tempToken` are public request-shape concerns, not
  // sensitive values (the user already knows what they sent).
  token: "token",
  tempToken: "tempToken",
  // Passkey-registration fields. `response` is the outer WebAuthn
  // assertion object; `deviceName` is the optional label the user
  // attaches to the credential at finish time. Both are public
  // request-shape concerns.
  response: "response",
  deviceName: "deviceName",
};

function issueToError(issue: ZodIssue): string {
  // Strict-mode unknown-keys errors land at the root path with a dedicated
  // code. Surface them as a distinct error so clients can tell "you sent a
  // field I don't know" apart from "your body isn't an object".
  if (issue.code === "unrecognized_keys") return "Unknown field";
  if (issue.path.length === 0) return "Invalid body";
  const head = String(issue.path[0]);
  return `Invalid ${FIELD_LABEL[head] ?? head}`;
}

function parse<T>(body: unknown, schema: ZodSchema<T>): Result<T> {
  if (!body || typeof body !== "object") {
    return { ok: false, error: "Invalid body" };
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return { ok: false, error: issueToError(parsed.error.issues[0]) };
  }
  return { ok: true, data: parsed.data };
}

export function validateRegister(body: unknown): Result<RegisterInput> {
  return parse(body, registerSchema);
}

export function validateLogin(body: unknown): Result<LoginInput> {
  return parse(body, loginSchema);
}

export function validateVaultSync(body: unknown): Result<VaultSyncInput> {
  return parse(body, vaultSyncSchema);
}

export function validateVaultRestore(body: unknown): Result<VaultRestoreInput> {
  return parse(body, vaultRestoreSchema);
}

// TOTP body validators — same parse helper as every other endpoint so
// the "Unknown field" / "Invalid <field>" / "Invalid body" error
// shapes stay uniform across the API.
export function validateTotpVerify(body: unknown): Result<TotpVerifyInput> {
  return parse(body, totpVerifySchema);
}

export function validateTotpLogin(body: unknown): Result<TotpLoginInput> {
  return parse(body, totpLoginSchema);
}

// Passkey-registration body validators — same parse helper as every
// other endpoint so the "Unknown field" / "Invalid <field>" /
// "Invalid body" error shapes stay uniform across the API.
export function validatePasskeyRegisterStart(
  body: unknown,
): Result<PasskeyRegisterStartInput> {
  return parse(body, passkeyRegisterStartSchema);
}

export function validatePasskeyRegisterFinish(
  body: unknown,
): Result<PasskeyRegisterFinishInput> {
  return parse(body, passkeyRegisterFinishSchema);
}

// Passkey-login body validators. /start carries the username so we
// can scope the challenge + load the user's allowCredentials list;
// /finish carries the WebAuthn assertion produced by the
// authenticator. Same parse helper as the registration validators
// above for uniform error shapes.
export function validatePasskeyLoginStart(
  body: unknown,
): Result<PasskeyLoginStartInput> {
  return parse(body, passkeyLoginStartSchema);
}

export function validatePasskeyLoginFinish(
  body: unknown,
): Result<PasskeyLoginFinishInput> {
  return parse(body, passkeyLoginFinishSchema);
}

export function validateUsernameParam(value: unknown): Result<string> {
  const parsed = usernameParamSchema.safeParse(value);
  if (!parsed.success) return { ok: false, error: "Invalid username" };
  return { ok: true, data: parsed.data };
}

export type AuthHeaders = { userId: string; authHash: string };

// Validates the x-user-id and x-auth-hash headers used by the LEGACY vault
// auth path. Returns a SINGLE error message regardless of which header is
// missing/malformed/duplicated so an attacker probing the endpoint cannot
// distinguish "I sent the wrong shape" from "I sent nothing at all".
//
// Routes translate `!ok` into a 400 response. 400 (not 401) is correct here
// because the headers themselves are malformed input — the user has not yet
// presented credentials we could even attempt to authenticate. 401 is reserved
// for "headers were well-formed but the credentials don't match a real user"
// (handled separately in the route handler).
//
// Rejected shapes (all → 400 "Invalid authentication headers"):
//   - header missing
//   - header sent more than once (Express represents this as string[])
//   - header is not a string (Node header-parsing edge cases)
//   - x-user-id is not a valid UUID
//   - x-auth-hash is not a hex string in the allowed length range
//
// On success, the returned strings are guaranteed safe to pass to
// storage.getUser() (Drizzle/PG would otherwise throw on a non-UUID input,
// surfacing as a misleading 500).
export function validateHeaders(req: Request): Result<AuthHeaders> {
  const rawUserId = req.headers["x-user-id"];
  const rawAuthHash = req.headers["x-auth-hash"];

  // Note: we do NOT cast headers to string blindly. Express types these as
  // `string | string[] | undefined` and the Zod schemas below reject any
  // non-string shape (including the duplicate-header `string[]` case).
  const userId = userIdHeaderSchema.safeParse(rawUserId);
  const authHash = authHashHeaderSchema.safeParse(rawAuthHash);
  if (!userId.success || !authHash.success) {
    return { ok: false, error: "Invalid authentication headers" };
  }
  return { ok: true, data: { userId: userId.data, authHash: authHash.data } };
}

// Tagged union representing the two ways a client may authenticate. Session
// tokens (preferred) carry their own user binding via the DB lookup; legacy
// auth-hash carries an explicit user id. Routes use a thin authenticate()
// helper to collapse both into a uniform { userId, sessionId? } downstream.
export type AuthHeaderKind =
  | { kind: "session"; token: string }
  | { kind: "legacy"; userId: string; authHash: string };

// Header validator for any endpoint that accepts EITHER auth scheme. The
// precedence rule (per spec): if x-session-token is present, use it; else
// fall back to legacy x-user-id + x-auth-hash. This means a client cannot
// "downgrade" by sending both — once they include x-session-token, the
// legacy headers are ignored even if also supplied.
//
// Why precedence rather than "must be exactly one": real-world clients in
// the middle of migrating may keep sending the legacy headers as a safety
// net. Tolerating that without surprise (always preferring the new scheme
// when present) is the safe default.
//
// Returns 400 for malformed headers (any branch); 401 lookups happen later
// in the route. Same single-error-message rule as validateHeaders.
export function validateAuthHeaders(req: Request): Result<AuthHeaderKind> {
  const rawSessionToken = req.headers["x-session-token"];
  if (rawSessionToken !== undefined) {
    const parsed = sessionTokenHeaderSchema.safeParse(rawSessionToken);
    if (!parsed.success) {
      return { ok: false, error: "Invalid authentication headers" };
    }
    return { ok: true, data: { kind: "session", token: parsed.data } };
  }
  const legacy = validateHeaders(req);
  if (!legacy.ok) return legacy;
  return { ok: true, data: { kind: "legacy", ...legacy.data } };
}

// Header validator for endpoints that REQUIRE a session token specifically
// (POST /api/auth/logout — there is no "log out" without a session id to
// delete). Falling back to legacy auth-hash here would be meaningless.
// Returns the parsed token; routes are responsible for hashing + DB lookup.
export function validateSessionTokenHeader(req: Request): Result<string> {
  const raw = req.headers["x-session-token"];
  const parsed = sessionTokenHeaderSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, error: "Invalid authentication headers" };
  }
  return { ok: true, data: parsed.data };
}

// Rejects any request that carries query parameters. None of the API endpoints
// accept query input today, so the safe default is "any unexpected query
// param is a 400". Mirrors the .strict() behaviour we apply to JSON bodies.
//
// Returns Result<void> for symmetry with the other validators; routes
// translate `!ok` into a 400 response.
export function validateNoQueryParams(req: Request): Result<undefined> {
  if (req.query && Object.keys(req.query).length > 0) {
    return { ok: false, error: "Unexpected query parameter" };
  }
  return { ok: true, data: undefined };
}
