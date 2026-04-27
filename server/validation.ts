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
  type RegisterInput,
  type LoginInput,
  type VaultSyncInput,
} from "../shared/schema";
import type { z } from "zod";

export type { RegisterInput, LoginInput, VaultSyncInput };
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

export function validateUsernameParam(value: unknown): Result<string> {
  const parsed = usernameParamSchema.safeParse(value);
  if (!parsed.success) return { ok: false, error: "Invalid username" };
  return { ok: true, data: parsed.data };
}

export type AuthHeaders = { userId: string; authHash: string };

// Validates the x-user-id and x-auth-hash headers used to authenticate vault
// reads/writes. Returns a SINGLE error message regardless of which header is
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
