import type { ZodIssue, ZodSchema } from "zod";
import {
  registerSchema,
  loginSchema,
  vaultSyncSchema,
  type RegisterInput,
  type LoginInput,
  type VaultSyncInput,
} from "../shared/schema";

export type { RegisterInput, LoginInput, VaultSyncInput };

type Result<T> =
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
