export interface RegisterInput {
  username: string;
  authHash: string;
  salt: string;
  iterations: number;
}

export interface LoginInput {
  username: string;
  authHash: string;
}

export interface VaultSyncInput {
  encryptedBlob: string;
  version: number;
}

export interface User {
  id: string;
  username: string;
  authHash: string;
  salt: string;
  iterations: number;
  createdAt: number;
}

export interface VaultBlob {
  userId: string;
  encryptedBlob: string;
  version: number;
  updatedAt: number;
}

export function validateRegister(body: any): { ok: true; data: RegisterInput } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "Invalid body" };
  const { username, authHash, salt, iterations } = body;
  if (typeof username !== "string" || username.length < 3 || username.length > 64) return { ok: false, error: "Invalid username" };
  if (typeof authHash !== "string" || authHash.length < 64 || authHash.length > 128) return { ok: false, error: "Invalid authHash" };
  if (typeof salt !== "string" || salt.length < 32 || salt.length > 128) return { ok: false, error: "Invalid salt" };
  if (typeof iterations !== "number" || !Number.isInteger(iterations) || iterations < 3 || iterations > 1000000) return { ok: false, error: "Invalid iterations" };
  return { ok: true, data: { username, authHash, salt, iterations } };
}

export function validateLogin(body: any): { ok: true; data: LoginInput } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "Invalid body" };
  const { username, authHash } = body;
  if (typeof username !== "string" || username.length < 3 || username.length > 64) return { ok: false, error: "Invalid username" };
  if (typeof authHash !== "string" || authHash.length < 64 || authHash.length > 128) return { ok: false, error: "Invalid authHash" };
  return { ok: true, data: { username, authHash } };
}

export function validateVaultSync(body: any): { ok: true; data: VaultSyncInput } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "Invalid body" };
  const { encryptedBlob, version } = body;
  if (typeof encryptedBlob !== "string" || encryptedBlob.length > 10 * 1024 * 1024) return { ok: false, error: "Invalid blob" };
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) return { ok: false, error: "Invalid version" };
  return { ok: true, data: { encryptedBlob, version } };
}
