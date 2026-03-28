import { z } from "zod";

export const registerSchema = z.object({
  username: z.string().min(3).max(64),
  authHash: z.string().min(64).max(128),
  salt: z.string().min(32).max(128),
  iterations: z.number().int().min(3).max(1000000),
});

export const loginSchema = z.object({
  username: z.string().min(3).max(64),
  authHash: z.string().min(64).max(128),
});

export const vaultSyncSchema = z.object({
  encryptedBlob: z.string().max(10 * 1024 * 1024),
  version: z.number().int().min(1),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VaultSyncInput = z.infer<typeof vaultSyncSchema>;

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
