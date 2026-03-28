import { type User, type VaultBlob } from "./validation";
import { randomUUID } from "node:crypto";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(input: { username: string; authHash: string; salt: string; iterations: number }): Promise<User>;
  getVaultBlob(userId: string): Promise<VaultBlob | undefined>;
  upsertVaultBlob(userId: string, encryptedBlob: string, version: number): Promise<VaultBlob>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private vaultBlobs: Map<string, VaultBlob>;

  constructor() {
    this.users = new Map();
    this.vaultBlobs = new Map();
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(input: { username: string; authHash: string; salt: string; iterations: number }): Promise<User> {
    const id = randomUUID();
    const user: User = {
      id,
      username: input.username,
      authHash: input.authHash,
      salt: input.salt,
      iterations: input.iterations,
      createdAt: Date.now(),
    };
    this.users.set(id, user);
    return user;
  }

  async getVaultBlob(userId: string): Promise<VaultBlob | undefined> {
    return this.vaultBlobs.get(userId);
  }

  async upsertVaultBlob(userId: string, encryptedBlob: string, version: number): Promise<VaultBlob> {
    const blob: VaultBlob = {
      userId,
      encryptedBlob,
      version,
      updatedAt: Date.now(),
    };
    this.vaultBlobs.set(userId, blob);
    return blob;
  }
}

export const storage = new MemStorage();
