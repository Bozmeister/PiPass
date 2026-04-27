import { eq, sql } from "drizzle-orm";
import { db } from "./db";
import { users, vaultBlobs, type User, type VaultBlob } from "../shared/schema";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(input: { username: string; authHash: string; salt: string; iterations: number }): Promise<User>;
  getVaultBlob(userId: string): Promise<VaultBlob | undefined>;
  upsertVaultBlob(userId: string, encryptedBlob: string, version: number): Promise<VaultBlob | null>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return rows[0];
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const rows = await db
      .select()
      .from(users)
      .where(eq(users.username, username))
      .limit(1);
    return rows[0];
  }

  async createUser(input: {
    username: string;
    authHash: string;
    salt: string;
    iterations: number;
  }): Promise<User> {
    const rows = await db
      .insert(users)
      .values({
        username: input.username,
        authHash: input.authHash,
        salt: input.salt,
        iterations: input.iterations,
      })
      .returning();
    return rows[0];
  }

  async getVaultBlob(userId: string): Promise<VaultBlob | undefined> {
    const rows = await db
      .select()
      .from(vaultBlobs)
      .where(eq(vaultBlobs.userId, userId))
      .limit(1);
    return rows[0];
  }

  async upsertVaultBlob(
    userId: string,
    encryptedBlob: string,
    version: number,
  ): Promise<VaultBlob | null> {
    const now = Date.now();
    const rows = await db
      .insert(vaultBlobs)
      .values({
        userId,
        encryptedBlob,
        version,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: vaultBlobs.userId,
        set: {
          encryptedBlob,
          version,
          updatedAt: now,
        },
        where: sql`${vaultBlobs.version} < ${version}`,
      })
      .returning();
    return rows[0] ?? null;
  }
}
