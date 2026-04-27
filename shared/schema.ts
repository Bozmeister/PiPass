import { z } from "zod";
import { sql } from "drizzle-orm";
import { pgTable, text, integer, bigint, uuid, check } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    username: text("username").notNull().unique(),
    authHash: text("auth_hash").notNull(),
    salt: text("salt").notNull(),
    iterations: integer("iterations").notNull(),
    createdAt: bigint("created_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (table) => [
    check(
      "users_iterations_range",
      sql`${table.iterations} >= 3 AND ${table.iterations} <= 1000000`,
    ),
  ],
);

export const vaultBlobs = pgTable(
  "vault_blobs",
  {
    userId: uuid("user_id")
      .primaryKey()
      .references(() => users.id, { onDelete: "cascade" }),
    encryptedBlob: text("encrypted_blob").notNull(),
    version: integer("version").notNull(),
    updatedAt: bigint("updated_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (table) => [
    check("vault_blobs_version_min", sql`${table.version} >= 1`),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type VaultBlob = typeof vaultBlobs.$inferSelect;
export type NewVaultBlob = typeof vaultBlobs.$inferInsert;

export const insertUserSchema = createInsertSchema(users);
export const selectUserSchema = createSelectSchema(users);
export const insertVaultBlobSchema = createInsertSchema(vaultBlobs);
export const selectVaultBlobSchema = createSelectSchema(vaultBlobs);

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
