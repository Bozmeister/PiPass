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
    check("vault_blobs_version_range", sql`${table.version} >= 1`),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type VaultBlob = typeof vaultBlobs.$inferSelect;
export type NewVaultBlob = typeof vaultBlobs.$inferInsert;

export const insertUserSchema = createInsertSchema(users, {
  username: (col) => col.min(3).max(64),
  authHash: (col) => col.min(64).max(128),
  salt: (col) => col.min(32).max(128),
  iterations: (col) => col.min(3).max(1000000),
});
export const selectUserSchema = createSelectSchema(users);

export const insertVaultBlobSchema = createInsertSchema(vaultBlobs, {
  encryptedBlob: (col) => col.max(10 * 1024 * 1024),
  version: (col) => col.min(1),
});
export const selectVaultBlobSchema = createSelectSchema(vaultBlobs);

export const registerSchema = insertUserSchema.pick({
  username: true,
  authHash: true,
  salt: true,
  iterations: true,
});

export const loginSchema = insertUserSchema.pick({
  username: true,
  authHash: true,
});

export const vaultSyncSchema = insertVaultBlobSchema.pick({
  encryptedBlob: true,
  version: true,
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VaultSyncInput = z.infer<typeof vaultSyncSchema>;
