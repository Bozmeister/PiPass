import { z } from "zod";
import { sql } from "drizzle-orm";
import { pgTable, text, integer, bigint, uuid, check, index } from "drizzle-orm/pg-core";
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

// Append-only ring-buffer of historical encrypted vault blobs. On every
// successful sync, the previous vault_blobs row is archived here BEFORE the
// new row is written, then this table is pruned to keep only the latest N
// entries per user (see DatabaseStorage.syncVault). The encrypted blob is
// stored verbatim — the server never decrypts it, preserving the
// zero-knowledge property. Restoration writes a historical blob back into
// vault_blobs as currentVersion + 1 (see DatabaseStorage.restoreVault).
export const vaultBlobHistory = pgTable(
  "vault_blob_history",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    version: integer("version").notNull(),
    encryptedBlob: text("encrypted_blob").notNull(),
    archivedAt: bigint("archived_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (table) => [
    index("vault_blob_history_user_version_idx").on(
      table.userId,
      table.version.desc(),
    ),
    index("vault_blob_history_user_archived_idx").on(
      table.userId,
      table.archivedAt.desc(),
    ),
    check("vault_blob_history_version_range", sql`${table.version} >= 1`),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type VaultBlob = typeof vaultBlobs.$inferSelect;
export type NewVaultBlob = typeof vaultBlobs.$inferInsert;
export type VaultBlobHistoryEntry = typeof vaultBlobHistory.$inferSelect;

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

// Request schemas use .strict() so unknown fields are REJECTED (not silently
// stripped). Clients sending fields the API doesn't recognize get a 400 instead
// of a deceptive 200 — they need to know their request shape is wrong.
export const registerSchema = insertUserSchema
  .pick({
    username: true,
    authHash: true,
    salt: true,
    iterations: true,
  })
  .strict();

export const loginSchema = insertUserSchema
  .pick({
    username: true,
    authHash: true,
  })
  .strict();

export const vaultSyncSchema = insertVaultBlobSchema
  .pick({
    encryptedBlob: true,
    version: true,
  })
  .strict();

// Restore endpoint — caller picks which historical version to roll back to.
// `version` is the historical version (the one stored in vault_blob_history),
// NOT the new version that will be written to vault_blobs (the server picks
// that as currentVersion + 1 to preserve monotonicity). .strict() so unknown
// fields (e.g. someone hand-crafting an `encryptedBlob` field hoping to inject
// blob content via the restore path) are rejected with 400.
export const vaultRestoreSchema = z
  .object({
    version: z.number().int().min(1),
  })
  .strict();

// Path/query/header param schemas — same constraints as the corresponding body
// fields, derived from the table-level insert schema so they cannot drift.
export const usernameParamSchema = insertUserSchema.shape.username;

// x-user-id header: must be a UUID (matches users.id column).
export const userIdHeaderSchema = z.string().uuid();

// x-auth-hash header: must be a hex string in the same length range the
// register endpoint accepts for authHash. The server SHA-256s this value before
// timing-safe comparison, so any input is technically "safe" — but rejecting
// malformed hashes early avoids spending CPU on obvious junk and gives a clean
// 401 instead of a misleading "Invalid credentials" after a wasted round trip.
export const authHashHeaderSchema = insertUserSchema.shape.authHash.regex(
  /^[0-9a-fA-F]+$/,
);

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VaultSyncInput = z.infer<typeof vaultSyncSchema>;
