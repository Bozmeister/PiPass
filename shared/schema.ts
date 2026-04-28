import { z } from "zod";
import { sql } from "drizzle-orm";
import { pgTable, text, integer, bigint, uuid, boolean, check, index } from "drizzle-orm/pg-core";
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

// Session lifecycle:
//   - Created on POST /api/auth/login (one row per login)
//   - Looked up by SHA-256(token) on every authenticated request
//   - Deleted by POST /api/auth/logout (current session) or
//     POST /api/auth/logout-all (every session for the user)
//   - Cascaded on user deletion (FK ON DELETE CASCADE)
//
// We store ONLY token_hash (SHA-256 of the raw token). The raw token is
// returned exactly once, in the login response, and is never persisted.
// A DB compromise therefore cannot impersonate any user — the attacker
// would have to find a SHA-256 preimage of a 32-byte (256-bit) secret,
// which is computationally infeasible.
//
// expires_at / created_at / last_seen_at use bigint epoch-ms to match the
// existing codebase convention (users.createdAt, vaultBlobs.updatedAt,
// vaultBlobHistory.archivedAt all use this shape) — a TIMESTAMP column
// would be inconsistent with the rest of the schema.
export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    createdAt: bigint("created_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
    expiresAt: bigint("expires_at", { mode: "number" }).notNull(),
    lastSeenAt: bigint("last_seen_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
    userAgent: text("user_agent"),
    ipAddress: text("ip_address"),
    // Set to TRUE when an anomaly_detected event fires for this user
    // while this session was the authenticating session. Surfaces in
    // GET /api/auth/sessions so users can see "this device flagged
    // suspicious activity" in their session list. Nullable + default
    // false so the column add is non-destructive — old rows pre-feature
    // simply read as not-suspicious. Never reset to false: a session
    // that ever tripped a flag stays flagged for the life of the row;
    // logout-all is the user's reset button.
    suspicious: boolean("suspicious").default(false),
    // Stable per-device identifier — SHA-256(user-agent || ip || platform).
    // Computed at login time and stored verbatim. We use it on subsequent
    // logins to decide whether the user is signing in from a device this
    // account has seen before. Nullable so old pre-feature rows survive
    // the additive column add unchanged; a NULL fingerprint never matches
    // a new login (which always has a non-null hash) so legacy sessions
    // are treated as "unknown device" if the user logs in fresh — exactly
    // the safe default. We deliberately do NOT store the raw user-agent
    // / ip in this column (those already live in user_agent / ip_address);
    // the hash is opaque so a DB leak cannot reconstruct browser
    // fingerprints from this column alone.
    deviceFingerprint: text("device_fingerprint"),
    // TRUE if the user has actively approved this device for sensitive
    // actions (sync / restore). Set on login when the same fingerprint
    // has been seen for this user before, OR on POST /api/auth/trust-device
    // for the current session. Never reset to false (the "I changed my
    // mind" path is logout / logout-all, not a trust toggle). Default
    // false matches the secure-by-default "treat unknown devices as
    // untrusted until proven otherwise" stance. Old pre-feature rows
    // surface as false to the client (see DatabaseStorage.listActiveSessionsForUser
    // for the coercion).
    trusted: boolean("trusted").default(false),
  },
  (table) => [
    index("sessions_user_expires_idx").on(table.userId, table.expiresAt),
    // Drives the new-device check on login: "has this (userId, fingerprint)
    // been seen before?" — a single indexed lookup. Without this index the
    // login path would full-scan the sessions table on every login, which
    // becomes painful as the table grows.
    index("sessions_user_fingerprint_idx").on(
      table.userId,
      table.deviceFingerprint,
    ),
  ],
);

// Append-only audit trail of sensitive user actions: logins, logouts,
// every successful vault read/write, and detected anomalies. Powers the
// user-facing GET /api/vault/audit endpoint and gives operators a way to
// reconstruct "what happened on this account" after a security incident.
//
// Zero-knowledge guarantees are preserved: this table NEVER stores
// encrypted blob contents, auth hashes, or session tokens — only
// metadata about the action (which version was written, how big the
// blob was, where the request came from).
//
// version_before / version_after / blob_size_bytes are nullable because
// only the vault_sync / vault_restore actions populate them; login,
// logout, fetch, and anomaly events leave them null.
//
// ip_address / user_agent are nullable because not every code path has
// a request object (background tasks, future CLI tools), and because
// the spec explicitly allows missing values.
//
// created_at uses bigint epoch-ms to match the existing codebase
// convention (users.createdAt, sessions.*, vaultBlobs.updatedAt,
// vaultBlobHistory.archivedAt all use this shape) — same deliberate
// deviation from the spec's "TIMESTAMP" wording as the sessions table.
export const vaultAuditLog = pgTable(
  "vault_audit_log",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    action: text("action").notNull(),
    versionBefore: integer("version_before"),
    versionAfter: integer("version_after"),
    blobSize: integer("blob_size_bytes"),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    createdAt: bigint("created_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (table) => [
    // Primary access pattern: "give me the most recent N entries for
    // this user" — drives GET /api/vault/audit. The .desc() on
    // createdAt makes the ORDER BY ... DESC LIMIT 100 a single index
    // scan with no sort step.
    index("vault_audit_user_created_idx").on(
      table.userId,
      table.createdAt.desc(),
    ),
    // Secondary access pattern: "did this user ever do action X?"
    // (anomaly review, security audit). Cheaper than a full scan with
    // a per-user predicate plus an action filter.
    index("vault_audit_user_action_idx").on(table.userId, table.action),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type VaultBlob = typeof vaultBlobs.$inferSelect;
export type NewVaultBlob = typeof vaultBlobs.$inferInsert;
export type VaultBlobHistoryEntry = typeof vaultBlobHistory.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type VaultAuditLogEntry = typeof vaultAuditLog.$inferSelect;

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

// x-session-token header: 32 random bytes encoded as 64 lowercase hex
// chars (see crypto.randomBytes(32).toString("hex") in the login route).
// Validating shape early avoids spending a SHA-256 + indexed lookup on
// obvious junk and gives a clean 400 for malformed tokens. Accepts both
// upper- and lower-case hex; the server normalizes by hashing.
export const sessionTokenHeaderSchema = z
  .string()
  .length(64)
  .regex(/^[0-9a-fA-F]+$/);

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VaultSyncInput = z.infer<typeof vaultSyncSchema>;
