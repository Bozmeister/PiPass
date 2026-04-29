import { z } from "zod";
import { sql } from "drizzle-orm";
import {
  pgTable,
  text,
  integer,
  bigint,
  uuid,
  boolean,
  check,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
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
    // TOTP (RFC 6238) second-factor state. Both columns are additive,
    // nullable / default-false so old rows pre-feature continue to work
    // unchanged: a user with totpEnabled=null|false is treated as
    // "TOTP not enabled" and the entire 2FA path is skipped for them.
    //
    // totpEnabled is the source of truth for "does this user have 2FA
    // turned on" — it's only set TRUE after POST /api/auth/totp/verify
    // proves the user holds the secret (so we never enable 2FA on a
    // half-finished setup that would lock the user out).
    totpEnabled: boolean("totp_enabled").default(false),
    // Encrypted form of the user's TOTP shared secret (base32 raw secret
    // wrapped via AES-256-GCM with a per-deployment key — see
    // server/totp.ts encryptTotpSecret). Stored ONLY as ciphertext: a
    // database leak therefore cannot be replayed against the user's
    // authenticator app. NULL until the user completes setup; reset to
    // NULL on disable. We deliberately do NOT store the plaintext or any
    // hash of the secret — verification re-derives the TOTP token from
    // the decrypted secret on demand.
    totpSecretEncrypted: text("totp_secret_encrypted"),
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
    // Step-up TOTP timestamp (epoch-ms): the session is considered
    // "2FA-verified for sensitive writes" while Date.now() < this value.
    // Set by POST /api/auth/totp/step-up to now + STEP_UP_TTL_MS (5 min)
    // and consulted on /api/vault/sync (when securityLevel >= high or
    // device untrusted) and /api/vault/restore (always). Nullable so old
    // pre-feature rows surface as "never step-up verified" — the safe
    // default. We deliberately do NOT clear this column on logout —
    // the row is deleted with the session, and on a fresh login a new
    // row is created with NULL anyway.
    totpVerifiedUntil: bigint("totp_verified_until", { mode: "number" }),
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

// WebAuthn credentials registered by users for passkey / hardware-key
// based authentication. This table is purely additive — it does not
// touch users or any other existing table.
//
// Notes on column choices:
// - credentialId is text (the credential id the authenticator returns
//   is base64url-encoded and variable length — text avoids byte-length
//   surprises). Marked unique so duplicate registrations are rejected
//   at the DB level rather than only in app code.
// - publicKey is text (COSE key serialised by @simplewebauthn/server,
//   stored base64url) — same reasoning.
// - counter is integer per the WebAuthn spec's signCount.
// - transports is a nullable JSON string ("usb", "nfc", "ble",
//   "internal", "hybrid"); the authenticator may report none.
// - createdAt / lastUsedAt are bigint epoch-ms to match every other
//   timestamp column in this codebase (users, sessions, vault*, audit).
// - revoked is a soft-delete flag so we keep the audit trail of who
//   ever registered what, without losing history on revoke.
export const webauthnCredentials = pgTable(
  "webauthn_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    credentialId: text("credential_id").notNull().unique(),
    publicKey: text("public_key").notNull(),
    counter: integer("counter").notNull(),
    deviceName: text("device_name"),
    transports: text("transports"),
    createdAt: bigint("created_at", { mode: "number" })
      .notNull()
      .$defaultFn(() => Date.now()),
    lastUsedAt: bigint("last_used_at", { mode: "number" }),
    revoked: boolean("revoked").notNull().default(false),
  },
  (table) => [
    // "List a user's passkeys" — drives the credentials management
    // screen and is also the prefilter before joining on credentialId.
    index("webauthn_credentials_user_idx").on(table.userId),
    // "Look up a credential by its WebAuthn credential id" — drives
    // every assertion verification (`navigator.credentials.get`).
    // Even though credentialId is UNIQUE (which already implies an
    // index), declaring it explicitly keeps the access pattern legible
    // and matches the rest of this file's convention of co-locating
    // hot-path indexes with the table definition.
    index("webauthn_credentials_credential_id_idx").on(table.credentialId),
  ],
);

// Per-user device trust ledger (separate from sessions). One row per
// (user, device-fingerprint) pair; the SAME physical device that logs in
// across multiple sessions reuses the same row (lastSeenAt is bumped on
// every authenticated request via authenticate()). Compared to the
// sessions table this is durable across logout/login cycles, so a user
// who has trusted "my iPhone" once does NOT get re-prompted every time
// they sign in from it.
//
// Why a separate table instead of reusing sessions.trusted:
//   - sessions.trusted is per-session (a fresh login on the same
//     device starts a new untrusted session) — useful for the "approve
//     this NEW SESSION" flow but wrong for "I trust this device".
//   - This table is per-device and persists across session lifetimes,
//     so it can drive the management UI ("here are all devices that
//     have ever signed into your account; revoke any you don't
//     recognize") without polluting the auth hot path.
//
// deviceFingerprint is the SHA-256(lowercased+trimmed UA || \0 || IP)
// computed by deriveDeviceFingerprint() in routes.ts. We deliberately
// do NOT store raw IP / UA values here — only the irreversible hash —
// so a leak of this table cannot be replayed to triangulate a user's
// movements. The label column is a USER-SUPPLIED nickname (e.g.
// "iPhone 15", "Work Laptop"); the server never auto-derives one.
//
// PRIMARY KEY shape matches every other id column in this file
// (uuid().defaultRandom()) — see the project's standing rule about
// preserving existing ID conventions for FK compatibility with users.id.
export const trustedDevices = pgTable(
  "trusted_devices",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    // SHA-256(lowercase(trim(user-agent)) || \0 || ip), hex-encoded.
    // 64-char fixed length; storing as text (not varchar(64)) keeps
    // the schema permissive in case the hash function is later
    // upgraded — old rows still validate. The hash is irreversible
    // by construction, so storing it does not leak the underlying
    // (UA, IP) pair.
    deviceFingerprint: text("device_fingerprint").notNull(),
    // User-supplied label, e.g. "iPhone 15" or "Work Laptop". Nullable
    // because devices appear here BEFORE the user has labeled them
    // (createOrUpdateDevice is called from authenticate()), so a
    // device that has never been visited in the management UI shows
    // up with label=null.
    label: text("label"),
    // FALSE on first sight — the user must explicitly confirm trust
    // via POST /api/security/device/trust (which itself requires a
    // step-up, so a stolen session cannot self-elevate). TRUE means
    // the device has been approved AT LEAST ONCE; the user can flip
    // it back to FALSE via /api/security/device/revoke.
    trusted: boolean("trusted").notNull().default(false),
    firstSeenAt: bigint("first_seen_at", { mode: "number" }).notNull(),
    lastSeenAt: bigint("last_seen_at", { mode: "number" }).notNull(),
  },
  (table) => [
    // Hot-path lookups: "list this user's devices" (management UI) and
    // "find this user's row for this fingerprint" (createOrUpdateDevice
    // upsert path). The composite UNIQUE index serves the upsert
    // ON CONFLICT target AND covers user-id-prefix queries at the
    // same time — Postgres can scan the leading column alone.
    uniqueIndex("trusted_devices_user_fingerprint_uidx").on(
      table.userId,
      table.deviceFingerprint,
    ),
    // Per-task spec: explicit single-column indexes on user_id and
    // device_fingerprint. The user_id index is technically redundant
    // with the composite uniqueIndex above (left-prefix), but kept
    // explicitly to match the task spec verbatim and to remain
    // readable to future maintainers.
    index("trusted_devices_user_idx").on(table.userId),
    index("trusted_devices_fingerprint_idx").on(table.deviceFingerprint),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type VaultBlob = typeof vaultBlobs.$inferSelect;
export type NewVaultBlob = typeof vaultBlobs.$inferInsert;
export type VaultBlobHistoryEntry = typeof vaultBlobHistory.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type VaultAuditLogEntry = typeof vaultAuditLog.$inferSelect;
export type WebauthnCredential = typeof webauthnCredentials.$inferSelect;
export type NewWebauthnCredential = typeof webauthnCredentials.$inferInsert;
export type TrustedDevice = typeof trustedDevices.$inferSelect;
export type NewTrustedDevice = typeof trustedDevices.$inferInsert;

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

// TOTP token shape — RFC 6238 default (6 digits, decimal). Strict regex
// instead of length()+isNumeric so something like "0123ab" trips the
// validator early instead of reaching otplib.authenticator.check (which
// would also reject it, but with a less specific error).
export const totpTokenSchema = z
  .string()
  .regex(/^\d{6}$/, "TOTP token must be 6 digits");

// Temp token returned by /api/auth/login when TOTP is required. Same
// shape as a session token (32 random bytes, hex-encoded) so we can
// re-use the same client-side validation pattern. The temp token is
// NOT a session token — it cannot authenticate any other endpoint and
// is single-use, consumed by /api/auth/totp/login.
export const totpTempTokenSchema = z
  .string()
  .length(64)
  .regex(/^[0-9a-fA-F]+$/);

// Body for POST /api/auth/totp/verify (enable flow) and
// /api/auth/totp/step-up (sensitive-action gate). .strict() so unknown
// fields are rejected — mirrors every other request schema in this file.
export const totpVerifySchema = z
  .object({
    token: totpTokenSchema,
  })
  .strict();

// Body for POST /api/auth/totp/login. Combines the temp token issued
// by the password phase with the user's current authenticator code.
export const totpLoginSchema = z
  .object({
    tempToken: totpTempTokenSchema,
    token: totpTokenSchema,
  })
  .strict();

// ----- WebAuthn / passkey registration request bodies -----
//
// /api/passkeys/register/start currently takes no body — the server
// derives everything from the authenticated session (userId,
// username) and the existing credential list. We still validate
// .strict() so a client that sends an unexpected field gets a clear
// 400 instead of a silently-ignored payload (consistent with every
// other endpoint in this file).
export const passkeyRegisterStartSchema = z.object({}).strict();

// Per the WebAuthn spec, the response object the browser hands back
// from `navigator.credentials.create()` has a known top-level shape
// (id, rawId, type, response, optional authenticatorAttachment +
// clientExtensionResults). We strict-check the OUTER object so a
// malformed wrapper is rejected, but pass through the INNER
// `response` sub-object: authenticators legitimately add fields
// (e.g. publicKey/publicKeyAlgorithm in newer browsers) and we want
// the @simplewebauthn library to be the source of truth on what's
// inside it, not this file. We DO validate the required strings
// (clientDataJSON, attestationObject) are non-empty so an obviously
// junk body never reaches the verifier.
//
// deviceName is collected here (not on /start) so the user can label
// the credential AFTER the authenticator ceremony succeeds. Bounded
// 1-128 chars, optional.
const webauthnRegistrationInnerResponseSchema = z
  .object({
    clientDataJSON: z.string().min(1).max(50_000),
    attestationObject: z.string().min(1).max(100_000),
  })
  .passthrough();

const webauthnRegistrationResponseSchema = z
  .object({
    id: z.string().min(1).max(2000),
    rawId: z.string().min(1).max(2000),
    type: z.literal("public-key"),
    response: webauthnRegistrationInnerResponseSchema,
    authenticatorAttachment: z
      .enum(["platform", "cross-platform"])
      .optional(),
    clientExtensionResults: z.record(z.unknown()).optional(),
  })
  .strict();

export const passkeyRegisterFinishSchema = z
  .object({
    response: webauthnRegistrationResponseSchema,
    deviceName: z.string().min(1).max(128).optional(),
  })
  .strict();

export type PasskeyRegisterStartInput = z.infer<
  typeof passkeyRegisterStartSchema
>;
export type PasskeyRegisterFinishInput = z.infer<
  typeof passkeyRegisterFinishSchema
>;

// Passkey login start: client tells us which user is trying to sign
// in so we can scope the challenge and look up their allowed
// credential ids for the authenticator allowlist. Username bounds
// match registerSchema/loginSchema (3-64 chars). Strict-checked so
// any unexpected field is a 400.
export const passkeyLoginStartSchema = z
  .object({
    username: z.string().min(3).max(64),
  })
  .strict();

// Mirror of the registration response schema: strict outer envelope,
// passthrough inner response. The required strings (clientDataJSON,
// authenticatorData, signature) are bounded non-empty so an obviously
// junk body never reaches the verifier; userHandle is optional and
// allowed-empty (the spec lets the authenticator omit it on the
// non-discoverable path).
const webauthnAuthenticationInnerResponseSchema = z
  .object({
    clientDataJSON: z.string().min(1).max(50_000),
    authenticatorData: z.string().min(1).max(50_000),
    signature: z.string().min(1).max(2000),
    userHandle: z.string().max(2000).optional(),
  })
  .passthrough();

const webauthnAuthenticationResponseSchema = z
  .object({
    id: z.string().min(1).max(2000),
    rawId: z.string().min(1).max(2000),
    type: z.literal("public-key"),
    response: webauthnAuthenticationInnerResponseSchema,
    authenticatorAttachment: z
      .enum(["platform", "cross-platform"])
      .optional(),
    clientExtensionResults: z.record(z.unknown()).optional(),
  })
  .strict();

export const passkeyLoginFinishSchema = z
  .object({
    response: webauthnAuthenticationResponseSchema,
  })
  .strict();

export type PasskeyLoginStartInput = z.infer<typeof passkeyLoginStartSchema>;
export type PasskeyLoginFinishInput = z.infer<typeof passkeyLoginFinishSchema>;

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VaultSyncInput = z.infer<typeof vaultSyncSchema>;
export type TotpVerifyInput = z.infer<typeof totpVerifySchema>;
export type TotpLoginInput = z.infer<typeof totpLoginSchema>;
