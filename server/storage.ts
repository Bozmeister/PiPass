import { and, desc, eq, gt, lt, sql } from "drizzle-orm";
import { db } from "./db";
import {
  users,
  vaultBlobs,
  vaultBlobHistory,
  sessions,
  vaultAuditLog,
  webauthnCredentials,
  trustedDevices,
  honeytokens,
  type User,
  type VaultBlob,
  type Session,
  type WebauthnCredential,
} from "../shared/schema";

// Maximum historical encrypted blobs retained per user. Bounded to keep
// storage growth O(N) per user — without a cap, a malicious creds-holder
// could spam syncs and balloon the table indefinitely.
export const VAULT_HISTORY_LIMIT = 10;

// Session lifetime. 30 days mirrors industry-standard "remember me" tokens
// (1Password, Bitwarden) and bounds the compromise window for a stolen
// token: even if logout-all is never called, a leaked token expires on
// its own. Picked here (rather than on the client) so server-side rotation
// of this constant immediately shortens every NEW session — old sessions
// keep their original TTL until they expire naturally.
export const SESSION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

export type VaultHistoryEntry = {
  version: number;
  archivedAt: number;
  blobSize: number;
};

// `previousVersion` is the version that was current in vault_blobs
// immediately BEFORE this sync committed (null on first-ever write for
// the user). Captured inside the same transaction as the CAS so it is
// race-free — a separate getVaultBlob() call from the route would risk
// reporting a stale version if a concurrent sync interleaved. Consumed
// by the audit log to populate version_before.
export type SyncVaultResult =
  | { ok: true; blob: VaultBlob; previousVersion: number | null }
  | { ok: false; code: "version_conflict"; serverVersion: number };

// `previousVersion` is the version that was current BEFORE the restore
// overwrote it (null if the user had no current vault yet — restoring
// directly into an empty user state). Same race-free guarantee as
// SyncVaultResult.previousVersion.
export type RestoreVaultResult =
  | {
      ok: true;
      blob: VaultBlob;
      restoredFromVersion: number;
      previousVersion: number | null;
    }
  | { ok: false; code: "not_found" }
  | { ok: false; code: "version_conflict"; serverVersion: number };

// Public shape for GET /api/auth/sessions. The token_hash column is
// deliberately omitted — it would let a DB-leak attacker invert the hash
// table to identify "this user was active across these N devices". Only
// non-sensitive metadata flows out: id, timestamps, user-agent, ip,
// and the suspicious flag (TRUE if this session was the authenticating
// session at the time an anomaly_detected event fired).
export type SessionListItem = {
  id: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  userAgent: string | null;
  ipAddress: string | null;
  suspicious: boolean;
  // TRUE if this device has been approved for sensitive actions (sync /
  // restore). Drives the per-row "Trusted device" / "New device — needs
  // approval" badge in the user-facing sessions UI. Coerced from the
  // nullable DB column so old pre-feature rows surface as false (the
  // safe default — old sessions are treated as untrusted on the read
  // path until the user explicitly trusts them).
  trusted: boolean;
};

// Input shape for the audit-log writer. `action` is intentionally a
// loose string (not a union) so anomaly_detected / ip_change_detected
// and any future event types can be appended without changing the
// storage interface. Optional fields default to null in the DB.
export type AuditEventInput = {
  userId: string;
  action: string;
  versionBefore?: number | null;
  versionAfter?: number | null;
  blobSize?: number | null;
  ipAddress?: string | null;
  userAgent?: string | null;
};

// Public shape for GET /api/vault/audit. The internal `id` column is
// deliberately omitted (per spec) — exposing the row UUID is gratuitous
// information leakage and serves no client-side use case. The shape is
// what the user sees in their "vault activity" view.
export type AuditLogItem = {
  action: string;
  createdAt: number;
  ipAddress: string | null;
  userAgent: string | null;
  versionBefore: number | null;
  versionAfter: number | null;
  blobSize: number | null;
};

// Bounded result count for GET /api/vault/audit (no pagination per
// spec). 100 is enough for a "recent activity" UI without paying the
// cost of the full table on every query.
export const AUDIT_LOG_LIMIT = 100;

// Public-safe projection of a WebAuthn credential for management
// screens ("here are the passkeys you've registered"). DELIBERATELY
// omits public_key (the COSE-encoded key material is only ever needed
// server-side during assertion verification, never on the wire to the
// user) and counter (an internal anti-replay scalar, not user-facing).
// Mirrors the same "minimum fields needed for the UI" discipline as
// SessionListItem and AuditLogItem.
export type CredentialListItem = {
  id: string;
  credentialId: string;
  deviceName: string | null;
  transports: string | null;
  createdAt: number;
  lastUsedAt: number | null;
};

// Public-safe projection of a trusted_devices row for the device
// management screen. Mirrors CredentialListItem's "minimum fields the
// UI needs" discipline: the fingerprint is the only stable handle the
// client uses to address subsequent /trust /revoke /label calls; label
// + trusted drive the row's display state; firstSeenAt + lastSeenAt
// drive the "first seen … last seen …" subtitle.
//
// DELIBERATELY OMITS:
//   - id (internal uuid PK; clients address rows by fingerprint, which
//     is itself unique per (user, device) — exposing the PK would
//     create a second handle to the same row and tempt callers to
//     stash and reuse it across contexts).
//   - userId (the client already knows its own userId from auth; echoing
//     it back is dead weight and a minor disclosure if any response
//     ever leaks cross-tenant).
//   - raw IP / UA values (we never stored them — only the irreversible
//     hash; this comment exists to make the absence intentional).
export type DeviceListItem = {
  fingerprint: string;
  label: string | null;
  trusted: boolean;
  firstSeenAt: number;
  lastSeenAt: number;
};

// Result of createOrUpdateDevice. `created` is true on first insert
// (new device for this user) so the caller can fire the
// new_device_detected audit row exactly once per device-discovery —
// repeated authenticated requests from the same device subsequently
// return created=false and audit nothing. `row` is the post-write
// projection (same shape as DeviceListItem) so the caller doesn't
// need a follow-up SELECT to know the device's current trust state.
export type DeviceUpsertResult = {
  created: boolean;
  row: DeviceListItem;
};

// Public projection of a honeytoken row. The `markerHash` column is
// DELIBERATELY EXCLUDED — once stored, the irreversible hash is never
// surfaced over the API. The management UI doesn't need it (the user
// already chose the marker locally; the hash is purely an internal
// equality key) and excluding it at the type-and-SELECT layer is
// belt-and-braces defense in depth: even if a future change accidentally
// returns these rows over the API, the type narrows the shape and the
// SELECT narrows the bytes that ever leave the DB. Same discipline as
// the public_key/counter exclusions on CredentialListItem above.
export type HoneytokenListItem = {
  id: string;
  label: string;
  tokenType: string;
  active: boolean;
  createdAt: number;
  triggeredAt: number | null;
  triggerCount: number;
};

// Result of triggerHoneytoken on a successful match. Returns the
// post-update counter so the route layer can decide whether to escalate
// to soft-lock (count >= 2). Also surfaces the row's label + tokenType
// so the audit row can carry human-readable context — NEVER includes
// the markerHash itself (route layer must not log it). Returns null
// when no active row matches the (userId, markerHash) pair, which the
// route layer treats as a no-op 200 to avoid leaking information about
// which markers exist.
export type HoneytokenTriggerResult = {
  honeytokenId: string;
  label: string;
  tokenType: string;
  triggerCount: number;
};

// Result of disableHoneytoken on success. Surfaces the same metadata
// (label + tokenType) so the route layer can write an honeytoken_disabled
// audit row WITHOUT a follow-up SELECT, and so the response can confirm
// to the UI which trap was retired. Returns null when no row matched
// (wrong id / wrong user / already inactive) — route layer treats null
// as a non-leaky 200-with-changed:false.
export type HoneytokenDisableResult = {
  label: string;
  tokenType: string;
};

// Sentinel error thrown by createHoneytoken when the (user_id,
// marker_hash) UNIQUE constraint fires. The route layer catches this
// and returns 409 — separate from generic 500s so the client can
// distinguish "duplicate" from "DB down". We extend Error rather than
// returning a tagged union so existing async-error machinery (try /
// catch, .catch handlers) can dispatch on instanceof — same pattern
// you'd reach for when wrapping a third-party SDK error.
export class HoneytokenMarkerConflictError extends Error {
  constructor() {
    super("honeytoken with this marker already exists for this user");
    this.name = "HoneytokenMarkerConflictError";
  }
}

// Input for createWebAuthnCredential. Required fields mirror what the
// @simplewebauthn-style verifyRegistrationResponse output gives us:
// the credentialId + COSE publicKey + initial signCount. deviceName /
// transports are caller-provided convenience fields (transports is
// reported by the authenticator; deviceName is typically a
// user-supplied label or a default like "iPhone passkey").
export type CreateWebAuthnCredentialInput = {
  userId: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  deviceName: string | null;
  transports: string | null;
};

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(input: {
    username: string;
    authHash: string;
    salt: string;
    iterations: number;
  }): Promise<User>;
  getVaultBlob(userId: string): Promise<VaultBlob | undefined>;
  syncVault(
    userId: string,
    encryptedBlob: string,
    version: number,
  ): Promise<SyncVaultResult>;
  getVaultHistory(userId: string): Promise<VaultHistoryEntry[]>;
  restoreVault(
    userId: string,
    targetVersion: number,
  ): Promise<RestoreVaultResult>;

  createSession(input: {
    userId: string;
    tokenHash: string;
    expiresAt: number;
    userAgent: string | null;
    ipAddress: string | null;
    // Per-device hash computed by getDeviceFingerprint() in routes.ts.
    // Nullable so background tasks / future callers without a Request
    // object can still create sessions; the login route always passes
    // a non-null value.
    deviceFingerprint: string | null;
    // TRUE if the route layer determined this device has been seen
    // before for this user. The route is responsible for the lookup;
    // this method just persists the decision.
    trusted: boolean;
  }): Promise<Session>;
  getActiveSessionByTokenHash(tokenHash: string): Promise<Session | undefined>;
  touchSession(id: string, lastSeenAt: number): Promise<void>;
  deleteSessionById(id: string): Promise<boolean>;
  deleteAllSessionsForUser(userId: string): Promise<number>;
  listActiveSessionsForUser(userId: string): Promise<SessionListItem[]>;

  // Returns true if this user has at least one EXISTING session row with
  // the given device fingerprint. Drives the "is this a new device?"
  // decision on login. We deliberately do NOT filter by expires_at: a
  // user logging back in after a session expires from a device we've
  // seen before should still be treated as a known device. (Logout-all
  // / explicit row deletion is the user's "forget my devices" reset.)
  // Fail-open: a NULL fingerprint never matches (callers should treat
  // a null fingerprint as "unknown device" without even calling this).
  hasDeviceFingerprintForUser(
    userId: string,
    fingerprint: string,
  ): Promise<boolean>;

  // Set sessions.trusted = true for the current session. Same fail-open
  // contract as markSessionSuspicious: MUST NOT throw — implementations
  // swallow errors internally. Called from POST /api/auth/trust-device
  // after the route has already issued its 200, so a DB hiccup here
  // cannot break the user-facing flow. Idempotent: marking an already-
  // trusted session is a no-op single-column UPDATE.
  markSessionTrusted(sessionId: string): Promise<void>;

  // Persist a freshly-verified TOTP secret AND flip the user's
  // totp_enabled flag in a single atomic UPDATE. We deliberately
  // combine the two writes: a partial outcome (secret stored but flag
  // not flipped, or vice versa) would leave the user in an unusable
  // state. Returns void on success; on DB error the call rejects
  // (caller surfaces 500) — UNLIKE the fire-and-forget audit/trust
  // helpers, this one IS on the critical path of /totp/verify and
  // must not silently succeed.
  setTotpEnabled(userId: string, encryptedSecret: string): Promise<void>;

  // Mirror the session column written by POST /api/auth/totp/step-up.
  // Same fail-open contract as markSessionTrusted / markSessionSuspicious:
  // MUST NOT throw — implementations swallow internally and only log.
  // Called fire-and-forget AFTER the route has already issued its 200.
  // Idempotent: calling it twice with the same `until` is a no-op.
  // Returns true if the session row was updated, false if the DB
  // write failed. Routes MUST treat false as a hard failure (500) —
  // see implementation note on DatabaseStorage.markSessionTotpVerified.
  markSessionTotpVerified(sessionId: string, until: number): Promise<boolean>;

  // Set sessions.suspicious = true. Same fail-open contract as
  // logAuditEvent: this method MUST NOT throw — implementations
  // swallow all errors internally. Called fire-and-forget from the
  // request handler when an anomaly fires; failing the suspicious flag
  // must NEVER fail the API response. Idempotent: marking an already-
  // suspicious session is a no-op (single-column UPDATE to the same
  // value). No-op when sessionId is null (legacy auth-hash callers
  // have no session row to mark).
  markSessionSuspicious(sessionId: string): Promise<void>;

  // Audit log writer. CONTRACT:
  //   - Must NEVER throw — implementations MUST swallow all errors
  //     internally and only log them. The caller relies on
  //     fire-and-forget semantics: a failed audit insert must NOT
  //     break the API response that triggered it.
  //   - Must NOT block. Callers do `void storage.logAuditEvent(...)`
  //     and immediately return their HTTP response; the row write
  //     races the response and may commit AFTER the client gets the
  //     200. That's intentional — the audit log is best-effort
  //     observability, not a critical path.
  logAuditEvent(input: AuditEventInput): Promise<void>;

  // Reader for GET /api/vault/audit. Returns at most `limit` rows
  // (defaults to AUDIT_LOG_LIMIT) ordered by created_at DESC. The
  // internal `id` column is NEVER included in the result — see
  // AuditLogItem doc for why.
  getAuditLog(userId: string, limit?: number): Promise<AuditLogItem[]>;

  // ----- WebAuthn / passkeys -----
  //
  // Insert a freshly-verified credential. Caller (the registration
  // verify route) is responsible for having validated the attestation
  // against the active challenge before calling this — storage just
  // persists. Returns the inserted row (including the generated id);
  // the caller decides what to surface to the client.
  // Throws on DB error: registration is on the critical path of "did
  // we actually save this passkey?" and silently succeeding would
  // leave the user with a passkey that never actually authenticates.
  createWebAuthnCredential(
    input: CreateWebAuthnCredentialInput,
  ): Promise<WebauthnCredential>;

  // Lookup by the WebAuthn credential id (NOT the internal uuid PK).
  // Drives assertion verification — given the credentialId the
  // browser sends in `navigator.credentials.get`, fetch the stored
  // public_key + counter so we can verify the signature.
  // EXCLUDES revoked rows: a revoked credential MUST NOT authenticate
  // even if the client somehow still has it cached locally. Returns
  // undefined if no row matches OR if the row exists but is revoked
  // (the route layer treats both as "unknown credential" with the
  // same error to avoid leaking which case applies).
  getCredentialById(
    credentialId: string,
  ): Promise<WebauthnCredential | undefined>;

  // List a user's NON-REVOKED credentials for the management screen.
  // Returns the public-safe projection — public_key and counter are
  // intentionally NOT included (see CredentialListItem doc). Ordered
  // by created_at DESC so the most-recently-registered passkey is
  // first, matching the convention of listActiveSessionsForUser.
  listCredentialsForUser(userId: string): Promise<CredentialListItem[]>;

  // Persist the new signCount returned by verifyAuthenticationResponse.
  // The WebAuthn spec requires the server to refuse any future
  // assertion whose counter is <= the stored counter (anti-replay) so
  // this write is on the critical path: we MUST throw on DB error so
  // the route can fail the assertion rather than blindly returning a
  // session that the next assertion can replay. Also bumps last_used_at
  // in the same UPDATE — assertion success is the natural "used" event,
  // so combining the writes saves a round trip and keeps the two
  // values in sync.
  // Refuses to update revoked rows (defense in depth — the route
  // already filters via getCredentialById, but a revoked row should
  // never get its counter advanced).
  //
  // T002 hardening: the UPDATE is conditional on the stored counter
  // being STRICTLY LESS THAN the new counter. Two concurrent
  // assertions for the same credential racing with the same
  // verified.newCounter (e.g. user double-taps a passkey prompt and
  // both assertions land at the server in parallel) will both pass
  // the SimpleWebAuthn verifier (which compared each independently
  // against the SAME stored counter), but only ONE can satisfy the
  // `counter < newCounter` predicate at commit time — the second
  // observes its own write equal-to-not-less-than and updates zero
  // rows. Returns FALSE in that case so the caller can treat it as
  // a counter-replay (revoke + audit + escalate) rather than
  // silently let the second assertion through. TRUE on the normal
  // path where the row was advanced.
  updateCredentialCounter(
    credentialId: string,
    counter: number,
  ): Promise<boolean>;

  // Standalone "I was just used" stamp for codepaths that don't bump
  // the counter (e.g. user-initiated re-verification flows that don't
  // produce a new signCount, or future passkey-list pings). Fail-open
  // per the same contract as markSessionTrusted: MUST NOT throw —
  // last_used_at is metadata, never load-bearing for auth correctness.
  // Refuses to update revoked rows.
  updateCredentialLastUsed(credentialId: string): Promise<void>;

  // Soft-delete: set revoked = true. Returns true if a non-revoked
  // row was actually flipped, false if no matching row was found OR
  // the row was already revoked. Idempotent at the DB level: a second
  // call simply returns false. Throws on DB error — revoke is a
  // user-facing security action ("remove this passkey") that MUST
  // surface failure rather than silently leaving the credential live.
  revokeCredential(credentialId: string): Promise<boolean>;

  // ----- Trusted devices (T002) -----
  //
  // Upsert by (userId, deviceFingerprint). On first sight the row is
  // inserted with trusted=false and label=null; subsequent calls only
  // bump lastSeenAt — they NEVER overwrite the user's existing label
  // or trust flag (the client must use the explicit /trust, /revoke,
  // /label endpoints to mutate those, all of which are step-up gated).
  //
  // CONTRACT:
  //   - Throws on DB error. Caller (authenticate()) wraps the call in
  //     its own try/catch so the auth hot path remains fail-open even
  //     if device tracking is briefly unavailable.
  //   - Returned `created` distinguishes the FIRST sighting (caller
  //     should audit new_device_detected) from a steady-state ping
  //     (no audit). The DB-side computation uses xmax=0 — true when
  //     ON CONFLICT DID NOT FIRE — so the signal is race-safe and
  //     does not need a follow-up SELECT.
  createOrUpdateDevice(input: {
    userId: string;
    deviceFingerprint: string;
    now: number;
  }): Promise<DeviceUpsertResult>;

  // List a user's known devices for the management screen. Returns the
  // public-safe projection (see DeviceListItem doc). Ordered by
  // lastSeenAt DESC so the user's CURRENT device floats to the top.
  // Scoped strictly by userId — there is no cross-tenant fallback path.
  getDevicesForUser(userId: string): Promise<DeviceListItem[]>;

  // Flip trusted=true. Scoped by (userId, fingerprint) so a caller
  // cannot trust another user's device by guessing fingerprints.
  // Returns true if a row was flipped, false if no matching device
  // exists for this user OR it was already trusted (idempotent).
  // Throws on DB error — like revokeCredential, this is a user-facing
  // security action that MUST surface failure.
  markDeviceTrusted(userId: string, deviceFingerprint: string): Promise<boolean>;

  // Inverse of markDeviceTrusted. Same semantics — scoped by user,
  // returns true on actual transition, false on already-untrusted or
  // not-found.
  revokeDeviceTrust(userId: string, deviceFingerprint: string): Promise<boolean>;

  // Update the user-supplied label. Caller is responsible for length
  // bounds + sanitization (route layer enforces ≤64 chars + control-
  // char rejection). Scoped by user. Returns true on row write, false
  // if the device does not exist for this user. Throws on DB error.
  relabelDevice(
    userId: string,
    deviceFingerprint: string,
    label: string,
  ): Promise<boolean>;

  // ----- Honeytokens (deception layer) -----
  //
  // Persist a freshly-registered honeytoken. Caller (the create route)
  // must have validated label/tokenType/markerHash bounds via the
  // request schema before calling — storage just persists. Returns the
  // public projection (NEVER includes markerHash) so the route layer
  // can echo back the row id + createdAt without a follow-up SELECT.
  // Throws on DB error. THROWS HoneytokenMarkerConflictError when the
  // composite UNIQUE (user_id, marker_hash) violates — the route layer
  // catches this and returns 409.
  createHoneytoken(input: {
    userId: string;
    label: string;
    tokenType: string;
    markerHash: string;
  }): Promise<HoneytokenListItem>;

  // List a user's honeytokens for the management UI. Returns the public
  // projection — markerHash is intentionally NOT included (see
  // HoneytokenListItem doc). Includes both active=true AND active=false
  // rows so the UI can show a "previously disabled" history; the UI
  // distinguishes via the active flag in the projection. Ordered by
  // createdAt DESC so the newest honeytoken floats to the top, matching
  // the convention of listCredentialsForUser. Scoped strictly by userId.
  listHoneytokens(userId: string): Promise<HoneytokenListItem[]>;

  // Atomic trigger: increments trigger_count and stamps triggered_at
  // for the (userId, markerHash, active=true) row in a single UPDATE.
  // Concurrent triggers on the same row are race-safe — both UPDATEs
  // serialize through the row lock and each one sees the post-update
  // counter. Returns null when no active row matches (wrong user,
  // unknown hash, or already disabled) — the route layer treats null
  // as a non-leaky 200 to avoid signaling which markers exist. Throws
  // on DB error: this method IS on the critical path of the security
  // escalation, and silently failing would mean an attacker probing
  // honeytokens leaves no audit trail.
  triggerHoneytoken(
    userId: string,
    markerHash: string,
  ): Promise<HoneytokenTriggerResult | null>;

  // Soft-disable: sets active=false. Scoped by (userId, id) so a
  // caller cannot disable another user's honeytoken by guessing the
  // PK uuid. Idempotent: WHERE active = true so re-disabling an
  // already-disabled row returns null. Returns the disabled row's
  // (label, tokenType) so the route layer can audit the disable
  // without a second SELECT. Throws on DB error — like
  // revokeCredential, this is a user-facing security action that
  // MUST surface failure.
  disableHoneytoken(
    userId: string,
    honeytokenId: string,
  ): Promise<HoneytokenDisableResult | null>;
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

  // Atomic sync — all of (lock + version-check + archive previous + write new
  // + prune history) happens inside a single PG transaction so concurrent
  // syncs cannot corrupt either the main row or the history ring buffer.
  //
  // Race scenario this prevents: client A and client B both try to sync.
  //   - A sees existing version 5, decides to write version 6
  //   - B sees existing version 5, decides to write version 6
  // Without locking, both could succeed (race on the CAS) or both could
  // archive the same v5 row (race on the read). With SELECT ... FOR UPDATE,
  // whichever transaction grabs the lock first wins; the loser sees the
  // updated row and aborts cleanly with version_conflict.
  //
  // History side-effects (archive + prune) only run on the success path. A
  // version_conflict short-circuits the transaction with no writes at all,
  // so the main vault is never disturbed by a failed history operation.
  async syncVault(
    userId: string,
    encryptedBlob: string,
    version: number,
  ): Promise<SyncVaultResult> {
    return await db.transaction(async (tx) => {
      // Lock the existing row (if any) so concurrent syncs serialize.
      // FOR UPDATE on a non-existent row is a no-op — the INSERT path below
      // is then protected by the PK uniqueness check.
      const existingRows = await tx
        .select()
        .from(vaultBlobs)
        .where(eq(vaultBlobs.userId, userId))
        .for("update")
        .limit(1);
      const existing = existingRows[0];

      if (existing && existing.version >= version) {
        return {
          ok: false as const,
          code: "version_conflict" as const,
          serverVersion: existing.version,
        };
      }

      // Archive the row we are about to overwrite. First-write case
      // (existing is undefined) creates no history entry, per spec.
      if (existing) {
        await tx.insert(vaultBlobHistory).values({
          userId,
          version: existing.version,
          encryptedBlob: existing.encryptedBlob,
        });
      }

      // Use INSERT ... ON CONFLICT (user_id) DO UPDATE so the write is
      // atomic at the DB level. SELECT FOR UPDATE above cannot lock a
      // non-existent row, so two concurrent first-writes for the same
      // user could both see "no row" and both reach this point. Plain
      // INSERT in that case would surface a unique-constraint violation
      // as a 500. With ON CONFLICT + the version-CAS WHERE clause, the
      // second writer either (a) successfully overwrites the racing
      // insert because its version is higher, or (b) gets an empty
      // RETURNING and is mapped to version_conflict below — never 500.
      const now = Date.now();
      const writtenRows = await tx
        .insert(vaultBlobs)
        .values({ userId, encryptedBlob, version, updatedAt: now })
        .onConflictDoUpdate({
          target: vaultBlobs.userId,
          set: { encryptedBlob, version, updatedAt: now },
          where: sql`${vaultBlobs.version} < ${version}`,
        })
        .returning();

      if (writtenRows.length === 0) {
        // ON CONFLICT fired AND the WHERE blocked the UPDATE — a
        // concurrent inserter already won with version >= ours. Re-read
        // the current row to report the truth back to the client.
        const currentRows = await tx
          .select()
          .from(vaultBlobs)
          .where(eq(vaultBlobs.userId, userId))
          .limit(1);
        return {
          ok: false as const,
          code: "version_conflict" as const,
          serverVersion: currentRows[0]?.version ?? 0,
        };
      }

      await this.pruneHistory(tx, userId);

      // previousVersion captured from the FOR-UPDATE-locked read above so
      // it reflects the state right before this commit, not a racy later
      // re-read. Null on first-ever sync (no prior row to displace).
      return {
        ok: true as const,
        blob: writtenRows[0],
        previousVersion: existing?.version ?? null,
      };
    });
  }

  async getVaultHistory(userId: string): Promise<VaultHistoryEntry[]> {
    const rows = await db
      .select({
        version: vaultBlobHistory.version,
        archivedAt: vaultBlobHistory.archivedAt,
        // octet_length on the TEXT column gives the on-disk byte size of the
        // encrypted blob without transferring the blob itself across the wire
        // (the encrypted blob can be up to 10 MiB, and history endpoints must
        // never return blob contents — see route doc).
        blobSize: sql<number>`octet_length(${vaultBlobHistory.encryptedBlob})`,
      })
      .from(vaultBlobHistory)
      .where(eq(vaultBlobHistory.userId, userId))
      .orderBy(desc(vaultBlobHistory.version))
      .limit(VAULT_HISTORY_LIMIT);

    return rows.map((r) => ({
      version: r.version,
      archivedAt: r.archivedAt,
      // pg returns octet_length as a number for typical TEXT sizes, but
      // coerce defensively in case the driver hands back a string for very
      // large blobs.
      blobSize: typeof r.blobSize === "string" ? Number(r.blobSize) : r.blobSize,
    }));
  }

  // Restore a historical encrypted blob as the new current vault, picking
  // the new version as max(currentVersion, targetVersion) + 1 so that
  //   (a) monotonicity is preserved (no client sees the version go backwards)
  //   (b) restoring "above" the current version is harmless (e.g. if some
  //       weird state means historical version 12 exists but current is 5,
  //       we still write 13, not 6 — never overwrite a higher live version
  //       with a lower one).
  // Like syncVault, this archives the displaced current row first so a
  // restore is itself reversible.
  async restoreVault(
    userId: string,
    targetVersion: number,
  ): Promise<RestoreVaultResult> {
    return await db.transaction(async (tx) => {
      const historyRows = await tx
        .select()
        .from(vaultBlobHistory)
        .where(
          and(
            eq(vaultBlobHistory.userId, userId),
            eq(vaultBlobHistory.version, targetVersion),
          ),
        )
        .limit(1);
      const historyEntry = historyRows[0];
      if (!historyEntry) {
        return { ok: false as const, code: "not_found" as const };
      }

      const existingRows = await tx
        .select()
        .from(vaultBlobs)
        .where(eq(vaultBlobs.userId, userId))
        .for("update")
        .limit(1);
      const existing = existingRows[0];

      const baseVersion = Math.max(existing?.version ?? 0, targetVersion);
      const newVersion = baseVersion + 1;

      if (existing) {
        await tx.insert(vaultBlobHistory).values({
          userId,
          version: existing.version,
          encryptedBlob: existing.encryptedBlob,
        });
      }

      // Same race-safe write pattern as syncVault — see comments there.
      // The "no current vault row" branch is the one at risk because
      // SELECT FOR UPDATE cannot lock a row that doesn't exist; ON CONFLICT
      // with the version-CAS WHERE turns any concurrent insert race into
      // either a successful overwrite (newVersion is higher) or a clean
      // version_conflict (mapped here to retry the restore).
      const now = Date.now();
      const writtenRows = await tx
        .insert(vaultBlobs)
        .values({
          userId,
          encryptedBlob: historyEntry.encryptedBlob,
          version: newVersion,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: vaultBlobs.userId,
          set: {
            encryptedBlob: historyEntry.encryptedBlob,
            version: newVersion,
            updatedAt: now,
          },
          where: sql`${vaultBlobs.version} < ${newVersion}`,
        })
        .returning();

      if (writtenRows.length === 0) {
        // A concurrent writer raced us with a version >= newVersion. The
        // historical entry still exists — only the write was blocked —
        // so we report version_conflict (NOT not_found). The caller can
        // retry the same restore; by then their recomputed newVersion
        // will exceed the racing writer's version and the CAS will pass.
        const currentRows = await tx
          .select()
          .from(vaultBlobs)
          .where(eq(vaultBlobs.userId, userId))
          .limit(1);
        return {
          ok: false as const,
          code: "version_conflict" as const,
          serverVersion: currentRows[0]?.version ?? 0,
        };
      }

      await this.pruneHistory(tx, userId);

      // previousVersion captured from the FOR-UPDATE-locked read above.
      // Null only if there was NO prior current vault row (restoring
      // straight into an empty user state — unusual but possible if the
      // user manually nuked vault_blobs while history survived).
      return {
        ok: true as const,
        blob: writtenRows[0],
        restoredFromVersion: targetVersion,
        previousVersion: existing?.version ?? null,
      };
    });
  }

  // Keep only the latest VAULT_HISTORY_LIMIT entries per user. Uses a
  // self-subquery on (user_id, version) — the subquery is a single index
  // scan thanks to vault_blob_history_user_version_idx. Called inside the
  // sync/restore transactions so pruning shares the same atomicity as the
  // archive insert that preceded it.
  private async pruneHistory(
    tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
    userId: string,
  ): Promise<void> {
    await tx.execute(sql`
      DELETE FROM ${vaultBlobHistory}
      WHERE ${vaultBlobHistory.userId} = ${userId}
        AND ${vaultBlobHistory.id} NOT IN (
          SELECT ${vaultBlobHistory.id}
          FROM ${vaultBlobHistory}
          WHERE ${vaultBlobHistory.userId} = ${userId}
          ORDER BY ${vaultBlobHistory.version} DESC
          LIMIT ${VAULT_HISTORY_LIMIT}
        )
    `);
  }

  // Persist a new session. Caller is responsible for hashing the raw
  // token (we never see it) and for picking expiresAt (typically
  // Date.now() + SESSION_LIFETIME_MS). The unique index on token_hash
  // is the last line of defense against duplicate-token bugs — a
  // 64-byte token collision is astronomically unlikely, but if it ever
  // happens we want a 500 here, not silent overlap.
  async createSession(input: {
    userId: string;
    tokenHash: string;
    expiresAt: number;
    userAgent: string | null;
    ipAddress: string | null;
    deviceFingerprint: string | null;
    trusted: boolean;
  }): Promise<Session> {
    const rows = await db
      .insert(sessions)
      .values({
        userId: input.userId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        userAgent: input.userAgent,
        ipAddress: input.ipAddress,
        deviceFingerprint: input.deviceFingerprint,
        trusted: input.trusted,
      })
      .returning();
    return rows[0];
  }

  // Look up a session by its (already hashed) token, filtering expired
  // rows so the caller cannot accidentally honor a stale token. The
  // composite index on (user_id, expires_at) does NOT cover this lookup
  // (we query by token_hash, which has its own unique index); the
  // expires_at predicate is just a cheap defense-in-depth filter on the
  // single-row result.
  async getActiveSessionByTokenHash(
    tokenHash: string,
  ): Promise<Session | undefined> {
    const now = Date.now();
    const rows = await db
      .select()
      .from(sessions)
      .where(
        and(eq(sessions.tokenHash, tokenHash), gt(sessions.expiresAt, now)),
      )
      .limit(1);
    return rows[0];
  }

  // Update last_seen_at on every authenticated request. This is a single
  // indexed UPDATE by PK — cheap, but it IS a write per request, so any
  // future "optimize for read-heavy" work should consider throttling
  // (e.g. only touch if last_seen_at is more than 60s old).
  async touchSession(id: string, lastSeenAt: number): Promise<void> {
    await db
      .update(sessions)
      .set({ lastSeenAt })
      .where(eq(sessions.id, id));
  }

  // Delete a single session by id. Returns true if a row was actually
  // removed so the route can distinguish "I just logged you out" from
  // "that session was already gone" (though the route currently treats
  // both as 200 — see comments there).
  async deleteSessionById(id: string): Promise<boolean> {
    const rows = await db
      .delete(sessions)
      .where(eq(sessions.id, id))
      .returning({ id: sessions.id });
    return rows.length > 0;
  }

  // Nuke every session for the user. Used by POST /api/auth/logout-all
  // and is the panic-button for "I think my account is compromised".
  // Returns the count of revoked sessions for the response payload.
  async deleteAllSessionsForUser(userId: string): Promise<number> {
    const rows = await db
      .delete(sessions)
      .where(eq(sessions.userId, userId))
      .returning({ id: sessions.id });
    return rows.length;
  }

  // Active (non-expired) sessions for the user. token_hash is NEVER
  // returned — see SessionListItem doc for why. Sorted by lastSeenAt
  // desc so the most recently active device shows up first in the
  // user-facing "where am I logged in?" view.
  async listActiveSessionsForUser(
    userId: string,
  ): Promise<SessionListItem[]> {
    const now = Date.now();
    const rows = await db
      .select({
        id: sessions.id,
        createdAt: sessions.createdAt,
        lastSeenAt: sessions.lastSeenAt,
        expiresAt: sessions.expiresAt,
        userAgent: sessions.userAgent,
        ipAddress: sessions.ipAddress,
        suspicious: sessions.suspicious,
        trusted: sessions.trusted,
      })
      .from(sessions)
      .where(and(eq(sessions.userId, userId), gt(sessions.expiresAt, now)))
      .orderBy(desc(sessions.lastSeenAt));
    // Coerce nullable columns → boolean so the API contract is the
    // narrower SessionListItem shape. Old pre-feature rows where the
    // columns are NULL surface as false to the client (the safe
    // default for both flags).
    return rows.map((r) => ({
      ...r,
      suspicious: r.suspicious === true,
      trusted: r.trusted === true,
    }));
  }

  // See IStorage.hasDeviceFingerprintForUser for the contract. We use
  // a LIMIT 1 SELECT (rather than COUNT) so the planner can short-
  // circuit on the first match — combined with the
  // sessions_user_fingerprint_idx index this is a single index probe.
  async hasDeviceFingerprintForUser(
    userId: string,
    fingerprint: string,
  ): Promise<boolean> {
    const rows = await db
      .select({ id: sessions.id })
      .from(sessions)
      .where(
        and(
          eq(sessions.userId, userId),
          eq(sessions.deviceFingerprint, fingerprint),
        ),
      )
      .limit(1);
    return rows.length > 0;
  }

  // Atomic enable: write encrypted secret AND flip the flag in a
  // single UPDATE so the row is never observed in a half-enabled
  // state. Throws on DB error (unlike the fail-open trust/suspicious
  // helpers) — see IStorage.setTotpEnabled doc for why.
  async setTotpEnabled(
    userId: string,
    encryptedSecret: string,
  ): Promise<void> {
    await db
      .update(users)
      .set({
        totpEnabled: true,
        totpSecretEncrypted: encryptedSecret,
      })
      .where(eq(users.id, userId));
  }

  // Step-up persistence MUST be reliable: returning success when the
  // column was not actually written would leave the user staring at
  // "verified" UI while the very next write 401s on the gate. We
  // catch + log the error (no raw message: same redaction discipline
  // as the other session writers) but return false so the route can
  // surface 500 and the user can retry. The audit row is still the
  // durable record of attempted step-up, but the cache column is
  // load-bearing for the gate to function — fail-closed wins here.
  async markSessionTotpVerified(
    sessionId: string,
    until: number,
  ): Promise<boolean> {
    try {
      await db
        .update(sessions)
        .set({ totpVerifiedUntil: until })
        .where(eq(sessions.id, sessionId));
      return true;
    } catch (err) {
      const errType =
        err instanceof Error ? err.constructor.name : typeof err;
      console.error(
        `markSessionTotpVerified failed for ${sessionId}: ${errType}`,
      );
      return false;
    }
  }

  // Fail-open per IStorage contract — same shape as markSessionSuspicious.
  // We deliberately do not gate on the current value: the UPDATE is
  // idempotent and PG will simply rewrite the row with the same value
  // on a no-op call, which is cheaper than the round-trip + branch.
  async markSessionTrusted(sessionId: string): Promise<void> {
    try {
      await db
        .update(sessions)
        .set({ trusted: true })
        .where(eq(sessions.id, sessionId));
    } catch (err) {
      // Same redaction discipline as markSessionSuspicious: log only
      // the exception type, not the error message (DB drivers can
      // include connection strings or query bodies in error.message).
      const errType =
        err instanceof Error ? err.constructor.name : typeof err;
      console.error(
        `markSessionTrusted swallowed error for ${sessionId}: ${errType}`,
      );
    }
  }

  // Fail-open per IStorage contract: any DB error is logged and
  // swallowed. Callers (the anomaly hook in routes.ts) fire-and-forget
  // this and rely on the guarantee that a transient DB hiccup setting
  // a metadata flag can never break the user's request.
  async markSessionSuspicious(sessionId: string): Promise<void> {
    try {
      await db
        .update(sessions)
        .set({ suspicious: true })
        .where(eq(sessions.id, sessionId));
    } catch (err) {
      // Include sessionId so an operator triaging "why didn't this
      // session get flagged" can correlate. The error itself is
      // intentionally NOT printed — DB drivers can include connection
      // strings or query bodies in error.message that we don't want
      // in plain logs. The exception type alone is enough signal.
      const errType =
        err instanceof Error ? err.constructor.name : typeof err;
      console.error(
        `markSessionSuspicious failed sessionId=${sessionId} errType=${errType}`,
      );
    }
  }

  // Append a single audit row. Hard contract: this method MUST NOT
  // throw — every code path is wrapped in try/catch and errors are
  // logged-only. Callers fire-and-forget (`void storage.logAuditEvent`)
  // and rely on this guarantee so a transient DB hiccup writing audit
  // metadata can never poison a successful API response.
  //
  // Defense-in-depth: we also clamp blob_size_bytes to a sane positive
  // integer range so a buggy caller can't insert NaN/Infinity/negative
  // values that the spec doesn't anticipate. Other numeric fields are
  // already small (versions are bounded by VAULT_HISTORY_LIMIT growth).
  async logAuditEvent(input: AuditEventInput): Promise<void> {
    try {
      await db.insert(vaultAuditLog).values({
        userId: input.userId,
        action: input.action,
        versionBefore: input.versionBefore ?? null,
        versionAfter: input.versionAfter ?? null,
        blobSize:
          typeof input.blobSize === "number" &&
          Number.isFinite(input.blobSize) &&
          input.blobSize >= 0
            ? Math.floor(input.blobSize)
            : null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
      });
    } catch (err) {
      // Log-only. Do NOT rethrow. The action that triggered this audit
      // event has already succeeded (we only log AFTER success per
      // spec) and the user-facing response either has already been
      // sent or is about to be — losing one audit row must never
      // become a 500 to the client.
      console.error("Audit log insert failed");
    }
  }

  // Read latest N audit rows for a user, newest first. The ORDER BY
  // ... DESC LIMIT N is a single index scan thanks to
  // vault_audit_user_created_idx (user_id, created_at desc). The
  // internal `id` column is deliberately excluded from the SELECT —
  // it is never exposed via the API (see AuditLogItem doc).
  async getAuditLog(
    userId: string,
    limit: number = AUDIT_LOG_LIMIT,
  ): Promise<AuditLogItem[]> {
    const rows = await db
      .select({
        action: vaultAuditLog.action,
        createdAt: vaultAuditLog.createdAt,
        ipAddress: vaultAuditLog.ipAddress,
        userAgent: vaultAuditLog.userAgent,
        versionBefore: vaultAuditLog.versionBefore,
        versionAfter: vaultAuditLog.versionAfter,
        blobSize: vaultAuditLog.blobSize,
      })
      .from(vaultAuditLog)
      .where(eq(vaultAuditLog.userId, userId))
      .orderBy(desc(vaultAuditLog.createdAt))
      .limit(limit);
    return rows;
  }

  // ----- WebAuthn / passkeys -----
  //
  // Persist a freshly-verified credential. We deliberately do NOT log
  // the publicKey (or any prefix of it) anywhere — it's the public
  // half of an asymmetric key, but echoing it through stdout would
  // both bloat operator logs and create a precedent we don't want.
  // The credentialId is fine to log if needed for triage; it's already
  // sent over the wire on every assertion.
  async createWebAuthnCredential(
    input: CreateWebAuthnCredentialInput,
  ): Promise<WebauthnCredential> {
    const [row] = await db
      .insert(webauthnCredentials)
      .values({
        userId: input.userId,
        credentialId: input.credentialId,
        publicKey: input.publicKey,
        counter: input.counter,
        deviceName: input.deviceName,
        transports: input.transports,
      })
      .returning();
    return row;
  }

  // Auth-path lookup. Filters revoked = false at the SQL layer so a
  // revoked credential is indistinguishable from a missing one as far
  // as callers are concerned. Index hit is on
  // webauthn_credentials_credential_id_idx (or the unique index for
  // the same column) — single-row fetch.
  async getCredentialById(
    credentialId: string,
  ): Promise<WebauthnCredential | undefined> {
    const [row] = await db
      .select()
      .from(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.credentialId, credentialId),
          eq(webauthnCredentials.revoked, false),
        ),
      )
      .limit(1);
    return row;
  }

  // Management screen reader. Public-safe projection only — public_key
  // and counter are EXCLUDED from the SELECT so a future change that
  // accidentally returns these rows over the API still cannot leak
  // them (defense in depth: the type narrows the shape, the SELECT
  // narrows the bytes that ever leave the DB). Revoked rows are
  // filtered out — a revoked passkey shouldn't appear in the user's
  // "active credentials" list.
  // Index hit: webauthn_credentials_user_idx on (user_id). Sorting
  // by created_at is an in-memory sort over a per-user result set,
  // bounded in practice (a user has on the order of a handful of
  // passkeys, not thousands).
  async listCredentialsForUser(
    userId: string,
  ): Promise<CredentialListItem[]> {
    const rows = await db
      .select({
        id: webauthnCredentials.id,
        credentialId: webauthnCredentials.credentialId,
        deviceName: webauthnCredentials.deviceName,
        transports: webauthnCredentials.transports,
        createdAt: webauthnCredentials.createdAt,
        lastUsedAt: webauthnCredentials.lastUsedAt,
      })
      .from(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.userId, userId),
          eq(webauthnCredentials.revoked, false),
        ),
      )
      .orderBy(desc(webauthnCredentials.createdAt));
    return rows;
  }

  // Critical-path: signCount persistence drives WebAuthn anti-replay.
  // We update counter AND last_used_at in the same UPDATE so a
  // successful assertion advances both atomically. The WHERE clause
  // also requires revoked = false: even if some buggy caller reaches
  // this method without going through getCredentialById first, a
  // revoked row will not have its counter advanced (defense in
  // depth). NOT wrapped in try/catch — see IStorage doc for why this
  // method must surface errors rather than fail-open.
  async updateCredentialCounter(
    credentialId: string,
    counter: number,
  ): Promise<boolean> {
    // T002 hardening: add `counter < newCounter` to the WHERE so two
    // concurrent assertions racing with the SAME verified.newCounter
    // can't both succeed. The first commit advances the row; the
    // second's predicate evaluates false at the DB and updates zero
    // rows. .returning() lets us distinguish "row advanced" (true)
    // from "lost the race / row already at-or-past newCounter / row
    // missing / row revoked" (false). Throwing on DB error is still
    // load-bearing — see IStorage doc — only the conditional-noop
    // case maps to FALSE.
    const updated = await db
      .update(webauthnCredentials)
      .set({ counter, lastUsedAt: Date.now() })
      .where(
        and(
          eq(webauthnCredentials.credentialId, credentialId),
          eq(webauthnCredentials.revoked, false),
          lt(webauthnCredentials.counter, counter),
        ),
      )
      .returning({ id: webauthnCredentials.id });
    return updated.length > 0;
  }

  // Fail-open metadata writer. Mirrors markSessionTrusted's redaction
  // discipline: log only the exception type, never the error message
  // (driver errors can include connection strings or query bodies).
  // Includes the same revoked = false guard as updateCredentialCounter.
  async updateCredentialLastUsed(credentialId: string): Promise<void> {
    try {
      await db
        .update(webauthnCredentials)
        .set({ lastUsedAt: Date.now() })
        .where(
          and(
            eq(webauthnCredentials.credentialId, credentialId),
            eq(webauthnCredentials.revoked, false),
          ),
        );
    } catch (err) {
      const errType =
        err instanceof Error ? err.constructor.name : typeof err;
      console.error(
        `updateCredentialLastUsed swallowed error: ${errType}`,
      );
    }
  }

  // Soft-delete via UPDATE ... WHERE revoked = false. Returning the
  // (id) of any row that was actually flipped lets us distinguish
  // "credential just revoked" from "credential was already revoked
  // or never existed" without a separate SELECT round-trip. Throws
  // on DB error per IStorage doc.
  async revokeCredential(credentialId: string): Promise<boolean> {
    const flipped = await db
      .update(webauthnCredentials)
      .set({ revoked: true })
      .where(
        and(
          eq(webauthnCredentials.credentialId, credentialId),
          eq(webauthnCredentials.revoked, false),
        ),
      )
      .returning({ id: webauthnCredentials.id });
    return flipped.length > 0;
  }

  // ----- Trusted devices (T002) -----
  //
  // INSERT … ON CONFLICT (user_id, device_fingerprint) DO UPDATE
  //   SET last_seen_at = excluded.last_seen_at
  //   RETURNING ..., (xmax = 0) AS created
  //
  // The composite UNIQUE INDEX trusted_devices_user_fingerprint_uidx
  // is the conflict target. ON CONFLICT only updates lastSeenAt — we
  // deliberately leave label and trusted alone so a steady-state ping
  // never silently re-trusts a device the user just revoked, or wipes
  // a user-supplied label.
  //
  // The xmax=0 trick distinguishes inserts from updates without a
  // separate SELECT: in Postgres, a freshly-inserted tuple has
  // xmax=0 (no concurrent xact has tried to update it yet) while an
  // ON CONFLICT update path has xmax = the updating xid. Drizzle's
  // raw sql template surfaces this as a boolean we can type as
  // `created`.
  async createOrUpdateDevice(input: {
    userId: string;
    deviceFingerprint: string;
    now: number;
  }): Promise<DeviceUpsertResult> {
    const rows = await db
      .insert(trustedDevices)
      .values({
        userId: input.userId,
        deviceFingerprint: input.deviceFingerprint,
        trusted: false,
        firstSeenAt: input.now,
        lastSeenAt: input.now,
      })
      .onConflictDoUpdate({
        target: [trustedDevices.userId, trustedDevices.deviceFingerprint],
        set: { lastSeenAt: input.now },
      })
      .returning({
        deviceFingerprint: trustedDevices.deviceFingerprint,
        label: trustedDevices.label,
        trusted: trustedDevices.trusted,
        firstSeenAt: trustedDevices.firstSeenAt,
        lastSeenAt: trustedDevices.lastSeenAt,
        created: sql<boolean>`(xmax = 0)`,
      });
    const row = rows[0];
    if (!row) {
      // RETURNING from an INSERT … ON CONFLICT DO UPDATE always yields
      // exactly one row in Postgres. Defensive throw so a future driver
      // change can't silently produce an undefined return.
      throw new Error("createOrUpdateDevice: empty RETURNING");
    }
    return {
      created: row.created === true,
      row: {
        fingerprint: row.deviceFingerprint,
        label: row.label,
        trusted: row.trusted,
        firstSeenAt: row.firstSeenAt,
        lastSeenAt: row.lastSeenAt,
      },
    };
  }

  async getDevicesForUser(userId: string): Promise<DeviceListItem[]> {
    const rows = await db
      .select({
        deviceFingerprint: trustedDevices.deviceFingerprint,
        label: trustedDevices.label,
        trusted: trustedDevices.trusted,
        firstSeenAt: trustedDevices.firstSeenAt,
        lastSeenAt: trustedDevices.lastSeenAt,
      })
      .from(trustedDevices)
      .where(eq(trustedDevices.userId, userId))
      .orderBy(desc(trustedDevices.lastSeenAt));
    return rows.map((r) => ({
      fingerprint: r.deviceFingerprint,
      label: r.label,
      trusted: r.trusted,
      firstSeenAt: r.firstSeenAt,
      lastSeenAt: r.lastSeenAt,
    }));
  }

  async markDeviceTrusted(
    userId: string,
    deviceFingerprint: string,
  ): Promise<boolean> {
    // Idempotent: WHERE trusted = false so a re-call on an already-
    // trusted device returns false (no DB write, no audit-worthy
    // change). Scoped strictly by userId so guessing another user's
    // fingerprint can't elevate trust on their device.
    const flipped = await db
      .update(trustedDevices)
      .set({ trusted: true })
      .where(
        and(
          eq(trustedDevices.userId, userId),
          eq(trustedDevices.deviceFingerprint, deviceFingerprint),
          eq(trustedDevices.trusted, false),
        ),
      )
      .returning({ id: trustedDevices.id });
    return flipped.length > 0;
  }

  async revokeDeviceTrust(
    userId: string,
    deviceFingerprint: string,
  ): Promise<boolean> {
    const flipped = await db
      .update(trustedDevices)
      .set({ trusted: false })
      .where(
        and(
          eq(trustedDevices.userId, userId),
          eq(trustedDevices.deviceFingerprint, deviceFingerprint),
          eq(trustedDevices.trusted, true),
        ),
      )
      .returning({ id: trustedDevices.id });
    return flipped.length > 0;
  }

  async relabelDevice(
    userId: string,
    deviceFingerprint: string,
    label: string,
  ): Promise<boolean> {
    const flipped = await db
      .update(trustedDevices)
      .set({ label })
      .where(
        and(
          eq(trustedDevices.userId, userId),
          eq(trustedDevices.deviceFingerprint, deviceFingerprint),
        ),
      )
      .returning({ id: trustedDevices.id });
    return flipped.length > 0;
  }

  // ----- Honeytokens (deception layer) -----
  //
  // INSERT … RETURNING (public projection — markerHash is NEVER returned).
  // The composite UNIQUE index honeytokens_user_marker_uidx is the conflict
  // surface; on violation the driver throws with code "23505" which we
  // detect and re-throw as HoneytokenMarkerConflictError so the route layer
  // can map it to a 409. Other DB errors propagate as-is per the IStorage
  // contract — the route layer wraps in try/catch and returns 500.
  async createHoneytoken(input: {
    userId: string;
    label: string;
    tokenType: string;
    markerHash: string;
  }): Promise<HoneytokenListItem> {
    try {
      const [row] = await db
        .insert(honeytokens)
        .values({
          userId: input.userId,
          label: input.label,
          tokenType: input.tokenType,
          markerHash: input.markerHash,
        })
        .returning({
          id: honeytokens.id,
          label: honeytokens.label,
          tokenType: honeytokens.tokenType,
          active: honeytokens.active,
          createdAt: honeytokens.createdAt,
          triggeredAt: honeytokens.triggeredAt,
          triggerCount: honeytokens.triggerCount,
        });
      if (!row) {
        // Defensive — INSERT … RETURNING on a non-conflict path always
        // yields exactly one row. A future driver change that surfaced
        // an empty array shouldn't pass off as a silent success.
        throw new Error("createHoneytoken: empty RETURNING");
      }
      return row;
    } catch (err) {
      // node-postgres / @neondatabase/serverless surface unique-violation
      // as `code === "23505"` on the error object. We do a structural
      // check rather than instanceof so the detection works regardless of
      // which driver layer wrapped the original DatabaseError. Any other
      // shape is re-thrown unchanged so the route layer's catch sees the
      // original.
      if (
        err !== null &&
        typeof err === "object" &&
        "code" in err &&
        (err as { code?: unknown }).code === "23505"
      ) {
        throw new HoneytokenMarkerConflictError();
      }
      throw err;
    }
  }

  // Management screen reader. PUBLIC PROJECTION ONLY — marker_hash is
  // EXCLUDED from the SELECT so a future change that accidentally returns
  // these rows over the API still cannot leak the irreversible hash.
  // Same defense-in-depth pattern as listCredentialsForUser. Index hit:
  // honeytokens_user_idx on (user_id). Sorting by created_at is an
  // in-memory sort over a per-user result set, bounded in practice (a
  // user has at most a handful of decoys, not thousands).
  async listHoneytokens(userId: string): Promise<HoneytokenListItem[]> {
    const rows = await db
      .select({
        id: honeytokens.id,
        label: honeytokens.label,
        tokenType: honeytokens.tokenType,
        active: honeytokens.active,
        createdAt: honeytokens.createdAt,
        triggeredAt: honeytokens.triggeredAt,
        triggerCount: honeytokens.triggerCount,
      })
      .from(honeytokens)
      .where(eq(honeytokens.userId, userId))
      .orderBy(desc(honeytokens.createdAt));
    return rows;
  }

  // Atomic increment-and-stamp. The single UPDATE … SET trigger_count =
  // trigger_count + 1 + RETURNING avoids a read-modify-write race on
  // concurrent triggers — Postgres serializes the row update, both
  // callers see distinct post-update values. WHERE clause requires
  // active = true so a disabled honeytoken is treated as not-found
  // (preventing escalation from a stale client cache). Scoped strictly
  // by userId so an attacker who somehow guessed a marker hash for
  // another user gets null. Throws on DB error — the caller relies on
  // this method to fail loudly so a probing attacker cannot evade
  // detection by triggering a transient DB outage.
  async triggerHoneytoken(
    userId: string,
    markerHash: string,
  ): Promise<HoneytokenTriggerResult | null> {
    const now = Date.now();
    const updated = await db
      .update(honeytokens)
      .set({
        triggerCount: sql`${honeytokens.triggerCount} + 1`,
        triggeredAt: now,
      })
      .where(
        and(
          eq(honeytokens.userId, userId),
          eq(honeytokens.markerHash, markerHash),
          eq(honeytokens.active, true),
        ),
      )
      .returning({
        id: honeytokens.id,
        label: honeytokens.label,
        tokenType: honeytokens.tokenType,
        triggerCount: honeytokens.triggerCount,
      });
    const row = updated[0];
    if (!row) return null;
    return {
      honeytokenId: row.id,
      label: row.label,
      tokenType: row.tokenType,
      triggerCount: row.triggerCount,
    };
  }

  // Soft-disable via UPDATE … WHERE active = true. Returning the
  // (label, tokenType) of any row that was actually flipped lets the
  // caller distinguish "honeytoken just disabled" (audit-worthy) from
  // "already disabled or wrong owner" (no audit) without a separate
  // SELECT. Scoped by (userId, id) so guessing another user's PK uuid
  // can't disable their honeytoken. Throws on DB error per IStorage
  // contract.
  async disableHoneytoken(
    userId: string,
    honeytokenId: string,
  ): Promise<HoneytokenDisableResult | null> {
    const flipped = await db
      .update(honeytokens)
      .set({ active: false })
      .where(
        and(
          eq(honeytokens.id, honeytokenId),
          eq(honeytokens.userId, userId),
          eq(honeytokens.active, true),
        ),
      )
      .returning({
        label: honeytokens.label,
        tokenType: honeytokens.tokenType,
      });
    const row = flipped[0];
    if (!row) return null;
    return { label: row.label, tokenType: row.tokenType };
  }
}
