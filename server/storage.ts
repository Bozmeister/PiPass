import { and, desc, eq, gt, sql } from "drizzle-orm";
import { db } from "./db";
import {
  users,
  vaultBlobs,
  vaultBlobHistory,
  sessions,
  type User,
  type VaultBlob,
  type Session,
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

export type SyncVaultResult =
  | { ok: true; blob: VaultBlob }
  | { ok: false; code: "version_conflict"; serverVersion: number };

export type RestoreVaultResult =
  | { ok: true; blob: VaultBlob; restoredFromVersion: number }
  | { ok: false; code: "not_found" }
  | { ok: false; code: "version_conflict"; serverVersion: number };

// Public shape for GET /api/auth/sessions. The token_hash column is
// deliberately omitted — it would let a DB-leak attacker invert the hash
// table to identify "this user was active across these N devices". Only
// non-sensitive metadata flows out: id, timestamps, user-agent, ip.
export type SessionListItem = {
  id: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  userAgent: string | null;
  ipAddress: string | null;
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
  }): Promise<Session>;
  getActiveSessionByTokenHash(tokenHash: string): Promise<Session | undefined>;
  touchSession(id: string, lastSeenAt: number): Promise<void>;
  deleteSessionById(id: string): Promise<boolean>;
  deleteAllSessionsForUser(userId: string): Promise<number>;
  listActiveSessionsForUser(userId: string): Promise<SessionListItem[]>;
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

      return { ok: true as const, blob: writtenRows[0] };
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

      return {
        ok: true as const,
        blob: writtenRows[0],
        restoredFromVersion: targetVersion,
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
  }): Promise<Session> {
    const rows = await db
      .insert(sessions)
      .values({
        userId: input.userId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        userAgent: input.userAgent,
        ipAddress: input.ipAddress,
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
      })
      .from(sessions)
      .where(and(eq(sessions.userId, userId), gt(sessions.expiresAt, now)))
      .orderBy(desc(sessions.lastSeenAt));
    return rows;
  }
}
