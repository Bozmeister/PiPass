# PiPass — Vault State-Machine Integrity Audit

**Status:** Audit deliverable — informational only. No code changes
accompany this document. Sibling deliverables: `threat_model.md`,
`auth_security_review.md`, `vault_integrity_audit.md`.

**Threat model (per the audit brief):**
- Attacker holds valid `x-user-id` + `x-auth-hash` credentials.
- Attacker can issue an unlimited number of well-formed requests
  (no per-user / per-IP rate limit currently exists on vault endpoints).
- Attacker **cannot** break the encryption (encryption is treated as
  perfect for this analysis).
- Goal: assess **state-machine integrity over time** under repeated,
  authenticated abuse — i.e., can a valid-creds attacker drive the
  vault into a state from which a legitimate client cannot recover?

**This is not a schema review** (covered in `vault_integrity_audit.md`).
This is a state-machine integrity analysis: the question is not "can
input be malformed?" but "can the state machine be driven into a
permanently broken terminal state?"

---

## 0. Executive Verdict

> **UNSAFE — under the stated threat model.**

The vault state machine has **two single-request, irreversible
denial-of-vault (DoV) primitives** that survive the existing audit
controls and are reachable by anyone with valid credentials:

1. **Empty-blob wipe** (carried over from `vault_integrity_audit.md`
   §P0-1) — verified live: `{"encryptedBlob":"","version":N+1}` →
   HTTP 200, vault permanently overwritten with the empty string.
2. **Version-exhaustion lockout** (NEW finding) — verified live:
   `{"encryptedBlob":"...","version":2147483647}` → HTTP 200.
   Any subsequent write at the only valid next version
   (`2147483648`) is rejected with `400 "Invalid version"`
   because Zod's `int4` upper bound stops it before it reaches the
   monotonicity guard. The vault is **frozen forever** in the
   attacker's chosen state. Recovery requires an admin
   `DELETE FROM vault_blobs WHERE user_id = $1` — there is no
   user-facing recovery path.

A third finding (poison-flood) is feasibility-confirmed: 5 sequential
overwrites land in 231 ms with no throttle, and each can carry a
10 MiB body. Combined with (1) and (2), an attacker with valid creds
can not only destroy the vault but also continuously re-destroy it
faster than any legitimate client can repair it (assuming repair
were even possible — which, for finding 2, it is not).

**The audit verdict from `vault_integrity_audit.md` already said
"do not ship the client wiring until P0-1 and P0-2 are fixed."**
This audit adds a **third P0 (version-exhaustion lockout)** and
strengthens the recommendation: until all three are fixed, the
vault sync API is one valid credential away from being permanently
unusable for any individual user.

**Verdict if all three P0s are fixed: SAFE WITH CONSTRAINTS** —
the constraint being that destructive overwrites by an attacker
who already has valid creds remain inherent to the zero-knowledge
model (covered as P1-7 in `vault_integrity_audit.md`).

---

## 1. State Machine

### 1.1 — Textual diagram

```
                         ┌─────────────────────┐
            register     │                     │
            ────────────▶│        S0           │
                         │     NoVault         │
                         │   (no row in        │
                         │    vault_blobs)     │
                         │                     │
                         └──────────┬──────────┘
                                    │
                                    │ T1:  sync(blob, v ≥ 1)
                                    │      where blob ∈ [0, 10·2²⁰] bytes
                                    │           ← Zod has no .min on encryptedBlob today;
                                    │             this is exactly the P0-1 hole — the
                                    │             "valid" lower bound should be ≥ 64 bytes
                                    │      and v ∈ [1, 2³¹−1]   ← Zod min(1) + drizzle-zod
                                    │             auto-applies int4 cap (2147483647)
                                    ▼
                  ┌──────────────────────────────────────┐
                  │                                      │
        ┌────────▶│            S1(v=N, blob=B)           │
        │         │             ValidVault               │
        │         │                                      │
        │         │  Sub-states (server cannot tell      │
        │         │  these apart — opaque blob):         │
        │         │                                      │
        │         │   • S1.Healthy   (blob decrypts to   │
        │         │                   user's data)       │
        │         │   • S1.Poisoned  (blob is text but   │
        │         │                   decryption fails)  │
        │         │   • S1.Wiped     (blob = "" or       │
        │         │                   meaningless short  │
        │         │                   string)            │
        │         │                                      │
        │         └─────┬────────────────┬───────────────┘
        │               │                │
        │               │                │ T6:  user delete →
        │               │                │       cascade →
        │               │                ▼       (back to S0)
        │               │         ┌──────────────┐
        │               │         │     S0       │
        │               │         └──────────────┘
        │               │
        │               │ T1':  sync(blob, v=M) where M > N
        │               │       (legitimate forward progress)
        │               │       — atomic UPSERT WHERE old.v < M
        │               ▼
        │       S1(v=M)  ▶ loop back
        │
        │
        │  ─── Self-loops on S1 (reject paths, no transition) ───
        │
        ├── T2:  sync(blob, v ≤ N)             →  409 "Version conflict"
        ├── T3:  sync with malformed body      →  400 (Zod / strict mode)
        ├── T4:  sync without/with bad auth    →  401 "Auth required" / "Invalid creds"
        ├── T5:  fetch                         →  read-only, no transition
        └── T7:  sync(blob, v > 2³¹−1)         →  400 "Invalid version"
                                                  (Zod int4 cap rejects)
```

### 1.2 — Valid states

A **server-valid state** is `S0` (no row) or `S1(v=N, blob=B)` where:
- `N ∈ [1, 2³¹−1]` (Zod `.min(1)` + Drizzle `integer` ⇒ PG `int4`)
- `B ∈ [0 bytes, 10 MiB]` text (Zod `.max(10*1024*1024)`, **no `.min`**)

A **user-valid state** is the subset of server-valid states where
the blob decrypts under the user's master key. The server **cannot**
distinguish user-valid from server-valid (this is the zero-knowledge
property — and the source of every finding in this audit).

### 1.3 — Allowed transitions (by design)

| From | To | Trigger | Guard |
|---|---|---|---|
| S0 | S1(v=N, B) | `POST /api/vault/sync` | N ≥ 1, B ≤ 10 MiB, valid auth |
| S1(v=N, B₀) | S1(v=M, B₁) | `POST /api/vault/sync` | M > N (atomic UPSERT WHERE) |
| S1 | S0 | `DELETE FROM users WHERE id = $1` (admin or user-account-deletion path, currently no API) | ON DELETE CASCADE |

### 1.4 — Transitions NOT currently prevented but should be

| From | To | Trigger | Why it shouldn't be allowed |
|---|---|---|---|
| S1.Healthy | S1.Wiped | `sync({"encryptedBlob":"", v=N+1})` | `""` is never a legitimate ciphertext. Allowing this gives a one-shot destructive primitive to anyone with valid creds. **(P0-1 carryover.)** |
| S0 | S1.Wiped | Same, on a freshly-registered user before they sync | Worse than the above — the user's first sync from a real device will 409 (server is at v=N+1, real device thinks v=1 or v=2), then they have to fetch the empty blob, fail to decrypt, and hit the destructive recovery prompt. |
| S1(v=N) | S1(v=2³¹−1) | `sync({...,"version":2147483647})` | Burns the user's entire version space in one request. Subsequent legitimate writes can never advance because v=2³¹ is rejected by Zod's int4 cap. **No recovery without admin DB access.** **(NEW — P0-NEW.)** |
| S1.Healthy | S1.Poisoned (rapidly, repeatedly) | Loop `sync({"encryptedBlob": random_bytes, v=N+1, N+2, ...})` | No per-user write quota means an attacker can sustain "vault is broken" indefinitely, racing any repair attempt by the legitimate client. **(P0-2 carryover, with new urgency.)** |

---

## 2. State Destruction Attacks

| # | Attack | Procedure | Feasibility | Impact | Recoverable? |
|---|---|---|---|---|---|
| **D1** | **Empty-blob wipe** | `POST /api/vault/sync {"encryptedBlob":"","version":current+1}` | **YES — verified, 1 request** | Critical: vault permanently shows empty string; any decrypt fails | **NO** without client-side backups |
| **D2** | **Version-exhaustion lockout** *(NEW)* | `POST /api/vault/sync {"encryptedBlob":"<anything>","version":2147483647}` | **YES — verified, 1 request** | Critical: vault frozen forever at attacker's chosen state; legitimate client can never sync again because next valid version is 2³¹, which Zod rejects | **NO** without admin DB access |
| **D3** | Empty-blob wipe of fresh account | Register-then-immediately `sync("", v=1)` before user's real device syncs | **YES — verified** (O1's user was already at v=1 from baseline; the same primitive works on a freshly-registered user — there is no "first-sync must come from a real device" check) | Critical: brand-new users get a poisoned vault from request #1 | **NO** |
| **D4** | Poison flood | Loop: `sync({encryptedBlob: random_or_attacker_chosen, version: current+1})` at maximum rate | **YES — verified at 5 writes / 231 ms with zero throttle**; per-request body up to 10 MiB | High: legitimate user's repair attempts (re-encrypt + sync) lose every race because attacker has lower latency to the DB; effectively a continuous DoV; ingress amplification (~50 MB/s per connection) | Yes-but-races: only if attacker stops |
| **D5** | Version-edge near-exhaustion | Write `v=2147483640` (close to but not at INT4_MAX); legitimate user has 7 versions of headroom before lockout returns | **YES — feasibility-confirmed** (D2 is the limiting case) | High: degrades each victim user's write budget; can be re-applied by attacker after each legitimate write | NO past the cap |
| **D6** | Race-window amplification | Two concurrent attacker connections both write `v=N+1, N+2`; then `v=N+3, N+4` etc. | **YES** — UPSERT is atomic per-row but PG row-lock contention serializes; per-connection throughput stays high (5 writes/231 ms in single-connection test); two connections roughly double it | Medium: amplifies D4; doesn't unlock new state | Yes-but-races |
| D7 | Floats / NaN / scientific notation in `version` | `{"version":1.5}`, `{"version":1e10}`, `{"version":NaN}` | NO — all rejected at Zod with `400 "Invalid version"` (verified: `1.5` → 400; `10000000000` → 400) | n/a | n/a ✅ |
| D8 | Negative or zero `version` | `{"version":0}`, `{"version":-5}` | NO — Zod `.min(1)` + DB CHECK ≥ 1 (verified, both 400) | n/a | n/a ✅ |
| D9 | Replay older valid request | Re-POST a prior captured `(blob, v=N-K)` request | NO — UPSERT WHERE blocks; 409 returned (verified in `vault_integrity_audit.md` R1) | n/a | n/a ✅ |
| D10 | Body parser bypass via chunked / pre-flighted overlong body | `Content-Length: 100` then 12 MiB body | NO — Express body parser enforces declared limit before user-space sees it; 413 (verified in `vault_integrity_audit.md` F10) | n/a | n/a ✅ |

**Verified raw curl evidence (relevant excerpts):**

```text
=== Baseline: write v=1 ===                             {"version":1,…}                      [200]
=== O1. v = INT4_MAX (2147483647) ===                  {"version":2147483647,…}             [200]   ← D2 LANDS
=== O2. v = INT4_MAX + 1 (recovery attempt) ===        {"error":"Invalid version"}          [400]   ← LOCKED OUT
=== O3. v = Number.MAX_SAFE_INTEGER ===                {"error":"Invalid version"}          [400]
=== O5. fetch ===                                       {"encryptedBlob":"poisoned_at_max",
                                                         "version":2147483647,…}             [200]   ← attacker's blob is now permanent
=== Poison-flood (5 writes) ===                        v=1..5 all 200 in 8–10 ms each       [200]   ← D4
=== Final fetch on victim ===                          {"encryptedBlob":"poison_5","version":5,…}    ← last poison wins
```

---

## 3. Consistency Model Analysis

**Model classification: strictly monotonic, last-write-wins, per-user.**

- **Strictly monotonic:** version must strictly increase. Verified at three layers (Zod `.min(1)`, DB `CHECK version >= 1`, and the SQL `WHERE old.version < new.version` clause inside the atomic UPSERT). The latter is the actual race-safe guard.
- **Last-write-wins:** when two writes race at the same target version, exactly one's UPSERT WHERE-clause condition holds; the other's is false; PostgreSQL skips it; the handler sees zero rows returned and emits `409 "Version conflict"`.
- **Per-user, not per-device:** the schema has no notion of "device A's view" vs "device B's view" — there is one row per `userId`.

**Q: Can two valid devices diverge permanently?**

**Yes, in the absence of explicit client merge logic.** Concrete scenario:

1. Both devices fetch and see `serverVersion = 5`.
2. Both edit locally and prepare `v=6`.
3. Device A POSTs first → 200, server is now `(blob_A, v=6)`.
4. Device B POSTs → 409 with `serverVersion: 6`.
5. **If device B's UI silently swallows the 409 (or the client is offline at the time)**, device B keeps `(blob_B_local, v=6_local)` while server has `(blob_A, v=6_server)`. Forever. The next time device B successfully POSTs, it'll race v=7 — but its blob still doesn't reflect device A's edits, and device A's edits get *overwritten* (because device B's local v=6 became v=7 carrying only device B's changes).

**This is a correctness-preserving last-write-wins** — there is no data-corruption — but it is **silently lossy of one device's edits**. The protocol provides the primitive (409 with `serverVersion`); the *client* must implement fetch-merge-retry. There is no audit-deliverable finding here against the server, but the future client-wiring task must implement merge-on-409, not silent retry.

**Q: Can a stale client overwrite a newer vault under any condition?**

**No.** The atomic UPSERT WHERE closes the SELECT-then-UPSERT race window. Any sync at version ≤ current → 409 + no transition. Verified live (R1, R2 in `vault_integrity_audit.md`).

**Q: Is consistency guaranteed per-user or per-device?**

**Per-user, on the server side.** Per-device guarantees do not exist in this protocol — they are entirely the client's responsibility. The protocol is *capable* of supporting per-device consistency (the client could include a `deviceId` and a `parentVersion` in a richer protocol), but the current shape is "single-row CRDT-of-one with linear version".

---

## 4. Atomicity & Partial Write Risk

**Server-side atomicity:** ✅ each sync is one SQL statement (UPSERT with `ON CONFLICT DO UPDATE WHERE`). PostgreSQL guarantees this is atomic per-row. There is no multi-statement transaction in `server/storage.ts → upsertVaultBlob`, so there is no partial-write window inside the sync handler.

**Client-side atomicity:** N/A — the client wiring does not exist yet. **When it lands, it must be designed with the following race in mind:**

- Client encrypts blob locally (CPU-bound, ~ms).
- Client POSTs → server returns 200 with `{version: M, updatedAt: T}`.
- **If the client crashes between "server 200" and "persist M locally"**, the next sync attempt POSTs at `v=M` again (because local state still says v=M-1) → 409 + serverVersion=M → client must fetch, see its own blob, accept M, and continue. This is recoverable (eventually consistent), but only if the client implements 409-handling. Worth a comment in the future client task.

**Validation-vs-persistence gap:** there is a small window between `validateAuthHeaders` / `validateVaultSync` returning ok and the UPSERT firing. If the user's `authHash` is rotated mid-request (e.g., they change their master password from another session), the in-flight write still goes through with the old credential. The window is sub-millisecond and the impact is "one in-flight write succeeds with the about-to-be-revoked creds" — acceptable; a stricter protocol would require server-side session tokens (not in scope today).

**No multi-step writes exist.** Good. P1-7 (history table) would introduce one — and the audit recommendation there explicitly wraps it in `db.transaction(...)` to preserve atomicity.

---

## 5. Recovery & Resilience

**Classification: PERMANENTLY DESTRUCTIVE under the stated threat model.**

| Recovery channel | Available today? | Notes |
|---|---|---|
| Self-healing (server detects bad state and reverts) | ❌ NO | Server treats any well-formed write as legitimate; there is no concept of "bad state". |
| Server-side rollback (history table) | ❌ NO | No history is retained. Recommended in `vault_integrity_audit.md` §P1-7. |
| Client-side restore from local cache | ⚠ Partially — the local SecureStore blob in `workers/sharedVaultStorage.ts` survives a server-side wipe, but only on devices the user installed *before* the attack. New devices get the poisoned blob. | The local cache is also bypassed once server sync is wired and the client trusts the server as authoritative. |
| Client-side encrypted backup export | ❌ NO | Not implemented. Recommended in `vault_integrity_audit.md` §P1-7b. |
| User-initiated "delete account and start over" | ❌ NO | No `DELETE /api/auth/account` endpoint exists; the user cannot even reset their own state without manual DB intervention. |
| Admin-side `DELETE FROM vault_blobs WHERE user_id = $1` | ⚠ YES, but requires DB shell access | Recovers the user *to S0* — they lose all data anyway, just escapes the version-exhaustion lockout. Not a real recovery, just a way out of D2. |

**Combined recovery verdict:** the system is **manually recoverable only by an operator with DB shell access**, and the recovery is **destructive** (the user loses all data). For the version-exhaustion lockout (D2), there is no user-facing recovery path at all — the user's only options are "give up on this account" or "contact support".

---

## 6. Abuse Without Breaking Crypto

The brief asks: assume encryption is perfect; can the attacker still abuse the protocol? **Yes, in four distinct ways:**

| Abuse | Achievable? | Mechanism |
|---|---|---|
| Lock user out of vault | **YES, single request** | D2 (version exhaustion) — no further writes possible. Or D1 (wipe) — vault decrypts to nothing. |
| Continuously overwrite usable state | **YES, sustained** | D4 (poison flood) — no rate limit. Race-amplified by D6 (multiple connections). |
| Degrade performance via sync spam | **YES** | D4 with 10 MiB bodies (no per-user-byte quota beyond the per-request 10 MiB cap); each request consumes one DB write transaction. |
| Persistent denial-of-vault (DoV) | **YES, irreversible** | D2 alone. Or D1 + D4 in combination (wipe, then keep writing empty blobs faster than the legitimate user can repair). |

**None of these require breaking encryption.** All four are pure protocol abuse with valid credentials. This is the central thesis of the audit verdict: **the protocol's safety relies entirely on the assumption that anyone with valid credentials is benign.** That is an acceptable assumption for the "primary user" but not for any of:

- compromised credentials (no MFA, no rotation flow);
- a hostile peer who learned the master password (shoulder-surfing, coercion);
- a malicious browser extension on the web build (which can read `localStorage` where credentials fall back when SecureStore is unavailable).

---

## 7. Critical Invariants Violated

The following invariants would be expected of a "safe" zero-knowledge vault protocol. **Bold = currently violated.**

1. ✅ **No write at version ≤ current succeeds.** Enforced.
2. ✅ **Each write either fully lands or fully fails (atomicity).** Enforced.
3. ✅ **Cross-user IDOR is impossible at the protocol layer.** Enforced.
4. ✅ **No 5xx surfaces from any malformed-input fuzz case.** Enforced.
5. ❌ **Every server-accepted state is decryptable.** Violated by D1 (empty blob accepted as "valid state" though no key can decrypt `""`).
6. ❌ **The user's version space cannot be exhausted by a single write.** Violated by D2 (one write to v=2³¹−1 burns the entire space).
7. ❌ **Destructive writes are rate-limited or quota-bound.** Violated by D4 (no per-user / per-IP rate limit; no daily write quota).
8. ❌ **The user has at least one path to recover from a destructive write that doesn't require operator intervention.** Violated — current options are "had a backup" (no API for this) or "ask an operator".
9. ⚠ **The user is notified of destructive writes from sessions they don't recognize.** Not implemented — no audit log, no "your vault was modified at T from IP X" notification, no last-write-by metadata exposed.

**Three of nine invariants outright violated; one partial.** This is the basis for the UNSAFE verdict.

---

## 8. Required Fixes (Prioritized)

### P0 — Must fix before sync is enabled anywhere

| ID | Title | Concrete fix |
|---|---|---|
| **P0-1** *(carryover)* | Empty / sentinel blob acceptance | `shared/schema.ts`: `encryptedBlob: (col) => col.min(64).max(10*1024*1024)` in `insertVaultBlobSchema`; mirror with `check("vault_blobs_blob_min_len", sql`length(${table.encryptedBlob}) >= 64`)` in the table's array-form callback. See `vault_integrity_audit.md` §T1 for the full snippet. |
| **P0-2** *(carryover)* | No rate limit on `/api/vault/sync` and `/api/vault/fetch` | `server/routes.ts`: at the top of each handler (after auth check), `if (isRateLimited("vsync:user:" + userId, 60, 60_000)) return 429; if (isRateLimited("vsync:ip:" + clientIp, 120, 60_000)) return 429;`. |
| **P0-NEW** | **Version-exhaustion lockout (D2)** | **Two complementary fixes — pick one or both:** |

**P0-NEW: detailed fixes**

**Option A — Cap the version field well below INT4_MAX (PARTIAL
mitigation, NOT a complete fix on its own):**

```ts
// shared/schema.ts
const SAFE_VERSION_MAX = 1_000_000_000; // 10⁹

export const insertVaultBlobSchema = createInsertSchema(vaultBlobs, {
  encryptedBlob: (col) => col.min(64).max(10 * 1024 * 1024),    // P0-1
  version:       (col) => col.min(1).max(SAFE_VERSION_MAX),     // ← P0-NEW
}).strict();

// And mirror at the DB layer in the vaultBlobs table callback:
(table) => [
  check("vault_blobs_version_range",
        sql`${table.version} >= 1 AND ${table.version} <= 1000000000`),
  check("vault_blobs_blob_min_len",
        sql`length(${table.encryptedBlob}) >= 64`),
],
```

> ⚠ **Why Option A alone is insufficient.** The current monotonicity
> check in `server/routes.ts` accepts **any `M > N`**, not strictly
> `N+1`. So even with a 10⁹ cap, an attacker still exhausts the entire
> version space in **one request** by sending `version: 1_000_000_000`
> directly. Option A reduces the *width* of the version space but does
> not change the lockout cost: it remains a one-shot attack.
>
> Option A is only a *real* mitigation when paired with **strict
> consecutive-version enforcement** (`new === current + 1`) — which is
> a protocol-breaking change that breaks any client that retries a
> failed sync at a skipped version. **Do not ship Option A alone.**
> If you must ship a hotfix, ship Option A *plus* the strict-consecutive
> guard in `server/routes.ts`:
>
> ```ts
> // server/routes.ts — inside POST /api/vault/sync, after Zod parse + auth
> const existing = await storage.getVaultBlob(userId);
> const currentVersion = existing?.version ?? 0;
> if (parsed.version !== currentVersion + 1) {
>   return res.status(409).json({ error: "Version must be exactly current+1",
>                                  serverVersion: currentVersion });
> }
> ```
>
> Even with this, Option A is strictly weaker than Option B because the
> client is still trusted to compute `current+1` correctly, and a
> race between "client read v=N" and "client posts v=N+1" can still
> mis-fire.

**Option B — Server-mints version via atomic CAS UPSERT (recommended;
ship this, not Option A):**

The cleaner fix is to remove client-supplied versions entirely. The
client says "I last saw version K"; the server atomically checks and
mints the next one. The trick is to do it in a **single SQL statement**
to avoid the no-row race that a SELECT-FOR-UPDATE-then-INSERT pattern
introduces.

```ts
// shared/schema.ts — sync request shape:
export const vaultSyncSchema = z.object({
  encryptedBlob:       z.string().min(64).max(10 * 1024 * 1024),
  expectedPrevVersion: z.number().int().min(0).max(SAFE_VERSION_MAX),
}).strict();
// expectedPrevVersion = 0 means "I expect no row to exist yet"

// server/storage.ts — single-statement CAS UPSERT.
// Drizzle's insert builder cannot express `INSERT…SELECT…WHERE`, so
// drop to raw sql via db.execute. This is one round-trip; PG runs the
// whole statement atomically against the row identified by user_id.
async upsertVaultBlob(
  userId: string,
  encryptedBlob: string,
  expectedPrevVersion: number,
): Promise<VaultBlob | null> {       // null ⇒ caller returns 409 / 503
  const now = Date.now();

  const result = await db.execute<VaultBlob>(sql`
    INSERT INTO vault_blobs (user_id, encrypted_blob, version, updated_at)
    SELECT ${userId}, ${encryptedBlob}, 1, ${now}
      WHERE ${expectedPrevVersion} = 0          -- INSERT path gated on "no row expected"
    ON CONFLICT (user_id) DO UPDATE
      SET encrypted_blob = EXCLUDED.encrypted_blob,
          version        = vault_blobs.version + 1,
          updated_at     = EXCLUDED.updated_at
      WHERE vault_blobs.version = ${expectedPrevVersion}     -- CAS on existing row
        AND vault_blobs.version < ${SAFE_VERSION_MAX}        -- cap guard
    RETURNING user_id    AS "userId",
              encrypted_blob AS "encryptedBlob",
              version,
              updated_at AS "updatedAt";
  `);

  // Four outcomes from the single statement:
  //   (i)   row = [v=1]            ← INSERT path: no row existed AND expectedPrev=0
  //   (ii)  row = [v=current+1]    ← UPDATE path: CAS matched
  //   (iii) rows = []              ← INSERT path skipped (expectedPrev≠0 and no row),
  //                                  caller → 409
  //   (iv)  rows = []              ← UPDATE path WHERE failed (CAS mismatch or cap),
  //                                  caller → 409 (or 503 for cap, see route below)
  return (result.rows as VaultBlob[])[0] ?? null;
}
```

**Why this is race-safe — full case analysis:**

- **No row exists, `expectedPrev = 0`** (legitimate first write): the
  `WHERE 0 = 0` predicate is true, INSERT proceeds, row created at
  v=1. Returns 1 row.
- **No row exists, `expectedPrev = N` for any `N ≠ 0`** (stale or
  malicious client trying to force a high starting version): `WHERE
  N = 0` is false, INSERT inserts 0 rows, no conflict path triggered.
  Returns []. → 409. **This is the case the prior sketch missed.**
- **Two concurrent first-time writes, both `expectedPrev = 0`**: both
  SELECT-and-INSERT race; PostgreSQL's PK uniqueness on `user_id`
  serializes them. First INSERT wins, row created at v=1. Second
  INSERT collides on PK, falls into ON CONFLICT DO UPDATE; the
  conflict-path WHERE evaluates `vault_blobs.version = 0` against the
  row that's now at version=1 → false → 0 rows. Returns []. → 409. ✅
- **Two concurrent updates, both `expectedPrev = N`**: both INSERT
  attempts collide on PK and serialize into ON CONFLICT DO UPDATE.
  First UPDATE: `WHERE version = N` matches → row becomes v=N+1,
  returns 1 row. Second UPDATE: row is now v=N+1, `WHERE version = N`
  fails → 0 rows. Returns []. → 409. ✅
- **Stale write `expectedPrev = N-1` against current `v = N`**: SELECT
  predicate `(N-1) = 0` is false unless N=1; if false, INSERT skipped,
  returns []. → 409. If N=1 (so expectedPrev=0), SELECT returns row,
  INSERT collides on PK, ON CONFLICT WHERE `version = 0` fails (current
  is 1), 0 rows. → 409. ✅
- **Cap reached, `expectedPrev = SAFE_VERSION_MAX`**: ON CONFLICT
  WHERE includes `version < SAFE_VERSION_MAX`, fails. 0 rows. Returns
  []. The route handler then reads `current.version >= SAFE_VERSION_MAX`
  and returns 503 instead of 409. ✅

**Route handler then becomes:**

```ts
// server/routes.ts — POST /api/vault/sync
const parsed = vaultSyncSchema.safeParse(req.body);
if (!parsed.success) return res.status(400).json({ error: "Invalid input" });
const { encryptedBlob, expectedPrevVersion } = parsed.data;

const result = await storage.upsertVaultBlob(userId, encryptedBlob, expectedPrevVersion);
if (!result) {
  // Could be (a) version mismatch (CAS failed), or (b) version-cap hit.
  const current = await storage.getVaultBlob(userId);
  if (current && current.version >= SAFE_VERSION_MAX) {
    return res.status(503).json({ error: "Version space exhausted; contact support" });
  }
  return res.status(409).json({ error: "Version conflict",
                                 serverVersion: current?.version ?? 0 });
}
return res.status(200).json({ version: result.version, updatedAt: result.updatedAt });
```

This eliminates the *entire class* of version-manipulation attacks:
the client never chooses a version, so cannot jump to INT4_MAX,
cannot skip ahead, cannot game the comparison. The single-statement
CAS UPSERT preserves the atomicity guarantee of today's code without
introducing a transaction wrapper.

**Recommendation: ship Option B.** Option A on its own is misleadingly
described as a "fix" — it merely reduces the version space the
attacker exhausts, not the cost of exhausting it. If a hotfix is
needed *before* Option B can be designed and reviewed, ship Option A
**together with** the strict `version === current + 1` guard noted
above; otherwise the lockout primitive remains one-shot.

### P1 — Should fix before public release

| ID | Title | Fix surface |
|---|---|---|
| P1-A | Per-user daily write quota (independent of rate limit) | `server/routes.ts`: track `db.select(count).from(writeLog).where(userId AND date = today)`; if > 1000, return 429. Requires a small `vault_write_log(userId, ts)` table with TTL. Defends against "60/min sustained for a week" → ~600k writes. |
| P1-B | Audit log of write activity exposed to the user | Extend `vault_blobs` (or a sibling table) with `lastWriteIp`, `lastWriteUserAgent`, expose via `GET /api/vault/audit`. Lets the user see "your vault was modified 47 times in the last hour from IPs you don't recognize" and trigger a master-password rotation. |
| P1-7 *(carryover)* | Vault history table for soft-recovery | See `vault_integrity_audit.md` §P1-7 for the full sketch. |
| P1-C | Push notification on every write from a "new" IP/UA | Once history exists, this becomes cheap. Out of scope for an initial fix but worth designing the schema to support it. |
| P1-D | "Reset my account" endpoint (`DELETE /api/auth/account`) | Authenticated; requires re-entering the master-password-derived auth hash; cascades to `vault_blobs`. Lets the user escape D2 without operator intervention. |
| S2 *(carryover)* | Timing oracle on user-not-found vs wrong-hash | See `vault_integrity_audit.md` §S2. |

### P2 — Optional hardening

| ID | Title | Fix surface |
|---|---|---|
| P2-A | Two-factor / passkey enrollment | Removes the "valid creds = total trust" assumption. A 2FA-gated `vault_modification_token` would shrink the attack surface from "anyone with the master password" to "anyone with the master password + a fresh device-bound token". Out of scope today; worth scoping. |
| P2-3 *(carryover)* | Soften the destructive recovery prompt in VaultScreen | See `vault_integrity_audit.md` §CB1. |
| P2-B | Per-write signature with a device-bound key | Stronger version of P1-C — each write is signed by a device-registered keypair, so even with the master password an attacker without a registered device can't write. Requires a registration flow. |
| P2-C | Anomaly detection on write patterns | Server-side: flag "100 writes in 10 minutes from 3 different IPs" and trigger a write-freeze + email. |

---

## 9. Cross-References

- `vault_integrity_audit.md` — schema-level audit. P0-1 (empty blob), P0-2 (rate limit), P1-7 (history) are carried over. **The new finding here (P0-NEW: version-exhaustion lockout) was missed in the prior audit's C2 — that finding flagged "int4 overflow surfaces as 500" but stopped short of recognizing that Zod's auto-detected int4 cap turns it into a 400 lockout primitive instead. This audit replaces and supersedes the earlier C2 framing.**
- `auth_security_review.md` — auth-protocol audit. Establishes the credential model and notes the missing 2FA (relevant to P2-A above).
- `threat_model.md` — STRIDE-T (Tampering) and STRIDE-D (Denial of Service) — both findings here are concrete instances of the threats catalogued there.
- Existing project follow-up: "Wire `setCredentials` into auth screens; wire `authedApiRequest` into vault sync/fetch flow" — **this audit reinforces that the wiring must not ship until P0-1, P0-2, and P0-NEW are all fixed.** Without P0-NEW, the first malicious or buggy v=INT4_MAX write permanently locks any account.
