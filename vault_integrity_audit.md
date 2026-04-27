# PiPass — Vault Integrity & Tamper-Resistance Audit

**Status:** Audit deliverable — informational only. No code changes accompany
this document. Sibling deliverables: `threat_model.md`, `auth_security_review.md`.

**Scope:** the `/api/vault/sync` and `/api/vault/fetch` endpoints, their
validation/storage path (`server/validation.ts`, `server/storage.ts`,
`shared/schema.ts`), the client credential helper (`lib/credentials.ts`),
the authenticated request helper (`lib/query-client.ts → authedApiRequest`),
and the client crypto layer (`crypto/encryption.ts`,
`workers/vaultWorker.ts`) as the trust boundary that backs all of the above.

**Out of scope:** `crypto/*` is not modified by this audit (per project
constraints). `workers/storageWorker.ts → JSON.stringify(entries)` is the
**local** App-Group keychain blob, not the wire-format that will eventually
reach `/api/vault/sync` — that wiring does not exist yet (called out below
as a precondition for safe deployment).

---

## 1. Executive Summary

PiPass's server-side vault layer is conservatively designed: it treats
`encryptedBlob` as opaque text bounded to 10 MiB, enforces strict
monotonic versioning at three layers (Zod `.min(1)`, PostgreSQL `CHECK`
constraint, and an UPSERT `WHERE old_version < new_version`), validates
both auth headers as a UUID + 64–128-char hex string before touching the
DB, and uses two tiered 401 messages for unauthorized paths:
`"Authentication required"` for malformed/missing headers (returned by
`validateAuthHeaders` in `server/validation.ts`) and `"Invalid
credentials"` for auth-failed paths (where the latter deliberately
collapses "unknown user" and "wrong hash" into one identical response
to prevent user enumeration). Replay of a stale version, concurrent
writes from two devices at the same version, and cross-user IDOR were
all confirmed to fail safely during live testing.

**One P0 finding gates this layer from being safely wired into the app:**
the server accepts `encryptedBlob: ""` as a valid blob (verified — HTTP
200). With valid credentials, this is a single-request, irreversible
**vault wipe**: the empty string overwrites the user's only stored
ciphertext, the version monotonicity then prevents any "rollback" sync,
and there is no server-side history to restore from. Fixing this is a
one-line schema change.

A second P0 (rate limiting on vault endpoints) is carried over from the
prior auth security review — it remains the most exploitable lever for
both denial-of-service and the wipe attack above.

The rest of the system is in good shape. The **client crypto layer
provides AEAD-equivalent integrity** (AES-256-CBC + HMAC-SHA256 in
Encrypt-then-MAC order, MAC verified before decryption with a
constant-time compare, MAC key derived from the encryption key via a
distinct HMAC subkey constant). This is correctly implemented today, but
it is a *custom* construction — a P1 recommendation is to migrate to a
single-call AEAD primitive (AES-GCM via `react-native-quick-crypto` or
similar) once the project leaves Expo Go, and to add a regression test
that asserts a tampered ciphertext is rejected.

The client **trust boundary** is well-defined on the cryptographic side
(decryption throws on MAC mismatch) but no UI-side error boundary
currently exists for "the server returned a poisoned blob" — a
compromised or buggy server can crash the app. P2.

**Overall verdict:** the server protocol is sound *once the empty-blob
floor and per-user vault rate limit are in place*. Until then, do not
ship the client wiring (`setCredentials` → `authedApiRequest("POST",
"/api/vault/sync", ...)`) — a single buggy code path on the client could
wipe a user's vault.

---

## 2. Attack Scenarios Table

| # | Attacker capability | Scenario | Outcome (verified) | Status |
|---|---|---|---|---|
| A1 | None (network observer, TLS intact) | Capture `/api/vault/*` traffic | Sees opaque ciphertext bounded ≤ 10 MiB; no plaintext, no metadata beyond size+version+timestamp | ✅ Mitigated by zero-knowledge design |
| A2 | None (try random `x-user-id` UUIDs) | Brute-force fetch | Each attempt → `401 "Invalid credentials"` (collapsed with "wrong hash"); no enumeration distinguisher. UUID space (~2¹²²) is computationally unbruteable, but the *attempt rate* is not throttled on vault endpoints. | ⚠ Per-attempt mitigated by collapsed error; no per-IP rate limit caps the volume — see P0-2 |
| A3 | Valid creds | **Replay a stale `(blob, version=N-1)` after current is N** | `409 "Version conflict"` with `serverVersion: N`; old blob NOT restored | ✅ Mitigated by SQL `WHERE version < new_version` + app-level pre-check |
| A4 | Valid creds, two devices | Concurrent writes both at `version=N+1` | First write wins (200); second gets `409 + serverVersion=N+1`; client must fetch, merge locally, retry with `N+2` | ✅ Mitigated by UPSERT WHERE closing the SELECT-then-INSERT race |
| A5 | **Valid creds** | **Submit `{encryptedBlob: "", version: current+1}`** | **HTTP 200. Vault permanently wiped — no rollback path, no history.** | ❌ **P0-1 — NOT MITIGATED** |
| A6 | Valid creds | Spam `/api/vault/sync` with 10 MiB bodies | Each request accepted (or 409); no per-user/per-IP throttle on vault endpoints | ❌ **P0-2 — NOT MITIGATED** (carried from auth review) |
| A7 | Network MITM (assume TLS broken) | Mutate one byte of the in-flight ciphertext | Client `decryptData` throws `"Authentication failed — data may be tampered"` (MAC mismatch); plaintext never reached | ✅ Mitigated by Encrypt-then-MAC + authenticate-then-decrypt |
| A8 | Malicious / compromised server | Return crafted blob to client `/fetch` | Client MAC verify fails → `decryptData` throws → caught by existing try/catch in `VaultScreen.tsx` (initial-load site at ~L282 and per-entry decrypt at ~L345) | ✅ Cryptographic + UI both mitigated; see CB1 for a residual UX concern around the destructive recovery prompt |
| A9 | Valid creds | Submit `{encryptedBlob, version, hax: true}` (extra field) | `400 "Unknown field"` | ✅ Mitigated by Zod `.strict()` |
| A10 | Valid creds | Submit `version: 0`, `-5`, or `"5"` (string) | `400 "Invalid version"` (Zod first); DB CHECK `version >= 1` is the backstop | ✅ Mitigated at three layers |
| A11 | Valid creds | Submit blob = 10 MiB + 1 byte | `400 "Invalid blob"`; > 11 MiB → `413 "Payload too large"` from body parser | ✅ Mitigated by Zod `.max()` + Express body limit |
| A12 | Cross-user IDOR (user-1 creds, user-2 `x-user-id`) | Fetch other user's vault | `401 "Invalid credentials"` (auth check uses *header* userId to look up the row, then compares against *that* user's stored hash → mismatch) | ✅ Mitigated by per-request auth re-binding |
| A13 | Valid creds | Submit `encryptedBlob: null` or `12345` (number) | `400 "Invalid blob"` (not 500) | ✅ Mitigated |
| A14 | Valid creds, future client bug | Submit blob in legacy 2-part format `iv:ciphertext` | Decryption succeeds **without** MAC verification (no integrity check) | ⚠️ P2-4 — backward-compat path bypasses MAC |
| A15 | Two writers race (~ms apart) | Both pass app-level pre-check (`existing.version < new`), both call UPSERT | Second UPSERT's `WHERE version < $new` fails atomically, returns 0 rows, app returns 409 | ✅ Mitigated by atomic UPSERT WHERE |

**Table legend:** ✅ mitigated and verified · ⚠️ partial mitigation · ❌ not mitigated

---

## 3. Detailed Findings

### 3.1 — Tamper Resistance (Section 1 of brief)

**With valid credentials, can an attacker corrupt or poison stored vault data?**

**Yes, in two ways:**

**Finding T1 [P0-1] — Empty / sentinel blob accepted; one-shot irreversible vault wipe.**

Verified live:
```
$ curl -X POST /api/vault/sync -H 'x-user-id: …' -H 'x-auth-hash: …' \
       -d '{"encryptedBlob":"","version":1}'
{"version":1,"updatedAt":1777313986357}    HTTP 200
```

The Zod schema in `shared/schema.ts` declares only the upper bound:

```ts
// shared/schema.ts (current)
export const insertVaultBlobSchema = createInsertSchema(vaultBlobs, {
  encryptedBlob: (col) => col.max(10 * 1024 * 1024),
  version: (col) => col.min(1),
}).strict();
```

There is no `.min(...)` on `encryptedBlob`. An empty string passes
validation, the UPSERT runs, and the previous (real) ciphertext is
overwritten. Because the version is now strictly higher, no client
"rollback" sync is accepted afterwards. Because there is no history
table, the previous blob is gone.

This is exploitable by:
- a hostile peer who learned the credentials (e.g. via shoulder-surfing the
  master password during initial setup);
- a buggy future client that hits an edge case and POSTs an empty
  `JSON.stringify(entries)` (e.g. `entries` was `null` or `undefined`);
- a malicious browser extension on the web build of the app, since
  `lib/credentials.ts` falls back to `localStorage` on web, which is
  readable by any extension with `<all_urls>` access.

**Concrete fix** (one line in `shared/schema.ts`):

```ts
export const insertVaultBlobSchema = createInsertSchema(vaultBlobs, {
  encryptedBlob: (col) => col.min(1).max(10 * 1024 * 1024),  // ← .min(1)
  version: (col) => col.min(1),
}).strict();
```

A stronger version raises the floor to "must be at least the size of an
empty encrypted JSON array". An empty `[]` plaintext encrypted with
`encryptData("[]", key)` produces 32 hex chars (IV) + `:` + ~32 hex
chars (cipher of one 16-byte AES block) + `:` + 64 hex chars (MAC) =
~129 chars minimum. A floor of `64` is a safe pragmatic minimum that
still rejects "" / "null" / "[]" / single-byte sentinels:

```ts
encryptedBlob: (col) => col.min(64).max(10 * 1024 * 1024),
```

The DB-level CHECK constraint should mirror this for defense in depth.
Note the existing table uses **array-form** callbacks (not object-form),
so the addition is one extra array entry next to the existing version
constraint:

```ts
// shared/schema.ts — vaultBlobs table definition (existing array form)
export const vaultBlobs = pgTable(
  "vault_blobs",
  {
    userId:        uuid("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
    encryptedBlob: text("encrypted_blob").notNull(),
    version:       integer("version").notNull(),
    updatedAt:     bigint("updated_at", { mode: "number" }).notNull().$defaultFn(() => Date.now()),
  },
  (table) => [
    check("vault_blobs_version_range", sql`${table.version} >= 1`),
    check("vault_blobs_blob_min_len",  sql`length(${table.encryptedBlob}) >= 64`),  // ← new
  ],
);
```

After this edit, run `npm run db:push --force` (per the project's
DB safety rules) to apply the new CHECK without writing a manual
migration.

**Finding T2 [P1-7] — No history; destructive writes are permanently
destructive (product-resilience, not a security control).**

Even after T1 is fixed, an attacker with valid credentials can still
overwrite a user's vault with `encryptData("[]", attacker_master_key)`
(a properly-formatted empty vault), which the server has no way to
distinguish from a legitimate "user deleted all entries". The user
loses all data.

**This is a deliberate trait of the zero-knowledge design**, not a
security flaw — the server, by definition, cannot tell a legitimate
write from a malicious one once the attacker has valid credentials.
Compromised-credential recovery is the user's responsibility (via
backups). Most password managers in this design tier (e.g., Bitwarden,
1Password) *do* keep server-side history as a UX safety net, but they
also depend on TOTP/2FA to prevent credential theft from leading to
overwrite in the first place — and PiPass has no second factor today
(noted in `auth_security_review.md`).

Two complementary improvements (either or both, in priority order):

- **(P1-7a)** Server-side soft history: a `vault_blob_history` table
  retaining the last N=10 versions per user (or all versions for the
  last K=30 days), with a transactional append in `upsertVaultBlob`
  and a `POST /api/vault/restore` endpoint that promotes a chosen
  history row to a new version > current. Sketch (uses the same
  `uuid().primaryKey().defaultRandom()` pattern as `users.id` and the
  array-form `check` callback that the rest of the schema uses):

  ```ts
  // shared/schema.ts — additional table
  // (add `index` to the existing drizzle-orm/pg-core import line)
  export const vaultBlobHistory = pgTable(
    "vault_blob_history",
    {
      id:            uuid("id").primaryKey().defaultRandom(),
      userId:        uuid("user_id").notNull()
                       .references(() => users.id, { onDelete: "cascade" }),
      encryptedBlob: text("encrypted_blob").notNull(),
      version:       integer("version").notNull(),
      archivedAt:    bigint("archived_at", { mode: "number" })
                       .notNull().$defaultFn(() => Date.now()),
    },
    (table) => [
      index("vbh_user_version_idx").on(table.userId, table.version),
      check("vbh_version_range",   sql`${table.version} >= 1`),
      check("vbh_blob_min_len",    sql`length(${table.encryptedBlob}) >= 64`),
    ],
  );
  ```

  In `server/storage.ts → upsertVaultBlob`, wrap the existing UPSERT in
  `db.transaction(async (tx) => { … })` and `INSERT INTO
  vault_blob_history SELECT … FROM vault_blobs WHERE user_id = $1` *before*
  the UPSERT. A scheduled prune job (cron, or `pg_cron`) deletes rows
  beyond N or older than K days.

- **(P1-7b)** Client-side encrypted exports: a "Download backup" UI
  that writes the current encrypted blob to the device's downloads/
  share-sheet. Cheap, no server changes, no new attack surface. Should
  ship regardless of (a).

This finding was originally listed as **P0-3** in this document and
has been **downgraded to P1** on review: the underlying capability
(an attacker with valid creds can destroy data) is inherent to the
zero-knowledge model and cannot be eliminated server-side. P0-1
(empty-blob wipe) and P0-2 (no rate limit on vault endpoints) remain
the actual ship-blockers because they let an attacker amplify the
destruction without needing to know the user's master key — they only
need to bypass the master-password barrier *once* and then they can
spam destructive writes indefinitely.

---

### 3.2 — Integrity Guarantees (Section 2 of brief)

**Is `encryptedBlob` integrity verifiable?**

**Yes, fully — but client-side only, with a custom (non-AEAD) construction.**

The server treats the blob as opaque text. This is the **correct**
choice for a zero-knowledge design — the server *must not* be able to
inspect the blob's structure, otherwise the protocol leaks information.
But it means: **all integrity checking happens in `crypto/encryption.ts`
on the client.**

The construction (read from `crypto/encryption.ts`):

- **Format:** `ivHex(32):cipherHex(N):macHex(64)`.
- **Cipher:** AES-256-CBC + PKCS7 padding (crypto-js).
- **MAC:** HMAC-SHA256 over `ivHex || cipherHex` (Encrypt-then-MAC — the
  cryptographically correct order).
- **MAC key:** `HmacSHA256("hmac-subkey", encKey)` — derived from the
  encryption key via a distinct constant, so the same key is never
  reused for both AES and HMAC.
- **Verification order:** MAC checked **before** decryption
  (authenticate-then-decrypt — correct).
- **Compare:** constant-time over hex bytes (`constantTimeEqual` in
  `crypto/encryption.ts:13–24`) — resists timing oracles.

This provides the same security guarantees as AES-GCM (confidentiality +
integrity + authenticity). **It is correctly implemented today.**

**Finding I1 [P1-1] — Custom AEAD construction; future-contributor risk.**

The protocol is correct *as written*. It is also a 30-line custom
construction in user-space code, with a legacy 2-part decryption path
that has no MAC. Any future change — swapping the order of MAC and
decrypt, dropping the constant-time compare in favour of `===`,
removing the subkey derivation — silently breaks the integrity property
without changing any tests, any types, or any API surface.

**Recommend** (in priority order):

1. **Add a regression test** that asserts:
   - flipping any single byte of the cipher → `decryptData` throws;
   - flipping any single byte of the MAC → `decryptData` throws;
   - flipping any single byte of the IV → `decryptData` throws;
   - swapping the MAC for an HMAC over `cipher` only (omitting IV) → throws;
   - decrypting with the wrong key → throws.
2. **Migrate to a single-call AEAD primitive** when the project leaves
   Expo Go: `react-native-quick-crypto` exposes `createCipheriv("aes-256-gcm", …)`.
   This collapses 3 separate primitives (cipher, HMAC, constant-time
   compare) into one well-tested library function. Until then, the
   regression test in (1) is the gating control.
3. **Delete the legacy 2-part decryption path** (`decryptLegacy`) once
   all stored entries are confirmed to be 3-part. Today, any blob a
   future client happens to format as `iv:cipher` (no MAC) is decrypted
   without integrity check — a footgun. (See P2-4.)

**Finding I2 — Should the server enforce blob format (length, encoding)?**

**No, beyond the size envelope already enforced.** Enforcing
hex-encoding or a `iv:cipher:mac` shape would:

- couple the server to one specific client crypto version (breaks future
  AEAD migration);
- give an attacker a structural oracle (`400 "Invalid format"` vs `200`)
  that distinguishes "well-formed" from "garbage" ciphertexts — a
  zero-knowledge violation, however small.

The size envelope (`min`–`max`) is the correct level of server
involvement. The minimum should be raised per Finding T1.

---

### 3.3 — Concurrency & Race Conditions (Section 3 of brief)

**Two devices syncing simultaneously with different versions:**

Walk-through with current code:

1. Both devices read `serverVersion = 5` via `/fetch`.
2. Device A locally bumps to v=6, POSTs `(blob_A, v=6)`.
3. Device B *concurrently* locally bumps to v=6, POSTs `(blob_B, v=6)`.

Server-side handler (`server/routes.ts:217–242`):

```ts
const existing = await storage.getVaultBlob(userId);                       // (1) SELECT
if (existing && existing.version >= parsed.data.version) {                 // (2) app-level check
  return res.status(409).json({ error: "Version conflict",
                                serverVersion: existing.version });
}
const blob = await storage.upsertVaultBlob(userId, ...parsed.data);        // (3) UPSERT
if (!blob) {                                                               // (4) fallback check
  const current = await storage.getVaultBlob(userId);
  return res.status(409).json({ error: "Version conflict",
                                serverVersion: current?.version ?? 0 });
}
```

The pre-check at (2) is *not* race-safe on its own — between SELECT and
UPSERT, the other request can interleave. **The race is closed at the
SQL layer in `server/storage.ts:65–80`:**

```ts
.onConflictDoUpdate({
  target: vaultBlobs.userId,
  set: { encryptedBlob, version, updatedAt: now },
  where: sql`${vaultBlobs.version} < ${version}`,    // ← atomic guard
})
.returning();
```

This `WHERE` is part of a single atomic statement. If between (1) and
(3) the other writer landed at v=6, the `WHERE 5 < 6` condition is now
`WHERE 6 < 6` = false; PostgreSQL skips the update; `returning()`
yields zero rows; the handler's check at (4) returns 409 with the
new `serverVersion: 6`.

**Verified live:**

```
R1. Replay STALE version (write v=3 after current is v=5)
    → 409 {"error":"Version conflict","serverVersion":5}
R2. Re-write SAME version v=5 (=existing)
    → 409 {"error":"Version conflict","serverVersion":5}
R4. Successor write v=6 (legitimate forward progress)
    → 200 {"version":6,"updatedAt":…}
```

**Verdict: last-write-wins is intentional, atomic, and safe at the SQL
level.** No compare-and-swap needed beyond what's already there.

**Finding C1 [P2-6] — The app-level pre-check at (2) is redundant
defense-in-depth, not a correctness control.** If it's ever removed
"because the SQL handles it", that's fine. If it's ever modified to
relax the comparison (`>=` → `>`), that's a regression. Suggest a
comment in `server/routes.ts` explaining the role of each layer:

```ts
// Defense in depth: the SQL UPSERT below has a `WHERE version < $new`
// clause that is the actual race-safe guard. This pre-check just turns
// "obvious conflict" into a 409 without making a DB write attempt. Do
// not rely on this check for correctness — the SQL clause is authoritative.
if (existing && existing.version >= parsed.data.version) { … }
```

**Out-of-order requests:** the protocol has no concept of request
ordering beyond the version field. If client retries arrive
out-of-order, each is evaluated independently against the current
serverVersion. There is no replay window: an old `(blob, v=5)` request
delivered late always 409s. ✅

**Finding C2 [P1-5] — `version` is a 32-bit signed integer
(`integer` Drizzle type → PostgreSQL `int4`).** Maximum value is
`2_147_483_647`. With a per-write monotonic counter this is more than
ample. But if any client uses `Date.now()` as the version (the local
shared-vault code currently hard-codes `version: 1`, but the field is
typed `number` in `workers/sharedVaultStorage.ts:11` and could
trivially regress), `Date.now()` is already at `1.78 × 10¹²`, which
overflows `int4` → PostgreSQL throws `22003 numeric_value_out_of_range`
→ surfaces as a 500.

**Recommend:**

- Document that `version` is an opaque monotonic counter, **not** a
  timestamp. A `// monotonic; do not use Date.now()` comment on the
  `version` field in `shared/schema.ts` and on the `version` field of
  `SharedVaultBlob` in `workers/sharedVaultStorage.ts`.
- Optionally widen to `bigint` (`{ mode: "number" }` is safe up to
  `2^53`). Cheap insurance.

---

### 3.4 — Replay & Reorder Attacks (Section 4 of brief)

**Can an attacker replay an older valid sync request to overwrite newer data?**

**No** — verified above (R1, R2). The version monotonicity at three
layers (Zod, DB CHECK, UPSERT WHERE) prevents any rollback. An
attacker who captures a `(blob, v=5)` request can replay it *forever*,
and the server will keep returning 409 once the user advances past v=5.

**Can an attacker capture a fresh sync request mid-flight (before the
user has advanced) and replay it later?**

The attacker would need TLS to be broken first. Once broken, the
attacker can replay the request only until the legitimate user advances
past that version (typically seconds to minutes after any vault edit).
After that, the replay 409s. The *captured* request was valid for that
version anyway, so the replay can only "successfully" land the same
state the legitimate user already chose. No protocol-level mitigation
is needed beyond TLS + version monotonicity.

**Finding R1 [P1-6] — No nonce / request freshness on the wire.**
Without a per-request nonce or timestamp signed into the auth flow, the
*identical* sync request could be replayed across the brief window
between the legitimate POST and the user's next local edit — even with
TLS, an active proxy could "replay" the request to itself just before
the legitimate one lands, forcing the legitimate request into a 409
("you wrote v=N a moment ago"). This is a denial-of-service annoyance,
not a data-corruption vector. **Acceptable to defer**, but a future
hardening would add a `nonce` field to the request that the server
caches for *T* seconds and rejects on repeat. Combined with the
recommended per-user rate limit (P0-2), the practical impact is low.

---

### 3.5 — Malformed Input Edge Cases (Section 5 of brief)

**All fuzz cases verified to return 4xx, never 5xx, never crash:**

| Input | Result | Status |
|---|---|---|
| `encryptedBlob: ""` | **HTTP 200 (persisted)** | ❌ P0-1 |
| `encryptedBlob: "   "` (whitespace) | HTTP 200 (persisted, treated as opaque text) | ⚠️ informational — same root cause as P0-1 (no `.min`) |
| `encryptedBlob: "not even ciphertext, just plain text"` | HTTP 200 (persisted, server is correctly opaque) | ✅ |
| `encryptedBlob: 12345` (number) | `400 "Invalid blob"` | ✅ |
| `encryptedBlob: null` | `400 "Invalid blob"` | ✅ |
| `version: 0` | `400 "Invalid version"` | ✅ |
| `version: -5` | `400 "Invalid version"` | ✅ |
| `version: "5"` (string) | `400 "Invalid version"` | ✅ |
| `{..., hax: true}` (extra field) | `400 "Unknown field"` | ✅ |
| Body > 11 MiB | `413 "Payload too large"` (express body parser) | ✅ |
| Blob > 10 MiB but body < 11 MiB | `400 "Invalid blob"` | ✅ |
| Blob = exactly 10 MiB | HTTP 200 | ✅ |

The Zod `.strict()` mode is doing meaningful work: a future endpoint
extension that adds, say, `clientId` would otherwise silently accept
any extra fields a client smuggled in.

**Finding M1 — `encryptedBlob: "   "` (whitespace-only) is accepted.**
Same root cause as P0-1; a `.min(64)` floor closes both at once.

**Finding M2 — `encryptedBlob: "not even ciphertext"` is accepted.**
This is **correct behavior** for a zero-knowledge design — the server
must treat the blob opaquely. Anything else would leak structure. The
*client* will throw on decryption (no `:` separators → falls into the
3-part `parts.length !== 3` branch → `throw new Error("Invalid
ciphertext format")`). This needs the UI error boundary recommended in
P2-3.

---

### 3.6 — Client Trust Boundary (Section 6 of brief)

**Does the client ever trust the fetched blob blindly?**

**No on the cryptographic side, partially yes on the UI side.**

- `decryptData` (`crypto/encryption.ts:54–95`) verifies the MAC *before*
  attempting decryption (authenticate-then-decrypt — correct). Any of
  the following throws:
  - blob has wrong number of `:` separators → `"Invalid ciphertext format"`;
  - MAC byte-mismatch → `"Authentication failed — data may be tampered"`;
  - PKCS7 padding fails or UTF-8 decode produces empty string →
    `"Decryption failed — invalid key or corrupted data"`.
- `decryptVaultEntry` (`workers/vaultWorker.ts:100–144`) lets these
  exceptions propagate.
- **`screens/VaultScreen.tsx`** wraps both decrypt sites in `try/catch`:
  the initial-load probe at ~L282 catches and surfaces a "Key Mismatch"
  alert; the per-entry decrypt at ~L345 catches and surfaces a
  "Decryption Error" alert. Verified — no propagation to React's render
  path.

**Finding CB1 [P2-3] — UI recovery prompt for a single decrypt failure
is destructive.** The cryptographic integrity guarantees are correctly
caught (good), but the *recovery action* offered when the initial-load
decrypt fails is `"Clear & Start Fresh? [Clear (destructive) — destroyAllData()]"`
(`screens/VaultScreen.tsx` ~L282). Once the server-sync wiring lands,
a malicious or compromised server can return a single poisoned blob
and the user is one tap away from total local data loss — the
destructive option is offered as the *only* recovery path, with no
"refresh from server" or "sign in again on a known-good network"
intermediate step.

**Concrete fix** (forward-looking, applies once server sync is wired):

```ts
// screens/VaultScreen.tsx — Key Mismatch handler at ~L282
Alert.alert(
  "Key Mismatch",
  "This entry could not be decrypted. It may have been corrupted on " +
  "the server or your vault may need to be re-synced.",
  [
    { text: "Sign in again",     onPress: () => onLock() },          // ← non-destructive default
    { text: "Try again",         onPress: () => loadVault() },
    { text: "Clear & Start Fresh", style: "destructive",
      onPress: async () => { await destroyAllData(); onReset(); } }, // ← keep as last resort
  ],
);
```

Severity is P2 because: (a) the cryptographic check correctly fails
closed; (b) the issue only matters once server sync is wired; (c) the
wipe requires explicit user confirmation. But it should be fixed as
part of the sync-wiring task, not after.

**Finding CB2 — Credential helper validators are belt-and-suspenders.**
`lib/credentials.ts` validates UUID + 64–128 hex on both read **and**
write, auto-clears corrupted values on read. ✅ This is the correct
posture: even if SecureStore is somehow corrupted (jailbroken device,
disk error, future migration bug), the next request fails fast as
`AuthRequiredError` rather than sending garbage headers and getting a
confusing 401 round-trip. Already approved by architect review. No
finding.

---

### 3.7 — Storage Safety (Section 7 of brief)

**Confirm:**

- ✅ **No plaintext secrets stored server-side.** `users` table holds
  `username`, `authHash` (SHA-256 of the wire `authHash`), `salt`,
  `iterations`. `vault_blobs` holds `userId`, `encryptedBlob` (opaque
  to the server), `version`, `updatedAt`. No password fields, no
  recovery codes, no master keys.
- ✅ **Server SHA-256s the wire-form `authHash` before storage.**
  `server/routes.ts:111` (register handler) — even if the DB is
  exfiltrated, the attacker recovers a hashed-hash, not the original
  PBKDF2 output, adding one more layer to crack.
- ✅ **Request logger emits only `METHOD path STATUS in Xms`.**
  `server/index.ts:67–85`. No headers, no body, no userId.
- ✅ **Error handler returns generic `"Internal server error"` on 500;**
  the underlying error is logged with a constant string
  (`console.error("Vault sync error")`) — no stack traces, no request
  context, no body.

**Finding S1 [P1-3] — No CI guard against future log-leak regressions.**
Carried over from `auth_security_review.md`. The current logger is
correct, but a future "log full headers in dev" change would silently
start emitting `x-auth-hash` to stdout. A test that captures the
logger's output during representative requests and asserts the absence
of `x-auth-hash` (case-insensitive) and absence of any 64+ char hex
string would prevent this. Already on the follow-up list there.

**Finding S2 [P2-7] — Error message leaks "user does not exist" path
length differential.** In both vault sync (`server/routes.ts:213`) and
fetch (`server/routes.ts:264`), the "user not found" branch is
`getUser(userId)` returning undefined → 401 immediately, **without**
calling `hashForComparison(authHash)` or `timingSafeEqual`. The
"wrong password" branch *does* call both. An attacker measuring
response time can distinguish "this UUID doesn't exist" from "this
UUID exists with wrong hash" — a small enumeration oracle.

The auth handlers (login, register) already have explicit anti-timing
defenses (deterministic dummy salt for unknown users in
`/api/auth/salt`). The vault handlers should match: even when the user
is not found, do a dummy `hashForComparison` + `timingSafeEqual` on a
constant. Pseudocode:

```ts
const user = await storage.getUser(userId);
const referenceHash = user
  ? Buffer.from(user.authHash, "hex")
  : DUMMY_REFERENCE_HASH;       // 32 bytes of zeros, computed once at boot
const providedHash = hashForComparison(authHash);
const equal = providedHash.length === referenceHash.length
              && timingSafeEqual(providedHash, referenceHash);
if (!user || !equal) {
  return res.status(401).json({ error: "Invalid credentials" });
}
```

**Finding S3 — `vault_blobs.userId` is `uuid` PK with `ON DELETE CASCADE`
on `users.id`.** ✅ Deleting a user atomically deletes their vault.
No orphan rows possible. No finding.

---

### 3.8 — No Vault Rate Limit (carried from auth review)

**Finding RL1 [P0-2] — No per-user / per-IP rate limit on
`/api/vault/sync` or `/api/vault/fetch`.**

Repeated from `auth_security_review.md` because it directly amplifies
P0-1 (an attacker with valid creds can wipe + repeat the wipe + spam
sync) and is the single most exploitable lever for DoS.

The auth endpoints already use `isRateLimited(`auth:${clientIp}`)` /
`isRateLimited(`salt:${clientIp}`)` — the same primitive can be
applied to vault endpoints with both an IP key and a userId key:

```ts
// server/routes.ts — at the top of /api/vault/sync (after auth check)
if (isRateLimited(`vsync:user:${userId}`, /*max*/ 60, /*windowMs*/ 60_000)) {
  return res.status(429).json({ error: "Too many sync attempts. Please try again later." });
}
if (isRateLimited(`vsync:ip:${clientIp}`, /*max*/ 120, /*windowMs*/ 60_000)) {
  return res.status(429).json({ error: "Too many sync attempts. Please try again later." });
}
```

Suggested limits:

| Endpoint | Per-userId | Per-IP |
|---|---|---|
| `POST /api/vault/sync` | 60/min | 120/min |
| `GET  /api/vault/fetch` | 60/min | 120/min |

These ceilings are well above any plausible legitimate traffic
(autosync after every edit) and well below the levels needed for
amplified DoS or rapid-fire wipe-then-replace abuse.

---

## 4. Recommendations Summary

### P0 — Must fix before wiring vault sync into the client

| ID | Title | Fix surface |
|---|---|---|
| P0-1 | Empty/short blob accepted; one-shot vault wipe | `shared/schema.ts` — add `.min(64)` to `encryptedBlob` in `insertVaultBlobSchema`; add matching `check("vault_blobs_blob_min_len", …)` to the table's array-form callback |
| P0-2 | No rate limit on `/api/vault/sync` and `/api/vault/fetch` | `server/routes.ts` — add `isRateLimited("vsync:user:…")` and `…:ip:…` calls (60/min per userId, 120/min per IP) |

### P1 — Should fix before production launch

| ID | Title | Fix surface |
|---|---|---|
| P1-1 | Custom AEAD construction; no regression test | Add `crypto/__tests__/encryption.test.ts` asserting tampering (each of IV / cipher / MAC) and wrong-key throw; plan AES-GCM migration when leaving Expo Go |
| P1-3 | No CI guard against log-leak regressions | Already on follow-up list (carried from auth review) |
| P1-5 | `version` is `int4`; document monotonic-counter contract | Comment in `shared/schema.ts` and `workers/sharedVaultStorage.ts`; consider widening to `bigint({ mode: "number" })` |
| P1-6 | No request-freshness nonce | Defer; revisit after P0-2 lands |
| **P1-7** | **No vault history; destructive writes are permanently destructive (downgraded from P0-3 — inherent to zero-knowledge model, but still a strong UX safety net)** | **New `vault_blob_history` table + transactional append in `upsertVaultBlob` (P1-7a) and/or client-side encrypted backup export (P1-7b)** |
| S2 | Timing oracle distinguishes "user not found" vs "wrong hash" on vault endpoints | `server/routes.ts` — perform dummy `timingSafeEqual` against a constant when `user === undefined` |

### P2 — Nice to have

| ID | Title | Fix surface |
|---|---|---|
| P2-3 | Destructive "Clear & Start Fresh" is the default recovery action on a single decrypt failure (the existing try/catch is fine; the recovery prompt is too aggressive once server sync lands) | `screens/VaultScreen.tsx` — add non-destructive "Sign in again" / "Try again" options *before* the destructive one in the Key Mismatch alert |
| P2-4 | Legacy 2-part decryption path bypasses MAC | `crypto/encryption.ts` — delete `decryptLegacy` after migration window; meanwhile, log (telemetry only, never the blob) when it's hit |
| P2-6 | App-level pre-check is defense-in-depth, not correctness — comment it | `server/routes.ts` |
| P2-7 | Vault size leaks via ciphertext length | Pre-encryption padding to a fixed bucket size (e.g., next power of two) in the future client wrapper |
| (info) | `JSON.stringify(entries)` in `workers/storageWorker.ts` is the **local** SecureStore blob, not the wire blob — when sync is wired, the client MUST `encryptData(JSON.stringify(entries), masterKey)` before POST | Future client integration task |

---

## 5. Cross-References

- `threat_model.md` §STRIDE-T (Tampering) — this audit is the deep dive on T.
- `auth_security_review.md` §P0 #2 (no rate limit) — re-stated here as P0-2 with new vault-specific impact.
- `auth_security_review.md` §P0 #3 (log-leak guard test) — re-stated here as P1-3.
- Existing project follow-up: "Wire `setCredentials` into auth screens; wire `authedApiRequest` into vault sync/fetch flow" — **must not ship until at least P0-1 and P0-2 are fixed**, per this audit. P1-7 (history) and P2-3 (recovery prompt softening) should land alongside the same task.
