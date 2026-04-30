import {
  generateSecret,
  generateSync,
  generateURI,
  verifySync,
  NobleCryptoPlugin,
  ScureBase32Plugin,
} from "otplib";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

// otplib v13 uses an explicit plugin model: the crypto and base32
// implementations are passed in per-call instead of being globally
// configured. We pin to the noble crypto plugin (audited pure-JS HMAC,
// available in every runtime including Workers/Deno/Bun should we
// ever swap host) and the scure base32 plugin (matches the format
// every authenticator app expects). Constructed once at module load
// so we don't re-instantiate on every TOTP call.
const cryptoPlugin = new NobleCryptoPlugin();
const base32Plugin = new ScureBase32Plugin();

// Canonical RFC 6238 / Google Authenticator defaults shared by every
// generate / verify call. Captured once so the values are not
// scattered across call sites:
//   - 6 digit codes
//   - 30 second time step
//   - SHA-1 HMAC (de-facto standard — SHA-256 / SHA-512 exist but
//     are not universally supported by every app)
//   - tolerance: 30 — accept the current step plus +/- 1 step
//     (90 second total tolerance) to absorb client clock skew. This
//     matches RFC 6238 §5.2 guidance and replaces the old
//     authenticator.options.window=1 setting from otplib v12.
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;
const TOTP_ALGORITHM = "sha1" as const;
const TOTP_TOLERANCE_SECONDS = 30;

// ---------------------------------------------------------------------------
// At-rest encryption for the user's TOTP shared secret
// ---------------------------------------------------------------------------
//
// The TOTP secret IS a credential — anyone who reads it can mint valid
// codes for the user. We MUST NOT store it in plaintext: if the DB is
// leaked, every user's 2FA is bypassable. We wrap each secret in
// AES-256-GCM with a per-deployment key.
//
// KEY SOURCE: process.env.TOTP_ENCRYPTION_KEY ONLY.
//   - 64 hex chars (32 bytes) OR 44-char base64 of 32 bytes.
//   - No fallback chain. Earlier revisions of this code transparently
//     fell back to SHA-256(SESSION_SECRET) and then SHA-256(DATABASE_URL)
//     when this var was unset. Both fallbacks are removed because they
//     coupled TOTP at-rest encryption to unrelated rotation cycles
//     (rotating SESSION_SECRET silently corrupted every user's 2FA),
//     and because "silent fallback to a derived secret" is the kind of
//     surprise this codebase explicitly tries to avoid in security
//     paths. The operator MUST set TOTP_ENCRYPTION_KEY explicitly.
//   - The value is validated eagerly at server boot via
//     `assertTotpKeyConfigured()` (called from server/index.ts) so a
//     missing/misformatted key fails loudly at startup rather than the
//     first time a user enables 2FA.
const KEY_LEN_BYTES = 32; // AES-256
const IV_LEN_BYTES = 12; // GCM standard nonce length
const TAG_LEN_BYTES = 16; // GCM auth tag

const TOTP_KEY_HELP =
  "Set the TOTP_ENCRYPTION_KEY secret to a freshly-generated 32-byte value. " +
  "Generate one with: `node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"` " +
  "and add it via Replit Secrets. Do not reuse SESSION_SECRET or any other secret.";

function parseEncryptionKey(raw: string): Buffer {
  // Accept hex (64 chars) or base64 (44 chars w/ padding) of 32 bytes.
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return Buffer.from(raw, "hex");
  }
  // base64: tolerate either padded ("=") or unpadded forms; both must
  // decode to exactly 32 bytes.
  try {
    const buf = Buffer.from(raw, "base64");
    if (buf.length === KEY_LEN_BYTES) return buf;
  } catch {
    // fall through to throw below
  }
  throw new Error(
    "TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes " +
      "(64 hex chars or base64 of 32 bytes). " +
      TOTP_KEY_HELP,
  );
}

function deriveEncryptionKey(): Buffer {
  const fromEnv = process.env.TOTP_ENCRYPTION_KEY;
  if (typeof fromEnv !== "string" || fromEnv.length === 0) {
    throw new Error(
      "TOTP_ENCRYPTION_KEY is not set. " + TOTP_KEY_HELP,
    );
  }
  return parseEncryptionKey(fromEnv);
}

// Module-local cache for the derived AES key. Primed at boot by
// `assertTotpKeyConfigured()`; falls back to lazy derivation on first
// use (e.g. tests that import this module without a boot path).
let cachedKey: Buffer | null = null;

// Eager boot-time validation. server/index.ts calls this BEFORE the
// HTTP listener binds, so a missing/invalid TOTP key fails the process
// immediately rather than waiting for the first 2FA enrollment to
// blow up at runtime. Also primes `cachedKey` so the value validated
// at boot is guaranteed to be the same Buffer used by every subsequent
// encrypt/decrypt — even if process.env.TOTP_ENCRYPTION_KEY is later
// mutated in-process. Idempotent: re-calling after a successful
// derivation is a no-op.
export function assertTotpKeyConfigured(): void {
  if (cachedKey === null) cachedKey = deriveEncryptionKey();
}

function getKey(): Buffer {
  if (cachedKey === null) cachedKey = deriveEncryptionKey();
  return cachedKey;
}

// Wire format: `${ivHex}:${ciphertextHex}:${tagHex}`. Storing the IV
// inline (not at the start of a single binary blob) keeps the column
// human-debuggable and matches the existing project convention for
// 3-part wrapped values (see crypto/encryption format docs in
// replit.md). We DO NOT include a version tag — a future re-key will
// require a migration step that re-encrypts every row, at which point
// a versioned format can be introduced.
export function encryptTotpSecret(secret: string): string {
  const iv = randomBytes(IV_LEN_BYTES);
  const cipher = createCipheriv("aes-256-gcm", getKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(secret, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${encrypted.toString("hex")}:${tag.toString("hex")}`;
}

// Returns null on any decryption failure (wrong key, corrupted blob,
// truncated tag) so callers can treat "couldn't decrypt" as "no usable
// secret" without a try/catch at every callsite. We deliberately do
// NOT log the error message — a GCM tag mismatch could include
// attacker-controlled data and should not reach console.
export function decryptTotpSecret(wrapped: string): string | null {
  try {
    const parts = wrapped.split(":");
    if (parts.length !== 3) return null;
    const [ivHex, dataHex, tagHex] = parts;
    if (!/^[0-9a-fA-F]+$/.test(ivHex)) return null;
    if (!/^[0-9a-fA-F]+$/.test(dataHex)) return null;
    if (!/^[0-9a-fA-F]+$/.test(tagHex)) return null;
    const iv = Buffer.from(ivHex, "hex");
    const data = Buffer.from(dataHex, "hex");
    const tag = Buffer.from(tagHex, "hex");
    if (iv.length !== IV_LEN_BYTES) return null;
    if (tag.length !== TAG_LEN_BYTES) return null;
    const decipher = createDecipheriv("aes-256-gcm", getKey(), iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public TOTP API
// ---------------------------------------------------------------------------

// 160 bits of entropy as base32 — RFC 6238 / RFC 4226 recommended size.
// otplib's generateSecret() defaults to 20 bytes, exactly this. Uses
// the audited noble crypto under the hood (no native bindings — works
// in every runtime).
export function generateTotpSecret(): string {
  return generateSecret({
    length: 20,
    crypto: cryptoPlugin,
    base32: base32Plugin,
  });
}

// Verify a 6-digit code against a base32 secret. Tolerance of 30s
// (1 step on either side) absorbs client clock skew per RFC 6238.
// Returns false on any malformed input rather than throwing — the
// route layer will surface 401 and the user can retry.
export function verifyTotp(secret: string, token: string): boolean {
  if (typeof secret !== "string" || secret.length === 0) return false;
  if (typeof token !== "string" || !/^\d{6}$/.test(token)) return false;
  try {
    const result = verifySync({
      strategy: "totp",
      secret,
      token,
      epochTolerance: TOTP_TOLERANCE_SECONDS,
      algorithm: TOTP_ALGORITHM,
      digits: TOTP_DIGITS,
      period: TOTP_PERIOD,
      crypto: cryptoPlugin,
      base32: base32Plugin,
    });
    return result.valid === true;
  } catch {
    // verifySync throws on a malformed base32 secret. Treat as "no"
    // rather than crashing the request — the server is the source of
    // the secret so a malformed value here means we have a corrupted
    // DB row, not a malicious client.
    return false;
  }
}

// Synchronous code generator — used ONLY by the test harness to
// derive a "current" code for a known secret. The production code
// path never generates codes server-side (the user's authenticator
// app does). Exported so tests don't need to re-implement TOTP.
export function generateTotpToken(secret: string): string {
  return generateSync({
    strategy: "totp",
    secret,
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    crypto: cryptoPlugin,
    base32: base32Plugin,
  });
}

// Build the otpauth:// URL that authenticator apps consume to
// provision the secret (typically rendered as a QR code on the
// client). Format follows the de-facto Google Authenticator URI:
//   otpauth://totp/{issuer}:{label}?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
//
// otplib's generateURI handles encoding for both the issuer and the
// label so a username with a colon, slash, or space (any of which
// are legal per usernameSchema's 3-64 char range without further
// restriction) cannot break the URI shape and confuse the client app.
export function buildOtpauthUrl(input: {
  secret: string;
  username: string;
  issuer?: string;
}): string {
  const issuer = input.issuer ?? "PiPass";
  return generateURI({
    strategy: "totp",
    issuer,
    label: input.username,
    secret: input.secret,
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
  });
}
