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
  createHash,
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
// Key source order:
//   1. process.env.TOTP_ENCRYPTION_KEY (preferred — operator-managed)
//      Must be 64 hex chars (32 bytes) or base64 of 32 bytes.
//   2. SHA-256 of process.env.SESSION_SECRET (existing app secret, if any)
//   3. SHA-256 of process.env.DATABASE_URL (last-resort dev fallback)
//
// Path #3 lets local dev work without extra config — it derives a
// stable key from a value the dev environment already has. It is
// deliberately NOT acceptable in production: every prod deployment
// must set TOTP_ENCRYPTION_KEY explicitly. We log a warning on boot if
// we fall through to #2 or #3.
const KEY_LEN_BYTES = 32; // AES-256
const IV_LEN_BYTES = 12; // GCM standard nonce length
const TAG_LEN_BYTES = 16; // GCM auth tag

function deriveEncryptionKey(): Buffer {
  const fromEnv = process.env.TOTP_ENCRYPTION_KEY;
  if (typeof fromEnv === "string" && fromEnv.length > 0) {
    // Accept hex (64 chars) or base64 (44 chars w/ padding) of 32 bytes.
    if (/^[0-9a-fA-F]{64}$/.test(fromEnv)) {
      return Buffer.from(fromEnv, "hex");
    }
    try {
      const buf = Buffer.from(fromEnv, "base64");
      if (buf.length === KEY_LEN_BYTES) return buf;
    } catch {
      // fall through to error
    }
    throw new Error(
      "TOTP_ENCRYPTION_KEY must be 32 bytes (64 hex chars or 44 base64 chars).",
    );
  }
  const sessionSecret = process.env.SESSION_SECRET;
  if (typeof sessionSecret === "string" && sessionSecret.length > 0) {
    if (process.env.NODE_ENV === "production") {
      console.warn(
        "[totp] Falling back to SHA-256(SESSION_SECRET) for TOTP encryption. " +
          "Set TOTP_ENCRYPTION_KEY explicitly in production.",
      );
    }
    return createHash("sha256").update(sessionSecret).digest();
  }
  const dbUrl = process.env.DATABASE_URL;
  if (typeof dbUrl === "string" && dbUrl.length > 0) {
    if (process.env.NODE_ENV === "production") {
      console.warn(
        "[totp] Falling back to SHA-256(DATABASE_URL) for TOTP encryption. " +
          "Set TOTP_ENCRYPTION_KEY explicitly in production.",
      );
    }
    return createHash("sha256").update(dbUrl).digest();
  }
  throw new Error(
    "TOTP encryption key cannot be derived: set TOTP_ENCRYPTION_KEY (or " +
      "SESSION_SECRET, or DATABASE_URL) in the environment.",
  );
}

// Lazy single-shot derivation. Throws on first use if no source is
// available — that's the right time to fail (the server is already up
// and serving non-TOTP routes; the explosion happens only when someone
// actually touches the TOTP flow). We do NOT cache the env var directly
// at module load so a missing-but-later-set value (devs editing .env
// without restart) still surfaces with the right error message.
let cachedKey: Buffer | null = null;
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
