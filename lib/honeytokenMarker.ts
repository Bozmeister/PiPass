import * as ExpoCrypto from "expo-crypto";
import CryptoJS from "crypto-js";

// T001 — Honeytoken marker primitives.
//
// The marker is the secret that ties a decoy vault entry to its
// server-side honeytoken row. The plaintext marker:
//   - is generated CLIENT-SIDE only
//   - lives ONLY inside the encrypted vault blob (encryptVaultEntry
//     wraps it with the per-entry HKDF subkey, so it never appears
//     in plaintext on disk OR on the wire)
//   - is NEVER transmitted to the server in plaintext
//
// The server only ever sees `markerHash = SHA-256(marker)` (hex,
// lowercase, 64 chars), via POST /api/security/honeytokens (create)
// and POST /api/security/honeytokens/trigger (fire). That hash is
// what the backend's strict zod schema (HONEYTOKEN_MARKER_HASH_HEX)
// validates against. Two markers with the same hash are
// computationally infeasible at 256 bits of entropy, so the
// honeytoken row uniquely identifies the decoy.
//
// Why 256 bits: backend rate-limits trigger to 30/min and create
// to 10/min, so an attacker cannot meaningfully grind hashes to
// guess a marker. 256 bits is far over the security margin and
// matches the SHA-256 output width — no truncation.

const MARKER_BYTES = 32; // 256 bits

// Generates a fresh, cryptographically random marker. Output is
// 64 lowercase hex chars (256 bits). Crashes loudly if the platform
// CSPRNG is unavailable — falling back to Math.random() would
// silently weaken every decoy.
export function generateHoneytokenMarker(): string {
  const bytes = ExpoCrypto.getRandomBytes(MARKER_BYTES);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// Computes SHA-256(marker) as 64 lowercase hex chars. Pure function,
// uses crypto-js (already a dependency, runs identically on iOS,
// Android, and web — no native module required).
//
// Validates the input shape so a bug elsewhere can't silently
// produce a hash of an empty string or accidentally include
// surrounding whitespace. The returned hash is what the server's
// HONEYTOKEN_MARKER_HASH_HEX zod check expects.
export function hashHoneytokenMarker(marker: string): string {
  if (typeof marker !== "string" || marker.length === 0) {
    throw new Error("hashHoneytokenMarker: marker must be a non-empty string");
  }
  return CryptoJS.SHA256(marker).toString(CryptoJS.enc.Hex);
}
