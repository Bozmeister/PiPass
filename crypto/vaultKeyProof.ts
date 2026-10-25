/**
 * Vault-key proof-of-possession for cloud sync / restore.
 *
 * Session auth is not enough to overwrite a cloud blob. The client must
 * also send HMAC-SHA256(masterKey, "pipass.vault.pop.v1|" + userId).
 * The server stores SHA-256(proof), never the master key.
 *
 * Local-only vaults never call this.
 */

import CryptoJS from "crypto-js";

export const VAULT_KEY_PROOF_INFO = "pipass.vault.pop.v1";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX_KEY = /^[0-9a-f]{64}$/i;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isWellFormedVaultKeyProof(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

/**
 * Build the 64-hex HMAC proof from the 32-byte master key and account id.
 */
export function createVaultKeyProof(masterKeyHex: string, userId: string): string {
  if (!HEX_KEY.test(masterKeyHex)) {
    throw new Error("createVaultKeyProof: master key must be 32-byte hex");
  }
  if (!UUID.test(userId)) {
    throw new Error("createVaultKeyProof: userId must be a UUID");
  }
  return CryptoJS.HmacSHA256(
    `${VAULT_KEY_PROOF_INFO}|${userId.toLowerCase()}`,
    CryptoJS.enc.Hex.parse(masterKeyHex.toLowerCase()),
  ).toString(CryptoJS.enc.Hex);
}
