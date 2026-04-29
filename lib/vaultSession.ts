import type { KeyShares } from "../crypto/secureMemory";
import { wipeShares } from "../crypto/secureMemory";

// Module-level holder for the currently-unlocked vault key shares.
//
// Background: the master-key shares used to be private state inside
// VaultScreen (`keySharesRef.current`), which meant only that one
// component could decrypt vault entries. The honeytoken UX (T002,
// T006) needs to encrypt/decrypt entries from a sibling screen
// (`app/(tabs)/settings/honeytokens.tsx`) — without a shared
// holder, the management screen would have to re-prompt the user
// for the master password just to add or strip a decoy field.
//
// Threat model note: this does NOT widen the attack surface beyond
// what was already there. The shares were already alive in JS heap
// memory while unlocked; making them readable from another module
// in the same JS bundle adds no new path for an attacker. The
// shares are still XOR-split at rest in memory (per
// crypto/secureMemory.ts), wiped on lock, and never written to
// disk or sent to the server.
//
// Discipline:
//   - VaultScreen is the SOLE writer. It calls setActiveKeyShares
//     whenever keySharesRef.current changes (unlock, password
//     rotation) and clearActiveKeyShares on lock.
//   - Other screens are READERS ONLY. They MUST gracefully handle
//     null (== "vault is locked, ask the user to unlock first").
//   - Never persist this value. Never copy it into a closure that
//     outlives the unlock window.

let activeShares: KeyShares | null = null;

// Set or replace the active shares. Passing the SAME shares object
// repeatedly is safe (no-op). Replacing wipes the previous shares
// because retaining the old ones is dead-weight risk.
export function setActiveKeyShares(shares: KeyShares | null): void {
  if (activeShares && activeShares !== shares) {
    try {
      wipeShares(activeShares);
    } catch {
      // wipeShares is defensive but should never throw; swallow
      // anyway so a corrupted previous state can't block setting
      // the new one.
    }
  }
  activeShares = shares;
}

// Read-only accessor. Returns null when the vault is locked.
// Callers MUST check for null and surface a "vault locked" path
// rather than crashing.
export function getActiveKeyShares(): KeyShares | null {
  return activeShares;
}

// Convenience wiper. Equivalent to setActiveKeyShares(null) but
// reads more clearly at call sites that explicitly mean "lock".
export function clearActiveKeyShares(): void {
  setActiveKeyShares(null);
}
