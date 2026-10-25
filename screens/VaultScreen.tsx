import React, { useState, useEffect, useMemo, useRef } from "react";
import { 
  View, Text, FlatList, Pressable, Alert, Platform, 
  ActivityIndicator, AppState, Modal, Switch, TextInput 
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useRouter, useFocusEffect } from "expo-router";
import { 
  VaultEntry, 
  SecureNote, 
  DecryptedVaultEntry,
  encryptVaultEntry,
  decryptVaultEntry,
  reEncryptEntry,
  reEncryptSecureNote,
} from "../workers/vaultWorker";
import { enableScreenCaptureProtection } from "../lib/screenCaptureProtection";

import { 
  getAllEntries, 
  saveEntry, 
  deleteEntry as deleteStoredEntry, 
  destroyAllData, 
  saveSecureNote,
  getAllSecureNotes,
  getShowKeyprints, 
  saveShowKeyprints,
  getMasterSalt,
  getMasterKeyHash,
  getKdfMetadataState,
  saveMasterKeyHash,
  saveKdfMetadata,
  saveFractalFingerprint,
  getFractalFingerprint,
  FractalFingerprintRecord,
  migrateToSharedStorage,
  storeMasterKeySecurely,
  hasLocalEncryptedVaultData,
  buildArgon2idKdfMetadata,
  buildPbkdf2KdfMetadata,
  KDF_DEVICE_BINDING_NONE,
} from "../workers/storageWorker";

import { KeyShares, wipeShares, combineShares, hexToBytes, wipeBuffer, splitKeyIntoShares } from "../crypto/secureMemory";
import { setActiveKeyShares, clearActiveKeyShares } from "../lib/vaultSession";
import {
  hashMasterKey,
  planUnlockKdfDerivation,
  getArgon2idKdfParameters,
  getStrongPbkdf2FallbackParameters,
  deriveMasterKeyWithArgon2id,
  deriveMasterKeyWithPbkdf2,
  KdfDerivationError,
} from "../crypto/keyDerivation";
import { verifyMasterPasswordWithStoredKdf } from "../lib/currentUnlock";
import { requireFreshBiometric } from "../crypto/biometricGate";
import { sanitizeEntryFields } from "../crypto/hyperbaricSanitizer";
import { deriveFractalSeed, deriveFractalSeedLegacy, FractalParams, DEFAULT_FRACTAL_PARAMS } from "../crypto/hkdf";
import { INPUT_BG, INPUT_TEXT, INPUT_PLACEHOLDER, INPUT_BORDER, INPUT_BORDER_FOCUS } from "../styles/inputTheme";

import AddEntryModal from "../components/AddEntryModal";
import EntryDetailModal from "../components/EntryDetailModal";
import DeleteEntryModal from "../components/DeleteEntryModal";
import SecureNotesModal from "../components/SecureNotesModal";
import FractalKeyprint from "../components/FractalKeyprint";
import AnimatedFractalView from "../components/AnimatedFractalView";
import KeyprintViewer from "../components/KeyprintViewer";
import FaviconImage from "../components/FaviconImage";
import NuclearResetModal from "../components/NuclearResetModal";
import FractalBackground from "../components/FractalBackground";
import { useSecurityState } from "../context/SecurityContext";
import {
  visibleVaultEntries,
  type SearchIndexPlain,
  type SearchSort,
} from "../lib/vaultSearch";
import {
  rebuildSearchIndex,
  removeStoredSearchRecord,
  upsertVaultEntrySearch,
  loadSearchIndex,
} from "../lib/vaultSearchStore";
import { formatFeatureStatus, reportFeatureStatus } from "../lib/intentdb/featureStatus";

const AUTO_LOCK_MS = 120000;
const PROFILE_CHANGE_PAUSED_TITLE = "Profile changes are paused";
const PROFILE_CHANGE_REENCRYPTION_MESSAGE =
  "Changing the security profile changes the vault key path. A safe re-encryption flow is required before this can be enabled for vaults that contain entries or secure notes.";
const PROFILE_CHANGE_VERIFY_MESSAGE =
  "PiPass could not verify whether this vault contains entries or secure notes, so the profile was left unchanged.";

const PROFILES = [
  { label: "Balanced", iterations: 25000, time: "~3s", desc: "Fast unlock", color: "#4CAF50", icon: "flash-outline" as const },
  { label: "Fortress", iterations: 100000, time: "~8s", desc: "Recommended", color: "#fbbf24", icon: "shield-checkmark-outline" as const },
  { label: "Deep Vault", iterations: 250000, time: "~20s", desc: "Maximum protection", color: "#ef4444", icon: "lock-closed-outline" as const },
];

interface VaultScreenProps {
  keyShares: KeyShares | null;
  iterations: number;
  locked?: boolean;
  onLock: () => void;
  onIterationsChange: (iterations: number) => void;
  onReset: () => void;
}

function deriveVisualSeedFromHkdf(shares: KeyShares): { seedNumber: number; fingerprint: string; fractalParams: FractalParams } {
  const keyHex = combineShares(shares);
  const result = deriveFractalSeed(keyHex);
  const keyBytes = hexToBytes(keyHex);
  wipeBuffer(keyBytes);
  return result;
}

export default function VaultScreen({ keyShares, iterations, locked = false, onLock, onIterationsChange, onReset }: VaultScreenProps) {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  // T002 — fractal reads from this so it shifts color/glow whenever
  // the audit endpoint reports a posture change.
  const securityState = useSecurityState();
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const keySharesRef = useRef<KeyShares | null>(keyShares);
  const isBiometricActive = useRef(false);

  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<VaultEntry | null>(null);
  const [decryptedEntry, setDecryptedEntry] = useState<DecryptedVaultEntry | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [secureNotes, setSecureNotes] = useState<SecureNote[]>([]);
  const [showSecureNotes, setShowSecureNotes] = useState(false);
  const [showKeyprints, setShowKeyprints] = useState(true);
  const [showKeyprintViewer, setShowKeyprintViewer] = useState(false);
  const [pendingProfileIterations, setPendingProfileIterations] = useState<number | null>(null);
  const [profilePassword, setProfilePassword] = useState("");
  const [profilePasswordFocused, setProfilePasswordFocused] = useState(false);
  const [showNuclearReset, setShowNuclearReset] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [deleteTargetTitle, setDeleteTargetTitle] = useState("");
  const [showUndoSnackbar, setShowUndoSnackbar] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchSort, setSearchSort] = useState<SearchSort>("none");
  const [searchIndex, setSearchIndex] = useState<SearchIndexPlain | null>(null);

  const recentlyDeletedEntryRef = useRef<VaultEntry | null>(null);
  const undoTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const settingsTapCountRef = useRef(0);
  const settingsTapTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lastActivityRef = useRef<number>(Date.now());
  const autoLockTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const selectTokenRef = useRef<number>(0);

  const initialFractal = useRef(keyShares ? deriveVisualSeedFromHkdf(keyShares) : { seedNumber: 0, fingerprint: "", fractalParams: { cx: -0.7, cy: 0, zoom: 1, maxIterations: 100 } }).current;
  const [fractalSeedNumber, setFractalSeedNumber] = useState(initialFractal.seedNumber);
  const [fractalFingerprint, setFractalFingerprint] = useState(initialFractal.fingerprint);
  const [fractalParams, setFractalParams] = useState<FractalParams>(initialFractal.fractalParams);
  const visualSeed = fractalSeedNumber;
  const [fractalTampered, setFractalTampered] = useState(false);

  useEffect(() => {
    keySharesRef.current = keyShares;
    // Mirror into the cross-screen vault session holder so sibling
    // routes (e.g. settings/honeytokens) can encrypt/decrypt entries
    // without re-prompting the user. Passing null on lock clears
    // (and wipes) the previous shares — see lib/vaultSession.ts.
    setActiveKeyShares(keyShares);
    if (!keyShares) {
      clearActiveKeyShares();
    }
  }, [keyShares]);

  useEffect(() => {
    if (locked) {
      // Drop any plaintext list fields held in React state (titles,
      // usernames, urls injected by withDisplayFields). Ciphertext-only
      // reload happens after full password unlock.
      setEntries([]);
      setSecureNotes([]);
      setSearchIndex(null);
      setSearchQuery("");
      setSearchSort("none");
      setSelectedEntry(null);
      setDecryptedEntry(null);
      setDecrypting(false);
      setShowSettings(false);
      setShowSecureNotes(false);
      setShowKeyprintViewer(false);
      setShowNuclearReset(false);
      setShowDeleteModal(false);
      setDeleteTargetId(null);
      setDeleteTargetTitle("");
      commitPendingDeletion();
      setPendingProfileIterations(null);
      setProfilePassword("");
      recentlyDeletedEntryRef.current = null;
      selectTokenRef.current++;
      // Defensive: vaultSession must not retain key material while locked.
      if (!keySharesRef.current) {
        clearActiveKeyShares();
      }
    }
  }, [locked]);

  // After a hard lock, entries were cleared from memory. Re-hydrate
  // ciphertext + display fields only when key shares are available again
  // (full master-password unlock), not from retained soft-lock state.
  useEffect(() => {
    if (locked || !keyShares) return;
    let cancelled = false;
    (async () => {
      try {
        const stored = await getAllEntries();
        if (cancelled) return;
        const notes = await getAllSecureNotes();
        if (cancelled) return;
        setEntries(stored);
        setSecureNotes(notes);
        try {
          const index = await rebuildSearchIndex(keyShares, stored, notes);
          if (!cancelled) setSearchIndex(index);
        } catch {
          if (!cancelled) {
            setSearchIndex(null);
            setEntries(withDisplayFields(stored));
          }
        }
      } catch {
        // Non-fatal: user can retry by reopening the vault tab.
      }
      if (cancelled) return;
      try {
        const line = formatFeatureStatus(await reportFeatureStatus());
        if (!cancelled) console.info(line);
      } catch {
        // A status line must not fail unlock.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [locked, keyShares]);

  // Bind / verify fractal fingerprint whenever key material is available.
  // Integrity is based on the fingerprint string (derived from the master key).
  // Metadata (iterations / kdf label) is self-healed when the fingerprint matches
  // so newly created Argon2id/PBKDF2 vaults never false-alarm "tampering".
  useEffect(() => {
    if (!keyShares) return;
    const result = refreshFractalFromShares(keyShares);
    void verifyFractalFingerprint(result.fingerprint);
  }, [keyShares, iterations]);

  function buildFingerprintRecord(fp: string): FractalFingerprintRecord {
    // Fractal is derived from master key only; kdf label is informational.
    // Prefer argon2id for new binds; unlock path may self-heal over pbkdf2-sha256 records.
    return { fingerprint: fp, iterations, kdf: "argon2id", version: 1 };
  }

  function getLegacyFingerprint(): string {
    if (!keySharesRef.current) return "";
    const keyHex = combineShares(keySharesRef.current);
    const legacy = deriveFractalSeedLegacy(keyHex);
    const kb = hexToBytes(keyHex);
    wipeBuffer(kb);
    return legacy.fingerprint;
  }

  function isValidRecord(v: unknown): v is FractalFingerprintRecord {
    if (!v || typeof v !== "object") return false;
    const r = v as Record<string, unknown>;
    return (
      typeof r.fingerprint === "string" &&
      r.fingerprint.length > 0 &&
      typeof r.iterations === "number" &&
      (r.kdf === "argon2id" || r.kdf === "pbkdf2-sha256") &&
      r.version === 1
    );
  }

  async function verifyFractalFingerprint(currentFingerprint: string) {
    // Never bind or compare an empty fingerprint (mount-before-key race).
    if (!currentFingerprint || currentFingerprint.length < 16) {
      return;
    }

    try {
      const legacyFp = getLegacyFingerprint();
      const stored = await getFractalFingerprint();
      const expected = buildFingerprintRecord(currentFingerprint);

      if (stored === null) {
        // First unlock of this vault — bind current fingerprint.
        await saveFractalFingerprint(expected);
        setFractalTampered(false);
        return;
      }

      if (typeof stored === "string") {
        if (stored === currentFingerprint || (legacyFp && stored === legacyFp)) {
          await saveFractalFingerprint(expected);
          setFractalTampered(false);
          return;
        }
        setFractalTampered(true);
        return;
      }

      const storedFp =
        stored && typeof stored === "object" && typeof (stored as FractalFingerprintRecord).fingerprint === "string"
          ? (stored as FractalFingerprintRecord).fingerprint
          : "";

      // Primary integrity signal: fingerprint matches current or legacy derivation.
      if (
        storedFp === currentFingerprint ||
        (legacyFp && storedFp === legacyFp)
      ) {
        // Self-heal metadata (iterations/kdf/version) without warning.
        if (
          !isValidRecord(stored) ||
          stored.fingerprint !== expected.fingerprint ||
          stored.iterations !== expected.iterations ||
          stored.kdf !== expected.kdf ||
          stored.version !== expected.version
        ) {
          await saveFractalFingerprint(expected);
        }
        setFractalTampered(false);
        return;
      }

      // Genuine mismatch — different master-key visual identity.
      setFractalTampered(true);
    } catch (err) {
      console.error("[VAULT] verifyFractalFingerprint failed");
      // Fail open: do not brick the vault UI on storage/read errors.
    }
  }

  function refreshFractalFromShares(shares: KeyShares) {
    const result = deriveVisualSeedFromHkdf(shares);
    setFractalSeedNumber(result.seedNumber);
    setFractalFingerprint(result.fingerprint);
    setFractalParams(result.fractalParams);
    return result;
  }

  // Screen capture is blocked app-wide (root layout) for production native builds.
  // Re-assert here when the vault is visible; never call allowScreenCaptureAsync —
  // that previously re-enabled capture on unmount and cleared Android FLAG_SECURE.
  useEffect(() => {
    void enableScreenCaptureProtection();
  }, []);

  const lockedRef = useRef(locked);
  useEffect(() => { lockedRef.current = locked; }, [locked]);

  useEffect(() => {
    if (!locked) {
      lastActivityRef.current = Date.now();
    }
  }, [locked]);

  // T002 — Reload entries when the Vault tab regains focus.
  //
  // The honeytoken management screen (settings/honeytokens) writes
  // a new decoy directly into shared storage via saveEntry(). With
  // tab-preserved mount state, VaultScreen wouldn't see that new
  // entry until the user fully relaunches the app — useFocusEffect
  // bridges the gap. Skipped while locked because loadVault() also
  // tries to decrypt a sample entry to verify the key matches, and
  // there's no key while locked.
  //
  // Guarded against the initial mount (loadVault is already called
  // in the next useEffect) by tracking whether we've seen the
  // first focus yet — otherwise the first focus would fire two
  // identical loadVault calls in parallel.
  const hasSeenFirstFocusRef = useRef(false);
  useFocusEffect(
    React.useCallback(() => {
      if (!hasSeenFirstFocusRef.current) {
        hasSeenFirstFocusRef.current = true;
        return;
      }
      if (lockedRef.current) return;
      // Reload silently — no setLoading(true) so the user doesn't
      // see a flash of the loading state on every tab switch.
      getAllEntries()
        .then(async (stored) => {
          if (lockedRef.current) return;
          setEntries(stored);
          const shares = keySharesRef.current;
          if (!shares) return;
          const loaded = await loadSearchIndex(shares);
          const indexedIds = new Set(
            loaded.ok
              ? loaded.index.records.filter((record) => record.kind === "vault-entry").map((record) => record.id)
              : [],
          );
          const stale = !loaded.ok || stored.some((entry) => !indexedIds.has(entry.id));
          if (!stale && loaded.ok) {
            setSearchIndex(loaded.index);
            return;
          }
          const notes = await getAllSecureNotes();
          if (lockedRef.current || !keySharesRef.current) return;
          try {
            setSearchIndex(await rebuildSearchIndex(keySharesRef.current, stored, notes));
          } catch {
            setSearchIndex(null);
          }
        })
        .catch(() => {
          // Silent: a refetch failure is non-fatal; the user can
          // pull-to-refresh or wait for the next focus.
        });
    }, []),
  );

  useEffect(() => {
    loadVault();
    const appStateSub = AppState.addEventListener("change", (state) => {
      if ((state === "background" || state === "inactive") && !isBiometricActive.current && !lockedRef.current) {
        onLock();
      }
    });
    return () => {
      if (autoLockTimerRef.current) clearInterval(autoLockTimerRef.current);
      if (undoTimerRef.current) {
        clearTimeout(undoTimerRef.current);
        if (recentlyDeletedEntryRef.current) {
          deleteStoredEntry(recentlyDeletedEntryRef.current.id).catch(() => {});
          recentlyDeletedEntryRef.current = null;
        }
      }
      appStateSub.remove();
    };
  }, []);

  function resetActivity() {
    if (!lockedRef.current) lastActivityRef.current = Date.now();
  }

  /** Attach decrypted title/username/url for list display (encrypted-only entries have blank plaintext fields). */
  function withDisplayFields(stored: VaultEntry[]): VaultEntry[] {
    const shares = keySharesRef.current;
    if (!shares) return stored;
    return stored.map((e) => {
      try {
        const d = decryptVaultEntry(e, shares);
        return {
          ...e,
          title: d.title,
          username: d.username,
          url: d.url,
        };
      } catch {
        return e;
      }
    });
  }

  async function reloadEntries() {
    const stored = await getAllEntries();
    setEntries(stored);
  }

  async function syncSearchEntry(entry: VaultEntry) {
    const shares = keySharesRef.current;
    if (!shares || lockedRef.current) return;
    try {
      const updated = await upsertVaultEntrySearch(shares, entry);
      if (updated) {
        setSearchIndex(updated);
        return;
      }
      const stored = await getAllEntries();
      const notes = await getAllSecureNotes();
      setSearchIndex(await rebuildSearchIndex(shares, stored, notes));
    } catch {
      // The next unlock rebuilds the index.
    }
  }

  async function loadVault() {
    try {
      await migrateToSharedStorage();

      const keyprintPref = await getShowKeyprints();
      setShowKeyprints(keyprintPref);

      const stored = await getAllEntries();
      const notes = await getAllSecureNotes();
      setEntries(stored);
      setSecureNotes(notes);
      if (keySharesRef.current && !lockedRef.current) {
        try {
          setSearchIndex(await rebuildSearchIndex(keySharesRef.current, stored, notes));
        } catch {
          setSearchIndex(null);
          setEntries(withDisplayFields(stored));
        }
      }

      if (stored.length > 0 && keySharesRef.current) {
        try {
          decryptVaultEntry(stored[0], keySharesRef.current);
        } catch {
          Alert.alert("Key Mismatch", "The stored entries don't match your current key. Clear & Start Fresh?", [
            { text: "Clear", style: "destructive", onPress: async () => { await destroyAllData(); onReset(); } }
          ]);
        }
      }
    } catch (err) {
      Alert.alert("Error", "Failed to load vault.", [
        { text: "Try Again", onPress: () => loadVault() },
        { text: "Wipe Data", style: "destructive", onPress: async () => { await destroyAllData(); onReset(); } },
      ]);
    }
    setLoading(false);
    resetActivity();

    autoLockTimerRef.current = setInterval(() => {
      if (!lockedRef.current && Date.now() - lastActivityRef.current > AUTO_LOCK_MS) onLock();
    }, 5000);
  }

  async function handleAddEntry(entry: any) {
    if (!keySharesRef.current || lockedRef.current) return;

    const { sanitized, ok, error } = sanitizeEntryFields(entry);
    if (!ok) {
      Alert.alert("Sanitization Error", error || "Input rejected.");
      return;
    }

    const encrypted = encryptVaultEntry(sanitized, keySharesRef.current);
    await saveEntry(encrypted);
    await syncSearchEntry(encrypted);
    await reloadEntries();
    setShowAddModal(false);
  }

  async function handleUpdateEntry(entry: {
    title: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
  }) {
    if (!keySharesRef.current || lockedRef.current || !selectedEntry || !decryptedEntry) return;

    const { sanitized, ok, error } = sanitizeEntryFields(entry);
    if (!ok) {
      Alert.alert("Sanitization Error", error || "Input rejected.");
      return;
    }

    const encrypted = encryptVaultEntry(
      {
        ...sanitized,
        // Preserve honeytoken status across edits
        isHoneytoken: decryptedEntry.isHoneytoken,
        honeytokenId: decryptedEntry.honeytokenId,
        honeytokenMarker: decryptedEntry.honeytokenMarker,
      },
      keySharesRef.current,
      selectedEntry.id,
    );
    // Keep original creation time; encryptVaultEntry stamps both to "now".
    encrypted.createdAt = selectedEntry.createdAt;
    encrypted.updatedAt = Date.now();

    await saveEntry(encrypted);
    await syncSearchEntry(encrypted);
    await reloadEntries();
    setSelectedEntry(null);
    setDecryptedEntry(null);
    setShowEditModal(false);
  }

  async function handleSelectEntry(entry: VaultEntry) {
    if (!keySharesRef.current || lockedRef.current) return;
    const token = ++selectTokenRef.current;
    setDecrypting(true);
    setSelectedEntry(entry);
    setDecryptedEntry(null);
    try {
      isBiometricActive.current = true;
      const authenticated = await requireFreshBiometric();
      isBiometricActive.current = false;

      if (selectTokenRef.current !== token) return;

      if (!authenticated) {
        setSelectedEntry(null);
        setDecrypting(false);
        return;
      }

      if (!keySharesRef.current) {
        Alert.alert("Vault Locked", "Vault was locked during authentication.");
        setSelectedEntry(null);
        setDecrypting(false);
        return;
      }

      const decrypted = decryptVaultEntry(entry, keySharesRef.current);
      if (selectTokenRef.current !== token) return;
      setDecryptedEntry(decrypted);
    } catch (err) {
      if (selectTokenRef.current === token) {
        Alert.alert("Decryption Error", "Something went wrong.");
        setSelectedEntry(null);
      }
    } finally {
      isBiometricActive.current = false;
      if (selectTokenRef.current === token) setDecrypting(false);
    }
  }

  async function commitPendingDeletion() {
    if (undoTimerRef.current) {
      clearTimeout(undoTimerRef.current);
      undoTimerRef.current = null;
    }
    const pending = recentlyDeletedEntryRef.current;
    if (pending) {
      recentlyDeletedEntryRef.current = null;
      setShowUndoSnackbar(false);
      try {
        await deleteStoredEntry(pending.id);
        if (keySharesRef.current) {
          const next = await removeStoredSearchRecord(keySharesRef.current, pending.id, "vault-entry");
          if (next) setSearchIndex(next);
        }
      } catch {
        setEntries(prev => [...prev, pending].sort((a, b) => b.createdAt - a.createdAt));
        Alert.alert("Delete Failed", "Could not permanently delete the entry. It has been restored to your vault.");
      }
    }
  }

  function handleRequestDelete(entryId: string) {
    const target = entries.find(e => e.id === entryId);
    if (!target) return;
    const indexed = searchIndex?.records.find(
      (record) => record.id === entryId && record.kind === "vault-entry",
    );

    Alert.alert(
      "Delete entry?",
      "This will permanently delete this vault item from this device and from sync.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Delete",
          style: "destructive",
          onPress: () => beginSecureDeleteFlow(entryId, indexed?.title || target.title || "Untitled entry"),
        },
      ]
    );
  }

  async function beginSecureDeleteFlow(entryId: string, entryTitle: string) {
    try {
      isBiometricActive.current = true;
      const authenticated = await requireFreshBiometric();
      isBiometricActive.current = false;

      if (!authenticated) return;
      if (lockedRef.current) return;

      setDeleteTargetId(entryId);
      setDeleteTargetTitle(entryTitle);
      setShowDeleteModal(true);
    } catch {
      isBiometricActive.current = false;
    }
  }

  function handleConfirmDelete() {
    if (!deleteTargetId) return;

    const targetEntry = entries.find(e => e.id === deleteTargetId);
    if (!targetEntry) return;

    commitPendingDeletion();

    recentlyDeletedEntryRef.current = targetEntry;
    setEntries(prev => prev.filter(e => e.id !== deleteTargetId));
    setSelectedEntry(null);
    setDecryptedEntry(null);
    setShowDeleteModal(false);
    setDeleteTargetId(null);
    setDeleteTargetTitle("");
    setShowUndoSnackbar(true);

    undoTimerRef.current = setTimeout(() => {
      commitPendingDeletion();
    }, 10000);
  }

  function handleUndoDelete() {
    if (undoTimerRef.current) {
      clearTimeout(undoTimerRef.current);
      undoTimerRef.current = null;
    }
    const restored = recentlyDeletedEntryRef.current;
    recentlyDeletedEntryRef.current = null;
    setShowUndoSnackbar(false);

    if (restored) {
      setEntries(prev => [...prev, restored].sort((a, b) => b.createdAt - a.createdAt));
    }
  }

  function handleCloseDetail() {
    setSelectedEntry(null);
    setDecryptedEntry(null);
    setShowEditModal(false);
  }

  function showProfileChangePaused(message = PROFILE_CHANGE_REENCRYPTION_MESSAGE) {
    Alert.alert(PROFILE_CHANGE_PAUSED_TITLE, message);
  }

  async function handleProfileChange(newIterations: number) {
    if (newIterations === iterations || !keySharesRef.current) return;
    try {
      if (await hasLocalEncryptedVaultData()) {
        showProfileChangePaused();
        return;
      }
    } catch {
      showProfileChangePaused(PROFILE_CHANGE_VERIFY_MESSAGE);
      return;
    }

    const safeNew = Math.max(newIterations || 100000, 3);
    setPendingProfileIterations(safeNew);
    setProfilePassword("");
  }

  async function confirmProfileChange() {
    if (!pendingProfileIterations || !profilePassword.trim()) return;

    setMigrating(true);
    try {
      try {
        if (await hasLocalEncryptedVaultData()) {
          setPendingProfileIterations(null);
          setProfilePassword("");
          showProfileChangePaused();
          return;
        }
      } catch {
        showProfileChangePaused(PROFILE_CHANGE_VERIFY_MESSAGE);
        return;
      }

      const salt = await getMasterSalt();
      if (!salt) throw new Error("No salt found");

      // Verify current password against stored hash + KDF metadata (no silent downgrade).
      const passwordOk = await verifyMasterPasswordWithStoredKdf(
        { password: profilePassword, salt, iterations },
        {
          getMasterKeyHash,
          getKdfMetadataState,
          planUnlockKdfDerivation,
        },
      );
      if (!passwordOk) {
        throw new Error("Incorrect password");
      }

      // Re-derive for the NEW profile with explicit algorithm + matching metadata.
      // Prefer Argon2id; only fall back to strong PBKDF2 when Argon2 is unavailable,
      // and always persist the actual parameters used.
      let newKeyHex: string;
      let kdfLabel: "argon2id" | "pbkdf2-sha256";
      const argonParams = getArgon2idKdfParameters(pendingProfileIterations);
      try {
        newKeyHex = await deriveMasterKeyWithArgon2id(
          profilePassword,
          salt,
          argonParams,
        );
        await saveKdfMetadata(
          buildArgon2idKdfMetadata(pendingProfileIterations, argonParams, "profile-change", {
            deviceBinding: KDF_DEVICE_BINDING_NONE,
          }),
        );
        kdfLabel = "argon2id";
      } catch (err) {
        if (!(err instanceof KdfDerivationError)) throw err;
        const pbkdf2Params = getStrongPbkdf2FallbackParameters(pendingProfileIterations);
        newKeyHex = await deriveMasterKeyWithPbkdf2(
          profilePassword,
          salt,
          pbkdf2Params,
        );
        await saveKdfMetadata(
          buildPbkdf2KdfMetadata(pendingProfileIterations, pbkdf2Params, "profile-change", {
            deviceBinding: KDF_DEVICE_BINDING_NONE,
          }),
        );
        kdfLabel = "pbkdf2-sha256";
      }

      const newKeyHash = hashMasterKey(newKeyHex);
      const newShares = splitKeyIntoShares(newKeyHex);

      await saveMasterKeyHash(newKeyHash);
      await onIterationsChange(pendingProfileIterations);
      await storeMasterKeySecurely(newKeyHex);

      const newKeyBytes = hexToBytes(newKeyHex);
      wipeBuffer(newKeyBytes);

      keySharesRef.current = newShares;
      // Mirror the rotated shares into the cross-screen holder so
      // the honeytoken management screen continues to work after
      // a master-key change without forcing the user to lock/unlock.
      setActiveKeyShares(newShares);

      const newFractal = refreshFractalFromShares(newShares);
      await saveFractalFingerprint({
        fingerprint: newFractal.fingerprint,
        iterations: pendingProfileIterations,
        kdf: kdfLabel,
        version: 1,
      });
      setFractalTampered(false);

      setPendingProfileIterations(null);
      setProfilePassword("");
      Alert.alert("Profile Updated", `Now using ${PROFILES.find(p => p.iterations === pendingProfileIterations)?.label || "custom"} profile.`);
    } catch (err) {
      Alert.alert("Migration Failed", "Incorrect password or key derivation error. Settings remain unchanged.");
    } finally {
      setMigrating(false);
    }
  }

  async function verifyPasswordForReset(pw: string): Promise<boolean> {
    const salt = await getMasterSalt();
    if (!salt) return false;
    return verifyMasterPasswordWithStoredKdf(
      { password: pw, salt, iterations },
      {
        getMasterKeyHash,
        getKdfMetadataState,
        planUnlockKdfDerivation,
      },
    );
  }

  async function executeNuclearReset() {
    await destroyAllData();
    onReset();
  }

  async function toggleKeyprints(value: boolean) {
    setShowKeyprints(value);
    await saveShowKeyprints(value);
  }

  function handleSettingsIconTap() {
    settingsTapCountRef.current += 1;
    if (settingsTapTimerRef.current) clearTimeout(settingsTapTimerRef.current);
    if (settingsTapCountRef.current >= 7) {
      settingsTapCountRef.current = 0;
      if (__DEV__) {
        // Debug screen removed for production
      } else {
        // Production: 7 taps on settings icon does nothing special.
        setShowSettings(true);
      }
      return;
    }
    settingsTapTimerRef.current = setTimeout(() => {
      settingsTapCountRef.current = 0;
      setShowSettings(true);
    }, 400);
  }

  const webTopInset = Platform.OS === "web" ? 67 : 0;
  const visibleEntries = useMemo(
    () => visibleVaultEntries(entries, locked ? null : searchIndex, searchQuery, searchSort),
    [entries, locked, searchIndex, searchQuery, searchSort],
  );
  const searchActive = searchQuery.trim().length > 0 || searchSort !== "none";

  const renderItem = ({ item }: { item: VaultEntry }) => (
    <Pressable onPress={() => handleSelectEntry(item)} style={{ padding: 16, borderBottomWidth: 1, borderBottomColor: "#222", flexDirection: "row", alignItems: "center" }}>
      {showKeyprints ? (
        <Pressable
          onPress={(e) => {
            e.stopPropagation?.();
            resetActivity();
            // T007 — tap a keyprint to open the security dashboard
            // (was: open a passive fullscreen view of the same fractal).
            router.push("/settings/security");
          }}
        >
          <FractalKeyprint seed={visualSeed} size={44} animate={false} fractalParams={fractalParams} />
        </Pressable>
      ) : (
        <FaviconImage url={item.url} size={32} />
      )}
      <View style={{ marginLeft: 12, flex: 1 }}>
        <Text style={{ color: "#f0f0f0", fontSize: 18, fontWeight: "600" as const }} numberOfLines={1}>
          {item.title || "Untitled"}
        </Text>
        <Text style={{ color: "#aaaaaa" }} numberOfLines={1}>
          {item.username || ""}
        </Text>
      </View>
    </Pressable>
  );

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#000" }}>
        <AnimatedFractalView
          seed={visualSeed}
          size={200}
          fractalParams={fractalParams}
          securityState={securityState}
        />
        <ActivityIndicator size="large" color="#4CAF50" style={{ marginTop: 30 }} />
        <Text style={{ color: "#fff", fontSize: 20, marginTop: 20 }}>Loading Vault...</Text>
      </View>
    );
  }

  return (
    <View
      style={{ flex: 1, backgroundColor: "#000" }}
      onTouchStart={resetActivity}
      onTouchMove={resetActivity}
    >
      <View style={{ paddingTop: insets.top + webTopInset, padding: 16, flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
        <Text style={{ color: "#fff", fontSize: 28, fontWeight: "bold" as const }}>Vault</Text>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 20 }}>
          <Pressable onPress={() => setShowSecureNotes(true)}>
            <Ionicons name="document-lock-outline" size={24} color="#4CAF50" />
          </Pressable>
          <Pressable onPress={handleSettingsIconTap}>
            <Ionicons name="settings-outline" size={24} color="#fff" />
          </Pressable>
          <Pressable onPress={() => setShowAddModal(true)}>
            <Ionicons name="add-circle-outline" size={32} color="#fff" />
          </Pressable>
        </View>
      </View>

      {!locked && (
        <View style={{ paddingHorizontal: 16, paddingBottom: 8 }}>
          <TextInput
            value={searchQuery}
            onChangeText={(text) => {
              resetActivity();
              setSearchQuery(text);
            }}
            placeholder="Search vault"
            placeholderTextColor={INPUT_PLACEHOLDER}
            autoCapitalize="none"
            autoCorrect={false}
            autoComplete="off"
            textContentType="none"
            clearButtonMode="while-editing"
            style={{
              color: INPUT_TEXT,
              fontSize: 16,
              padding: 12,
              backgroundColor: INPUT_BG,
              borderRadius: 10,
              borderWidth: 1,
              borderColor: INPUT_BORDER,
            }}
            testID="vault-search-input"
          />
          <View style={{ flexDirection: "row", gap: 8, marginTop: 8 }}>
            {([
              ["none", "None"],
              ["az", "A-Z"],
              ["za", "Z-A"],
            ] as const).map(([mode, label]) => {
              const selected = searchSort === mode;
              return (
                <Pressable
                  key={mode}
                  onPress={() => {
                    resetActivity();
                    setSearchSort(mode);
                  }}
                  testID={`vault-sort-${mode}`}
                  style={{
                    paddingVertical: 6,
                    paddingHorizontal: 12,
                    borderRadius: 8,
                    backgroundColor: selected ? "#1a2e1a" : "#141414",
                    borderWidth: 1,
                    borderColor: selected ? "#4CAF50" : "#333",
                  }}
                >
                  <Text style={{ color: selected ? "#4CAF50" : "#aaa", fontSize: 14 }}>{label}</Text>
                </Pressable>
              );
            })}
          </View>
        </View>
      )}

      {fractalTampered && (
        <View style={{
          backgroundColor: "#3a0a0a",
          borderWidth: 1,
          borderColor: "#ef4444",
          borderRadius: 10,
          marginHorizontal: 16,
          marginBottom: 8,
          padding: 14,
          flexDirection: "row",
          alignItems: "center",
        }}>
          <Ionicons name="warning" size={22} color="#ef4444" style={{ marginRight: 10 }} />
          <View style={{ flex: 1 }}>
            <Text style={{ color: "#ef4444", fontSize: 14, fontWeight: "700" as const }}>
              Fractal Fingerprint Changed
            </Text>
            <Text style={{ color: "#cc8888", fontSize: 12, marginTop: 2 }}>
              Your vault's visual identity has changed unexpectedly. This may indicate key derivation tampering.
            </Text>
          </View>
        </View>
      )}

      {/* T008 — Subtle fractal underlay. We render ONE static SVG
          background behind the entire list rather than per-row to
          stay 60fps-safe; the visual effect is identical at the
          0.08 default opacity. */}
      <View style={{ flex: 1 }}>
        <FractalBackground seed={visualSeed} fractalParams={fractalParams} />
        <FlatList
          data={visibleEntries}
          keyExtractor={(item) => item.id}
          renderItem={renderItem}
          style={{ backgroundColor: "transparent" }}
          keyboardShouldPersistTaps="handled"
          ListEmptyComponent={
            searchActive && entries.length > 0 ? (
              <View style={{ flex: 1, justifyContent: "center", alignItems: "center", marginTop: 80 }}>
                <Text style={{ color: "#888", fontSize: 18 }} testID="vault-search-empty">No matches</Text>
              </View>
            ) : (
              <View style={{ flex: 1, justifyContent: "center", alignItems: "center", marginTop: 100 }}>
                <Pressable
                  onPress={() => {
                    resetActivity();
                    // T007 — same as the per-row keyprint tap.
                    router.push("/settings/security");
                  }}
                >
                  <AnimatedFractalView
                    seed={visualSeed}
                    size={150}
                    fractalParams={fractalParams}
                    securityState={securityState}
                  />
                </Pressable>
                <Text style={{ color: "#888", fontSize: 18, marginTop: 30 }}>Empty vault — add something!</Text>
              </View>
            )
          }
        />
      </View>

      <AddEntryModal
        visible={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSave={handleAddEntry}
        onActivity={resetActivity}
      />

      <AddEntryModal
        visible={showEditModal && !!decryptedEntry}
        mode="edit"
        initialValues={
          decryptedEntry
            ? {
                title: decryptedEntry.title,
                username: decryptedEntry.username,
                password: decryptedEntry.password,
                url: decryptedEntry.url,
                notes: decryptedEntry.notes,
              }
            : undefined
        }
        onClose={() => setShowEditModal(false)}
        onSave={handleUpdateEntry}
        onActivity={resetActivity}
      />

      {selectedEntry && (
        <EntryDetailModal
          visible={true}
          entry={selectedEntry}
          decryptedEntry={decryptedEntry}
          decrypting={decrypting}
          visualSeed={visualSeed}
          fractalParams={fractalParams}
          onClose={handleCloseDetail}
          onRequestDelete={handleRequestDelete}
          onRequestEdit={() => {
            if (!decryptedEntry) return;
            setShowEditModal(true);
          }}
          onActivity={resetActivity}
        />
      )}

      <DeleteEntryModal
        visible={showDeleteModal}
        entryTitle={deleteTargetTitle}
        onConfirmDelete={handleConfirmDelete}
        onCancel={() => { setShowDeleteModal(false); setDeleteTargetId(null); setDeleteTargetTitle(""); }}
        onActivity={resetActivity}
      />

      <SecureNotesModal
        visible={showSecureNotes}
        notes={secureNotes}
        keyShares={keySharesRef.current}
        onClose={() => setShowSecureNotes(false)}
        onNotesChanged={async () => {
          const notes = await getAllSecureNotes();
          setSecureNotes(notes);
          const shares = keySharesRef.current;
          if (!shares || lockedRef.current) return;
          try {
            const stored = await getAllEntries();
            setSearchIndex(await rebuildSearchIndex(shares, stored, notes));
          } catch {
            // The next unlock rebuilds the index.
          }
        }}
        onActivity={resetActivity}
      />

      <KeyprintViewer visible={showKeyprintViewer} seed={visualSeed} fractalParams={fractalParams} onClose={() => setShowKeyprintViewer(false)} />

      <Modal visible={showSettings} animationType="slide" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.9)", justifyContent: "flex-end" }}>
          <View style={{ backgroundColor: "#111", borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 20, paddingBottom: insets.bottom + 20 }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
              <Text style={{ color: "#fff", fontSize: 24, fontWeight: "bold" as const }}>Settings</Text>
              <Pressable onPress={() => setShowSettings(false)}>
                <Ionicons name="close" size={28} color="#666" />
              </Pressable>
            </View>

            <Text style={{ color: "#aaa", fontSize: 14, marginBottom: 12 }}>Security Profile</Text>
            {PROFILES.map((profile) => (
              <Pressable
                key={profile.iterations}
                onPress={() => handleProfileChange(profile.iterations)}
                disabled={migrating}
                style={{
                  flexDirection: "row",
                  alignItems: "center",
                  backgroundColor: iterations === profile.iterations ? "#1a1a1a" : "#0a0a0a",
                  padding: 16,
                  borderRadius: 12,
                  marginBottom: 8,
                  borderWidth: iterations === profile.iterations ? 2 : 0,
                  borderColor: profile.color,
                  opacity: migrating ? 0.5 : 1,
                }}
              >
                <Ionicons name={profile.icon} size={24} color={profile.color} />
                <View style={{ marginLeft: 16, flex: 1 }}>
                  <Text style={{ color: "#fff", fontSize: 18, fontWeight: "600" as const }}>{profile.label}</Text>
                  <Text style={{ color: "#888" }}>{profile.desc} {profile.time}</Text>
                </View>
                {iterations === profile.iterations && <Ionicons name="checkmark-circle" size={24} color={profile.color} />}
              </Pressable>
            ))}

            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginTop: 20, paddingVertical: 12 }}>
              <Text style={{ color: "#fff", fontSize: 18 }}>Show Fractal Keyprints</Text>
              <Switch
                value={showKeyprints}
                onValueChange={toggleKeyprints}
                trackColor={{ false: "#333", true: "#00ff9f" }}
                thumbColor={showKeyprints ? "#fff" : "#888"}
              />
            </View>

            <Pressable
              onPress={() => {
                setShowSettings(false);
                router.push("/settings/security");
              }}
              style={{ backgroundColor: "#0f0f0f", padding: 16, borderRadius: 12, marginTop: 24, borderWidth: 1, borderColor: "#1a1a1a", flexDirection: "row", alignItems: "center", gap: 12 }}
            >
              <Ionicons name="shield-checkmark-outline" size={20} color="#00ff9f" />
              <View style={{ flex: 1 }}>
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Security &amp; Devices</Text>
                <Text style={{ color: "#888", fontSize: 12, marginTop: 2 }}>Review threat status, devices and passkeys</Text>
              </View>
              <Ionicons name="chevron-forward" size={20} color="#666" />
            </Pressable>

            <Pressable onPress={onLock} style={{ backgroundColor: "#1a1a1a", padding: 16, borderRadius: 12, alignItems: "center", marginTop: 12 }}>
              <Ionicons name="lock-closed-outline" size={20} color="#ef4444" style={{ marginBottom: 6 }} />
              <Text style={{ color: "#ef4444", fontWeight: "600" as const, fontSize: 16 }}>Lock Vault Now</Text>
            </Pressable>

            <Pressable
              onPress={() => { setShowSettings(false); setShowNuclearReset(true); }}
              style={{ backgroundColor: "#1a0808", padding: 16, borderRadius: 12, alignItems: "center", marginTop: 12, borderWidth: 1, borderColor: "#3a1515" }}
            >
              <Ionicons name="nuclear-outline" size={20} color="#ef4444" style={{ marginBottom: 6 }} />
              <Text style={{ color: "#ef4444", fontWeight: "600" as const, fontSize: 16 }}>Nuclear Reset</Text>
            </Pressable>
          </View>
        </View>
      </Modal>

      <Modal visible={pendingProfileIterations !== null} animationType="fade" transparent>
        <View style={{ flex: 1, backgroundColor: "rgba(0,0,0,0.9)", justifyContent: "center", alignItems: "center", padding: 24 }}>
          <View style={{ backgroundColor: "#111", borderRadius: 16, padding: 24, width: "100%", maxWidth: 400 }}>
            <Text style={{ color: "#fff", fontSize: 20, fontWeight: "bold" as const, marginBottom: 8 }}>
              Confirm Password
            </Text>
            <Text style={{ color: "#aaa", fontSize: 14, marginBottom: 20 }}>
              Enter your master password to change the security profile. Your key will be re-derived with the new settings.
            </Text>
            <TextInput
              value={profilePassword}
              onChangeText={setProfilePassword}
              placeholder="Master password"
              placeholderTextColor={INPUT_PLACEHOLDER}
              secureTextEntry
              autoCapitalize="none"
              autoCorrect={false}
              autoComplete="off"
              textContentType="none"
              onFocus={() => setProfilePasswordFocused(true)}
              onBlur={() => setProfilePasswordFocused(false)}
              style={{ color: INPUT_TEXT, fontSize: 16, padding: 14, backgroundColor: INPUT_BG, borderRadius: 8, borderWidth: 1, borderColor: profilePasswordFocused ? INPUT_BORDER_FOCUS : INPUT_BORDER, marginBottom: 16 }}
              testID="profile-password-input"
            />
            {migrating && (
              <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 16 }}>
                <ActivityIndicator color="#4CAF50" />
                <Text style={{ color: "#aaa", marginLeft: 12, fontSize: 14 }}>Re-deriving key...</Text>
              </View>
            )}
            <View style={{ flexDirection: "row", gap: 12 }}>
              <Pressable
                onPress={() => { setPendingProfileIterations(null); setProfilePassword(""); }}
                disabled={migrating}
                style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: "#1a1a1a", alignItems: "center" }}
              >
                <Text style={{ color: "#aaa", fontSize: 16 }}>Cancel</Text>
              </Pressable>
              <Pressable
                onPress={confirmProfileChange}
                disabled={!profilePassword.trim() || migrating}
                style={{ flex: 1, padding: 14, borderRadius: 8, backgroundColor: profilePassword.trim() && !migrating ? "#4CAF50" : "#333", alignItems: "center" }}
              >
                <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600" as const }}>Confirm</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      <NuclearResetModal
        visible={showNuclearReset}
        onClose={() => setShowNuclearReset(false)}
        onConfirmReset={executeNuclearReset}
        verifyPassword={verifyPasswordForReset}
        requireBiometric={requireFreshBiometric}
      />

      {showUndoSnackbar && (
        <View
          style={{
            position: "absolute",
            bottom: insets.bottom + (Platform.OS === "web" ? 34 : 0) + 16,
            left: 16,
            right: 16,
            backgroundColor: "#1a1a1a",
            borderRadius: 12,
            flexDirection: "row",
            alignItems: "center",
            justifyContent: "space-between",
            paddingVertical: 14,
            paddingHorizontal: 16,
            borderWidth: 1,
            borderColor: "#333",
          }}
        >
          <View style={{ flexDirection: "row", alignItems: "center", flex: 1 }}>
            <Ionicons name="trash-outline" size={18} color="#ef4444" style={{ marginRight: 10 }} />
            <Text style={{ color: "#fff", fontSize: 15 }}>Entry deleted</Text>
          </View>
          <Pressable
            onPress={handleUndoDelete}
            style={{
              paddingVertical: 6,
              paddingHorizontal: 14,
              borderRadius: 6,
              backgroundColor: "#2a2a2a",
            }}
          >
            <Text style={{ color: "#4CAF50", fontSize: 15, fontWeight: "700" as const }}>UNDO</Text>
          </Pressable>
        </View>
      )}
    </View>
  );
}
