import React, { useCallback, useState } from "react";
import {
  View,
  Text,
  ScrollView,
  Pressable,
  ActivityIndicator,
  Alert,
  Platform,
  RefreshControl,
} from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Ionicons } from "@expo/vector-icons";
import { useRouter } from "expo-router";
import {
  securityApi,
  SecurityApiError,
  isMarkerConflict,
  type HoneytokenItem,
} from "../../../components/security/api";
import HoneytokenRow from "../../../components/security/HoneytokenRow";
import {
  generateHoneytokenMarker,
  hashHoneytokenMarker,
} from "../../../lib/honeytokenMarker";
import {
  encryptVaultEntry,
  decryptVaultEntry,
  type VaultEntry,
  type DecryptedVaultEntry,
} from "../../../workers/vaultWorker";
import { saveEntry, deleteEntry as deleteStoredEntry, getAllEntries } from "../../../workers/storageWorker";
import { getActiveKeyShares } from "../../../lib/vaultSession";

// T003 + T006 + T008 — Decoy management screen.
//
// Three responsibilities:
//   1. List existing honeytokens (GET /api/security/honeytokens)
//   2. Create a new decoy: generate a random marker locally,
//      register the SHA-256 hash with the backend, then save the
//      decoy as a normal-looking encrypted vault entry. If EITHER
//      side fails we roll the other back so we never leave a
//      half-armed decoy.
//   3. Disable a decoy: tells the backend, then strips honeytoken
//      fields from the local vault entry (or deletes it entirely
//      after user confirmation, per T006).
//
// MarkerHash is NEVER displayed (T003 + spec §"Do NOT display
// markerHash"). The HoneytokenRow component enforces the same.

const QK_HONEYTOKENS = ["/api/security/honeytokens"] as const;

// Realistic-looking decoy templates (T002 §"realistic-looking
// decoy vault entry"). Picked at random so a user creating
// multiple decoys doesn't end up with N copies of "Backup Crypto
// Wallet" — that pattern itself would be a tell.
const DECOY_TEMPLATES: readonly {
  label: string;
  title: string;
  username: string;
  url: string;
  notes: string;
}[] = [
  {
    label: "Backup Crypto Wallet",
    title: "Backup Crypto Wallet",
    username: "recovery",
    url: "https://wallet-backup.example",
    notes: "Emergency recovery",
  },
  {
    label: "Old Email",
    title: "Personal Email (Old)",
    username: "me.personal",
    url: "https://mail.example-service.com",
    notes: "Pre-2022 mailbox — keep for archives",
  },
  {
    label: "Bank Login",
    title: "Bank — Online Access",
    username: "primary",
    url: "https://bank.example",
    notes: "Joint account",
  },
  {
    label: "Server SSH",
    title: "Server (root)",
    username: "root",
    url: "https://server.example",
    notes: "Production",
  },
];

// Random but realistic-looking decoy password. Mix of upper/lower/
// digits/punct so it doesn't visually scream "this is fake".
function randomDecoyPassword(): string {
  const chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";
  let out = "";
  // Use Math.random — this is the FAKE password, NOT a secret. It
  // never protects anything; using Math.random here keeps the
  // module dependency-free and signals the intent (it's bait, not
  // a credential).
  for (let i = 0; i < 16; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function pickTemplate(existing: HoneytokenItem[]): typeof DECOY_TEMPLATES[number] {
  // Bias toward templates the user doesn't already have a decoy
  // for. Falls back to a uniform random pick if all four are taken.
  const usedLabels = new Set(existing.map((h) => h.label));
  const fresh = DECOY_TEMPLATES.filter((t) => !usedLabels.has(t.label));
  const pool = fresh.length > 0 ? fresh : DECOY_TEMPLATES;
  return pool[Math.floor(Math.random() * pool.length)];
}

// Generic action-failed message (matches the security dashboard's
// explainError; duplicated here rather than exported because the
// honeytoken-specific surfaces have a couple of distinct cases —
// step-up on disable, marker_conflict on create).
function explainError(err: unknown): string {
  if (err instanceof SecurityApiError) {
    if (err.kind === "step-up") {
      return "This action needs a fresh second-factor check. Sign out and back in with your TOTP code, then try again.";
    }
    if (err.kind === "rate") {
      return "Too many requests. Please wait a moment and try again.";
    }
    if (err.kind === "auth") {
      return "Your session has expired. Please sign in again.";
    }
  }
  return "Action failed. Please try again.";
}

export default function HoneytokensScreen() {
  const insets = useSafeAreaInsets();
  const router = useRouter();
  const qc = useQueryClient();

  const honeytokensQ = useQuery({
    queryKey: QK_HONEYTOKENS,
    queryFn: securityApi.fetchHoneytokens,
    retry: false,
  });

  const [refreshing, setRefreshing] = useState(false);
  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await qc.invalidateQueries({ queryKey: QK_HONEYTOKENS });
    } finally {
      setRefreshing(false);
    }
  }, [qc]);

  // Per-row pending state for disable so two rows can be acted on
  // independently. Same pattern as DeviceRow / PasskeyRow.
  const [pendingDisableId, setPendingDisableId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const honeytokens = honeytokensQ.data?.honeytokens ?? [];
  const activeCount = honeytokens.filter((h) => h.active).length;

  // T002 — Create flow.
  //
  // Order of operations is critical for atomicity:
  //   1. Generate marker locally + compute its hash
  //   2. POST to backend FIRST (so we know the marker is registered
  //      and didn't collide). On failure, abort cleanly — no local
  //      state changed yet.
  //   3. Encrypt + save the vault entry locally with isHoneytoken,
  //      honeytokenId, encryptedHoneytokenMarker.
  //   4. If step 3 fails, fire a best-effort disable on the backend
  //      so we don't leave an orphan honeytoken row pointing at no
  //      vault entry.
  //
  // T002 §"realistic-looking" — title/username/url/notes are
  // picked from DECOY_TEMPLATES; password is random so a leaked
  // decoy password never matches a real one.
  async function handleCreateDecoy() {
    if (creating) return;
    const shares = getActiveKeyShares();
    if (!shares) {
      Alert.alert(
        "Vault locked",
        "Unlock your vault before creating a decoy entry.",
      );
      return;
    }

    setCreating(true);
    let registeredId: string | null = null;
    try {
      const tpl = pickTemplate(honeytokens);
      const marker = generateHoneytokenMarker();
      const markerHash = hashHoneytokenMarker(marker);

      // Step 2: register with backend FIRST.
      const registered = await securityApi.createHoneytoken({
        label: tpl.label,
        tokenType: "vault_entry",
        markerHash,
      });
      registeredId = registered.honeytoken.id;

      // Step 3: save the vault entry. Encryption uses the per-entry
      // HKDF subkey (same protection as the password).
      const encrypted = encryptVaultEntry(
        {
          title: tpl.title,
          username: tpl.username,
          password: randomDecoyPassword(),
          url: tpl.url,
          notes: tpl.notes,
          isHoneytoken: true,
          honeytokenId: registeredId,
          honeytokenMarker: marker,
        },
        shares,
      );
      await saveEntry(encrypted);

      await qc.invalidateQueries({ queryKey: QK_HONEYTOKENS });
      Alert.alert(
        "Decoy created",
        `"${tpl.label}" is now in your vault. It looks like a normal entry — touching it raises a quiet security alert.`,
      );
    } catch (err) {
      // T002 §"If vault save fails, disable/delete the honeytoken
      // metadata if possible". registeredId is non-null only after
      // step 2 succeeded; if the throw came from saveEntry, we
      // try to disable on the way out so the backend doesn't carry
      // an orphan.
      if (registeredId) {
        try {
          await securityApi.disableHoneytoken(registeredId);
        } catch {
          // best-effort only — the user already has a worse error
          // to deal with
        }
      }
      if (isMarkerConflict(err)) {
        Alert.alert(
          "Couldn't create decoy",
          "Please try again — the system needs a fresh marker.",
        );
      } else {
        Alert.alert("Couldn't create decoy", explainError(err));
      }
    } finally {
      setCreating(false);
    }
  }

  // T006 — Disable flow.
  //
  // Two-step: the user picks "just disable" (keep the entry as a
  // normal-looking vault row) or "remove entirely" (delete the
  // local entry). Either way we tell the backend first so a
  // concurrent trigger after this point returns triggered:false.
  //
  // Local cleanup: the cleanest path is to find the local vault
  // entry by honeytokenId and either re-encrypt it without the
  // honeytoken fields, or deleteEntry()-it. We use deleteEntry on
  // "remove" and re-encrypt on "keep" since re-encryption is the
  // existing pattern for changing entry contents.
  function confirmDisable(item: HoneytokenItem) {
    Alert.alert(
      "Disable decoy?",
      `"${item.label}" will stop raising security alerts. The vault entry stays in place unless you remove it too.`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Disable & remove entry",
          style: "destructive",
          onPress: () => disableMut.mutate({ item, removeLocal: true }),
        },
        {
          text: "Disable only",
          onPress: () => disableMut.mutate({ item, removeLocal: false }),
        },
      ],
    );
  }

  const disableMut = useMutation({
    mutationFn: async ({
      item,
      removeLocal,
    }: {
      item: HoneytokenItem;
      removeLocal: boolean;
    }) => {
      setPendingDisableId(item.id);
      // Backend first — if step-up is required, the local vault
      // shouldn't have been touched yet.
      await securityApi.disableHoneytoken(item.id);

      // Find the local vault entry that points to this honeytoken.
      //
      // honeytokenId now lives ENCRYPTED inside `encryptedAux`
      // (see vaultWorker.ts comments) so we have no plaintext index
      // to filter against — we must decrypt each candidate. This is
      // O(N) AES-GCM per disable, which is fine for the disable
      // codepath (rare, user-initiated) and is the price of the
      // zero-knowledge indistinguishability guarantee.
      //
      // Vault may be locked: without the master key we can't
      // decrypt anything, so the local row will keep looking like a
      // decoy until the user unlocks. The backend disable above has
      // already neutralised the trigger server-side (any future
      // ping with this markerHash returns triggered:false), so the
      // worst case is a stale-looking row, not a security issue.
      const shares = getActiveKeyShares();
      if (shares) {
        const all = await getAllEntries();
        let target: VaultEntry | null = null;
        let decryptedTarget: DecryptedVaultEntry | null = null;
        for (const candidate of all) {
          if (!candidate.encryptedAux) continue;
          try {
            const dec = decryptVaultEntry(candidate, shares);
            if (dec.isHoneytoken && dec.honeytokenId === item.id) {
              target = candidate;
              decryptedTarget = dec;
              break;
            }
          } catch {
            // Skip undecryptable rows (legacy / corrupt) silently.
          }
        }

        if (target && decryptedTarget) {
          if (removeLocal) {
            await deleteStoredEntry(target.id);
          } else {
            // Re-encrypt without the honeytoken metadata so the
            // entry stops triggering on view/copy.
            const stripped = encryptVaultEntry(
              {
                title: decryptedTarget.title,
                username: decryptedTarget.username,
                password: decryptedTarget.password,
                url: decryptedTarget.url,
                notes: decryptedTarget.notes,
                // Honeytoken fields deliberately dropped here.
              },
              shares,
              target.id,
            );
            await saveEntry(stripped);
          }
        }
      }
    },
    onError: (err) => {
      Alert.alert("Couldn't disable decoy", explainError(err));
    },
    onSettled: () => {
      setPendingDisableId(null);
      qc.invalidateQueries({ queryKey: QK_HONEYTOKENS });
      // Disabling a decoy can shift the threat picture (one fewer
      // active sensor). Refresh the audit query so the dashboard
      // and fractal pick up the new state.
      qc.invalidateQueries({ queryKey: ["/api/vault/audit"] });
    },
  });

  // Web-only top inset — same pattern as the security dashboard.
  const topPadding = Platform.OS === "web" ? Math.max(insets.top, 67) : insets.top;
  const bottomPadding = Platform.OS === "web" ? Math.max(insets.bottom, 34) : insets.bottom + 24;

  return (
    <View style={{ flex: 1, backgroundColor: "#000", paddingTop: topPadding }}>
      <View
        style={{
          flexDirection: "row",
          alignItems: "center",
          paddingHorizontal: 16,
          paddingBottom: 12,
          borderBottomWidth: 1,
          borderBottomColor: "#1a1a1a",
        }}
      >
        <Pressable
          onPress={() => router.back()}
          hitSlop={12}
          accessibilityRole="button"
          accessibilityLabel="Back"
          style={{ padding: 4 }}
        >
          <Ionicons name="chevron-back" size={26} color="#fff" />
        </Pressable>
        <Text style={{ color: "#fff", fontSize: 18, fontWeight: "700" as const, marginLeft: 8 }}>
          Decoy Entries
        </Text>
      </View>

      <ScrollView
        contentContainerStyle={{ padding: 16, paddingBottom: bottomPadding, gap: 12 }}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#888" />
        }
      >
        {/* T008 — calm, descriptive copy. No exclamation marks, no
            scary language. */}
        <View
          style={{
            backgroundColor: "#0a0a0a",
            borderRadius: 12,
            borderWidth: 1,
            borderColor: "#1a1a1a",
            padding: 14,
            gap: 6,
          }}
        >
          <Text style={{ color: "#ccc", fontSize: 14, lineHeight: 20 }}>
            Decoy entries help detect suspicious access. They look like normal vault
            entries, but touching one raises a security alert.
          </Text>
          <Text style={{ color: "#888", fontSize: 12, marginTop: 4 }}>
            Do not store real information in decoy entries.
          </Text>
        </View>

        {honeytokensQ.isError ? (
          <View
            style={{
              padding: 12,
              borderRadius: 12,
              backgroundColor: "#1a0808",
              borderWidth: 1,
              borderColor: "#3a1515",
              flexDirection: "row",
              alignItems: "center",
              gap: 10,
            }}
          >
            <Ionicons name="cloud-offline-outline" size={18} color="#ef4444" />
            <Text style={{ color: "#ef4444", fontSize: 13, flex: 1 }}>
              Couldn&apos;t load decoys. Pull to refresh.
            </Text>
          </View>
        ) : null}

        <Pressable
          onPress={handleCreateDecoy}
          disabled={creating}
          accessibilityRole="button"
          accessibilityLabel="Create a new decoy entry"
          style={{
            backgroundColor: creating ? "#0a2818" : "#0d3a22",
            borderRadius: 12,
            borderWidth: 1,
            borderColor: "#1a5a35",
            padding: 14,
            flexDirection: "row",
            alignItems: "center",
            justifyContent: "center",
            gap: 8,
            opacity: creating ? 0.7 : 1,
          }}
        >
          {creating ? (
            <ActivityIndicator size="small" color="#9be3b6" />
          ) : (
            <Ionicons name="add-circle-outline" size={20} color="#9be3b6" />
          )}
          <Text style={{ color: "#9be3b6", fontSize: 15, fontWeight: "600" as const }}>
            {creating ? "Creating decoy…" : "Create Decoy Entry"}
          </Text>
        </Pressable>

        {/* Inline summary — only shown when we have data to summarize.
            Keeps the screen quiet when the user hasn't created any
            decoys yet. */}
        {honeytokens.length > 0 ? (
          <Text style={{ color: "#666", fontSize: 12, marginTop: 4 }}>
            {activeCount} active · {honeytokens.length} total
          </Text>
        ) : null}

        {honeytokensQ.isLoading ? (
          <View style={{ paddingVertical: 24, alignItems: "center" }}>
            <ActivityIndicator size="small" color="#444" />
          </View>
        ) : honeytokens.length === 0 ? (
          <View
            style={{
              padding: 24,
              alignItems: "center",
              backgroundColor: "#0a0a0a",
              borderRadius: 12,
              borderWidth: 1,
              borderColor: "#1a1a1a",
              borderStyle: "dashed" as const,
            }}
          >
            <Ionicons name="shield-outline" size={28} color="#444" />
            <Text style={{ color: "#666", fontSize: 13, marginTop: 8, textAlign: "center" }}>
              No decoys yet. Create one to start watching for suspicious access.
            </Text>
          </View>
        ) : (
          <View style={{ gap: 8 }}>
            {honeytokens.map((h) => (
              <HoneytokenRow
                key={h.id}
                item={h}
                pending={pendingDisableId === h.id}
                onDisable={() => confirmDisable(h)}
              />
            ))}
          </View>
        )}
      </ScrollView>
    </View>
  );
}
