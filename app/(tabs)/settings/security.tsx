import React, { useCallback, useMemo, useState } from "react";
import {
  View,
  Text,
  ScrollView,
  Pressable,
  ActivityIndicator,
  Alert,
  Platform,
  RefreshControl,
  useWindowDimensions,
} from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Ionicons } from "@expo/vector-icons";
import { useRouter } from "expo-router";
import {
  securityApi,
  SecurityApiError,
  relativeTime,
  type DeviceItem,
  type PasskeyItem,
  type SessionItem,
} from "../../../components/security/api";
import SecurityStatus from "../../../components/security/SecurityStatus";
import RecoveryBanner from "../../../components/security/RecoveryBanner";
import DeviceRow from "../../../components/security/DeviceRow";
import PasskeyRow from "../../../components/security/PasskeyRow";
import AnimatedFractalView from "../../../components/AnimatedFractalView";
import { useSecurityState } from "../../../context/SecurityContext";
import { DEFAULT_FRACTAL_PARAMS } from "../../../crypto/hkdf";

// T007 — Hero fractal seed. The dashboard's fractal is meant to
// visualize SECURITY STATE rather than user identity (the per-user
// keyprint lives on vault entries). A constant seed gives every
// user the same recognizable shape; what changes between accounts
// — and over time — is the color/glow/distortion driven by
// SecurityContext.
const DASHBOARD_FRACTAL_SEED = 8675309;

// Security Dashboard screen (T001-T010).
//
// Dashboard sections stay in a fixed order so the most-urgent UI is
// at the top: Status, Sessions, Devices, Passkeys. All data comes
// from existing safe GETs:
//   - /api/vault/audit       (level, threat, recoveryMode, anomaly bit)
//   - /api/auth/sessions     (safe session metadata)
//   - /api/security/devices  (device ledger)
//   - /api/passkeys          (registered passkeys)
//
// Mutations are optimistic where the optimistic state has a clean
// rollback (device trust toggle); destructive ones (passkey revoke,
// acknowledge recovery) are NOT optimistic — we wait for server
// confirmation before pulling the row from the UI to avoid a flash
// of "this is gone" followed by a re-appearance on rollback.

const QK = {
  audit: ["/api/vault/audit"] as const,
  sessions: ["/api/auth/sessions"] as const,
  devices: ["/api/security/devices"] as const,
  passkeys: ["/api/passkeys"] as const,
};

// Generic action-failed message — never expose raw backend errors
// per T009. step-up gets a slightly more helpful nudge so a user
// who has TOTP enabled understands why their click did nothing.
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

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <Text
      style={{
        color: "#aaa",
        fontSize: 12,
        letterSpacing: 0.8,
        textTransform: "uppercase" as const,
        marginBottom: 10,
        marginTop: 8,
      }}
    >
      {children}
    </Text>
  );
}

function Skeleton({ height }: { height: number }) {
  return (
    <View
      style={{
        height,
        backgroundColor: "#0f0f0f",
        borderRadius: 12,
        borderWidth: 1,
        borderColor: "#1a1a1a",
        marginBottom: 8,
      }}
    />
  );
}

function EmptyState({ icon, text }: { icon: keyof typeof Ionicons.glyphMap; text: string }) {
  return (
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
      <Ionicons name={icon} size={28} color="#444" />
      <Text style={{ color: "#666", fontSize: 13, marginTop: 8, textAlign: "center" }}>{text}</Text>
    </View>
  );
}

function TrustBadge({ trusted }: { trusted: boolean }) {
  return (
    <View
      style={{
        paddingHorizontal: 8,
        paddingVertical: 2,
        borderRadius: 10,
        backgroundColor: trusted ? "#0a1a10" : "#1a1208",
        borderWidth: 1,
        borderColor: trusted ? "#143a25" : "#3a2510",
      }}
    >
      <Text
        style={{
          color: trusted ? "#22c55e" : "#eab308",
          fontSize: 10,
          fontWeight: "600" as const,
        }}
      >
        {trusted ? "TRUSTED" : "UNTRUSTED"}
      </Text>
    </View>
  );
}

function sessionTitle(session: SessionItem): string {
  if (session.current) return "Current session";
  const ua = session.userAgent?.trim();
  if (!ua) return "Recent session";
  return ua.length > 72 ? `${ua.slice(0, 69)}...` : ua;
}

function sessionDetail(session: SessionItem): string {
  const parts = [`last seen ${relativeTime(session.lastSeenAt)}`];
  if (session.ipAddress) parts.push(session.ipAddress);
  return parts.join(" - ");
}

function SessionSummary({ session }: { session: SessionItem }) {
  return (
    <View
      style={{
        backgroundColor: "#0f0f0f",
        borderRadius: 12,
        borderWidth: 1,
        borderColor: session.suspicious ? "#3a2510" : "#1a1a1a",
        padding: 14,
        flexDirection: "row",
        alignItems: "center",
        gap: 12,
      }}
    >
      <Ionicons
        name={session.suspicious ? "warning-outline" : "phone-portrait-outline"}
        size={20}
        color={session.suspicious ? "#f97316" : session.trusted ? "#22c55e" : "#888"}
      />
      <View style={{ flex: 1 }}>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
          <Text
            style={{ color: "#fff", fontSize: 14, fontWeight: "600" as const, flexShrink: 1 }}
            numberOfLines={1}
          >
            {sessionTitle(session)}
          </Text>
          <TrustBadge trusted={session.trusted} />
        </View>
        <Text style={{ color: "#777", fontSize: 12, marginTop: 4 }} numberOfLines={1}>
          {sessionDetail(session)}
        </Text>
      </View>
      {session.suspicious ? (
        <Text style={{ color: "#f97316", fontSize: 11, fontWeight: "600" as const }}>
          REVIEW
        </Text>
      ) : null}
    </View>
  );
}

export default function SecurityScreen() {
  const insets = useSafeAreaInsets();
  const router = useRouter();
  const qc = useQueryClient();
  const { width } = useWindowDimensions();
  // Hero fractal sized to fit comfortably on phone & tablet. Capped
  // so it never dominates a wide screen (web/tablet).
  const heroFractalSize = Math.min(width - 64, 260);
  // T002 — single source of truth for the fractal's reactive params.
  const securityState = useSecurityState();

  // T002 — Independent fetches. Each one's loading state is
  // surfaced separately so a slow audit endpoint doesn't blank the
  // (already-cached) device list. retry:false matches the project
  // QueryClient default so a transient 500 doesn't re-fire the call
  // five times silently.
  const auditQ = useQuery({
    queryKey: QK.audit,
    queryFn: securityApi.fetchAudit,
    retry: false,
  });
  const sessionsQ = useQuery({
    queryKey: QK.sessions,
    queryFn: securityApi.fetchSessions,
    retry: false,
  });
  const devicesQ = useQuery({
    queryKey: QK.devices,
    queryFn: securityApi.fetchDevices,
    retry: false,
  });
  const passkeysQ = useQuery({
    queryKey: QK.passkeys,
    queryFn: securityApi.fetchPasskeys,
    retry: false,
  });

  const [refreshing, setRefreshing] = useState(false);
  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        qc.invalidateQueries({ queryKey: QK.audit }),
        qc.invalidateQueries({ queryKey: QK.sessions }),
        qc.invalidateQueries({ queryKey: QK.devices }),
        qc.invalidateQueries({ queryKey: QK.passkeys }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }, [qc]);

  // Per-row pending state for the trust toggle and passkey revoke.
  // We track by fingerprint / passkeyId so two parallel actions
  // (e.g. user mashing two trust buttons) each render their own
  // spinner without bleeding into each other.
  const [pendingDeviceFp, setPendingDeviceFp] = useState<string | null>(null);
  const [pendingPasskeyId, setPendingPasskeyId] = useState<string | null>(null);

  // T008 — Optimistic device-trust toggle. We snapshot the current
  // devices payload, write the flipped state into the cache
  // immediately, and on error roll back. On success we leave the
  // optimistic state in place AND invalidate so the next refetch
  // picks up server-side firstSeen/lastSeen drift.
  const trustMut = useMutation({
    mutationFn: ({ fingerprint, makeTrusted }: { fingerprint: string; makeTrusted: boolean }) =>
      makeTrusted
        ? securityApi.trustDevice(fingerprint)
        : securityApi.revokeDeviceTrust(fingerprint),
    onMutate: async ({ fingerprint, makeTrusted }) => {
      setPendingDeviceFp(fingerprint);
      await qc.cancelQueries({ queryKey: QK.devices });
      const prev = qc.getQueryData<{ devices: DeviceItem[] }>(QK.devices);
      if (prev) {
        qc.setQueryData<{ devices: DeviceItem[] }>(QK.devices, {
          devices: prev.devices.map((d) =>
            d.fingerprint === fingerprint ? { ...d, trusted: makeTrusted } : d,
          ),
        });
      }
      return { prev };
    },
    onError: (err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(QK.devices, ctx.prev);
      Alert.alert("Could not update device", explainError(err));
    },
    onSettled: () => {
      setPendingDeviceFp(null);
      qc.invalidateQueries({ queryKey: QK.devices });
      // Trust changes can shift securityLevel; refresh audit too so
      // the status block reflects the new posture immediately.
      qc.invalidateQueries({ queryKey: QK.audit });
      qc.invalidateQueries({ queryKey: QK.sessions });
    },
  });

  const revokePasskeyMut = useMutation({
    mutationFn: (passkeyId: string) => securityApi.revokePasskey(passkeyId),
    onMutate: (passkeyId) => {
      setPendingPasskeyId(passkeyId);
    },
    onError: (err) => {
      Alert.alert("Could not revoke passkey", explainError(err));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QK.passkeys });
    },
    onSettled: () => {
      setPendingPasskeyId(null);
    },
  });

  const ackMut = useMutation({
    mutationFn: () => securityApi.acknowledgeRecovery(),
    onError: (err) => {
      Alert.alert("Could not acknowledge", explainError(err));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QK.audit });
    },
  });

  function confirmRevokePasskey(p: PasskeyItem) {
    const label = p.deviceName ?? "this passkey";
    Alert.alert(
      "Revoke passkey?",
      `Once revoked, "${label}" can no longer sign in to your account.`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Revoke",
          style: "destructive",
          onPress: () => revokePasskeyMut.mutate(p.id),
        },
      ],
    );
  }

  const audit = auditQ.data;
  const sessions = sessionsQ.data?.sessions;
  const devices = devicesQ.data?.devices;
  const passkeys = passkeysQ.data?.passkeys ?? [];

  // Web-only top inset (per Expo guidelines): a fixed 67px header
  // safe-area shim because Platform.OS === "web" doesn't get a real
  // status bar inset from useSafeAreaInsets.
  const topPadding = Platform.OS === "web" ? Math.max(insets.top, 67) : insets.top;
  const bottomPadding = Platform.OS === "web" ? Math.max(insets.bottom, 34) : insets.bottom + 24;

  // Fail-open: any of the three queries failing surfaces a single
  // soft error block at the top instead of a screen-wide error so
  // the user can still see whichever sections did load.
  const anyError = auditQ.isError || sessionsQ.isError || devicesQ.isError || passkeysQ.isError;

  const currentSession = useMemo(() => {
    return sessions?.find((s) => s.current === true) ?? null;
  }, [sessions]);

  const recentSessions = useMemo(() => {
    return [...(sessions ?? [])].sort((a, b) => b.lastSeenAt - a.lastSeenAt).slice(0, 3);
  }, [sessions]);

  // useMemo: stable device sort — trusted-current device most
  // recent first. Server already returns by lastSeenAt DESC; we
  // just push untrusted-but-recent above trusted-but-stale so the
  // user's current (likely-new) device is the one they see first.
  const sortedDevices = useMemo(() => {
    return [...(devices ?? [])].sort((a, b) => b.lastSeenAt - a.lastSeenAt);
  }, [devices]);

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
          Security
        </Text>
      </View>

      <ScrollView
        contentContainerStyle={{ padding: 16, paddingBottom: bottomPadding, gap: 8 }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#888" />}
      >
        {anyError ? (
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
              Some details couldn&apos;t be loaded. Pull to refresh.
            </Text>
          </View>
        ) : null}

        {/* T006 — Recovery banner. Only when server reports recoveryMode. */}
        {audit?.recoveryMode ? (
          <RecoveryBanner acknowledging={ackMut.isPending} onAcknowledge={() => ackMut.mutate()} />
        ) : null}

        {/* T007 — Hero fractal. Reads SecurityState directly so its
            color/glow/distortion always agrees with the data shown
            in the sections below it. The fractal itself is the only
            thing on screen that visualises the live state — the
            text/bar/list reflect the same query but in numeric form. */}
        <View
          style={{
            alignItems: "center",
            paddingVertical: 12,
          }}
        >
          <View
            style={{
              width: heroFractalSize,
              height: heroFractalSize,
              borderRadius: heroFractalSize / 2,
              overflow: "hidden",
              borderWidth: 2,
              borderColor: "rgba(0,255,159,0.4)",
              ...(Platform.OS === "web"
                ? { boxShadow: "0 0 30px rgba(0,255,159,0.35)" as any }
                : {
                    shadowColor: "#00ff9f",
                    shadowOffset: { width: 0, height: 0 },
                    shadowOpacity: 0.4,
                    shadowRadius: 20,
                    elevation: 12,
                  }),
            }}
          >
            <AnimatedFractalView
              seed={DASHBOARD_FRACTAL_SEED}
              fractalParams={DEFAULT_FRACTAL_PARAMS}
              size={heroFractalSize}
              securityState={securityState}
            />
          </View>
        </View>

        {/* Section: Security Status (T001 + T007) */}
        <SectionHeading>Security Status</SectionHeading>
        {auditQ.isLoading ? (
          <Skeleton height={120} />
        ) : (
          <SecurityStatus
            level={audit?.securityLevel}
            threatLevel={audit?.threatLevel}
            hasRecentAnomalies={audit?.hasRecentAnomalies}
          />
        )}

        {/* Section: Sessions. Existing safe endpoint data only; installId is not shown here. */}
        <SectionHeading>Sessions</SectionHeading>
        {sessionsQ.isLoading ? (
          <>
            <Skeleton height={76} />
            <Skeleton height={76} />
          </>
        ) : recentSessions.length === 0 ? (
          <EmptyState icon="phone-portrait-outline" text="No active sessions found." />
        ) : (
          <View style={{ gap: 8 }}>
            <View
              style={{
                backgroundColor: "#0f0f0f",
                borderRadius: 12,
                borderWidth: 1,
                borderColor: "#1a1a1a",
                padding: 14,
                flexDirection: "row",
                alignItems: "center",
                gap: 12,
              }}
            >
              <Ionicons
                name={currentSession?.trusted ? "shield-checkmark-outline" : "shield-outline"}
                size={20}
                color={currentSession?.trusted ? "#22c55e" : "#888"}
              />
              <View style={{ flex: 1 }}>
                <Text style={{ color: "#fff", fontSize: 14, fontWeight: "600" as const }}>
                  Current session
                </Text>
                <Text style={{ color: "#777", fontSize: 12, marginTop: 4 }}>
                  {currentSession
                    ? currentSession.trusted
                      ? "Server trust state: trusted."
                      : "Server trust state: untrusted."
                    : "Current session details are not available for this sign-in method."}
                </Text>
              </View>
            </View>
            {recentSessions.map((s) => (
              <SessionSummary key={s.id} session={s} />
            ))}
          </View>
        )}

        {/* Section: Devices (T003) */}
        <SectionHeading>Devices</SectionHeading>
        {devicesQ.isLoading ? (
          <>
            <Skeleton height={68} />
            <Skeleton height={68} />
          </>
        ) : sortedDevices.length === 0 ? (
          <EmptyState icon="phone-portrait-outline" text="No devices recorded yet." />
        ) : (
          <View style={{ gap: 8 }}>
            {sortedDevices.map((d) => (
              <DeviceRow
                key={d.fingerprint}
                device={d}
                pending={pendingDeviceFp === d.fingerprint}
                onTrust={() =>
                  trustMut.mutate({ fingerprint: d.fingerprint, makeTrusted: true })
                }
                onRevoke={() =>
                  trustMut.mutate({ fingerprint: d.fingerprint, makeTrusted: false })
                }
              />
            ))}
          </View>
        )}

        {/* Section: Passkeys (T004) */}
        <SectionHeading>Passkeys</SectionHeading>
        {passkeysQ.isLoading ? (
          <>
            <Skeleton height={68} />
          </>
        ) : passkeys.length === 0 ? (
          <EmptyState icon="key-outline" text="No passkeys registered." />
        ) : (
          <View style={{ gap: 8 }}>
            {passkeys.map((p) => (
              <PasskeyRow
                key={p.id}
                passkey={p}
                pending={pendingPasskeyId === p.id}
                onRevoke={() => confirmRevokePasskey(p)}
              />
            ))}
          </View>
        )}

        {/* Section: Decoys (honeytokens) — entry point to the
            management screen (app/(tabs)/settings/honeytokens.tsx).
            Shown as a single nav row rather than embedding the list
            inline so the dashboard stays scannable. The fractal
            already reacts to triggered decoys via SecurityContext,
            so there's no extra "alerts" widget here. */}
        <SectionHeading>Decoys</SectionHeading>
        <Pressable
          onPress={() => router.push("/settings/honeytokens")}
          accessibilityRole="button"
          accessibilityLabel="Manage decoy entries"
          style={({ pressed }) => ({
            backgroundColor: "#0f0f0f",
            borderRadius: 12,
            borderWidth: 1,
            borderColor: "#1a1a1a",
            padding: 14,
            flexDirection: "row",
            alignItems: "center",
            opacity: pressed ? 0.7 : 1,
          })}
        >
          <Ionicons name="shield-half-outline" size={20} color="#9be3b6" />
          <View style={{ marginLeft: 12, flex: 1 }}>
            <Text style={{ color: "#fff", fontSize: 14, fontWeight: "500" as const }}>
              Decoy Entries
            </Text>
            <Text style={{ color: "#888", fontSize: 12, marginTop: 2 }}>
              Plant fake vault items that quietly raise alerts when touched.
            </Text>
          </View>
          <Ionicons name="chevron-forward" size={18} color="#666" />
        </Pressable>

        {/* Section: Activity (T007 — last anomaly readout) */}
        <SectionHeading>Activity</SectionHeading>
        <View
          style={{
            backgroundColor: "#0f0f0f",
            borderRadius: 12,
            borderWidth: 1,
            borderColor: "#1a1a1a",
            padding: 14,
            flexDirection: "row",
            alignItems: "center",
          }}
        >
          <Ionicons
            name={securityState.lastAnomalyAt ? "pulse" : "checkmark-circle-outline"}
            size={18}
            color={securityState.lastAnomalyAt ? "#f97316" : "#22c55e"}
          />
          <View style={{ marginLeft: 10, flex: 1 }}>
            <Text style={{ color: "#fff", fontSize: 14 }}>
              {securityState.lastAnomalyAt
                ? "Last anomaly"
                : "No anomalies"}
            </Text>
            <Text style={{ color: "#888", fontSize: 12, marginTop: 2 }}>
              {securityState.lastAnomalyAt
                ? relativeTime(securityState.lastAnomalyAt)
                : "Your account hasn't seen unusual activity recently."}
            </Text>
          </View>
        </View>

        {(sessionsQ.isFetching || devicesQ.isFetching || passkeysQ.isFetching || auditQ.isFetching) && !refreshing ? (
          <View style={{ padding: 12, alignItems: "center" }}>
            <ActivityIndicator size="small" color="#444" />
          </View>
        ) : null}
      </ScrollView>
    </View>
  );
}
