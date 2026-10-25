/**
 * Shared security state for rate limits, soft-locks, anomaly windows,
 * login/passkey failure bursts, IP-change bursts, and IP-threat blocks.
 *
 * Backend selection:
 *   - REDIS_URL set  → Redis (survives restart, shared across instances)
 *   - REDIS_URL unset → in-process Maps (local/test default)
 *
 * Failure policy when Redis is configured but unreachable:
 *   - Rate limits, vault write soft-lock checks, and login IP blocks
 *     fail CLOSED (treat as limited / locked / blocked).
 *   - Observability mutations (anomaly, failure bursts) fail OPEN
 *     (skip the write; request continues).
 *
 * Local development: leave REDIS_URL unset. Production should set it
 * (see .env.example). DISABLE_RATE_LIMIT remains a non-production-only
 * bypass in routes.ts and is not implemented here.
 */

import { createHash } from "node:crypto";
import Redis from "ioredis";

export const RATE_LIMIT_WINDOW_MS = 60_000;

export const ANOMALY_FETCH_THRESHOLD = 30;
export const ANOMALY_SYNC_THRESHOLD = 15;
export const ANOMALY_WINDOW_MS = 60_000;
export const ANOMALY_STATE_TTL_MS = 60 * 60_000;

export const PASSKEY_FAILURE_THRESHOLD = 5;
export const PASSKEY_FAILURE_WINDOW_MS = 5 * 60_000;
export const PASSKEY_FAILURE_STATE_TTL_MS = 60 * 60_000;

export const LOGIN_FAILURE_THRESHOLD = 5;
export const LOGIN_FAILURE_WINDOW_MS = 5 * 60_000;
export const LOGIN_FAILURE_STATE_TTL_MS = 60 * 60_000;

export const IP_THREAT_INACTIVITY_TTL_MS = 30 * 60_000;
export const IP_THREAT_BRUTE_THRESHOLD = 10;
export const IP_THREAT_BRUTE_WINDOW_MS = 5 * 60_000;
export const IP_THREAT_STUFFING_THRESHOLD = 5;
export const IP_THREAT_STUFFING_WINDOW_MS = 10 * 60_000;
export const IP_THREAT_BLOCK_MS = 5 * 60_000;
export const IP_THREAT_TARGETS_CAP = 1000;
export const IP_THREAT_DECAY_PER_SUCCESS = 2;
export const IP_THREAT_FAILURE_QUEUE_CAP = 200;

export const SOFT_LOCK_DURATION_MS = 5 * 60_000;
export const IP_CHANGE_WINDOW_MS = 10 * 60_000;
export const IP_CHANGE_THRESHOLD = 3;
export const IP_HISTORY_MAX = IP_CHANGE_THRESHOLD + 3;

export const ANOMALY_RECENT_WINDOW_MS = 10 * 60_000;

const KEY_PREFIX = "pipass:";

export type SecurityStoreBackend = "memory" | "redis";

export type RateLimitResult = {
  limited: boolean;
  count: number;
  /** Shared store was unavailable; caller applied fail-closed policy. */
  degraded?: boolean;
};

export type AnomalySignal = {
  rateAnomalyMeta?: string;
  ipChangeFromIp?: string;
};

export type BurstSignal = { burstMeta?: string };

export type IpThreatDetection = {
  type: "brute_force" | "credential_stuffing";
  count: number;
  realUserIds: string[];
};

export type PasskeyFailureState = {
  windowStart: number;
  count: number;
  burstLogged: boolean;
  lastTouchedAt: number;
};

export type LoginFailureState = {
  windowStart: number;
  count: number;
  burstLogged: boolean;
  lastTouchedAt: number;
};

export type SoftLockReadOptions = {
  /**
   * When the shared store is unreachable:
   *   true  → treat the user as locked (vault write gates)
   *   false → return undefined (display / hydration)
   */
  failClosed?: boolean;
};

export interface SharedSecurityStore {
  readonly backend: SecurityStoreBackend;
  isDegraded(): boolean;

  incrementRateLimit(
    key: string,
    limit: number,
    windowMs?: number,
  ): Promise<RateLimitResult>;

  getSoftLockUntil(
    userId: string,
    opts?: SoftLockReadOptions,
  ): Promise<number | undefined>;
  triggerSoftLock(userId: string, durationMs?: number): Promise<number>;

  recordAnomaly(
    userId: string,
    action: "vault_fetch" | "vault_sync",
    ip: string,
  ): Promise<AnomalySignal>;

  recordPasskeyFailure(userId: string): Promise<BurstSignal>;
  decayPasskeyFailures(userId: string): Promise<void>;
  getPasskeyFailure(userId: string): Promise<PasskeyFailureState | undefined>;
  seedPasskeyFailures(
    userId: string,
    state: PasskeyFailureState,
  ): Promise<void>;

  recordLoginFailure(userId: string): Promise<BurstSignal>;
  decayLoginFailures(userId: string): Promise<void>;

  isIpBlocked(ip: string): Promise<boolean>;
  recordIpBlockedAttempt(ip: string): Promise<void>;
  recordIpFailure(
    ip: string,
    targetKey: string,
    realUserId: string | null,
  ): Promise<IpThreatDetection[]>;
  recordIpSuccess(ip: string): Promise<void>;
  getIpFailureQueueLength(ip: string): Promise<number>;

  trackIpAndCheckBurst(userId: string, ip: string): Promise<boolean>;

  recordRecentAnomalyAt(userId: string, at: number): Promise<void>;
  getRecentAnomalyAt(userId: string): Promise<number | undefined>;

  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Shared policy helpers (identical for memory + Redis)
// ---------------------------------------------------------------------------

type AnomalyState = {
  windowStart: number;
  fetchCount: number;
  syncCount: number;
  fetchAnomalyLogged: boolean;
  syncAnomalyLogged: boolean;
  ipChangeAnomalyLogged: boolean;
  lastIp?: string;
  lastTouchedAt: number;
};

type IpHistoryEntry = { ip: string; at: number };

type IpThreatEntry = {
  failureTimestamps: number[];
  targetTimestamps: Map<string, { lastSeen: number; isReal: boolean }>;
  lastSeenAt: number;
  blockedUntil?: number;
  bruteAlerted: boolean;
  stuffingAlerted: boolean;
};

function applyAnomaly(
  entry: AnomalyState | undefined,
  action: "vault_fetch" | "vault_sync",
  ip: string,
  now: number,
): { entry: AnomalyState; signal: AnomalySignal } {
  let next = entry;
  if (!next || now - next.windowStart > ANOMALY_WINDOW_MS) {
    next = {
      windowStart: now,
      fetchCount: 0,
      syncCount: 0,
      fetchAnomalyLogged: false,
      syncAnomalyLogged: false,
      ipChangeAnomalyLogged: false,
      lastIp: entry?.lastIp,
      lastTouchedAt: now,
    };
  }

  let rateAnomalyMeta: string | undefined;
  if (action === "vault_fetch") {
    next.fetchCount++;
    if (
      next.fetchCount > ANOMALY_FETCH_THRESHOLD &&
      !next.fetchAnomalyLogged
    ) {
      next.fetchAnomalyLogged = true;
      rateAnomalyMeta = `vault_fetch threshold exceeded (${next.fetchCount} in ${ANOMALY_WINDOW_MS / 1000}s)`;
    }
  } else {
    next.syncCount++;
    if (
      next.syncCount > ANOMALY_SYNC_THRESHOLD &&
      !next.syncAnomalyLogged
    ) {
      next.syncAnomalyLogged = true;
      rateAnomalyMeta = `vault_sync threshold exceeded (${next.syncCount} in ${ANOMALY_WINDOW_MS / 1000}s)`;
    }
  }

  let ipChangeFromIp: string | undefined;
  if (next.lastIp && next.lastIp !== ip && !next.ipChangeAnomalyLogged) {
    ipChangeFromIp = next.lastIp;
    next.ipChangeAnomalyLogged = true;
  }
  next.lastIp = ip;
  next.lastTouchedAt = now;
  return { entry: next, signal: { rateAnomalyMeta, ipChangeFromIp } };
}

function applyFailureBurst(
  entry: PasskeyFailureState | LoginFailureState | undefined,
  now: number,
  windowMs: number,
  threshold: number,
  label: string,
): { entry: PasskeyFailureState; signal: BurstSignal } {
  let next = entry;
  if (!next || now - next.windowStart > windowMs) {
    next = {
      windowStart: now,
      count: 0,
      burstLogged: false,
      lastTouchedAt: now,
    };
  }
  next.count++;
  next.lastTouchedAt = now;
  let burstMeta: string | undefined;
  if (next.count > threshold && !next.burstLogged) {
    next.burstLogged = true;
    burstMeta = `${label} failure threshold exceeded (${next.count} in ${windowMs / 1000}s)`;
  }
  return { entry: next, signal: { burstMeta } };
}

function decayFailureBurst(
  entry: PasskeyFailureState | LoginFailureState | undefined,
  now: number,
): PasskeyFailureState | undefined {
  if (!entry) return undefined;
  const next = {
    ...entry,
    count: Math.max(0, entry.count - 1),
    lastTouchedAt: now,
  };
  if (next.count === 0) return undefined;
  return next;
}

function pruneIpThreatEntry(entry: IpThreatEntry, now: number): void {
  const longerWindow = Math.max(
    IP_THREAT_BRUTE_WINDOW_MS,
    IP_THREAT_STUFFING_WINDOW_MS,
  );
  const cutoff = now - longerWindow;
  const ts = entry.failureTimestamps;
  let drop = 0;
  while (drop < ts.length && ts[drop] < cutoff) drop++;
  if (drop > 0) ts.splice(0, drop);
  for (const [key, val] of entry.targetTimestamps) {
    if (val.lastSeen < cutoff) entry.targetTimestamps.delete(key);
  }
}

function ipThreatBruteCount(entry: IpThreatEntry, now: number): number {
  const cutoff = now - IP_THREAT_BRUTE_WINDOW_MS;
  const ts = entry.failureTimestamps;
  let n = 0;
  for (let i = ts.length - 1; i >= 0; i--) {
    if (ts[i] >= cutoff) n++;
    else break;
  }
  return n;
}

function ipThreatStuffingCount(entry: IpThreatEntry, now: number): number {
  const cutoff = now - IP_THREAT_STUFFING_WINDOW_MS;
  let n = 0;
  for (const v of entry.targetTimestamps.values()) {
    if (v.lastSeen >= cutoff) n++;
  }
  return n;
}

function ipThreatRecentRealUserIds(
  entry: IpThreatEntry,
  now: number,
): string[] {
  const cutoff =
    now - Math.max(IP_THREAT_BRUTE_WINDOW_MS, IP_THREAT_STUFFING_WINDOW_MS);
  const out: string[] = [];
  for (const [key, val] of entry.targetTimestamps) {
    if (val.isReal && val.lastSeen >= cutoff) out.push(key);
  }
  return out;
}

function evaluateIpThreat(
  entry: IpThreatEntry,
  now: number,
): IpThreatDetection[] {
  const detections: IpThreatDetection[] = [];
  const bruteCount = ipThreatBruteCount(entry, now);
  if (!entry.bruteAlerted && bruteCount >= IP_THREAT_BRUTE_THRESHOLD) {
    entry.bruteAlerted = true;
    entry.blockedUntil = now + IP_THREAT_BLOCK_MS;
    detections.push({
      type: "brute_force",
      count: bruteCount,
      realUserIds: ipThreatRecentRealUserIds(entry, now),
    });
  }
  const stuffingCount = ipThreatStuffingCount(entry, now);
  if (
    !entry.stuffingAlerted &&
    stuffingCount >= IP_THREAT_STUFFING_THRESHOLD
  ) {
    entry.stuffingAlerted = true;
    entry.blockedUntil = now + IP_THREAT_BLOCK_MS;
    detections.push({
      type: "credential_stuffing",
      count: bruteCount,
      realUserIds: ipThreatRecentRealUserIds(entry, now),
    });
  }
  return detections;
}

function applyIpHistoryBurst(
  history: IpHistoryEntry[],
  ip: string,
  now: number,
): { history: IpHistoryEntry[]; crossed: boolean } {
  let next = history.filter((e) => now - e.at <= IP_CHANGE_WINDOW_MS);
  const transitionsBefore = Math.max(0, next.length - 1);
  const last = next[next.length - 1];
  if (!last || last.ip !== ip) {
    next.push({ ip, at: now });
  }
  if (next.length > IP_HISTORY_MAX) {
    next = next.slice(-IP_HISTORY_MAX);
  }
  const transitionsAfter = next.length - 1;
  return {
    history: next,
    crossed:
      transitionsAfter > IP_CHANGE_THRESHOLD &&
      transitionsBefore <= IP_CHANGE_THRESHOLD,
  };
}

function emptyIpThreat(now: number): IpThreatEntry {
  return {
    failureTimestamps: [],
    targetTimestamps: new Map(),
    lastSeenAt: now,
    bruteAlerted: false,
    stuffingAlerted: false,
  };
}

type IpThreatSerialized = {
  failureTimestamps: number[];
  targetTimestamps: Record<string, { lastSeen: number; isReal: boolean }>;
  lastSeenAt: number;
  blockedUntil?: number;
  bruteAlerted: boolean;
  stuffingAlerted: boolean;
};

function serializeIpThreat(entry: IpThreatEntry): IpThreatSerialized {
  const targetTimestamps: IpThreatSerialized["targetTimestamps"] = {};
  for (const [k, v] of entry.targetTimestamps) {
    targetTimestamps[k] = v;
  }
  return {
    failureTimestamps: entry.failureTimestamps,
    targetTimestamps,
    lastSeenAt: entry.lastSeenAt,
    blockedUntil: entry.blockedUntil,
    bruteAlerted: entry.bruteAlerted,
    stuffingAlerted: entry.stuffingAlerted,
  };
}

function deserializeIpThreat(raw: IpThreatSerialized): IpThreatEntry {
  return {
    failureTimestamps: raw.failureTimestamps ?? [],
    targetTimestamps: new Map(Object.entries(raw.targetTimestamps ?? {})),
    lastSeenAt: raw.lastSeenAt,
    blockedUntil: raw.blockedUntil,
    bruteAlerted: raw.bruteAlerted,
    stuffingAlerted: raw.stuffingAlerted,
  };
}

// ---------------------------------------------------------------------------
// Memory backend
// ---------------------------------------------------------------------------

export class MemorySecurityStore implements SharedSecurityStore {
  readonly backend = "memory" as const;

  private readonly rateLimitMap = new Map<
    string,
    { count: number; resetAt: number }
  >();
  private readonly softLocks = new Map<string, number>();
  private readonly anomalyState = new Map<string, AnomalyState>();
  private readonly passkeyFailureState = new Map<string, PasskeyFailureState>();
  private readonly loginFailureState = new Map<string, LoginFailureState>();
  private readonly ipThreatState = new Map<string, IpThreatEntry>();
  private readonly ipHistory = new Map<string, IpHistoryEntry[]>();
  private readonly recentAnomalyAt = new Map<string, number>();
  private readonly timers: ReturnType<typeof setInterval>[] = [];

  constructor() {
    this.timers.push(
      setInterval(() => this.gc(), 5 * 60_000),
    );
    for (const t of this.timers) {
      if (typeof t.unref === "function") t.unref();
    }
  }

  isDegraded(): boolean {
    return false;
  }

  async incrementRateLimit(
    key: string,
    limit: number,
    windowMs: number = RATE_LIMIT_WINDOW_MS,
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const entry = this.rateLimitMap.get(key);
    if (!entry || now > entry.resetAt) {
      this.rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
      return { limited: false, count: 1 };
    }
    entry.count++;
    return { limited: entry.count > limit, count: entry.count };
  }

  async getSoftLockUntil(
    userId: string,
    _opts?: SoftLockReadOptions,
  ): Promise<number | undefined> {
    const until = this.softLocks.get(userId);
    if (until === undefined) return undefined;
    if (until > Date.now()) return until;
    this.softLocks.delete(userId);
    return undefined;
  }

  async triggerSoftLock(
    userId: string,
    durationMs: number = SOFT_LOCK_DURATION_MS,
  ): Promise<number> {
    const candidate = Date.now() + durationMs;
    const next = Math.max(this.softLocks.get(userId) ?? 0, candidate);
    this.softLocks.set(userId, next);
    return next;
  }

  async recordAnomaly(
    userId: string,
    action: "vault_fetch" | "vault_sync",
    ip: string,
  ): Promise<AnomalySignal> {
    const { entry, signal } = applyAnomaly(
      this.anomalyState.get(userId),
      action,
      ip,
      Date.now(),
    );
    this.anomalyState.set(userId, entry);
    return signal;
  }

  async recordPasskeyFailure(userId: string): Promise<BurstSignal> {
    const { entry, signal } = applyFailureBurst(
      this.passkeyFailureState.get(userId),
      Date.now(),
      PASSKEY_FAILURE_WINDOW_MS,
      PASSKEY_FAILURE_THRESHOLD,
      "passkey",
    );
    this.passkeyFailureState.set(userId, entry);
    return signal;
  }

  async decayPasskeyFailures(userId: string): Promise<void> {
    const next = decayFailureBurst(
      this.passkeyFailureState.get(userId),
      Date.now(),
    );
    if (!next) this.passkeyFailureState.delete(userId);
    else this.passkeyFailureState.set(userId, next);
  }

  async getPasskeyFailure(
    userId: string,
  ): Promise<PasskeyFailureState | undefined> {
    return this.passkeyFailureState.get(userId);
  }

  async seedPasskeyFailures(
    userId: string,
    state: PasskeyFailureState,
  ): Promise<void> {
    if (!this.passkeyFailureState.has(userId)) {
      this.passkeyFailureState.set(userId, { ...state });
    }
  }

  async recordLoginFailure(userId: string): Promise<BurstSignal> {
    const { entry, signal } = applyFailureBurst(
      this.loginFailureState.get(userId),
      Date.now(),
      LOGIN_FAILURE_WINDOW_MS,
      LOGIN_FAILURE_THRESHOLD,
      "login",
    );
    this.loginFailureState.set(userId, entry);
    return signal;
  }

  async decayLoginFailures(userId: string): Promise<void> {
    const next = decayFailureBurst(
      this.loginFailureState.get(userId),
      Date.now(),
    );
    if (!next) this.loginFailureState.delete(userId);
    else this.loginFailureState.set(userId, next);
  }

  async isIpBlocked(ip: string): Promise<boolean> {
    if (!ip) return false;
    const entry = this.ipThreatState.get(ip);
    if (!entry?.blockedUntil) return false;
    if (entry.blockedUntil > Date.now()) return true;
    delete entry.blockedUntil;
    entry.bruteAlerted = false;
    entry.stuffingAlerted = false;
    return false;
  }

  async recordIpBlockedAttempt(ip: string): Promise<void> {
    if (!ip) return;
    const now = Date.now();
    const entry = this.ipThreatState.get(ip);
    if (!entry) return;
    pruneIpThreatEntry(entry, now);
    if (entry.failureTimestamps.length >= IP_THREAT_FAILURE_QUEUE_CAP) {
      entry.failureTimestamps.shift();
    }
    entry.failureTimestamps.push(now);
    entry.lastSeenAt = now;
  }

  async recordIpFailure(
    ip: string,
    targetKey: string,
    realUserId: string | null,
  ): Promise<IpThreatDetection[]> {
    if (!ip) return [];
    const now = Date.now();
    let entry = this.ipThreatState.get(ip);
    if (!entry) {
      entry = emptyIpThreat(now);
      this.ipThreatState.set(ip, entry);
    }
    pruneIpThreatEntry(entry, now);
    if (entry.failureTimestamps.length >= IP_THREAT_FAILURE_QUEUE_CAP) {
      entry.failureTimestamps.shift();
    }
    entry.failureTimestamps.push(now);
    if (
      entry.targetTimestamps.has(targetKey) ||
      entry.targetTimestamps.size < IP_THREAT_TARGETS_CAP
    ) {
      entry.targetTimestamps.set(targetKey, {
        lastSeen: now,
        isReal: realUserId !== null,
      });
    }
    entry.lastSeenAt = now;
    return evaluateIpThreat(entry, now);
  }

  async recordIpSuccess(ip: string): Promise<void> {
    if (!ip) return;
    const entry = this.ipThreatState.get(ip);
    if (!entry) return;
    for (
      let i = 0;
      i < IP_THREAT_DECAY_PER_SUCCESS && entry.failureTimestamps.length > 0;
      i++
    ) {
      entry.failureTimestamps.pop();
    }
    entry.lastSeenAt = Date.now();
    if (entry.failureTimestamps.length === 0 && !entry.blockedUntil) {
      this.ipThreatState.delete(ip);
    }
  }

  async getIpFailureQueueLength(ip: string): Promise<number> {
    return this.ipThreatState.get(ip)?.failureTimestamps.length ?? 0;
  }

  async trackIpAndCheckBurst(userId: string, ip: string): Promise<boolean> {
    const { history, crossed } = applyIpHistoryBurst(
      this.ipHistory.get(userId) ?? [],
      ip,
      Date.now(),
    );
    this.ipHistory.set(userId, history);
    return crossed;
  }

  async recordRecentAnomalyAt(userId: string, at: number): Promise<void> {
    this.recentAnomalyAt.set(userId, at);
  }

  async getRecentAnomalyAt(userId: string): Promise<number | undefined> {
    const at = this.recentAnomalyAt.get(userId);
    if (at === undefined) return undefined;
    if (Date.now() - at > ANOMALY_RECENT_WINDOW_MS) {
      this.recentAnomalyAt.delete(userId);
      return undefined;
    }
    return at;
  }

  async close(): Promise<void> {
    for (const t of this.timers) clearInterval(t);
    this.timers.length = 0;
  }

  private gc(): void {
    const now = Date.now();
    for (const [key, entry] of this.rateLimitMap) {
      if (now > entry.resetAt) this.rateLimitMap.delete(key);
    }
    for (const [k, v] of this.anomalyState) {
      if (now - v.lastTouchedAt > ANOMALY_STATE_TTL_MS) {
        this.anomalyState.delete(k);
      }
    }
    for (const [k, v] of this.passkeyFailureState) {
      if (now - v.lastTouchedAt > PASSKEY_FAILURE_STATE_TTL_MS) {
        this.passkeyFailureState.delete(k);
      }
    }
    for (const [k, v] of this.loginFailureState) {
      if (now - v.lastTouchedAt > LOGIN_FAILURE_STATE_TTL_MS) {
        this.loginFailureState.delete(k);
      }
    }
    for (const [k, v] of this.ipThreatState) {
      if (now - v.lastSeenAt > IP_THREAT_INACTIVITY_TTL_MS) {
        this.ipThreatState.delete(k);
      }
    }
    for (const [k, until] of this.softLocks) {
      if (until <= now) this.softLocks.delete(k);
    }
    for (const [k, hist] of this.ipHistory) {
      const kept = hist.filter((e) => now - e.at <= IP_CHANGE_WINDOW_MS);
      if (kept.length === 0) this.ipHistory.delete(k);
      else this.ipHistory.set(k, kept);
    }
    for (const [k, at] of this.recentAnomalyAt) {
      if (now - at > ANOMALY_RECENT_WINDOW_MS) this.recentAnomalyAt.delete(k);
    }
  }
}

// ---------------------------------------------------------------------------
// Redis backend
// ---------------------------------------------------------------------------

const INCR_WINDOW_LUA = `
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n
`;

const TRIGGER_SLOCK_LUA = `
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local candidate = tonumber(ARGV[1])
local px = tonumber(ARGV[2])
if current > candidate then
  return current
end
redis.call('SET', KEYS[1], tostring(candidate), 'PX', px)
return candidate
`;

export type RedisSecurityStoreOptions = {
  redis?: Redis;
  connectTimeout?: number;
  commandTimeout?: number;
};

export class RedisSecurityStore implements SharedSecurityStore {
  readonly backend = "redis" as const;
  private readonly redis: Redis;
  private readonly ownsClient: boolean;
  private healthy = false;
  private connecting: Promise<void> | null = null;

  constructor(url: string, options: RedisSecurityStoreOptions = {}) {
    if (options.redis) {
      this.redis = options.redis;
      this.ownsClient = false;
      this.healthy = options.redis.status === "ready";
    } else {
      this.ownsClient = true;
      this.redis = new Redis(url, {
        lazyConnect: true,
        enableOfflineQueue: false,
        maxRetriesPerRequest: 1,
        connectTimeout: options.connectTimeout ?? 750,
        commandTimeout: options.commandTimeout ?? 500,
        retryStrategy(times) {
          return Math.min(times * 200, 2000);
        },
      });
    }
    this.redis.on("ready", () => {
      this.healthy = true;
    });
    this.redis.on("end", () => {
      this.healthy = false;
    });
    this.redis.on("error", () => {
      this.healthy = false;
    });
  }

  isDegraded(): boolean {
    return !this.healthy;
  }

  async incrementRateLimit(
    key: string,
    limit: number,
    windowMs: number = RATE_LIMIT_WINDOW_MS,
  ): Promise<RateLimitResult> {
    try {
      const n = Number(
        await this.eval(INCR_WINDOW_LUA, [this.k("rl", key)], [String(windowMs)]),
      );
      return { limited: n > limit, count: n };
    } catch {
      this.healthy = false;
      return { limited: true, count: limit + 1, degraded: true };
    }
  }

  async getSoftLockUntil(
    userId: string,
    opts?: SoftLockReadOptions,
  ): Promise<number | undefined> {
    try {
      const raw = await this.cmd(() => this.redis.get(this.k("slock", userId)));
      if (!raw) return undefined;
      const until = Number(raw);
      if (!Number.isFinite(until) || until <= Date.now()) {
        await this.cmd(() => this.redis.del(this.k("slock", userId)));
        return undefined;
      }
      return until;
    } catch {
      this.healthy = false;
      if (opts?.failClosed) return Date.now() + SOFT_LOCK_DURATION_MS;
      return undefined;
    }
  }

  async triggerSoftLock(
    userId: string,
    durationMs: number = SOFT_LOCK_DURATION_MS,
  ): Promise<number> {
    const candidate = Date.now() + durationMs;
    try {
      const until = Number(
        await this.eval(
          TRIGGER_SLOCK_LUA,
          [this.k("slock", userId)],
          [String(candidate), String(durationMs)],
        ),
      );
      return Number.isFinite(until) ? until : candidate;
    } catch {
      this.healthy = false;
      return candidate;
    }
  }

  async recordAnomaly(
    userId: string,
    action: "vault_fetch" | "vault_sync",
    ip: string,
  ): Promise<AnomalySignal> {
    try {
      const { signal } = await this.mutateJson<AnomalyState, AnomalySignal>(
        this.k("anom", userId),
        ANOMALY_STATE_TTL_MS,
        (cur) => applyAnomaly(cur, action, ip, Date.now()),
      );
      return signal;
    } catch {
      this.healthy = false;
      return {};
    }
  }

  async recordPasskeyFailure(userId: string): Promise<BurstSignal> {
    try {
      const { signal } = await this.mutateJson<PasskeyFailureState, BurstSignal>(
        this.k("pfail", userId),
        PASSKEY_FAILURE_STATE_TTL_MS,
        (cur) =>
          applyFailureBurst(
            cur,
            Date.now(),
            PASSKEY_FAILURE_WINDOW_MS,
            PASSKEY_FAILURE_THRESHOLD,
            "passkey",
          ),
      );
      return signal;
    } catch {
      this.healthy = false;
      return {};
    }
  }

  async decayPasskeyFailures(userId: string): Promise<void> {
    try {
      await this.mutateJson<PasskeyFailureState>(
        this.k("pfail", userId),
        PASSKEY_FAILURE_STATE_TTL_MS,
        (cur) => {
          const next = decayFailureBurst(cur, Date.now());
          return { entry: next, signal: undefined };
        },
      );
    } catch {
      this.healthy = false;
    }
  }

  async getPasskeyFailure(
    userId: string,
  ): Promise<PasskeyFailureState | undefined> {
    try {
      return await this.getJson<PasskeyFailureState>(this.k("pfail", userId));
    } catch {
      this.healthy = false;
      return undefined;
    }
  }

  async seedPasskeyFailures(
    userId: string,
    state: PasskeyFailureState,
  ): Promise<void> {
    try {
      const key = this.k("pfail", userId);
      const existing = await this.cmd(() => this.redis.get(key));
      if (existing) return;
      await this.cmd(() =>
        this.redis.set(key, JSON.stringify(state), "PX", PASSKEY_FAILURE_STATE_TTL_MS),
      );
    } catch {
      this.healthy = false;
    }
  }

  async recordLoginFailure(userId: string): Promise<BurstSignal> {
    try {
      const { signal } = await this.mutateJson<LoginFailureState, BurstSignal>(
        this.k("lfail", userId),
        LOGIN_FAILURE_STATE_TTL_MS,
        (cur) =>
          applyFailureBurst(
            cur,
            Date.now(),
            LOGIN_FAILURE_WINDOW_MS,
            LOGIN_FAILURE_THRESHOLD,
            "login",
          ),
      );
      return signal;
    } catch {
      this.healthy = false;
      return {};
    }
  }

  async decayLoginFailures(userId: string): Promise<void> {
    try {
      await this.mutateJson<LoginFailureState>(
        this.k("lfail", userId),
        LOGIN_FAILURE_STATE_TTL_MS,
        (cur) => {
          const next = decayFailureBurst(cur, Date.now());
          return { entry: next, signal: undefined };
        },
      );
    } catch {
      this.healthy = false;
    }
  }

  async isIpBlocked(ip: string): Promise<boolean> {
    if (!ip) return false;
    try {
      const key = this.k("ipth", ip);
      const entry = await this.getJson<IpThreatSerialized>(key);
      if (!entry?.blockedUntil) return false;
      if (entry.blockedUntil > Date.now()) return true;
      delete entry.blockedUntil;
      entry.bruteAlerted = false;
      entry.stuffingAlerted = false;
      await this.cmd(() =>
        this.redis.set(
          key,
          JSON.stringify(entry),
          "PX",
          IP_THREAT_INACTIVITY_TTL_MS,
        ),
      );
      return false;
    } catch {
      this.healthy = false;
      return true;
    }
  }

  async recordIpBlockedAttempt(ip: string): Promise<void> {
    if (!ip) return;
    try {
      await this.mutateJson<IpThreatSerialized>(
        this.k("ipth", ip),
        IP_THREAT_INACTIVITY_TTL_MS,
        (raw) => {
          if (!raw) return { entry: undefined, signal: undefined };
          const entry = deserializeIpThreat(raw);
          const now = Date.now();
          pruneIpThreatEntry(entry, now);
          if (entry.failureTimestamps.length >= IP_THREAT_FAILURE_QUEUE_CAP) {
            entry.failureTimestamps.shift();
          }
          entry.failureTimestamps.push(now);
          entry.lastSeenAt = now;
          return { entry: serializeIpThreat(entry), signal: undefined };
        },
      );
    } catch {
      this.healthy = false;
    }
  }

  async recordIpFailure(
    ip: string,
    targetKey: string,
    realUserId: string | null,
  ): Promise<IpThreatDetection[]> {
    if (!ip) return [];
    try {
      const { signal } = await this.mutateJson<IpThreatSerialized, IpThreatDetection[]>(
        this.k("ipth", ip),
        IP_THREAT_INACTIVITY_TTL_MS,
        (raw) => {
          const now = Date.now();
          const entry = raw ? deserializeIpThreat(raw) : emptyIpThreat(now);
          pruneIpThreatEntry(entry, now);
          if (entry.failureTimestamps.length >= IP_THREAT_FAILURE_QUEUE_CAP) {
            entry.failureTimestamps.shift();
          }
          entry.failureTimestamps.push(now);
          if (
            entry.targetTimestamps.has(targetKey) ||
            entry.targetTimestamps.size < IP_THREAT_TARGETS_CAP
          ) {
            entry.targetTimestamps.set(targetKey, {
              lastSeen: now,
              isReal: realUserId !== null,
            });
          }
          entry.lastSeenAt = now;
          const detections = evaluateIpThreat(entry, now);
          return { entry: serializeIpThreat(entry), signal: detections };
        },
      );
      return signal ?? [];
    } catch {
      this.healthy = false;
      return [];
    }
  }

  async recordIpSuccess(ip: string): Promise<void> {
    if (!ip) return;
    try {
      await this.mutateJson<IpThreatSerialized>(
        this.k("ipth", ip),
        IP_THREAT_INACTIVITY_TTL_MS,
        (raw) => {
          if (!raw) return { entry: undefined, signal: undefined };
          const entry = deserializeIpThreat(raw);
          for (
            let i = 0;
            i < IP_THREAT_DECAY_PER_SUCCESS &&
            entry.failureTimestamps.length > 0;
            i++
          ) {
            entry.failureTimestamps.pop();
          }
          entry.lastSeenAt = Date.now();
          if (entry.failureTimestamps.length === 0 && !entry.blockedUntil) {
            return { entry: undefined, signal: undefined };
          }
          return { entry: serializeIpThreat(entry), signal: undefined };
        },
      );
    } catch {
      this.healthy = false;
    }
  }

  async getIpFailureQueueLength(ip: string): Promise<number> {
    try {
      const entry = await this.getJson<IpThreatSerialized>(this.k("ipth", ip));
      return entry?.failureTimestamps.length ?? 0;
    } catch {
      this.healthy = false;
      return 0;
    }
  }

  async trackIpAndCheckBurst(userId: string, ip: string): Promise<boolean> {
    try {
      const { signal } = await this.mutateJson<IpHistoryEntry[], boolean>(
        this.k("iph", userId),
        IP_CHANGE_WINDOW_MS,
        (cur) => {
          const { history, crossed } = applyIpHistoryBurst(
            cur ?? [],
            ip,
            Date.now(),
          );
          return { entry: history, signal: crossed };
        },
      );
      return Boolean(signal);
    } catch {
      this.healthy = false;
      return false;
    }
  }

  async recordRecentAnomalyAt(userId: string, at: number): Promise<void> {
    try {
      await this.cmd(() =>
        this.redis.set(
          this.k("ranom", userId),
          String(at),
          "PX",
          ANOMALY_RECENT_WINDOW_MS,
        ),
      );
    } catch {
      this.healthy = false;
    }
  }

  async getRecentAnomalyAt(userId: string): Promise<number | undefined> {
    try {
      const raw = await this.cmd(() => this.redis.get(this.k("ranom", userId)));
      if (!raw) return undefined;
      const at = Number(raw);
      return Number.isFinite(at) ? at : undefined;
    } catch {
      this.healthy = false;
      return undefined;
    }
  }

  async close(): Promise<void> {
    if (!this.ownsClient) return;
    try {
      this.redis.disconnect();
    } catch {
      // ignore
    }
  }

  private k(kind: string, id: string): string {
    return `${KEY_PREFIX}${kind}:${id}`;
  }

  private async ensureConnected(): Promise<void> {
    if (this.redis.status === "ready") {
      this.healthy = true;
      return;
    }
    if (!this.connecting) {
      this.connecting = this.redis
        .connect()
        .then(() => {
          this.healthy = true;
        })
        .catch((err: unknown) => {
          this.healthy = false;
          throw err;
        })
        .finally(() => {
          this.connecting = null;
        });
    }
    await this.connecting;
  }

  private async cmd<T>(fn: () => Promise<T>): Promise<T> {
    await this.ensureConnected();
    const result = await fn();
    this.healthy = true;
    return result;
  }

  private async eval(
    script: string,
    keys: string[],
    args: string[],
  ): Promise<unknown> {
    await this.ensureConnected();
    const result = await this.redis.eval(script, keys.length, ...keys, ...args);
    this.healthy = true;
    return result;
  }

  private async getJson<T>(key: string): Promise<T | undefined> {
    const raw = await this.cmd(() => this.redis.get(key));
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return undefined;
    }
  }

  private async mutateJson<T, S = undefined>(
    key: string,
    ttlMs: number,
    fn: (current: T | undefined) => { entry: T | undefined; signal: S },
  ): Promise<{ entry: T | undefined; signal: S }> {
    const current = await this.getJson<T>(key);
    const result = fn(current);
    if (result.entry === undefined) {
      await this.cmd(() => this.redis.del(key));
    } else {
      await this.cmd(() =>
        this.redis.set(key, JSON.stringify(result.entry), "PX", ttlMs),
      );
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

let sharedStore: SharedSecurityStore | null = null;

export function resolveRedisUrl(
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const url = env.REDIS_URL?.trim();
  return url ? url : undefined;
}

export function createSecurityStore(
  env: NodeJS.ProcessEnv = process.env,
): SharedSecurityStore {
  const url = resolveRedisUrl(env);
  if (!url) {
    if (env.NODE_ENV === "production") {
      console.warn(
        "[security-store] REDIS_URL is not set. Rate limits, soft-locks, " +
          "and IP-threat state are process-local and will not be shared " +
          "across instances or survive restart. Set REDIS_URL in production.",
      );
    }
    return new MemorySecurityStore();
  }
  console.info("[security-store] using Redis at REDIS_URL for shared security state");
  return new RedisSecurityStore(url);
}

export function getSharedSecurityStore(): SharedSecurityStore {
  if (!sharedStore) {
    sharedStore = createSecurityStore();
  }
  return sharedStore;
}

/** Test-only: replace or clear the process singleton. */
export function resetSharedSecurityStoreForTests(
  store?: SharedSecurityStore | null,
): void {
  sharedStore = store ?? null;
}

export function hashUsernameForIpThreat(username: string): string {
  return (
    "u:" + createHash("sha256").update(username).digest("hex").slice(0, 32)
  );
}
