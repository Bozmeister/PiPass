import { test, after } from "node:test";
import assert from "node:assert/strict";
import {
  MemorySecurityStore,
  RedisSecurityStore,
  createSecurityStore,
  RATE_LIMIT_WINDOW_MS,
  SOFT_LOCK_DURATION_MS,
  ANOMALY_FETCH_THRESHOLD,
  ANOMALY_SYNC_THRESHOLD,
  IP_CHANGE_THRESHOLD,
  IP_THREAT_BRUTE_THRESHOLD,
  PASSKEY_FAILURE_THRESHOLD,
} from "../securityStore";

const stores: Array<{ close(): Promise<void> }> = [];

after(async () => {
  await Promise.all(stores.map((s) => s.close()));
});

function memory(): MemorySecurityStore {
  const s = new MemorySecurityStore();
  stores.push(s);
  return s;
}

test("createSecurityStore uses memory when REDIS_URL is unset", () => {
  const store = createSecurityStore({ NODE_ENV: "test" });
  stores.push(store);
  assert.equal(store.backend, "memory");
  assert.equal(store.isDegraded(), false);
});

test("memory rate limit: first N requests pass, N+1 is limited", async () => {
  const store = memory();
  const key = "login:10.0.0.1";
  for (let i = 1; i <= 10; i++) {
    const r = await store.incrementRateLimit(key, 10);
    assert.equal(r.limited, false, `request ${i} should be allowed`);
    assert.equal(r.count, i);
  }
  const blocked = await store.incrementRateLimit(key, 10);
  assert.equal(blocked.limited, true);
  assert.equal(blocked.count, 11);
});

test("memory rate limit: independent keys do not share a bucket", async () => {
  const store = memory();
  for (let i = 0; i < 10; i++) {
    await store.incrementRateLimit("login:10.0.0.1", 10);
  }
  const other = await store.incrementRateLimit("login:10.0.0.2", 10);
  assert.equal(other.limited, false);
  assert.equal(other.count, 1);
});

test("memory rate limit: window expiry starts a new count", async () => {
  const store = memory();
  const key = "salt:10.1.2.3";
  await store.incrementRateLimit(key, 2, 5);
  await store.incrementRateLimit(key, 2, 5);
  assert.equal((await store.incrementRateLimit(key, 2, 5)).limited, true);
  await new Promise((r) => setTimeout(r, 8));
  const after = await store.incrementRateLimit(key, 2, 5);
  assert.equal(after.limited, false);
  assert.equal(after.count, 1);
  assert.ok(RATE_LIMIT_WINDOW_MS >= 1000);
});

test("memory soft-lock: trigger, read, and expire", async () => {
  const store = memory();
  const userId = "user-lock-1";
  assert.equal(await store.getSoftLockUntil(userId), undefined);
  const until = await store.triggerSoftLock(userId, 40);
  assert.ok(until > Date.now());
  assert.equal(await store.getSoftLockUntil(userId), until);
  const again = await store.triggerSoftLock(userId, 10);
  assert.equal(again, until, "shorter candidate must not shrink an existing lock");
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(await store.getSoftLockUntil(userId), undefined);
});

test("memory anomaly: fetch/sync thresholds fire once per window", async () => {
  const store = memory();
  const userId = "user-anom-1";
  for (let i = 0; i < ANOMALY_FETCH_THRESHOLD; i++) {
    const s = await store.recordAnomaly(userId, "vault_fetch", "10.0.0.1");
    assert.equal(s.rateAnomalyMeta, undefined);
  }
  const crossed = await store.recordAnomaly(userId, "vault_fetch", "10.0.0.1");
  assert.match(crossed.rateAnomalyMeta ?? "", /vault_fetch threshold exceeded/);
  const again = await store.recordAnomaly(userId, "vault_fetch", "10.0.0.1");
  assert.equal(again.rateAnomalyMeta, undefined, "deduped inside the same window");

  const syncUser = "user-anom-2";
  for (let i = 0; i < ANOMALY_SYNC_THRESHOLD; i++) {
    await store.recordAnomaly(syncUser, "vault_sync", "10.0.0.2");
  }
  const syncCross = await store.recordAnomaly(syncUser, "vault_sync", "10.0.0.2");
  assert.match(syncCross.rateAnomalyMeta ?? "", /vault_sync threshold exceeded/);
});

test("memory anomaly: first IP change in a window is reported", async () => {
  const store = memory();
  const userId = "user-ip-change";
  const first = await store.recordAnomaly(userId, "vault_fetch", "10.0.0.1");
  assert.equal(first.ipChangeFromIp, undefined);
  const second = await store.recordAnomaly(userId, "vault_fetch", "10.0.0.2");
  assert.equal(second.ipChangeFromIp, "10.0.0.1");
  const third = await store.recordAnomaly(userId, "vault_fetch", "10.0.0.3");
  assert.equal(third.ipChangeFromIp, undefined);
});

test("memory passkey/login burst: 6th failure in window escalates; decay is one step", async () => {
  const store = memory();
  const userId = "user-burst";
  for (let i = 0; i <= PASSKEY_FAILURE_THRESHOLD; i++) {
    const s = await store.recordPasskeyFailure(userId);
    if (i < PASSKEY_FAILURE_THRESHOLD) {
      assert.equal(s.burstMeta, undefined);
    } else {
      assert.match(s.burstMeta ?? "", /passkey failure threshold exceeded/);
    }
  }
  assert.equal((await store.recordPasskeyFailure(userId)).burstMeta, undefined);

  const loginId = "user-login-burst";
  for (let i = 0; i <= PASSKEY_FAILURE_THRESHOLD; i++) {
    await store.recordLoginFailure(loginId);
  }
  const loginBurst = await store.recordLoginFailure(loginId);
  // already logged on the 6th; 7th is deduped
  assert.equal(loginBurst.burstMeta, undefined);

  await store.decayPasskeyFailures(userId);
  const after = await store.getPasskeyFailure(userId);
  assert.ok(after);
  assert.equal(after!.count, PASSKEY_FAILURE_THRESHOLD + 1);
});

test("memory IP-change burst: edge-detects the crossing only", async () => {
  const store = memory();
  const userId = "user-burst-ip";
  assert.equal(await store.trackIpAndCheckBurst(userId, "10.0.0.1"), false);
  assert.equal(await store.trackIpAndCheckBurst(userId, "10.0.0.2"), false);
  assert.equal(await store.trackIpAndCheckBurst(userId, "10.0.0.3"), false);
  assert.equal(await store.trackIpAndCheckBurst(userId, "10.0.0.4"), false);
  // transitions = 4 > IP_CHANGE_THRESHOLD (3)
  assert.equal(await store.trackIpAndCheckBurst(userId, "10.0.0.5"), true);
  assert.equal(
    await store.trackIpAndCheckBurst(userId, "10.0.0.6"),
    false,
    "already past threshold — no second edge",
  );
  assert.ok(IP_CHANGE_THRESHOLD === 3);
});

test("memory IP threat: brute-force block after threshold; login fail-closed not required here", async () => {
  const store = memory();
  const ip = "198.51.100.9";
  const userId = "user-brute";
  assert.equal(await store.isIpBlocked(ip), false);
  let detections = 0;
  for (let i = 0; i < IP_THREAT_BRUTE_THRESHOLD; i++) {
    const d = await store.recordIpFailure(ip, userId, userId);
    detections += d.length;
  }
  assert.ok(detections >= 1);
  assert.equal(await store.isIpBlocked(ip), true);
  assert.ok((await store.getIpFailureQueueLength(ip)) >= IP_THREAT_BRUTE_THRESHOLD);
  await store.recordIpSuccess(ip);
  assert.ok(
    (await store.getIpFailureQueueLength(ip)) < IP_THREAT_BRUTE_THRESHOLD,
  );
});

test("Redis store fail-closes rate limits, write locks, and IP blocks when unreachable", async () => {
  const store = new RedisSecurityStore("redis://127.0.0.1:1", {
    connectTimeout: 80,
    commandTimeout: 80,
  });
  stores.push(store);

  const limited = await store.incrementRateLimit("login:203.0.113.1", 10);
  assert.equal(limited.limited, true);
  assert.equal(limited.degraded, true);

  const lock = await store.getSoftLockUntil("user-x", { failClosed: true });
  assert.ok(lock !== undefined && lock > Date.now());

  const display = await store.getSoftLockUntil("user-x", { failClosed: false });
  assert.equal(display, undefined);

  assert.equal(await store.isIpBlocked("203.0.113.1"), true);

  const anomaly = await store.recordAnomaly("user-x", "vault_fetch", "203.0.113.1");
  assert.deepEqual(anomaly, {});

  assert.equal(store.backend, "redis");
  assert.ok(SOFT_LOCK_DURATION_MS > 0);
});
