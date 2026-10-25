// Shared security state (rate limits / soft-lock / IP threat) uses Redis
// only when REDIS_URL is set. A developer .env that points at a down
// Redis would fail-close every login in this suite, so we drop REDIS_URL
// unless the operator explicitly opted into a test Redis via TEST_REDIS_URL.
if (process.env.TEST_REDIS_URL?.trim()) {
  process.env.REDIS_URL = process.env.TEST_REDIS_URL.trim();
} else {
  delete process.env.REDIS_URL;
}

const testDatabaseUrl = process.env.TEST_DATABASE_URL?.trim();

if (testDatabaseUrl) {
  process.env.DATABASE_URL = testDatabaseUrl;
  console.warn(
    "[test-env] TEST_DATABASE_URL is set; server tests will use the dedicated test database.",
  );
} else {
  console.warn(
    "[test-env] TEST_DATABASE_URL is not set; server tests will use DATABASE_URL and may write test rows to that database.",
  );
}

// Stub react-native for Node unit tests (tsx cannot transform RN's Flow entrypoint).
// keyDerivation and other modules import Platform; keep OS as "web" so native Argon2
// is skipped and hash-wasm / PBKDF2 paths are exercised in CI.
try {
  const Module = require("module");
  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === "react-native") {
      return {
        Platform: { OS: "web", select: (spec) => spec.web ?? spec.default },
        NativeModules: {},
      };
    }
    return originalLoad.apply(this, arguments);
  };
} catch {
  // ignore if Module hook unavailable
}
