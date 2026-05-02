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
