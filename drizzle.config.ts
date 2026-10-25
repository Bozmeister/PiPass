import "dotenv/config";
import { defineConfig } from "drizzle-kit";
import { resolveDatabaseConfig } from "./server/dbConfig";

const databaseConfig = resolveDatabaseConfig();

export default defineConfig({
  out: "./migrations",
  schema: "./shared/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: databaseConfig.connectionString,
    ssl: databaseConfig.ssl === false ? false : databaseConfig.ssl,
  },
});
