import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "../shared/schema";
import { poolConfigFromResolved, resolveDatabaseConfig } from "./dbConfig";

const databaseConfig = resolveDatabaseConfig();

export const pool = new Pool(poolConfigFromResolved(databaseConfig));

if (process.env.NODE_ENV === "production") {
  console.info(
    `[db] TLS mode=${databaseConfig.sslMode} host=${databaseConfig.hostLabel}`,
  );
}

export const db = drizzle(pool, { schema });

export type DB = typeof db;
