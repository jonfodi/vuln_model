import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

let client: postgres.Sql | undefined;

export function getDb() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required to create a database client.");
  }

  client ??= postgres(databaseUrl, {
    max: databaseConnectionLimit(),
  });

  return drizzle(client, { schema });
}

function databaseConnectionLimit() {
  const configured = Number(process.env.DATABASE_MAX_CONNECTIONS);
  if (Number.isFinite(configured) && configured > 0) {
    return Math.floor(configured);
  }

  return process.env.VERCEL ? 1 : 10;
}

export async function closeDb() {
  if (!client) {
    return;
  }

  const currentClient = client;
  client = undefined;
  await currentClient.end();
}
