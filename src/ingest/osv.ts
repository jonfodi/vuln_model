import { getDb } from "../db";
import { osvAdapter, type OsvIngestOptions } from "./adapters/osv";
import { ingestSource } from "./orchestrator";
import type { IngestDb } from "./repository";
import type { IngestResult } from "./types";

export type { OsvIngestOptions };
export type OsvIngestResult = IngestResult;

export async function ingestOsvDirectoryFromEnv(options: OsvIngestOptions) {
  return ingestOsvDirectory(getDb(), options);
}

export async function ingestOsvDirectory(
  db: IngestDb,
  options: OsvIngestOptions,
) {
  return ingestSource(db, osvAdapter, options);
}
