import { getDb } from "../db";
import { cveAdapter, type CveIngestOptions } from "./adapters/cve";
import { ingestSource } from "./orchestrator";
import type { IngestDb } from "./repository";
import type { IngestResult } from "./types";

export type { CveIngestOptions };
export type CveIngestResult = IngestResult;

export async function ingestCveDirectoryFromEnv(options: CveIngestOptions) {
  return ingestCveDirectory(getDb(), options);
}

export async function ingestCveDirectory(
  db: IngestDb,
  options: CveIngestOptions,
) {
  return ingestSource(db, cveAdapter, options);
}
