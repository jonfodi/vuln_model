import { getDb } from "../db";
import { epssAdapter, type EpssIngestOptions } from "./adapters/epss";
import { ingestSource } from "./orchestrator";
import type { IngestDb } from "./repository";
import type { IngestResult } from "./types";

export type { EpssIngestOptions };
export type EpssIngestResult = IngestResult;

export async function ingestEpssCsvFromEnv(options: EpssIngestOptions) {
  return ingestEpssCsv(getDb(), options);
}

export async function ingestEpssCsv(db: IngestDb, options: EpssIngestOptions) {
  return ingestSource(db, epssAdapter, options);
}
