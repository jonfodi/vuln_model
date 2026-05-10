import { getDb } from "../db";
import { kevAdapter, type KevIngestOptions } from "./adapters/kev";
import { ingestSource } from "./orchestrator";
import type { IngestDb } from "./repository";
import type { IngestResult } from "./types";

export type { KevIngestOptions };
export type KevIngestResult = IngestResult;

export async function ingestKevFileFromEnv(options: KevIngestOptions) {
  return ingestKevFile(getDb(), options);
}

export async function ingestKevFile(db: IngestDb, options: KevIngestOptions) {
  return ingestSource(db, kevAdapter, options);
}
