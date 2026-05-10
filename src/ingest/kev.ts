import { readFile } from "node:fs/promises";
import { getDb } from "../db";
import {
  linkVulnerabilityIdentifier,
  upsertIdentifier,
  upsertKevEntry,
  upsertSource,
  upsertSourceRecord,
  upsertVulnerability,
  type IngestDb,
} from "./repository";
import { SOURCE_SEEDS, seedReferenceData } from "./seed";
import {
  asArray,
  asObject,
  asString,
  normalizeIdentifierValue,
  toDateString,
  type JsonObject,
} from "./standardize";

export type KevIngestOptions = {
  file: string;
};

export type KevIngestResult = {
  scanned: number;
  ingested: number;
  failed: Array<{ cveId: string; error: string }>;
};

export async function ingestKevFileFromEnv(options: KevIngestOptions) {
  return ingestKevFile(getDb(), options);
}

export async function ingestKevFile(
  db: IngestDb,
  options: KevIngestOptions,
): Promise<KevIngestResult> {
  await seedReferenceData(db);

  const sourceSeed = SOURCE_SEEDS.find((source) => source.slug === "cisa-kev");
  if (!sourceSeed) {
    throw new Error("Missing cisa-kev source seed.");
  }

  const source = await upsertSource(db, sourceSeed);
  const raw = JSON.parse(await readFile(options.file, "utf8")) as unknown;
  const catalog = asObject(raw);
  const entries = asArray(catalog?.vulnerabilities);
  const result: KevIngestResult = { scanned: 0, ingested: 0, failed: [] };

  for (const entryValue of entries) {
    const entry = asObject(entryValue);
    const cveId = asString(entry?.cveID) ?? asString(entry?.cveId) ?? "unknown";
    result.scanned += 1;

    if (!entry) {
      result.failed.push({ cveId, error: "Expected vulnerability object." });
      continue;
    }

    try {
      await ingestKevEntry(db, {
        sourceId: source.id,
        entry,
      });
      result.ingested += 1;
    } catch (error) {
      result.failed.push({
        cveId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return result;
}

async function ingestKevEntry(
  db: IngestDb,
  input: {
    sourceId: string;
    entry: JsonObject;
  },
) {
  const cveId = asString(input.entry.cveID) ?? asString(input.entry.cveId);
  if (!cveId) {
    throw new Error("KEV entry is missing cveID.");
  }

  const normalizedCveId = normalizeIdentifierValue(cveId);
  const identifier = await upsertIdentifier(db, normalizedCveId);
  const vulnerability = await upsertVulnerability(db, {
    primaryIdentifier: normalizedCveId,
    title: asString(input.entry.vulnerabilityName),
    summary: asString(input.entry.shortDescription),
    preserveExistingText: true,
  });
  await linkVulnerabilityIdentifier(db, vulnerability.id, identifier.id, "primary");
  const sourceRecord = await upsertSourceRecord(db, {
    sourceId: input.sourceId,
    externalId: normalizedCveId,
    url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${normalizedCveId}`,
    sourcePublishedAt: null,
    sourceModifiedAt: null,
    raw: input.entry,
  });

  await upsertKevEntry(db, {
    vulnerabilityId: vulnerability.id,
    sourceRecordId: sourceRecord.id,
    cveIdentifierId: identifier.id,
    knownExploited: true,
    vendorProject: asString(input.entry.vendorProject),
    product: asString(input.entry.product),
    vulnerabilityName: asString(input.entry.vulnerabilityName),
    shortDescription: asString(input.entry.shortDescription),
    dateAdded: toDateString(input.entry.dateAdded),
    dueDate: toDateString(input.entry.dueDate),
    requiredAction: asString(input.entry.requiredAction),
    knownRansomwareCampaignUse: asString(
      input.entry.knownRansomwareCampaignUse,
    ),
    notes: asString(input.entry.notes),
  });
}
