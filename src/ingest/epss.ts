import { readFile } from "node:fs/promises";
import { getDb } from "../db";
import {
  linkVulnerabilityIdentifier,
  upsertEpssScore,
  upsertIdentifier,
  upsertSource,
  upsertSourceRecord,
  upsertVulnerability,
  type IngestDb,
} from "./repository";
import { SOURCE_SEEDS, seedReferenceData } from "./seed";
import { normalizeIdentifierValue } from "./standardize";

export type EpssIngestOptions = {
  file: string;
  date?: string;
};

export type EpssIngestResult = {
  scanned: number;
  ingested: number;
  failed: Array<{ cveId: string; error: string }>;
};

export async function ingestEpssCsvFromEnv(options: EpssIngestOptions) {
  return ingestEpssCsv(getDb(), options);
}

export async function ingestEpssCsv(
  db: IngestDb,
  options: EpssIngestOptions,
): Promise<EpssIngestResult> {
  await seedReferenceData(db);

  const sourceSeed = SOURCE_SEEDS.find((source) => source.slug === "first-epss");
  if (!sourceSeed) {
    throw new Error("Missing first-epss source seed.");
  }

  const source = await upsertSource(db, sourceSeed);
  const text = await readFile(options.file, "utf8");
  const result: EpssIngestResult = { scanned: 0, ingested: 0, failed: [] };

  for (const row of parseEpssCsv(text, options.date)) {
    result.scanned += 1;

    try {
      const cveId = normalizeIdentifierValue(row.cve);
      const identifier = await upsertIdentifier(db, cveId);
      const vulnerability = await upsertVulnerability(db, {
        primaryIdentifier: cveId,
      });
      await linkVulnerabilityIdentifier(
        db,
        vulnerability.id,
        identifier.id,
        "primary",
      );
      const sourceRecord = await upsertSourceRecord(db, {
        sourceId: source.id,
        externalId: `${row.date}:${cveId}`,
        schemaVersion: "epss-csv",
        raw: row,
      });

      await upsertEpssScore(db, {
        vulnerabilityId: vulnerability.id,
        sourceRecordId: sourceRecord.id,
        cveIdentifierId: identifier.id,
        score: row.epss,
        percentile: row.percentile,
        scoreDate: row.date,
      });

      result.ingested += 1;
    } catch (error) {
      result.failed.push({
        cveId: row.cve,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return result;
}

type EpssRow = {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
};

function parseEpssCsv(text: string, fallbackDate?: string): EpssRow[] {
  const rows: EpssRow[] = [];
  let date = fallbackDate;
  let header: string[] | null = null;

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();

    if (!trimmed) {
      continue;
    }

    if (trimmed.startsWith("#")) {
      const dateMatch = trimmed.match(/\b\d{4}-\d{2}-\d{2}\b/);
      date ??= dateMatch?.[0];
      continue;
    }

    const columns = splitCsvLine(trimmed);

    if (!header) {
      header = columns.map((column) => column.trim().toLowerCase());
      continue;
    }

    const row = Object.fromEntries(
      header.map((column, index) => [column, columns[index] ?? ""]),
    );
    const cve = row.cve;
    const epss = row.epss;
    const percentile = row.percentile;
    const scoreDate = row.date || date;

    if (cve && epss && percentile && scoreDate) {
      rows.push({ cve, epss, percentile, date: scoreDate });
    }
  }

  return rows;
}

function splitCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let quoted = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (char === '"' && next === '"') {
      current += '"';
      index += 1;
      continue;
    }

    if (char === '"') {
      quoted = !quoted;
      continue;
    }

    if (char === "," && !quoted) {
      values.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current);
  return values;
}
