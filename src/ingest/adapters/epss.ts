import { readFile } from "node:fs/promises";
import { normalizeIdentifierValue } from "../standardize";
import type { NormalizedIngestItem, SourceAdapter } from "../types";

export type EpssIngestOptions = {
  file: string;
  date?: string;
  progressEvery?: number;
};

type EpssRow = {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
};

export const epssAdapter: SourceAdapter<EpssIngestOptions> = {
  sourceSlug: "first-epss",
  async *read(options) {
    let text: string;

    try {
      text = await readFile(options.file, "utf8");
    } catch (error) {
      yield { label: options.file, error };
      return;
    }

    for (const row of parseEpssCsv(text, options.date)) {
      yield { label: row.cve, raw: row };
    }
  },
  normalize(raw): NormalizedIngestItem {
    if (!isEpssRow(raw)) {
      throw new Error("Expected EPSS CSV row.");
    }

    const cveId = normalizeIdentifierValue(raw.cve);

    return {
      kind: "vulnerability_signal",
      sourceRecord: {
        sourceSlug: "first-epss",
        externalId: `${raw.date}:${cveId}`,
        schemaVersion: "epss-csv",
        raw,
      },
      canonical: {
        primaryIdentifier: cveId,
      },
      identifiers: [{ value: cveId, relationship: "primary" }],
      signal: {
        kind: "epss",
        cveIdentifier: cveId,
        score: raw.epss,
        percentile: raw.percentile,
        scoreDate: raw.date,
      },
    };
  },
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

    if (char === "\"" && next === "\"") {
      current += "\"";
      index += 1;
      continue;
    }

    if (char === "\"") {
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

function isEpssRow(value: unknown): value is EpssRow {
  if (!value || typeof value !== "object") {
    return false;
  }

  return (
    "cve" in value &&
    "epss" in value &&
    "percentile" in value &&
    "date" in value
  );
}
