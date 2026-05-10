import { readFile } from "node:fs/promises";
import {
  asArray,
  asObject,
  asString,
  normalizeIdentifierValue,
  toDateString,
  type JsonObject,
} from "../standardize";
import type {
  NormalizedIngestItem,
  SourceAdapter,
} from "../types";

export type KevIngestOptions = {
  file: string;
  progressEvery?: number;
};

export const kevAdapter: SourceAdapter<KevIngestOptions> = {
  sourceSlug: "cisa-kev",
  async *read(options) {
    let raw: unknown;

    try {
      raw = JSON.parse(await readFile(options.file, "utf8")) as unknown;
    } catch (error) {
      yield { label: options.file, error };
      return;
    }

    const catalog = asObject(raw);
    const entries = asArray(catalog?.vulnerabilities);

    for (const entryValue of entries) {
      const entry = asObject(entryValue);
      const cveId = asString(entry?.cveID) ?? asString(entry?.cveId) ?? "unknown";

      if (!entry) {
        yield { label: cveId, error: new Error("Expected vulnerability object.") };
        continue;
      }

      yield { label: cveId, raw: entry };
    }
  },
  normalize(raw): NormalizedIngestItem {
    const entry = asObject(raw);
    if (!entry) {
      throw new Error("Expected vulnerability object.");
    }

    return normalizeKevEntry(entry);
  },
};

function normalizeKevEntry(entry: JsonObject): NormalizedIngestItem {
  const cveId = asString(entry.cveID) ?? asString(entry.cveId);
  if (!cveId) {
    throw new Error("KEV entry is missing cveID.");
  }

  const normalizedCveId = normalizeIdentifierValue(cveId);

  return {
    kind: "vulnerability_signal",
    sourceRecord: {
      sourceSlug: "cisa-kev",
      externalId: normalizedCveId,
      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${normalizedCveId}`,
      raw: entry,
    },
    canonical: {
      primaryIdentifier: normalizedCveId,
      title: asString(entry.vulnerabilityName),
      summary: asString(entry.shortDescription),
      preserveExistingText: true,
    },
    identifiers: [{ value: normalizedCveId, relationship: "primary" }],
    signal: {
      kind: "kev",
      cveIdentifier: normalizedCveId,
      knownExploited: true,
      vendorProject: asString(entry.vendorProject),
      product: asString(entry.product),
      vulnerabilityName: asString(entry.vulnerabilityName),
      shortDescription: asString(entry.shortDescription),
      dateAdded: toDateString(entry.dateAdded),
      dueDate: toDateString(entry.dueDate),
      requiredAction: asString(entry.requiredAction),
      knownRansomwareCampaignUse: asString(entry.knownRansomwareCampaignUse),
      notes: asString(entry.notes),
    },
  };
}
