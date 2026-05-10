import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  asArray,
  asObject,
  asString,
  ecosystemFromOsv,
  normalizeIdentifierValue,
  normalizePackageName,
  referenceKindFromTags,
  toTimestamp,
  type JsonObject,
} from "../standardize";
import type {
  NormalizedAdvisoryRecord,
  NormalizedAffectedPackage,
  NormalizedIngestItem,
  NormalizedReference,
  NormalizedSeverityMetric,
  NormalizedVersionRange,
  SourceAdapter,
} from "../types";

export type OsvIngestOptions = {
  dir: string;
  limit?: number;
  progressEvery?: number;
};

export const osvAdapter: SourceAdapter<OsvIngestOptions> = {
  sourceSlug: "osv",
  async *read(options) {
    const files = await listJsonFiles(options.dir);
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    let scanned = 0;

    for (const file of files) {
      if (scanned >= limit) {
        break;
      }

      scanned += 1;

      try {
        const rawText = await readFile(file, "utf8");
        const raw = JSON.parse(rawText) as unknown;
        yield { label: file, raw };
      } catch (error) {
        yield { label: file, error };
      }
    }
  },
  normalize(raw): NormalizedIngestItem {
    const record = asObject(raw);
    if (!record) {
      throw new Error("Expected a JSON object.");
    }

    return normalizeOsvRecord(record);
  },
};

function normalizeOsvRecord(raw: JsonObject): NormalizedAdvisoryRecord {
  const id = asString(raw.id);
  if (!id) {
    throw new Error("OSV record is missing id.");
  }

  const identifierValues = [
    id,
    ...asArray(raw.aliases).map(asString).filter(isString),
  ];
  const primaryIdentifier = choosePrimaryIdentifier(identifierValues);
  const status = raw.withdrawn ? "withdrawn" : "active";
  const summary = asString(raw.summary) ?? asString(raw.details);

  return {
    kind: "advisory_record",
    sourceRecord: {
      sourceSlug: "osv",
      externalId: id,
      url: `https://osv.dev/vulnerability/${id}`,
      schemaVersion: asString(raw.schema_version),
      sourcePublishedAt: toTimestamp(raw.published),
      sourceModifiedAt: toTimestamp(raw.modified),
      raw,
    },
    canonical: {
      primaryIdentifier,
      summary,
      status,
    },
    record: {
      recordId: id,
      summary,
      details: asString(raw.details),
      publishedAt: toTimestamp(raw.published),
      modifiedAt: toTimestamp(raw.modified),
      withdrawnAt: toTimestamp(raw.withdrawn),
      status,
    },
    identifiers: identifierValues.map((identifierValue) => ({
      value: identifierValue,
      relationship:
        normalizeIdentifierValue(identifierValue) ===
        normalizeIdentifierValue(primaryIdentifier)
          ? "primary"
          : "alias",
    })),
    relationships: normalizeOsvRelatedIdentifiers(raw),
    affectedPackages: normalizeOsvAffectedPackages(raw),
    severityMetrics: normalizeOsvSeverity(raw),
    references: normalizeOsvReferences(raw),
  };
}

function normalizeOsvAffectedPackages(
  raw: JsonObject,
): NormalizedAffectedPackage[] {
  const affectedPackages: NormalizedAffectedPackage[] = [];

  for (const [sourceIndex, affectedValue] of asArray(raw.affected).entries()) {
    const affected = asObject(affectedValue);
    const packageObject = asObject(affected?.package);

    if (!affected || !packageObject) {
      continue;
    }

    const ecosystemValue = asString(packageObject.ecosystem) ?? "generic";
    const ecosystemInfo = ecosystemFromOsv(ecosystemValue);
    const purl = asString(packageObject.purl);
    const packageName = normalizePackageName(asString(packageObject.name), purl);

    if (!packageName) {
      continue;
    }

    affectedPackages.push({
      sourceIndex,
      ecosystem: {
        slug: ecosystemInfo.slug,
        name: ecosystemInfo.slug,
        kind: ecosystemInfo.slug === "ubuntu" ? "distro-package" : undefined,
        aliases: [
          {
            alias: ecosystemValue,
            aliasKind: "osv_ecosystem",
            scope: ecosystemInfo.scope,
            source: "osv",
          },
        ],
      },
      package: {
        name: packageName,
        purl: purl ?? null,
      },
      relationship: "affected",
      raw: affected,
      versionRanges: normalizeOsvRanges(affected),
    });
  }

  return affectedPackages;
}

function normalizeOsvRanges(affected: JsonObject): NormalizedVersionRange[] {
  const versionRanges: NormalizedVersionRange[] = [];

  for (const [rangeIndex, rangeValue] of asArray(affected.ranges).entries()) {
    const range = asObject(rangeValue);
    if (!range) {
      continue;
    }

    let introduced: string | null = null;
    let insertedRange = false;
    let eventIndex = 0;

    for (const eventValue of asArray(range.events)) {
      const event = asObject(eventValue);
      if (!event) {
        continue;
      }

      if (asString(event.introduced)) {
        introduced = asString(event.introduced) ?? null;
        eventIndex += 1;
        continue;
      }

      const fixed = asString(event.fixed) ?? null;
      const lastAffected = asString(event.last_affected) ?? null;
      const limit = asString(event.limit) ?? null;

      if (fixed || lastAffected || limit) {
        versionRanges.push({
          rangeType: asString(range.type) ?? "osv",
          sourceIndex: rangeIndex * 100000 + eventIndex,
          status: "affected",
          introduced,
          fixed,
          lastAffected,
          limit,
          expression: renderOsvExpression(introduced, fixed, lastAffected, limit),
          repo: asString(range.repo),
          raw: range,
        });
        insertedRange = true;
      }

      eventIndex += 1;
    }

    if (introduced && !insertedRange) {
      versionRanges.push({
        rangeType: asString(range.type) ?? "osv",
        sourceIndex: rangeIndex * 100000 + eventIndex,
        status: "affected",
        introduced,
        expression: renderOsvExpression(introduced, null, null, null),
        repo: asString(range.repo),
        raw: range,
      });
    }
  }

  for (const [versionIndex, versionValue] of asArray(
    affected.versions,
  ).entries()) {
    const version = asString(versionValue);
    if (!version) {
      continue;
    }

    versionRanges.push({
      rangeType: "osv-version",
      sourceIndex: versionIndex,
      status: "affected",
      version,
      expression: `affected: ${version}`,
      raw: { version },
    });
  }

  return versionRanges;
}

function normalizeOsvSeverity(raw: JsonObject): NormalizedSeverityMetric[] {
  const severityMetrics: NormalizedSeverityMetric[] = [];

  for (const severityValue of asArray(raw.severity)) {
    const severity = asObject(severityValue);
    if (!severity) {
      continue;
    }

    severityMetrics.push(osvSeverityMetric(severity));
  }

  for (const [sourceIndex, affectedValue] of asArray(raw.affected).entries()) {
    const affected = asObject(affectedValue);
    if (!affected) {
      continue;
    }

    for (const severityValue of asArray(affected.severity)) {
      const severity = asObject(severityValue);
      if (!severity) {
        continue;
      }

      severityMetrics.push({
        ...osvSeverityMetric(severity),
        affectedPackageSourceIndex: sourceIndex,
      });
    }
  }

  return severityMetrics;
}

function osvSeverityMetric(severity: JsonObject): NormalizedSeverityMetric {
  return {
    provider: "OSV",
    system: asString(severity.type) ?? "osv",
    vector: asString(severity.score),
    raw: severity,
    cvss: maybeOsvCvssDetails(severity),
  };
}

function maybeOsvCvssDetails(severity: JsonObject) {
  const type = asString(severity.type);
  const vector = asString(severity.score);

  if (!type?.toUpperCase().startsWith("CVSS") || !vector) {
    return null;
  }

  return {
    cvssVersion: cvssVersionFromOsv(type, vector),
    ...parseCvssVector(vector),
    raw: severity,
  };
}

function normalizeOsvReferences(raw: JsonObject): NormalizedReference[] {
  const references: NormalizedReference[] = [];

  for (const referenceValue of asArray(raw.references)) {
    const reference = asObject(referenceValue);
    if (!reference) {
      continue;
    }

    const url = asString(reference.url);
    if (!url) {
      continue;
    }

    references.push({
      url,
      kind: asString(reference.type) ?? referenceKindFromTags(reference.tags),
      sourceName: "OSV",
      relationship: asString(reference.type) ?? "references",
      raw: reference,
    });
  }

  return references;
}

function normalizeOsvRelatedIdentifiers(raw: JsonObject) {
  const relationships = [];

  for (const relationship of ["upstream", "related"] as const) {
    for (const value of asArray(raw[relationship])) {
      const identifier = asString(value);
      if (!identifier) {
        continue;
      }

      relationships.push({
        identifier,
        relationship,
        raw: { [relationship]: identifier },
      });
    }
  }

  return relationships;
}

function choosePrimaryIdentifier(values: string[]) {
  const normalized = values.map(normalizeIdentifierValue);
  return (
    normalized.find((value) => value.startsWith("CVE-")) ??
    normalized.find((value) => value.startsWith("GHSA-")) ??
    normalized[0] ??
    "UNKNOWN"
  );
}

function renderOsvExpression(
  introduced: string | null,
  fixed: string | null,
  lastAffected: string | null,
  limit: string | null,
) {
  const parts = [];

  if (introduced) {
    parts.push(`>= ${introduced}`);
  }

  if (fixed) {
    parts.push(`< ${fixed}`);
  }

  if (lastAffected) {
    parts.push(`<= ${lastAffected}`);
  }

  if (limit) {
    parts.push(`< ${limit}`);
  }

  return parts.length > 0 ? parts.join(" ") : null;
}

function cvssVersionFromOsv(type: string, vector: string) {
  const vectorVersion = vector.match(/^CVSS:(\d+(?:\.\d+)?)/)?.[1];
  if (vectorVersion) {
    return vectorVersion;
  }

  return type
    .replace(/^CVSS[_-]?/i, "")
    .replace(/^V/i, "")
    .replace("_", ".");
}

function parseCvssVector(vector: string) {
  const metrics = Object.fromEntries(
    vector
      .split("/")
      .slice(1)
      .map((part) => part.split(":"))
      .filter((part): part is [string, string] => part.length === 2),
  );

  return {
    attackVector: decodeCvssValue("AV", metrics.AV),
    attackComplexity: decodeCvssValue("AC", metrics.AC),
    privilegesRequired: decodeCvssValue("PR", metrics.PR),
    userInteraction: decodeCvssValue("UI", metrics.UI),
    scope: decodeCvssValue("S", metrics.S),
    confidentialityImpact: decodeCvssValue("I", metrics.C ?? metrics.VC),
    integrityImpact: decodeCvssValue("I", metrics.I ?? metrics.VI),
    availabilityImpact: decodeCvssValue("I", metrics.A ?? metrics.VA),
  };
}

function decodeCvssValue(metric: string, value: string | undefined) {
  if (!value) {
    return null;
  }

  const maps: Record<string, Record<string, string>> = {
    AV: {
      N: "NETWORK",
      A: "ADJACENT_NETWORK",
      L: "LOCAL",
      P: "PHYSICAL",
    },
    AC: {
      L: "LOW",
      H: "HIGH",
    },
    PR: {
      N: "NONE",
      L: "LOW",
      H: "HIGH",
    },
    UI: {
      N: "NONE",
      R: "REQUIRED",
      P: "PASSIVE",
      A: "ACTIVE",
    },
    S: {
      U: "UNCHANGED",
      C: "CHANGED",
    },
    I: {
      H: "HIGH",
      L: "LOW",
      N: "NONE",
    },
  };

  return maps[metric]?.[value] ?? value;
}

function isString(value: string | undefined): value is string {
  return Boolean(value);
}

async function listJsonFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await listJsonFiles(fullPath)));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".json")) {
      files.push(fullPath);
    }
  }

  return files.sort();
}
