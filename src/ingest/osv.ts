import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { getDb } from "../db";
import {
  clearVulnerabilityRecordFacts,
  insertCvssMetricDetails,
  insertSeverityMetric,
  insertVersionRange,
  linkVulnerabilityIdentifier,
  linkVulnerabilityRecordIdentifier,
  linkVulnerabilityRecordReference,
  upsertAffectedPackage,
  upsertEcosystem,
  upsertEcosystemAlias,
  upsertExternalReference,
  upsertIdentifier,
  upsertPackage,
  upsertSource,
  upsertSourceRecord,
  upsertVulnerability,
  upsertVulnerabilityRecord,
  upsertVulnerabilityRecordRelationship,
  type IngestDb,
} from "./repository";
import { SOURCE_SEEDS, seedReferenceData } from "./seed";
import {
  asArray,
  asObject,
  asString,
  ecosystemFromOsv,
  firstEnglishValue,
  normalizePackageName,
  normalizeIdentifierValue,
  referenceKindFromTags,
  toTimestamp,
  type JsonObject,
} from "./standardize";

export type OsvIngestOptions = {
  dir: string;
  limit?: number;
  progressEvery?: number;
};

export type OsvIngestResult = {
  scanned: number;
  ingested: number;
  failed: Array<{ file: string; error: string }>;
};

export async function ingestOsvDirectoryFromEnv(options: OsvIngestOptions) {
  return ingestOsvDirectory(getDb(), options);
}

export async function ingestOsvDirectory(
  db: IngestDb,
  options: OsvIngestOptions,
): Promise<OsvIngestResult> {
  await seedReferenceData(db);

  const osvSourceSeed = SOURCE_SEEDS.find((source) => source.slug === "osv");
  if (!osvSourceSeed) {
    throw new Error("Missing osv source seed.");
  }

  const source = await upsertSource(db, osvSourceSeed);
  const files = await listJsonFiles(options.dir);
  const result: OsvIngestResult = { scanned: 0, ingested: 0, failed: [] };
  const limit = options.limit ?? Number.POSITIVE_INFINITY;
  const progressEvery = options.progressEvery ?? 1000;

  for (const file of files) {
    if (result.scanned >= limit) {
      break;
    }

    result.scanned += 1;

    try {
      const raw = JSON.parse(await readFile(file, "utf8")) as unknown;
      const record = asObject(raw);

      if (!record) {
        throw new Error("Expected a JSON object.");
      }

      await db.transaction(async (tx) => {
        await ingestOsvRecord(tx as IngestDb, {
          sourceId: source.id,
          raw: record,
        });
      });

      result.ingested += 1;
    } catch (error) {
      result.failed.push({
        file,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    if (result.scanned % progressEvery === 0) {
      console.log(
        `osv: scanned=${result.scanned} ingested=${result.ingested} failed=${result.failed.length}`,
      );
    }
  }

  return result;
}

async function ingestOsvRecord(
  db: IngestDb,
  input: {
    sourceId: string;
    raw: JsonObject;
  },
) {
  const id = asString(input.raw.id);
  if (!id) {
    throw new Error("OSV record is missing id.");
  }

  const identifierValues = [
    id,
    ...asArray(input.raw.aliases).map(asString).filter(isString),
  ];
  const primaryIdentifier = choosePrimaryIdentifier(identifierValues);
  const status = input.raw.withdrawn ? "withdrawn" : "active";
  const summary = asString(input.raw.summary) ?? firstEnglishValue(input.raw.details);

  const sourceRecord = await upsertSourceRecord(db, {
    sourceId: input.sourceId,
    externalId: id,
    schemaVersion: asString(input.raw.schema_version),
    sourcePublishedAt: toTimestamp(input.raw.published),
    sourceModifiedAt: toTimestamp(input.raw.modified),
    raw: input.raw,
  });

  const vulnerability = await upsertVulnerability(db, {
    primaryIdentifier,
    summary,
    status,
  });

  const vulnerabilityRecord = await upsertVulnerabilityRecord(db, {
    sourceRecordId: sourceRecord.id,
    vulnerabilityId: vulnerability.id,
    recordId: id,
    summary,
    details: asString(input.raw.details),
    publishedAt: toTimestamp(input.raw.published),
    modifiedAt: toTimestamp(input.raw.modified),
    withdrawnAt: toTimestamp(input.raw.withdrawn),
    status,
  });

  await clearVulnerabilityRecordFacts(db, vulnerabilityRecord.id);

  for (const identifierValue of identifierValues) {
    const identifier = await upsertIdentifier(db, identifierValue);
    const relationship =
      normalizeIdentifierValue(identifierValue) ===
      normalizeIdentifierValue(primaryIdentifier)
        ? "primary"
        : "alias";

    await linkVulnerabilityIdentifier(
      db,
      vulnerability.id,
      identifier.id,
      relationship,
    );
    await linkVulnerabilityRecordIdentifier(
      db,
      vulnerabilityRecord.id,
      identifier.id,
      relationship,
    );
  }

  await ingestOsvRelatedIdentifiers(db, {
    raw: input.raw,
    vulnerabilityRecordId: vulnerabilityRecord.id,
    sourceRecordId: sourceRecord.id,
  });

  await ingestOsvAffectedPackages(db, {
    raw: input.raw,
    sourceRecordId: sourceRecord.id,
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });

  await ingestOsvSeverity(db, {
    severities: input.raw.severity,
    sourceRecordId: sourceRecord.id,
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });

  await ingestOsvReferences(db, {
    raw: input.raw,
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });
}

async function ingestOsvAffectedPackages(
  db: IngestDb,
  input: {
    raw: JsonObject;
    sourceRecordId: string;
    vulnerabilityRecordId: string;
  },
) {
  for (const [sourceIndex, affectedValue] of asArray(
    input.raw.affected,
  ).entries()) {
    const affected = asObject(affectedValue);
    const packageObject = asObject(affected?.package);

    if (!affected || !packageObject) {
      continue;
    }

    const ecosystemValue = asString(packageObject.ecosystem) ?? "generic";
    const ecosystemInfo = ecosystemFromOsv(ecosystemValue);
    const ecosystem = await upsertEcosystem(db, {
      slug: ecosystemInfo.slug,
      name: ecosystemInfo.slug,
      kind: ecosystemInfo.slug === "ubuntu" ? "distro-package" : undefined,
    });

    await upsertEcosystemAlias(db, {
      ecosystemId: ecosystem.id,
      alias: ecosystemValue,
      aliasKind: "osv_ecosystem",
      scope: ecosystemInfo.scope,
      source: "osv",
    });

    const purl = asString(packageObject.purl);
    const packageName = normalizePackageName(
      asString(packageObject.name),
      purl,
    );

    if (!packageName) {
      continue;
    }

    const pkg = await upsertPackage(db, {
      ecosystemId: ecosystem.id,
      name: packageName,
      purl: purl ?? null,
    });
    const affectedPackage = await upsertAffectedPackage(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      packageId: pkg.id,
      sourceIndex,
      raw: affected,
    });

    await ingestOsvRanges(db, affected, affectedPackage.id);
    await ingestOsvAffectedSeverity(db, {
      affected,
      sourceRecordId: input.sourceRecordId,
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      affectedPackageId: affectedPackage.id,
    });
  }
}

async function ingestOsvRanges(
  db: IngestDb,
  affected: JsonObject,
  affectedPackageId: string,
) {
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
        await insertVersionRange(db, {
          affectedPackageId,
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
      await insertVersionRange(db, {
        affectedPackageId,
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

    await insertVersionRange(db, {
      affectedPackageId,
      rangeType: "osv-version",
      sourceIndex: versionIndex,
      status: "affected",
      version,
      expression: `affected: ${version}`,
      raw: { version },
    });
  }
}

async function ingestOsvSeverity(
  db: IngestDb,
  input: {
    severities: unknown;
    sourceRecordId: string;
    vulnerabilityRecordId: string;
  },
) {
  for (const severityValue of asArray(input.severities)) {
    const severity = asObject(severityValue);
    if (!severity) {
      continue;
    }

    const severityMetric = await insertSeverityMetric(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      sourceRecordId: input.sourceRecordId,
      provider: "OSV",
      system: asString(severity.type) ?? "osv",
      vector: asString(severity.score),
      raw: severity,
    });
    await maybeInsertOsvCvssDetails(db, severityMetric.id, severity);
  }
}

async function ingestOsvAffectedSeverity(
  db: IngestDb,
  input: {
    affected: JsonObject;
    sourceRecordId: string;
    vulnerabilityRecordId: string;
    affectedPackageId: string;
  },
) {
  for (const severityValue of asArray(input.affected.severity)) {
    const severity = asObject(severityValue);
    if (!severity) {
      continue;
    }

    const severityMetric = await insertSeverityMetric(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      sourceRecordId: input.sourceRecordId,
      provider: "OSV",
      system: asString(severity.type) ?? "osv",
      affectedPackageId: input.affectedPackageId,
      vector: asString(severity.score),
      raw: severity,
    });
    await maybeInsertOsvCvssDetails(db, severityMetric.id, severity);
  }
}

async function maybeInsertOsvCvssDetails(
  db: IngestDb,
  severityMetricId: string,
  severity: JsonObject,
) {
  const type = asString(severity.type);
  const vector = asString(severity.score);

  if (!type?.toUpperCase().startsWith("CVSS") || !vector) {
    return;
  }

  await insertCvssMetricDetails(db, {
    severityMetricId,
    cvssVersion: type.replace(/^CVSS[_-]?/i, "").replace("_", "."),
    ...parseCvssVector(vector),
    raw: severity,
  });
}

async function ingestOsvReferences(
  db: IngestDb,
  input: {
    raw: JsonObject;
    vulnerabilityRecordId: string;
  },
) {
  for (const referenceValue of asArray(input.raw.references)) {
    const reference = asObject(referenceValue);
    const url = asString(reference?.url);

    if (!reference || !url) {
      continue;
    }

    const externalReference = await upsertExternalReference(db, {
      url,
      kind: asString(reference.type) ?? referenceKindFromTags(reference.tags),
    });

    await linkVulnerabilityRecordReference(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      referenceId: externalReference.id,
      sourceName: "OSV",
      relationship: asString(reference.type) ?? "references",
      raw: reference,
    });
  }
}

async function ingestOsvRelatedIdentifiers(
  db: IngestDb,
  input: {
    raw: JsonObject;
    vulnerabilityRecordId: string;
    sourceRecordId: string;
  },
) {
  for (const relationship of ["upstream", "related"] as const) {
    for (const value of asArray(input.raw[relationship])) {
      const identifierValue = asString(value);
      if (!identifierValue) {
        continue;
      }

      const identifier = await upsertIdentifier(db, identifierValue);
      await upsertVulnerabilityRecordRelationship(db, {
        vulnerabilityRecordId: input.vulnerabilityRecordId,
        sourceRecordId: input.sourceRecordId,
        relatedIdentifierId: identifier.id,
        relationship,
        raw: { [relationship]: identifierValue },
      });
    }
  }
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
