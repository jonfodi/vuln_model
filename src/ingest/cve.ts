import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { getDb } from "../db";
import {
  clearVulnerabilityRecordFacts,
  clearSourceRecordSignals,
  insertAffectedSoftwareIdentifier,
  insertCvssMetricDetails,
  insertSeverityMetric,
  insertSsvcAssessment,
  insertVersionRange,
  linkPackageProduct,
  linkVulnerabilityIdentifier,
  linkVulnerabilityRecordIdentifier,
  linkVulnerabilityRecordReference,
  linkVulnerabilityRecordWeakness,
  upsertAffectedPackage,
  upsertAffectedProduct,
  upsertEcosystem,
  upsertEcosystemAlias,
  upsertExternalReference,
  upsertIdentifier,
  upsertKevEntry,
  upsertPackage,
  upsertProduct,
  upsertSource,
  upsertSourceRecord,
  upsertVulnerability,
  upsertVulnerabilityRecord,
  upsertVulnerabilityRecordRelationship,
  upsertWeakness,
  type IngestDb,
} from "./repository";
import { SOURCE_SEEDS, seedReferenceData } from "./seed";
import {
  asArray,
  asNumber,
  asObject,
  asString,
  cvssSystemFromKey,
  ecosystemFromCollectionUrl,
  ecosystemFromPurl,
  firstEnglishValue,
  normalizeIdentifierValue,
  normalizePackageName,
  referenceKindFromTags,
  slugify,
  toDateString,
  toTimestamp,
  versionRangeExpression,
  type JsonObject,
} from "./standardize";

const CVSS_KEYS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"];

export type CveIngestOptions = {
  dir: string;
  limit?: number;
  progressEvery?: number;
};

export type CveIngestResult = {
  scanned: number;
  ingested: number;
  failed: Array<{ file: string; error: string }>;
};

export async function ingestCveDirectoryFromEnv(options: CveIngestOptions) {
  return ingestCveDirectory(getDb(), options);
}

export async function ingestCveDirectory(
  db: IngestDb,
  options: CveIngestOptions,
): Promise<CveIngestResult> {
  await seedReferenceData(db);

  const cveSourceSeed = SOURCE_SEEDS.find(
    (source) => source.slug === "cve-list-v5",
  );

  if (!cveSourceSeed) {
    throw new Error("Missing cve-list-v5 source seed.");
  }

  const source = await upsertSource(db, cveSourceSeed);
  const files = await listJsonFiles(options.dir);
  const result: CveIngestResult = { scanned: 0, ingested: 0, failed: [] };
  const limit = options.limit ?? Number.POSITIVE_INFINITY;
  const progressEvery = options.progressEvery ?? 1000;

  for (const file of files) {
    if (result.scanned >= limit) {
      break;
    }

    result.scanned += 1;

    try {
      const rawText = await readFile(file, "utf8");
      const raw = JSON.parse(rawText) as unknown;
      const record = asObject(raw);

      if (!record) {
        throw new Error("Expected a JSON object.");
      }

      await db.transaction(async (tx) => {
        await ingestCveRecord(tx as IngestDb, {
          sourceId: source.id,
          raw: record,
          file,
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
        `cve-list-v5: scanned=${result.scanned} ingested=${result.ingested} failed=${result.failed.length}`,
      );
    }
  }

  return result;
}

async function ingestCveRecord(
  db: IngestDb,
  input: {
    sourceId: string;
    raw: JsonObject;
    file: string;
  },
) {
  const cveMetadata = asObject(input.raw.cveMetadata);
  const containers = asObject(input.raw.containers);
  const cna = asObject(containers?.cna);
  const cveId = asString(cveMetadata?.cveId);

  if (!cveId || !cna) {
    throw new Error("CVE record is missing cveMetadata.cveId or containers.cna.");
  }

  const normalizedCveId = normalizeIdentifierValue(cveId);
  const state = asString(cveMetadata?.state)?.toLowerCase() ?? "unknown";
  const status = state === "rejected" ? "rejected" : "active";
  const title = asString(cna.title);
  const summary =
    title ??
    firstEnglishValue(cna.descriptions) ??
    firstEnglishValue(cna.rejectedReasons);
  const details =
    firstEnglishValue(cna.descriptions) ??
    firstEnglishValue(cna.rejectedReasons);

  const sourceRecord = await upsertSourceRecord(db, {
    sourceId: input.sourceId,
    externalId: normalizedCveId,
    url: `https://www.cve.org/CVERecord?id=${normalizedCveId}`,
    schemaVersion: asString(input.raw.dataVersion),
    sourcePublishedAt: toTimestamp(cveMetadata?.datePublished),
    sourceModifiedAt: toTimestamp(cveMetadata?.dateUpdated),
    raw: input.raw,
  });

  const vulnerability = await upsertVulnerability(db, {
    primaryIdentifier: normalizedCveId,
    title,
    summary,
    status,
  });

  const vulnerabilityRecord = await upsertVulnerabilityRecord(db, {
    sourceRecordId: sourceRecord.id,
    vulnerabilityId: vulnerability.id,
    recordId: normalizedCveId,
    summary,
    details,
    publishedAt: toTimestamp(cveMetadata?.datePublished),
    modifiedAt: toTimestamp(cveMetadata?.dateUpdated),
    withdrawnAt: toTimestamp(cveMetadata?.dateRejected),
    status,
  });

  await clearVulnerabilityRecordFacts(db, vulnerabilityRecord.id);
  await clearSourceRecordSignals(db, sourceRecord.id);

  const cveIdentifier = await upsertIdentifier(db, normalizedCveId);
  await linkVulnerabilityIdentifier(
    db,
    vulnerability.id,
    cveIdentifier.id,
    "primary",
  );
  await linkVulnerabilityRecordIdentifier(
    db,
    vulnerabilityRecord.id,
    cveIdentifier.id,
    "primary",
  );

  await ingestCveReplacements(db, {
    cna,
    sourceRecordId: sourceRecord.id,
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });

  await ingestCveAffected(db, {
    cna,
    sourceRecordId: sourceRecord.id,
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });

  await ingestCveWeaknesses(db, {
    cna,
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });

  await ingestCveMetrics(db, {
    container: cna,
    sourceRecordId: sourceRecord.id,
    vulnerabilityRecordId: vulnerabilityRecord.id,
    provider: providerShortName(cna),
    vulnerabilityId: vulnerability.id,
    cveIdentifierId: cveIdentifier.id,
  });

  for (const adpContainer of asArray(containers?.adp)) {
    const adp = asObject(adpContainer);
    if (!adp) {
      continue;
    }

    await ingestCveMetrics(db, {
      container: adp,
      sourceRecordId: sourceRecord.id,
      vulnerabilityRecordId: vulnerabilityRecord.id,
      provider: providerShortName(adp),
      vulnerabilityId: vulnerability.id,
      cveIdentifierId: cveIdentifier.id,
    });
  }

  await ingestCveReferences(db, {
    container: cna,
    sourceName: providerShortName(cna),
    vulnerabilityRecordId: vulnerabilityRecord.id,
  });

  for (const adpContainer of asArray(containers?.adp)) {
    const adp = asObject(adpContainer);
    if (!adp) {
      continue;
    }

    await ingestCveReferences(db, {
      container: adp,
      sourceName: providerShortName(adp),
      vulnerabilityRecordId: vulnerabilityRecord.id,
    });
  }
}

async function ingestCveAffected(
  db: IngestDb,
  input: {
    cna: JsonObject;
    sourceRecordId: string;
    vulnerabilityRecordId: string;
  },
) {
  const affectedRows = asArray(input.cna.affected);

  for (const [sourceIndex, affectedValue] of affectedRows.entries()) {
    const affected = asObject(affectedValue);
    if (!affected) {
      continue;
    }

    const productName = asString(affected.product);
    const vendorName = asString(affected.vendor);
    const packageInfo = await resolveCvePackage(db, affected);
    const defaultStatus = asString(affected.defaultStatus);
    let affectedProductId: string | null = null;
    let affectedPackageId: string | null = null;

    if (productName && productName.toLowerCase() !== "n/a") {
      const product = await upsertProduct(db, {
        name: productName,
        vendor: vendorName,
      });
      const affectedProduct = await upsertAffectedProduct(db, {
        vulnerabilityRecordId: input.vulnerabilityRecordId,
        productId: product.id,
        sourceIndex,
        relationship: "affected",
        defaultStatus,
        platforms: affected.platforms,
        modules: affected.modules,
        programFiles: affected.programFiles,
        programRoutines: affected.programRoutines,
        repo: asString(affected.repo),
        raw: affected,
      });
      affectedProductId = affectedProduct.id;

      await insertAffectedProductIdentifiers(db, affected, affectedProductId);
    }

    if (packageInfo) {
      const affectedPackage = await upsertAffectedPackage(db, {
        vulnerabilityRecordId: input.vulnerabilityRecordId,
        packageId: packageInfo.packageId,
        sourceIndex,
        relationship: "affected",
        defaultStatus,
        platforms: affected.platforms,
        modules: affected.modules,
        repo: asString(affected.repo),
        raw: affected,
      });
      affectedPackageId = affectedPackage.id;

      await insertAffectedPackageIdentifiers(db, affected, affectedPackageId);

      if (affectedProductId) {
        const product = await upsertProduct(db, {
          name: productName ?? packageInfo.packageName,
          vendor: vendorName,
        });
        await linkPackageProduct(db, packageInfo.packageId, product.id, {
          source: "cve-list-v5",
          confidence: productName ? "medium" : "low",
        });
      }
    }

    await insertCveVersionRanges(db, affected, {
      affectedProductId,
      affectedPackageId,
    });
  }
}

async function resolveCvePackage(db: IngestDb, affected: JsonObject) {
  const packageUrl = asString(affected.packageURL);
  const collectionUrl = asString(affected.collectionURL);
  const packageName = normalizePackageName(
    asString(affected.packageName),
    packageUrl,
  );

  if (!packageName) {
    return null;
  }

  const ecosystemSlug =
    (packageUrl ? ecosystemFromPurl(packageUrl) : undefined) ??
    (collectionUrl ? ecosystemFromCollectionUrl(collectionUrl) : undefined) ??
    "generic";

  const ecosystem = await upsertEcosystem(db, {
    slug: ecosystemSlug,
    name: ecosystemSlug,
    kind: ecosystemSlug.startsWith("collection-")
      ? "package-collection"
      : undefined,
  });

  if (packageUrl) {
    await upsertEcosystemAlias(db, {
      ecosystemId: ecosystem.id,
      alias: packageUrl.split("/")[0]?.replace("pkg:", "") ?? ecosystemSlug,
      aliasKind: "purl_type",
      source: "cve-list-v5",
      raw: { packageURL: packageUrl },
    });
  }

  if (collectionUrl) {
    await upsertEcosystemAlias(db, {
      ecosystemId: ecosystem.id,
      alias: collectionUrl,
      aliasKind: "collection_url",
      source: "cve-list-v5",
      raw: { collectionURL: collectionUrl },
    });
  }

  const pkg = await upsertPackage(db, {
    ecosystemId: ecosystem.id,
    name: packageName,
    purl: packageUrl ?? null,
  });

  return {
    packageId: pkg.id,
    packageName,
  };
}

async function insertAffectedProductIdentifiers(
  db: IngestDb,
  affected: JsonObject,
  affectedProductId: string,
) {
  for (const cpe of asArray(affected.cpes)) {
    const value = asString(cpe);
    if (!value) {
      continue;
    }

    await insertAffectedSoftwareIdentifier(db, {
      affectedProductId,
      kind: "cpe",
      value,
      sourceField: "cpes",
    });
  }
}

async function insertAffectedPackageIdentifiers(
  db: IngestDb,
  affected: JsonObject,
  affectedPackageId: string,
) {
  const packageName = asString(affected.packageName);
  const packageUrl = asString(affected.packageURL);
  const collectionUrl = asString(affected.collectionURL);

  if (packageName) {
    await insertAffectedSoftwareIdentifier(db, {
      affectedPackageId,
      kind: "package_name",
      value: packageName,
      sourceField: "packageName",
    });
  }

  if (packageUrl) {
    await insertAffectedSoftwareIdentifier(db, {
      affectedPackageId,
      kind: "purl",
      value: packageUrl,
      sourceField: "packageURL",
    });
  }

  if (collectionUrl) {
    await insertAffectedSoftwareIdentifier(db, {
      affectedPackageId,
      kind: "collection_url",
      value: collectionUrl,
      sourceField: "collectionURL",
    });
  }
}

async function insertCveVersionRanges(
  db: IngestDb,
  affected: JsonObject,
  target: {
    affectedProductId?: string | null;
    affectedPackageId?: string | null;
  },
) {
  for (const [sourceIndex, versionValue] of asArray(
    affected.versions,
  ).entries()) {
    const version = asObject(versionValue);
    if (!version) {
      continue;
    }

    const status = asString(version.status);
    const lessThan = asString(version.lessThan);
    const lessThanOrEqual = asString(version.lessThanOrEqual);
    const startVersion = asString(version.version);

    const baseValues = {
      sourceIndex,
      rangeType: "cve-version",
      status,
      version: startVersion,
      versionType: asString(version.versionType),
      introduced: startVersion,
      fixed:
        status === "affected" && lessThan && lessThan !== "*"
          ? lessThan
          : null,
      lastAffected:
        status === "affected" && lessThanOrEqual ? lessThanOrEqual : null,
      lessThan,
      lessThanOrEqual,
      expression: versionRangeExpression(version),
      repo: asString(affected.repo),
      changes: version.changes ?? null,
      raw: version,
    };

    if (target.affectedProductId) {
      await insertVersionRange(db, {
        affectedProductId: target.affectedProductId,
        ...baseValues,
      });
    }

    if (target.affectedPackageId) {
      await insertVersionRange(db, {
        affectedPackageId: target.affectedPackageId,
        ...baseValues,
      });
    }
  }
}

async function ingestCveWeaknesses(
  db: IngestDb,
  input: {
    cna: JsonObject;
    vulnerabilityRecordId: string;
  },
) {
  for (const problemType of asArray(input.cna.problemTypes)) {
    const problem = asObject(problemType);
    if (!problem) {
      continue;
    }

    for (const descriptionValue of asArray(problem.descriptions)) {
      const description = asObject(descriptionValue);
      const cweId = asString(description?.cweId)?.toUpperCase();

      if (!cweId?.startsWith("CWE-")) {
        continue;
      }

      const value = asString(description?.description);
      const weakness = await upsertWeakness(db, {
        cweId,
        name: value?.replace(new RegExp(`^${cweId}:?\\s*`, "i"), nullish()),
        description: value ?? null,
      });

      await linkVulnerabilityRecordWeakness(
        db,
        input.vulnerabilityRecordId,
        weakness.id,
      );
    }
  }
}

async function ingestCveMetrics(
  db: IngestDb,
  input: {
    container: JsonObject;
    sourceRecordId: string;
    vulnerabilityRecordId: string;
    provider: string | null;
    vulnerabilityId: string;
    cveIdentifierId: string;
  },
) {
  for (const metricValue of asArray(input.container.metrics)) {
    const metric = asObject(metricValue);
    if (!metric) {
      continue;
    }

    for (const cvssKey of CVSS_KEYS) {
      const cvss = asObject(metric[cvssKey]);
      if (!cvss) {
        continue;
      }

      const severityMetric = await insertSeverityMetric(db, {
        vulnerabilityRecordId: input.vulnerabilityRecordId,
        sourceRecordId: input.sourceRecordId,
        provider: input.provider,
        system: cvssSystemFromKey(cvssKey),
        score: scoreString(cvss.baseScore),
        severity: asString(cvss.baseSeverity),
        vector: asString(cvss.vectorString),
        raw: metric,
      });

      await insertCvssMetricDetails(db, {
        severityMetricId: severityMetric.id,
        cvssVersion: asString(cvss.version) ?? cvssKey,
        attackVector: asString(cvss.attackVector),
        attackComplexity: asString(cvss.attackComplexity),
        privilegesRequired: asString(cvss.privilegesRequired),
        userInteraction: asString(cvss.userInteraction),
        scope: asString(cvss.scope),
        confidentialityImpact:
          asString(cvss.confidentialityImpact) ??
          asString(cvss.vulnerableSystemConfidentiality),
        integrityImpact:
          asString(cvss.integrityImpact) ??
          asString(cvss.vulnerableSystemIntegrity),
        availabilityImpact:
          asString(cvss.availabilityImpact) ??
          asString(cvss.vulnerableSystemAvailability),
        raw: cvss,
      });
    }

    const other = asObject(metric.other);
    if (!other) {
      continue;
    }

    const otherType = asString(other.type);
    const content = asObject(other.content);

    if (otherType?.toLowerCase().startsWith("ssvc") && content) {
      await insertSsvcAssessment(db, {
        vulnerabilityRecordId: input.vulnerabilityRecordId,
        sourceRecordId: input.sourceRecordId,
        provider: input.provider,
        ...parseSsvcContent(content),
      });
      continue;
    }

    if (otherType?.toLowerCase() === "kev" && content) {
      await upsertKevEntry(db, {
        vulnerabilityId: input.vulnerabilityId,
        sourceRecordId: input.sourceRecordId,
        cveIdentifierId: input.cveIdentifierId,
        knownExploited: true,
        dateAdded: toDateString(content.dateAdded),
        notes: asString(content.reference),
      });
      continue;
    }

    await insertSeverityMetric(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      sourceRecordId: input.sourceRecordId,
      provider: input.provider,
      system: otherType ? slugify(otherType) : "other",
      severity: asString(content?.value) ?? asString(otherType),
      raw: metric,
    });
  }
}

async function ingestCveReferences(
  db: IngestDb,
  input: {
    container: JsonObject;
    sourceName: string | null;
    vulnerabilityRecordId: string;
  },
) {
  for (const referenceValue of asArray(input.container.references)) {
    const reference = asObject(referenceValue);
    const url = asString(reference?.url);

    if (!reference || !url) {
      continue;
    }

    const externalReference = await upsertExternalReference(db, {
      url,
      title: asString(reference.name),
      kind: referenceKindFromTags(reference.tags),
    });

    await linkVulnerabilityRecordReference(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      referenceId: externalReference.id,
      sourceName: input.sourceName,
      tags: reference.tags ?? null,
      raw: reference,
    });
  }
}

async function ingestCveReplacements(
  db: IngestDb,
  input: {
    cna: JsonObject;
    sourceRecordId: string;
    vulnerabilityRecordId: string;
  },
) {
  for (const value of asArray(input.cna.replacedBy)) {
    const identifierValue = asString(value);
    if (!identifierValue) {
      continue;
    }

    const identifier = await upsertIdentifier(db, identifierValue);
    await upsertVulnerabilityRecordRelationship(db, {
      vulnerabilityRecordId: input.vulnerabilityRecordId,
      sourceRecordId: input.sourceRecordId,
      relatedIdentifierId: identifier.id,
      relationship: "replaced_by",
      raw: { replacedBy: identifierValue },
    });
  }
}

function parseSsvcContent(content: JsonObject) {
  const options = asArray(content.options)
    .map(asObject)
    .filter((entry): entry is JsonObject => Boolean(entry));

  return {
    exploitation: ssvcOption(options, "Exploitation"),
    automatable: ssvcOption(options, "Automatable"),
    technicalImpact: ssvcOption(options, "Technical Impact"),
    role: asString(content.role),
    version: asString(content.version),
    assessedAt: toTimestamp(content.timestamp),
  };
}

function ssvcOption(options: JsonObject[], key: string): string | null {
  for (const option of options) {
    const value = asString(option[key]);
    if (value) {
      return value;
    }
  }

  return null;
}

function providerShortName(container: JsonObject) {
  return asString(asObject(container.providerMetadata)?.shortName) ?? null;
}

function scoreString(value: unknown): string | null {
  const number = asNumber(value);
  return typeof number === "number" ? number.toFixed(1) : null;
}

function nullish() {
  return "";
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

    if (
      entry.isFile() &&
      entry.name.endsWith(".json") &&
      entry.name.startsWith("CVE-")
    ) {
      files.push(fullPath);
    }
  }

  return files.sort();
}
