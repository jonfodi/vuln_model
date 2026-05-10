import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
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
} from "../standardize";
import type {
  NormalizedAdvisoryRecord,
  NormalizedAffectedPackage,
  NormalizedAffectedProduct,
  NormalizedEcosystem,
  NormalizedIngestItem,
  NormalizedReference,
  NormalizedSeverityMetric,
  NormalizedSignal,
  NormalizedSsvcAssessment,
  NormalizedVersionRange,
  NormalizedWeakness,
  SourceAdapter,
} from "../types";

const CVSS_KEYS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"];

export type CveIngestOptions = {
  dir: string;
  limit?: number;
  progressEvery?: number;
};

export const cveAdapter: SourceAdapter<CveIngestOptions> = {
  sourceSlug: "cve-list-v5",
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

    return normalizeCveRecord(record);
  },
};

function normalizeCveRecord(raw: JsonObject): NormalizedAdvisoryRecord {
  const cveMetadata = asObject(raw.cveMetadata);
  const containers = asObject(raw.containers);
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
  const affected = normalizeCveAffected(cna);
  const metrics = [
    ...normalizeCveMetrics({
      container: cna,
      provider: providerShortName(cna),
      cveIdentifier: normalizedCveId,
    }),
  ];
  const ssvcAssessments: NormalizedSsvcAssessment[] = [];
  const signals: NormalizedSignal[] = [];

  for (const metric of metrics) {
    if (metric.kind === "severity") {
      continue;
    }

    if (metric.kind === "ssvc") {
      ssvcAssessments.push(metric.value);
      continue;
    }

    signals.push(metric.value);
  }

  const severityMetrics = metrics
    .filter((metric): metric is { kind: "severity"; value: NormalizedSeverityMetric } => metric.kind === "severity")
    .map((metric) => metric.value);
  const references = normalizeCveReferences(cna, providerShortName(cna));

  for (const adpContainer of asArray(containers?.adp)) {
    const adp = asObject(adpContainer);
    if (!adp) {
      continue;
    }

    for (const metric of normalizeCveMetrics({
      container: adp,
      provider: providerShortName(adp),
      cveIdentifier: normalizedCveId,
    })) {
      if (metric.kind === "severity") {
        severityMetrics.push(metric.value);
      } else if (metric.kind === "ssvc") {
        ssvcAssessments.push(metric.value);
      } else {
        signals.push(metric.value);
      }
    }

    references.push(...normalizeCveReferences(adp, providerShortName(adp)));
  }

  return {
    kind: "advisory_record",
    sourceRecord: {
      sourceSlug: "cve-list-v5",
      externalId: normalizedCveId,
      url: `https://www.cve.org/CVERecord?id=${normalizedCveId}`,
      schemaVersion: asString(raw.dataVersion),
      sourcePublishedAt: toTimestamp(cveMetadata?.datePublished),
      sourceModifiedAt: toTimestamp(cveMetadata?.dateUpdated),
      raw,
    },
    canonical: {
      primaryIdentifier: normalizedCveId,
      title,
      summary,
      status,
    },
    record: {
      recordId: normalizedCveId,
      summary,
      details,
      publishedAt: toTimestamp(cveMetadata?.datePublished),
      modifiedAt: toTimestamp(cveMetadata?.dateUpdated),
      withdrawnAt: toTimestamp(cveMetadata?.dateRejected),
      status,
    },
    identifiers: [{ value: normalizedCveId, relationship: "primary" }],
    relationships: normalizeCveReplacements(cna),
    affectedProducts: affected.products,
    affectedPackages: affected.packages,
    weaknesses: normalizeCveWeaknesses(cna),
    severityMetrics,
    ssvcAssessments,
    references,
    signals,
  };
}

function normalizeCveAffected(cna: JsonObject): {
  products: NormalizedAffectedProduct[];
  packages: NormalizedAffectedPackage[];
} {
  const products: NormalizedAffectedProduct[] = [];
  const packages: NormalizedAffectedPackage[] = [];

  for (const [sourceIndex, affectedValue] of asArray(cna.affected).entries()) {
    const affected = asObject(affectedValue);
    if (!affected) {
      continue;
    }

    const productName = asString(affected.product);
    const vendorName = asString(affected.vendor);
    const packageInfo = cvePackageInfo(affected);
    const defaultStatus = asString(affected.defaultStatus);
    const versionRanges = cveVersionRanges(affected);
    const relationship = cveAffectedRelationship(defaultStatus, versionRanges);

    if (productName && productName.toLowerCase() !== "n/a") {
      products.push({
        sourceIndex,
        name: productName,
        vendor: vendorName,
        relationship,
        defaultStatus,
        platforms: affected.platforms,
        modules: affected.modules,
        programFiles: affected.programFiles,
        programRoutines: affected.programRoutines,
        repo: asString(affected.repo),
        raw: affected,
        identifiers: cveProductIdentifiers(affected),
        versionRanges,
      });
    }

    if (packageInfo) {
      packages.push({
        sourceIndex,
        ecosystem: packageInfo.ecosystem,
        package: {
          name: packageInfo.packageName,
          purl: packageInfo.packageUrl,
        },
        relationship,
        defaultStatus,
        platforms: affected.platforms,
        modules: affected.modules,
        repo: asString(affected.repo),
        raw: affected,
        identifiers: cvePackageIdentifiers(affected),
        versionRanges,
        productLink: productName
          ? {
              name: productName,
              vendor: vendorName,
              source: "cve-list-v5",
              confidence: "medium",
            }
          : undefined,
      });
    }
  }

  return { products, packages };
}

function cvePackageInfo(affected: JsonObject):
  | {
      ecosystem: NormalizedEcosystem;
      packageName: string;
      packageUrl: string | null;
    }
  | undefined {
  const packageUrl = asString(affected.packageURL);
  const collectionUrl = asString(affected.collectionURL);
  const packageName = normalizePackageName(
    asString(affected.packageName),
    packageUrl,
  );

  if (!packageName) {
    return undefined;
  }

  const ecosystemSlug =
    (packageUrl ? ecosystemFromPurl(packageUrl) : undefined) ??
    (collectionUrl ? ecosystemFromCollectionUrl(collectionUrl) : undefined) ??
    "generic";
  const aliases: NormalizedEcosystem["aliases"] = [];

  if (packageUrl) {
    aliases.push({
      alias: packageUrl.split("/")[0]?.replace("pkg:", "") ?? ecosystemSlug,
      aliasKind: "purl_type",
      source: "cve-list-v5",
      raw: { packageURL: packageUrl },
    });
  }

  if (collectionUrl) {
    aliases.push({
      alias: collectionUrl,
      aliasKind: "collection_url",
      source: "cve-list-v5",
      raw: { collectionURL: collectionUrl },
    });
  }

  return {
    ecosystem: {
      slug: ecosystemSlug,
      name: ecosystemSlug,
      kind: ecosystemSlug.startsWith("collection-")
        ? "package-collection"
        : undefined,
      aliases,
    },
    packageName,
    packageUrl: packageUrl ?? null,
  };
}

function cveProductIdentifiers(affected: JsonObject) {
  return asArray(affected.cpes)
    .map(asString)
    .filter((value): value is string => Boolean(value))
    .map((value) => ({
      kind: "cpe",
      value,
      sourceField: "cpes",
    }));
}

function cvePackageIdentifiers(affected: JsonObject) {
  const identifiers = [];
  const packageName = asString(affected.packageName);
  const packageUrl = asString(affected.packageURL);
  const collectionUrl = asString(affected.collectionURL);

  if (packageName) {
    identifiers.push({
      kind: "package_name",
      value: packageName,
      sourceField: "packageName",
    });
  }

  if (packageUrl) {
    identifiers.push({
      kind: "purl",
      value: packageUrl,
      sourceField: "packageURL",
    });
  }

  if (collectionUrl) {
    identifiers.push({
      kind: "collection_url",
      value: collectionUrl,
      sourceField: "collectionURL",
    });
  }

  return identifiers;
}

function cveVersionRanges(affected: JsonObject): NormalizedVersionRange[] {
  return asArray(affected.versions)
    .map(asObject)
    .filter((version): version is JsonObject => Boolean(version))
    .map((version, sourceIndex) => {
      const status = asString(version.status);
      const lessThan = asString(version.lessThan);
      const lessThanOrEqual = asString(version.lessThanOrEqual);
      const startVersion = asString(version.version);

      return {
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
    });
}

function cveAffectedRelationship(
  defaultStatus: string | undefined,
  ranges: NormalizedVersionRange[],
) {
  if (
    defaultStatus === "affected" ||
    ranges.some((range) => range.status === "affected")
  ) {
    return "affected";
  }

  if (ranges.length > 0 && ranges.every((range) => range.status === "unaffected")) {
    return "unaffected";
  }

  return "affected";
}

function normalizeCveWeaknesses(cna: JsonObject): NormalizedWeakness[] {
  const weaknesses: NormalizedWeakness[] = [];

  for (const problemType of asArray(cna.problemTypes)) {
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
      weaknesses.push({
        cweId,
        name: value?.replace(new RegExp(`^${cweId}:?\\s*`, "i"), ""),
        description: value ?? null,
      });
    }
  }

  return weaknesses;
}

type MetricItem =
  | { kind: "severity"; value: NormalizedSeverityMetric }
  | { kind: "ssvc"; value: NormalizedSsvcAssessment }
  | { kind: "signal"; value: NormalizedSignal };

function normalizeCveMetrics(input: {
  container: JsonObject;
  provider: string | null;
  cveIdentifier: string;
}): MetricItem[] {
  const metrics: MetricItem[] = [];

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

      metrics.push({
        kind: "severity",
        value: {
          provider: input.provider,
          system: cvssSystemFromKey(cvssKey),
          score: scoreString(cvss.baseScore),
          severity: asString(cvss.baseSeverity),
          vector: asString(cvss.vectorString),
          raw: metric,
          cvss: {
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
          },
        },
      });
    }

    const other = asObject(metric.other);
    if (!other) {
      continue;
    }

    const otherType = asString(other.type);
    const content = asObject(other.content);

    if (otherType?.toLowerCase().startsWith("ssvc") && content) {
      metrics.push({
        kind: "ssvc",
        value: {
          provider: input.provider,
          ...parseSsvcContent(content),
        },
      });
      continue;
    }

    if (otherType?.toLowerCase() === "kev" && content) {
      metrics.push({
        kind: "signal",
        value: {
          kind: "kev",
          cveIdentifier: input.cveIdentifier,
          knownExploited: true,
          dateAdded: toDateString(content.dateAdded),
          notes: asString(content.reference),
        },
      });
      continue;
    }

    metrics.push({
      kind: "severity",
      value: {
        provider: input.provider,
        system: otherType ? slugify(otherType) : "other",
        severity: asString(content?.value) ?? asString(otherType),
        raw: metric,
      },
    });
  }

  return metrics;
}

function normalizeCveReferences(
  container: JsonObject,
  sourceName: string | null,
): NormalizedReference[] {
  const references: NormalizedReference[] = [];

  for (const referenceValue of asArray(container.references)) {
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
      title: asString(reference.name),
      kind: referenceKindFromTags(reference.tags),
      sourceName,
      tags: reference.tags ?? null,
      raw: reference,
    });
  }

  return references;
}

function normalizeCveReplacements(cna: JsonObject) {
  return asArray(cna.replacedBy)
    .map(asString)
    .filter((identifier): identifier is string => Boolean(identifier))
    .map((identifier) => ({
      identifier,
      relationship: "replaced_by",
      raw: { replacedBy: identifier },
    }));
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
