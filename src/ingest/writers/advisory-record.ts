import {
  clearSourceRecordSignals,
  clearVulnerabilityRecordFacts,
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
  upsertPackage,
  upsertProduct,
  upsertSource,
  upsertSourceRecord,
  upsertVulnerabilityRecord,
  upsertVulnerabilityRecordRelationship,
  upsertWeakness,
  type IngestDb,
} from "../repository";
import { sourceSeedForSlug } from "../seed";
import type {
  NormalizedAdvisoryRecord,
  NormalizedAffectedPackage,
  NormalizedAffectedProduct,
  NormalizedVersionRange,
} from "../types";
import { resolveCanonicalVulnerability } from "./resolve-vulnerability";
import { writeSignal } from "./signals";

export async function writeAdvisoryRecord(
  db: IngestDb,
  item: NormalizedAdvisoryRecord,
) {
  const source = await upsertSource(db, sourceSeedForSlug(item.sourceRecord.sourceSlug));
  const sourceRecord = await upsertSourceRecord(db, {
    sourceId: source.id,
    externalId: item.sourceRecord.externalId,
    url: item.sourceRecord.url,
    schemaVersion: item.sourceRecord.schemaVersion,
    sourcePublishedAt: item.sourceRecord.sourcePublishedAt,
    sourceModifiedAt: item.sourceRecord.sourceModifiedAt,
    raw: item.sourceRecord.raw,
  });
  const vulnerability = await resolveCanonicalVulnerability(db, item.canonical);
  const vulnerabilityRecord = await upsertVulnerabilityRecord(db, {
    sourceRecordId: sourceRecord.id,
    vulnerabilityId: vulnerability.id,
    recordId: item.record.recordId,
    summary: item.record.summary,
    details: item.record.details,
    publishedAt: item.record.publishedAt,
    modifiedAt: item.record.modifiedAt,
    withdrawnAt: item.record.withdrawnAt,
    status: item.record.status,
  });

  await clearVulnerabilityRecordFacts(db, vulnerabilityRecord.id);
  await clearSourceRecordSignals(db, sourceRecord.id);

  for (const identifierValue of item.identifiers) {
    const identifier = await upsertIdentifier(db, identifierValue.value);
    const relationship = identifierValue.relationship ?? "alias";
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

  for (const relationship of item.relationships ?? []) {
    const identifier = await upsertIdentifier(db, relationship.identifier);
    await upsertVulnerabilityRecordRelationship(db, {
      vulnerabilityRecordId: vulnerabilityRecord.id,
      sourceRecordId: sourceRecord.id,
      relatedIdentifierId: identifier.id,
      relationship: relationship.relationship,
      raw: relationship.raw,
    });
  }

  const affectedProductIds = new Map<number, string>();
  const affectedPackageIds = new Map<number, string>();

  for (const affectedProduct of item.affectedProducts ?? []) {
    const affectedProductId = await writeAffectedProduct(db, {
      vulnerabilityRecordId: vulnerabilityRecord.id,
      affectedProduct,
    });
    affectedProductIds.set(affectedProduct.sourceIndex, affectedProductId);
  }

  for (const affectedPackage of item.affectedPackages ?? []) {
    const affectedPackageId = await writeAffectedPackage(db, {
      vulnerabilityRecordId: vulnerabilityRecord.id,
      affectedPackage,
    });
    affectedPackageIds.set(affectedPackage.sourceIndex, affectedPackageId);
  }

  for (const weaknessValue of item.weaknesses ?? []) {
    const weakness = await upsertWeakness(db, {
      cweId: weaknessValue.cweId,
      name: weaknessValue.name,
      description: weaknessValue.description,
    });
    await linkVulnerabilityRecordWeakness(
      db,
      vulnerabilityRecord.id,
      weakness.id,
      weaknessValue.relationship,
    );
  }

  for (const severity of item.severityMetrics ?? []) {
    const severityMetric = await insertSeverityMetric(db, {
      vulnerabilityRecordId: vulnerabilityRecord.id,
      sourceRecordId: sourceRecord.id,
      provider: severity.provider,
      system: severity.system,
      affectedProductId:
        severity.affectedProductSourceIndex == null
          ? null
          : affectedProductIds.get(severity.affectedProductSourceIndex),
      affectedPackageId:
        severity.affectedPackageSourceIndex == null
          ? null
          : affectedPackageIds.get(severity.affectedPackageSourceIndex),
      score: severity.score,
      severity: severity.severity,
      vector: severity.vector,
      raw: severity.raw,
    });

    if (severity.cvss) {
      await insertCvssMetricDetails(db, {
        severityMetricId: severityMetric.id,
        ...severity.cvss,
      });
    }
  }

  for (const ssvc of item.ssvcAssessments ?? []) {
    await insertSsvcAssessment(db, {
      vulnerabilityRecordId: vulnerabilityRecord.id,
      sourceRecordId: sourceRecord.id,
      provider: ssvc.provider,
      exploitation: ssvc.exploitation,
      automatable: ssvc.automatable,
      technicalImpact: ssvc.technicalImpact,
      role: ssvc.role,
      version: ssvc.version,
      assessedAt: ssvc.assessedAt,
    });
  }

  for (const referenceValue of item.references ?? []) {
    const reference = await upsertExternalReference(db, {
      url: referenceValue.url,
      title: referenceValue.title,
      kind: referenceValue.kind,
    });
    await linkVulnerabilityRecordReference(db, {
      vulnerabilityRecordId: vulnerabilityRecord.id,
      referenceId: reference.id,
      relationship: referenceValue.relationship,
      sourceName: referenceValue.sourceName,
      tags: referenceValue.tags,
      raw: referenceValue.raw,
    });
  }

  for (const signal of item.signals ?? []) {
    await writeSignal(db, {
      vulnerabilityId: vulnerability.id,
      sourceRecordId: sourceRecord.id,
      signal,
    });
  }
}

async function writeAffectedProduct(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    affectedProduct: NormalizedAffectedProduct;
  },
) {
  const product = await upsertProduct(db, {
    name: values.affectedProduct.name,
    vendor: values.affectedProduct.vendor,
  });
  const affectedProduct = await upsertAffectedProduct(db, {
    vulnerabilityRecordId: values.vulnerabilityRecordId,
    productId: product.id,
    sourceIndex: values.affectedProduct.sourceIndex,
    relationship: affectedRelationship(values.affectedProduct),
    defaultStatus: values.affectedProduct.defaultStatus,
    platforms: values.affectedProduct.platforms,
    modules: values.affectedProduct.modules,
    programFiles: values.affectedProduct.programFiles,
    programRoutines: values.affectedProduct.programRoutines,
    repo: values.affectedProduct.repo,
    raw: values.affectedProduct.raw,
  });

  for (const identifierValue of values.affectedProduct.identifiers ?? []) {
    await insertAffectedSoftwareIdentifier(db, {
      affectedProductId: affectedProduct.id,
      kind: identifierValue.kind,
      value: identifierValue.value,
      sourceField: identifierValue.sourceField,
      raw: identifierValue.raw,
    });
  }

  for (const versionRange of values.affectedProduct.versionRanges ?? []) {
    await writeVersionRange(db, versionRange, {
      affectedProductId: affectedProduct.id,
    });
  }

  return affectedProduct.id;
}

async function writeAffectedPackage(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    affectedPackage: NormalizedAffectedPackage;
  },
) {
  const ecosystem = await upsertEcosystem(db, values.affectedPackage.ecosystem);

  for (const alias of values.affectedPackage.ecosystem.aliases ?? []) {
    await upsertEcosystemAlias(db, {
      ecosystemId: ecosystem.id,
      alias: alias.alias,
      aliasKind: alias.aliasKind,
      scope: alias.scope,
      source: alias.source,
      raw: alias.raw,
    });
  }

  const pkg = await upsertPackage(db, {
    ecosystemId: ecosystem.id,
    name: values.affectedPackage.package.name,
    purl: values.affectedPackage.package.purl,
  });
  const affectedPackage = await upsertAffectedPackage(db, {
    vulnerabilityRecordId: values.vulnerabilityRecordId,
    packageId: pkg.id,
    sourceIndex: values.affectedPackage.sourceIndex,
    relationship: affectedRelationship(values.affectedPackage),
    defaultStatus: values.affectedPackage.defaultStatus,
    platforms: values.affectedPackage.platforms,
    modules: values.affectedPackage.modules,
    repo: values.affectedPackage.repo,
    raw: values.affectedPackage.raw,
  });

  for (const identifierValue of values.affectedPackage.identifiers ?? []) {
    await insertAffectedSoftwareIdentifier(db, {
      affectedPackageId: affectedPackage.id,
      kind: identifierValue.kind,
      value: identifierValue.value,
      sourceField: identifierValue.sourceField,
      raw: identifierValue.raw,
    });
  }

  for (const versionRange of values.affectedPackage.versionRanges ?? []) {
    await writeVersionRange(db, versionRange, {
      affectedPackageId: affectedPackage.id,
    });
  }

  if (values.affectedPackage.productLink) {
    const product = await upsertProduct(db, {
      name: values.affectedPackage.productLink.name,
      vendor: values.affectedPackage.productLink.vendor,
    });
    await linkPackageProduct(db, pkg.id, product.id, {
      relationship: values.affectedPackage.productLink.relationship,
      confidence: values.affectedPackage.productLink.confidence,
      source: values.affectedPackage.productLink.source,
    });
  }

  return affectedPackage.id;
}

async function writeVersionRange(
  db: IngestDb,
  versionRange: NormalizedVersionRange,
  target: {
    affectedProductId?: string;
    affectedPackageId?: string;
  },
) {
  await insertVersionRange(db, {
    affectedProductId: target.affectedProductId,
    affectedPackageId: target.affectedPackageId,
    rangeType: versionRange.rangeType,
    sourceIndex: versionRange.sourceIndex,
    status: versionRange.status,
    version: versionRange.version,
    versionType: versionRange.versionType,
    introduced: versionRange.introduced,
    fixed: versionRange.fixed,
    lastAffected: versionRange.lastAffected,
    limit: versionRange.limit,
    lessThan: versionRange.lessThan,
    lessThanOrEqual: versionRange.lessThanOrEqual,
    expression: versionRange.expression,
    repo: versionRange.repo,
    changes: versionRange.changes,
    raw: versionRange.raw,
  });
}

function affectedRelationship(
  affected: NormalizedAffectedProduct | NormalizedAffectedPackage,
) {
  if (affected.relationship) {
    return affected.relationship;
  }

  if (
    affected.defaultStatus === "affected" ||
    affected.versionRanges?.some((range) => range.status === "affected")
  ) {
    return "affected";
  }

  if (
    affected.versionRanges?.length &&
    affected.versionRanges.every((range) => range.status === "unaffected")
  ) {
    return "unaffected";
  }

  return "affected";
}
