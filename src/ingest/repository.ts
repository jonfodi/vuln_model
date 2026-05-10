import { and, eq, sql } from "drizzle-orm";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import * as schema from "../db/schema";
import {
  buildProductSlug,
  inferIdentifierKind,
  normalizeIdentifierValue,
  slugify,
  type JsonObject,
} from "./standardize";

export type IngestDb = PostgresJsDatabase<typeof schema>;

export type SourceSeed = {
  slug: string;
  name: string;
  kind: string;
  url?: string;
};

export async function upsertSource(db: IngestDb, seed: SourceSeed) {
  const [row] = await db
    .insert(schema.sources)
    .values({
      slug: seed.slug,
      name: seed.name,
      kind: seed.kind,
      url: seed.url ?? null,
    })
    .onConflictDoUpdate({
      target: schema.sources.slug,
      set: {
        name: seed.name,
        kind: seed.kind,
        url: seed.url ?? null,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertSourceRecord(
  db: IngestDb,
  values: {
    sourceId: string;
    externalId: string;
    url?: string | null;
    schemaVersion?: string | null;
    sourcePublishedAt?: Date | null;
    sourceModifiedAt?: Date | null;
    raw: unknown;
  },
) {
  const [row] = await db
    .insert(schema.sourceRecords)
    .values({
      sourceId: values.sourceId,
      externalId: values.externalId,
      url: values.url ?? null,
      schemaVersion: values.schemaVersion ?? null,
      sourcePublishedAt: values.sourcePublishedAt ?? null,
      sourceModifiedAt: values.sourceModifiedAt ?? null,
      raw: values.raw,
    })
    .onConflictDoUpdate({
      target: [
        schema.sourceRecords.sourceId,
        schema.sourceRecords.externalId,
      ],
      set: {
        url: values.url ?? null,
        schemaVersion: values.schemaVersion ?? null,
        sourcePublishedAt: values.sourcePublishedAt ?? null,
        sourceModifiedAt: values.sourceModifiedAt ?? null,
        raw: values.raw,
        fetchedAt: sql`now()`,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertIdentifier(db: IngestDb, value: string) {
  const normalized = normalizeIdentifierValue(value);
  const [row] = await db
    .insert(schema.identifiers)
    .values({
      value: normalized,
      kind: inferIdentifierKind(normalized),
    })
    .onConflictDoUpdate({
      target: schema.identifiers.value,
      set: {
        kind: inferIdentifierKind(normalized),
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertVulnerability(
  db: IngestDb,
  values: {
    primaryIdentifier: string;
    title?: string | null;
    summary?: string | null;
    status?: string | null;
    preserveExistingText?: boolean;
  },
) {
  const primaryIdentifier = normalizeIdentifierValue(values.primaryIdentifier);
  const titleUpdate = values.preserveExistingText
    ? sql`coalesce(${schema.vulnerabilities.title}, ${values.title ?? null})`
    : values.title == null
      ? sql`${schema.vulnerabilities.title}`
      : values.title;
  const summaryUpdate = values.preserveExistingText
    ? sql`coalesce(${schema.vulnerabilities.summary}, ${values.summary ?? null})`
    : values.summary == null
      ? sql`${schema.vulnerabilities.summary}`
      : values.summary;
  const [row] = await db
    .insert(schema.vulnerabilities)
    .values({
      primaryIdentifier,
      title: values.title ?? null,
      summary: values.summary ?? null,
      status: values.status ?? "active",
    })
    .onConflictDoUpdate({
      target: schema.vulnerabilities.primaryIdentifier,
      set: {
        title: titleUpdate,
        summary: summaryUpdate,
        status:
          values.status == null
            ? sql`${schema.vulnerabilities.status}`
            : values.status,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertVulnerabilityRecord(
  db: IngestDb,
  values: {
    sourceRecordId: string;
    vulnerabilityId?: string | null;
    recordId: string;
    summary?: string | null;
    details?: string | null;
    publishedAt?: Date | null;
    modifiedAt?: Date | null;
    withdrawnAt?: Date | null;
    status?: string | null;
  },
) {
  const [row] = await db
    .insert(schema.vulnerabilityRecords)
    .values({
      sourceRecordId: values.sourceRecordId,
      vulnerabilityId: values.vulnerabilityId ?? null,
      recordId: values.recordId,
      summary: values.summary ?? null,
      details: values.details ?? null,
      publishedAt: values.publishedAt ?? null,
      modifiedAt: values.modifiedAt ?? null,
      withdrawnAt: values.withdrawnAt ?? null,
      status: values.status ?? "active",
    })
    .onConflictDoUpdate({
      target: schema.vulnerabilityRecords.sourceRecordId,
      set: {
        vulnerabilityId: values.vulnerabilityId ?? null,
        recordId: values.recordId,
        summary: values.summary ?? null,
        details: values.details ?? null,
        publishedAt: values.publishedAt ?? null,
        modifiedAt: values.modifiedAt ?? null,
        withdrawnAt: values.withdrawnAt ?? null,
        status: values.status ?? "active",
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function linkVulnerabilityIdentifier(
  db: IngestDb,
  vulnerabilityId: string,
  identifierId: string,
  relationship = "alias",
) {
  await db
    .insert(schema.vulnerabilityIdentifiers)
    .values({ vulnerabilityId, identifierId, relationship })
    .onConflictDoUpdate({
      target: [
        schema.vulnerabilityIdentifiers.vulnerabilityId,
        schema.vulnerabilityIdentifiers.identifierId,
      ],
      set: {
        relationship,
        updatedAt: sql`now()`,
      },
    });
}

export async function linkVulnerabilityRecordIdentifier(
  db: IngestDb,
  vulnerabilityRecordId: string,
  identifierId: string,
  relationship = "alias",
) {
  await db
    .insert(schema.vulnerabilityRecordIdentifiers)
    .values({ vulnerabilityRecordId, identifierId, relationship })
    .onConflictDoUpdate({
      target: [
        schema.vulnerabilityRecordIdentifiers.vulnerabilityRecordId,
        schema.vulnerabilityRecordIdentifiers.identifierId,
      ],
      set: {
        relationship,
        updatedAt: sql`now()`,
      },
    });
}

export async function upsertVulnerabilityRecordRelationship(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    sourceRecordId: string;
    relatedIdentifierId: string;
    relationship: string;
    raw?: unknown;
  },
) {
  await db
    .insert(schema.vulnerabilityRecordRelationships)
    .values({
      vulnerabilityRecordId: values.vulnerabilityRecordId,
      sourceRecordId: values.sourceRecordId,
      relatedIdentifierId: values.relatedIdentifierId,
      relationship: values.relationship,
      raw: values.raw ?? null,
    })
    .onConflictDoUpdate({
      target: [
        schema.vulnerabilityRecordRelationships.vulnerabilityRecordId,
        schema.vulnerabilityRecordRelationships.relatedIdentifierId,
        schema.vulnerabilityRecordRelationships.relationship,
      ],
      set: {
        sourceRecordId: values.sourceRecordId,
        raw: values.raw ?? null,
        updatedAt: sql`now()`,
      },
    });
}

export async function upsertEcosystem(
  db: IngestDb,
  values: {
    slug: string;
    name?: string | null;
    kind?: string | null;
    versionScheme?: string | null;
    packageUrlType?: string | null;
  },
) {
  const slug = slugify(values.slug);
  const [row] = await db
    .insert(schema.ecosystems)
    .values({
      slug,
      name: values.name ?? slug,
      kind: values.kind ?? "package-registry",
      versionScheme: values.versionScheme ?? null,
      packageUrlType: values.packageUrlType ?? null,
    })
    .onConflictDoUpdate({
      target: schema.ecosystems.slug,
      set: {
        name:
          values.name == null ? sql`${schema.ecosystems.name}` : values.name,
        kind:
          values.kind == null ? sql`${schema.ecosystems.kind}` : values.kind,
        versionScheme:
          values.versionScheme == null
            ? sql`${schema.ecosystems.versionScheme}`
            : values.versionScheme,
        packageUrlType:
          values.packageUrlType == null
            ? sql`${schema.ecosystems.packageUrlType}`
            : values.packageUrlType,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertEcosystemAlias(
  db: IngestDb,
  values: {
    ecosystemId: string;
    alias: string;
    aliasKind: string;
    scope?: string | null;
    source?: string | null;
    raw?: unknown;
  },
) {
  await db
    .insert(schema.ecosystemAliases)
    .values({
      ecosystemId: values.ecosystemId,
      alias: values.alias,
      aliasKind: values.aliasKind,
      scope: values.scope ?? "",
      source: values.source ?? null,
      raw: values.raw ?? null,
    })
    .onConflictDoUpdate({
      target: [
        schema.ecosystemAliases.alias,
        schema.ecosystemAliases.aliasKind,
        schema.ecosystemAliases.scope,
      ],
      set: {
        ecosystemId: values.ecosystemId,
        source: values.source ?? null,
        raw: values.raw ?? null,
        updatedAt: sql`now()`,
      },
    });
}

export async function upsertProduct(
  db: IngestDb,
  values: {
    name: string;
    vendor?: string | null;
  },
) {
  const [row] = await db
    .insert(schema.products)
    .values({
      slug: buildProductSlug(values.vendor ?? undefined, values.name),
      name: values.name,
      vendor: values.vendor ?? null,
    })
    .onConflictDoUpdate({
      target: schema.products.slug,
      set: {
        name: values.name,
        vendor: values.vendor ?? null,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertPackage(
  db: IngestDb,
  values: {
    ecosystemId: string;
    name: string;
    purl?: string | null;
  },
) {
  if (values.purl) {
    const existingByPurl = await db
      .select()
      .from(schema.packages)
      .where(eq(schema.packages.purl, values.purl))
      .limit(1);

    if (existingByPurl[0]) {
      const [row] = await db
        .update(schema.packages)
        .set({ updatedAt: sql`now()` })
        .where(eq(schema.packages.id, existingByPurl[0].id))
        .returning();

      return row;
    }
  }

  const existing = await db
    .select()
    .from(schema.packages)
    .where(
      and(
        eq(schema.packages.ecosystemId, values.ecosystemId),
        eq(schema.packages.name, values.name),
      ),
    )
    .limit(1);

  if (existing[0]) {
    const [row] = await db
      .update(schema.packages)
      .set({
        purl: values.purl ?? existing[0].purl,
        updatedAt: sql`now()`,
      })
      .where(eq(schema.packages.id, existing[0].id))
      .returning();

    return row;
  }

  const [row] = await db
    .insert(schema.packages)
    .values({
      ecosystemId: values.ecosystemId,
      name: values.name,
      purl: values.purl ?? null,
    })
    .onConflictDoUpdate({
      target: [schema.packages.ecosystemId, schema.packages.name],
      set: {
        purl: values.purl ?? null,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function linkPackageProduct(
  db: IngestDb,
  packageId: string,
  productId: string,
  values?: {
    relationship?: string;
    confidence?: string;
    source?: string | null;
  },
) {
  await db
    .insert(schema.packageProducts)
    .values({
      packageId,
      productId,
      relationship: values?.relationship ?? "distributed_as",
      confidence: values?.confidence ?? "medium",
      source: values?.source ?? null,
    })
    .onConflictDoUpdate({
      target: [
        schema.packageProducts.packageId,
        schema.packageProducts.productId,
      ],
      set: {
        relationship: values?.relationship ?? "distributed_as",
        confidence: values?.confidence ?? "medium",
        source: values?.source ?? null,
        updatedAt: sql`now()`,
      },
    });
}

export async function upsertAffectedProduct(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    productId: string;
    sourceIndex: number;
    relationship?: string;
    defaultStatus?: string | null;
    platforms?: unknown;
    modules?: unknown;
    programFiles?: unknown;
    programRoutines?: unknown;
    repo?: string | null;
    raw?: unknown;
  },
) {
  const [row] = await db
    .insert(schema.affectedProducts)
    .values({
      vulnerabilityRecordId: values.vulnerabilityRecordId,
      productId: values.productId,
      sourceIndex: values.sourceIndex,
      relationship: values.relationship ?? "affected",
      defaultStatus: values.defaultStatus ?? null,
      platforms: values.platforms ?? null,
      modules: values.modules ?? null,
      programFiles: values.programFiles ?? null,
      programRoutines: values.programRoutines ?? null,
      repo: values.repo ?? null,
      raw: values.raw ?? null,
    })
    .onConflictDoUpdate({
      target: [
        schema.affectedProducts.vulnerabilityRecordId,
        schema.affectedProducts.productId,
        schema.affectedProducts.sourceIndex,
      ],
      set: {
        relationship: values.relationship ?? "affected",
        defaultStatus: values.defaultStatus ?? null,
        platforms: values.platforms ?? null,
        modules: values.modules ?? null,
        programFiles: values.programFiles ?? null,
        programRoutines: values.programRoutines ?? null,
        repo: values.repo ?? null,
        raw: values.raw ?? null,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function upsertAffectedPackage(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    packageId: string;
    sourceIndex: number;
    relationship?: string;
    defaultStatus?: string | null;
    platforms?: unknown;
    modules?: unknown;
    repo?: string | null;
    raw?: unknown;
  },
) {
  const [row] = await db
    .insert(schema.affectedPackages)
    .values({
      vulnerabilityRecordId: values.vulnerabilityRecordId,
      packageId: values.packageId,
      sourceIndex: values.sourceIndex,
      relationship: values.relationship ?? "affected",
      defaultStatus: values.defaultStatus ?? null,
      platforms: values.platforms ?? null,
      modules: values.modules ?? null,
      repo: values.repo ?? null,
      raw: values.raw ?? null,
    })
    .onConflictDoUpdate({
      target: [
        schema.affectedPackages.vulnerabilityRecordId,
        schema.affectedPackages.packageId,
        schema.affectedPackages.sourceIndex,
      ],
      set: {
        relationship: values.relationship ?? "affected",
        defaultStatus: values.defaultStatus ?? null,
        platforms: values.platforms ?? null,
        modules: values.modules ?? null,
        repo: values.repo ?? null,
        raw: values.raw ?? null,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function insertVersionRange(
  db: IngestDb,
  values: {
    affectedPackageId?: string | null;
    affectedProductId?: string | null;
    rangeType?: string | null;
    sourceIndex?: number;
    status?: string | null;
    version?: string | null;
    versionType?: string | null;
    introduced?: string | null;
    fixed?: string | null;
    lastAffected?: string | null;
    limit?: string | null;
    lessThan?: string | null;
    lessThanOrEqual?: string | null;
    expression?: string | null;
    repo?: string | null;
    changes?: unknown;
    raw?: unknown;
  },
) {
  const [row] = await db
    .insert(schema.versionRanges)
    .values({
      affectedPackageId: values.affectedPackageId ?? null,
      affectedProductId: values.affectedProductId ?? null,
      rangeType: values.rangeType ?? null,
      sourceIndex: values.sourceIndex ?? 0,
      status: values.status ?? null,
      version: values.version ?? null,
      versionType: values.versionType ?? null,
      introduced: values.introduced ?? null,
      fixed: values.fixed ?? null,
      lastAffected: values.lastAffected ?? null,
      limit: values.limit ?? null,
      lessThan: values.lessThan ?? null,
      lessThanOrEqual: values.lessThanOrEqual ?? null,
      expression: values.expression ?? null,
      repo: values.repo ?? null,
      changes: values.changes ?? null,
      raw: values.raw ?? null,
    })
    .returning();

  return row;
}

export async function insertAffectedSoftwareIdentifier(
  db: IngestDb,
  values: {
    affectedPackageId?: string | null;
    affectedProductId?: string | null;
    kind: string;
    value: string;
    sourceField?: string | null;
    raw?: unknown;
  },
) {
  await db.insert(schema.affectedSoftwareIdentifiers).values({
    affectedPackageId: values.affectedPackageId ?? null,
    affectedProductId: values.affectedProductId ?? null,
    kind: values.kind,
    value: values.value,
    sourceField: values.sourceField ?? null,
    raw: values.raw ?? null,
  });
}

export async function upsertWeakness(
  db: IngestDb,
  values: {
    cweId: string;
    name?: string | null;
    description?: string | null;
  },
) {
  const [row] = await db
    .insert(schema.weaknesses)
    .values({
      cweId: values.cweId,
      name: values.name ?? null,
      description: values.description ?? null,
    })
    .onConflictDoUpdate({
      target: schema.weaknesses.cweId,
      set: {
        name:
          values.name == null ? sql`${schema.weaknesses.name}` : values.name,
        description:
          values.description == null
            ? sql`${schema.weaknesses.description}`
            : values.description,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function linkVulnerabilityRecordWeakness(
  db: IngestDb,
  vulnerabilityRecordId: string,
  weaknessId: string,
  relationship = "asserts",
) {
  await db
    .insert(schema.vulnerabilityRecordWeaknesses)
    .values({ vulnerabilityRecordId, weaknessId, relationship })
    .onConflictDoNothing();
}

export async function insertSeverityMetric(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    sourceRecordId: string;
    provider?: string | null;
    system: string;
    affectedPackageId?: string | null;
    affectedProductId?: string | null;
    score?: string | null;
    severity?: string | null;
    vector?: string | null;
    raw?: unknown;
  },
) {
  const [row] = await db
    .insert(schema.severityMetrics)
    .values({
      vulnerabilityRecordId: values.vulnerabilityRecordId,
      sourceRecordId: values.sourceRecordId,
      provider: values.provider ?? null,
      system: values.system,
      affectedPackageId: values.affectedPackageId ?? null,
      affectedProductId: values.affectedProductId ?? null,
      score: values.score ?? null,
      severity: values.severity ?? null,
      vector: values.vector ?? null,
      raw: values.raw ?? null,
    })
    .returning();

  return row;
}

export async function insertCvssMetricDetails(
  db: IngestDb,
  values: {
    severityMetricId: string;
    cvssVersion: string;
    attackVector?: string | null;
    attackComplexity?: string | null;
    privilegesRequired?: string | null;
    userInteraction?: string | null;
    scope?: string | null;
    confidentialityImpact?: string | null;
    integrityImpact?: string | null;
    availabilityImpact?: string | null;
    raw?: unknown;
  },
) {
  await db
    .insert(schema.cvssMetricDetails)
    .values({
      severityMetricId: values.severityMetricId,
      cvssVersion: values.cvssVersion,
      attackVector: values.attackVector ?? null,
      attackComplexity: values.attackComplexity ?? null,
      privilegesRequired: values.privilegesRequired ?? null,
      userInteraction: values.userInteraction ?? null,
      scope: values.scope ?? null,
      confidentialityImpact: values.confidentialityImpact ?? null,
      integrityImpact: values.integrityImpact ?? null,
      availabilityImpact: values.availabilityImpact ?? null,
      raw: values.raw ?? null,
    })
    .onConflictDoUpdate({
      target: schema.cvssMetricDetails.severityMetricId,
      set: {
        cvssVersion: values.cvssVersion,
        attackVector: values.attackVector ?? null,
        attackComplexity: values.attackComplexity ?? null,
        privilegesRequired: values.privilegesRequired ?? null,
        userInteraction: values.userInteraction ?? null,
        scope: values.scope ?? null,
        confidentialityImpact: values.confidentialityImpact ?? null,
        integrityImpact: values.integrityImpact ?? null,
        availabilityImpact: values.availabilityImpact ?? null,
        raw: values.raw ?? null,
        updatedAt: sql`now()`,
      },
    });
}

export async function insertSsvcAssessment(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    sourceRecordId: string;
    provider?: string | null;
    exploitation?: string | null;
    automatable?: string | null;
    technicalImpact?: string | null;
    role?: string | null;
    version?: string | null;
    assessedAt?: Date | null;
  },
) {
  await db.insert(schema.ssvcAssessments).values({
    vulnerabilityRecordId: values.vulnerabilityRecordId,
    sourceRecordId: values.sourceRecordId,
    provider: values.provider ?? null,
    exploitation: values.exploitation ?? null,
    automatable: values.automatable ?? null,
    technicalImpact: values.technicalImpact ?? null,
    role: values.role ?? null,
    version: values.version ?? null,
    assessedAt: values.assessedAt ?? null,
  });
}

export async function upsertKevEntry(
  db: IngestDb,
  values: {
    vulnerabilityId?: string | null;
    sourceRecordId: string;
    cveIdentifierId: string;
    knownExploited?: boolean;
    vendorProject?: string | null;
    product?: string | null;
    vulnerabilityName?: string | null;
    shortDescription?: string | null;
    dateAdded?: string | null;
    dueDate?: string | null;
    requiredAction?: string | null;
    knownRansomwareCampaignUse?: string | null;
    notes?: string | null;
  },
) {
  await db
    .insert(schema.kevEntries)
    .values({
      vulnerabilityId: values.vulnerabilityId ?? null,
      sourceRecordId: values.sourceRecordId,
      cveIdentifierId: values.cveIdentifierId,
      knownExploited: values.knownExploited ?? true,
      vendorProject: values.vendorProject ?? null,
      product: values.product ?? null,
      vulnerabilityName: values.vulnerabilityName ?? null,
      shortDescription: values.shortDescription ?? null,
      dateAdded: values.dateAdded ?? null,
      dueDate: values.dueDate ?? null,
      requiredAction: values.requiredAction ?? null,
      knownRansomwareCampaignUse: values.knownRansomwareCampaignUse ?? null,
      notes: values.notes ?? null,
    })
    .onConflictDoUpdate({
      target: schema.kevEntries.sourceRecordId,
      set: {
        vulnerabilityId: values.vulnerabilityId ?? null,
        cveIdentifierId: values.cveIdentifierId,
        knownExploited: values.knownExploited ?? true,
        vendorProject: values.vendorProject ?? null,
        product: values.product ?? null,
        vulnerabilityName: values.vulnerabilityName ?? null,
        shortDescription: values.shortDescription ?? null,
        dateAdded: values.dateAdded ?? null,
        dueDate: values.dueDate ?? null,
        requiredAction: values.requiredAction ?? null,
        knownRansomwareCampaignUse:
          values.knownRansomwareCampaignUse ?? null,
        notes: values.notes ?? null,
        updatedAt: sql`now()`,
      },
    });
}

export async function upsertEpssScore(
  db: IngestDb,
  values: {
    vulnerabilityId?: string | null;
    sourceRecordId: string;
    cveIdentifierId: string;
    score: string;
    percentile: string;
    scoreDate: string;
  },
) {
  await db
    .insert(schema.epssScores)
    .values({
      vulnerabilityId: values.vulnerabilityId ?? null,
      sourceRecordId: values.sourceRecordId,
      cveIdentifierId: values.cveIdentifierId,
      score: values.score,
      percentile: values.percentile,
      scoreDate: values.scoreDate,
    })
    .onConflictDoUpdate({
      target: [
        schema.epssScores.cveIdentifierId,
        schema.epssScores.scoreDate,
      ],
      set: {
        vulnerabilityId: values.vulnerabilityId ?? null,
        sourceRecordId: values.sourceRecordId,
        score: values.score,
        percentile: values.percentile,
        updatedAt: sql`now()`,
      },
    });
}

export async function upsertExternalReference(
  db: IngestDb,
  values: {
    url: string;
    title?: string | null;
    kind?: string | null;
  },
) {
  const [row] = await db
    .insert(schema.externalReferences)
    .values({
      url: values.url,
      title: values.title ?? null,
      kind: values.kind ?? null,
    })
    .onConflictDoUpdate({
      target: schema.externalReferences.url,
      set: {
        title:
          values.title == null
            ? sql`${schema.externalReferences.title}`
            : values.title,
        kind:
          values.kind == null
            ? sql`${schema.externalReferences.kind}`
            : values.kind,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return row;
}

export async function linkVulnerabilityRecordReference(
  db: IngestDb,
  values: {
    vulnerabilityRecordId: string;
    referenceId: string;
    relationship?: string;
    sourceName?: string | null;
    tags?: unknown;
    raw?: unknown;
  },
) {
  await db
    .insert(schema.vulnerabilityRecordReferences)
    .values({
      vulnerabilityRecordId: values.vulnerabilityRecordId,
      referenceId: values.referenceId,
      relationship: values.relationship ?? "references",
      sourceName: values.sourceName ?? null,
      tags: values.tags ?? null,
      raw: values.raw ?? null,
    })
    .onConflictDoUpdate({
      target: [
        schema.vulnerabilityRecordReferences.vulnerabilityRecordId,
        schema.vulnerabilityRecordReferences.referenceId,
      ],
      set: {
        relationship: values.relationship ?? "references",
        sourceName: values.sourceName ?? null,
        tags: values.tags ?? null,
        raw: values.raw ?? null,
        updatedAt: sql`now()`,
      },
    });
}

export async function clearVulnerabilityRecordFacts(
  db: IngestDb,
  vulnerabilityRecordId: string,
) {
  await db
    .delete(schema.vulnerabilityRecordReferences)
    .where(
      eq(
        schema.vulnerabilityRecordReferences.vulnerabilityRecordId,
        vulnerabilityRecordId,
      ),
    );

  await db
    .delete(schema.vulnerabilityRecordRelationships)
    .where(
      eq(
        schema.vulnerabilityRecordRelationships.vulnerabilityRecordId,
        vulnerabilityRecordId,
      ),
    );

  await db
    .delete(schema.vulnerabilityRecordIdentifiers)
    .where(
      eq(
        schema.vulnerabilityRecordIdentifiers.vulnerabilityRecordId,
        vulnerabilityRecordId,
      ),
    );

  await db
    .delete(schema.vulnerabilityRecordWeaknesses)
    .where(
      eq(
        schema.vulnerabilityRecordWeaknesses.vulnerabilityRecordId,
        vulnerabilityRecordId,
      ),
    );

  await db
    .delete(schema.severityMetrics)
    .where(
      eq(schema.severityMetrics.vulnerabilityRecordId, vulnerabilityRecordId),
    );

  await db
    .delete(schema.ssvcAssessments)
    .where(
      eq(schema.ssvcAssessments.vulnerabilityRecordId, vulnerabilityRecordId),
    );

  await db
    .delete(schema.affectedPackages)
    .where(
      eq(schema.affectedPackages.vulnerabilityRecordId, vulnerabilityRecordId),
    );

  await db
    .delete(schema.affectedProducts)
    .where(
      eq(schema.affectedProducts.vulnerabilityRecordId, vulnerabilityRecordId),
    );
}

export async function clearSourceRecordSignals(
  db: IngestDb,
  sourceRecordId: string,
) {
  await db
    .delete(schema.kevEntries)
    .where(eq(schema.kevEntries.sourceRecordId, sourceRecordId));
}

export function jsonObject(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}
