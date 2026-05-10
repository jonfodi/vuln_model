import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  date,
  index,
  jsonb,
  numeric,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
};

export const sources = pgTable(
  "sources",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    kind: text("kind").notNull(),
    url: text("url"),
    ...timestamps,
  },
  (table) => ({
    slugIdx: uniqueIndex("sources_slug_idx").on(table.slug),
  }),
);

export const sourceRecords = pgTable(
  "source_records",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    sourceId: uuid("source_id")
      .notNull()
      .references(() => sources.id, { onDelete: "cascade" }),
    externalId: text("external_id").notNull(),
    url: text("url"),
    schemaVersion: text("schema_version"),
    sourcePublishedAt: timestamp("source_published_at", { withTimezone: true }),
    sourceModifiedAt: timestamp("source_modified_at", { withTimezone: true }),
    fetchedAt: timestamp("fetched_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    raw: jsonb("raw").notNull(),
    ...timestamps,
  },
  (table) => ({
    sourceExternalIdx: uniqueIndex("source_records_source_external_idx").on(
      table.sourceId,
      table.externalId,
    ),
    sourceIdx: index("source_records_source_idx").on(table.sourceId),
  }),
);

export const vulnerabilities = pgTable(
  "vulnerabilities",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    primaryIdentifier: text("primary_identifier"),
    title: text("title"),
    summary: text("summary"),
    status: text("status").notNull().default("active"),
    ...timestamps,
  },
  (table) => ({
    primaryIdentifierIdx: uniqueIndex("vulnerabilities_primary_identifier_idx").on(
      table.primaryIdentifier,
    ),
  }),
);

export const vulnerabilityRecords = pgTable(
  "vulnerability_records",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    sourceRecordId: uuid("source_record_id")
      .notNull()
      .references(() => sourceRecords.id, { onDelete: "cascade" }),
    vulnerabilityId: uuid("vulnerability_id").references(
      () => vulnerabilities.id,
      { onDelete: "set null" },
    ),
    recordId: text("record_id").notNull(),
    summary: text("summary"),
    details: text("details"),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    modifiedAt: timestamp("modified_at", { withTimezone: true }),
    withdrawnAt: timestamp("withdrawn_at", { withTimezone: true }),
    status: text("status").notNull().default("active"),
    ...timestamps,
  },
  (table) => ({
    sourceRecordIdx: uniqueIndex("vulnerability_records_source_record_idx").on(
      table.sourceRecordId,
    ),
    vulnerabilityIdx: index("vulnerability_records_vulnerability_idx").on(
      table.vulnerabilityId,
    ),
    recordIdIdx: index("vulnerability_records_record_id_idx").on(table.recordId),
  }),
);

// External identifiers used to reconcile source records into one vulnerability.
// Ingestion examples: CVE cveMetadata.cveId, OSV id/aliases/upstream, GHSA IDs,
// distro advisory IDs.
export const identifiers = pgTable(
  "identifiers",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    value: text("value").notNull(),
    kind: text("kind").notNull(),
    ...timestamps,
  },
  (table) => ({
    valueIdx: uniqueIndex("identifiers_value_idx").on(table.value),
    kindIdx: index("identifiers_kind_idx").on(table.kind),
  }),
);

// Canonical identifiers after clustering records into a vulnerability.
export const vulnerabilityIdentifiers = pgTable(
  "vulnerability_identifiers",
  {
    vulnerabilityId: uuid("vulnerability_id")
      .notNull()
      .references(() => vulnerabilities.id, { onDelete: "cascade" }),
    identifierId: uuid("identifier_id")
      .notNull()
      .references(() => identifiers.id, { onDelete: "cascade" }),
    relationship: text("relationship").notNull().default("alias"),
    ...timestamps,
  },
  (table) => ({
    pk: primaryKey({
      columns: [table.vulnerabilityId, table.identifierId],
    }),
  }),
);

export const vulnerabilityRecordIdentifiers = pgTable(
  "vulnerability_record_identifiers",
  {
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    identifierId: uuid("identifier_id")
      .notNull()
      .references(() => identifiers.id, { onDelete: "cascade" }),
    relationship: text("relationship").notNull().default("alias"),
    ...timestamps,
  },
  (table) => ({
    pk: primaryKey({
      columns: [table.vulnerabilityRecordId, table.identifierId],
    }),
  }),
);

// Package distribution namespace. OSV affected[].package.ecosystem is the
// primary source for this in the MVP; examples: npm, Maven, PyPI, Ubuntu.
export const ecosystems = pgTable(
  "ecosystems",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    kind: text("kind").notNull(),
    versionScheme: text("version_scheme"),
    packageUrlType: text("package_url_type"),
    ...timestamps,
  },
  (table) => ({
    slugIdx: uniqueIndex("ecosystems_slug_idx").on(table.slug),
  }),
);

// Vendor/product-level affected software. CVE containers.cna.affected[] is the
// primary source for this in the MVP; examples: Google Chrome, Cisco IOS XE.
export const products = pgTable(
  "products",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    vendor: text("vendor"),
    ...timestamps,
  },
  (table) => ({
    slugIdx: uniqueIndex("products_slug_idx").on(table.slug),
    nameIdx: index("products_name_idx").on(table.name),
  }),
);

// Installable package in a package ecosystem. OSV affected[].package.name/purl
// is the primary source for this in the MVP.
export const packages = pgTable(
  "packages",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    ecosystemId: uuid("ecosystem_id")
      .notNull()
      .references(() => ecosystems.id, { onDelete: "restrict" }),
    name: text("name").notNull(),
    purl: text("purl"),
    ...timestamps,
  },
  (table) => ({
    identityIdx: uniqueIndex("packages_ecosystem_name_idx").on(
      table.ecosystemId,
      table.name,
    ),
    purlIdx: uniqueIndex("packages_purl_idx").on(table.purl),
    nameIdx: index("packages_name_idx").on(table.name),
  }),
);

// Enrichment link from installable packages back to human product/project names.
// This is not proof of affectedness; affectedPackages/affectedProducts hold
// source-backed affectedness.
export const packageProducts = pgTable(
  "package_products",
  {
    packageId: uuid("package_id")
      .notNull()
      .references(() => packages.id, { onDelete: "cascade" }),
    productId: uuid("product_id")
      .notNull()
      .references(() => products.id, { onDelete: "cascade" }),
    relationship: text("relationship").notNull().default("distributed_as"),
    confidence: text("confidence").notNull().default("medium"),
    source: text("source"),
    ...timestamps,
  },
  (table) => ({
    pk: primaryKey({
      columns: [table.packageId, table.productId],
    }),
    productIdx: index("package_products_product_idx").on(table.productId),
  }),
);

export const packageVersions = pgTable(
  "package_versions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    packageId: uuid("package_id")
      .notNull()
      .references(() => packages.id, { onDelete: "cascade" }),
    version: text("version").notNull(),
    normalizedVersion: text("normalized_version"),
    releasedAt: timestamp("released_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    identityIdx: uniqueIndex("package_versions_package_version_idx").on(
      table.packageId,
      table.version,
    ),
    packageIdx: index("package_versions_package_idx").on(table.packageId),
  }),
);

export const affectedPackages = pgTable(
  "affected_packages",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    packageId: uuid("package_id")
      .notNull()
      .references(() => packages.id, { onDelete: "restrict" }),
    relationship: text("relationship").notNull().default("affected"),
    ...timestamps,
  },
  (table) => ({
    identityIdx: uniqueIndex("affected_packages_record_package_idx").on(
      table.vulnerabilityRecordId,
      table.packageId,
    ),
    packageIdx: index("affected_packages_package_idx").on(table.packageId),
    recordIdx: index("affected_packages_record_idx").on(
      table.vulnerabilityRecordId,
    ),
  }),
);

// Affected/fixed version logic for a source-backed affected package or product.
// OSV contributes package ranges from affected[].ranges/events and versions[].
// CVE contributes product ranges from containers.cna.affected[].versions.
export const versionRanges = pgTable(
  "version_ranges",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    affectedPackageId: uuid("affected_package_id").references(
      () => affectedPackages.id,
      { onDelete: "cascade" },
    ),
    affectedProductId: uuid("affected_product_id").references(
      () => affectedProducts.id,
      { onDelete: "cascade" },
    ),
    rangeType: text("range_type"),
    introduced: text("introduced"),
    fixed: text("fixed"),
    lastAffected: text("last_affected"),
    limit: text("limit"),
    expression: text("expression"),
    repo: text("repo"),
    raw: jsonb("raw"),
    ...timestamps,
  },
  (table) => ({
    affectedPackageIdx: index("version_ranges_affected_package_idx").on(
      table.affectedPackageId,
    ),
    affectedProductIdx: index("version_ranges_affected_product_idx").on(
      table.affectedProductId,
    ),
    fixedIdx: index("version_ranges_fixed_idx").on(table.fixed),
    oneAffectedTargetChk: check(
      "version_ranges_one_affected_target_chk",
      sql`(${table.affectedPackageId} is not null and ${table.affectedProductId} is null) or (${table.affectedPackageId} is null and ${table.affectedProductId} is not null)`,
    ),
  }),
);

export const affectedProducts = pgTable(
  "affected_products",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    productId: uuid("product_id")
      .notNull()
      .references(() => products.id, { onDelete: "restrict" }),
    relationship: text("relationship").notNull().default("affected"),
    ...timestamps,
  },
  (table) => ({
    identityIdx: uniqueIndex("affected_products_record_product_idx").on(
      table.vulnerabilityRecordId,
      table.productId,
    ),
    productIdx: index("affected_products_product_idx").on(table.productId),
  }),
);

// CWE weakness classes asserted by source records. CVE problemTypes is the
// primary source in the MVP; GHSA/NVD may add more CWE facts later.
export const weaknesses = pgTable(
  "weaknesses",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    cweId: text("cwe_id").notNull(),
    name: text("name"),
    description: text("description"),
    ...timestamps,
  },
  (table) => ({
    cweIdIdx: uniqueIndex("weaknesses_cwe_id_idx").on(table.cweId),
  }),
);

export const vulnerabilityRecordWeaknesses = pgTable(
  "vulnerability_record_weaknesses",
  {
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    weaknessId: uuid("weakness_id")
      .notNull()
      .references(() => weaknesses.id, { onDelete: "cascade" }),
    relationship: text("relationship").notNull().default("asserts"),
    ...timestamps,
  },
  (table) => ({
    pk: primaryKey({
      columns: [table.vulnerabilityRecordId, table.weaknessId],
    }),
    weaknessIdx: index("vulnerability_record_weaknesses_weakness_idx").on(
      table.weaknessId,
    ),
  }),
);

// Severity facts asserted by a source record. CVE contributes metrics from
// containers.cna.metrics[] and containers.adp[].metrics[]; OSV contributes
// severity[]; direct GHSA ingestion may contribute GitHub severity/CVSS later.
export const severityMetrics = pgTable(
  "severity_metrics",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    sourceRecordId: uuid("source_record_id")
      .notNull()
      .references(() => sourceRecords.id, { onDelete: "cascade" }),
    provider: text("provider"),
    system: text("system").notNull(),
    score: numeric("score", { precision: 4, scale: 1 }),
    severity: text("severity"),
    vector: text("vector"),
    ...timestamps,
  },
  (table) => ({
    vulnerabilityRecordIdx: index("severity_metrics_record_idx").on(
      table.vulnerabilityRecordId,
    ),
    sourceRecordIdx: index("severity_metrics_source_record_idx").on(
      table.sourceRecordId,
    ),
    systemIdx: index("severity_metrics_system_idx").on(table.system),
  }),
);

// Mechanical parse of CVSS vectors stored in severityMetrics.vector. These are
// source-backed exploitability conditions, not our own exploit path inference.
export const cvssMetricDetails = pgTable(
  "cvss_metric_details",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    severityMetricId: uuid("severity_metric_id")
      .notNull()
      .references(() => severityMetrics.id, { onDelete: "cascade" }),
    cvssVersion: text("cvss_version").notNull(),
    attackVector: text("attack_vector"),
    attackComplexity: text("attack_complexity"),
    privilegesRequired: text("privileges_required"),
    userInteraction: text("user_interaction"),
    scope: text("scope"),
    confidentialityImpact: text("confidentiality_impact"),
    integrityImpact: text("integrity_impact"),
    availabilityImpact: text("availability_impact"),
    ...timestamps,
  },
  (table) => ({
    severityMetricIdx: uniqueIndex("cvss_metric_details_metric_idx").on(
      table.severityMetricId,
    ),
    attackVectorIdx: index("cvss_metric_details_attack_vector_idx").on(
      table.attackVector,
    ),
  }),
);

// CISA ADP Vulnrichment can appear inside CVE containers.adp[].metrics[] as
// other.type = "ssvc". This is source-backed prioritization context.
export const ssvcAssessments = pgTable(
  "ssvc_assessments",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    sourceRecordId: uuid("source_record_id")
      .notNull()
      .references(() => sourceRecords.id, { onDelete: "cascade" }),
    provider: text("provider"),
    exploitation: text("exploitation"),
    automatable: text("automatable"),
    technicalImpact: text("technical_impact"),
    role: text("role"),
    version: text("version"),
    assessedAt: timestamp("assessed_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    vulnerabilityRecordIdx: index("ssvc_assessments_record_idx").on(
      table.vulnerabilityRecordId,
    ),
    sourceRecordIdx: index("ssvc_assessments_source_record_idx").on(
      table.sourceRecordId,
    ),
    exploitationIdx: index("ssvc_assessments_exploitation_idx").on(
      table.exploitation,
    ),
  }),
);

// CISA Known Exploited Vulnerabilities entries. Presence in this table means
// CISA says the CVE is known exploited; fields come from the KEV catalog.
export const kevEntries = pgTable(
  "kev_entries",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityId: uuid("vulnerability_id").references(
      () => vulnerabilities.id,
      { onDelete: "set null" },
    ),
    sourceRecordId: uuid("source_record_id")
      .notNull()
      .references(() => sourceRecords.id, { onDelete: "cascade" }),
    cveIdentifierId: uuid("cve_identifier_id")
      .notNull()
      .references(() => identifiers.id, { onDelete: "restrict" }),
    knownExploited: boolean("known_exploited").notNull().default(true),
    vendorProject: text("vendor_project"),
    product: text("product"),
    vulnerabilityName: text("vulnerability_name"),
    shortDescription: text("short_description"),
    dateAdded: date("date_added"),
    dueDate: date("due_date"),
    requiredAction: text("required_action"),
    knownRansomwareCampaignUse: text("known_ransomware_campaign_use"),
    notes: text("notes"),
    ...timestamps,
  },
  (table) => ({
    sourceRecordIdx: uniqueIndex("kev_entries_source_record_idx").on(
      table.sourceRecordId,
    ),
    cveIdx: index("kev_entries_cve_idx").on(table.cveIdentifierId),
    vulnerabilityIdx: index("kev_entries_vulnerability_idx").on(
      table.vulnerabilityId,
    ),
  }),
);

// FIRST EPSS scores. EPSS is keyed by CVE and gives exploitation probability
// and percentile for a scoring date.
export const epssScores = pgTable(
  "epss_scores",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityId: uuid("vulnerability_id").references(
      () => vulnerabilities.id,
      { onDelete: "set null" },
    ),
    sourceRecordId: uuid("source_record_id")
      .notNull()
      .references(() => sourceRecords.id, { onDelete: "cascade" }),
    cveIdentifierId: uuid("cve_identifier_id")
      .notNull()
      .references(() => identifiers.id, { onDelete: "restrict" }),
    score: numeric("score", { precision: 7, scale: 6 }).notNull(),
    percentile: numeric("percentile", { precision: 7, scale: 6 }).notNull(),
    scoreDate: date("score_date").notNull(),
    ...timestamps,
  },
  (table) => ({
    identityIdx: uniqueIndex("epss_scores_cve_date_idx").on(
      table.cveIdentifierId,
      table.scoreDate,
    ),
    sourceRecordIdx: index("epss_scores_source_record_idx").on(
      table.sourceRecordId,
    ),
    vulnerabilityIdx: index("epss_scores_vulnerability_idx").on(
      table.vulnerabilityId,
    ),
  }),
);

export const externalReferences = pgTable(
  "external_references",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    url: text("url").notNull(),
    title: text("title"),
    kind: text("kind"),
    ...timestamps,
  },
  (table) => ({
    urlIdx: uniqueIndex("external_references_url_idx").on(table.url),
  }),
);

export const vulnerabilityRecordReferences = pgTable(
  "vulnerability_record_references",
  {
    vulnerabilityRecordId: uuid("vulnerability_record_id")
      .notNull()
      .references(() => vulnerabilityRecords.id, { onDelete: "cascade" }),
    referenceId: uuid("reference_id")
      .notNull()
      .references(() => externalReferences.id, { onDelete: "cascade" }),
    relationship: text("relationship").notNull().default("references"),
    ...timestamps,
  },
  (table) => ({
    pk: primaryKey({
      columns: [table.vulnerabilityRecordId, table.referenceId],
    }),
  }),
);
