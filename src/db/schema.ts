import {
  index,
  jsonb,
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

// same vulnerability can be referenced by multiple sources 
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

// join table 
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

export const versionRanges = pgTable(
  "version_ranges",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    affectedPackageId: uuid("affected_package_id")
      .notNull()
      .references(() => affectedPackages.id, { onDelete: "cascade" }),
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
    fixedIdx: index("version_ranges_fixed_idx").on(table.fixed),
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
