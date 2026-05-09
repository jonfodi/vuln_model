import {
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

export const sources = pgTable("sources", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: text("name").notNull(),
  type: text("type").notNull(),
  url: text("url"),
  trustTier: text("trust_tier").notNull().default("standard"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export const vulnerabilities = pgTable(
  "vulnerabilities",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    primaryId: text("primary_id").notNull(),
    title: text("title"),
    summary: text("summary"),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    modifiedAt: timestamp("modified_at", { withTimezone: true }),
    withdrawnAt: timestamp("withdrawn_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    primaryIdIdx: uniqueIndex("vulnerabilities_primary_id_idx").on(
      table.primaryId,
    ),
  }),
);

export const vulnerabilityAliases = pgTable(
  "vulnerability_aliases",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityId: uuid("vulnerability_id")
      .notNull()
      .references(() => vulnerabilities.id),
    alias: text("alias").notNull(),
  },
  (table) => ({
    aliasIdx: uniqueIndex("vulnerability_aliases_alias_idx").on(table.alias),
  }),
);

export const advisories = pgTable(
  "advisories",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    sourceId: uuid("source_id")
      .notNull()
      .references(() => sources.id),
    sourceRecordId: text("source_record_id").notNull(),
    vulnerabilityId: uuid("vulnerability_id").references(
      () => vulnerabilities.id,
    ),
    url: text("url"),
    severityText: text("severity_text"),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    modifiedAt: timestamp("modified_at", { withTimezone: true }),
    raw: jsonb("raw").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    sourceRecordIdx: uniqueIndex("advisories_source_record_idx").on(
      table.sourceId,
      table.sourceRecordId,
    ),
  }),
);

export const packages = pgTable(
  "packages",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    ecosystem: text("ecosystem").notNull(),
    name: text("name").notNull(),
    purl: text("purl"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    packageIdentityIdx: uniqueIndex("packages_identity_idx").on(
      table.ecosystem,
      table.name,
    ),
  }),
);

export const packageVersions = pgTable(
  "package_versions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    packageId: uuid("package_id")
      .notNull()
      .references(() => packages.id),
    version: text("version").notNull(),
    normalizedVersion: text("normalized_version"),
    releasedAt: timestamp("released_at", { withTimezone: true }),
  },
  (table) => ({
    packageVersionIdx: uniqueIndex("package_versions_identity_idx").on(
      table.packageId,
      table.version,
    ),
  }),
);

export const affectedRanges = pgTable(
  "affected_ranges",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityId: uuid("vulnerability_id")
      .notNull()
      .references(() => vulnerabilities.id),
    packageId: uuid("package_id").references(() => packages.id),
    introduced: text("introduced"),
    fixed: text("fixed"),
    lastAffected: text("last_affected"),
    rangeType: text("range_type"),
    expression: text("expression").notNull(),
    source: text("source").notNull(),
    confidence: text("confidence").notNull().default("medium"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    vulnerabilityIdx: index("affected_ranges_vulnerability_idx").on(
      table.vulnerabilityId,
    ),
    packageIdx: index("affected_ranges_package_idx").on(table.packageId),
  }),
);

export const claims = pgTable(
  "claims",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityId: uuid("vulnerability_id").references(
      () => vulnerabilities.id,
    ),
    claimType: text("claim_type").notNull(),
    knowledgeKind: text("knowledge_kind").notNull(),
    status: text("status").notNull().default("active"),
    confidence: text("confidence").notNull().default("medium"),
    statement: text("statement").notNull(),
    sourceId: uuid("source_id").references(() => sources.id),
    advisoryId: uuid("advisory_id").references(() => advisories.id),
    payload: jsonb("payload").notNull().default({}),
    collectedAt: timestamp("collected_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    vulnerabilityClaimIdx: index("claims_vulnerability_claim_idx").on(
      table.vulnerabilityId,
      table.claimType,
    ),
  }),
);

export const evidence = pgTable(
  "evidence",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    claimId: uuid("claim_id").references(() => claims.id),
    advisoryId: uuid("advisory_id").references(() => advisories.id),
    sourceId: uuid("source_id").references(() => sources.id),
    title: text("title").notNull(),
    url: text("url"),
    rawLocation: text("raw_location"),
    statement: text("statement"),
    confidence: text("confidence").notNull().default("medium"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    claimIdx: index("evidence_claim_idx").on(table.claimId),
  }),
);

export const exploitSignals = pgTable(
  "exploit_signals",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    vulnerabilityId: uuid("vulnerability_id")
      .notNull()
      .references(() => vulnerabilities.id),
    sourceId: uuid("source_id").references(() => sources.id),
    signalType: text("signal_type").notNull(),
    score: text("score"),
    percentile: text("percentile"),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
    payload: jsonb("payload").notNull().default({}),
  },
  (table) => ({
    signalIdx: index("exploit_signals_vulnerability_signal_idx").on(
      table.vulnerabilityId,
      table.signalType,
    ),
  }),
);

