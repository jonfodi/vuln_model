import type { JsonObject } from "./standardize";

export type SourceAdapterItem =
  | {
      label: string;
      raw: unknown;
      error?: never;
    }
  | {
      label: string;
      raw?: never;
      error: unknown;
    };

export type SourceAdapter<Input = unknown> = {
  sourceSlug: string;
  read(input: Input): AsyncIterable<SourceAdapterItem>;
  normalize(raw: unknown): NormalizedIngestItem;
};

export type IngestOptions = {
  limit?: number;
  progressEvery?: number;
};

export type IngestResult = {
  scanned: number;
  ingested: number;
  failed: Array<{ item: string; error: string }>;
};

export type NormalizedIngestItem =
  | NormalizedAdvisoryRecord
  | NormalizedVulnerabilitySignal;

export type NormalizedSourceRecord = {
  sourceSlug: string;
  externalId: string;
  url?: string | null;
  schemaVersion?: string | null;
  sourcePublishedAt?: Date | null;
  sourceModifiedAt?: Date | null;
  raw: unknown;
};

export type NormalizedCanonicalVulnerability = {
  primaryIdentifier: string;
  title?: string | null;
  summary?: string | null;
  status?: string | null;
  preserveExistingText?: boolean;
};

export type NormalizedIdentifier = {
  value: string;
  relationship?: string;
};

export type NormalizedAdvisoryRecord = {
  kind: "advisory_record";
  sourceRecord: NormalizedSourceRecord;
  canonical: NormalizedCanonicalVulnerability;
  record: {
    recordId: string;
    summary?: string | null;
    details?: string | null;
    publishedAt?: Date | null;
    modifiedAt?: Date | null;
    withdrawnAt?: Date | null;
    status?: string | null;
  };
  identifiers: NormalizedIdentifier[];
  relationships?: NormalizedRecordRelationship[];
  affectedProducts?: NormalizedAffectedProduct[];
  affectedPackages?: NormalizedAffectedPackage[];
  weaknesses?: NormalizedWeakness[];
  severityMetrics?: NormalizedSeverityMetric[];
  ssvcAssessments?: NormalizedSsvcAssessment[];
  references?: NormalizedReference[];
  signals?: NormalizedSignal[];
};

export type NormalizedRecordRelationship = {
  identifier: string;
  relationship: string;
  raw?: unknown;
};

export type NormalizedAffectedSoftwareIdentifier = {
  kind: string;
  value: string;
  sourceField?: string | null;
  raw?: unknown;
};

export type NormalizedVersionRange = {
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
};

export type NormalizedAffectedProduct = {
  sourceIndex: number;
  name: string;
  vendor?: string | null;
  relationship?: string | null;
  defaultStatus?: string | null;
  platforms?: unknown;
  modules?: unknown;
  programFiles?: unknown;
  programRoutines?: unknown;
  repo?: string | null;
  raw?: unknown;
  identifiers?: NormalizedAffectedSoftwareIdentifier[];
  versionRanges?: NormalizedVersionRange[];
};

export type NormalizedEcosystem = {
  slug: string;
  name?: string | null;
  kind?: string | null;
  versionScheme?: string | null;
  packageUrlType?: string | null;
  aliases?: Array<{
    alias: string;
    aliasKind: string;
    scope?: string | null;
    source?: string | null;
    raw?: unknown;
  }>;
};

export type NormalizedAffectedPackage = {
  sourceIndex: number;
  ecosystem: NormalizedEcosystem;
  package: {
    name: string;
    purl?: string | null;
  };
  relationship?: string | null;
  defaultStatus?: string | null;
  platforms?: unknown;
  modules?: unknown;
  repo?: string | null;
  raw?: unknown;
  identifiers?: NormalizedAffectedSoftwareIdentifier[];
  versionRanges?: NormalizedVersionRange[];
  productLink?: {
    name: string;
    vendor?: string | null;
    relationship?: string;
    confidence?: string;
    source?: string | null;
  };
};

export type NormalizedWeakness = {
  cweId: string;
  name?: string | null;
  description?: string | null;
  relationship?: string;
};

export type NormalizedCvssMetricDetails = {
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
};

export type NormalizedSeverityMetric = {
  provider?: string | null;
  system: string;
  affectedProductSourceIndex?: number | null;
  affectedPackageSourceIndex?: number | null;
  score?: string | null;
  severity?: string | null;
  vector?: string | null;
  raw?: unknown;
  cvss?: NormalizedCvssMetricDetails | null;
};

export type NormalizedSsvcAssessment = {
  provider?: string | null;
  exploitation?: string | null;
  automatable?: string | null;
  technicalImpact?: string | null;
  role?: string | null;
  version?: string | null;
  assessedAt?: Date | null;
};

export type NormalizedReference = {
  url: string;
  title?: string | null;
  kind?: string | null;
  relationship?: string;
  sourceName?: string | null;
  tags?: unknown;
  raw?: unknown;
};

export type NormalizedKevSignal = {
  kind: "kev";
  cveIdentifier: string;
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
};

export type NormalizedEpssSignal = {
  kind: "epss";
  cveIdentifier: string;
  score: string;
  percentile: string;
  scoreDate: string;
};

export type NormalizedSignal = NormalizedKevSignal | NormalizedEpssSignal;

export type NormalizedVulnerabilitySignal = {
  kind: "vulnerability_signal";
  sourceRecord: NormalizedSourceRecord;
  canonical: NormalizedCanonicalVulnerability;
  identifiers: NormalizedIdentifier[];
  signal: NormalizedSignal;
};

export type JsonObjectInput = JsonObject;
