export type SearchRequest = {
  query: string;
  limit?: number;
};

export type SearchIntent =
  | "specific_vulnerability"
  | "software_lookup"
  | "package_version_check"
  | "product_lookup"
  | "weakness_lookup"
  | "unknown";

export type SearchConfidence = "high" | "medium" | "low";

export type SearchResponse = {
  query: string;
  interpretation: SearchInterpretation;
  selectedTarget?: TargetCandidate;
  alternateTargets: TargetCandidate[];
  sections: SearchResultSection[];
  caveats: string[];
  execution: {
    strategy: "identifier" | "target_resolution" | "text_search" | "hybrid";
    ranker: "stub";
    interpreter: "deterministic";
  };
};

export type SearchInterpretation = {
  intent: SearchIntent;
  confidence: SearchConfidence;
  interpretedAs: string;
  extracted: {
    identifier?: string;
    packageName?: string;
    productName?: string;
    vendor?: string;
    ecosystem?: string;
    version?: string;
    weakness?: string;
    knownExploited?: boolean;
    severityHint?: "critical" | "high" | "medium" | "low";
  };
};

export type SearchSpec = SearchInterpretation & {
  rawQuery: string;
  normalizedQuery: string;
};

export type TargetCandidate = {
  type: "vulnerability" | "package" | "product" | "ecosystem" | "weakness";
  id: string;
  label: string;
  subtitle?: string;
  matchedBy: "identifier" | "name" | "alias" | "purl" | "cpe" | "text";
  confidence: SearchConfidence;
};

export type SearchResultSection = {
  key:
    | "exact_matches"
    | "vulnerabilities_for_target"
    | "known_exploited"
    | "version_relevant"
    | "related_matches"
    | "source_text_matches";
  title: string;
  reason: string;
  results: VulnerabilityResult[];
};

export type VulnerabilityResult = {
  id: string;
  primaryIdentifier: string | null;
  aliases: string[];
  title: string | null;
  summary: string | null;
  url: string;
  matchedOn: {
    type: "identifier" | "package" | "product" | "weakness" | "reference" | "text";
    label: string;
  };
  severity: {
    maxCvssScore?: number;
    maxCvssSeverity?: string;
  };
  exploitSignals: {
    knownExploited: boolean;
    epssScore?: number;
    epssPercentile?: number;
    ssvcExploitation?: string;
    ssvcAutomatable?: string;
    ssvcTechnicalImpact?: string;
  };
  affectedSoftware: {
    products: Array<{ id: string; vendor?: string; name: string }>;
    packages: Array<{ id: string; ecosystem: string; name: string }>;
    fixedVersions: string[];
    versionStatus?: "affected" | "fixed" | "unknown" | "not_evaluated";
  };
  evidence: {
    sources: string[];
    sourceRecordCount: number;
    referenceCount: number;
  };
  updatedAt?: string;
};

