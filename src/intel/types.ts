export type CareVerdict = "Act Now" | "Investigate" | "Monitor" | "Low Signal";

export type Confidence = "high" | "medium" | "low";

export type KnowledgeKind = "reported" | "extracted" | "inferred" | "curated";

export type AffectedSoftware = {
  package: string;
  ecosystem: string;
  affectedRange: string;
  fixedVersion: string;
  source: string;
};

export type SourceSignal = {
  label: string;
  value: string;
  source: string;
};

export type EvidenceReference = {
  title: string;
  source: string;
  url: string;
};

export type VulnerabilityDecision = {
  primaryId: string;
  aliases: string[];
  summary: string;
  verdict: CareVerdict;
  confidence: Confidence;
  verdictReasons: string[];
  affectedSoftware: AffectedSoftware[];
  weakness: string;
  exploitPrimitive: string;
  outcomes: string[];
  prerequisites: string[];
  signals: SourceSignal[];
  evidence: EvidenceReference[];
};

export type VerdictInput = {
  cisaKev: boolean;
  epssPercentile?: number;
  cvssScore?: number;
  publicExploit: boolean;
  networkExploitable: boolean;
  privilegesRequired: "none" | "low" | "high" | "unknown";
  userInteractionRequired: boolean;
  fixAvailable: boolean;
};

