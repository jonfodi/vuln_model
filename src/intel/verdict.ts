import type { CareVerdict, Confidence, VerdictInput } from "./types";

export type VerdictResult = {
  verdict: CareVerdict;
  confidence: Confidence;
  score: number;
  reasons: string[];
};

export function calculateVerdict(input: VerdictInput): VerdictResult {
  let score = 0;
  const reasons: string[] = [];

  if (input.cisaKev) {
    score += 40;
    reasons.push("listed in CISA KEV");
  }

  if ((input.epssPercentile ?? 0) >= 0.95) {
    score += 20;
    reasons.push("EPSS percentile is very high");
  } else if ((input.epssPercentile ?? 0) >= 0.8) {
    score += 10;
    reasons.push("EPSS percentile is elevated");
  }

  if ((input.cvssScore ?? 0) >= 9) {
    score += 15;
    reasons.push("CVSS is critical");
  } else if ((input.cvssScore ?? 0) >= 7) {
    score += 8;
    reasons.push("CVSS is high");
  }

  if (input.publicExploit) {
    score += 20;
    reasons.push("public exploit evidence exists");
  }

  if (input.networkExploitable) {
    score += 10;
    reasons.push("network exploitable");
  }

  if (input.privilegesRequired === "none") {
    score += 8;
    reasons.push("no privileges required");
  }

  if (!input.userInteractionRequired) {
    score += 5;
    reasons.push("no user interaction required");
  }

  if (input.fixAvailable) {
    score += 5;
    reasons.push("fix is available");
  }

  if (score >= 65) {
    return { verdict: "Act Now", confidence: "high", score, reasons };
  }

  if (score >= 35) {
    return { verdict: "Investigate", confidence: "medium", score, reasons };
  }

  if (score >= 15) {
    return { verdict: "Monitor", confidence: "medium", score, reasons };
  }

  return {
    verdict: "Low Signal",
    confidence: "low",
    score,
    reasons: reasons.length > 0 ? reasons : ["limited current exploit signal"],
  };
}

