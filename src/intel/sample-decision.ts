import { getWeaknessMapping } from "./cwe-map";
import { calculateVerdict } from "./verdict";
import type { VulnerabilityDecision } from "./types";

export function getSampleDecision(id: string): VulnerabilityDecision {
  const cwe = getWeaknessMapping("CWE-502");
  const verdict = calculateVerdict({
    cisaKev: true,
    epssPercentile: 0.99,
    cvssScore: 10,
    publicExploit: true,
    networkExploitable: true,
    privilegesRequired: "none",
    userInteractionRequired: false,
    fixAvailable: true,
  });

  return {
    primaryId: id.toUpperCase(),
    aliases: ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
    summary:
      "Sample decision page using Log4Shell-like signals. The next implementation slice will replace this object with normalized OSV, NVD, CISA KEV, EPSS, and CWE data.",
    verdict: verdict.verdict,
    confidence: verdict.confidence,
    verdictReasons: verdict.reasons,
    affectedSoftware: [
      {
        package: "org.apache.logging.log4j:log4j-core",
        ecosystem: "Maven",
        affectedRange: ">= 2.0-beta9 < 2.15.0",
        fixedVersion: "2.15.0+",
        source: "OSV / GHSA",
      },
    ],
    weakness: cwe ? `${cwe.cweId} ${cwe.name}` : "Unknown weakness",
    exploitPrimitive: cwe?.primitive ?? "unknown attacker capability",
    outcomes: cwe?.likelyOutcomes ?? ["unknown outcome"],
    prerequisites: [
      "vulnerable code is present",
      "attacker-controlled input reaches logging path",
      "runtime configuration permits exploit path",
    ],
    signals: [
      { label: "CISA KEV", value: "listed", source: "CISA" },
      { label: "EPSS", value: "99th percentile", source: "FIRST EPSS" },
      { label: "CVSS", value: "10.0 critical", source: "NVD" },
      { label: "Fix", value: "available", source: "OSV / vendor" },
    ],
    evidence: [
      {
        title: "OSV vulnerability record",
        source: "OSV",
        url: "https://osv.dev/vulnerability/CVE-2021-44228",
      },
      {
        title: "CISA Known Exploited Vulnerabilities catalog",
        source: "CISA",
        url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      },
      {
        title: "NVD vulnerability record",
        source: "NVD",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      },
    ],
  };
}

