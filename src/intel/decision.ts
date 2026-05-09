import { fetchCisaKevEntry } from "@/ingest/cisa-kev";
import { fetchEpss } from "@/ingest/epss";
import { fetchNvdCve, type NvdCve, type NvdCvssMetric } from "@/ingest/nvd";
import {
  fetchOsvVulnerability,
  type OsvAffected,
  type OsvVulnerability,
} from "@/ingest/osv";
import { getWeaknessMapping } from "./cwe-map";
import type {
  AffectedSoftware,
  EvidenceReference,
  SourceSignal,
  VulnerabilityDecision,
} from "./types";
import { calculateVerdict } from "./verdict";

const cvePattern = /^CVE-\d{4}-\d{4,}$/i;

type OsvRange = NonNullable<OsvAffected["ranges"]>[number];

export async function getVulnerabilityDecision(
  rawId: string,
): Promise<VulnerabilityDecision> {
  const inputId = rawId.trim();
  const osvResult = await fetchOsvVulnerability(inputId);
  const osv = osvResult.ok ? osvResult.data : undefined;
  const aliases = unique([
    inputId,
    osv?.id,
    ...(osv?.aliases ?? []),
    ...(osv?.related ?? []),
  ]);
  const cveId = aliases.find((alias) => cvePattern.test(alias));

  const [nvdResult, cisaResult, epssResult] = cveId
    ? await Promise.all([
        fetchNvdCve(cveId),
        fetchCisaKevEntry(cveId),
        fetchEpss(cveId),
      ])
    : [undefined, undefined, undefined];

  const nvd =
    nvdResult?.ok === true ? nvdResult.data.vulnerabilities?.[0]?.cve : undefined;
  const cisa = cisaResult?.ok === true ? cisaResult.data : undefined;
  const epss = epssResult?.ok === true ? epssResult.data : undefined;
  const cvss = nvd ? pickCvssMetric(nvd) : undefined;
  const weaknessId = pickWeaknessId(nvd, cisa?.cwes);
  const weaknessMapping = weaknessId
    ? getWeaknessMapping(weaknessId)
    : undefined;
  const affectedSoftware = buildAffectedSoftware(osv, cisa);
  const publicExploit = hasPublicExploitEvidence(osv, nvd);
  const cvssData = cvss?.cvssData;
  const verdict = calculateVerdict({
    cisaKev: Boolean(cisa),
    epssPercentile: epss ? Number(epss.percentile) : undefined,
    cvssScore: cvssData?.baseScore,
    publicExploit,
    networkExploitable:
      cvssData?.attackVector === "NETWORK" ||
      Boolean(cvssData?.vectorString?.includes("/AV:N")),
    privilegesRequired: normalizePrivileges(cvssData?.privilegesRequired),
    userInteractionRequired: cvssData?.userInteraction
      ? cvssData.userInteraction !== "NONE"
      : true,
    fixAvailable: affectedSoftware.some(
      (item) => item.fixedVersion !== "not specified",
    ),
  });

  const genericOutcomes = inferOutcomesFromCvss(cvss);
  const outcomes = unique([
    ...(weaknessMapping?.likelyOutcomes ?? []),
    ...genericOutcomes,
  ]);

  return {
    primaryId: normalizePrimaryId(inputId, osv, cveId),
    aliases,
    summary: buildSummary(osv, nvd, cisa?.shortDescription, inputId),
    verdict: verdict.verdict,
    confidence: verdict.confidence,
    verdictReasons: verdict.reasons,
    affectedSoftware,
    weakness: weaknessMapping
      ? `${weaknessMapping.cweId} ${weaknessMapping.name}`
      : weaknessId ?? "Unknown weakness",
    exploitPrimitive:
      weaknessMapping?.primitive ??
      inferPrimitiveFromText([osv?.summary, osv?.details, nvdDescription(nvd)]),
    outcomes: outcomes.length > 0 ? outcomes : ["unknown outcome"],
    prerequisites: buildPrerequisites(cvss, weaknessMapping?.commonPrerequisites),
    signals: buildSignals({
      cisaListed: Boolean(cisa),
      epssPercentile: epss?.percentile,
      epssScore: epss?.epss,
      cvss,
      publicExploit,
      fixAvailable: affectedSoftware.some(
        (item) => item.fixedVersion !== "not specified",
      ),
    }),
    evidence: buildEvidence(osv, nvd, cisa ? cveId : undefined),
  };
}

function normalizePrimaryId(
  inputId: string,
  osv: OsvVulnerability | undefined,
  cveId: string | undefined,
) {
  if (cveId) {
    return cveId.toUpperCase();
  }

  return (osv?.id ?? inputId).toUpperCase();
}

function buildSummary(
  osv: OsvVulnerability | undefined,
  nvd: NvdCve | undefined,
  cisaDescription: string | undefined,
  inputId: string,
) {
  return (
    osv?.summary ??
    firstSentence(osv?.details) ??
    nvdDescription(nvd) ??
    cisaDescription ??
    `No source summary found yet for ${inputId}.`
  );
}

function buildAffectedSoftware(
  osv: OsvVulnerability | undefined,
  cisa:
    | {
        vendorProject?: string;
        product?: string;
      }
    | undefined,
): AffectedSoftware[] {
  const fromOsv =
    osv?.affected?.flatMap((affected) => affectedToSoftware(affected)) ?? [];

  if (fromOsv.length > 0) {
    return dedupeAffected(fromOsv);
  }

  if (cisa?.vendorProject || cisa?.product) {
    return [
      {
        package: [cisa.vendorProject, cisa.product].filter(Boolean).join(" / "),
        ecosystem: "Product",
        affectedRange: "not specified",
        fixedVersion: "not specified",
        source: "CISA KEV",
      },
    ];
  }

  return [];
}

function affectedToSoftware(affected: OsvAffected): AffectedSoftware[] {
  const packageName = affected.package?.name ?? affected.package?.purl;

  if (!packageName) {
    return [];
  }

  if (!affected.ranges || affected.ranges.length === 0) {
    return [
      {
        package: packageName,
        ecosystem: affected.package?.ecosystem ?? "Unknown",
        affectedRange:
          affected.versions && affected.versions.length > 0
            ? `${affected.versions.length} listed versions`
            : "not specified",
        fixedVersion: "not specified",
        source: "OSV",
      },
    ];
  }

  return affected.ranges.map((range) => {
    const fixed = range.events?.find((event) => event.fixed)?.fixed;

    return {
      package: packageName,
      ecosystem: affected.package?.ecosystem ?? "Unknown",
      affectedRange: formatRangeExpression(range.events),
      fixedVersion: fixed ?? "not specified",
      source: "OSV",
    };
  });
}

function formatRangeExpression(events: OsvRange["events"]) {
  if (!events || events.length === 0) {
    return "not specified";
  }

  const introduced = events.find((event) => event.introduced)?.introduced;
  const fixed = events.find((event) => event.fixed)?.fixed;
  const lastAffected = events.find((event) => event.last_affected)?.last_affected;
  const limit = events.find((event) => event.limit)?.limit;

  if (introduced && fixed) {
    return introduced === "0" ? `< ${fixed}` : `>= ${introduced} < ${fixed}`;
  }

  if (introduced && lastAffected) {
    return introduced === "0"
      ? `<= ${lastAffected}`
      : `>= ${introduced} <= ${lastAffected}`;
  }

  if (fixed) {
    return `< ${fixed}`;
  }

  if (introduced) {
    return introduced === "0" ? "all versions" : `>= ${introduced}`;
  }

  if (limit) {
    return `< ${limit}`;
  }

  return events
    .map((event) =>
      Object.entries(event)
        .map(([key, value]) => `${key}: ${value}`)
        .join(", "),
    )
    .filter(Boolean)
    .join("; ");
}

function buildPrerequisites(
  cvss: NvdCvssMetric | undefined,
  commonPrerequisites: string[] | undefined,
) {
  const prerequisites = [...(commonPrerequisites ?? [])];
  const cvssData = cvss?.cvssData;

  if (cvssData?.attackVector === "NETWORK") {
    prerequisites.push("network reachable attack path");
  }

  if (cvssData?.privilegesRequired === "NONE") {
    prerequisites.push("no prior privileges required");
  } else if (cvssData?.privilegesRequired) {
    prerequisites.push(
      `${cvssData.privilegesRequired.toLowerCase()} privileges required`,
    );
  }

  if (cvssData?.userInteraction === "NONE") {
    prerequisites.push("no user interaction required");
  } else if (cvssData?.userInteraction) {
    prerequisites.push("user interaction required");
  }

  return unique(
    prerequisites.length > 0
      ? prerequisites
      : ["source data does not state exploitation prerequisites"],
  );
}

function buildSignals(input: {
  cisaListed: boolean;
  epssScore: string | undefined;
  epssPercentile: string | undefined;
  cvss: NvdCvssMetric | undefined;
  publicExploit: boolean;
  fixAvailable: boolean;
}): SourceSignal[] {
  const signals: SourceSignal[] = [
    {
      label: "CISA KEV",
      value: input.cisaListed ? "listed" : "not listed",
      source: "CISA",
    },
  ];

  if (input.epssScore && input.epssPercentile) {
    signals.push({
      label: "EPSS",
      value: `${percent(input.epssScore)} score / ${percent(
        input.epssPercentile,
      )} percentile`,
      source: "FIRST EPSS",
    });
  }

  if (input.cvss?.cvssData?.baseScore) {
    signals.push({
      label: "CVSS",
      value: `${input.cvss.cvssData.baseScore.toFixed(1)} ${
        input.cvss.cvssData.baseSeverity?.toLowerCase() ?? ""
      }`.trim(),
      source: input.cvss.source ?? "NVD",
    });
  }

  signals.push({
    label: "Public exploit",
    value: input.publicExploit ? "evidence found" : "not found in sources",
    source: "OSV / NVD references",
  });

  signals.push({
    label: "Fix",
    value: input.fixAvailable ? "available" : "not identified",
    source: "OSV affected ranges",
  });

  return signals;
}

function buildEvidence(
  osv: OsvVulnerability | undefined,
  nvd: NvdCve | undefined,
  cveIdForCisa: string | undefined,
): EvidenceReference[] {
  const evidence: EvidenceReference[] = [];

  if (osv) {
    evidence.push({
      title: "OSV vulnerability record",
      source: "OSV",
      url: `https://osv.dev/vulnerability/${encodeURIComponent(osv.id)}`,
    });
  }

  if (nvd) {
    evidence.push({
      title: "NVD vulnerability record",
      source: "NVD",
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(nvd.id)}`,
    });
  }

  if (cveIdForCisa) {
    evidence.push({
      title: "CISA Known Exploited Vulnerabilities catalog",
      source: "CISA",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    });
  }

  const osvReferences =
    osv?.references?.map((reference) => ({
      title: reference.type
        ? `${reference.type.toLowerCase()} reference`
        : "OSV reference",
      source: "OSV",
      url: reference.url,
    })) ?? [];

  const nvdReferences =
    nvd?.references?.referenceData?.map((reference) => ({
      title: reference.tags?.[0] ?? reference.source ?? "NVD reference",
      source: reference.source ?? "NVD",
      url: reference.url,
    })) ?? [];

  return dedupeEvidence([...evidence, ...osvReferences, ...nvdReferences]).slice(
    0,
    12,
  );
}

function pickCvssMetric(nvd: NvdCve): NvdCvssMetric | undefined {
  const metricGroups = [
    nvd.metrics?.cvssMetricV40,
    nvd.metrics?.cvssMetricV31,
    nvd.metrics?.cvssMetricV30,
    nvd.metrics?.cvssMetricV2,
  ];

  return metricGroups
    .flatMap((group) => group ?? [])
    .filter((metric) => metric.cvssData?.baseScore !== undefined)
    .sort(
      (a, b) => (b.cvssData?.baseScore ?? 0) - (a.cvssData?.baseScore ?? 0),
    )[0];
}

function pickWeaknessId(nvd: NvdCve | undefined, cisaCwes: string[] | undefined) {
  const nvdWeakness = nvd?.weaknesses
    ?.flatMap((weakness) => weakness.description ?? [])
    .map((description) => description.value)
    .find((value) => value && /^CWE-\d+$/i.test(value));

  const cisaWeakness = cisaCwes?.find((value) => /^CWE-\d+$/i.test(value));

  return (nvdWeakness ?? cisaWeakness)?.toUpperCase();
}

function nvdDescription(nvd: NvdCve | undefined) {
  return nvd?.descriptions?.find((description) => description.lang === "en")
    ?.value;
}

function inferPrimitiveFromText(values: Array<string | undefined>) {
  const text = values.filter(Boolean).join(" ").toLowerCase();

  if (text.includes("remote code execution") || text.includes("rce")) {
    return "arbitrary code execution";
  }

  if (text.includes("sql injection")) {
    return "database query manipulation";
  }

  if (text.includes("cross-site scripting") || text.includes("xss")) {
    return "browser script execution";
  }

  if (text.includes("server-side request forgery") || text.includes("ssrf")) {
    return "server-side request forgery";
  }

  if (text.includes("path traversal")) {
    return "arbitrary file path access";
  }

  if (text.includes("denial of service")) {
    return "resource exhaustion";
  }

  return "unknown attacker capability";
}

function inferOutcomesFromCvss(cvss: NvdCvssMetric | undefined) {
  const cvssData = cvss?.cvssData;

  if (!cvssData) {
    return [];
  }

  const outcomes: string[] = [];

  if (cvssData.confidentialityImpact === "HIGH") {
    outcomes.push("data exposure");
  }

  if (cvssData.integrityImpact === "HIGH") {
    outcomes.push("data modification");
  }

  if (cvssData.availabilityImpact === "HIGH") {
    outcomes.push("denial of service");
  }

  return outcomes;
}

function hasPublicExploitEvidence(
  osv: OsvVulnerability | undefined,
  nvd: NvdCve | undefined,
) {
  const references = [
    ...(osv?.references?.map((reference) => reference.url) ?? []),
    ...(nvd?.references?.referenceData?.map((reference) => [
      reference.url,
      ...(reference.tags ?? []),
    ]) ?? []),
  ]
    .flat()
    .join(" ")
    .toLowerCase();

  return [
    "exploit-db",
    "metasploit",
    "packetstormsecurity",
    "packetstorm",
    "0day",
    "proof of concept",
    "poc",
    "exploit",
  ].some((marker) => references.includes(marker));
}

function normalizePrivileges(value: string | undefined) {
  if (value === "NONE") {
    return "none";
  }

  if (value === "LOW") {
    return "low";
  }

  if (value === "HIGH") {
    return "high";
  }

  return "unknown";
}

function firstSentence(value: string | undefined) {
  const sentence = value?.split(/(?<=\.)\s+/)[0]?.trim();

  return sentence || undefined;
}

function unique(values: Array<string | undefined>) {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value))));
}

function dedupeAffected(items: AffectedSoftware[]) {
  const seen = new Set<string>();

  return items.filter((item) => {
    const key = [
      item.package,
      item.ecosystem,
      item.affectedRange,
      item.fixedVersion,
    ].join("|");

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

function dedupeEvidence(items: EvidenceReference[]) {
  const seen = new Set<string>();

  return items.filter((item) => {
    if (seen.has(item.url)) {
      return false;
    }

    seen.add(item.url);
    return true;
  });
}

function percent(value: string) {
  const parsed = Number(value);

  if (Number.isNaN(parsed)) {
    return value;
  }

  return `${(parsed * 100).toFixed(1)}%`;
}
