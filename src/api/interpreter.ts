import { normalizeIdentifierValue, slugify } from "../ingest/standardize";
import type { SearchSpec } from "./types";

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,}\b/i;
const GHSA_PATTERN = /\bGHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\b/i;
const CWE_PATTERN = /\bCWE-\d+\b/i;
const VERSION_PATTERN = /\bv?\d+(?:\.\d+){1,5}[a-z0-9.+:~_-]*\b/i;

export function interpretSearchQuery(rawQuery: string): SearchSpec {
  const query = rawQuery.trim();
  const normalizedQuery = query.replace(/\s+/g, " ");
  const purl = parsePackageUrl(normalizedQuery);
  const identifier = extractIdentifier(normalizedQuery);
  const weakness = normalizedQuery.match(CWE_PATTERN)?.[0]?.toUpperCase();
  const severityHint = extractSeverityHint(normalizedQuery);
  const knownExploited = /\b(kev|known exploited|exploited in the wild|active exploitation)\b/i.test(
    normalizedQuery,
  );

  if (identifier) {
    return {
      rawQuery,
      normalizedQuery,
      intent: "specific_vulnerability",
      confidence: "high",
      interpretedAs: identifier,
      extracted: { identifier, knownExploited, severityHint },
    };
  }

  if (purl) {
    return {
      rawQuery,
      normalizedQuery,
      intent: purl.version ? "package_version_check" : "software_lookup",
      confidence: "high",
      interpretedAs: [
        purl.ecosystem,
        purl.packageName,
        purl.version ? `@${purl.version}` : null,
      ]
        .filter(Boolean)
        .join(" "),
      extracted: {
        ecosystem: purl.ecosystem,
        packageName: purl.packageName,
        version: purl.version,
        knownExploited,
        severityHint,
      },
    };
  }

  if (weakness) {
    return {
      rawQuery,
      normalizedQuery,
      intent: "weakness_lookup",
      confidence: "high",
      interpretedAs: weakness,
      extracted: { weakness, knownExploited, severityHint },
    };
  }

  const version = extractLooseVersion(normalizedQuery);
  const targetText = version
    ? normalizedQuery.replace(version, " ").replace(/\s+/g, " ").trim()
    : normalizedQuery;
  const cleanedTarget = cleanupTargetText(targetText);

  if (cleanedTarget && version) {
    return {
      rawQuery,
      normalizedQuery,
      intent: "package_version_check",
      confidence: "medium",
      interpretedAs: `${cleanedTarget} ${version}`,
      extracted: {
        packageName: cleanedTarget,
        productName: cleanedTarget,
        version,
        knownExploited,
        severityHint,
      },
    };
  }

  if (cleanedTarget) {
    return {
      rawQuery,
      normalizedQuery,
      intent: "software_lookup",
      confidence: "medium",
      interpretedAs: cleanedTarget,
      extracted: {
        packageName: cleanedTarget,
        productName: cleanedTarget,
        knownExploited,
        severityHint,
      },
    };
  }

  return {
    rawQuery,
    normalizedQuery,
    intent: "unknown",
    confidence: "low",
    interpretedAs: normalizedQuery,
    extracted: { knownExploited, severityHint },
  };
}

function extractIdentifier(query: string) {
  const cve = query.match(CVE_PATTERN)?.[0];
  if (cve) {
    return normalizeIdentifierValue(cve);
  }

  const ghsa = query.match(GHSA_PATTERN)?.[0];
  if (ghsa) {
    return normalizeIdentifierValue(ghsa);
  }

  return undefined;
}

function extractLooseVersion(query: string) {
  const version = query.match(VERSION_PATTERN)?.[0];
  return version?.replace(/^v/i, "");
}

function extractSeverityHint(query: string) {
  const match = query.match(/\b(critical|high|medium|low)\b/i)?.[1];
  return match?.toLowerCase() as
    | "critical"
    | "high"
    | "medium"
    | "low"
    | undefined;
}

function cleanupTargetText(value: string) {
  const cleaned = value
    .replace(/\b(vulnerability|vulnerabilities|cve|ghsa|package|product|software|security|bug|issue|issues|about|for|in|is|are|do|does|need|worry|bad|exploited|known|critical|high|medium|low)\b/gi, " ")
    .replace(/[?.,;:]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned || undefined;
}

function parsePackageUrl(query: string) {
  const match = query.match(/\bpkg:([a-zA-Z0-9.+_-]+)\/([^\s?#]+)(?:\?[^ \t]*)?/);
  if (!match) {
    const shorthand = query.match(
      /\b([a-zA-Z][a-zA-Z0-9.+_-]*):([^\s@]+(?:\/[^\s@]+|:[^\s@]+)?)(?:@([^\s]+))?\b/,
    );
    if (!shorthand || shorthand[1].toLowerCase() === "cve") {
      return undefined;
    }

    return {
      ecosystem: slugify(shorthand[1]),
      packageName: shorthand[2],
      version: shorthand[3],
    };
  }

  const ecosystem = slugify(match[1]);
  const rawPath = match[2];
  const lastSlash = rawPath.lastIndexOf("/");
  const rawName = lastSlash === -1 ? rawPath : rawPath.slice(lastSlash + 1);
  const namespace = lastSlash === -1 ? undefined : rawPath.slice(0, lastSlash);
  const atIndex = rawName.lastIndexOf("@");
  const name = atIndex > 0 ? rawName.slice(0, atIndex) : rawName;
  const version = atIndex > 0 ? rawName.slice(atIndex + 1) : undefined;

  return {
    ecosystem,
    packageName:
      ecosystem === "maven" && namespace
        ? `${decodeURIComponent(namespace)}:${decodeURIComponent(name)}`
        : [namespace, name]
            .filter((value): value is string => Boolean(value))
            .map((value) => decodeURIComponent(value))
            .join("/"),
    version: version ? decodeURIComponent(version) : undefined,
  };
}
