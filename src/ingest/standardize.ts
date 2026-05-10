export type JsonObject = Record<string, unknown>;

export const KNOWN_ECOSYSTEMS = [
  {
    slug: "npm",
    name: "npm",
    kind: "package-registry",
    versionScheme: "semver",
    packageUrlType: "npm",
    aliases: [
      ["purl_type", "npm"],
      ["collection_url", "https://registry.npmjs.org"],
      ["collection_url", "https://www.npmjs.com"],
    ],
  },
  {
    slug: "pypi",
    name: "PyPI",
    kind: "package-registry",
    versionScheme: "python",
    packageUrlType: "pypi",
    aliases: [
      ["purl_type", "pypi"],
      ["collection_url", "https://pypi.org"],
      ["collection_url", "https://pypi.python.org"],
    ],
  },
  {
    slug: "maven",
    name: "Maven",
    kind: "package-registry",
    versionScheme: "maven",
    packageUrlType: "maven",
    aliases: [
      ["purl_type", "maven"],
      ["collection_url", "https://repo.maven.apache.org/maven2"],
      ["collection_url", "https://repo1.maven.org/maven2"],
    ],
  },
  {
    slug: "go",
    name: "Go",
    kind: "package-registry",
    versionScheme: "semver",
    packageUrlType: "golang",
    aliases: [
      ["purl_type", "golang"],
      ["collection_url", "https://pkg.go.dev"],
      ["collection_url", "https://go.dev"],
    ],
  },
  {
    slug: "cargo",
    name: "Cargo",
    kind: "package-registry",
    versionScheme: "semver",
    packageUrlType: "cargo",
    aliases: [["purl_type", "cargo"]],
  },
  {
    slug: "nuget",
    name: "NuGet",
    kind: "package-registry",
    versionScheme: "nuget",
    packageUrlType: "nuget",
    aliases: [["purl_type", "nuget"]],
  },
  {
    slug: "github",
    name: "GitHub",
    kind: "source-repository",
    versionScheme: "git",
    packageUrlType: "github",
    aliases: [
      ["purl_type", "github"],
      ["collection_url", "https://github.com"],
    ],
  },
  {
    slug: "generic",
    name: "Generic",
    kind: "generic-package",
    versionScheme: "custom",
    packageUrlType: "generic",
    aliases: [["purl_type", "generic"]],
  },
  {
    slug: "wordpress-plugin",
    name: "WordPress plugin",
    kind: "package-registry",
    versionScheme: "custom",
    packageUrlType: "wordpress-plugin",
    aliases: [
      ["purl_type", "wordpress-plugin"],
      ["collection_url", "https://wordpress.org/plugins"],
    ],
  },
  {
    slug: "wordpress-theme",
    name: "WordPress theme",
    kind: "package-registry",
    versionScheme: "custom",
    packageUrlType: "wordpress-theme",
    aliases: [
      ["purl_type", "wordpress-theme"],
      ["collection_url", "https://wordpress.org/themes"],
    ],
  },
  {
    slug: "redhat",
    name: "Red Hat package",
    kind: "distro-package",
    versionScheme: "rpm",
    packageUrlType: "rpm",
    aliases: [
      ["collection_url", "https://access.redhat.com/downloads/content/package-browser"],
      ["collection_url", "https://access.redhat.com/jbossnetwork/restricted/listSoftware.html"],
    ],
  },
  {
    slug: "redhat-container",
    name: "Red Hat container",
    kind: "container-image",
    versionScheme: "rpm",
    packageUrlType: "oci",
    aliases: [
      ["collection_url", "https://catalog.redhat.com/software/containers"],
    ],
  },
  {
    slug: "ubuntu",
    name: "Ubuntu",
    kind: "distro-package",
    versionScheme: "dpkg",
    packageUrlType: "deb",
    aliases: [["osv_ecosystem", "Ubuntu"]],
  },
] as const;

const COLLECTION_URL_ALIASES = new Map<string, string>();
const PURL_TYPE_ALIASES = new Map<string, string>();

for (const ecosystem of KNOWN_ECOSYSTEMS) {
  for (const [aliasKind, alias] of ecosystem.aliases) {
    if (aliasKind === "collection_url") {
      COLLECTION_URL_ALIASES.set(normalizeUrlAlias(alias), ecosystem.slug);
    }

    if (aliasKind === "purl_type") {
      PURL_TYPE_ALIASES.set(alias.toLowerCase(), ecosystem.slug);
    }
  }
}

export function asObject(value: unknown): JsonObject | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as JsonObject;
  }

  return undefined;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

export function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

export function toTimestamp(value: unknown): Date | null {
  const text = asString(value);
  if (!text) {
    return null;
  }

  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function toDateString(value: unknown): string | null {
  const text = asString(value);
  if (!text) {
    return null;
  }

  const match = text.match(/^\d{4}-\d{2}-\d{2}/);
  return match?.[0] ?? null;
}

export function normalizeIdentifierValue(value: string): string {
  return value.trim().toUpperCase();
}

export function inferIdentifierKind(value: string): string {
  const normalized = normalizeIdentifierValue(value);

  if (/^CVE-\d{4}-\d+/.test(normalized)) {
    return "cve";
  }

  if (/^GHSA-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$/.test(normalized)) {
    return "ghsa";
  }

  const prefix = normalized.split("-")[0];
  return prefix ? prefix.toLowerCase() : "unknown";
}

export function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return slug || "unknown";
}

export function buildProductSlug(vendor: string | undefined, product: string) {
  return slugify([vendor, product].filter(Boolean).join(" "));
}

export function normalizeUrlAlias(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    parsed.search = "";
    parsed.pathname = parsed.pathname.replace(/\/+$/g, "");
    return parsed.toString().replace(/\/+$/g, "");
  } catch {
    return url.trim().replace(/\/+$/g, "");
  }
}

export type ParsedPurl = {
  type: string;
  name: string;
  namespace: string | null;
};

export function parsePurl(value: string): ParsedPurl | undefined {
  if (!value.startsWith("pkg:")) {
    return undefined;
  }

  const withoutPrefix = value.slice(4);
  const [withoutQuery] = withoutPrefix.split("?");
  if (!withoutQuery) {
    return undefined;
  }

  const slashIndex = withoutQuery.indexOf("/");
  if (slashIndex === -1) {
    return undefined;
  }

  const type = decodeURIComponent(withoutQuery.slice(0, slashIndex));
  const path = withoutQuery.slice(slashIndex + 1);
  const parts = path.split("/").filter(Boolean).map(decodeURIComponent);
  const name = parts.pop();

  if (!type || !name) {
    return undefined;
  }

  return {
    type,
    name,
    namespace: parts.length > 0 ? parts.join("/") : null,
  };
}

export function packageNameFromPurl(value: string): string | undefined {
  const parsed = parsePurl(value);
  if (!parsed) {
    return undefined;
  }

  if (parsed.type.toLowerCase() === "maven" && parsed.namespace) {
    return `${parsed.namespace}:${parsed.name}`;
  }

  return parsed.namespace ? `${parsed.namespace}/${parsed.name}` : parsed.name;
}

export function normalizePackageName(
  name: string | undefined,
  purl: string | undefined,
) {
  const purlName = purl ? packageNameFromPurl(purl) : undefined;
  const purlType = purl ? parsePurl(purl)?.type.toLowerCase() : undefined;

  if (purlType === "maven" && purlName) {
    return purlName;
  }

  return name ?? purlName;
}

export function ecosystemFromPurl(value: string): string | undefined {
  const parsed = parsePurl(value);
  if (!parsed) {
    return undefined;
  }

  return PURL_TYPE_ALIASES.get(parsed.type.toLowerCase()) ?? parsed.type;
}

export function ecosystemFromCollectionUrl(
  value: string,
): string | undefined {
  const normalized = normalizeUrlAlias(value);
  const direct = COLLECTION_URL_ALIASES.get(normalized);
  if (direct) {
    return direct;
  }

  try {
    const parsed = new URL(normalized);
    return `collection-${slugify(parsed.hostname)}`;
  } catch {
    return undefined;
  }
}

export function ecosystemFromOsv(value: string): {
  slug: string;
  scope: string | null;
} {
  const [base, ...scopeParts] = value.split(":");
  const slug = slugify(base);
  return {
    slug,
    scope: scopeParts.length > 0 ? scopeParts.join(":") : null,
  };
}

export function firstEnglishValue(
  values: unknown,
  valueKey = "value",
): string | undefined {
  const entries = asArray(values)
    .map(asObject)
    .filter((entry): entry is JsonObject => Boolean(entry));
  const english =
    entries.find((entry) => entry.lang === "en") ?? entries.at(0);

  return english ? asString(english[valueKey]) : undefined;
}

export function referenceKindFromTags(tags: unknown): string | null {
  const first = asArray(tags).map(asString).find(Boolean);
  return first ?? null;
}

export function cvssSystemFromKey(key: string): string {
  if (key === "cvssV4_0") {
    return "cvss_v4_0";
  }

  if (key === "cvssV3_1") {
    return "cvss_v3_1";
  }

  if (key === "cvssV3_0") {
    return "cvss_v3_0";
  }

  if (key === "cvssV2_0") {
    return "cvss_v2_0";
  }

  return key;
}

export function versionRangeExpression(version: JsonObject): string {
  const status = asString(version.status) ?? "unknown";
  const start = asString(version.version);
  const lessThan = asString(version.lessThan);
  const lessThanOrEqual = asString(version.lessThanOrEqual);

  if (start && lessThan) {
    return `${status}: >= ${start} < ${lessThan}`;
  }

  if (start && lessThanOrEqual) {
    return `${status}: >= ${start} <= ${lessThanOrEqual}`;
  }

  if (start) {
    return `${status}: ${start}`;
  }

  return status;
}
