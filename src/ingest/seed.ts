import { getDb } from "../db";
import {
  upsertEcosystem,
  upsertEcosystemAlias,
  upsertSource,
  type IngestDb,
  type SourceSeed,
} from "./repository";
import { KNOWN_ECOSYSTEMS } from "./standardize";

export const SOURCE_SEEDS: SourceSeed[] = [
  {
    slug: "cve-list-v5",
    name: "CVE List V5",
    kind: "vulnerability-records",
    url: "https://github.com/CVEProject/cvelistV5",
  },
  {
    slug: "osv",
    name: "Open Source Vulnerabilities",
    kind: "package-advisories",
    url: "https://osv.dev",
  },
  {
    slug: "cisa-kev",
    name: "CISA Known Exploited Vulnerabilities",
    kind: "known-exploitation",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  },
  {
    slug: "first-epss",
    name: "FIRST EPSS",
    kind: "exploit-probability",
    url: "https://www.first.org/epss/",
  },
];

export function sourceSeedForSlug(slug: string) {
  const seed = SOURCE_SEEDS.find((source) => source.slug === slug);
  if (!seed) {
    throw new Error(`Unknown ingestion source: ${slug}`);
  }

  return seed;
}

export async function seedReferenceData(db: IngestDb) {
  for (const source of SOURCE_SEEDS) {
    await upsertSource(db, source);
  }

  for (const ecosystemSeed of KNOWN_ECOSYSTEMS) {
    const ecosystem = await upsertEcosystem(db, ecosystemSeed);

    for (const [aliasKind, alias] of ecosystemSeed.aliases) {
      await upsertEcosystemAlias(db, {
        ecosystemId: ecosystem.id,
        alias,
        aliasKind,
        source: "seed",
      });
    }
  }
}

export async function seedReferenceDataFromEnv() {
  await seedReferenceData(getDb());
}
