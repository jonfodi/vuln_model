export const initialSources = [
  {
    name: "OSV",
    type: "vulnerability_database",
    url: "https://osv.dev",
    trustTier: "foundation",
  },
  {
    name: "NVD",
    type: "vulnerability_database",
    url: "https://nvd.nist.gov",
    trustTier: "foundation",
  },
  {
    name: "CISA KEV",
    type: "known_exploitation_catalog",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    trustTier: "high",
  },
  {
    name: "FIRST EPSS",
    type: "exploit_prediction",
    url: "https://www.first.org/epss",
    trustTier: "high",
  },
] as const;

