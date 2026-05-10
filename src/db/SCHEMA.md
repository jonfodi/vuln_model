# Schema Ontology

This schema is built around one product idea:

```text
What vulnerability is this, what software does it affect, what versions are affected or fixed, how exploitable is it, and which source records support those facts?
```

The database intentionally separates source-backed facts from application/enrichment tables. Ingestion should preserve that distinction.

## Source-Backed Ontology

These tables represent facts we expect to extract from OSV, CVE List, CISA KEV, FIRST EPSS, and later direct GHSA or vendor feeds.

| Table | Meaning | Primary source facts |
| --- | --- | --- |
| `sources` | A feed/provider we ingest from. | OSV, CVE List, CISA KEV, FIRST EPSS, GitHub Advisory Database later. |
| `source_records` | One raw external record from a source. | OSV vulnerability JSON, CVE 5.x record, KEV entry, EPSS row/batch item. |
| `vulnerability_records` | Our normalized record-level view of one source record. | OSV `id`, CVE `cveMetadata.cveId`, advisory summary/details/timestamps/status. |
| `identifiers` | External IDs used to find/group vulnerabilities. | `CVE-*`, `GHSA-*`, OSV IDs, distro advisory IDs. |
| `vulnerability_record_identifiers` | IDs present on a specific source record. | OSV `id`, `aliases`, `upstream`; CVE `cveMetadata.cveId`. |
| `vulnerability_identifiers` | IDs attached to our canonical vulnerability after clustering. | Derived from record identifiers after reconciliation. |
| `products` | Vendor/product-level affected software. | CVE `containers.cna.affected[].vendor/product`. |
| `packages` | Installable package in an ecosystem. | OSV `affected[].package.name` and `purl`. |
| `ecosystems` | Package namespace/distribution context. | OSV `affected[].package.ecosystem`; examples: npm, Maven, PyPI, Ubuntu. |
| `affected_products` | Source record says this product is affected. | CVE `containers.cna.affected[]`. |
| `affected_packages` | Source record says this package is affected. | OSV `affected[]`. |
| `version_ranges` | Affected/fixed version logic for an affected product or package. | OSV `affected[].ranges/events`, OSV `versions[]`, CVE `affected[].versions`. |
| `weaknesses` | CWE weakness classes. | CVE `problemTypes[].descriptions[].cweId` or CWE-like descriptions. |
| `vulnerability_record_weaknesses` | Source record asserts a CWE for the vuln. | CVE problem types, later GHSA/NVD CWE facts. |
| `severity_metrics` | CVSS/vendor/GitHub/OSV severity facts. | CVE `metrics[]`, CVE ADP metrics, OSV `severity[]`, GHSA severity later. |
| `cvss_metric_details` | Parsed CVSS exploitability and impact fields. | Mechanical parse of `severity_metrics.vector`. |
| `ssvc_assessments` | CISA SSVC prioritization context. | CVE `containers.adp[].metrics[].other.type = "ssvc"`. |
| `kev_entries` | CISA says a CVE is known exploited. | CISA KEV catalog fields. |
| `epss_scores` | Exploitation probability score by CVE/date. | FIRST EPSS `cve`, `epss`, `percentile`, `date`. |
| `external_references` | External URLs used as evidence. | OSV references, CVE references, advisory links, release notes, issues. |
| `vulnerability_record_references` | Source record references a URL. | Record-level evidence links. |

## Canonical/Derived Tables

`vulnerabilities` is canonical, but not a direct source document. It is our grouped view of one underlying vulnerability after we reconcile multiple source records through identifiers.

Example:

```text
Vulnerability
  identifiers:
    CVE-2021-44228
    GHSA-jfh8-c2jp-5v3q

  records:
    OSV / GHSA-jfh8-c2jp-5v3q
    CVE List / CVE-2021-44228

  affected software:
    packages from OSV
    products from CVE

  context:
    weaknesses, severity, CVSS conditions, KEV, EPSS, references
```

The canonical vulnerability exists to give users one page and one search result for many source records. It should not erase source provenance.

## Application / Enrichment Tables

These tables are useful for the product, search, navigation, or later enrichment, but they are not core vulnerability source facts in the same way as `affected_packages`, `affected_products`, `kev_entries`, or `epss_scores`.

| Table | Why it exists | Important rule |
| --- | --- | --- |
| `package_products` | Connects a package back to a human product/project for search and navigation. | Not proof of affectedness. Do not infer all related packages are vulnerable. |
| `package_versions` | Can support package version lookup, comparison, and future package catalog features. | Not currently guaranteed by OSV/CVE/KEV/EPSS ingestion. Treat as catalog/enrichment unless populated from a version source. |

Example:

```text
Product: Apache Log4j
  distributed as:
    Maven package org.apache.logging.log4j:log4j-core
    Maven package org.apache.logging.log4j:log4j-api
    Ubuntu package liblog4j2-java
```

That mapping helps users search for "Log4j" and discover related packages. It does not mean every package is affected by every Log4j vulnerability. Affectedness must come from source-backed rows in `affected_packages` or `affected_products`.

## Source Extraction Map

### OSV

OSV is package/ecosystem/version-centric.

Populate:

```text
source_records
vulnerability_records
identifiers
vulnerability_record_identifiers
ecosystems
packages
affected_packages
version_ranges
severity_metrics
external_references
vulnerability_record_references
```

Important fields:

```text
id
aliases
upstream
affected[].package.ecosystem
affected[].package.name
affected[].package.purl
affected[].ranges
affected[].versions
severity[]
references[]
published / modified / withdrawn
```

### CVE List

CVE is product/source/context-centric.

Populate:

```text
source_records
vulnerability_records
identifiers
vulnerability_record_identifiers
products
affected_products
version_ranges
weaknesses
vulnerability_record_weaknesses
severity_metrics
cvss_metric_details
ssvc_assessments
external_references
vulnerability_record_references
```

Important fields:

```text
cveMetadata.cveId
cveMetadata.state
cveMetadata.datePublished / dateUpdated
containers.cna.affected[]
containers.cna.problemTypes[]
containers.cna.descriptions[]
containers.cna.metrics[]
containers.cna.references[]
containers.adp[].metrics[]
```

### CISA KEV

KEV is a known-exploited signal keyed by CVE.

Populate:

```text
source_records
identifiers
kev_entries
```

Important fields:

```text
cveID
vendorProject
product
vulnerabilityName
dateAdded
shortDescription
requiredAction
dueDate
knownRansomwareCampaignUse
notes
```

### FIRST EPSS

EPSS is an exploitation probability score keyed by CVE and date.

Populate:

```text
source_records
identifiers
epss_scores
```

Important fields:

```text
cve
epss
percentile
date
```

## Modeling Rules

1. Every normalized source-backed fact must retain provenance through `source_record_id`, `vulnerability_record_id`, or both.
2. Do not infer package affectedness from product affectedness.
3. Do not infer product affectedness from package affectedness.
4. `version_ranges` belongs to an affected edge, not directly to a vulnerability.
5. `aliases` mean same vulnerability; `upstream` means a downstream record points to an upstream issue.
6. CVSS-derived fields in `cvss_metric_details` are source-backed only because they are parsed from a source vector.
7. KEV means known exploited. EPSS means predicted exploitation likelihood. These are different signals.
8. `package_products` is enrichment, not vulnerability truth.

## Deliberately Not Modeled Yet

These concepts are directionally important but outside the current source-backed MVP:

```text
security incidents
attack path hops
OAuth applications
stolen tokens
identity compromise
downstream SaaS exposure
public exploit code
exploit outcomes like RCE or data theft unless source-structured
```

Those belong to a future attack-path or exposure ontology. The current schema preserves the factual base needed to add that later without pretending OSV/CVE/KEV/EPSS already provide those hops.
