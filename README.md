# Vulnerability Intelligence Product

This project is a search-first vulnerability intelligence system.

The product helps users answer:

```text
What vulnerability is this, what software does it affect, which versions are
affected or fixed, how exploitable is it, and which source records support those
facts?
```

The first version does not use customer asset data. It focuses on public/global
vulnerability intelligence: vulnerabilities, source records, identifiers,
products, packages, ecosystems, affected versions, fixes, weaknesses, severity,
known exploitation, exploit probability, and evidence.

## Who This Serves

Initial users:

- security engineers triaging public vulnerability intelligence
- AppSec teams tracking dependency, framework, and product risk
- SecOps teams watching known exploited vulnerabilities
- platform engineers responsible for common stacks
- open-source maintainers and package users
- cyber-curious users trying to understand how vulnerabilities become attacks

Without customer data, the product should not claim:

```text
Your asset is vulnerable.
```

It can say:

```text
This product or package is affected according to these source records, these
versions are affected or fixed, and these source-backed exploitability signals
exist.
```

Customer-specific exposure can come later by connecting this global graph to
assets, identities, SaaS integrations, SBOMs, repositories, scanners, and runtime
data.

## Product Thesis

Most vulnerability databases answer a narrow question:

```text
Is this package or product affected by a known vulnerability?
```

That is useful but incomplete. Users also need to know:

```text
How much should I care, what could an attacker do, what conditions matter, what
should I do next, and who says so?
```

The product should reconcile public sources into a clear, provenance-backed
answer. A user should be able to search for `react`, `next`, `vercel`, `log4j`,
`CVE-...`, `GHSA-...`, an ecosystem, or a package name and quickly understand:

- relevant vulnerabilities
- affected products/packages/ecosystems
- affected and fixed versions
- source records behind each fact
- weakness class, usually CWE
- severity and CVSS conditions
- known exploitation via CISA KEV
- exploitation probability via EPSS
- references and evidence

The graph matters because it connects naming systems and source facts:

```text
CVE / GHSA / OSV / distro IDs
  -> one canonical vulnerability
  -> source records
  -> affected products and packages
  -> affected/fixed versions
  -> weaknesses, severity, KEV, EPSS, references
```

It should not invent affectedness. Product-to-package relationships are useful
for search and navigation, but affectedness must come from source-backed records.

## Current Scope

The MVP is intentionally source-backed and conservative.

In scope now:

- OSV package vulnerability records
- CVE List source records
- CISA KEV known-exploited signals
- FIRST EPSS probability scores
- canonical vulnerability grouping through identifiers
- product/package/ecosystem affectedness
- affected/fixed version ranges
- CWE weaknesses
- CVSS/vendor severity
- parsed CVSS exploitability conditions
- CISA ADP SSVC assessments when present in CVE records
- references/evidence

Out of scope for the current schema:

- customer assets
- customer identities
- OAuth grants
- SaaS account exposure
- attack path hops
- stolen token modeling
- public exploit-code ingestion
- derived outcomes like RCE/data theft unless source-structured

Those are future attack-path/exposure concepts. They are important to the
long-term product, but the current schema should not pretend OSV/CVE/KEV/EPSS
provide those facts.

## Source Mental Model

Different sources answer different questions.

| Source | Main value |
| --- | --- |
| OSV | Package, ecosystem, affected range, fixed range, aliases, references. |
| CVE List | Canonical CVE record, CNA/product facts, descriptions, CWE, CVSS, ADP enrichment. |
| CISA KEV | Source-backed known exploitation signal. |
| FIRST EPSS | Exploitation probability and percentile by CVE/date. |
| Direct GHSA later | GitHub-specific advisory details if OSV drops information we need. |

High-level rule:

```text
OSV = package/ecosystem/version-centric
CVE = product/source/context-centric
KEV = known exploited
EPSS = predicted exploitation likelihood
```

## Ontology

The current ontology centers on `Vulnerability`.

```text
Source
  PUBLISHED -> SourceRecord

SourceRecord
  NORMALIZES_TO -> VulnerabilityRecord

VulnerabilityRecord
  DESCRIBES -> Vulnerability
  HAS_IDENTIFIER -> Identifier
  AFFECTS -> Product / Package
  HAS_WEAKNESS -> Weakness
  HAS_SEVERITY -> SeverityMetric
  HAS_REFERENCE -> Reference

AffectedProduct / AffectedPackage
  HAS_VERSION_RANGE -> VersionRange

SeverityMetric
  MAY_HAVE -> CVSSMetricDetails

Vulnerability
  HAS_IDENTIFIER -> Identifier
  MAY_HAVE -> KEVEntry
  MAY_HAVE -> EPSSScore
```

Important distinction:

- `affected_products`, `affected_packages`, `version_ranges`, `weaknesses`,
  `severity_metrics`, `kev_entries`, and `epss_scores` are source-backed facts.
- `vulnerabilities` is canonical/derived. It groups multiple source records into
  one user-facing vulnerability.
- `package_products` and `package_versions` are application/enrichment tables.
  They are useful for search and navigation, but they are not vulnerability
  truth.

For the detailed schema ontology and ingestion mapping, read
[src/db/SCHEMA.md](src/db/SCHEMA.md).

## Modeling Rules

1. Preserve source provenance for every important normalized fact.
2. Do not infer package affectedness from product affectedness.
3. Do not infer product affectedness from package affectedness.
4. Attach version ranges to affected product/package edges, not directly to a
   vulnerability.
5. Treat OSV `aliases` as same-vulnerability identifiers.
6. Treat OSV `upstream` as a downstream record pointing to an upstream issue, not
   necessarily the same source record identity.
7. Treat KEV and EPSS as different signals: known exploited vs probability.
8. Keep future attack-path modeling separate until we ingest sources that
   actually describe those hops.

## Future Direction

The long-term product should model scenarios like:

```text
Product security issue
  -> enables access capability
  -> exposes downstream surface
  -> affects connected SaaS/account/identity/assets
```

Example shape:

```text
Context AI incident
  -> OAuth token compromise
  -> Google Workspace access
  -> Vercel account exposure
  -> environment variable exposure
```

That is the attack-path/exposure graph. It requires different source data:
incident reports, vendor bulletins, IOCs, OAuth app metadata, identity/asset
graphs, and customer context. The current MVP builds the public vulnerability
knowledge graph that can later connect to that layer.

## Implementation Order

The project is intentionally schema-first:

1. Build the canonical data model.
2. Build ingestion pipelines that normalize source data into the model.
3. Build API/UI feature slices against the model.

Reason: once the model is stable, ingestion and product features can move in
parallel.

Current likely ingestion order:

1. Seed known ecosystems as reference data, but allow unknown ecosystems to be
   upserted.
2. Ingest OSV for package/ecosystem/version facts.
3. Ingest CVE List for product/context/CWE/CVSS/SSVC facts.
4. Ingest CISA KEV for known exploitation.
5. Ingest FIRST EPSS for probability scores.
6. Reconcile records into canonical vulnerabilities through identifiers.

Current implemented ingestion commands:

```bash
bun run ingest:seed
bun run ingest:cve -- --dir RESOURCES/cvelistV5-main/cves
bun run ingest -- osv --dir /path/to/osv/json
bun run ingest -- kev --file /path/to/known_exploited_vulnerabilities.json
bun run ingest -- epss --file /path/to/epss_scores.csv --date YYYY-MM-DD
```

The local CVE List V5 checkout in `RESOURCES/cvelistV5-main/cves` is the first
real corpus for the pipeline. The CVE importer preserves rejected records,
affected product/package rows, CPE/PURL/package identifiers, version status
objects, CVSS, SSVC, CISA ADP KEV hints, weaknesses, and references.

## Stack

- App framework: Next.js
- Runtime/package manager: Bun
- Language: TypeScript
- Database: Postgres
- ORM/migrations: Drizzle

Postgres is the canonical store. A graph database can be added later as a
projection if traversal/query needs justify it.

## Local Setup

Install dependencies:

```bash
bun install
```

Create `.env`:

```bash
cp .env.example .env
```

Start local Postgres:

```bash
docker run --name vulnerability-model-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=vulnerability_model \
  -p 5432:5432 \
  -d postgres:16
```

Push schema during early schema-design work:

```bash
bun run db:push
```

Generate migrations when we want durable migration files:

```bash
bun run db:generate
```

Typecheck:

```bash
bun run typecheck
```

Start the Next.js app:

```bash
bun run dev
```

The app exposes:

```bash
GET /
GET /health
GET /api/health
POST /api/search
GET /api/search?q=log4j
```

Example search request:

```bash
curl -s http://localhost:3000/api/search \
  -H 'content-type: application/json' \
  -d '{"query":"log4j 2.14.1","limit":10}'
```

Run the first local ingestion slice:

```bash
bun run db:migrate
bun run ingest:seed
bun run ingest:cve -- --dir RESOURCES/cvelistV5-main/cves --limit 100
```

## Agent Reading Order

Any agent working on this project should read:

1. `README.md` for product direction and implementation boundaries.
2. `src/db/SCHEMA.md` for ontology and source extraction mapping.
3. `src/db/schema.ts` for the actual Drizzle tables.

Do not start by adding UI or ingestion-specific abstractions until the change is
clear against this ontology.
