# Global Vulnerability Intelligence Graph

A model for the global, non-customer-specific layer of a vulnerability platform.

This layer does not know about a customer's assets, identities, networks,
owners, tickets, or findings. It models public and vendor-provided security
knowledge: what vulnerabilities exist, what software they affect, which versions
are vulnerable, how they are fixed, whether they are exploited, and how reliable
each claim is.

The customer layer can later attach to this graph through package versions,
container images, SBOM components, scanner findings, or asset inventories.

## Why a global layer

Customer-specific data answers:

> "Where am I exposed?"

The global layer answers:

> "What is this vulnerability, what does it affect, how is it fixed, and how
> much should I care before I know where it appears in my environment?"

That distinction matters. A vulnerability platform should not need customer data
to understand that `CVE-2021-44228` affects certain Log4j versions, has public
exploit activity, maps to a weakness class, has fixed releases, and is present
in multiple advisory sources.

The global graph becomes the shared knowledge base that customer-specific
finding graphs can join against.

## What this layer should model

The global layer should model facts that are true outside any one customer
environment:

- Vulnerability identity and aliases
- Affected products, packages, modules, operating systems, and version ranges
- Fixed versions and remediation guidance
- Advisories and source provenance
- Weakness classes and root-cause categories
- Exploitability signals
- Known exploitation in the wild
- Severity and prioritization signals
- Attack prerequisites and required configurations
- Relationships between vulnerabilities
- References, patches, commits, and disclosure timeline

It should explicitly avoid modeling:

- Customer assets
- Customer identities
- Customer networks
- Customer owners
- Customer tickets
- Customer-specific finding state
- Customer-specific reachability or exploitability

Those belong in the customer layer.

## Core node types

### Vulnerability

A security weakness with a stable public identifier or source-specific advisory
identifier.

- **Properties:** `{id, primary_id, title, summary, published_at, modified_at, reserved_at, withdrawn_at}`
- **Examples:** `CVE-2021-44228`, `GHSA-jfh8-c2jp-5v3q`, `PYSEC-2022-42969`

`Vulnerability` is the center of the global graph. It should support aliases
because many sources describe the same issue with different identifiers.

### Advisory

A source document that makes claims about a vulnerability.

- **Properties:** `{source, source_id, url, published_at, modified_at, withdrawn, severity_text}`
- **Examples:** NVD record, GitHub Security Advisory, OSV advisory, vendor bulletin, distro advisory.

Advisories should be first-class nodes because provenance matters. Two sources
can disagree about affected ranges, fixed versions, severity, or exploitability.

### Source

An upstream authority or feed.

- **Properties:** `{name, type, trust_tier, url}`
- **Examples:** NVD, OSV, GitHub Advisory Database, CISA KEV, vendor advisory feed, distro security tracker.

### Package

A named software artifact within an ecosystem.

- **Properties:** `{name, ecosystem, namespace, purl}`
- **Examples:** Maven `org.apache.logging.log4j:log4j-core`, npm `lodash`, PyPI `django`.

### PackageVersion

A concrete released version of a package.

- **Properties:** `{version, normalized_version, released_at, yanked}`
- **Examples:** `2.14.1`, `1.2.3-r0`, `3.11.4`.

Use this when the graph needs exact release points, dependency matching, or
fixed-version traversal.

### AffectedVersionRange

A version constraint that describes vulnerable versions.

- **Properties:** `{introduced, fixed, last_affected, limit, range_type, expression}`
- **Examples:** `< 2.17.1`, `>= 2.0-beta9 < 2.15.0`, `introduced: 0, fixed: 1.26.5`.

This should be first-class. Many sources describe vulnerability impact as ranges,
not enumerated versions. Ranges also handle ecosystem-specific version semantics,
distro backports, and open-ended affected intervals more accurately than exact
version nodes alone.

### Product

A vendor product, project, operating system, image, appliance, or service.

- **Properties:** `{name, vendor, product_type, cpe}`
- **Examples:** OpenSSL, Windows Server, Ubuntu, Cisco IOS XE, Apache HTTP Server.

Use `Product` for CPE-style or vendor-product advisories that do not map cleanly
to a package ecosystem.

### Vendor

An organization responsible for a product or advisory.

- **Properties:** `{name, url}`
- **Examples:** Microsoft, Apache Software Foundation, Red Hat, Cisco.

### Weakness

A class of software or system weakness.

- **Properties:** `{cwe_id, name, abstraction_level}`
- **Examples:** `CWE-79`, `CWE-89`, `CWE-502`.

### SeverityAssessment

A source-specific severity claim.

- **Properties:** `{system, score, vector, rating, assessed_at}`
- **Examples:** CVSS v3.1 vector, CVSS v4.0 vector, vendor criticality, distro severity.

Severity should be modeled as a claim, not only as a property on
`Vulnerability`, because sources often disagree or change over time.

### Exploit

Evidence of exploit code, a proof of concept, weaponization, or observed
exploitation.

- **Properties:** `{type, maturity, url, published_at, verified, description}`
- **Examples:** public PoC, Metasploit module, exploit-db entry, vendor statement, observed exploitation report.

### ExploitSignal

A time-varying prioritization or exploitability signal.

- **Properties:** `{signal_type, score, percentile, observed_at}`
- **Examples:** EPSS score, CISA KEV status, exploit maturity, ransomware association.

Use a separate node when the signal has a source, timestamp, and history.

### AttackTechnique

A tactic, technique, or procedure associated with exploitation.

- **Properties:** `{framework, technique_id, name}`
- **Examples:** MITRE ATT&CK technique IDs.

### Prerequisite

A condition required for exploitation.

- **Properties:** `{kind, description}`
- **Examples:** authentication required, local access required, vulnerable feature enabled, public endpoint exposed, specific configuration flag.

### Patch

A change that remediates or mitigates a vulnerability.

- **Properties:** `{type, url, commit_sha, released_at, description}`
- **Examples:** Git commit, pull request, vendor patch, distro package update, workaround.

### Reference

A supporting URL or document.

- **Properties:** `{url, title, tags, published_at}`
- **Examples:** vendor blog, mailing list post, release note, commit URL, exploit write-up.

### Evidence

A source-backed assertion supporting a relationship or property.

- **Properties:** `{statement, confidence, collected_at, extractor, raw_location}`

Use evidence when the platform needs to explain why a relationship exists,
especially for inferred or ML-extracted data.

## Core edge types

Edges should be typed and should carry provenance where useful.

### Vulnerability identity

- `Vulnerability --HAS_ALIAS--> Vulnerability`
- `Vulnerability --DESCRIBED_BY--> Advisory`
- `Advisory --PUBLISHED_BY--> Source`
- `Advisory --REFERENCES--> Reference`

Aliases can also be represented as properties, but an edge is useful when alias
records come from different sources and need provenance.

### Affected software

- `Vulnerability --AFFECTS--> Package`
- `Vulnerability --AFFECTS_PRODUCT--> Product`
- `Vulnerability --HAS_AFFECTED_RANGE--> AffectedVersionRange`
- `AffectedVersionRange --OF_PACKAGE--> Package`
- `AffectedVersionRange --OF_PRODUCT--> Product`
- `PackageVersion --IS_VERSION_OF--> Package`
- `PackageVersion --MATCHES_RANGE--> AffectedVersionRange`

The important relationship is usually not "CVE affects exact version X." It is:

> This source claims this vulnerability affects this package or product under
> these version constraints.

Exact version matching can be materialized later for fast lookup.

### Fixes and remediation

- `AffectedVersionRange --FIXED_BY_VERSION--> PackageVersion`
- `Vulnerability --FIXED_BY--> Patch`
- `Patch --CHANGES--> Package`
- `Patch --REFERENCES--> Reference`
- `Vulnerability --MITIGATED_BY--> Patch`

Fix data should distinguish between:

- a fixed upstream package version
- a vendor patch
- a distro backport
- a configuration workaround
- a compensating control

### Severity and prioritization

- `Vulnerability --HAS_SEVERITY--> SeverityAssessment`
- `SeverityAssessment --ASSERTED_BY--> Source`
- `Vulnerability --HAS_EXPLOIT_SIGNAL--> ExploitSignal`
- `ExploitSignal --ASSERTED_BY--> Source`

Do not collapse all prioritization into one severity number. CVSS, EPSS, KEV,
exploit maturity, and vendor criticality answer different questions.

### Weakness and attack context

- `Vulnerability --INSTANCE_OF--> Weakness`
- `Vulnerability --ENABLES_TECHNIQUE--> AttackTechnique`
- `Vulnerability --REQUIRES--> Prerequisite`
- `Vulnerability --RELATED_TO--> Vulnerability` (props: `{relationship_type}`)

Useful `RELATED_TO` values include:

- `same_root_cause`
- `same_patch`
- `bypasses_fix_for`
- `exploited_together`
- `duplicate_of`
- `supersedes`
- `variant_of`

### Exploit evidence

- `Vulnerability --HAS_EXPLOIT--> Exploit`
- `Exploit --REFERENCES--> Reference`
- `Exploit --ASSERTED_BY--> Source`
- `Exploit --TARGETS--> Product`
- `Exploit --TARGETS_PACKAGE--> Package`

Exploit relationships should be careful about confidence. A public blog claiming
"exploitation is possible" is different from CISA KEV inclusion or confirmed
incident response evidence.

### Provenance and evidence

- `AnyNodeOrEdge --SUPPORTED_BY--> Evidence`
- `Evidence --FROM_ADVISORY--> Advisory`
- `Evidence --FROM_REFERENCE--> Reference`
- `Evidence --ASSERTED_BY--> Source`

Most graph databases do not support edges pointing to edges directly. If edge
provenance is required, use one of these patterns:

1. Store `{source, confidence, observed_at}` properties on the edge.
2. Promote the claim to a node, such as `AffectedClaim`.
3. Use an `Evidence` node connected to the entities involved in the claim.

For high-quality vulnerability intelligence, the second pattern is often best.

## Claim nodes for disputed facts

Some facts should be modeled as claims rather than direct edges because sources
disagree.

### AffectedClaim

A source-backed claim that a vulnerability affects a software target under a
specific constraint.

- **Properties:** `{status, confidence, collected_at, last_verified_at}`
- **Edges:**
  - `AffectedClaim --ABOUT--> Vulnerability`
  - `AffectedClaim --TARGETS_PACKAGE--> Package`
  - `AffectedClaim --TARGETS_PRODUCT--> Product`
  - `AffectedClaim --USES_RANGE--> AffectedVersionRange`
  - `AffectedClaim --ASSERTED_BY--> Advisory`
  - `AffectedClaim --SUPPORTED_BY--> Evidence`

This makes disagreement explicit. One advisory can say a version is affected,
another can say it is not, and the graph can preserve both claims.

### FixClaim

A source-backed claim that a version, patch, or workaround fixes a vulnerability.

- **Properties:** `{fix_type, confidence, collected_at}`
- **Edges:**
  - `FixClaim --ABOUT--> Vulnerability`
  - `FixClaim --FIXED_BY_VERSION--> PackageVersion`
  - `FixClaim --FIXED_BY_PATCH--> Patch`
  - `FixClaim --ASSERTED_BY--> Advisory`

### SeverityClaim

A source-backed severity assessment.

- **Properties:** `{system, score, vector, rating, confidence, assessed_at}`
- **Edges:**
  - `SeverityClaim --ABOUT--> Vulnerability`
  - `SeverityClaim --ASSERTED_BY--> Advisory`

## Design rule: global fact vs. customer fact

A concept belongs in the global layer when it is true independent of a customer's
environment.

Good global facts:

- Log4j `2.14.1` is within an affected range for a vulnerability.
- A vendor advisory says version `2.17.1` fixes the issue.
- A vulnerability has public exploit code.
- A vulnerability maps to a CWE.
- A vulnerability is in CISA KEV.

Customer facts:

- This company runs Log4j `2.14.1` on host `ip-10-0-4-12`.
- This vulnerable host is internet-exposed.
- The platform team owns the service.
- A scanner opened a finding yesterday.
- The issue is accepted risk until next quarter.

The customer layer should point into the global layer, not duplicate it.

## Entity resolution

Entity resolution is still the hard problem even without customer data.

The graph must normalize:

- CVE IDs, GHSA IDs, OSV IDs, vendor advisory IDs, and distro advisory IDs
- Package names across ecosystems
- CPEs, PURLs, SWIDs, and vendor-product names
- Version syntax across semver, Maven, Debian, RPM, Go modules, Python, npm, and containers
- Forks, renamed projects, split packages, and bundled dependencies
- Distro backports where the visible version may remain old but contain a fix

Bad entity resolution creates bad vulnerability intelligence. It can make safe
versions look vulnerable, hide vulnerable forks, or merge unrelated products.

## Useful queries

### What versions are affected?

```cypher
MATCH (v:Vulnerability {id: 'CVE-2021-44228'})
      -[:HAS_AFFECTED_RANGE]->(r:AffectedVersionRange)
      -[:OF_PACKAGE]->(p:Package)
RETURN p.ecosystem, p.name, r.expression, r.introduced, r.fixed
```

### What fixes are available?

```cypher
MATCH (v:Vulnerability {id: 'CVE-2021-44228'})
      -[:HAS_AFFECTED_RANGE]->(:AffectedVersionRange)
      -[:FIXED_BY_VERSION]->(pv:PackageVersion)
      -[:IS_VERSION_OF]->(p:Package)
RETURN p.ecosystem, p.name, pv.version
```

### Which sources disagree?

```cypher
MATCH (v:Vulnerability {id: 'CVE-2021-44228'})
      <-[:ABOUT]-(claim:AffectedClaim)
      -[:ASSERTED_BY]->(a:Advisory)
RETURN claim.status, claim.confidence, a.source, a.source_id
```

### What should be prioritized globally?

```cypher
MATCH (v:Vulnerability)-[:HAS_EXPLOIT_SIGNAL]->(s:ExploitSignal)
WHERE s.signal_type IN ['kev', 'epss', 'public_exploit']
RETURN v.id, collect(s) AS signals
```

### What is related to this vulnerability?

```cypher
MATCH path = (:Vulnerability {id: 'CVE-2021-44228'})
             -[:INSTANCE_OF|RELATED_TO|ENABLES_TECHNIQUE*1..3]-(related)
RETURN path
```

## Ingestion sources

Useful sources for the global layer include:

| Source type | Maps to |
|---|---|
| CVE / NVD records | `Vulnerability`, `SeverityClaim`, `Weakness`, `Reference` |
| OSV advisories | `Advisory`, `AffectedClaim`, `AffectedVersionRange`, `Package`, `PackageVersion` |
| GitHub Security Advisories | `Advisory`, `Vulnerability`, `Package`, `AffectedClaim`, `FixClaim` |
| Vendor advisories | `Advisory`, `Product`, `Patch`, `Reference`, `FixClaim` |
| Distro security trackers | `Product`, `Package`, `AffectedClaim`, `FixClaim` |
| CISA KEV | `ExploitSignal` |
| EPSS | `ExploitSignal` |
| Exploit databases | `Exploit`, `Reference`, `ExploitSignal` |
| CWE catalog | `Weakness` |
| ATT&CK mappings | `AttackTechnique` |
| Source repositories | `Patch`, `Reference`, `PackageVersion` |

Every connector should preserve source identity, timestamps, and raw references.
The goal is not just to know the answer; it is to know who claimed it, when, and
with what confidence.

## How this connects to the customer layer

The customer layer should attach through observed software or findings:

- `Finding --DETECTS--> Vulnerability`
- `Asset --RUNS--> PackageVersion`
- `SBOMComponent --RESOLVES_TO--> PackageVersion`
- `ContainerImage --CONTAINS--> PackageVersion`
- `Repository --DECLARES_DEPENDENCY_ON--> Package`
- `DependencyInstance --MATCHES_RANGE--> AffectedVersionRange`

Then customer-specific risk queries can combine both layers:

> "Show me internet-exposed assets running package versions that match affected
> ranges for vulnerabilities with KEV status or high EPSS scores."

The global layer supplies the vulnerability truth. The customer layer supplies
exposure, ownership, and remediation workflow.

## Product value without customer data

A global vulnerability graph is valuable even before customer data is attached,
but only if it does more than draw a large graph.

Valuable experiences include:

- Explain why a package version is or is not vulnerable.
- Compare advisories and show conflicting claims.
- Show all known fix paths and their source.
- Track exploitability and prioritization signals over time.
- Map vulnerability families, shared weaknesses, and related fixes.
- Let users inspect provenance for every important conclusion.
- Provide an API that answers "is this package/version affected?"

Less valuable experiences include:

- A generic CVE-to-package visualization with no query focus.
- A dense graph that is visually impressive but hard to act on.
- A single severity score with no source breakdown.
- A vulnerability page that repeats NVD without reconciling other sources.

The graph should be useful as an intelligence engine first and a visualization
second.

## Mental model

The global layer is a source-backed map of vulnerability knowledge.

`Vulnerability` is the central concept. Around it are claims about affected
software, fixed versions, weaknesses, exploitability, references, and source
provenance. The graph preserves disagreement instead of flattening it away.

The customer layer later asks:

> "Do any of these global facts apply to my environment?"

That separation is the point. The global graph can be built, validated, queried,
and sold as useful intelligence before a customer connects a single scanner or
uploads a single asset inventory.
