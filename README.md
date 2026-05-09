# Vulnerability Intelligence Product

This product is a search-first vulnerability intelligence system.

Its purpose is to help users understand:

> What vulnerabilities matter, what software they affect, how exploitation may
> work, what harm exploitation can cause, how to fix the issue, and what
> evidence supports each conclusion.

The first version does not use customer asset data. It focuses on global
vulnerability knowledge: vulnerabilities, packages, products, frameworks,
platforms, dependency relationships, exploitation signals, fixes, and evidence.

## Product Thesis

Most vulnerability tools answer one narrow question:

> Is this package or product affected by a known vulnerability?

That is useful, but incomplete. Security engineers usually need to answer a more
operational question:

> Should I care about this vulnerability, what could an attacker do with it, and
> what should I do next?

This product turns public vulnerability data into decision-grade intelligence.
It should help someone search for `react`, `next`, `vercel`, `log4j`, a CVE, a
GHSA, or a package URL and quickly understand:

- which vulnerabilities are relevant
- which versions or products are affected
- whether the issue is known exploited or likely exploitable
- what attacker capability the vulnerability may create
- what malicious outcomes may follow
- what fixes, patches, or mitigations exist
- which sources agree, disagree, or are uncertain
- what evidence backs the answer

## Who We Serve

The initial audience is:

- security engineers triaging public vulnerability intelligence
- AppSec teams tracking package and framework risk
- SecOps teams watching newly exploited vulnerabilities
- platform engineers responsible for common stacks
- open-source maintainers and package users
- cyber-curious users trying to understand how vulnerabilities become attacks

Without customer data, we cannot say:

> Your asset is vulnerable.

Instead, we can say:

> This software, version, package, dependency chain, framework, or platform is
> affected or potentially affected, and here is why it matters.

Customer-specific asset exposure can be added later by attaching asset, scanner,
SBOM, repository, and runtime data to the global graph.

## How We Help

The product should reduce the work required to go from raw vulnerability record
to security decision.

Instead of forcing users to manually compare OSV, NVD, GitHub advisories, vendor
bulletins, CISA KEV, EPSS, exploit databases, package metadata, and patch notes,
the system should reconcile those sources into a clear page.

Each important conclusion should answer:

- What is the claim?
- Who says so?
- How confident are we?
- Is it reported, extracted, inferred, or curated?
- What evidence supports it?

## Differentiation

OSV is the closest public analog to the foundation of this product. OSV is very
good at package/version vulnerability matching. It answers:

> Is this package version affected?

This product should build on sources like OSV but answer a broader question:

> How much should I care, how might exploitation work, what harm could result,
> and why should I trust the answer?

Compared with traditional vulnerability databases, the product should emphasize:

- vulnerability-to-exploitation reasoning
- exploitability and impact, not only severity
- source disagreement and claim provenance
- dependency and reverse-dependency traversal
- ecosystem search from terms like `react`, `next`, or `vercel`
- fix paths and mitigation clarity
- explicit uncertainty instead of false precision

The product should be an intelligence engine first and a visualization second.
Graph traversal is valuable because it answers questions across relationships,
not because a graph view looks impressive.

## Core User Flow

The landing experience should be search plus a high-signal intelligence feed.

Users can start with:

- a vulnerability ID: `CVE-2021-44228`, `GHSA-...`
- a package: `react`, `lodash`, `log4j-core`
- a framework: `Next.js`, `Remix`, `Django`
- a platform or vendor: `Vercel`, `Cloudflare`, `Ubuntu`
- a package URL or version

The page should surface:

- **Act Now:** known exploited, high-confidence, high-impact items
- **Investigate:** serious but conditional or uncertain items
- **Monitor:** real issues with weak current exploit signal
- **Low Signal:** searchable, but not promoted by default

For a package or ecosystem search, the product should show:

- direct vulnerabilities in that package
- affected and fixed versions
- relevant dependency vulnerabilities
- downstream packages, frameworks, or products that may be affected
- current high-signal issues connected to the ecosystem

For a vulnerability page, the product should show:

- verdict and rationale
- affected software and versions
- exploitation model
- likely or confirmed malicious outcomes
- prerequisites and conditions
- fixes, patches, and mitigations
- source comparison
- evidence and timeline
- related vulnerabilities, weaknesses, and patches

## Vulnerability To Exploitation

A vulnerability is not the harm itself. Exploitation is how an attacker turns a
weakness into a capability, and then into an outcome that causes damage.

The product should teach and model this chain:

```text
Vulnerable software exists
-> vulnerable code is included
-> vulnerable code is reachable
-> attacker can trigger it
-> attacker gains an exploit primitive
-> attacker achieves a malicious outcome
```

Each step matters. If package `A` depends on vulnerable package `B`, then `A` is
not automatically exploitable in the strongest sense. It is potentially affected.
Whether it matters depends on runtime use, attacker-controlled input, feature
configuration, reachability, and exploit maturity.

Example:

```text
SQL injection
-> query manipulation
-> data read, data modification, possible auth bypass
```

Example:

```text
SSRF
-> server-side request forgery
-> internal service access, cloud credential theft, network pivot
```

Example:

```text
XSS
-> browser script execution
-> session theft, account takeover, user impersonation
```

This distinction is central to the product. A vulnerability page should not only
say:

```text
CWE-89 SQL Injection
Severity: Critical
```

It should explain:

```text
Weakness: SQL injection
Exploit primitive: attacker may manipulate database queries
Likely outcomes: data extraction, data modification, possible auth bypass
Requires: attacker-controlled input reaches a vulnerable query
Evidence: source advisories, CVSS vector, exploit references
```

## Confidence And Provenance

Most sources do not provide an exact structured exploitation model. They provide
clues:

- CWE mappings
- CVSS vectors
- affected versions
- fixed versions
- summary text
- references
- exploit signals
- advisory metadata

The product should separate four kinds of knowledge:

- **Reported:** explicitly stated by a source
- **Extracted:** parsed from advisory text, patch notes, or references
- **Inferred:** derived from CWE, CVSS, exploit signals, or source combinations
- **Curated:** reviewed or corrected by us

This prevents the system from overclaiming. A page can say:

```text
Confirmed: public exploit exists
Likely: network exploitation is practical
Possible: data exfiltration
Unknown: whether unauthenticated RCE is possible
```

## MVP Data Model

The MVP should use a graph-shaped model even if the initial storage is Postgres.

### Primary Nodes

```text
Source
Advisory
Vulnerability
Package
PackageVersion
Product
Framework
Platform
AffectedVersionRange
Weakness
ExploitPrimitive
MaliciousOutcome
Prerequisite
ExploitArtifact
ExploitSignal
Evidence
```

### Claim Nodes

Facts that are source-specific, disputed, extracted, or inferred should be
modeled as claims.

```text
AffectedClaim
FixClaim
SeverityClaim
ExploitabilityClaim
OutcomeClaim
PrerequisiteClaim
```

Claims should carry:

```text
source
confidence
status
collected_at
last_verified_at
extraction_method
evidence
```

### Core Relationships

Identity and provenance:

```text
Vulnerability --HAS_ALIAS--> Vulnerability
Vulnerability --DESCRIBED_BY--> Advisory
Advisory --PUBLISHED_BY--> Source
Advisory --REFERENCES--> Evidence
```

Affected software:

```text
Vulnerability --AFFECTS--> Package
Vulnerability --AFFECTS_PRODUCT--> Product
Vulnerability --HAS_AFFECTED_RANGE--> AffectedVersionRange
AffectedVersionRange --OF_PACKAGE--> Package
AffectedVersionRange --OF_PRODUCT--> Product
PackageVersion --IS_VERSION_OF--> Package
PackageVersion --MATCHES_RANGE--> AffectedVersionRange
AffectedVersionRange --FIXED_BY_VERSION--> PackageVersion
```

Dependencies and ecosystem context:

```text
PackageVersion --DEPENDS_ON--> PackageVersion
Package --COMMONLY_USED_WITH--> Package
Framework --COMMONLY_USES--> Package
Platform --SUPPORTS--> Framework
```

Exploitation model:

```text
Vulnerability --HAS_WEAKNESS--> Weakness
Weakness --MAY_GRANT--> ExploitPrimitive
Vulnerability --CONFIRMED_GRANTS--> ExploitPrimitive
Vulnerability --REQUIRES--> Prerequisite
ExploitPrimitive --CAN_LEAD_TO--> MaliciousOutcome
Vulnerability --MAY_ENABLE--> MaliciousOutcome
Vulnerability --CONFIRMED_ENABLES--> MaliciousOutcome
```

Exploit evidence and prioritization:

```text
Vulnerability --HAS_EXPLOIT--> ExploitArtifact
Vulnerability --HAS_EXPLOIT_SIGNAL--> ExploitSignal
ExploitArtifact --DEMONSTRATES--> ExploitPrimitive
Evidence --SUPPORTS--> Claim
Evidence --FROM_ADVISORY--> Advisory
Evidence --ASSERTED_BY--> Source
```

## MVP Sources

Start with sources that give the most leverage:

- OSV for package vulnerabilities, affected ranges, fixes, aliases, references
- NVD for CVEs, CVSS, CWE, CPE/product mappings, references
- CISA KEV for known exploited status
- EPSS for exploitation probability and percentile
- CWE catalog for weakness taxonomy
- npm/package registry or deps.dev for package versions and dependencies

The first ecosystem should likely be JavaScript/npm because it supports searches
like `react`, `next`, and `vercel`, and because dependency relationships are
central to the product thesis.

## MVP Verdict Model

The product should produce a transparent care verdict:

```text
Act Now
Investigate
Monitor
Low Signal
```

Useful scoring inputs:

- CISA KEV inclusion
- EPSS score and percentile
- public exploit or PoC
- exploit maturity
- CVSS vector and impact
- remote/network exploitability
- privileges required
- user interaction required
- affected package popularity
- fix availability
- source confidence
- source disagreement

The score should be less important than the explanation. Users should see why
the system reached the verdict.

## Implementation Direction

Build in this order:

1. Ingest OSV, NVD, CISA KEV, EPSS, CWE, and npm package metadata.
2. Normalize vulnerabilities, aliases, packages, versions, affected ranges, and
   sources.
3. Create claim and evidence records instead of flattening all facts into one
   vulnerability object.
4. Add rules-based mappings from CWE/CVSS to exploit primitives and likely
   malicious outcomes.
5. Build search for vulnerabilities, packages, frameworks, platforms, and
   products.
6. Build vulnerability decision pages.
7. Build package/ecosystem pages.
8. Add dependency and reverse-dependency traversal.
9. Add source comparison and confidence visualization.

The MVP is successful when a user can search for a package, platform, framework,
or vulnerability and quickly answer:

- Is anything here worth caring about?
- What exactly is affected?
- How could exploitation work?
- What harm could result?
- What fixes or mitigations exist?
- Who says so?
- How confident is the system?

