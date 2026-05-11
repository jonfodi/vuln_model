# Product

## Register

product

## Users

Security engineers, AppSec teams, SecOps teams, platform engineers, open-source maintainers, package users, and technically curious users who need to understand public vulnerability intelligence quickly. They are often triaging risk, checking software or dependency exposure, comparing source records, or trying to understand whether a vulnerability is known exploited, likely to be exploited, or relevant to a specific package, product, ecosystem, or version.

## Product Purpose

This product is a search-first vulnerability intelligence system. It reconciles public vulnerability sources into clear, provenance-backed answers about what a vulnerability is, what software it affects, which versions are affected or fixed, how exploitable it appears, and which source records support those facts.

The current product focuses on global vulnerability intelligence, not customer-specific exposure. It should not claim that a user's asset is vulnerable until customer asset, identity, repository, scanner, SBOM, SaaS, or runtime context is connected later. Its job now is to make source-backed vulnerability facts easier to search, inspect, compare, and trust.

## Brand Personality

Clear, evidence-backed, analyst-grade.

The product should feel precise and calm under pressure. It should reduce ambiguity without oversimplifying uncertainty, expose supporting evidence instead of hiding it, and help technical users move from a raw identifier, package name, product name, ecosystem, weakness, or version query to an answer they can defend.

## Anti-references

Avoid unclear hierarchy, overuse of colors, and unoriginality.

The product should not look like a generic cybersecurity dashboard, threat-map fantasy, neon terminal, or fear-driven severity wall. It should not bury provenance behind vague summaries, flatten all signals into one risk score, or imply affectedness from weak relationships. Color should guide attention sparingly, especially for severity and exploitability, rather than saturating the whole interface.

## Design Principles

1. Evidence before assertion: important facts should point back to their source records, and uncertainty should be visible.
2. Preserve source distinctions: OSV, CVE List, CISA KEV, FIRST EPSS, and future sources answer different questions; the interface should not collapse them into false equivalence.
3. Triage starts with hierarchy: search results and vulnerability pages should make identifier, affected software, versions, exploitability, and evidence easy to scan in that order.
4. Conservative by default: do not infer affectedness across product/package relationships unless a source-backed record supports it.
5. Analyst-grade restraint: use density, structure, and sharp labels to create confidence; avoid decorative cyber tropes.

## Accessibility & Inclusion

Target WCAG AA for contrast, keyboard navigation, focus states, and semantic structure. Severity, exploitation, and version status must never depend on color alone; use labels, icons, ordering, and text to carry meaning. Prefer reduced-motion-safe interactions by default, with motion used only to clarify state changes or preserve orientation.
