<!-- SEED: re-run /impeccable document once there's code to capture the actual tokens and components. -->
---
name: Vulnerability Intelligence Product
description: Search-first, source-backed vulnerability intelligence for analyst-grade triage.
---

# Design System: Vulnerability Intelligence Product

## 1. Overview

**Creative North Star: "The Evidence Desk"**

This system should feel like a well-lit analyst workspace: dense enough for real investigation, calm enough for urgent triage, and structured enough that every important fact can be traced. The interface serves security engineers and technical users who need to move from a raw identifier, package, product, ecosystem, weakness, or version query to a defensible answer.

The visual language is restrained, precise, and source-aware. It should reject unclear hierarchy, overuse of colors, and unoriginality. It should also avoid generic cybersecurity tropes: no neon threat theater, no fear-driven dashboards, no decorative noise pretending to be signal.

**Key Characteristics:**

- Evidence-led hierarchy over decorative intensity.
- Restrained color with one carefully held accent.
- Dense but breathable layouts for search, comparison, and provenance.
- Familiar product UI patterns tuned for analyst trust.
- State changes that respond quickly without choreographed page behavior.

## 2. Colors

The palette should use tinted neutrals with a single non-obvious accent, chosen for focus and evidence rather than cybersecurity category reflex.

### Primary

- **Graphite Signal Accent** ([to be resolved during implementation]): Reserved for primary actions, selected state, active navigation, links, and the most important interactive focus points. It should be quiet enough to coexist with severity states and distinct enough to be found quickly in dense screens.

### Neutral

- **Paper Graphite Surface** ([to be resolved during implementation]): The main application surface, slightly tinted rather than pure white.
- **Instrument Panel Surface** ([to be resolved during implementation]): A subtle secondary surface for sidebars, filters, toolbars, and structured panels.
- **Evidence Ink** ([to be resolved during implementation]): Primary text, identifiers, labels, and source names.
- **Divider Dust** ([to be resolved during implementation]): Borders, separators, table rules, and subdued UI structure.

### Named Rules

**The Ten Percent Signal Rule.** The primary accent must stay rare, usually under ten percent of a screen. Its scarcity is what makes it useful.

**The Severity Is Not Decor Rule.** Severity, exploitation, and version status colors must be semantic, label-backed, and color-blind safe. Never use them as ambient decoration.

## 3. Typography

**Display Font:** [single sans family to be chosen at implementation]
**Body Font:** [same sans family to be chosen at implementation]
**Label/Mono Font:** [optional mono for identifiers and code-like values to be chosen at implementation]

**Character:** The typography should be technical but human: precise labels, compact tables, readable summaries, and identifiers that can be scanned without turning the whole interface into a terminal.

### Hierarchy

- **Display** ([size and weight to be chosen at implementation]): Rare. Use only for major product surfaces, not routine app screens.
- **Headline** ([size and weight to be chosen at implementation]): Page titles, search result headings, and vulnerability detail headers.
- **Title** ([size and weight to be chosen at implementation]): Section titles, panel headers, and grouped result labels.
- **Body** ([size and weight to be chosen at implementation]): Summaries, caveats, source descriptions, and explanatory copy. Keep prose line length around 65 to 75 characters.
- **Label** ([size and weight to be chosen at implementation]): Metadata, table headers, chips, filters, and compact source-backed facts.

### Named Rules

**The Analyst Scale Rule.** Type hierarchy should come from clear size and weight steps, not oversized headings. Product screens need order more than drama.

**The Identifier Legibility Rule.** CVEs, GHSAs, package names, ecosystems, versions, and source IDs must remain copyable, scannable, and visually distinct from prose.

## 4. Elevation

The system should be flat by default and layered by structure, not by shadow. Depth should come from surface tone, borders, spacing, grouping, and state changes. Shadows may appear on transient overlays or focused interactive surfaces only after the implementation proves they help orientation.

### Named Rules

**The Flat Until Proven Useful Rule.** Resting surfaces do not need shadows. Use tonal layers and dividers first.

**The State Motion Rule.** Motion should be responsive: hover, focus, selection, loading, expansion, and result updates. No page-load choreography.

## 6. Do's and Don'ts

### Do:

- **Do** use a restrained color strategy: tinted neutrals plus one accent used sparingly.
- **Do** make hierarchy visible through structure, typography, spacing, and labels before adding color.
- **Do** keep evidence, source names, caveats, and provenance close to the claims they support.
- **Do** use familiar product patterns for navigation, filters, tables, tabs, search, and detail pages.
- **Do** make severity, exploitation, and version status readable without relying on color alone.

### Don't:

- **Don't** create unclear hierarchy. If a user cannot identify the query, selected target, main result, caveat, and evidence path in a few seconds, the layout has failed.
- **Don't** overuse colors. Severity colors, accent colors, and source colors must not fight for attention.
- **Don't** settle for unoriginality. Avoid generic cybersecurity dashboards, neon terminal styling, threat-map fantasy, and fear-driven severity walls.
- **Don't** imply customer-specific exposure before the product has customer asset context.
- **Don't** flatten OSV, CVE List, CISA KEV, FIRST EPSS, and future sources into one vague risk blob.
