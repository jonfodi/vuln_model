"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import type {
  SearchResponse,
  TargetCandidate,
  VulnerabilityResult,
} from "../src/api/types";

type SearchState =
  | { status: "idle"; data?: undefined; error?: undefined }
  | { status: "loading"; data?: SearchResponse; error?: undefined }
  | { status: "success"; data: SearchResponse; error?: undefined }
  | { status: "error"; data?: SearchResponse; error: string };

type ApiState = "checking" | "ready" | "offline";

const SAMPLE_QUERIES = [
  "CVE-2021-44228",
  "log4j 2.14.1",
  "npm:next",
  "CWE-79",
  "known exploited chrome",
];

const SOURCES = [
  {
    name: "CVE List V5",
    description: "Product facts, descriptions, CWE, CVSS, ADP enrichment",
  },
  {
    name: "OSV",
    description: "Package, ecosystem, affected and fixed ranges",
  },
  {
    name: "CISA KEV",
    description: "Known exploitation signal",
  },
  {
    name: "FIRST EPSS",
    description: "Exploit probability and percentile",
  },
];

export function SearchClient() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [state, setState] = useState<SearchState>({ status: "idle" });
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const resultCount = useMemo(() => {
    return (state.data?.sections ?? []).reduce(
      (total, section) => total + section.results.length,
      0,
    );
  }, [state.data]);

  useEffect(() => {
    void checkHealth(setApiState);

    const params = new URLSearchParams(window.location.search);
    const urlQuery = params.get("q") ?? params.get("query");
    if (urlQuery) {
      setQuery(urlQuery);
      void submitSearch(urlQuery, { replaceUrl: false });
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }

      const active = document.activeElement;
      const isTyping =
        active instanceof HTMLInputElement ||
        active instanceof HTMLTextAreaElement ||
        Boolean(active?.hasAttribute("contenteditable"));

      if (isTyping) {
        return;
      }

      event.preventDefault();
      inputRef.current?.focus();
    }

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  async function submitSearch(
    nextQuery = query,
    options: { replaceUrl?: boolean } = {},
  ) {
    const trimmed = nextQuery.trim();
    if (!trimmed) {
      setState({
        status: "error",
        error: "Please enter a vulnerability, package, product, weakness, or version.",
      });
      inputRef.current?.focus();
      return;
    }

    setQuery(trimmed);

    if (options.replaceUrl !== false) {
      const params = new URLSearchParams({ q: trimmed });
      window.history.replaceState({}, "", `${window.location.pathname}?${params}`);
    }

    setState((current) => ({ status: "loading", data: current.data }));

    try {
      const response = await fetch(
        `/api/search?q=${encodeURIComponent(trimmed)}&limit=12`,
        { headers: { accept: "application/json" } },
      );
      const body = (await response.json().catch(() => null)) as unknown;

      if (!response.ok) {
        const message =
          body &&
          typeof body === "object" &&
          "message" in body &&
          typeof body.message === "string"
            ? body.message
            : "Search failed.";
        setState({ status: "error", error: message });
        return;
      }

      setState({ status: "success", data: body as SearchResponse });
    } catch (error) {
      setState({
        status: "error",
        error:
          error instanceof Error
            ? error.message
            : "We could not reach the search API.",
      });
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submitSearch();
  }

  function clearSearch() {
    setQuery("");
    setState({ status: "idle" });
    window.history.replaceState({}, "", window.location.pathname);
    inputRef.current?.focus();
  }

  async function copyIdentifier(identifier: string, rowId: string) {
    try {
      await navigator.clipboard.writeText(identifier);
      setCopiedId(rowId);
      window.setTimeout(() => setCopiedId(null), 1300);
    } catch {
      setCopiedId(null);
    }
  }

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <header className="site-header" aria-label="Primary">
        <a className="brand" href="/" aria-label="Vulnerability Intelligence home">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-copy">
            <span className="brand-name">Vulnerability Intelligence</span>
            <span className="brand-subtitle">Evidence-first search</span>
          </span>
        </a>
        <nav className="nav-links" aria-label="Product">
          <a href="#sources">Sources</a>
          <a href="#model">Model</a>
          <a href="/api/search?q=log4j">API</a>
        </nav>
      </header>

      <main id="main-content">
        <section className="hero" aria-labelledby="page-title">
          <div className="hero-copy">
            <p className="eyebrow">Public vulnerability intelligence</p>
            <h1 id="page-title">Search public vulnerability intelligence.</h1>
            <p className="hero-text">
              Find affected software, fixed versions, exploitability signals, and
              source records behind the facts.
            </p>
          </div>

          <aside className="source-ledger" id="sources" aria-labelledby="sources-title">
            <div className="rail-heading">
              <p className="eyebrow">Source ledger</p>
              <ApiBadge state={apiState} />
            </div>
            <h2 id="sources-title">Signals stay distinct.</h2>
            <div className="source-list" aria-label="Supported sources">
              {SOURCES.map((source) => (
                <div className="source-item" key={source.name}>
                  <span>{source.name}</span>
                  <small>{source.description}</small>
                </div>
              ))}
            </div>
          </aside>
        </section>

        <section className="search-workspace" aria-label="Search workspace">
          <div className="search-panel">
            <form className="search-form" onSubmit={onSubmit} role="search">
              <label htmlFor="query">
                Search by CVE, GHSA, package, product, CWE, or version
              </label>
              <div className="query-control">
                <input
                  ref={inputRef}
                  id="query"
                  name="query"
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Try CVE-2021-44228, log4j 2.14.1, npm:next, or CWE-79"
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby="query-help"
                />
                <button
                  className="primary-action"
                  type="submit"
                  disabled={state.status === "loading"}
                >
                  {state.status === "loading" ? "Searching" : "Search"}
                </button>
              </div>
              <p id="query-help" className="field-note">
                Version queries show source-backed ranges, not asset claims.
              </p>
            </form>

            <div className="example-bar" aria-label="Example searches">
              {SAMPLE_QUERIES.map((sample) => (
                <button
                  className="query-chip"
                  key={sample}
                  type="button"
                  onClick={() => void submitSearch(sample)}
                >
                  {sample}
                </button>
              ))}
            </div>
          </div>

          <section
            className="results-panel"
            aria-live="polite"
            aria-busy={state.status === "loading"}
            aria-labelledby="results-title"
          >
            <div className="results-head">
              <div>
                <p className="eyebrow">Search response</p>
                <h2 id="results-title">Evidence desk</h2>
              </div>
              {state.status !== "idle" ? (
                <button className="ghost-action" type="button" onClick={clearSearch}>
                  Clear
                </button>
              ) : null}
            </div>

            <StatusMessage state={state} query={query} />
            <SearchResults
              state={state}
              resultCount={resultCount}
              copiedId={copiedId}
              onCopy={copyIdentifier}
            />
          </section>
        </section>

        <section className="model-section" id="model" aria-labelledby="model-title">
          <div className="section-intro">
            <p className="eyebrow">Model boundary</p>
            <h2 id="model-title">It answers what public records support.</h2>
          </div>
          <div className="model-grid">
            <article>
              <h3>What it can say</h3>
              <p>
                This product or package is affected according to source records.
                These fixed versions, severity metrics, KEV, EPSS, and references
                support that answer.
              </p>
            </article>
            <article>
              <h3>What it will not say yet</h3>
              <p>
                Your asset is vulnerable. Customer assets, repositories, SBOMs,
                scanners, identities, and runtime context are intentionally outside
                this MVP.
              </p>
            </article>
            <article>
              <h3>Why the graph matters</h3>
              <p>
                CVE, GHSA, OSV, and distro identifiers resolve into one canonical
                vulnerability while preserving the source records behind each fact.
              </p>
            </article>
          </div>
        </section>
      </main>
    </>
  );
}

function ApiBadge({ state }: { state: ApiState }) {
  const label =
    state === "ready" ? "API ready" : state === "offline" ? "API offline" : "Checking API";

  return (
    <div className="api-state" data-state={state}>
      <span className="state-dot" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

function StatusMessage({
  state,
  query,
}: {
  state: SearchState;
  query: string;
}) {
  if (state.status === "loading") {
    return (
      <p className="message">
        Searching source-backed records for &quot;{query}&quot;...
      </p>
    );
  }

  if (state.status === "error") {
    return (
      <p className="message message-error">
        {state.error}. Check the database connection and try again.
      </p>
    );
  }

  return <p className="message" aria-hidden="true" />;
}

function SearchResults({
  state,
  resultCount,
  copiedId,
  onCopy,
}: {
  state: SearchState;
  resultCount: number;
  copiedId: string | null;
  onCopy: (identifier: string, rowId: string) => void;
}) {
  if (state.status === "idle") {
    return (
      <EmptyState
        kicker="Ready for a query"
        title="Start with an identifier, package, product, weakness, or version."
        body="Results will show the API interpretation, source-backed caveats, exploitability signals, affected software, and evidence counts."
      />
    );
  }

  if (state.status === "loading") {
    return <LoadingState />;
  }

  if (state.status === "error" && !state.data) {
    return (
      <EmptyState
        kicker="Search unavailable"
        title="The interface is ready, but the API did not return results."
        body="Try a sample query again once the database connection is available."
      />
    );
  }

  const data = state.data;
  if (!data || resultCount === 0) {
    return (
      <>
        {data ? <ResponseContext response={data} /> : null}
        <EmptyState
          kicker="No source-backed match"
          title="No vulnerability records matched this query."
          body="Try a CVE, GHSA, package URL, ecosystem package shorthand, product name, or CWE identifier."
        />
      </>
    );
  }

  return (
    <>
      <ResponseContext response={data} />
      {data.sections.map((section) => (
        <section className="result-section" key={section.key}>
          <div className="section-title-row">
            <div>
              <h3>{section.title}</h3>
              <p>{section.reason}</p>
            </div>
            <span className="confidence">{section.results.length}</span>
          </div>
          <div className="result-list">
            {section.results.map((result) => (
              <ResultCard
                key={`${section.key}-${result.id}`}
                result={result}
                copied={copiedId === `${section.key}-${result.id}`}
                onCopy={(identifier) => onCopy(identifier, `${section.key}-${result.id}`)}
              />
            ))}
          </div>
        </section>
      ))}
    </>
  );
}

function ResponseContext({ response }: { response: SearchResponse }) {
  return (
    <>
      <div className="interpretation" aria-label="Search interpretation">
        <Pill label="Intent" value={readable(response.interpretation.intent)} />
        <Pill label="Confidence" value={readable(response.interpretation.confidence)} />
        <Pill label="Interpreted as" value={response.interpretation.interpretedAs} />
        {response.interpretation.extracted.identifier ? (
          <Pill label="Identifier" value={response.interpretation.extracted.identifier} />
        ) : null}
        {response.interpretation.extracted.version ? (
          <Pill label="Version" value={response.interpretation.extracted.version} />
        ) : null}
        {response.interpretation.extracted.weakness ? (
          <Pill label="Weakness" value={response.interpretation.extracted.weakness} />
        ) : null}
      </div>

      {response.caveats.length ? (
        <div className="caveats" aria-label="Search caveats">
          {response.caveats.map((caveat) => (
            <div className="caveat" key={caveat}>
              {caveat}
            </div>
          ))}
        </div>
      ) : null}

      {response.selectedTarget ? (
        <TargetCard
          target={response.selectedTarget}
          alternates={response.alternateTargets}
        />
      ) : null}
    </>
  );
}

function Pill({ label, value }: { label: string; value: string }) {
  return (
    <span className="pill">
      {label} <strong>{value}</strong>
    </span>
  );
}

function TargetCard({
  target,
  alternates,
}: {
  target: TargetCandidate;
  alternates: TargetCandidate[];
}) {
  const alternateText =
    alternates.length > 0
      ? `${alternates.length} alternate target${alternates.length === 1 ? "" : "s"} found`
      : "No alternate targets";

  return (
    <div className="target-card">
      <div className="target-row">
        <div>
          <div className="target-type">
            {target.type} matched by {target.matchedBy}
          </div>
          <p className="target-label">{target.label}</p>
          <p className="target-subtitle">{target.subtitle ?? alternateText}</p>
        </div>
        <span className="confidence">{readable(target.confidence)}</span>
      </div>
    </div>
  );
}

function ResultCard({
  result,
  copied,
  onCopy,
}: {
  result: VulnerabilityResult;
  copied: boolean;
  onCopy: (identifier: string) => void;
}) {
  const identifier = result.primaryIdentifier ?? result.id;
  const severity = result.severity.maxCvssSeverity ?? "Unknown";
  const severityTone = severity.toLowerCase();
  const score =
    typeof result.severity.maxCvssScore === "number"
      ? result.severity.maxCvssScore.toFixed(1)
      : "No score";
  const epssScore =
    typeof result.exploitSignals.epssScore === "number"
      ? `${Math.round(result.exploitSignals.epssScore * 1000) / 10}%`
      : "No EPSS";
  const epssPercentile =
    typeof result.exploitSignals.epssPercentile === "number"
      ? `${Math.round(result.exploitSignals.epssPercentile * 100)}th`
      : "No percentile";
  const products = result.affectedSoftware.products.map((product) =>
    [product.vendor, product.name].filter(Boolean).join(" "),
  );
  const packages = result.affectedSoftware.packages.map(
    (pkg) => `${pkg.ecosystem}:${pkg.name}`,
  );
  const fixedVersions = result.affectedSoftware.fixedVersions.map(
    (version) => `fixed ${version}`,
  );

  return (
    <article className="result-card">
      <div className="result-title-row">
        <div className="identifier-group">
          <span className="identifier">{identifier}</span>
          <h3>{result.title ?? result.summary ?? "Untitled vulnerability record"}</h3>
        </div>
        <button
          className="copy-button"
          type="button"
          onClick={() => onCopy(identifier)}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>

      {result.summary ? <p className="result-summary">{result.summary}</p> : null}

      <div className="result-metrics" aria-label="Exploitability and evidence metrics">
        <Metric
          label="CVSS"
          value={`${score} ${severity}`}
          severityTone={severityTone}
        />
        <Metric
          label="Known exploited"
          value={result.exploitSignals.knownExploited ? "Yes, via KEV" : "No KEV signal"}
        />
        <Metric label="EPSS" value={`${epssScore} | ${epssPercentile}`} />
        <Metric
          label="Evidence"
          value={`${result.evidence.sourceRecordCount} records | ${result.evidence.referenceCount} refs`}
        />
      </div>

      <div className="software-grid">
        <TagBlock title="Affected products" values={products} />
        <TagBlock title="Affected packages" values={packages} />
      </div>

      <div className="evidence-block">
        <h4>Evidence and fixes</h4>
        <div className="tag-list">
          <Tags values={result.evidence.sources} emptyLabel="No source names returned" />
          <Tags values={fixedVersions} emptyLabel="No fixed versions returned" />
        </div>
      </div>
    </article>
  );
}

function Metric({
  label,
  value,
  severityTone,
}: {
  label: string;
  value: string;
  severityTone?: string;
}) {
  return (
    <div className="metric">
      <span className="metric-label">{label}</span>
      <span className="metric-value" data-severity={severityTone}>
        {value}
      </span>
    </div>
  );
}

function TagBlock({ title, values }: { title: string; values: string[] }) {
  return (
    <div className="software-block">
      <h4>{title}</h4>
      <div className="tag-list">
        <Tags values={values} emptyLabel="No source-backed rows returned" />
      </div>
    </div>
  );
}

function Tags({
  values,
  emptyLabel,
}: {
  values: string[];
  emptyLabel: string;
}) {
  const normalized = values.filter(Boolean);
  if (!normalized.length) {
    return (
      <span className="tag" data-muted="true">
        {emptyLabel}
      </span>
    );
  }

  const visible = normalized.slice(0, 5);
  const remaining = normalized.length - visible.length;

  return (
    <>
      {visible.map((value) => (
        <span className="tag" key={value}>
          {value}
        </span>
      ))}
      {remaining > 0 ? (
        <span className="tag" data-muted="true">
          +{remaining} more
        </span>
      ) : null}
    </>
  );
}

function LoadingState() {
  return (
    <div className="skeleton" aria-label="Loading search results">
      <div className="skeleton-line short" />
      <div className="skeleton-line medium" />
      <div className="skeleton-block" />
      <div className="skeleton-block" />
    </div>
  );
}

function EmptyState({
  kicker,
  title,
  body,
}: {
  kicker: string;
  title: string;
  body: string;
}) {
  return (
    <div className="empty-state">
      <p className="empty-kicker">{kicker}</p>
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}

function readable(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

async function checkHealth(setApiState: (state: ApiState) => void) {
  try {
    const response = await fetch("/health", {
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error("Health check failed");
    }
    setApiState("ready");
  } catch {
    setApiState("offline");
  }
}
