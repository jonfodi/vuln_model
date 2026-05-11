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
  "Log4Shell",
  "Next.js",
  "chrome known exploited",
  "log4j 2.14.1",
  "npm:next",
];

const SOURCE_NAMES = ["OSV", "CVE List", "CISA KEV", "FIRST EPSS"];

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

  const hasSearched = state.status !== "idle";
  const displayedQuery = state.data?.query ?? query.trim();

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
      focusSearch();
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
        error: "Enter a package, product, version, advisory ID, or weakness name.",
      });
      focusSearch();
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
        setState({ status: "error", data: state.data, error: message });
        return;
      }

      setState({ status: "success", data: body as SearchResponse });
    } catch (error) {
      setState({
        status: "error",
        data: state.data,
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

  function focusSearch() {
    inputRef.current?.focus();
    inputRef.current?.select();
  }

  function resetSearch() {
    setQuery("");
    setState({ status: "idle" });
    window.history.replaceState({}, "", window.location.pathname);
    window.setTimeout(focusSearch, 0);
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
          <span className="brand-name">Vulnerability Intelligence</span>
        </a>
        <div className="header-actions">
          <a href="/api/search?q=log4j">API</a>
          <ApiBadge state={apiState} />
        </div>
      </header>

      <main id="main-content" className={hasSearched ? "has-results" : undefined}>
        <section className="search-hero" aria-labelledby="page-title">
          <div className="hero-copy">
            <p className="eyebrow">Evidence-backed vulnerability intelligence</p>
            <h1 id="page-title">Software risk, decoded.</h1>
            <p className="hero-text">
              Search packages, products, versions, and advisories. See affected
              software, fixes, exploitation signals, and source evidence in one view.
            </p>
          </div>

          <form className="search-form" onSubmit={onSubmit} role="search">
            <div className="search-panel">
              <label htmlFor="query">Investigate a package, product, version, or advisory</label>
              <div className="query-control">
                <input
                  ref={inputRef}
                  id="query"
                  name="query"
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Try Log4Shell, Next.js, chrome known exploited, npm:next"
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby="source-strip"
                />
                <button
                  className="primary-action"
                  type="submit"
                  disabled={state.status === "loading"}
                >
                  {state.status === "loading" ? "Analyzing" : "Analyze"}
                </button>
              </div>
              <div id="source-strip" className="source-strip" aria-label="Evidence sources">
                <span>Signals from</span>
                {SOURCE_NAMES.map((source) => (
                  <span className="source-pill" key={source}>
                    {source}
                  </span>
                ))}
              </div>
            </div>
          </form>

          {!hasSearched ? (
            <div className="example-bar" aria-label="Example searches">
              <span className="example-label">Quick starts</span>
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
          ) : null}
        </section>

        {hasSearched ? (
          <section
            className="results-region"
            aria-live="polite"
            aria-busy={state.status === "loading"}
            aria-labelledby="results-title"
          >
            <div className="results-head">
              <div>
                <p className="eyebrow">Results</p>
                <h2 id="results-title">
                  {resultsHeading(state, resultCount, displayedQuery)}
                </h2>
              </div>
              <div className="results-actions">
                <button className="text-action" type="button" onClick={focusSearch}>
                  Run another search <kbd>/</kbd>
                </button>
                <button className="ghost-action" type="button" onClick={resetSearch}>
                  Reset
                </button>
              </div>
            </div>

            <StatusMessage state={state} query={displayedQuery} />
            <SearchResults
              state={state}
              resultCount={resultCount}
              copiedId={copiedId}
              onCopy={copyIdentifier}
            />
          </section>
        ) : null}
      </main>
    </>
  );
}

function ApiBadge({ state }: { state: ApiState }) {
  const label =
    state === "ready" ? "Ready" : state === "offline" ? "Offline" : "Checking";

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
    return <p className="message">Searching &quot;{query}&quot;...</p>;
  }

  if (state.status === "error") {
    return <p className="message message-error">{state.error}</p>;
  }

  return null;
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
  if (state.status === "loading") {
    return <LoadingState />;
  }

  const data = state.data;
  if (!data || resultCount === 0) {
    return (
      <>
        {data ? <ResponseContext response={data} /> : null}
        <EmptyState />
      </>
    );
  }

  return (
    <>
      <ResponseContext response={data} />
      <div className="result-list">
        {data.sections.flatMap((section) =>
          section.results.map((result) => (
            <ResultCard
              key={`${section.key}-${result.id}`}
              result={result}
              sectionTitle={section.title}
              copied={copiedId === `${section.key}-${result.id}`}
              onCopy={(identifier) => onCopy(identifier, `${section.key}-${result.id}`)}
            />
          )),
        )}
      </div>
    </>
  );
}

function ResponseContext({ response }: { response: SearchResponse }) {
  const interpretation = response.interpretation.interpretedAs;

  return (
    <div className="response-context">
      <div className="interpretation" aria-label="Search interpretation">
        <span>
          Interpreted as <strong>{interpretation}</strong>
        </span>
        {response.selectedTarget ? <TargetSummary target={response.selectedTarget} /> : null}
      </div>

    </div>
  );
}

function TargetSummary({ target }: { target: TargetCandidate }) {
  return (
    <span>
      Matched {target.type} <strong>{target.label}</strong>
    </span>
  );
}

function ResultCard({
  result,
  sectionTitle,
  copied,
  onCopy,
}: {
  result: VulnerabilityResult;
  sectionTitle: string;
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
      ? `${Math.round(result.exploitSignals.epssPercentile * 100)}th percentile`
      : null;
  const products = result.affectedSoftware.products.map((product) =>
    [product.vendor, product.name].filter(Boolean).join(" "),
  );
  const packages = result.affectedSoftware.packages.map(
    (pkg) => `${pkg.ecosystem}:${pkg.name}`,
  );
  const fixedVersions = result.affectedSoftware.fixedVersions.map(
    (version) => `Fixed ${version}`,
  );
  const evidenceTags = [...result.evidence.sources, ...fixedVersions];

  return (
    <article className="result-card">
      <div className="result-title-row">
        <div className="identifier-group">
          <span className="section-label">{sectionTitle}</span>
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
          label="KEV"
          value={result.exploitSignals.knownExploited ? "Known exploited" : "No signal"}
        />
        <Metric
          label="EPSS"
          value={epssPercentile ? `${epssScore}, ${epssPercentile}` : epssScore}
        />
        <Metric
          label="Evidence"
          value={`${result.evidence.sourceRecordCount} records, ${result.evidence.referenceCount} refs`}
        />
      </div>

      <div className="software-grid">
        <TagBlock title="Products" values={products} />
        <TagBlock title="Packages" values={packages} />
      </div>

      {evidenceTags.length ? (
        <div className="evidence-block">
          <h4>Sources and fixes</h4>
          <div className="tag-list">
            <Tags values={evidenceTags} />
          </div>
        </div>
      ) : null}
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
  const normalized = values.filter(Boolean);
  if (!normalized.length) {
    return null;
  }

  return (
    <div className="software-block">
      <h4>{title}</h4>
      <div className="tag-list">
        <Tags values={normalized} />
      </div>
    </div>
  );
}

function Tags({ values }: { values: string[] }) {
  const normalized = values.filter(Boolean);
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

function EmptyState() {
  return (
    <div className="empty-state">
      <h3>No matches for this query.</h3>
      <p>Try a package, product, version, advisory ID, or weakness name.</p>
    </div>
  );
}

function resultsHeading(
  state: SearchState,
  resultCount: number,
  displayedQuery: string,
) {
  if (state.status === "loading") {
    return `Searching "${displayedQuery}"`;
  }

  if (resultCount === 0) {
    return `No results for "${displayedQuery}"`;
  }

  return `${resultCount} result${resultCount === 1 ? "" : "s"} for "${displayedQuery}"`;
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
