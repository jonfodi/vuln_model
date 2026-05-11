"use client";

import { FormEvent, useMemo, useState } from "react";
import type { SearchResponse, VulnerabilityResult } from "../src/api/types";

type SearchState =
  | { status: "idle"; data?: undefined; error?: undefined }
  | { status: "loading"; data?: SearchResponse; error?: undefined }
  | { status: "success"; data: SearchResponse; error?: undefined }
  | { status: "error"; data?: SearchResponse; error: string };

const SAMPLE_QUERIES = ["log4j", "react", "CWE-79", "CVE-2021-44228"];

export function SearchClient() {
  const [query, setQuery] = useState("");
  const [state, setState] = useState<SearchState>({ status: "idle" });

  async function submit(nextQuery = query) {
    const trimmed = nextQuery.trim();
    if (!trimmed) {
      setState({ status: "error", error: "Enter a search query." });
      return;
    }

    setQuery(trimmed);
    setState((current) => ({ status: "loading", data: current.data }));

    try {
      const response = await fetch(
        `/api/search?q=${encodeURIComponent(trimmed)}&limit=12`,
        { headers: { accept: "application/json" } },
      );
      const body = (await response.json()) as unknown;

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
        error: error instanceof Error ? error.message : "Search failed.",
      });
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submit();
  }

  const results = useMemo(() => flattenResults(state.data), [state.data]);
  const selectedTarget = state.data?.selectedTarget;

  return (
    <main className="app-shell">
      <section className="workspace">
        <aside className="sidebar">
          <div>
            <p className="eyebrow">Source-backed graph</p>
            <h1>Vulnerability Intelligence</h1>
          </div>

          <dl className="metric-list" aria-label="Search metadata">
            <div>
              <dt>Intent</dt>
              <dd>{state.data?.interpretation.intent ?? "None"}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{state.data?.interpretation.confidence ?? "None"}</dd>
            </div>
            <div>
              <dt>Results</dt>
              <dd>{results.length}</dd>
            </div>
          </dl>

          {selectedTarget ? (
            <div className="target-panel">
              <span className="panel-label">Selected Target</span>
              <strong>{selectedTarget.label}</strong>
              <span>{selectedTarget.subtitle ?? selectedTarget.type}</span>
            </div>
          ) : null}
        </aside>

        <section className="main-panel">
          <form className="search-form" onSubmit={onSubmit}>
            <label htmlFor="query">Search</label>
            <div className="search-row">
              <input
                id="query"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="CVE-2021-44228, log4j, react"
                autoComplete="off"
              />
              <button type="submit" disabled={state.status === "loading"}>
                {state.status === "loading" ? "Searching" : "Search"}
              </button>
            </div>
          </form>

          <div className="sample-row" aria-label="Sample searches">
            {SAMPLE_QUERIES.map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => void submit(sample)}
              >
                {sample}
              </button>
            ))}
          </div>

          {state.status === "error" ? (
            <div className="notice error">{state.error}</div>
          ) : null}

          {state.data?.caveats.length ? (
            <div className="notice">
              {state.data.caveats.map((caveat) => (
                <p key={caveat}>{caveat}</p>
              ))}
            </div>
          ) : null}

          <section className="results" aria-live="polite">
            {state.status === "idle" ? (
              <EmptyState />
            ) : results.length ? (
              results.map((result) => (
                <ResultCard key={result.id} result={result} />
              ))
            ) : state.status === "loading" ? (
              <EmptyState label="Loading results" />
            ) : (
              <EmptyState label="No results" />
            )}
          </section>
        </section>
      </section>
    </main>
  );
}

function flattenResults(response: SearchResponse | undefined) {
  const unique = new Map<string, VulnerabilityResult>();

  for (const section of response?.sections ?? []) {
    for (const result of section.results) {
      unique.set(result.id, result);
    }
  }

  return [...unique.values()];
}

function ResultCard({ result }: { result: VulnerabilityResult }) {
  const severity = result.severity.maxCvssSeverity ?? "Unknown";
  const score = result.severity.maxCvssScore;

  return (
    <article className="result-card">
      <div className="result-header">
        <div>
          <a href={result.url} target="_blank" rel="noreferrer">
            {result.primaryIdentifier ?? "Unidentified vulnerability"}
          </a>
          <h2>{result.title ?? result.summary ?? "Untitled record"}</h2>
        </div>
        <span className={`severity severity-${severity.toLowerCase()}`}>
          {score ? `${severity} ${score}` : severity}
        </span>
      </div>

      {result.summary ? <p>{result.summary}</p> : null}

      <div className="fact-grid">
        <div>
          <span>Known exploited</span>
          <strong>{result.exploitSignals.knownExploited ? "Yes" : "No"}</strong>
        </div>
        <div>
          <span>EPSS</span>
          <strong>
            {typeof result.exploitSignals.epssScore === "number"
              ? `${Math.round(result.exploitSignals.epssScore * 100)}%`
              : "None"}
          </strong>
        </div>
        <div>
          <span>Sources</span>
          <strong>{result.evidence.sourceRecordCount}</strong>
        </div>
      </div>

      <div className="software-list">
        {result.affectedSoftware.packages.slice(0, 4).map((pkg) => (
          <span key={pkg.id}>
            {pkg.ecosystem}:{pkg.name}
          </span>
        ))}
        {result.affectedSoftware.products.slice(0, 4).map((product) => (
          <span key={product.id}>
            {[product.vendor, product.name].filter(Boolean).join(" ")}
          </span>
        ))}
      </div>
    </article>
  );
}

function EmptyState({ label = "No query" }: { label?: string }) {
  return (
    <div className="empty-state">
      <div className="pulse-mark" />
      <strong>{label}</strong>
    </div>
  );
}
