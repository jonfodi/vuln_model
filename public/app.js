const form = document.querySelector("#search-form");
const input = document.querySelector("#query-input");
const button = document.querySelector("#search-button");
const clearButton = document.querySelector("#clear-button");
const resultsRoot = document.querySelector("#results-root");
const resultsPanel = document.querySelector(".results-panel");
const message = document.querySelector("#search-message");
const apiState = document.querySelector("#api-state");
const apiStateLabel = document.querySelector("#api-state-label");

const MAX_TAGS = 5;

const demoQueries = document.querySelectorAll("[data-query]");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runSearch(input.value);
});

clearButton.addEventListener("click", () => {
  input.value = "";
  history.replaceState({}, "", window.location.pathname);
  clearButton.hidden = true;
  setMessage("");
  renderEmptyState();
  input.focus();
});

demoQueries.forEach((chip) => {
  chip.addEventListener("click", () => {
    const query = chip.getAttribute("data-query") || "";
    input.value = query;
    runSearch(query);
  });
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) {
    return;
  }

  const active = document.activeElement;
  const isTyping =
    active instanceof HTMLInputElement ||
    active instanceof HTMLTextAreaElement ||
    active?.isContentEditable;

  if (isTyping) {
    return;
  }

  event.preventDefault();
  input.focus();
});

checkHealth();
hydrateFromUrl();

async function checkHealth() {
  try {
    const response = await fetch("/health", { headers: { accept: "application/json" } });
    if (!response.ok) {
      throw new Error("Health check failed");
    }
    apiState.dataset.state = "ok";
    apiStateLabel.textContent = "API ready";
  } catch {
    apiState.dataset.state = "error";
    apiStateLabel.textContent = "API offline";
  }
}

function hydrateFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const query = params.get("q") || params.get("query");
  if (!query) {
    return;
  }

  input.value = query;
  runSearch(query, { replaceUrl: false });
}

async function runSearch(rawQuery, options = {}) {
  const query = rawQuery.trim();
  if (!query) {
    setMessage("Please enter a vulnerability, package, product, weakness, or version.", "error");
    input.focus();
    return;
  }

  const replaceUrl = options.replaceUrl !== false;
  if (replaceUrl) {
    const params = new URLSearchParams({ q: query });
    history.replaceState({}, "", `${window.location.pathname}?${params.toString()}`);
  }

  setLoading(true);
  renderLoadingState();
  setMessage(`Searching source-backed records for "${query}"...`);

  try {
    const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=12`, {
      headers: { accept: "application/json" },
    });
    const body = await response.json().catch(() => null);

    if (!response.ok) {
      throw new Error(body?.message || "Search failed");
    }

    renderSearchResponse(body);
    setMessage("");
    clearButton.hidden = false;
  } catch (error) {
    renderErrorState(error);
    setMessage("We could not reach the search API. Check the server and try again.", "error");
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  resultsPanel.setAttribute("aria-busy", String(isLoading));
  button.disabled = isLoading;
  button.textContent = isLoading ? "Searching" : "Search";
}

function setMessage(value, tone = "") {
  message.textContent = value;
  if (tone) {
    message.dataset.tone = tone;
  } else {
    delete message.dataset.tone;
  }
}

function renderEmptyState() {
  resultsRoot.innerHTML = `
    <div class="empty-state">
      <p class="empty-kicker">Ready for a query</p>
      <h3>Start with an identifier, package, product, weakness, or version.</h3>
      <p>Results will show the API interpretation, source-backed caveats, exploitability signals, affected software, and evidence counts.</p>
    </div>
  `;
}

function renderLoadingState() {
  resultsRoot.innerHTML = `
    <div class="skeleton" aria-label="Loading search results">
      <div class="skeleton-line short"></div>
      <div class="skeleton-line medium"></div>
      <div class="skeleton-block"></div>
      <div class="skeleton-block"></div>
    </div>
  `;
}

function renderErrorState(error) {
  const detail = error instanceof Error ? error.message : "Search failed";
  resultsRoot.innerHTML = `
    <div class="empty-state">
      <p class="empty-kicker">Search unavailable</p>
      <h3>The interface is ready, but the API did not return results.</h3>
      <p>${escapeHtml(detail)}. Try a sample query again once the database connection is available.</p>
    </div>
  `;
}

function renderSearchResponse(response) {
  const sections = Array.isArray(response.sections) ? response.sections : [];

  if (sections.length === 0) {
    resultsRoot.innerHTML = [
      renderInterpretation(response),
      renderCaveats(response.caveats),
      `
        <div class="empty-state">
          <p class="empty-kicker">No source-backed match</p>
          <h3>No vulnerability records matched this query.</h3>
          <p>Try a CVE, GHSA, package URL, ecosystem package shorthand, product name, or CWE identifier.</p>
        </div>
      `,
    ].join("");
    return;
  }

  resultsRoot.innerHTML = [
    renderInterpretation(response),
    renderCaveats(response.caveats),
    renderTarget(response.selectedTarget, response.alternateTargets),
    sections.map(renderSection).join(""),
  ].join("");

  resultsRoot.querySelectorAll("[data-copy]").forEach((copyButton) => {
    copyButton.addEventListener("click", async () => {
      const value = copyButton.getAttribute("data-copy") || "";
      try {
        await navigator.clipboard.writeText(value);
        copyButton.textContent = "Copied";
        setTimeout(() => {
          copyButton.textContent = "Copy";
        }, 1300);
      } catch {
        copyButton.textContent = "Copy failed";
      }
    });
  });
}

function renderInterpretation(response) {
  const interpretation = response.interpretation || {};
  const extracted = interpretation.extracted || {};
  const parts = [
    ["Intent", readable(interpretation.intent)],
    ["Confidence", readable(interpretation.confidence)],
    ["Interpreted as", interpretation.interpretedAs],
    ["Identifier", extracted.identifier],
    ["Package", extracted.packageName],
    ["Product", extracted.productName],
    ["Version", extracted.version],
    ["Weakness", extracted.weakness],
  ].filter(([, value]) => value);

  return `
    <div class="interpretation" aria-label="Search interpretation">
      ${parts.map(([label, value]) => `<span class="pill">${escapeHtml(label)} <strong>${escapeHtml(value)}</strong></span>`).join("")}
    </div>
  `;
}

function renderCaveats(caveats) {
  if (!Array.isArray(caveats) || caveats.length === 0) {
    return "";
  }

  return `
    <div class="caveats" aria-label="Search caveats">
      ${caveats.map((caveat) => `<div class="caveat">${escapeHtml(caveat)}</div>`).join("")}
    </div>
  `;
}

function renderTarget(target, alternates = []) {
  if (!target) {
    return "";
  }

  const alternateText = Array.isArray(alternates) && alternates.length > 0
    ? `${alternates.length} alternate target${alternates.length === 1 ? "" : "s"} found`
    : "No alternate targets";

  return `
    <div class="target-card">
      <div class="target-row">
        <div>
          <div class="target-type">${escapeHtml(target.type || "target")} matched by ${escapeHtml(target.matchedBy || "text")}</div>
          <p class="target-label">${escapeHtml(target.label || "Selected target")}</p>
          <p class="target-subtitle">${escapeHtml(target.subtitle || alternateText)}</p>
        </div>
        <span class="confidence">${escapeHtml(readable(target.confidence || "unknown"))}</span>
      </div>
    </div>
  `;
}

function renderSection(section) {
  const results = Array.isArray(section.results) ? section.results : [];

  return `
    <section class="result-section" aria-labelledby="${escapeHtml(sectionId(section.key))}">
      <div class="section-title-row">
        <div>
          <h3 id="${escapeHtml(sectionId(section.key))}">${escapeHtml(section.title || "Results")}</h3>
          <p>${escapeHtml(section.reason || "These records matched the query.")}</p>
        </div>
        <span class="confidence">${results.length}</span>
      </div>
      <div class="result-list">
        ${results.map(renderResult).join("")}
      </div>
    </section>
  `;
}

function renderResult(result) {
  const identifier = result.primaryIdentifier || result.id || "Unknown identifier";
  const severity = result.severity || {};
  const exploit = result.exploitSignals || {};
  const affected = result.affectedSoftware || {};
  const evidence = result.evidence || {};
  const severityLabel = severity.maxCvssSeverity || "Unknown";
  const severityTone = String(severityLabel).toLowerCase();
  const score = typeof severity.maxCvssScore === "number" ? severity.maxCvssScore.toFixed(1) : "No score";
  const epssScore = typeof exploit.epssScore === "number" ? `${Math.round(exploit.epssScore * 1000) / 10}%` : "No EPSS";
  const epssPercentile = typeof exploit.epssPercentile === "number" ? `${Math.round(exploit.epssPercentile * 100)}th` : "No percentile";
  const products = Array.isArray(affected.products) ? affected.products : [];
  const packages = Array.isArray(affected.packages) ? affected.packages : [];
  const fixedVersions = Array.isArray(affected.fixedVersions) ? affected.fixedVersions : [];
  const sources = Array.isArray(evidence.sources) ? evidence.sources : [];

  return `
    <article class="result-card">
      <div class="result-title-row">
        <div class="identifier-group">
          <span class="identifier">${escapeHtml(identifier)}</span>
          <h3>${escapeHtml(result.title || result.summary || "Untitled vulnerability record")}</h3>
        </div>
        <button class="copy-button" type="button" data-copy="${escapeHtml(identifier)}">Copy</button>
      </div>
      ${result.summary ? `<p class="result-summary">${escapeHtml(result.summary)}</p>` : ""}
      <div class="result-metrics" aria-label="Exploitability and evidence metrics">
        <div class="metric">
          <span class="metric-label">CVSS</span>
          <span class="metric-value" data-severity="${escapeHtml(severityTone)}">${escapeHtml(score)} ${escapeHtml(severityLabel)}</span>
        </div>
        <div class="metric">
          <span class="metric-label">Known exploited</span>
          <span class="metric-value">${exploit.knownExploited ? "Yes, via KEV" : "No KEV signal"}</span>
        </div>
        <div class="metric">
          <span class="metric-label">EPSS</span>
          <span class="metric-value">${escapeHtml(epssScore)} · ${escapeHtml(epssPercentile)}</span>
        </div>
        <div class="metric">
          <span class="metric-label">Evidence</span>
          <span class="metric-value">${Number(evidence.sourceRecordCount || 0)} records · ${Number(evidence.referenceCount || 0)} refs</span>
        </div>
      </div>
      <div class="software-grid">
        ${renderSoftwareBlock("Affected products", products.map((item) => [item.vendor, item.name].filter(Boolean).join(" ")))}
        ${renderSoftwareBlock("Affected packages", packages.map((item) => `${item.ecosystem}:${item.name}`))}
      </div>
      <div class="evidence-block">
        <h4>Evidence and fixes</h4>
        <div class="tag-list">
          ${renderTags(sources, "No source names returned")}
          ${renderTags(fixedVersions.map((version) => `fixed ${version}`), "No fixed versions returned")}
        </div>
      </div>
    </article>
  `;
}

function renderSoftwareBlock(title, values) {
  return `
    <div class="software-block">
      <h4>${escapeHtml(title)}</h4>
      <div class="tag-list">
        ${renderTags(values, "No source-backed rows returned")}
      </div>
    </div>
  `;
}

function renderTags(values, emptyLabel) {
  const normalized = values.filter(Boolean);
  if (normalized.length === 0) {
    return `<span class="tag" data-muted="true">${escapeHtml(emptyLabel)}</span>`;
  }

  const visible = normalized.slice(0, MAX_TAGS);
  const remaining = normalized.length - visible.length;
  return [
    ...visible.map((value) => `<span class="tag">${escapeHtml(value)}</span>`),
    remaining > 0 ? `<span class="tag" data-muted="true">+${remaining} more</span>` : "",
  ].join("");
}

function readable(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function sectionId(value) {
  return `section-${String(value || "results").replace(/[^a-z0-9_-]/gi, "-")}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
