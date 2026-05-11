import { sql } from "drizzle-orm";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import * as schema from "../db/schema";
import { interpretSearchQuery } from "./interpreter";
import type {
  SearchConfidence,
  SearchRequest,
  SearchResponse,
  SearchResultSection,
  SearchSpec,
  TargetCandidate,
  VulnerabilityResult,
} from "./types";

type SearchDb = PostgresJsDatabase<typeof schema>;

type CandidateRow = {
  type: TargetCandidate["type"];
  id: string;
  label: string;
  subtitle: string | null;
  matched_by: TargetCandidate["matchedBy"];
  confidence: SearchConfidence;
  sort_weight: number;
};

type VulnerabilityIdRow = {
  id: string;
};

type VulnerabilityRow = {
  id: string;
  primary_identifier: string | null;
  title: string | null;
  summary: string | null;
  updated_at: string | null;
  aliases: string[] | null;
  max_cvss_score: number | string | null;
  max_cvss_severity: string | null;
  known_exploited: boolean | null;
  epss_score: number | string | null;
  epss_percentile: number | string | null;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
  products: unknown;
  packages: unknown;
  fixed_versions: string[] | null;
  sources: string[] | null;
  source_record_count: number | string | null;
  reference_count: number | string | null;
};

export async function runSearch(
  db: SearchDb,
  request: SearchRequest,
): Promise<SearchResponse> {
  const limit = clampLimit(request.limit);
  const query = request.query.trim();
  const spec = interpretSearchQuery(query);
  const candidates = await findCandidates(db, spec, limit);
  const selectedTarget = selectTarget(candidates);
  const alternateTargets = candidates.filter(
    (candidate) =>
      !selectedTarget ||
      candidate.id !== selectedTarget.id ||
      candidate.type !== selectedTarget.type,
  );
  const caveats: string[] = [];

  if (spec.extracted.version) {
    caveats.push(
      "Version-specific affectedness is not evaluated yet; results show source-backed affected software and fixed versions.",
    );
  }

  if (!selectedTarget && candidates.length > 1) {
    caveats.push(
      "Several possible targets matched the query; results use broader text matching.",
    );
  }

  const vulnerabilityIds = selectedTarget
    ? await findVulnerabilityIdsForTarget(db, selectedTarget, limit)
    : await findTextMatchedVulnerabilityIds(db, spec, limit);
  let results = await hydrateVulnerabilityResults(db, {
    ids: vulnerabilityIds,
    matchedOn: selectedTarget
      ? matchedOnForTarget(selectedTarget)
      : {
          type: spec.extracted.identifier ? "identifier" : "text",
          label: spec.extracted.identifier ?? spec.interpretedAs,
        },
    version: spec.extracted.version,
  });

  results = applyInternalConstraints(results, spec);
  results = stubSort(results).slice(0, limit);

  if (results.length === 0) {
    caveats.push("No source-backed vulnerability records matched this query.");
  }

  return {
    query,
    interpretation: {
      intent: spec.intent,
      confidence: spec.confidence,
      interpretedAs: spec.interpretedAs,
      extracted: spec.extracted,
    },
    selectedTarget,
    alternateTargets,
    sections: buildSections({
      spec,
      selectedTarget,
      results,
    }),
    caveats,
    execution: {
      strategy: executionStrategy(spec, selectedTarget),
      ranker: "stub",
      interpreter: "deterministic",
    },
  };
}

function clampLimit(value: number | undefined) {
  if (!value || !Number.isFinite(value)) {
    return 20;
  }

  return Math.min(Math.max(Math.floor(value), 1), 50);
}

async function findCandidates(
  db: SearchDb,
  spec: SearchSpec,
  limit: number,
): Promise<TargetCandidate[]> {
  const rows: CandidateRow[] = [];

  if (spec.extracted.identifier) {
    rows.push(
      ...(await findIdentifierCandidates(db, spec.extracted.identifier, limit)),
    );
  }

  if (spec.extracted.packageName) {
    rows.push(
      ...(await findPackageCandidates(
        db,
        {
          packageName: spec.extracted.packageName,
          ecosystem: spec.extracted.ecosystem,
        },
        limit,
      )),
    );
  }

  if (spec.extracted.productName) {
    rows.push(
      ...(await findProductCandidates(db, spec.extracted.productName, limit)),
    );
  }

  if (spec.extracted.weakness) {
    rows.push(
      ...(await findWeaknessCandidates(db, spec.extracted.weakness, limit)),
    );
  }

  if (rows.length === 0 && spec.normalizedQuery) {
    rows.push(...(await findTextCandidates(db, spec.normalizedQuery, limit)));
  }

  const unique = new Map<string, TargetCandidate & { sortWeight: number }>();

  for (const row of rows) {
    const key = `${row.type}:${row.id}`;
    const existing = unique.get(key);
    if (existing && existing.sortWeight <= row.sort_weight) {
      continue;
    }

    unique.set(key, {
      type: row.type,
      id: row.id,
      label: row.label,
      subtitle: row.subtitle ?? undefined,
      matchedBy: row.matched_by,
      confidence: row.confidence,
      sortWeight: row.sort_weight,
    });
  }

  return [...unique.values()]
    .sort((a, b) => a.sortWeight - b.sortWeight || a.label.localeCompare(b.label))
    .slice(0, limit)
    .map(({ sortWeight: _sortWeight, ...candidate }) => candidate);
}

async function findIdentifierCandidates(
  db: SearchDb,
  identifier: string,
  limit: number,
) {
  return db.execute<CandidateRow>(sql`
    select
      'vulnerability'::text as type,
      v.id::text as id,
      coalesce(v.primary_identifier, i.value) as label,
      coalesce(v.title, v.summary) as subtitle,
      'identifier'::text as matched_by,
      'high'::text as confidence,
      0::int as sort_weight
    from identifiers i
    join vulnerability_identifiers vi on vi.identifier_id = i.id
    join vulnerabilities v on v.id = vi.vulnerability_id
    where i.value = ${identifier}
    order by case when vi.relationship = 'primary' then 0 else 1 end
    limit ${limit}
  `);
}

async function findPackageCandidates(
  db: SearchDb,
  input: { packageName: string; ecosystem?: string },
  limit: number,
) {
  const like = likePattern(input.packageName);
  const ecosystem = input.ecosystem ?? null;

  return db.execute<CandidateRow>(sql`
    select
      'package'::text as type,
      p.id::text as id,
      p.name as label,
      concat(e.name, case when p.purl is not null then concat(' - ', p.purl) else '' end) as subtitle,
      case when p.purl ilike ${like} then 'purl' else 'name' end as matched_by,
      case
        when lower(p.name) = lower(${input.packageName}) then 'high'
        when p.purl ilike ${like} then 'high'
        else 'medium'
      end as confidence,
      case
        when ${ecosystem}::text is not null and e.slug = ${ecosystem}::text and lower(p.name) = lower(${input.packageName}) then 0
        when lower(p.name) = lower(${input.packageName}) then 1
        when p.purl ilike ${like} then 2
        else 5
      end as sort_weight
    from packages p
    join ecosystems e on e.id = p.ecosystem_id
    where
      p.name ilike ${like}
      or p.purl ilike ${like}
    order by sort_weight, length(p.name), p.name
    limit ${limit}
  `);
}

async function findProductCandidates(
  db: SearchDb,
  productName: string,
  limit: number,
) {
  const like = likePattern(productName);

  return db.execute<CandidateRow>(sql`
    select
      'product'::text as type,
      p.id::text as id,
      p.name as label,
      p.vendor as subtitle,
      'name'::text as matched_by,
      case
        when lower(p.name) = lower(${productName}) then 'high'
        when lower(concat_ws(' ', p.vendor, p.name)) = lower(${productName}) then 'high'
        else 'medium'
      end as confidence,
      case
        when lower(p.name) = lower(${productName}) then 1
        when lower(concat_ws(' ', p.vendor, p.name)) = lower(${productName}) then 1
        else 6
      end as sort_weight
    from products p
    where
      p.name ilike ${like}
      or p.vendor ilike ${like}
      or concat_ws(' ', p.vendor, p.name) ilike ${like}
    order by sort_weight, length(coalesce(p.vendor, '') || p.name), p.name
    limit ${limit}
  `);
}

async function findWeaknessCandidates(
  db: SearchDb,
  weakness: string,
  limit: number,
) {
  const like = likePattern(weakness);

  return db.execute<CandidateRow>(sql`
    select
      'weakness'::text as type,
      w.id::text as id,
      w.cwe_id as label,
      coalesce(w.name, w.description) as subtitle,
      case when w.cwe_id = ${weakness} then 'identifier' else 'name' end as matched_by,
      case when w.cwe_id = ${weakness} then 'high' else 'medium' end as confidence,
      case when w.cwe_id = ${weakness} then 0 else 4 end as sort_weight
    from weaknesses w
    where w.cwe_id = ${weakness} or w.name ilike ${like} or w.description ilike ${like}
    order by sort_weight, w.cwe_id
    limit ${limit}
  `);
}

async function findTextCandidates(db: SearchDb, query: string, limit: number) {
  const like = likePattern(query);

  return db.execute<CandidateRow>(sql`
    (
      select
        'vulnerability'::text as type,
        v.id::text as id,
        coalesce(v.primary_identifier, v.title, v.id::text) as label,
        coalesce(v.title, v.summary) as subtitle,
        'text'::text as matched_by,
        'low'::text as confidence,
        20::int as sort_weight
      from vulnerabilities v
      where v.primary_identifier ilike ${like}
        or v.title ilike ${like}
        or v.summary ilike ${like}
      limit ${limit}
    )
    union all
    (
      select
        'package'::text as type,
        p.id::text as id,
        p.name as label,
        e.name as subtitle,
        'name'::text as matched_by,
        'medium'::text as confidence,
        10::int as sort_weight
      from packages p
      join ecosystems e on e.id = p.ecosystem_id
      where p.name ilike ${like} or p.purl ilike ${like}
      limit ${limit}
    )
    union all
    (
      select
        'product'::text as type,
        p.id::text as id,
        p.name as label,
        p.vendor as subtitle,
        'name'::text as matched_by,
        'medium'::text as confidence,
        11::int as sort_weight
      from products p
      where p.name ilike ${like} or p.vendor ilike ${like}
      limit ${limit}
    )
    order by sort_weight, label
    limit ${limit}
  `);
}

function selectTarget(candidates: TargetCandidate[]) {
  if (candidates.length === 0) {
    return undefined;
  }

  return (
    candidates.find((candidate) => candidate.type === "vulnerability") ??
    candidates.find((candidate) => candidate.confidence === "high") ??
    candidates[0]
  );
}

async function findVulnerabilityIdsForTarget(
  db: SearchDb,
  target: TargetCandidate,
  limit: number,
) {
  if (target.type === "vulnerability") {
    return [target.id];
  }

  const rows =
    target.type === "package"
      ? await db.execute<VulnerabilityIdRow>(sql`
          select distinct vr.vulnerability_id::text as id
          from affected_packages ap
          join vulnerability_records vr on vr.id = ap.vulnerability_record_id
          where ap.package_id = ${target.id}::uuid
            and vr.vulnerability_id is not null
          limit ${limit}
        `)
      : target.type === "product"
        ? await db.execute<VulnerabilityIdRow>(sql`
            select distinct vr.vulnerability_id::text as id
            from affected_products ap
            join vulnerability_records vr on vr.id = ap.vulnerability_record_id
            where ap.product_id = ${target.id}::uuid
              and vr.vulnerability_id is not null
            limit ${limit}
          `)
        : target.type === "weakness"
          ? await db.execute<VulnerabilityIdRow>(sql`
              select distinct vr.vulnerability_id::text as id
              from vulnerability_record_weaknesses vrw
              join vulnerability_records vr on vr.id = vrw.vulnerability_record_id
              where vrw.weakness_id = ${target.id}::uuid
                and vr.vulnerability_id is not null
              limit ${limit}
            `)
          : [];

  return rows.map((row) => row.id);
}

async function findTextMatchedVulnerabilityIds(
  db: SearchDb,
  spec: SearchSpec,
  limit: number,
) {
  const terms = [
    spec.extracted.identifier,
    spec.extracted.packageName,
    spec.extracted.productName,
    spec.extracted.weakness,
    spec.normalizedQuery,
  ].filter((value): value is string => Boolean(value));
  const like = likePattern(terms[0] ?? spec.normalizedQuery);

  const rows = await db.execute<VulnerabilityIdRow>(sql`
    (
      select v.id::text as id
      from vulnerabilities v
      where v.primary_identifier ilike ${like}
        or v.title ilike ${like}
        or v.summary ilike ${like}
      limit ${limit}
    )
    union
    (
      select distinct vr.vulnerability_id::text as id
      from vulnerability_records vr
      where vr.vulnerability_id is not null
        and (
          vr.record_id ilike ${like}
          or vr.summary ilike ${like}
          or vr.details ilike ${like}
        )
      limit ${limit}
    )
    union
    (
      select distinct vr.vulnerability_id::text as id
      from affected_packages ap
      join packages p on p.id = ap.package_id
      join vulnerability_records vr on vr.id = ap.vulnerability_record_id
      where vr.vulnerability_id is not null
        and p.name ilike ${like}
      limit ${limit}
    )
    union
    (
      select distinct vr.vulnerability_id::text as id
      from affected_products ap
      join products p on p.id = ap.product_id
      join vulnerability_records vr on vr.id = ap.vulnerability_record_id
      where vr.vulnerability_id is not null
        and (p.name ilike ${like} or p.vendor ilike ${like})
      limit ${limit}
    )
    limit ${limit}
  `);

  return rows.map((row) => row.id);
}

async function hydrateVulnerabilityResults(
  db: SearchDb,
  input: {
    ids: string[];
    matchedOn: VulnerabilityResult["matchedOn"];
    version?: string;
  },
): Promise<VulnerabilityResult[]> {
  if (input.ids.length === 0) {
    return [];
  }

  const selectedValues = sql.join(
    input.ids.map((id, index) => sql`(${id}::uuid, ${index}::int)`),
    sql`, `,
  );

  const rows = await db.execute<VulnerabilityRow>(sql`
    with selected(id, ord) as (
      values ${selectedValues}
    )
    select
      v.id::text as id,
      v.primary_identifier,
      v.title,
      v.summary,
      v.updated_at::text as updated_at,
      coalesce((
        select array_agg(distinct i.value order by i.value)
        from vulnerability_identifiers vi
        join identifiers i on i.id = vi.identifier_id
        where vi.vulnerability_id = v.id
      ), array[]::text[]) as aliases,
      (
        select max(sm.score)::double precision
        from vulnerability_records vr
        join severity_metrics sm on sm.vulnerability_record_id = vr.id
        where vr.vulnerability_id = v.id
      ) as max_cvss_score,
      (
        select sm.severity
        from vulnerability_records vr
        join severity_metrics sm on sm.vulnerability_record_id = vr.id
        where vr.vulnerability_id = v.id
        order by sm.score desc nulls last, sm.severity nulls last
        limit 1
      ) as max_cvss_severity,
      exists(
        select 1 from kev_entries ke where ke.vulnerability_id = v.id
      ) as known_exploited,
      (
        select es.score::double precision
        from epss_scores es
        where es.vulnerability_id = v.id
        order by es.score_date desc
        limit 1
      ) as epss_score,
      (
        select es.percentile::double precision
        from epss_scores es
        where es.vulnerability_id = v.id
        order by es.score_date desc
        limit 1
      ) as epss_percentile,
      (
        select ssvc.exploitation
        from vulnerability_records vr
        join ssvc_assessments ssvc on ssvc.vulnerability_record_id = vr.id
        where vr.vulnerability_id = v.id
        order by ssvc.assessed_at desc nulls last, ssvc.updated_at desc
        limit 1
      ) as ssvc_exploitation,
      (
        select ssvc.automatable
        from vulnerability_records vr
        join ssvc_assessments ssvc on ssvc.vulnerability_record_id = vr.id
        where vr.vulnerability_id = v.id
        order by ssvc.assessed_at desc nulls last, ssvc.updated_at desc
        limit 1
      ) as ssvc_automatable,
      (
        select ssvc.technical_impact
        from vulnerability_records vr
        join ssvc_assessments ssvc on ssvc.vulnerability_record_id = vr.id
        where vr.vulnerability_id = v.id
        order by ssvc.assessed_at desc nulls last, ssvc.updated_at desc
        limit 1
      ) as ssvc_technical_impact,
      coalesce((
        select jsonb_agg(distinct jsonb_build_object(
          'id', p.id::text,
          'vendor', p.vendor,
          'name', p.name
        ))
        from vulnerability_records vr
        join affected_products ap on ap.vulnerability_record_id = vr.id
        join products p on p.id = ap.product_id
        where vr.vulnerability_id = v.id
      ), '[]'::jsonb) as products,
      coalesce((
        select jsonb_agg(distinct jsonb_build_object(
          'id', p.id::text,
          'ecosystem', e.slug,
          'name', p.name
        ))
        from vulnerability_records vr
        join affected_packages ap on ap.vulnerability_record_id = vr.id
        join packages p on p.id = ap.package_id
        join ecosystems e on e.id = p.ecosystem_id
        where vr.vulnerability_id = v.id
      ), '[]'::jsonb) as packages,
      coalesce((
        select array_agg(distinct range.fixed order by range.fixed)
        from vulnerability_records vr
        left join affected_packages apkg on apkg.vulnerability_record_id = vr.id
        left join affected_products aprod on aprod.vulnerability_record_id = vr.id
        join version_ranges range on range.affected_package_id = apkg.id or range.affected_product_id = aprod.id
        where vr.vulnerability_id = v.id
          and range.fixed is not null
      ), array[]::text[]) as fixed_versions,
      coalesce((
        select array_agg(distinct s.name order by s.name)
        from vulnerability_records vr
        join source_records sr on sr.id = vr.source_record_id
        join sources s on s.id = sr.source_id
        where vr.vulnerability_id = v.id
      ), array[]::text[]) as sources,
      (
        select count(*)::int
        from vulnerability_records vr
        where vr.vulnerability_id = v.id
      ) as source_record_count,
      (
        select count(distinct vrr.reference_id)::int
        from vulnerability_records vr
        join vulnerability_record_references vrr on vrr.vulnerability_record_id = vr.id
        where vr.vulnerability_id = v.id
      ) as reference_count
    from selected
    join vulnerabilities v on v.id = selected.id
    order by selected.ord
  `);

  return rows.map((row) => ({
    id: row.id,
    primaryIdentifier: row.primary_identifier,
    aliases: row.aliases ?? [],
    title: row.title,
    summary: row.summary,
    url: `/vulnerabilities/${encodeURIComponent(row.primary_identifier ?? row.id)}`,
    matchedOn: input.matchedOn,
    severity: {
      maxCvssScore: toNumber(row.max_cvss_score),
      maxCvssSeverity: row.max_cvss_severity ?? undefined,
    },
    exploitSignals: {
      knownExploited: Boolean(row.known_exploited),
      epssScore: toNumber(row.epss_score),
      epssPercentile: toNumber(row.epss_percentile),
      ssvcExploitation: row.ssvc_exploitation ?? undefined,
      ssvcAutomatable: row.ssvc_automatable ?? undefined,
      ssvcTechnicalImpact: row.ssvc_technical_impact ?? undefined,
    },
    affectedSoftware: {
      products: parseProductList(row.products),
      packages: parsePackageList(row.packages),
      fixedVersions: row.fixed_versions ?? [],
      versionStatus: input.version ? "not_evaluated" : undefined,
    },
    evidence: {
      sources: row.sources ?? [],
      sourceRecordCount: toInteger(row.source_record_count),
      referenceCount: toInteger(row.reference_count),
    },
    updatedAt: row.updated_at ?? undefined,
  }));
}

function applyInternalConstraints(
  results: VulnerabilityResult[],
  spec: SearchSpec,
) {
  let filtered = results;

  if (spec.extracted.knownExploited) {
    const knownExploited = filtered.filter(
      (result) => result.exploitSignals.knownExploited,
    );
    if (knownExploited.length > 0) {
      filtered = knownExploited;
    }
  }

  const severityHint = spec.extracted.severityHint;
  if (severityHint) {
    const minRank = severityRank(severityHint);
    const severityMatches = filtered.filter(
      (result) =>
        severityRank(result.severity.maxCvssSeverity) >= minRank ||
        (result.severity.maxCvssScore ?? 0) >= scoreFloor(severityHint),
    );
    if (severityMatches.length > 0) {
      filtered = severityMatches;
    }
  }

  return filtered;
}

function stubSort(results: VulnerabilityResult[]) {
  return [...results].sort(
    (a, b) =>
      Number(b.exploitSignals.knownExploited) -
        Number(a.exploitSignals.knownExploited) ||
      (b.severity.maxCvssScore ?? -1) - (a.severity.maxCvssScore ?? -1) ||
      Date.parse(b.updatedAt ?? "0") - Date.parse(a.updatedAt ?? "0") ||
      (a.primaryIdentifier ?? a.id).localeCompare(b.primaryIdentifier ?? b.id),
  );
}

function buildSections(input: {
  spec: SearchSpec;
  selectedTarget?: TargetCandidate;
  results: VulnerabilityResult[];
}): SearchResultSection[] {
  if (input.results.length === 0) {
    return [];
  }

  if (input.selectedTarget?.type === "vulnerability") {
    return [
      {
        key: "exact_matches",
        title: "Exact vulnerability match",
        reason: "The query resolved to a known vulnerability identifier.",
        results: input.results,
      },
    ];
  }

  const sections: SearchResultSection[] = [];
  const knownExploited = input.results.filter(
    (result) => result.exploitSignals.knownExploited,
  );
  const remaining = input.results.filter(
    (result) => !result.exploitSignals.knownExploited,
  );
  const targetLabel = input.selectedTarget?.label ?? input.spec.interpretedAs;

  if (knownExploited.length > 0) {
    sections.push({
      key: "known_exploited",
      title: "Known exploited vulnerabilities",
      reason: "These results have a source-backed known-exploitation signal.",
      results: knownExploited,
    });
  }

  if (remaining.length > 0) {
    sections.push({
      key: input.selectedTarget
        ? "vulnerabilities_for_target"
        : "source_text_matches",
      title: input.selectedTarget
        ? `Vulnerabilities for ${targetLabel}`
        : "Source-backed text matches",
      reason: input.selectedTarget
        ? "These vulnerabilities are connected to the resolved software target."
        : "These vulnerabilities matched the query text across normalized vulnerability data.",
      results: remaining,
    });
  }

  return sections;
}

function executionStrategy(
  spec: SearchSpec,
  selectedTarget: TargetCandidate | undefined,
): SearchResponse["execution"]["strategy"] {
  if (spec.extracted.identifier) {
    return "identifier";
  }

  if (selectedTarget) {
    return "target_resolution";
  }

  return "text_search";
}

function matchedOnForTarget(
  target: TargetCandidate,
): VulnerabilityResult["matchedOn"] {
  if (target.type === "package") {
    return { type: "package", label: target.label };
  }

  if (target.type === "product") {
    return { type: "product", label: target.label };
  }

  if (target.type === "weakness") {
    return { type: "weakness", label: target.label };
  }

  return { type: "identifier", label: target.label };
}

function likePattern(value: string) {
  return `%${value.trim().replace(/[%_\\]/g, "\\$&")}%`;
}

function toNumber(value: number | string | null | undefined) {
  if (value == null) {
    return undefined;
  }

  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function toInteger(value: number | string | null | undefined) {
  return Math.trunc(toNumber(value) ?? 0);
}

function parseProductList(value: unknown) {
  return parseJsonList(value)
    .map((entry) => ({
      id: stringValue(entry.id),
      vendor: stringValue(entry.vendor) || undefined,
      name: stringValue(entry.name),
    }))
    .filter((entry) => entry.id && entry.name);
}

function parsePackageList(value: unknown) {
  return parseJsonList(value)
    .map((entry) => ({
      id: stringValue(entry.id),
      ecosystem: stringValue(entry.ecosystem),
      name: stringValue(entry.name),
    }))
    .filter((entry) => entry.id && entry.ecosystem && entry.name);
}

function parseJsonList(value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) {
    return value.filter(isObject);
  }

  if (typeof value === "string") {
    try {
      const parsed: unknown = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.filter(isObject) : [];
    } catch {
      return [];
    }
  }

  return [];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value : "";
}

function severityRank(value: string | undefined) {
  switch (value?.toUpperCase()) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    default:
      return 0;
  }
}

function scoreFloor(value: string) {
  switch (value) {
    case "critical":
      return 9;
    case "high":
      return 7;
    case "medium":
      return 4;
    case "low":
      return 0.1;
    default:
      return 0;
  }
}
