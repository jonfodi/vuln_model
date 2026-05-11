import { getDb } from "../db";
import { runSearch } from "./search";
import type { SearchRequest } from "./types";

export async function handleApiRequest(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const pathname = normalizePathname(url.pathname);

    if (request.method === "OPTIONS") {
      return emptyCorsResponse();
    }

    if (pathname === "/health" || pathname === "/api/health") {
      return withCors({ ok: true });
    }

    if (pathname === "/api/search") {
      if (request.method === "GET") {
        return handleSearchRequest(readGetSearchRequest(url));
      }

      if (request.method === "POST") {
        return handleSearchRequest(await readPostSearchRequest(request));
      }

      return withCors(
        { error: "method_not_allowed", message: "Method not allowed." },
        { status: 405 },
      );
    }

    return withCors(
      { error: "not_found", message: "Route not found." },
      { status: 404 },
    );
  } catch (error) {
    console.error(error);
    return withCors(
      { error: "internal_error", message: "Internal server error." },
      { status: 500 },
    );
  }
}

async function handleSearchRequest(searchRequest: SearchRequest) {
  const validationError = validateSearchRequest(searchRequest);
  if (validationError) {
    return withCors(
      { error: "invalid_request", message: validationError },
      { status: 400 },
    );
  }

  const response = await runSearch(getDb(), searchRequest);
  return withCors(response);
}

function readGetSearchRequest(url: URL): SearchRequest {
  return {
    query: url.searchParams.get("q") ?? url.searchParams.get("query") ?? "",
    limit: parseOptionalNumber(url.searchParams.get("limit")),
  };
}

async function readPostSearchRequest(request: Request): Promise<SearchRequest> {
  const body: unknown = await request.json().catch(() => ({}));

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { query: "" };
  }

  const input = body as Record<string, unknown>;
  return {
    query: typeof input.query === "string" ? input.query : "",
    limit:
      typeof input.limit === "number"
        ? input.limit
        : typeof input.limit === "string"
          ? parseOptionalNumber(input.limit)
          : undefined,
  };
}

function validateSearchRequest(request: SearchRequest) {
  if (!request.query.trim()) {
    return "query is required.";
  }

  if (request.query.length > 500) {
    return "query must be 500 characters or fewer.";
  }

  return undefined;
}

function parseOptionalNumber(value: string | null) {
  if (!value) {
    return undefined;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function normalizePathname(pathname: string) {
  return pathname.length > 1 && pathname.endsWith("/")
    ? pathname.slice(0, -1)
    : pathname;
}

function withCors(value: unknown, init?: ResponseInit) {
  const { headers: _headers, ...rest } = init ?? {};
  return Response.json(value, { ...rest, headers: corsHeaders() });
}

function emptyCorsResponse() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
  };
}
