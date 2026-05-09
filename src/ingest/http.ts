import { z } from "zod";

export type SourceResult<T> =
  | {
      ok: true;
      data: T;
    }
  | {
      ok: false;
      error: string;
    };

export async function fetchJson<T>(
  url: string,
  schema: z.ZodType<T>,
): Promise<SourceResult<T>> {
  try {
    const response = await fetch(url, {
      headers: {
        accept: "application/json",
        "user-agent": "vulnerability-model/0.1",
      },
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      return {
        ok: false,
        error: `${response.status} ${response.statusText}`,
      };
    }

    const json = await response.json();
    const parsed = schema.safeParse(json);

    if (!parsed.success) {
      return {
        ok: false,
        error: parsed.error.issues.map((issue) => issue.message).join("; "),
      };
    }

    return {
      ok: true,
      data: parsed.data,
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "unknown fetch error",
    };
  }
}

