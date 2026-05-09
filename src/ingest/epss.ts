import { z } from "zod";
import { fetchJson } from "./http";

export const epssEntrySchema = z.object({
  cve: z.string(),
  epss: z.string(),
  percentile: z.string(),
  date: z.string().optional(),
});

export const epssResponseSchema = z
  .object({
    status: z.string().optional(),
    data: z.array(epssEntrySchema).optional(),
  })
  .passthrough();

export type EpssEntry = z.infer<typeof epssEntrySchema>;

export async function fetchEpss(cveId: string) {
  const result = await fetchJson(
    `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`,
    epssResponseSchema,
  );

  if (!result.ok) {
    return result;
  }

  return {
    ok: true as const,
    data: result.data.data?.[0],
  };
}

