import { z } from "zod";
import { fetchJson } from "./http";

export const cisaKevEntrySchema = z
  .object({
    cveID: z.string(),
    vendorProject: z.string().optional(),
    product: z.string().optional(),
    vulnerabilityName: z.string().optional(),
    dateAdded: z.string().optional(),
    shortDescription: z.string().optional(),
    requiredAction: z.string().optional(),
    dueDate: z.string().optional(),
    knownRansomwareCampaignUse: z.string().optional(),
    notes: z.string().optional(),
    cwes: z.array(z.string()).optional(),
  })
  .passthrough();

export const cisaKevCatalogSchema = z
  .object({
    title: z.string().optional(),
    catalogVersion: z.string().optional(),
    dateReleased: z.string().optional(),
    vulnerabilities: z.array(cisaKevEntrySchema).optional(),
  })
  .passthrough();

export type CisaKevEntry = z.infer<typeof cisaKevEntrySchema>;

const cisaKevUrl =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export async function fetchCisaKevEntry(cveId: string) {
  const result = await fetchJson(cisaKevUrl, cisaKevCatalogSchema);

  if (!result.ok) {
    return result;
  }

  const entry = result.data.vulnerabilities?.find(
    (vulnerability) => vulnerability.cveID.toUpperCase() === cveId.toUpperCase(),
  );

  return {
    ok: true as const,
    data: entry,
  };
}

