import { z } from "zod";
import { fetchJson } from "./http";

const descriptionSchema = z.object({
  lang: z.string().optional(),
  value: z.string().optional(),
});

const cvssDataSchema = z
  .object({
    version: z.string().optional(),
    vectorString: z.string().optional(),
    baseScore: z.number().optional(),
    baseSeverity: z.string().optional(),
    attackVector: z.string().optional(),
    attackComplexity: z.string().optional(),
    privilegesRequired: z.string().optional(),
    userInteraction: z.string().optional(),
    scope: z.string().optional(),
    confidentialityImpact: z.string().optional(),
    integrityImpact: z.string().optional(),
    availabilityImpact: z.string().optional(),
  })
  .passthrough();

const cvssMetricSchema = z
  .object({
    source: z.string().optional(),
    type: z.string().optional(),
    cvssData: cvssDataSchema.optional(),
    exploitabilityScore: z.number().optional(),
    impactScore: z.number().optional(),
  })
  .passthrough();

const referenceSchema = z.object({
  url: z.string(),
  source: z.string().optional(),
  tags: z.array(z.string()).optional(),
});

const weaknessSchema = z.object({
  source: z.string().optional(),
  type: z.string().optional(),
  description: z.array(descriptionSchema).optional(),
});

export const nvdCveSchema = z
  .object({
    id: z.string(),
    published: z.string().optional(),
    lastModified: z.string().optional(),
    vulnStatus: z.string().optional(),
    descriptions: z.array(descriptionSchema).optional(),
    metrics: z
      .object({
        cvssMetricV40: z.array(cvssMetricSchema).optional(),
        cvssMetricV31: z.array(cvssMetricSchema).optional(),
        cvssMetricV30: z.array(cvssMetricSchema).optional(),
        cvssMetricV2: z.array(cvssMetricSchema).optional(),
      })
      .passthrough()
      .optional(),
    weaknesses: z.array(weaknessSchema).optional(),
    references: z
      .object({
        referenceData: z.array(referenceSchema).optional(),
      })
      .optional(),
  })
  .passthrough();

export const nvdResponseSchema = z
  .object({
    vulnerabilities: z
      .array(
        z.object({
          cve: nvdCveSchema,
        }),
      )
      .optional(),
  })
  .passthrough();

export type NvdCve = z.infer<typeof nvdCveSchema>;
export type NvdCvssMetric = z.infer<typeof cvssMetricSchema>;

export async function fetchNvdCve(cveId: string) {
  return fetchJson(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(
      cveId,
    )}`,
    nvdResponseSchema,
  );
}

