import { z } from "zod";
import { fetchJson } from "./http";

const osvPackageSchema = z.object({
  ecosystem: z.string().optional(),
  name: z.string().optional(),
  purl: z.string().optional(),
});

const osvRangeEventSchema = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
  last_affected: z.string().optional(),
  limit: z.string().optional(),
});

const osvAffectedSchema = z.object({
  package: osvPackageSchema.optional(),
  ranges: z
    .array(
      z.object({
        type: z.string().optional(),
        repo: z.string().optional(),
        events: z.array(osvRangeEventSchema).optional(),
      }),
    )
    .optional(),
  versions: z.array(z.string()).optional(),
  ecosystem_specific: z.record(z.string(), z.unknown()).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
});

export const osvVulnerabilitySchema = z
  .object({
    schema_version: z.string().optional(),
    id: z.string(),
    modified: z.string().optional(),
    published: z.string().optional(),
    withdrawn: z.string().optional(),
    aliases: z.array(z.string()).optional(),
    related: z.array(z.string()).optional(),
    summary: z.string().optional(),
    details: z.string().optional(),
    severity: z
      .array(
        z.object({
          type: z.string().optional(),
          score: z.string().optional(),
        }),
      )
      .optional(),
    affected: z.array(osvAffectedSchema).optional(),
    references: z
      .array(
        z.object({
          type: z.string().optional(),
          url: z.string(),
        }),
      )
      .optional(),
    credits: z.array(z.unknown()).optional(),
    database_specific: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();

export type OsvVulnerability = z.infer<typeof osvVulnerabilitySchema>;
export type OsvAffected = NonNullable<OsvVulnerability["affected"]>[number];

export async function fetchOsvVulnerability(id: string) {
  return fetchJson(
    `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
    osvVulnerabilitySchema,
  );
}

