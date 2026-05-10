import { cveAdapter } from "./cve";
import { epssAdapter } from "./epss";
import { kevAdapter } from "./kev";
import { osvAdapter } from "./osv";
import type { SourceAdapter } from "../types";

const adapters: Record<string, SourceAdapter<any>> = {
  cve: cveAdapter,
  "cve-list-v5": cveAdapter,
  osv: osvAdapter,
  kev: kevAdapter,
  "cisa-kev": kevAdapter,
  epss: epssAdapter,
  "first-epss": epssAdapter,
};

export function getSourceAdapter(source: string) {
  const adapter = adapters[source];
  if (!adapter) {
    throw new Error(`Unknown ingest source: ${source}`);
  }

  return adapter;
}

export { cveAdapter, epssAdapter, kevAdapter, osvAdapter };
