import type { IngestDb } from "../repository";
import type { NormalizedIngestItem } from "../types";
import { writeAdvisoryRecord } from "./advisory-record";
import { writeVulnerabilitySignal } from "./vulnerability-signal";

export async function writeNormalizedIngestItem(
  db: IngestDb,
  item: NormalizedIngestItem,
) {
  if (item.kind === "advisory_record") {
    await writeAdvisoryRecord(db, item);
    return;
  }

  await writeVulnerabilitySignal(db, item);
}
