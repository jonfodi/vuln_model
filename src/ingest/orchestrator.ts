import { seedReferenceData } from "./seed";
import type {
  IngestOptions,
  IngestResult,
  SourceAdapter,
} from "./types";
import { writeNormalizedIngestItem } from "./writers";
import type { IngestDb } from "./repository";

export async function ingestSource<Input extends IngestOptions>(
  db: IngestDb,
  adapter: SourceAdapter<Input>,
  input: Input,
): Promise<IngestResult> {
  await seedReferenceData(db);

  const result: IngestResult = { scanned: 0, ingested: 0, failed: [] };
  const progressEvery = input.progressEvery ?? 1000;

  for await (const item of adapter.read(input)) {
    result.scanned += 1;

    if (item.error) {
      result.failed.push({
        item: item.label,
        error: item.error instanceof Error ? item.error.message : String(item.error),
      });
      continue;
    }

    try {
      const normalized = adapter.normalize(item.raw);
      await db.transaction(async (tx) => {
        await writeNormalizedIngestItem(tx as IngestDb, normalized);
      });
      result.ingested += 1;
    } catch (error) {
      result.failed.push({
        item: item.label,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    if (result.scanned % progressEvery === 0) {
      console.log(
        `${adapter.sourceSlug}: scanned=${result.scanned} ingested=${result.ingested} failed=${result.failed.length}`,
      );
    }
  }

  return result;
}
