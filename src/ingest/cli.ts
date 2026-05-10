import { closeDb, getDb } from "../db";
import { getSourceAdapter } from "./adapters";
import { ingestSource } from "./orchestrator";
import { seedReferenceData } from "./seed";

type Args = Record<string, string | boolean>;

const DEFAULT_CVE_DIR = "RESOURCES/cvelistV5-main/cves";

async function main() {
  const [command, ...rawArgs] = process.argv.slice(2);
  const args = parseArgs(rawArgs);

  try {
    switch (command) {
      case "seed": {
        const db = getDb();
        await seedReferenceData(db);
        console.log("Seeded sources and ecosystem aliases.");
        return;
      }

      case "cve": {
        const db = getDb();
        const result = await ingestSource(db, getSourceAdapter("cve"), {
          dir: stringArg(args, "dir") ?? DEFAULT_CVE_DIR,
          limit: numberArg(args, "limit"),
          progressEvery: numberArg(args, "progress-every"),
        });
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      case "osv": {
        const db = getDb();
        const dir = requiredStringArg(args, "dir", "osv requires --dir");
        const result = await ingestSource(db, getSourceAdapter("osv"), {
          dir,
          limit: numberArg(args, "limit"),
          progressEvery: numberArg(args, "progress-every"),
        });
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      case "kev": {
        const db = getDb();
        const file = requiredStringArg(args, "file", "kev requires --file");
        const result = await ingestSource(db, getSourceAdapter("kev"), {
          file,
          progressEvery: numberArg(args, "progress-every"),
        });
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      case "epss": {
        const db = getDb();
        const file = requiredStringArg(args, "file", "epss requires --file");
        const result = await ingestSource(db, getSourceAdapter("epss"), {
          file,
          date: stringArg(args, "date"),
          progressEvery: numberArg(args, "progress-every"),
        });
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      default:
        printUsage();
        process.exitCode = command ? 1 : 0;
    }
  } finally {
    await closeDb();
  }
}

function parseArgs(values: string[]): Args {
  const args: Args = {};

  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];

    if (!value.startsWith("--")) {
      continue;
    }

    const key = value.slice(2);
    const next = values[index + 1];

    if (!next || next.startsWith("--")) {
      args[key] = true;
      continue;
    }

    args[key] = next;
    index += 1;
  }

  return args;
}

function stringArg(args: Args, key: string) {
  const value = args[key];
  return typeof value === "string" ? value : undefined;
}

function requiredStringArg(args: Args, key: string, message: string) {
  const value = stringArg(args, key);
  if (!value) {
    throw new Error(message);
  }

  return value;
}

function numberArg(args: Args, key: string) {
  const value = stringArg(args, key);
  if (!value) {
    return undefined;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function printUsage() {
  console.log(`Usage:
  bun run ingest:seed
  bun run ingest:cve -- --dir RESOURCES/cvelistV5-main/cves --limit 100
  bun run ingest -- cve --dir RESOURCES/cvelistV5-main/cves
  bun run ingest -- osv --dir /path/to/osv/json
  bun run ingest -- kev --file /path/to/known_exploited_vulnerabilities.json
  bun run ingest -- epss --file /path/to/epss_scores.csv --date YYYY-MM-DD`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
