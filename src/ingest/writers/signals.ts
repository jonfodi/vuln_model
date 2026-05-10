import {
  linkVulnerabilityIdentifier,
  upsertEpssScore,
  upsertIdentifier,
  upsertKevEntry,
  type IngestDb,
} from "../repository";
import type { NormalizedSignal } from "../types";

export async function writeSignal(
  db: IngestDb,
  values: {
    vulnerabilityId: string;
    sourceRecordId: string;
    signal: NormalizedSignal;
  },
) {
  const cveIdentifier = await upsertIdentifier(db, values.signal.cveIdentifier);
  await linkVulnerabilityIdentifier(
    db,
    values.vulnerabilityId,
    cveIdentifier.id,
    "primary",
  );

  if (values.signal.kind === "kev") {
    await upsertKevEntry(db, {
      vulnerabilityId: values.vulnerabilityId,
      sourceRecordId: values.sourceRecordId,
      cveIdentifierId: cveIdentifier.id,
      knownExploited: values.signal.knownExploited,
      vendorProject: values.signal.vendorProject,
      product: values.signal.product,
      vulnerabilityName: values.signal.vulnerabilityName,
      shortDescription: values.signal.shortDescription,
      dateAdded: values.signal.dateAdded,
      dueDate: values.signal.dueDate,
      requiredAction: values.signal.requiredAction,
      knownRansomwareCampaignUse: values.signal.knownRansomwareCampaignUse,
      notes: values.signal.notes,
    });
    return;
  }

  await upsertEpssScore(db, {
    vulnerabilityId: values.vulnerabilityId,
    sourceRecordId: values.sourceRecordId,
    cveIdentifierId: cveIdentifier.id,
    score: values.signal.score,
    percentile: values.signal.percentile,
    scoreDate: values.signal.scoreDate,
  });
}
