import crypto from "node:crypto";
import type { ReviewFileRecord } from "./types.js";

/**
 * Deterministic, stable identifier for a stored finding. It uses only immutable
 * identity fields, so a re-scan or revalidation on another machine derives the
 * same value. Mutable evidence such as severity, line numbers, and verdicts
 * must never change an identifier the revalidation agent echoes back.
 */
export function computeReviewFindingId(
  projectId: string,
  filePath: string,
  title: string,
): string {
  const normalizedPath = filePath.replaceAll("\\", "/").replace(/^\.\//, "");
  const digest = crypto
    .createHash("sha256")
    .update(`${projectId}\0${normalizedPath}\0${title}`)
    .digest("hex");
  return `finding_${digest.slice(0, 16)}`;
}

/**
 * Lazily backfill IDs for records written before the field existed. Identical
 * titles in one file are disambiguated by their append-only ordinal.
 */
export function ensureReviewFindingIds(record: ReviewFileRecord): boolean {
  let changed = false;
  const used = new Set<string>();
  for (const finding of record.findings) {
    if (finding.findingId) used.add(finding.findingId);
  }

  for (const finding of record.findings) {
    if (finding.findingId) continue;

    let findingId = computeReviewFindingId(record.projectId, record.filePath, finding.title);
    for (let ordinal = 2; used.has(findingId); ordinal++) {
      findingId = computeReviewFindingId(
        record.projectId,
        record.filePath,
        `${finding.title}\0${ordinal}`,
      );
    }
    finding.findingId = findingId;
    used.add(findingId);
    changed = true;
  }

  return changed;
}
