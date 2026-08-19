/**
 * Per-task evidence ledger for the crafted-PoC path.
 *
 * Records deterministic observations and their disposition without retaining raw
 * target source, model transcripts, candidate bytes, or sanitizer text. The
 * ledger is task-local and returned with the run receipt; it is never a shared
 * memory source.
 */

import { truncateMiddle } from "../agent/output-truncation.js";

export type CraftEvidenceKind =
  | "target-spec"
  | "stage-transition"
  | "self-test"
  | "identity"
  | "candidate-review"
  | "oracle"
  | "run-summary";

export type CraftEvidenceStatus = "observed" | "validated" | "refuted" | "inconclusive";

export type CraftEvidenceStage = "reachability" | "trigger" | "counterexample";

export interface CraftEvidenceRecord {
  sequence: number;
  kind: CraftEvidenceKind;
  status: CraftEvidenceStatus;
  /** Program-produced, bounded summary; never a model claim or raw target text. */
  summary: string;
  step?: number;
  stage?: CraftEvidenceStage;
  /** One-based trajectory index when an ensemble aggregates task-local ledgers. */
  trajectory?: number;
  candidateSha256?: string;
  source?: { path: string; line?: number };
}

export interface CraftEvidenceInput {
  kind: CraftEvidenceKind;
  status: CraftEvidenceStatus;
  summary: string;
  step?: number;
  stage?: CraftEvidenceStage;
  candidateSha256?: string;
  source?: { path: string; line?: number };
}

const MAX_SUMMARY_BYTES = 480;
const MAX_RECORDS = 256;

/**
 * Append-only, bounded task-local ledger. Once at capacity it records a single
 * truncation marker rather than silently dropping the fact that observations
 * were omitted.
 */
export class CraftEvidenceLedger {
  private readonly records: CraftEvidenceRecord[] = [];
  private truncated = false;

  record(input: CraftEvidenceInput): void {
    if (this.records.length >= MAX_RECORDS) {
      if (!this.truncated) {
        this.truncated = true;
        this.records.push({
          sequence: this.records.length + 1,
          kind: "oracle",
          status: "inconclusive",
          summary: "evidence ledger capacity reached; later observations omitted",
        });
      }
      return;
    }
    this.records.push({
      sequence: this.records.length + 1,
      ...(input.stage !== undefined ? { stage: input.stage } : {}),
      kind: input.kind,
      status: input.status,
      summary: truncateMiddle(input.summary, { limit: MAX_SUMMARY_BYTES, mode: "bytes" }).text,
      ...(input.step !== undefined ? { step: input.step } : {}),
      ...(input.candidateSha256 ? { candidateSha256: input.candidateSha256 } : {}),
      ...(input.source ? { source: { ...input.source } } : {}),
    });
  }

  snapshot(): CraftEvidenceRecord[] {
    return this.records.map((record) => ({
      ...record,
      ...(record.source ? { source: { ...record.source } } : {}),
    }));
  }
}

/**
 * Re-sequence independent trajectory ledgers for one ensemble task receipt.
 * Per-trajectory sequence numbers would otherwise collide in a durable JSONL
 * row; the original trajectory remains explicit.
 */
export function mergeCraftEvidence(
  trajectories: readonly (readonly CraftEvidenceRecord[] | undefined)[],
): CraftEvidenceRecord[] {
  const merged: CraftEvidenceRecord[] = [];
  trajectories.forEach((records, index) => {
    for (const record of records ?? []) {
      merged.push({
        ...record,
        sequence: merged.length + 1,
        trajectory: index + 1,
        ...(record.source ? { source: { ...record.source } } : {}),
      });
    }
  });
  return merged;
}
