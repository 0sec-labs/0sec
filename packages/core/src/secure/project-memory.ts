// Learning loop for the secure lifecycle: recall prior repair learnings before
// investigation, write outcomes back after each repair. Uses the existing
// revision-aware HuntMemoryStore — recalled notes are UNTRUSTED hints pinned to
// source content digests; stale or tampered notes simply do not recall.

import { HuntMemoryStore } from "../memory/hunt-memory.js";
import type { Finding } from "@0sec/shared";
import type { BehavioralRepairResult, SecureEvent } from "./types.js";

export interface RepairLearning {
  findingId: string;
  category: string;
  title: string;
  status: BehavioralRepairResult["status"];
  attempts: number;
  changedFiles: string[];
  model?: string;
}

/**
 * Recall codebase notes still valid for this checkout (every cited file hash
 * matches). Rendered as untrusted hints for the investigation prompt — never
 * treated as evidence of a vulnerability or its absence.
 */
export function recallRepairLearnings(repoRoot: string): string[] {
  if (process.env["0SEC_DISABLE_HUNT_MEMORY"] === "1") return [];
  try {
    const store = new HuntMemoryStore();
    return store
      .recallCodebase(repoRoot, 6)
      .map((r) => `[prior learning, untrusted] ${r.title}: ${r.summary}`);
  } catch {
    return []; // Memory is an optimization, never a failure mode.
  }
}

/**
 * Persist the outcome of one repair attempt as a codebase-context note pinned
 * to the files it touched. Only files that still exist at their post-repair
 * content hash recall later — a changed file invalidates the note, which is
 * the correct behavior (the learning is about that code shape).
 */
export function recordRepairLearning(
  repoRoot: string,
  runId: string,
  finding: Finding,
  repair: BehavioralRepairResult,
): void {
  if (process.env["0SEC_DISABLE_HUNT_MEMORY"] === "1") return;
  const paths = (repair.changedFiles ?? []).slice(0, 8);
  if (paths.length === 0) return;
  try {
    const store = new HuntMemoryStore();
    const outcome =
      repair.status === "verified"
        ? `Repair VERIFIED after ${repair.attempts} attempt(s).`
        : `Repair ${repair.status} after ${repair.attempts} attempt(s): ${repair.reason ?? "no reason"}.`;
    store.rememberCodebase({
      root: repoRoot,
      paths,
      title: `Repair outcome: ${finding.title}`.slice(0, 2000),
      summary:
        `${outcome} Category: ${finding.category}. ` +
        `${repair.status === "verified"
          ? "The applied pattern fixed the root cause while preserving legitimate behavior."
          : "Do not repeat the same failed approach without new evidence."}`.slice(0, 4000),
      tags: ["secure-lifecycle", finding.category, repair.status],
      source: `secure:${runId}`,
    });
  } catch {
    // A memory write failure must never block a verified repair.
  }
}

export function learningEvent(
  phase: SecureEvent["phase"],
  message: string,
): SecureEvent {
  return { type: "secure:phase", phase, message };
}
