/**
 * Kernel archetype-SWEEP orchestration — the testable core of `hunt-sweep-run.ts`.
 *
 * `hunt-run.ts` seeds ONE bug class per invocation (a human/LLM names a bug
 * class, greps for variant sites, `runHuntScan`s that one plan). This module
 * runs `runHuntScan` once PER archetype plan produced by
 * `planArchetypeSweep` (`@pwnkit/core`'s archetype-catalog), so one invocation
 * sweeps many bug classes over the same source tree.
 *
 * Split out from the root-level `hunt-sweep-run.ts` script (which has no test
 * — it needs a real kernel source tree + a real LLM) so the two things worth
 * unit-testing live here, mock-at-module-boundary style (mirrors
 * `hunt-scan.test.ts`):
 *
 *   1. The file-size guard: the af_unix sweep run died to a finder timeout on
 *      5k+-line files (tcp_input.c, tcp.c). `guardCandidatesBySize` drops any
 *      candidate file over a line-count cap BEFORE it reaches the finder.
 *   2. `runArchetypeSweep`: iterates `ArchetypeSweepPlan[]`, applies the guard,
 *      calls `runHuntScan` per plan, aggregates a per-archetype summary +
 *      totals, and persists every finding record to the corpus.
 */

import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { ArchetypeSweepPlan, HuntCandidate, HuntVerifier } from "@pwnkit/core";
import { runHuntScan } from "@pwnkit/core";
import type { Finding, RuntimeMode } from "@pwnkit/shared";
import { appendToCorpus } from "./hunt-corpus.js";

// ── File-size guard ─────────────────────────────────────────────────────────

export interface SizeGuardDrop {
  path: string;
  lines: number;
}

export interface SizeGuardResult {
  kept: HuntCandidate[];
  dropped: SizeGuardDrop[];
}

/**
 * Drop candidate files over `maxLines` (default 2000) BEFORE they reach the
 * finder — the finder times out on huge files (tcp_input.c/tcp.c are 5k+
 * lines), which killed the af_unix sweep run entirely (a timeout looks like
 * every finder in the batch silently failing, not a clean per-file skip).
 *
 * Fail-open on an unreadable/missing file (keep it, let the finder surface
 * the real error) — this guard only exists to drop KNOWN-huge files, never to
 * introduce a new failure mode of its own.
 */
export function guardCandidatesBySize(
  candidates: readonly HuntCandidate[],
  sourceRoot: string,
  maxLines: number,
): SizeGuardResult {
  const kept: HuntCandidate[] = [];
  const dropped: SizeGuardDrop[] = [];
  for (const candidate of candidates) {
    const abs = isAbsolute(candidate.path) ? candidate.path : join(sourceRoot, candidate.path);
    let lines: number;
    try {
      const content = readFileSync(abs, "utf8");
      lines = content.length === 0 ? 0 : content.split("\n").length;
    } catch {
      kept.push(candidate);
      continue;
    }
    if (lines > maxLines) dropped.push({ path: candidate.path, lines });
    else kept.push(candidate);
  }
  return { kept, dropped };
}

// ── Best-effort file:line extraction (for the summary printout) ────────────

const FILE_LINE_RE = /\b[\w.\-/]+\.(?:c|h|cpp|hpp|rs)(?::\d+)?\b/;

/** Best-effort first `path/to/file.c:123`-shaped token in a finding's prose; undefined if none found. */
export function extractFileLine(finding: Finding): string | undefined {
  const haystacks = [finding.description, finding.evidence?.analysis].filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  for (const text of haystacks) {
    const m = text.match(FILE_LINE_RE);
    if (m) return m[0];
  }
  return undefined;
}

// ── The sweep runner ─────────────────────────────────────────────────────────

export interface ArchetypeSweepRunOptions {
  sourceRoot: string;
  plans: readonly ArchetypeSweepPlan[];
  runtime: RuntimeMode;
  /** Max finders running at once (per archetype plan). Default 3. */
  concurrency?: number;
  /** Drop candidate files over this many lines before they reach the finder. Default 2000. */
  maxFileLines?: number;
  attemptsPerCandidate?: number;
  judgeTopK?: number;
  judgeModel?: string;
  verify?: HuntVerifier;
  /** Corpus JSONL path. Omit to skip persistence entirely (tests). */
  corpusPath?: string;
  log?: (msg: string) => void;
}

export interface ConfirmedFindingSummary {
  title: string;
  /** Best-effort `path/to/file.c:123` pulled from the finding's prose; undefined if none found. */
  fileLine?: string;
}

export interface ArchetypeSweepSummary {
  uid: string;
  name: string;
  scanned: number;
  findings: number;
  confirmed: number;
  confirmedFindings: ConfirmedFindingSummary[];
  droppedForSize: number;
}

export interface ArchetypeSweepRunResult {
  perArchetype: ArchetypeSweepSummary[];
  totals: { scanned: number; findings: number; confirmed: number };
  warnings: string[];
}

/**
 * Run `runHuntScan` once per archetype plan, aggregating results. An empty
 * `plans` list is a clean no-op (e.g. the sweep gate `PWNKIT_ARCHETYPE_SWEEP`
 * was off, or nothing matched the filter) — not an error.
 */
export async function runArchetypeSweep(opts: ArchetypeSweepRunOptions): Promise<ArchetypeSweepRunResult> {
  const log = opts.log ?? (() => {});
  const maxFileLines = opts.maxFileLines ?? 2000;
  const concurrency = opts.concurrency ?? 3;
  const perArchetype: ArchetypeSweepSummary[] = [];
  const warnings: string[] = [];
  let totalScanned = 0;
  let totalFindings = 0;
  let totalConfirmed = 0;

  if (opts.plans.length === 0) {
    log("[hunt-sweep] no archetype plans to run — nothing to hunt");
    return { perArchetype: [], totals: { scanned: 0, findings: 0, confirmed: 0 }, warnings };
  }

  for (const plan of opts.plans) {
    const { kept, dropped } = guardCandidatesBySize(plan.candidates, opts.sourceRoot, maxFileLines);
    if (dropped.length > 0) {
      log(
        `[hunt-sweep] ${plan.archetype.uid}: dropped ${dropped.length} oversized candidate(s) ` +
          `(> ${maxFileLines} lines): ${dropped.map((d) => `${d.path} (${d.lines})`).join(", ")}`,
      );
    }

    if (kept.length === 0) {
      warnings.push(`${plan.archetype.uid}: no candidates left after the size guard — skipped`);
      perArchetype.push({
        uid: plan.archetype.uid,
        name: plan.archetype.name,
        scanned: 0,
        findings: 0,
        confirmed: 0,
        confirmedFindings: [],
        droppedForSize: dropped.length,
      });
      continue;
    }

    // Candidate paths from planArchetypeSweep are sourceRoot-relative; the
    // finder needs absolute paths (mirrors hunt-run.ts's `${SRC}/${c.path}`).
    const candidates = kept.map((c) => ({
      ...c,
      path: isAbsolute(c.path) ? c.path : join(opts.sourceRoot, c.path),
    }));

    const res = await runHuntScan({
      sourceRoot: opts.sourceRoot,
      candidates,
      brief: plan.brief,
      runtime: opts.runtime,
      concurrency,
      ...(opts.attemptsPerCandidate ? { attemptsPerCandidate: opts.attemptsPerCandidate } : {}),
      ...(opts.judgeTopK ? { judgeTopK: opts.judgeTopK } : {}),
      ...(opts.judgeModel ? { judgeModel: opts.judgeModel } : {}),
      ...(opts.verify ? { verify: opts.verify } : {}),
      log,
    });

    totalScanned += res.scanned;
    totalFindings += res.findings.length;
    totalConfirmed += res.confirmed.length;
    warnings.push(...res.warnings.map((w) => `${plan.archetype.uid}: ${w}`));

    perArchetype.push({
      uid: plan.archetype.uid,
      name: plan.archetype.name,
      scanned: res.scanned,
      findings: res.findings.length,
      confirmed: res.confirmed.length,
      confirmedFindings: res.confirmed.map((f) => ({ title: f.title, fileLine: extractFileLine(f) })),
      droppedForSize: dropped.length,
    });

    if (opts.corpusPath !== undefined) {
      appendToCorpus(res.records, opts.corpusPath, plan.brief);
      log(`[hunt-sweep] ${plan.archetype.uid}: appended ${res.records.length} record(s) to ${opts.corpusPath}`);
    }
  }

  return { perArchetype, totals: { scanned: totalScanned, findings: totalFindings, confirmed: totalConfirmed }, warnings };
}
