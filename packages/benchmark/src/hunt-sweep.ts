/**
 * Kernel archetype-SWEEP orchestration — the testable core of `hunt-sweep-run.ts`.
 *
 * `hunt-run.ts` seeds ONE bug class per invocation (a human/LLM names a bug
 * class, greps for variant sites, `runHuntScan`s that one plan). This module
 * runs `runHuntScan` once PER archetype plan produced by
 * `planArchetypeSweep` (`@0sec/core`'s archetype-catalog), so one invocation
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
import type { ArchetypeSweepPlan, HuntCandidate, HuntVerifier } from "@0sec/core";
import { runHuntScan } from "@0sec/core";
import type { Finding, RuntimeMode } from "@0sec/shared";
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
  /**
   * Load-spreading seam (bench token-contention fix): when set, each
   * archetype plan is pinned to ONE model from this pool, round-robin by
   * plan index (`pickModelForPlanIndex`) — plan 0 gets `modelPool[0]`, plan
   * 1 gets `modelPool[1]`, etc., wrapping around. Each plan's OWN candidate
   * fan-out is unchanged (still `concurrency`-wide, still one call per
   * candidate); only WHICH provider that plan's calls land on changes.
   *
   * Why this helps: every archetype plan run through `runHuntScan` without
   * an explicit model falls through to the shared env-priority provider
   * (today: the single ChatGPT/Codex subscription token — see
   * `0sec/packages/core/src/runtime/llm-api.ts`'s `detectProvider()`
   * env-priority chain). A multi-archetype sweep fans MANY archetype plans'
   * candidate pools through that ONE account/token, which is the measured
   * bench bottleneck (single shared token, ~90% timeouts/429s under
   * fan-out). Pinning alternating plans to a DIFFERENT model
   * (`providerForModel()` in llm-api.ts routes e.g. `glm-*` to the
   * completely separate Z.ai key/account, `gpt-*` to Codex) genuinely
   * splits load across independent provider accounts/rate-limit buckets,
   * instead of adding a second pass on top of the existing one (that would
   * be `HuntScanOptions.models`'s existing cartesian candidate×model
   * diversity fan-out — a different, additive feature; this option instead
   * assigns exactly one model per plan, so total finder-call volume is
   * unchanged from the no-pool baseline).
   *
   * Omit (default) to reproduce today's behavior exactly: no `models` is
   * passed to `runHuntScan` and every plan falls through to the shared
   * default provider, byte-for-byte identical to pre-existing behavior.
   */
  modelPool?: readonly string[];
  log?: (msg: string) => void;
}

/**
 * Pure round-robin picker: returns `pool[index % pool.length]`, or
 * `undefined` when `pool` is unset/empty (the "no pool configured" case —
 * callers should omit `models` entirely rather than pass `[undefined]`).
 * Exported for unit testing independent of `runArchetypeSweep`.
 */
export function pickModelForPlanIndex(
  pool: readonly string[] | undefined,
  index: number,
): string | undefined {
  if (!pool || pool.length === 0) return undefined;
  return pool[index % pool.length];
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
 * `plans` list is a clean no-op (e.g. the sweep gate `0SEC_ARCHETYPE_SWEEP`
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

  for (const [planIndex, plan] of opts.plans.entries()) {
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

    // Round-robin ONE model per plan from opts.modelPool (undefined/empty →
    // undefined, same as today). A single-element `models` array assigns
    // this plan's candidates to exactly one provider — it does NOT multiply
    // finder-call volume the way HuntScanOptions.models's cartesian
    // candidate×model diversity fan-out would with >1 element. See the
    // modelPool doc comment above for why this is the load-spreading lever.
    const pinnedModel = pickModelForPlanIndex(opts.modelPool, planIndex);
    if (pinnedModel) {
      log(`[hunt-sweep] ${plan.archetype.uid}: pinned to model ${pinnedModel} (modelPool round-robin)`);
    }

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
      ...(pinnedModel ? { models: [pinnedModel] } : {}),
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
