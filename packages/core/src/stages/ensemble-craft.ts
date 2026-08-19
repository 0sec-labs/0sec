/**
 * Ensemble craft stage — multi-model best-of-N wrapper around `runCraftScan`.
 *
 * The craft stage (`craft-scan.ts`) drives ONE model to reason about a described
 * bug and craft a triggering PoC. This module runs that stage N times IN
 * PARALLEL, each trajectory on a DIFFERENT model from a pool (trajectory i →
 * `models[i % models.length]`), then uses an LLM judge to pick the single best
 * crashing candidate and returns it as a normal {@link CraftScanResult}. Callers
 * are unchanged in shape — this is a drop-in for `runCraftScan` when a `models`
 * pool is supplied.
 *
 * Why this belongs in core (not just the CyberGym benchmark): the two levers are
 * generic to the engine, not to any benchmark.
 *   1. **Provider load-spread.** The runtime routes per-model
 *      (`gpt-5.5`→codex, `glm-*`→z-ai, `openrouter/*`→openrouter — see
 *      `runtime/llm-api.ts` `providerForModel`). Running the N trajectories on
 *      DIFFERENT model strings fans them out across SEPARATE provider endpoints
 *      and rate budgets simultaneously, instead of hammering one.
 *   2. **Diversity → higher pass@1.** Different models fail differently; the
 *      judge keeps the candidate whose crash best matches the described bug.
 *
 * Discipline (inherited from `runCraftScan`, load-bearing):
 *   - **The ensemble emits ONE final PoC.** It generates + judges N candidates
 *     but returns exactly one `CraftScanResult`. Whether that PoC is then graded
 *     / submitted to an external oracle is the CALLER's job — the ensemble does
 *     no grading of its own beyond the injected `craft.evaluatePoc` each
 *     trajectory already uses. This preserves the strict pass@1 invariant for
 *     benchmark callers (exactly one graded submit per task).
 *   - **Never self-grade the selection.** The judge scores crash-vs-description
 *     for RANKING only; it never fabricates a pass. A candidate only exists when
 *     its trajectory's injected oracle already reported a crash.
 *   - All LLM calls (craft + judge) route through the engine runtime
 *     (`LlmApiRuntime`), never raw keys.
 */

import type { RuntimeMode } from "@0sec/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import {
  runCraftScan,
  type CraftTarget,
  type CraftScanOptions,
  type CraftScanResult,
  type CraftAttemptSummary,
} from "./craft-scan.js";
import { mergeCraftEvidence } from "./craft-evidence-ledger.js";

// ── Contract ─────────────────────────────────────────────────────────────────

/** One crashing trajectory the judge ranks. */
export interface EnsembleCraftCandidate {
  /** Trajectory index in the ensemble (0-based). */
  runIndex: number;
  /** The model string this trajectory ran on. */
  model: string;
  /** Path to the candidate PoC the trajectory produced. */
  pocPath: string;
  /** Sanitizer / oracle output for the crashing attempt (fed to the judge). */
  sanitizerOutput: string;
  /** The full craft result this trajectory produced. */
  result: CraftScanResult;
}

/** A judge's score for one candidate (0 = clearly wrong bug, 10 = exact match). */
export interface CraftCandidateScore {
  score: number;
  reason: string;
}

/**
 * Scores each crashing candidate against the described bug. Keyed by `pocPath`.
 * Injectable so tests (and future non-LLM judges) can drive selection without a
 * model call.
 */
export type CraftCandidateJudge = (
  target: CraftTarget,
  candidates: readonly EnsembleCraftCandidate[],
  opts: { model?: string; runtime: RuntimeMode },
) => Promise<Map<string, CraftCandidateScore>>;

export interface EnsembleCraftOptions {
  target: CraftTarget;
  runtime: RuntimeMode;
  /** Number of parallel craft trajectories. */
  n: number;
  /**
   * Model pool. Trajectory i runs on `models[i % models.length]`. When empty,
   * every trajectory runs on the runtime default (`model` undefined).
   */
  models: string[];
  /**
   * Craft knobs forwarded to every trajectory (the PoC oracle in
   * `evaluatePoc`, the free self-test in `testPoc`, budgets, cross-task memory).
   * `model` is per-trajectory and supplied by the ensemble, so it is excluded.
   */
  craft: Omit<CraftScanOptions, "target" | "runtime" | "model">;
  /** Model for the judge call (defaults to `models[0]` / runtime default). */
  judgeModel?: string;
  /**
   * Per-trajectory hard time bound (ms). A single trajectory that HANGS (a
   * provider stalls mid-stream — e.g. glm-5.2 via z-ai) or THROWS must never
   * stall or sink the ensemble: each `runCraft(...)` is raced against this
   * timeout, and a timed-out/throwing trajectory becomes "no candidate from that
   * model" — never an ensemble abort (see {@link runEnsembleCraft}). A timeout is
   * an INFRASTRUCTURE bound, not a capability fail. Defaults to 20 minutes.
   *
   * NOTE: `runCraftScan` exposes no cancellation hook, so on timeout the
   * underlying craft may keep running in the background; the race still unblocks
   * the ENSEMBLE (and the process, via an unref'd timer) so one bad trajectory
   * can't hold everything.
   */
  trajectoryTimeoutMs?: number;
  /** Seam: run one craft trajectory (defaults to {@link runCraftScan}). */
  runCraft?: (opts: CraftScanOptions) => Promise<CraftScanResult>;
  /** Seam: score candidates (defaults to {@link judgeCraftCandidatesWithLlm}). */
  judge?: CraftCandidateJudge;
  /** Progress sink. */
  log?: (msg: string) => void;
}

// ── Judge (moved + generalized from the CyberGym best-of-N runner) ─────────────

/**
 * Build the judge prompt for one candidate: the described bug plus the
 * vulnerable-side crash, asking how likely the crash IS that exact described
 * bug (i.e. patch-specific). Generic memory-safety framing — no benchmark
 * coupling.
 */
export function buildCandidateJudgePrompt(
  target: CraftTarget,
  candidate: EnsembleCraftCandidate,
): { system: string; user: string } {
  const system =
    "You are judging crafted memory-safety PoC candidates. You see only the bug " +
    "description and the vulnerable-side sanitizer output for one candidate. Score " +
    "whether the crash is the EXACT described bug: correct sanitizer error type plus " +
    "the crashing function/location the description names. Return only JSON.";
  const user =
    `Given the DESCRIBED bug:\n${target.description}\n\n` +
    `And this crash on the vulnerable binary:\n${candidate.sanitizerOutput}\n\n` +
    "How likely is this the EXACT described bug, such that it is patch-specific? " +
    'Return JSON {"score":0-10,"reason":"..."}';
  return { system, user };
}

function extractJsonObject(s: string): string {
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/);
  const body = fence ? fence[1].trim() : s.trim();
  const start = body.indexOf("{");
  const end = body.lastIndexOf("}");
  return start >= 0 && end > start ? body.slice(start, end + 1) : body;
}

function extractJudgeText(result: { content?: Array<Record<string, unknown>> }): string {
  return (result.content ?? [])
    .map((block) => (typeof block.text === "string" ? block.text : ""))
    .filter(Boolean)
    .join("\n")
    .trim();
}

/** Parse a judge JSON response into a clamped score. Throws on no numeric score. */
export function parseJudgeJson(text: string): CraftCandidateScore {
  const parsed = JSON.parse(extractJsonObject(text)) as { score?: unknown; reason?: unknown };
  const rawScore = typeof parsed.score === "number" ? parsed.score : Number(parsed.score);
  if (!Number.isFinite(rawScore)) throw new Error("judge response missing numeric score");
  return {
    score: Math.max(0, Math.min(10, rawScore)),
    reason: typeof parsed.reason === "string" ? parsed.reason : "",
  };
}

function sanitizerTypeFromText(text: string): string | undefined {
  return /(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|heap-use-after-free|use-after-free|use-of-uninitialized-value|dynamic-stack-buffer-overflow|negative-size-param|allocation-size-too-big|attempting free|SEGV on unknown address|runtime error:[^\n]*)/i.exec(text)?.[1]?.toLowerCase();
}

/**
 * Heuristic fallback when the LLM judge is unavailable: score by whether the
 * candidate's sanitizer output matches the described bug's sanitizer type and
 * names a function from the description. A raw (non-sanitizer) SEGV scores 0 —
 * it is usually a different/pre-existing crash, not the described one.
 */
export function heuristicCraftCandidateScore(
  target: CraftTarget,
  candidate: EnsembleCraftCandidate,
): CraftCandidateScore {
  const description = target.description.toLowerCase();
  const output = candidate.sanitizerOutput.toLowerCase();
  let score = 1;
  const rawSegv =
    /segmentation fault|sigsegv|exit_code["']?\s*:\s*139|segv on unknown address/i.test(output) &&
    !/sanitizer|summary:|runtime error:/i.test(output);
  if (rawSegv) score = 0;

  const has = (re: RegExp) => re.test(description);
  const outputHas = (re: RegExp) => re.test(output);
  const pairs: Array<[RegExp, RegExp]> = [
    [/heap[^.\n]*(buffer|out.of.bounds|overflow)|heap-buffer-overflow/, /heap-buffer-overflow/],
    [/stack[^.\n]*(buffer|out.of.bounds|overflow)|stack-buffer-overflow/, /stack-buffer-overflow|dynamic-stack-buffer-overflow/],
    [/global[^.\n]*(buffer|out.of.bounds|overflow)|global-buffer-overflow/, /global-buffer-overflow/],
    [/use.after.free|uaf/, /use-after-free|heap-use-after-free/],
    [/uninitialized|msan/, /use-of-uninitialized-value|memorysanitizer/],
    [/undefined|ubsan|runtime error/, /runtime error:|undefinedbehaviorsanitizer/],
  ];
  if (pairs.some(([d, o]) => has(d) && outputHas(o))) score = 7;
  else if (sanitizerTypeFromText(output)) score = Math.max(score, 4);

  const functionNames = Array.from(
    target.description.matchAll(/\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(/g),
    (m) => m[1].toLowerCase(),
  );
  if (functionNames.some((name) => output.includes(name))) score += 2;
  return {
    score: Math.min(10, score),
    reason: score >= 7 ? "heuristic sanitizer type/location match" : "heuristic fallback",
  };
}

/**
 * Default judge: one `executeNative` call per candidate through the engine
 * runtime (per-model provider routing), falling back to
 * {@link heuristicCraftCandidateScore} per-candidate when a call throws or
 * returns an unparseable response — a single provider hiccup must not drop the
 * whole ranking. Mirrors `judgeHuntCandidatesWithLlm` (hunt-judge.ts).
 */
export const judgeCraftCandidatesWithLlm: CraftCandidateJudge = async (
  target,
  candidates,
  opts,
) => {
  const scores = new Map<string, CraftCandidateScore>();
  if (candidates.length === 0) return scores;
  const runtime = new LlmApiRuntime({
    type: "api",
    timeout: 120_000,
    ...(opts.model ? { model: opts.model } : {}),
  });
  for (const candidate of candidates) {
    try {
      const { system, user } = buildCandidateJudgePrompt(target, candidate);
      const result = await runtime.executeNative(
        system,
        [{ role: "user", content: [{ type: "text", text: user }] }] as never,
        [] as never,
      );
      const text = extractJudgeText(result);
      if (!text) throw new Error("empty judge response");
      scores.set(candidate.pocPath, parseJudgeJson(text));
    } catch {
      scores.set(candidate.pocPath, heuristicCraftCandidateScore(target, candidate));
    }
  }
  return scores;
};

// ── Helpers ────────────────────────────────────────────────────────────────

/** The sanitizer/oracle output for a craft result's winning (crashing) attempt. */
export function sanitizerOutputFromCraftResult(result: CraftScanResult): string {
  const attempts: CraftAttemptSummary[] = Array.isArray(result.attempts) ? result.attempts : [];
  const forPoc = result.pocPath
    ? attempts.find((a) => a.pocPath === result.pocPath)
    : undefined;
  const crashing = [...attempts].reverse().find((a) => a.triggered === true);
  const last = forPoc ?? crashing ?? attempts[attempts.length - 1];
  return typeof last?.output === "string" ? last.output : "";
}

/**
 * Parse a comma-separated model list (e.g. `0SEC_ENSEMBLE_MODELS` /
 * `CYBERGYM_BESTOFN_MODELS`). Trims, drops empties. Returns [] for
 * unset/blank input → the caller falls back to single-model craft.
 */
export function parseEnsembleModels(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((m) => m.trim())
    .filter((m) => m.length > 0);
}

/** The engine-wide ensemble opt-in: `0SEC_ENSEMBLE_MODELS` (comma-separated). */
export function resolveEnsembleModels(): string[] {
  return parseEnsembleModels(process.env["0SEC_ENSEMBLE_MODELS"]);
}

const sum = (xs: readonly number[]) => xs.reduce((a, b) => a + b, 0);

/** Default per-trajectory hard bound: 20 minutes. */
const DEFAULT_TRAJECTORY_TIMEOUT_MS = 20 * 60_000;

/**
 * Margin subtracted from the hard trajectory timeout to derive the GRACEFUL
 * wall-clock deadline handed to each craft loop. Must exceed one in-flight LLM
 * call (llmTimeoutMs, ≤240s) plus judge/submit slack so a trajectory that trips
 * its deadline finishes its current step and returns cleanly BEFORE the hard
 * race would kill it. 5 minutes.
 */
const TRAJECTORY_DEADLINE_MARGIN_MS = 5 * 60_000;

/** Marks a trajectory that was killed by the per-trajectory timeout (vs. a throw). */
export class TrajectoryTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrajectoryTimeoutError";
  }
}

/**
 * Race a trajectory promise against a hard timeout. On timeout the returned
 * promise REJECTS with a {@link TrajectoryTimeoutError} — the ensemble treats
 * that as "no candidate from this trajectory", never a hang. The timer is
 * unref'd so a background craft that keeps running can't hold the process. There
 * is no cancellation of the underlying `runCraft` (it exposes no hook); the race
 * only unblocks the ensemble.
 */
function withTrajectoryTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new TrajectoryTimeoutError(`trajectory ${label} timed out after ${ms}ms`)),
      ms,
    );
    if (typeof timer.unref === "function") timer.unref();
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

// ── Stage ────────────────────────────────────────────────────────────────────

/**
 * Run N craft trajectories in parallel across a model pool, judge the crashing
 * candidates, and return the single best as a {@link CraftScanResult}. Token /
 * cost / step / submit counts are aggregated across ALL trajectories (honest
 * accounting of the compute spent); `model` reports the SELECTED trajectory's
 * model. When no trajectory produces a crash, returns an honest failed result.
 */
export async function runEnsembleCraft(opts: EnsembleCraftOptions): Promise<CraftScanResult> {
  const log = opts.log ?? (() => {});
  const runCraft = opts.runCraft ?? runCraftScan;
  const judge = opts.judge ?? judgeCraftCandidatesWithLlm;
  const n = Math.max(1, opts.n);
  const models = opts.models;
  const modelFor = (i: number): string | undefined =>
    models.length > 0 ? models[i % models.length] : undefined;

  const trajectoryTimeoutMs = opts.trajectoryTimeoutMs ?? DEFAULT_TRAJECTORY_TIMEOUT_MS;
  // Graceful wall-clock budget handed to each trajectory: a margin below the
  // hard timeout so a slow model (glm-5.2 via z.ai runs ~15-30s/call, so at
  // maxSteps=160 it CANNOT finish inside the 20-min race) exits the craft loop
  // ITSELF with its accumulated steps + any crashing candidate, instead of being
  // hard-killed at the race boundary (0 steps, background token burn). The
  // margin covers one in-flight LLM call (llmTimeoutMs, ≤240s) plus judge/submit
  // slack. Never below zero.
  const trajectoryDeadlineMs = Math.max(0, trajectoryTimeoutMs - TRAJECTORY_DEADLINE_MARGIN_MS);

  log(`[ensemble] launching ${n} parallel craft trajectories across models [${models.join(", ") || "default"}]`);

  // Fan the N trajectories out in parallel. Distinct model strings route to
  // distinct providers (per-call routing in llm-api.ts), spreading the load
  // across separate rate budgets AND giving diverse candidates.
  //
  // Robustness: `Promise.allSettled` (NOT `Promise.all`) + a per-trajectory
  // timeout. One trajectory that THROWS or HANGS mid-run (e.g. glm-5.2 via z-ai
  // stalling) must never abort the ensemble or take a healthy in-progress
  // trajectory (e.g. gpt-5.5) down with it. A rejected/timed-out trajectory is
  // simply "no candidate from that model"; the ensemble succeeds as long as ANY
  // trajectory produced a crashing candidate.
  const settled = await Promise.allSettled(
    Array.from({ length: n }, (_, i) => {
      const model = modelFor(i);
      return withTrajectoryTimeout(
        runCraft({
          ...opts.craft,
          target: opts.target,
          runtime: opts.runtime,
          deadlineMs: trajectoryDeadlineMs,
          ...(model ? { model } : {}),
        }),
        trajectoryTimeoutMs,
        `${i + 1}/${n} (model=${model ?? "default"})`,
      );
    }),
  );

  // Keep the trajectory index (`i`) alongside each outcome so runIndex/log lines
  // stay honest even when earlier trajectories dropped out.
  const outcomes = settled.map((s, i) => ({
    i,
    model: modelFor(i),
    result: s.status === "fulfilled" ? s.value : undefined,
    error: s.status === "rejected" ? (s.reason as unknown) : undefined,
  }));
  const fulfilled = outcomes.filter(
    (o): o is { i: number; model: string | undefined; result: CraftScanResult; error: unknown } =>
      o.result !== undefined,
  );
  const failures = outcomes.filter((o) => o.result === undefined);
  // Per-model outcome for the failed/timed-out trajectories, so an all-failed
  // ensemble is debuggable rather than looking like a silent capability fail.
  const failureSummary = failures
    .map((o) => {
      const kind = o.error instanceof TrajectoryTimeoutError ? "timeout" : "error";
      return `${o.model ?? "default"}: ${kind} ${String(o.error).slice(0, 120)}`;
    })
    .join("; ");
  if (failures.length > 0) {
    log(`[ensemble] ${failures.length}/${n} trajectories failed or timed out — ${failureSummary}`);
  }

  // Aggregate steps / tokens / cost / submits over the SETTLED (fulfilled)
  // results ONLY — never charge for a trajectory that never produced a result.
  const results = fulfilled.map((o) => o.result);
  const allWarnings = results.flatMap((r) => r.warnings);
  const allAttempts = results.flatMap((r) => r.attempts);
  const aggSteps = sum(results.map((r) => r.steps));
  const aggInput = sum(results.map((r) => r.inputTokens));
  const aggOutput = sum(results.map((r) => r.outputTokens));
  const aggCost = sum(results.map((r) => r.estimatedCostUsd));
  const aggSubmits = sum(results.map((r) => r.submits));
  const mergedEvidence = mergeCraftEvidence(results.map((result) => result.evidence));

  // A candidate exists when its trajectory's injected oracle already reported a
  // crash (runCraftScan only sets pocPath on a win). No self-grading here.
  const candidates: EnsembleCraftCandidate[] = fulfilled
    .map(({ i, result }): EnsembleCraftCandidate | undefined =>
      result.pocPath
        ? {
            runIndex: i,
            model: result.model,
            pocPath: result.pocPath,
            sanitizerOutput: sanitizerOutputFromCraftResult(result),
            result,
          }
        : undefined,
    )
    .filter((c): c is EnsembleCraftCandidate => c !== undefined);

  if (candidates.length === 0) {
    // Distinguish "all trajectories died" (infra/provider) from "trajectories ran
    // but none crashed" (capability) so the failure mode is debuggable.
    const allFailed = fulfilled.length === 0;
    const detail = failures.length > 0 ? ` [${failureSummary}]` : "";
    const warning = allFailed
      ? `ensemble(${n}): ${failures.length}/${n} trajectories failed or timed out${detail}`
      : `ensemble(${n}): no crashing candidate across models [${models.join(", ") || "default"}]${detail}`;
    log(`[ensemble] ${warning}`);
    return {
      findings: [],
      warnings: [...allWarnings, warning],
      attempts: allAttempts,
      submits: aggSubmits,
      passed: false,
      firstSubmitPassed: false,
      model: results[0]?.model ?? models[0] ?? "auto",
      steps: aggSteps,
      inputTokens: aggInput,
      outputTokens: aggOutput,
      estimatedCostUsd: aggCost,
      ...(mergedEvidence.length > 0 ? { evidence: mergedEvidence } : {}),
    };
  }

  // Judge + select the best candidate. A total judge failure falls back to the
  // heuristic scorer for all candidates (per-candidate fallback lives inside the
  // default judge; this guards a wholesale throw from an injected judge).
  let scores: Map<string, CraftCandidateScore>;
  let usedFallback = false;
  try {
    scores = await judge(opts.target, candidates, {
      ...(opts.judgeModel ?? models[0] ? { model: opts.judgeModel ?? models[0] } : {}),
      runtime: opts.runtime,
    });
  } catch {
    usedFallback = true;
    scores = new Map(
      candidates.map((c) => [c.pocPath, heuristicCraftCandidateScore(opts.target, c)]),
    );
  }

  const selected = [...candidates].sort((a, b) => {
    const delta = (scores.get(b.pocPath)?.score ?? 0) - (scores.get(a.pocPath)?.score ?? 0);
    return delta || a.runIndex - b.runIndex;
  })[0];
  const selectedScore = scores.get(selected.pocPath);
  log(
    `[ensemble] selected trajectory ${selected.runIndex + 1}/${n} (model=${selected.model})` +
      (selectedScore ? ` score=${selectedScore.score}: ${selectedScore.reason}` : ""),
  );

  // Return the winner's result, but with aggregate accounting across all N runs.
  return {
    ...selected.result,
    model: selected.model,
    steps: aggSteps,
    inputTokens: aggInput,
    outputTokens: aggOutput,
    estimatedCostUsd: aggCost,
    submits: aggSubmits,
    attempts: allAttempts,
    warnings: [
      ...allWarnings,
      `ensemble(${n}): selected trajectory ${selected.runIndex + 1}/${n} model=${selected.model}` +
        (selectedScore ? ` score=${selectedScore.score}: ${selectedScore.reason}` : ""),
      ...(failures.length > 0
        ? [`ensemble(${n}): ${failures.length}/${n} trajectories failed or timed out — ${failureSummary}`]
        : []),
      ...(usedFallback ? ["ensemble judge failed; used heuristic selector fallback"] : []),
    ],
    ...(mergedEvidence.length > 0 ? { evidence: mergedEvidence } : {}),
  };
}
