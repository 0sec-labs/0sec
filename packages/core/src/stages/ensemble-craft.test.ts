/**
 * Unit tests for the ensemble craft stage (`runEnsembleCraft`).
 *
 * No real model calls: both seams — the per-trajectory craft runner and the
 * candidate judge — are injected as mocks. The point is to prove the glue:
 * N parallel trajectories across a model pool → collect crashing candidates →
 * judge → return the single best as a normal CraftScanResult, with aggregate
 * accounting and no self-grading.
 */

import { describe, it, expect } from "vitest";
import {
  runEnsembleCraft,
  heuristicCraftCandidateScore,
  parseJudgeJson as parseCraftJudgeJson,
  parseEnsembleModels,
  sanitizerOutputFromCraftResult,
  type CraftCandidateJudge,
  type EnsembleCraftCandidate,
} from "./ensemble-craft.js";
import type { CraftTarget, CraftScanOptions, CraftScanResult } from "./craft-scan.js";

const TARGET: CraftTarget = {
  sourceRoot: "/tmp/repo",
  description: "Heap buffer overflow in parse_header(). Trigger via crafted input.",
  language: "c",
  taskId: "arvo:10400",
};

/** Build a CraftScanResult; a crashing trajectory has a pocPath + a triggered attempt. */
function craftResult(opts: {
  model: string;
  pocPath?: string;
  output?: string;
  steps?: number;
  inputTokens?: number;
  outputTokens?: number;
  cost?: number;
}): CraftScanResult {
  const crashing = !!opts.pocPath;
  return {
    findings: [],
    warnings: [],
    attempts: crashing
      ? [{ submit: 1, pocPath: opts.pocPath!, triggered: true, output: opts.output ?? "" }]
      : [],
    submits: 1,
    passed: crashing,
    firstSubmitPassed: false,
    ...(opts.pocPath ? { pocPath: opts.pocPath } : {}),
    model: opts.model,
    steps: opts.steps ?? 5,
    inputTokens: opts.inputTokens ?? 100,
    outputTokens: opts.outputTokens ?? 50,
    estimatedCostUsd: opts.cost ?? 0.01,
  };
}

describe("parseEnsembleModels", () => {
  it("splits, trims and drops empties; blank/unset → []", () => {
    expect(parseEnsembleModels("gpt-5.5, glm-5.2 ,openrouter/x")).toEqual([
      "gpt-5.5",
      "glm-5.2",
      "openrouter/x",
    ]);
    expect(parseEnsembleModels(undefined)).toEqual([]);
    expect(parseEnsembleModels("  ")).toEqual([]);
  });
});

describe("parseJudgeJson", () => {
  it("parses + clamps a score, tolerates a code fence", () => {
    expect(parseCraftJudgeJson('{"score": 8, "reason": "ok"}')).toEqual({ score: 8, reason: "ok" });
    expect(parseCraftJudgeJson('```json\n{"score": 99}\n```').score).toBe(10);
    expect(() => parseCraftJudgeJson('{"reason":"x"}')).toThrow();
  });
});

describe("heuristicCraftCandidateScore", () => {
  it("scores a matching sanitizer type high and a raw SEGV at 0", () => {
    const match: EnsembleCraftCandidate = {
      runIndex: 0,
      model: "m",
      pocPath: "/p1",
      sanitizerOutput: "AddressSanitizer: heap-buffer-overflow in parse_header parser.c:1",
      result: craftResult({ model: "m", pocPath: "/p1" }),
    };
    const segv: EnsembleCraftCandidate = {
      runIndex: 1,
      model: "m",
      pocPath: "/p2",
      sanitizerOutput: "Segmentation fault (core dumped)",
      result: craftResult({ model: "m", pocPath: "/p2" }),
    };
    expect(heuristicCraftCandidateScore(TARGET, match).score).toBeGreaterThanOrEqual(7);
    expect(heuristicCraftCandidateScore(TARGET, segv).score).toBe(0);
  });
});

describe("sanitizerOutputFromCraftResult", () => {
  it("returns the winning attempt's output", () => {
    const r = craftResult({ model: "m", pocPath: "/p1", output: "heap-buffer-overflow" });
    expect(sanitizerOutputFromCraftResult(r)).toBe("heap-buffer-overflow");
  });
});

describe("runEnsembleCraft", () => {
  it("runs N trajectories across the model pool, judge-selects the best, aggregates accounting", async () => {
    const seen: string[] = [];
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> => {
      const model = opts.model ?? "auto";
      seen.push(model);
      // model-b crafts the matching heap overflow; the others a weaker crash.
      const idx = seen.length - 1;
      return craftResult({
        model,
        pocPath: `/poc-${idx}`,
        output:
          model === "model-b"
            ? "AddressSanitizer: heap-buffer-overflow in parse_header"
            : "AddressSanitizer: stack-buffer-overflow elsewhere",
        steps: 10 + idx,
        inputTokens: 100,
        outputTokens: 50,
        cost: 0.02,
      });
    };
    const judge: CraftCandidateJudge = async (_t, candidates) =>
      new Map(
        candidates.map((c) => [c.pocPath, { score: c.model === "model-b" ? 9 : 3, reason: c.model }]),
      );

    const result = await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 3,
      models: ["model-a", "model-b", "model-c"],
      craft: { evaluatePoc: async () => ({ triggered: true, output: "" }) },
      runCraft,
      judge,
    });

    // Three trajectories, one per pool model.
    expect(seen).toEqual(["model-a", "model-b", "model-c"]);
    // Winner is the judged-best (model-b), returned as a normal CraftScanResult.
    expect(result.model).toBe("model-b");
    expect(result.pocPath).toBe("/poc-1");
    // Aggregate accounting across ALL trajectories (honest compute spend).
    expect(result.steps).toBe(10 + 11 + 12);
    expect(result.inputTokens).toBe(300);
    expect(result.outputTokens).toBe(150);
    expect(result.estimatedCostUsd).toBeCloseTo(0.06, 6);
    expect(result.warnings.some((w) => w.includes("selected trajectory 2/3"))).toBe(true);
  });

  it("falls back to the heuristic scorer when the judge throws wholesale", async () => {
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> =>
      craftResult({
        model: opts.model ?? "auto",
        pocPath: `/poc-${opts.model}`,
        output:
          opts.model === "model-b"
            ? "AddressSanitizer: heap-buffer-overflow in parse_header"
            : "Segmentation fault",
      });
    const judge: CraftCandidateJudge = async () => {
      throw new Error("judge provider down");
    };
    const result = await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 2,
      models: ["model-a", "model-b"],
      craft: { evaluatePoc: async () => ({ triggered: true, output: "" }) },
      runCraft,
      judge,
    });
    // Heuristic ranks the heap-overflow (model-b) above the raw SEGV (model-a).
    expect(result.model).toBe("model-b");
    expect(result.warnings.some((w) => w.includes("heuristic selector fallback"))).toBe(true);
  });

  it("does NOT abort when one trajectory rejects — the healthy trajectory's candidate still wins", async () => {
    // model-a's provider throws mid-run (the glm-5.2/z-ai failure mode); model-b
    // crafts a real crash. With Promise.all this used to take the whole ensemble
    // down; with allSettled it must not.
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> => {
      if (opts.model === "model-a") throw new Error("z-ai provider hung/500");
      return craftResult({
        model: opts.model ?? "auto",
        pocPath: "/poc-b",
        output: "AddressSanitizer: heap-buffer-overflow in parse_header",
        steps: 7,
      });
    };
    const judge: CraftCandidateJudge = async (_t, candidates) =>
      new Map(candidates.map((c) => [c.pocPath, { score: 8, reason: c.model }]));
    const result = await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 2,
      models: ["model-a", "model-b"],
      craft: { evaluatePoc: async () => ({ triggered: true, output: "" }) },
      runCraft,
      judge,
    });
    expect(result.passed).toBe(true);
    expect(result.model).toBe("model-b");
    expect(result.pocPath).toBe("/poc-b");
    // Accounting aggregates over the SETTLED (surviving) trajectory only.
    expect(result.steps).toBe(7);
    // The failure is surfaced (debuggable) but not fatal.
    expect(result.warnings.some((w) => /1\/2 trajectories failed or timed out/.test(w))).toBe(true);
  });

  it("does NOT hang when one trajectory never resolves — the per-trajectory timeout unblocks the ensemble", async () => {
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> => {
      if (opts.model === "model-a") return new Promise<CraftScanResult>(() => {}); // hangs forever
      return craftResult({
        model: opts.model ?? "auto",
        pocPath: "/poc-b",
        output: "AddressSanitizer: heap-buffer-overflow in parse_header",
      });
    };
    const judge: CraftCandidateJudge = async (_t, candidates) =>
      new Map(candidates.map((c) => [c.pocPath, { score: 8, reason: c.model }]));
    const result = await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 2,
      models: ["model-a", "model-b"],
      craft: { evaluatePoc: async () => ({ triggered: true, output: "" }) },
      runCraft,
      judge,
      trajectoryTimeoutMs: 50,
    });
    expect(result.passed).toBe(true);
    expect(result.model).toBe("model-b");
    expect(result.warnings.some((w) => /timed out/.test(w))).toBe(true);
  });

  it("hands each trajectory a graceful wall-clock deadline BELOW the hard timeout (so a slow model exits with partial work, not a 0-step kill)", async () => {
    const seenDeadlines: Array<number | undefined> = [];
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> => {
      seenDeadlines.push(opts.deadlineMs);
      return craftResult({
        model: opts.model ?? "auto",
        pocPath: "/poc",
        output: "AddressSanitizer: heap-buffer-overflow in parse_header",
      });
    };
    const judge: CraftCandidateJudge = async (_t, candidates) =>
      new Map(candidates.map((c) => [c.pocPath, { score: 8, reason: c.model }]));
    const trajectoryTimeoutMs = 20 * 60_000;
    await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 2,
      models: ["gpt-5.5", "glm-5.2"],
      craft: { evaluatePoc: async () => ({ triggered: true, output: "" }) },
      runCraft,
      judge,
      trajectoryTimeoutMs,
    });
    expect(seenDeadlines).toHaveLength(2);
    // Every trajectory got a positive deadline strictly below the hard timeout,
    // leaving margin for one in-flight LLM call to finish before the race fires.
    for (const d of seenDeadlines) {
      expect(d).toBeDefined();
      expect(d!).toBeGreaterThan(0);
      expect(d!).toBeLessThan(trajectoryTimeoutMs);
    }
  });

  it("returns an honest failed result with a per-model failure summary when ALL trajectories fail", async () => {
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> => {
      throw new Error(`provider down for ${opts.model}`);
    };
    const result = await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 2,
      models: ["model-a", "model-b"],
      craft: { evaluatePoc: async () => ({ triggered: true, output: "" }) },
      runCraft,
      judge: async () => new Map(),
    });
    expect(result.passed).toBe(false);
    expect(result.pocPath).toBeUndefined();
    expect(result.warnings.some((w) => /2\/2 trajectories failed or timed out/.test(w))).toBe(true);
    // Distinguishable from a capability fail: names the per-model outcome.
    expect(result.warnings.some((w) => /model-a: error/.test(w))).toBe(true);
  });

  it("returns an honest failed result when no trajectory crashes (no PoC to grade)", async () => {
    const runCraft = async (opts: CraftScanOptions): Promise<CraftScanResult> =>
      craftResult({ model: opts.model ?? "auto" }); // no pocPath → no crash
    let judged = 0;
    const judge: CraftCandidateJudge = async () => {
      judged++;
      return new Map();
    };
    const result = await runEnsembleCraft({
      target: TARGET,
      runtime: "auto",
      n: 2,
      models: ["model-a", "model-b"],
      craft: { evaluatePoc: async () => ({ triggered: false, output: "" }) },
      runCraft,
      judge,
    });
    expect(result.passed).toBe(false);
    expect(result.pocPath).toBeUndefined();
    expect(judged).toBe(0); // nothing to judge
    expect(result.warnings.some((w) => w.includes("no crashing candidate"))).toBe(true);
  });
});
