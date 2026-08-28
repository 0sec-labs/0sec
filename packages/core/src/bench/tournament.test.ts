import { describe, it, expect } from "vitest";
import { parseManifest, type BenchManifest } from "./manifest.js";
import type { BenchScan } from "./runner.js";
import type { BenchScanResult } from "./oracle.js";
import {
  runTournament,
  compareScorecards,
  pickChampion,
  pairwiseDeltas,
  formatTournamentSummary,
  type VariantRunResult,
} from "./tournament.js";
import type { BenchVariant } from "./variant.js";
import { aggregateScorecard } from "./scorecard.js";
import { runBenchSuite } from "./runner.js";

// A corpus of N source-audit positives + M known-negatives, all sql-injection
// at the sink "SINK_MARKER" so a single mock scan can satisfy them.
function corpus(positives: number, negatives: number): BenchManifest {
  const cases: unknown[] = [];
  for (let i = 0; i < positives; i++) {
    cases.push({
      id: `pos-${i}`,
      target: { kind: "source-audit", package: `pkg-${i}`, version: "1.0.0" },
      objective: { type: "finding-match", vulnClass: "sql-injection", sinkMarkers: ["SINK_MARKER"] },
    });
  }
  for (let i = 0; i < negatives; i++) {
    cases.push({
      id: `neg-${i}`,
      target: { kind: "source-audit", package: `safe-${i}`, version: "9.9.9" },
      objective: { type: "finding-match", vulnClass: "sql-injection", sinkMarkers: ["SINK_MARKER"] },
      knownNegative: true,
    });
  }
  return parseManifest({ id: "tourney-corpus", cases });
}

// Variant behaviours:
//  - "strong": reports the sink finding on every POSITIVE (and stays quiet on
//    negatives) → high success, zero FP.
//  - "weak": never reports anything → zero success.
//  - "noisy": reports the sink finding on EVERY case incl. negatives → high
//    success but also high FP.
function scanFor(variantId: string): BenchScan {
  return async ({ case: c }): Promise<BenchScanResult> => {
    const positive = !c.knownNegative;
    const meta = { benchmarkMeta: { estimatedCostUsd: 0.2, attackTurns: 5 }, durationMs: 100 };
    const hit: BenchScanResult = {
      findings: [{ category: "sql-injection", description: "sqli at SINK_MARKER" }],
      ...meta,
    };
    const miss: BenchScanResult = { findings: [], ...meta };
    if (variantId === "strong") return positive ? hit : miss;
    if (variantId === "noisy") return hit; // fires on negatives too
    return miss; // weak
  };
}

const variantScan = (v: BenchVariant): BenchScan => scanFor(v.id);

describe("runTournament", () => {
  it("ranks a strong variant above a weak one and picks it champion", async () => {
    const m = corpus(8, 3);
    const t = await runTournament(m, {
      variants: [{ id: "weak" }, { id: "strong" }],
      variantScan,
    });
    expect(t.championId).toBe("strong");
    const strong = t.variants.find((v) => v.variant.id === "strong")!;
    const weak = t.variants.find((v) => v.variant.id === "weak")!;
    expect(strong.scorecard.successRate).toBe(1);
    expect(weak.scorecard.successRate).toBe(0);
    expect(strong.scorecard.fpRate).toBe(0);
  });

  it("a noisy variant's false positives show up in fpRate", async () => {
    const m = corpus(6, 4);
    const t = await runTournament(m, {
      variants: [{ id: "strong" }, { id: "noisy" }],
      variantScan,
    });
    const noisy = t.variants.find((v) => v.variant.id === "noisy")!;
    expect(noisy.scorecard.fpRate).toBe(1); // fired on every known-negative
    // Tie on success (both 100%) → champion broken by lower FP → strong.
    expect(t.championId).toBe("strong");
  });

  it("emits pairwise deltas with a Wilson-95 non-overlap significance flag", async () => {
    const m = corpus(20, 0); // big enough sample to separate 100% from 0%
    const t = await runTournament(m, {
      variants: [{ id: "strong" }, { id: "weak" }],
      variantScan,
    });
    expect(t.pairwise).toHaveLength(1);
    const d = t.pairwise[0];
    expect(d.a).toBe("strong"); // oriented better-first
    expect(d.b).toBe("weak");
    expect(d.successRateDelta).toBe(1);
    expect(d.significant).toBe(true);
  });

  it("marks a tiny-sample difference as NOT significant (overlapping CIs)", async () => {
    // 1 positive: 1/1 vs 0/1 — Wilson intervals are wide and overlap.
    const m = corpus(1, 0);
    const t = await runTournament(m, {
      variants: [{ id: "strong" }, { id: "weak" }],
      variantScan,
    });
    expect(t.pairwise[0].significant).toBe(false);
  });

  it("stamps generatedAt only when a clock is supplied", async () => {
    const m = corpus(2, 1);
    const withClock = await runTournament(m, {
      variants: [{ id: "strong" }],
      variantScan,
      clock: () => "2026-05-30T00:00:00.000Z",
    });
    expect(withClock.generatedAt).toBe("2026-05-30T00:00:00.000Z");
    const without = await runTournament(m, { variants: [{ id: "strong" }], variantScan });
    expect(without.generatedAt).toBeUndefined();
  });

  it("snapshots and freezes variants before constructing any scan", async () => {
    const champion: BenchVariant = {
      id: "strong",
      promptOverrides: { "source_audit.hypothesis": "Original champion prompt." },
    };
    const challenger: BenchVariant = {
      id: "weak",
      promptOverrides: { "source_audit.hypothesis": "Original challenger prompt." },
    };
    const seen: BenchVariant[] = [];
    const result = await runTournament(corpus(1, 0), {
      variants: [champion, challenger],
      variantScan: (variant) => {
        seen.push(variant);
        expect(Object.isFrozen(variant)).toBe(true);
        expect(Object.isFrozen(variant.promptOverrides)).toBe(true);
        champion.promptOverrides!["source_audit.hypothesis"] = "Mutated after snapshot.";
        challenger.promptOverrides!["source_audit.hypothesis"] = "Also mutated.";
        return scanFor(variant.id);
      },
    });
    expect(seen[0].promptOverrides).toEqual({
      "source_audit.hypothesis": "Original champion prompt.",
    });
    expect(seen[1].promptOverrides).toEqual({
      "source_audit.hypothesis": "Original challenger prompt.",
    });
    expect(result.variants.map((entry) => entry.variant.promptOverrides)).toEqual([
      { "source_audit.hypothesis": "Original champion prompt." },
      { "source_audit.hypothesis": "Original challenger prompt." },
    ]);
  });

  it("throws when no variants are supplied", async () => {
    await expect(
      runTournament(corpus(1, 0), { variants: [], variantScan }),
    ).rejects.toThrow(/no variants/);
  });
});

describe("runTournament — integration execution and scheduling", () => {
  it("interleaves variants per case without parallel target execution", async () => {
    const order: string[] = [];
    const tournament = await runTournament(corpus(2, 0), {
      variants: [{ id: "weak" }, { id: "strong" }],
      schedule: "case-major",
      executionFactory: (variant) => ({
        executionMetadata: { integrationId: "fixture", integrationVersion: "1" },
        scan: async (input) => {
          order.push(`${variant.id}:${input.case.id}`);
          return scanFor(variant.id)(input);
        },
      }),
    });
    expect(order).toEqual(["weak:pos-0", "strong:pos-0", "weak:pos-1", "strong:pos-1"]);
    expect(tournament.config.schedule).toBe("case-major");
    expect(tournament.variants[0].scorecard.cases[0].attempts[0].execution).toMatchObject({
      integrationId: "fixture",
    });
  });

  it("rejects ambiguous legacy and integration execution factories", async () => {
    await expect(runTournament(corpus(1, 0), {
      variants: [{ id: "strong" }],
      variantScan,
      executionFactory: () => ({ scan: scanFor("strong") }),
    })).rejects.toThrow(/variantScan or executionFactory/);
  });
});

describe("pickChampion tie-breaks", () => {
  function vr(id: string, successRate: number, fpRate: number, cps: number | null): VariantRunResult {
    return {
      variant: { id },
      scorecard: {
        schemaVersion: 1,
        manifestId: "m",
        config: {
          passAtK: 1,
          attemptPolicy: "pass-at-k",
          maxTurns: 1,
          costCeilingUsd: null,
          ciSubset: false,
        },
        totals: {
          cases: 1,
          positives: 1,
          knownNegatives: 0,
          verified: 1,
          refuted: 0,
          inconclusive: 0,
          attempts: 1,
          verifiedAttempts: 1,
          refutedAttempts: 0,
          inconclusiveAttempts: 0,
        },
        successRate,
        successRateCI95: [0, 1],
        attemptSuccessRate: successRate,
        attemptSuccessRateCI95: [0, 1],
        falsePositives: 0,
        fpRate,
        totalCostUsd: 0,
        costPerSuccessUsd: cps,
        totalAttackTurns: 0,
        totalInputTokens: 0,
        totalOutputTokens: 0,
        totalTokens: 0,
        byObjective: {},
        cases: [],
      },
    };
  }

  it("breaks a success-rate tie by lower FP rate", () => {
    expect(pickChampion([vr("a", 0.8, 0.2, 1), vr("b", 0.8, 0.1, 1)])).toBe("b");
  });

  it("breaks a success+fp tie by lower cost-per-success", () => {
    expect(pickChampion([vr("a", 0.8, 0.1, 2), vr("b", 0.8, 0.1, 1)])).toBe("b");
  });

  it("a null cost-per-success (no successes) loses to a finite one", () => {
    expect(pickChampion([vr("a", 0.8, 0.1, null), vr("b", 0.8, 0.1, 5)])).toBe("b");
  });
});

describe("compareScorecards / pairwiseDeltas helpers", () => {
  it("compareScorecards reports null cost delta when either side has no successes", () => {
    const a = aggregateScorecard(
      // both empty suites → costPerSuccess null
      {
        manifestId: "m",
        ciSubset: false,
        passAtK: 1,
        attemptPolicy: "pass-at-k",
        maxTurns: 1,
        costCeilingUsd: null,
        cases: [],
      },
    );
    const d = compareScorecards(a, a);
    expect(d.costPerSuccessDelta).toBeNull();
    expect(d.significant).toBe(false); // identical CIs overlap
  });

  it("formatTournamentSummary marks the champion with a star", async () => {
    const suite = await runBenchSuite(corpus(3, 0), { scan: scanFor("strong") });
    const sc = aggregateScorecard(suite);
    const summary = formatTournamentSummary({
      manifestId: "m",
      config: {
        passAtK: 1,
        attemptPolicy: "pass-at-k",
        maxTurns: 1,
        costCeilingUsd: null,
        ciSubset: false,
        schedule: "variant-major",
        variantIds: ["strong"],
      },
      variants: [{ variant: { id: "strong" }, scorecard: sc }],
      pairwise: [],
      championId: "strong",
    });
    expect(summary).toMatch(/strong ★/);
  });
});

describe("pairwiseDeltas orientation", () => {
  it("orders each pair better-first by success then -fp", async () => {
    const m = corpus(10, 2);
    const t = await runTournament(m, {
      variants: [{ id: "weak" }, { id: "noisy" }, { id: "strong" }],
      variantScan,
    });
    // 3 variants → 3 pairs.
    expect(t.pairwise).toHaveLength(3);
    // strong vs noisy: equal success (100%) but strong has lower fp → strong first.
    const sn = t.pairwise.find(
      (d) => (d.a === "strong" && d.b === "noisy") || (d.a === "noisy" && d.b === "strong"),
    )!;
    expect(sn.a).toBe("strong");
  });
});
