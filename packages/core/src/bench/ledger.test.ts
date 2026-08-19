import { describe, it, expect } from "vitest";
import {
  emptyLedger,
  appendLedgerEntry,
  lastGreen,
  evaluateRegression,
  type LedgerEntry,
} from "./ledger.js";
import type { BenchScorecard } from "./scorecard.js";

function scorecard(successRate: number, fpRate: number, inconclusive = 0, cases = 10): BenchScorecard {
  return {
    schemaVersion: 1,
    manifestId: "corpus-v1",
    config: { passAtK: 1, maxTurns: 40, costCeilingUsd: null, ciSubset: true },
    totals: {
      cases,
      positives: cases,
      knownNegatives: 0,
      verified: Math.round(successRate * cases),
      refuted: 0,
      inconclusive,
    },
    successRate,
    successRateCI95: [Math.max(0, successRate - 0.1), Math.min(1, successRate + 0.1)],
    falsePositives: 0,
    fpRate,
    totalCostUsd: 1,
    costPerSuccessUsd: 0.1,
    totalAttackTurns: 0,
    byObjective: {},
    cases: [],
  };
}

function entry(runId: string, sc: BenchScorecard, green: boolean): LedgerEntry {
  return { runId, manifestId: sc.manifestId, championId: "champ", scorecard: sc, green };
}

describe("ledger append + lastGreen", () => {
  it("appends immutably", () => {
    const l0 = emptyLedger();
    const l1 = appendLedgerEntry(l0, entry("r1", scorecard(0.8, 0), true));
    expect(l0.entries).toHaveLength(0); // original untouched
    expect(l1.entries).toHaveLength(1);
  });

  it("lastGreen skips red entries", () => {
    let l = emptyLedger();
    l = appendLedgerEntry(l, entry("r1", scorecard(0.8, 0), true));
    l = appendLedgerEntry(l, entry("r2", scorecard(0.5, 0), false)); // red
    expect(lastGreen(l)!.runId).toBe("r1");
  });

  it("lastGreen is null when there is no green history", () => {
    let l = emptyLedger();
    l = appendLedgerEntry(l, entry("r1", scorecard(0.5, 0), false));
    expect(lastGreen(l)).toBeNull();
  });
});

describe("evaluateRegression", () => {
  it("passes a first run with no baseline", () => {
    const r = evaluateRegression(scorecard(0.7, 0.1), null);
    expect(r.passed).toBe(true);
    expect(r.baseline).toBeNull();
  });

  it("fails a first run that is mostly inconclusive (flaky infra)", () => {
    const r = evaluateRegression(scorecard(0.2, 0, 8, 10), null);
    expect(r.passed).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/inconclusive/);
  });

  it("passes when within the success/fp slack vs the baseline", () => {
    const base = entry("base", scorecard(0.8, 0.1), true);
    // 3pp drop in success, 2pp rise in fp — both within default 5pp slack.
    const r = evaluateRegression(scorecard(0.77, 0.12), base);
    expect(r.passed).toBe(true);
  });

  it("fails when success rate drops beyond threshold", () => {
    const base = entry("base", scorecard(0.8, 0.1), true);
    const r = evaluateRegression(scorecard(0.7, 0.1), base, { maxSuccessRateDrop: 0.05 });
    expect(r.passed).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/success rate regressed/);
    expect(r.reasons.join(" ")).toMatch(/base/);
  });

  it("fails when fp rate rises beyond threshold", () => {
    const base = entry("base", scorecard(0.8, 0.1), true);
    const r = evaluateRegression(scorecard(0.8, 0.25), base, { maxFpRateRise: 0.05 });
    expect(r.passed).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/false-positive rate regressed/);
  });

  it("an improvement passes (success up, fp down)", () => {
    const base = entry("base", scorecard(0.7, 0.2), true);
    const r = evaluateRegression(scorecard(0.9, 0.05), base);
    expect(r.passed).toBe(true);
  });

  it("a degenerate 0-case run is SKIPPED (not a false regression)", () => {
    // CI without LLM creds / sandbox executes 0 scans -> successRate 0, which
    // would otherwise read as a full-baseline regression. Must not fail.
    const base = entry("base", scorecard(0.8, 0.1), true);
    const r = evaluateRegression(scorecard(0, 0, 0, 0), base, { maxSuccessRateDrop: 0.05 });
    expect(r.passed).toBe(true);
    expect(r.reasons.join(" ")).toMatch(/degenerate run: 0 cases/);
    expect(r.reasons.join(" ")).not.toMatch(/regressed/);
  });
});
