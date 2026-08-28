import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BenchManifest } from "@0sec/core";
import { objectiveOracleEvaluatorAttestation } from "@0sec/core";
import { sha256Bytes } from "../bench-improvement.js";

import {
  CALIBRATION_CHALLENGER_ID,
  CALIBRATION_CHAMPION_ID,
  materializeObjectiveOracleEvaluator,
  runZeroCostCalibration,
} from "../bench-calibration.js";

function manifest(): BenchManifest {
  return {
    id: "calibration-slice-v1",
    version: 1,
    cases: [
      {
        id: "positive-case",
        target: { kind: "source-audit", package: "fixture", version: "1.0.0", ecosystem: "npm" },
        objective: { type: "finding-match", vulnClass: "path-traversal", sinkMarkers: ["sink"] },
        knownNegative: false,
        ci: false,
        tags: ["fixture"],
      },
      {
        id: "negative-case",
        target: { kind: "kernel", reproducerRef: "fixture://negative", ecosystem: "linux-kernel" },
        objective: { type: "kasan-hit", signature: "use-after-free" },
        knownNegative: true,
        ci: false,
        tags: ["fixture"],
      },
    ],
  };
}

describe("zero-cost 0research calibration", () => {
  it("is byte-deterministic and records a complete provider-free no-uplift tournament", async () => {
    const first = await runZeroCostCalibration(manifest());
    const second = await runZeroCostCalibration(manifest());

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first.calibration).toEqual({
      schemaVersion: 1,
      mode: "zero-cost-no-uplift",
      networkAllowed: false,
      providerAllowed: false,
      expectedOutcome: "reject",
    });
    expect(first.tournament.config).toEqual({
      passAtK: 1,
      attemptPolicy: "pass-at-k",
      maxTurns: 1,
      costCeilingUsd: null,
      ciSubset: false,
      schedule: "variant-major",
      variantIds: [CALIBRATION_CHAMPION_ID, CALIBRATION_CHALLENGER_ID],
    });
    expect(first.tournament.championId).toBe(CALIBRATION_CHALLENGER_ID);
    expect(first.tournament.pairwise).toEqual([{
      a: CALIBRATION_CHAMPION_ID,
      b: CALIBRATION_CHALLENGER_ID,
      successRateDelta: 0,
      fpRateDelta: 0,
      costPerSuccessDelta: null,
      significant: false,
    }]);

    for (const variant of first.tournament.variants) {
      expect(variant.scorecard.totalCostUsd).toBe(0);
      expect(variant.scorecard.totalAttackTurns).toBe(0);
      expect(variant.scorecard.totals).toMatchObject({
        cases: 2,
        verified: 0,
        refuted: 2,
        inconclusive: 0,
      });
      expect(variant.scorecard.cases.flatMap((entry) => entry.attempts)).toHaveLength(2);
      expect(variant.scorecard.cases.every((entry) =>
        entry.attempts[0]?.costUsd === 0 &&
        entry.attempts[0]?.attackTurns === 0 &&
        entry.attempts[0]?.durationMs === 0
      )).toBe(true);
    }
  });

  it("refuses an empty calibration slice", async () => {
    await expect(runZeroCostCalibration({ ...manifest(), cases: [] }))
      .rejects.toThrow("calibration manifest must not be empty");
  });

  it("materializes the exact evaluator code, config, and canonical bundle bytes", () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-calibration-evaluator-"));
    const output = join(root, "evaluator");
    try {
      materializeObjectiveOracleEvaluator(output);
      const attestation = objectiveOracleEvaluatorAttestation();
      expect(sha256Bytes(readFileSync(join(output, "evaluator.js"))))
        .toBe(attestation.codeDigest);
      expect(sha256Bytes(readFileSync(join(output, "evaluator-config.json"))))
        .toBe(attestation.configDigest);
      expect(sha256Bytes(readFileSync(join(output, "evaluator-bundle.json"))))
        .toBe(attestation.bundleDigest);
      expect(readFileSync(join(output, "evaluator-bundle.json"), "utf8")).toBe(
        `${JSON.stringify({
          schemaVersion: 1,
          codeDigest: attestation.codeDigest,
          configDigest: attestation.configDigest,
        })}\n`,
      );
      expect(() => materializeObjectiveOracleEvaluator(output))
        .toThrow("evaluator output already exists");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
