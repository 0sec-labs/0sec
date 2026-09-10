import { chmodSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseEvolutionConfig } from "./config.js";
import { evaluateEvolutionCandidate } from "./evaluation.js";
import { createEvolutionCandidate, snapshotEvolutionSource } from "./registry.js";
import type { EvolutionConfig, EvolutionSandbox, EvolutionSnapshot } from "./types.js";

const directories: string[] = [];
afterEach(() => {
  const unlock = (directory: string): void => {
    chmodSync(directory, 0o700);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) unlock(join(directory, entry.name));
    }
  };
  for (const directory of directories.splice(0)) {
    unlock(directory);
    rmSync(directory, { recursive: true, force: true });
  }
});

async function setup(): Promise<{ config: EvolutionConfig; baseline: EvolutionSnapshot; candidate: EvolutionSnapshot }> {
  const directory = mkdtempSync(join(tmpdir(), "0sec-evaluation-"));
  directories.push(directory);
  const sourceRoot = join(directory, "source");
  mkdirSync(join(sourceRoot, "src"), { recursive: true });
  writeFileSync(join(sourceRoot, "src", "detector.js"), "export const revision = 1;\n");
  const config = parseEvolutionConfig({
    schemaVersion: 1,
    sourceRoot,
    storePath: join(directory, "store"),
    image: "node:22-alpine",
    sourcePaths: ["src"],
    editablePaths: ["src"],
    command: ["node", "src/detector.js"],
    computeUsdPerSecond: 0.001,
    objective: "Detect the intended condition without reporting unrelated findings.",
    promotionPolicy: { minimumCases: 3 },
    repeats: 2,
    maxOutputBytes: 1024,
    cases: ["development", "held-out", "negative-control"].flatMap((lane, group) =>
      [0, 1, 2].map((index) => ({
        id: `${lane}-${index}`, lane,
        input: { key: group * 3 + index, index, negative: lane === "negative-control" },
        expected: { findings: lane === "negative-control" ? [] : [{ category: "intended", location: index }] },
      }))),
  });
  const baseline = await snapshotEvolutionSource(config);
  const file = baseline.files.find((entry) => entry.path === "src/detector.js")!;
  const candidate = await createEvolutionCandidate(baseline, {
    rationale: "Refine the detector", modelCostUsd: 0.01,
    edits: [{ path: file.path, beforeDigest: file.digest, content: "export const revision = 2;\n" }],
  }, config);
  return { config, baseline, candidate };
}

function probe(candidateId: string, mode: "correct" | "unrelated" | "negative-error" | "flaky"): EvolutionSandbox {
  const calls = new Map<number, number>();
  return async ({ snapshot, input }) => {
    const value = input as { key: number; index: number; negative: boolean };
    const challenger = snapshot.id === candidateId;
    const count = calls.get(value.key) ?? 0;
    if (challenger) calls.set(value.key, count + 1);
    const error = mode === "negative-error" && value.negative ? "negative control could not execute" : undefined;
    let findings: Array<{ category: string; location: number }> = [];
    if (!value.negative && (challenger || value.index !== 2)) {
      findings = [{ category: challenger && mode === "unrelated" ? "unrelated" : "intended", location: value.index }];
    }
    if (mode === "flaky" && challenger && value.index === 2 && count > 0) findings = [];
    return {
      exitCode: error ? null : 0, stdout: JSON.stringify({ findings }), stderr: "",
      durationMs: 10, timedOut: false, ...(error ? { error } : {}),
    };
  };
}

describe("independent evolution oracle", () => {
  it("requires the intended output, not any finding produced by the candidate", async () => {
    const { config, baseline, candidate } = await setup();
    const correct = await evaluateEvolutionCandidate(baseline, candidate, config, { sandbox: probe(candidate.id, "correct") });
    const unrelated = await evaluateEvolutionCandidate(baseline, candidate, config, { sandbox: probe(candidate.id, "unrelated") });
    expect(correct.decision.status).toBe("requires_human_approval");
    expect(unrelated.decision.status).toBe("rejected");
    expect(unrelated.result.heldOut.challenger.successRate).toBe(0);
  });

  it("does not inflate confidence by repeating the same fixtures", async () => {
    const { config, baseline, candidate } = await setup();
    const first = await evaluateEvolutionCandidate(baseline, candidate, config, { sandbox: probe(candidate.id, "correct") });
    const repeated = await evaluateEvolutionCandidate(baseline, candidate, { ...config, repeats: 4 }, { sandbox: probe(candidate.id, "correct") });
    for (const lane of ["development", "heldOut"] as const) {
      for (const variant of ["champion", "challenger"] as const) {
        expect(repeated.result[lane][variant].successRateCI95).toEqual(first.result[lane][variant].successRateCI95);
      }
    }
  });

  it("does not treat failed negative controls as evidence of precision", async () => {
    const { config, baseline, candidate } = await setup();
    const evaluation = await evaluateEvolutionCandidate(baseline, candidate, config, { sandbox: probe(candidate.id, "negative-error") });
    expect(evaluation.decision.status).toBe("rejected");
    expect(evaluation.result.negativeControls.challenger.inconclusiveRate).toBe(1);
  });

  it("rejects gains that disappear on repeated execution", async () => {
    const { config, baseline, candidate } = await setup();
    const evaluation = await evaluateEvolutionCandidate(baseline, candidate, config, { sandbox: probe(candidate.id, "flaky") });
    expect(evaluation.result.heldOut.challenger.successRate).toBeGreaterThan(evaluation.result.heldOut.champion.successRate);
    expect(evaluation.decision.status).toBe("rejected");
  });

  it("rejects missing controls and reused development inputs in held-out lanes", async () => {
    const { config } = await setup();
    expect(() => parseEvolutionConfig({ ...config, cases: config.cases.filter((entry) => entry.lane !== "negative-control") })).toThrow(/negative-control/);
    const cases = config.cases.map((entry) => ({ ...entry }));
    cases[3]!.input = cases[0]!.input;
    expect(() => parseEvolutionConfig({ ...config, cases })).toThrow(/duplicate evaluation input/);
  });
});
