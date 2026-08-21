import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";

import { registerBenchImprovementCommand } from "../bench-improvement.js";

const roots: string[] = [];
const digest = (character: string) => `sha256:${character.repeat(64)}`;

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "0sec-improvement-assess-"));
  roots.push(value);
  return value;
}

function sealedResult() {
  const score = (successRate: number, falsePositiveRate: number, costPerSuccessUsd: number) => ({
    cases: 10,
    successRate,
    successRateCI95: [Math.max(0, successRate - 0.1), Math.min(1, successRate + 0.1)],
    falsePositiveRate,
    costPerSuccessUsd,
    inconclusiveRate: 0,
  });
  return {
    schemaVersion: 1,
    candidateId: "candidate-1",
    manifestId: "improvement-v1",
    developmentCorpusDigest: digest("a"),
    heldOutCorpusDigest: digest("a"),
    negativeControlCorpusDigest: digest("a"),
    evaluatorDigestBefore: digest("b"),
    evaluatorDigestAfter: digest("b"),
    ciPassed: true,
    development: { champion: score(0.5, 0.02, 1), challenger: score(0.56, 0.02, 1.2) },
    heldOut: { champion: score(0.5, 0.02, 1), challenger: score(0.54, 0.02, 1.2) },
    negativeControls: {
      champion: { cases: 10, falsePositiveRate: 0.02, inconclusiveRate: 0 },
      challenger: { cases: 10, falsePositiveRate: 0.03, inconclusiveRate: 0 },
    },
    evidenceRefs: ["artifact:sealed-evaluation.json"],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("bench improvement-assess", () => {
  it("publishes a sealed source-change decision that still requires human approval", async () => {
    const directory = root();
    const resultPath = join(directory, "result.json");
    const basePath = join(directory, "base.txt");
    const candidatePath = join(directory, "candidate.txt");
    const outputDirectory = join(directory, "assessment");
    writeFileSync(resultPath, JSON.stringify(sealedResult()));
    writeFileSync(basePath, "champion artifact");
    writeFileSync(candidatePath, "challenger artifact");

    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const program = new Command();
    const bench = program.command("bench");
    registerBenchImprovementCommand(bench);
    await program.parseAsync([
      "node",
      "0sec",
      "bench",
      "improvement-assess",
      "--result",
      resultPath,
      "--base-artifact",
      basePath,
      "--candidate-artifact",
      candidatePath,
      "--output-dir",
      outputDirectory,
    ]);

    const decision = JSON.parse(readFileSync(join(outputDirectory, "promotion-decision.json"), "utf8"));
    const ledger = JSON.parse(readFileSync(join(outputDirectory, "ledger.json"), "utf8"));
    expect(decision.status).toBe("requires_human_approval");
    expect(ledger).toHaveLength(2);
    expect(ledger.map((entry: { type: string }) => entry.type)).toEqual([
      "candidate_recorded",
      "promotion_decided",
    ]);
    expect(stdout).toHaveBeenCalledWith(`${outputDirectory}\n`);
  });
});
