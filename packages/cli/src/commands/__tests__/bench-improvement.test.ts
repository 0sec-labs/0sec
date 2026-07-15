import {
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Command } from "commander";
import {
  aggregateScorecard,
  digestBenchManifest,
  pairwiseDeltas,
  pickChampion,
  type BenchManifest,
} from "@pwnkit/core";
import {
  canonicalResultJson,
  parseCandidateMetadata,
  parseTournamentPair,
  projectImprovementFromArtifacts,
  readArtifactJson,
  registerBenchImprovementCommand,
  writeResultAtomic,
} from "../bench-improvement.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "pwnkit-improvement-project-"));
  roots.push(value);
  return value;
}

function manifest(id: string, knownNegative = false): BenchManifest {
  return {
    id,
    version: 1,
    cases: Array.from({ length: 5 }, (_, index) =>
      ({
        id: `${id}-case-${index}`,
        target: { kind: "source-audit", package: "fixture", version: "1.0.0", ecosystem: "npm" },
        objective: { type: "finding-match", vulnClass: "path-traversal", sinkMarkers: ["sink"] },
        knownNegative,
        ci: false,
        tags: [],
      }),
    ),
  };
}

function scorecard(corpus: BenchManifest, successRate: number) {
  const verified = Math.round(corpus.cases.length * successRate);
  const cases = corpus.cases.map((entry, index) => ({
    id: entry.id,
    kind: entry.target.kind,
    objective: entry.objective.type,
    knownNegative: entry.knownNegative,
    tags: entry.tags,
    passAtK: 1,
    attempts: [],
    verdict: index < verified ? "verified" as const : "refuted" as const,
    falsePositive: entry.knownNegative && index < verified,
    costUsd: 8,
    attackTurns: 20,
  }));
  return aggregateScorecard({
    manifestId: corpus.id,
    ciSubset: false,
    passAtK: 1,
    maxTurns: 20,
    costCeilingUsd: 10,
    cases,
  });
}

function pair(corpus: BenchManifest, championSuccess: number, challengerSuccess: number) {
  const variants = [
    { variant: { id: "champion" }, scorecard: scorecard(corpus, championSuccess) },
    { variant: { id: "challenger" }, scorecard: scorecard(corpus, challengerSuccess) },
  ];
  return {
    manifest: corpus,
    tournament: {
      manifestId: corpus.id,
      config: {
        passAtK: 1,
        maxTurns: 20,
        costCeilingUsd: 10,
        ciSubset: false,
        variantIds: ["champion", "challenger"],
      },
      variants,
      pairwise: pairwiseDeltas(variants),
      championId: pickChampion(variants),
    },
  };
}

function fixtures() {
  const development = pair(manifest("development"), 0.4, 0.8);
  const heldOut = pair(manifest("held-out"), 0.4, 0.8);
  const controls = pair(manifest("controls", true), 0, 0);
  const candidate = {
    schemaVersion: 1,
    id: "pwnkit_source_hypothesis_001",
    evaluation: {
      manifestId: "research-run-v1",
      evaluatorDigest: `sha256:${"e".repeat(64)}`,
      developmentCorpusDigest: digestBenchManifest(development.manifest),
      heldOutCorpusDigest: digestBenchManifest(heldOut.manifest),
      negativeControlCorpusDigest: digestBenchManifest(controls.manifest),
    },
  };
  return { development, heldOut, controls, candidate };
}

function project() {
  const values = fixtures();
  return projectImprovementFromArtifacts({
    candidate: parseCandidateMetadata(values.candidate),
    championVariantId: "champion",
    challengerVariantId: "challenger",
    development: parseTournamentPair(values.development, "development"),
    heldOut: parseTournamentPair(values.heldOut, "held-out"),
    negativeControls: parseTournamentPair(values.controls, "controls"),
    evaluatorDigestBefore: `sha256:${"e".repeat(64)}`,
    evaluatorDigestAfter: `sha256:${"e".repeat(64)}`,
    ciEvidence: { passed: true, evidenceRefs: ["artifact:ci"] },
    evidenceRefs: ["artifact:tournaments", "artifact:ci"],
  });
}

describe("offline 0research improvement projection", () => {
  it("emits the exact portable v1 result with deduplicated evidence", () => {
    const result = project();
    expect(result.schemaVersion).toBe(1);
    expect(result.candidateId).toBe("pwnkit_source_hypothesis_001");
    expect(result.manifestId).toBe("research-run-v1");
    expect(result.heldOut.challenger.successRate).toBe(0.8);
    expect(result.negativeControls.challenger).toEqual({
      cases: 5,
      falsePositiveRate: 0,
      inconclusiveRate: 0,
    });
    expect(result.evidenceRefs).toEqual(["artifact:ci", "artifact:tournaments"]);
    expect(Object.keys(result).sort()).toEqual([
      "candidateId",
      "ciPassed",
      "development",
      "developmentCorpusDigest",
      "evaluatorDigestAfter",
      "evaluatorDigestBefore",
      "evidenceRefs",
      "heldOut",
      "heldOutCorpusDigest",
      "manifestId",
      "negativeControlCorpusDigest",
      "negativeControls",
      "schemaVersion",
    ]);
  });

  it("writes deterministic canonical JSON once and refuses replacement", () => {
    const output = join(root(), "nested", "result.json");
    const result = project();
    writeResultAtomic(output, result);
    expect(readFileSync(output, "utf8")).toBe(canonicalResultJson(result));
    expect(() => writeResultAtomic(output, result)).toThrow(/already exists/);
  });

  it("rejects evaluator and corpus drift", () => {
    const values = fixtures();
    const inputs = {
      candidate: parseCandidateMetadata(values.candidate),
      championVariantId: "champion",
      challengerVariantId: "challenger",
      development: parseTournamentPair(values.development, "development"),
      heldOut: parseTournamentPair(values.heldOut, "held-out"),
      negativeControls: parseTournamentPair(values.controls, "controls"),
      evaluatorDigestBefore: `sha256:${"e".repeat(64)}`,
      evaluatorDigestAfter: `sha256:${"f".repeat(64)}`,
      ciEvidence: { passed: true, evidenceRefs: ["artifact:ci"] },
      evidenceRefs: [],
    };
    expect(() => projectImprovementFromArtifacts(inputs)).toThrow(/evaluator changed/);
    inputs.evaluatorDigestAfter = `sha256:${"e".repeat(64)}`;
    inputs.candidate.evaluation.heldOutCorpusDigest = `sha256:${"0".repeat(64)}`;
    expect(() => projectImprovementFromArtifacts(inputs)).toThrow(/held-out corpus digest/);
  });

  it("rejects malformed tournament identity and score counts", () => {
    const values = fixtures();
    values.development.tournament.config.variantIds.reverse();
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /configured variant ids/,
    );
    values.development.tournament.config.variantIds.reverse();
    values.development.tournament.variants[0].scorecard.totals.inconclusive = 2;
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /verdict counts disagree|summary does not match/,
    );
  });

  it("rejects forged summaries and non-SHA evaluator labels", () => {
    const values = fixtures();
    values.development.tournament.variants[0].scorecard.successRate = 0.5;
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /summary does not match its raw cases/,
    );
    values.candidate.evaluation.evaluatorDigest = "sha256:evaluator";
    expect(() => parseCandidateMetadata(values.candidate)).toThrow(/lowercase SHA-256/);
  });

  it("rejects symlinked evidence inputs", () => {
    const dir = root();
    const target = join(dir, "candidate.json");
    const link = join(dir, "link.json");
    writeFileSync(target, JSON.stringify(fixtures().candidate));
    symlinkSync(target, link);
    expect(() => readArtifactJson(link, "candidate")).toThrow(/non-symlink/);
  });

  it("does not replace an existing output when command validation fails", async () => {
    const dir = root();
    const values = fixtures();
    const paths = {
      candidate: join(dir, "candidate.json"),
      development: join(dir, "development.json"),
      heldOut: join(dir, "held-out.json"),
      controls: join(dir, "controls.json"),
      ci: join(dir, "ci.json"),
      output: join(dir, "result.json"),
    };
    writeFileSync(paths.candidate, JSON.stringify(values.candidate));
    writeFileSync(paths.development, JSON.stringify(values.development));
    writeFileSync(paths.heldOut, JSON.stringify(values.heldOut));
    writeFileSync(paths.controls, JSON.stringify(values.controls));
    writeFileSync(paths.ci, JSON.stringify({
      schemaVersion: 1,
      passed: true,
      evidenceRefs: ["artifact:ci"],
    }));
    writeFileSync(paths.output, "sentinel\n");

    const program = new Command();
    program.exitOverride();
    const bench = program.command("bench");
    registerBenchImprovementCommand(bench);
    await expect(program.parseAsync([
      "node",
      "pwnkit",
      "bench",
      "improvement-project",
      "--candidate", paths.candidate,
      "--champion-variant", "champion",
      "--challenger-variant", "challenger",
      "--development", paths.development,
      "--held-out", paths.heldOut,
      "--negative-controls", paths.controls,
      "--evaluator-before", `sha256:${"e".repeat(64)}`,
      "--evaluator-after", `sha256:${"f".repeat(64)}`,
      "--ci-evidence", paths.ci,
      "--output", paths.output,
    ])).rejects.toThrow(/evaluator changed/);
    expect(readFileSync(paths.output, "utf8")).toBe("sentinel\n");
  });
});
