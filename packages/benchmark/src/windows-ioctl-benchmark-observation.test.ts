import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  WINDOWS_IOCTL_BENCHMARK_OBSERVATION_SCHEMA,
  WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT,
  validateWindowsIoctlBenchmarkObservation,
  type WindowsIoctlBenchmarkBindingContext,
  type WindowsIoctlBenchmarkObservation,
} from "./windows-ioctl-benchmark-observation.js";
import {
  createWindowsLpeOpaqueProjection,
  type WindowsLpeOpaqueProjectionBundle,
} from "./windows-lpe-opaque-projection.js";
import {
  validateWindowsLpePairedCorpus,
  type WindowsLpePairedCorpusManifest,
} from "./windows-lpe-paired-corpus.js";
import { wilsonIntervalTuple } from "./wilson.js";

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../fixtures/windows-lpe-paired-corpus-contract-v2.json",
);
const manifest = JSON.parse(readFileSync(fixturePath, "utf8")) as WindowsLpePairedCorpusManifest;

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function sha(character: string): string {
  return character.repeat(64);
}

function opaque(byte: number): string {
  return Buffer.alloc(32, byte).toString("base64url");
}

function bundle(): WindowsLpeOpaqueProjectionBundle {
  let byte = 0;
  return createWindowsLpeOpaqueProjection(copy(manifest), {
    randomSource: () => {
      byte += 1;
      return Buffer.alloc(32, byte);
    },
  });
}

function contextFor(
  value: WindowsLpeOpaqueProjectionBundle,
  observation: WindowsIoctlBenchmarkObservation,
): WindowsIoctlBenchmarkBindingContext {
  return {
    manifest: copy(manifest),
    projection: copy(value.projection),
    resolver: copy(value.resolver),
    expectedResolverSha256: value.resolverSha256,
    handle: value.projection.targets[0]!.handle,
    expectedZeroverse: copy({ ...observation.zeroverse, counts: observation.counts }),
    policy: {
      rankCutoff: 2,
      minimumRecallPpm: 500_000,
      minimumControlSuppressionPpm: 1_000_000,
      maximumEmittedAbstentionRatePpm: 0,
      bestBaselineFoundAtCutoff: 1,
      minimumRecallLiftPpm: 2_000_000,
    },
  };
}

function observationFor(value: WindowsLpeOpaqueProjectionBundle): WindowsIoctlBenchmarkObservation {
  return {
    schemaVersion: WINDOWS_IOCTL_BENCHMARK_OBSERVATION_SCHEMA,
    "osec": {
      corpusId: manifest.corpusId,
      corpusManifestSha256: "",
      projectionSha256: value.projectionSha256,
      resolverSha256: value.resolverSha256,
      inventorySha256: value.inventorySha256,
      opaqueHandle: value.projection.targets[0]!.handle,
    },
    zeroverse: {
      driverSha256: sha("1"),
      analysisSha256: sha("2"),
      analysisReceiptSha256: sha("3"),
      siteUniverseManifestSha256: sha("4"),
      siteUniverseSha256: sha("5"),
      rankResultSha256: sha("6"),
      rankReceiptSha256: sha("7"),
      evaluationSha256: sha("8"),
    },
    counts: { siteUniverse: 5, rankResult: 5, evaluation: 5, candidateCount: 2 },
    rankRows: [
      {
        candidateId: sha("a"), candidateContentId: sha("b"), siteId: sha("c"),
        status: "candidate", score: 95, rank: 1,
      },
      {
        candidateId: sha("d"), candidateContentId: sha("e"), siteId: sha("f"),
        status: "candidate", score: 80, rank: 2,
      },
    ],
    evaluatorAggregate: {
      rankCutoff: 2,
      firstExpectedRank: 1,
      expectedCount: 2,
      expectedFoundAtCutoff: 2,
      controlCount: 2,
      controlsEmitted: 0,
      abstentionCount: 1,
      emittedAbstentionCount: 0,
      gates: {
        recallAtCutoff: true,
        controlSuppression: true,
        emittedAbstentionRate: true,
        baselineRecallLift: true,
        staticOnly: true,
      },
      passed: true,
    },
    timing: {
      startedAt: "2026-07-15T18:00:00.000Z",
      completedAt: "2026-07-15T18:00:01.000Z",
      durationMs: 1_000,
    },
    cost: { modelCalls: 1, inputTokens: 100, outputTokens: 25, estimatedUsd: 0.125 },
    safety: {
      evaluatorPrivate: true,
      agentVisible: false,
      benchmarkOnly: true,
      staticOnly: true,
      executionPerformed: false,
      executionAuthorized: false,
      runtimeConsumable: false,
      deviceIoctlAttempts: 0,
      researchFindingCreated: false,
      capabilityMeasure: false,
      reachabilityEstablished: false,
      vulnerabilityEstablished: false,
      impactEstablished: false,
      noveltyEstablished: false,
      claimEligible: false,
      bountyEligible: false,
      weaponization: false,
      automaticDisclosure: false,
      humanPromotionGate: true,
      humanReportGate: true,
    },
    proofLimit: WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT,
  };
}

function validFixture(): {
  bundle: WindowsLpeOpaqueProjectionBundle;
  context: WindowsIoctlBenchmarkBindingContext;
  observation: WindowsIoctlBenchmarkObservation;
} {
  const value = bundle();
  const observation = observationFor(value);
  const context = contextFor(value, observation);
  observation["osec"].corpusManifestSha256 = validateWindowsLpePairedCorpus(context.manifest).manifestSha256;
  return { bundle: value, context, observation };
}

describe("Windows IOCTL benchmark observation", () => {
  it("binds the evaluator-private closure and derives Wilson metrics without a finding or runner seam", () => {
    const { context, observation } = validFixture();
    const result = validateWindowsIoctlBenchmarkObservation(observation, context);

    expect(result.siteCount).toBe(5);
    expect(result.metrics).toEqual({
      recallAtCutoff: 1,
      recallAtCutoffCi95: wilsonIntervalTuple(2, 2),
      controlSuppression: 1,
      controlSuppressionCi95: wilsonIntervalTuple(2, 2),
      emittedAbstentionRate: 0,
      emittedAbstentionRateCi95: wilsonIntervalTuple(0, 2),
      mrrContributionPpm: 1_000_000,
      recallLiftPpm: 2_000_000,
      baselineWasZero: false,
    });
    expect(result.observation.safety).toMatchObject({
      evaluatorPrivate: true,
      agentVisible: false,
      executionPerformed: false,
      researchFindingCreated: false,
      humanReportGate: true,
    });
    expect(JSON.stringify(result)).not.toMatch(/caseId|family|advisoryId|groundTruth/i);
  });

  it("does not add evaluator commitments, identities, or labels to the agent projection", () => {
    const { bundle: value, context, observation } = validFixture();
    validateWindowsIoctlBenchmarkObservation(observation, context);
    const agentJson = JSON.stringify(value.projection);
    for (const forbidden of [
      observation["osec"].corpusManifestSha256,
      observation["osec"].resolverSha256,
      observation["osec"].inventorySha256,
      observation.zeroverse.evaluationSha256,
      "caseId", "family", "advisoryId", "groundTruth", "expectedCount", "controlCount",
    ]) {
      expect(agentJson).not.toContain(forbidden);
    }
    expect(value.projection.targets).toEqual(
      value.projection.targets.map(({ handle }) => ({ handle })),
    );
  });

  it("rejects corpus, projection, resolver, inventory, and handle substitution", () => {
    const { context, observation } = validFixture();
    for (const field of [
      "corpusManifestSha256", "projectionSha256", "resolverSha256", "inventorySha256",
    ] as const) {
      const mutated = copy(observation);
      mutated["osec"][field] = sha("0");
      expect(() => validateWindowsIoctlBenchmarkObservation(mutated, context)).toThrow(/evaluator corpus/);
    }

    const wrongHandle = copy(observation);
    wrongHandle["osec"].opaqueHandle = opaque(99);
    expect(() => validateWindowsIoctlBenchmarkObservation(wrongHandle, context)).toThrow(/evaluator corpus/);

    expect(() => validateWindowsIoctlBenchmarkObservation(observation, {
      ...context,
      expectedResolverSha256: sha("0"),
    })).toThrow(/independently pinned/);
    expect(() => validateWindowsIoctlBenchmarkObservation(observation, {
      ...context,
      handle: opaque(99),
    })).toThrow(/not bound by the evaluator projection/);
  });

  it("rejects unknown fields, digest aliases, and malformed 0verse bindings", () => {
    const { context, observation } = validFixture();
    const hidden = copy(observation) as unknown as Record<string, unknown>;
    hidden.labels = [];
    expect(() => validateWindowsIoctlBenchmarkObservation(hidden, context)).toThrow(/unknown or missing/);

    const alias = copy(observation);
    alias.zeroverse.evaluationSha256 = alias.zeroverse.rankResultSha256;
    expect(() => validateWindowsIoctlBenchmarkObservation(alias, context)).toThrow(/must not alias/);

    const malformed = copy(observation);
    malformed.zeroverse.analysisReceiptSha256 = "A".repeat(64);
    expect(() => validateWindowsIoctlBenchmarkObservation(malformed, context)).toThrow(/lowercase SHA-256/);

    for (const field of Object.keys(observation.zeroverse) as Array<keyof typeof observation.zeroverse>) {
      const untrustedDigest = copy(observation);
      untrustedDigest.zeroverse[field] = sha("f");
      expect(
        () => validateWindowsIoctlBenchmarkObservation(untrustedDigest, context),
        `zeroverse.${field}`,
      ).toThrow(/upstream verified commitment/);
    }

    for (const field of Object.keys(observation.counts) as Array<keyof typeof observation.counts>) {
      const untrustedContext = copy(context);
      untrustedContext.expectedZeroverse.counts[field] += 1;
      expect(
        () => validateWindowsIoctlBenchmarkObservation(observation, untrustedContext),
        `counts.${field}`,
      ).toThrow(/upstream verified count/);
    }
  });

  it("requires one site count, bounded candidate count, and complete deterministic rank rows", () => {
    const { context, observation } = validFixture();

    const mismatchedSites = copy(observation);
    mismatchedSites.counts.evaluation += 1;
    expect(() => validateWindowsIoctlBenchmarkObservation(mismatchedSites, context)).toThrow(/siteCount/);

    const tooManyCandidates = copy(observation);
    tooManyCandidates.counts.siteUniverse = 1;
    tooManyCandidates.counts.rankResult = 1;
    tooManyCandidates.counts.evaluation = 1;
    expect(() => validateWindowsIoctlBenchmarkObservation(tooManyCandidates, context)).toThrow(/candidateCount/);

    const missingRow = copy(observation);
    missingRow.rankRows.pop();
    expect(() => validateWindowsIoctlBenchmarkObservation(missingRow, context)).toThrow(/exactly cover/);

    const rankGap = copy(observation);
    rankGap.rankRows[1]!.rank = 3;
    expect(() => validateWindowsIoctlBenchmarkObservation(rankGap, context)).toThrow(/contiguous/);

    const wrongOrder = copy(observation);
    wrongOrder.rankRows[0]!.score = 80;
    wrongOrder.rankRows[1]!.score = 80;
    wrongOrder.rankRows[0]!.candidateContentId = sha("f");
    wrongOrder.rankRows[1]!.candidateContentId = sha("a");
    expect(() => validateWindowsIoctlBenchmarkObservation(wrongOrder, context)).toThrow(/score\/content order/);

    const duplicateSite = copy(observation);
    duplicateSite.rankRows[1]!.siteId = duplicateSite.rankRows[0]!.siteId;
    expect(() => validateWindowsIoctlBenchmarkObservation(duplicateSite, context)).toThrow(/duplicate siteId/);
  });

  it("rejects inconsistent evaluator aggregates without exposing row labels", () => {
    const { context, observation } = validFixture();

    const incompletePartition = copy(observation);
    incompletePartition.evaluatorAggregate.abstentionCount = 0;
    expect(() => validateWindowsIoctlBenchmarkObservation(incompletePartition, context)).toThrow(/aggregate counts/);

    const impossibleRecall = copy(observation);
    impossibleRecall.evaluatorAggregate.expectedFoundAtCutoff = 3;
    impossibleRecall.evaluatorAggregate.rankCutoff = 1;
    expect(() => validateWindowsIoctlBenchmarkObservation(impossibleRecall, context)).toThrow(/aggregate counts/);

    const gateMismatch = copy(observation);
    gateMismatch.evaluatorAggregate.gates.recallAtCutoff = false;
    expect(() => validateWindowsIoctlBenchmarkObservation(gateMismatch, context)).toThrow(/trusted threshold policy/);

    const selfAssertedPass = copy(observation);
    expect(() => validateWindowsIoctlBenchmarkObservation(selfAssertedPass, {
      ...context,
      policy: { ...context.policy, minimumRecallPpm: 1_000_000, minimumRecallLiftPpm: 3_000_000 },
    })).toThrow(/trusted threshold policy/);

    const selfAssertedOverallPass = copy(observation);
    selfAssertedOverallPass.evaluatorAggregate.passed = false;
    expect(() => validateWindowsIoctlBenchmarkObservation(selfAssertedOverallPass, context)).toThrow(/conjunction/);

    const impossibleFirstRank = copy(observation);
    impossibleFirstRank.evaluatorAggregate.firstExpectedRank = null;
    expect(() => validateWindowsIoctlBenchmarkObservation(impossibleFirstRank, context)).toThrow(/aggregate counts/);

    expect(() => validateWindowsIoctlBenchmarkObservation(observation, {
      ...context,
      policy: { ...context.policy, bestBaselineFoundAtCutoff: 3 },
    })).toThrow(/aggregate counts/);
    expect(() => validateWindowsIoctlBenchmarkObservation(observation, {
      ...context,
      policy: { ...context.policy, minimumRecallLiftPpm: 10_000_001 },
    })).toThrow(/integer/);
  });

  it("derives bounded MRR and Recall@k baseline lift from private rank and trusted policy", () => {
    const { context, observation } = validFixture();
    observation.evaluatorAggregate.firstExpectedRank = 2;
    const result = validateWindowsIoctlBenchmarkObservation(observation, context);
    expect(result.metrics.mrrContributionPpm).toBe(500_000);
    expect(result.metrics.recallLiftPpm).toBe(2_000_000);
    expect(result.metrics.baselineWasZero).toBe(false);

    const noHit = copy(observation);
    noHit.evaluatorAggregate.firstExpectedRank = null;
    noHit.evaluatorAggregate.expectedFoundAtCutoff = 0;
    noHit.evaluatorAggregate.gates.recallAtCutoff = false;
    noHit.evaluatorAggregate.gates.baselineRecallLift = false;
    noHit.evaluatorAggregate.passed = false;
    expect(validateWindowsIoctlBenchmarkObservation(noHit, context).metrics).toMatchObject({
      mrrContributionPpm: 0,
      recallLiftPpm: 0,
      baselineWasZero: false,
    });

    const zeroBaselineContext = copy(context);
    zeroBaselineContext.policy.bestBaselineFoundAtCutoff = 0;
    const zeroBaseline = copy(observation);
    zeroBaseline.evaluatorAggregate.gates.baselineRecallLift = false;
    zeroBaseline.evaluatorAggregate.passed = false;
    expect(validateWindowsIoctlBenchmarkObservation(zeroBaseline, zeroBaselineContext).metrics).toMatchObject({
      recallLiftPpm: null,
      baselineWasZero: true,
    });

    const claimedInfiniteLift = copy(observation);
    expect(() => validateWindowsIoctlBenchmarkObservation(claimedInfiniteLift, zeroBaselineContext)).toThrow(
      /trusted threshold policy/,
    );
  });

  it("binds canonical timing and bounded cost fields", () => {
    const { context, observation } = validFixture();
    const wrongDuration = copy(observation);
    wrongDuration.timing.durationMs = 999;
    expect(() => validateWindowsIoctlBenchmarkObservation(wrongDuration, context)).toThrow(/exactly bind/);

    const offsetTime = copy(observation);
    offsetTime.timing.startedAt = "2026-07-15T20:00:00+02:00";
    expect(() => validateWindowsIoctlBenchmarkObservation(offsetTime, context)).toThrow(/canonical UTC/);

    const negativeCost = copy(observation);
    negativeCost.cost.estimatedUsd = -0.01;
    expect(() => validateWindowsIoctlBenchmarkObservation(negativeCost, context)).toThrow(/bounded non-negative/);
  });

  it("fails closed if any static, no-finding, no-claim, or human gate changes", () => {
    const { context, observation } = validFixture();
    for (const [field, value] of Object.entries(observation.safety)) {
      const mutated = copy(observation);
      const safety = mutated.safety as unknown as Record<string, unknown>;
      safety[field] = typeof value === "boolean" ? !value : 1;
      expect(
        () => validateWindowsIoctlBenchmarkObservation(mutated, context),
        `safety.${field}`,
      ).toThrow(/must remain fail-closed/);
    }

    const proofLimit = copy(observation);
    proofLimit.proofLimit = "stronger claim" as typeof WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT;
    expect(() => validateWindowsIoctlBenchmarkObservation(proofLimit, context)).toThrow(/proof limit/);
  });
});
