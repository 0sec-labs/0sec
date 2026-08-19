import {
  validateWindowsLpePairedCorpus,
  type WindowsLpePairedCorpusManifest,
} from "./windows-lpe-paired-corpus.js";
import {
  validateWindowsLpeAgentProjection,
  validateWindowsLpeHandleResolver,
  type WindowsLpeAgentProjection,
  type WindowsLpeHandleResolver,
} from "./windows-lpe-opaque-projection.js";
import { wilsonIntervalTuple } from "./wilson.js";

export const WINDOWS_IOCTL_BENCHMARK_OBSERVATION_SCHEMA =
  "pwnkit.windows-ioctl-benchmark-observation/v1" as const;

export const WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT =
  "Evaluator-private import of commitment-bound 0verse Windows IOCTL static ranking and blinded aggregate evaluation only. It does not execute a target, resolve or expose a label, create a Research Finding, establish reachability, vulnerability, impact, novelty, claim or bounty eligibility, authorize disclosure, or provide weaponization evidence." as const;

const SHA256 = /^[a-f0-9]{64}$/;
const OPAQUE = /^[A-Za-z0-9_-]{43}$/;
const MAX_SITE_COUNT = 8_192;
const MAX_CANDIDATE_COUNT = 4_096;
const MAX_DURATION_MS = 7 * 24 * 60 * 60 * 1_000;
const RATE_SCALE_PPM = 1_000_000;

export interface WindowsIoctlBenchmarkRankRow {
  candidateId: string;
  candidateContentId: string;
  siteId: string;
  status: "candidate";
  score: number;
  rank: number;
}

export interface WindowsIoctlBenchmarkObservation {
  schemaVersion: typeof WINDOWS_IOCTL_BENCHMARK_OBSERVATION_SCHEMA;
  pwnkit: {
    corpusId: string;
    corpusManifestSha256: string;
    projectionSha256: string;
    resolverSha256: string;
    inventorySha256: string;
    opaqueHandle: string;
  };
  zeroverse: {
    driverSha256: string;
    analysisSha256: string;
    analysisReceiptSha256: string;
    siteUniverseManifestSha256: string;
    siteUniverseSha256: string;
    rankResultSha256: string;
    rankReceiptSha256: string;
    evaluationSha256: string;
  };
  counts: {
    siteUniverse: number;
    rankResult: number;
    evaluation: number;
    candidateCount: number;
  };
  rankRows: WindowsIoctlBenchmarkRankRow[];
  evaluatorAggregate: {
    rankCutoff: number;
    firstExpectedRank: number | null;
    expectedCount: number;
    expectedFoundAtCutoff: number;
    controlCount: number;
    controlsEmitted: number;
    abstentionCount: number;
    emittedAbstentionCount: number;
    gates: {
      recallAtCutoff: boolean;
      controlSuppression: boolean;
      emittedAbstentionRate: boolean;
      baselineRecallLift: boolean;
      staticOnly: true;
    };
    passed: boolean;
  };
  timing: {
    startedAt: string;
    completedAt: string;
    durationMs: number;
  };
  cost: {
    modelCalls: number;
    inputTokens: number;
    outputTokens: number;
    estimatedUsd: number;
  };
  safety: {
    evaluatorPrivate: true;
    agentVisible: false;
    benchmarkOnly: true;
    staticOnly: true;
    executionPerformed: false;
    executionAuthorized: false;
    runtimeConsumable: false;
    deviceIoctlAttempts: 0;
    researchFindingCreated: false;
    capabilityMeasure: false;
    reachabilityEstablished: false;
    vulnerabilityEstablished: false;
    impactEstablished: false;
    noveltyEstablished: false;
    claimEligible: false;
    bountyEligible: false;
    weaponization: false;
    automaticDisclosure: false;
    humanPromotionGate: true;
    humanReportGate: true;
  };
  proofLimit: typeof WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT;
}

export interface WindowsIoctlBenchmarkBindingContext {
  manifest: WindowsLpePairedCorpusManifest;
  projection: WindowsLpeAgentProjection;
  resolver: WindowsLpeHandleResolver;
  /** Independently provisioned evaluator commitment, not read from the resolver itself. */
  expectedResolverSha256: string;
  handle: string;
  /** Commitments and cardinalities authenticated by upstream 0verse verifiers. */
  expectedZeroverse: WindowsIoctlBenchmarkObservation["zeroverse"] & {
    counts: WindowsIoctlBenchmarkObservation["counts"];
  };
  /** Evaluator-owned policy. Rates use exact parts-per-million integers. */
  policy: {
    rankCutoff: number;
    minimumRecallPpm: number;
    minimumControlSuppressionPpm: number;
    maximumEmittedAbstentionRatePpm: number;
    bestBaselineFoundAtCutoff: number;
    minimumRecallLiftPpm: number;
  };
}

export interface ValidatedWindowsIoctlBenchmarkObservation {
  observation: WindowsIoctlBenchmarkObservation;
  siteCount: number;
  metrics: {
    recallAtCutoff: number;
    recallAtCutoffCi95: [number, number];
    controlSuppression: number;
    controlSuppressionCi95: [number, number];
    emittedAbstentionRate: number;
    emittedAbstentionRateCi95: [number, number];
    mrrContributionPpm: number;
    recallLiftPpm: number | null;
    baselineWasZero: boolean;
  };
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as JsonRecord;
}

function exact(value: unknown, name: string, fields: readonly string[]): JsonRecord {
  const row = record(value, name);
  const actual = Object.keys(row).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${name} has unknown or missing fields`);
  }
  return row;
}

function digest(value: unknown, name: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${name} must be a lowercase SHA-256`);
  }
  return value;
}

function opaque(value: unknown, name: string): string {
  if (typeof value !== "string" || !OPAQUE.test(value)
    || Buffer.from(value, "base64url").byteLength !== 32
    || Buffer.from(value, "base64url").toString("base64url") !== value) {
    throw new Error(`${name} must be a canonical opaque 256-bit handle`);
  }
  return value;
}

function integer(value: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${name} must be an integer in [${minimum}, ${maximum}]`);
  }
  return Number(value);
}

function finiteCost(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1_000_000
    || Number(value.toFixed(6)) !== value) {
    throw new Error(`${name} must be a bounded non-negative number`);
  }
  return value;
}

function utcTimestamp(value: unknown, name: string): { text: string; milliseconds: number } {
  if (typeof value !== "string" || value.length > 32
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    throw new Error(`${name} must be a canonical UTC RFC3339 timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error(`${name} must be a valid timestamp`);
  const normalized = new Date(milliseconds).toISOString();
  if (normalized !== (value.includes(".") ? value : value.replace("Z", ".000Z"))) {
    throw new Error(`${name} must be a valid canonical timestamp`);
  }
  return { text: value, milliseconds };
}

function bool(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${name} must be boolean`);
  return value;
}

function nullableRank(value: unknown, name: string): number | null {
  return value === null ? null : integer(value, name, 1, MAX_CANDIDATE_COUNT);
}

function ratePass(successes: number, attempts: number, thresholdPpm: number, minimum: boolean): boolean {
  if (attempts === 0) return minimum ? thresholdPpm === 0 : true;
  const scaled = successes * RATE_SCALE_PPM;
  const threshold = thresholdPpm * attempts;
  return minimum ? scaled >= threshold : scaled <= threshold;
}

function parseRankRows(value: unknown, candidateCount: number): WindowsIoctlBenchmarkRankRow[] {
  if (!Array.isArray(value) || value.length !== candidateCount) {
    throw new Error("rankRows must exactly cover candidateCount");
  }
  const rows = value.map((raw, index): WindowsIoctlBenchmarkRankRow => {
    const name = `rankRows[${index}]`;
    const row = exact(raw, name, [
      "candidateId", "candidateContentId", "siteId", "status", "score", "rank",
    ]);
    if (row.status !== "candidate") throw new Error(`${name}.status must be candidate`);
    const parsed: WindowsIoctlBenchmarkRankRow = {
      candidateId: digest(row.candidateId, `${name}.candidateId`),
      candidateContentId: digest(row.candidateContentId, `${name}.candidateContentId`),
      siteId: digest(row.siteId, `${name}.siteId`),
      status: "candidate",
      score: integer(row.score, `${name}.score`, 0, 100),
      rank: integer(row.rank, `${name}.rank`, 1, MAX_CANDIDATE_COUNT),
    };
    if (parsed.rank !== index + 1) throw new Error("rankRows must use complete contiguous ranks");
    return parsed;
  });
  for (const key of ["candidateId", "candidateContentId", "siteId"] as const) {
    if (new Set(rows.map((row) => row[key])).size !== rows.length) {
      throw new Error(`rankRows contains duplicate ${key}`);
    }
  }
  for (let index = 1; index < rows.length; index += 1) {
    const previous = rows[index - 1]!;
    const current = rows[index]!;
    if (previous.score < current.score
      || (previous.score === current.score
        && previous.candidateContentId >= current.candidateContentId)) {
      throw new Error("rankRows are not in deterministic 0verse score/content order");
    }
  }
  return rows;
}

function parseSafety(value: unknown): WindowsIoctlBenchmarkObservation["safety"] {
  const fields = [
    "evaluatorPrivate", "agentVisible", "benchmarkOnly", "staticOnly", "executionPerformed",
    "executionAuthorized", "runtimeConsumable", "deviceIoctlAttempts", "researchFindingCreated",
    "capabilityMeasure", "reachabilityEstablished", "vulnerabilityEstablished", "impactEstablished",
    "noveltyEstablished", "claimEligible", "bountyEligible", "weaponization", "automaticDisclosure",
    "humanPromotionGate", "humanReportGate",
  ] as const;
  const row = exact(value, "safety", fields);
  const expected: WindowsIoctlBenchmarkObservation["safety"] = {
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
  };
  for (const [field, expectedValue] of Object.entries(expected)) {
    if (row[field] !== expectedValue) throw new Error(`safety.${field} must remain fail-closed`);
  }
  return expected;
}

/**
 * Validate one evaluator-private observation. This is deliberately a pure parser:
 * it accepts no runner, callback, command, target path, or Research Finding type.
 * The validated result must remain inside the evaluator boundary.
 */
export function validateWindowsIoctlBenchmarkObservation(
  value: unknown,
  context: WindowsIoctlBenchmarkBindingContext,
): ValidatedWindowsIoctlBenchmarkObservation {
  const manifest = validateWindowsLpePairedCorpus(context.manifest);
  const projection = validateWindowsLpeAgentProjection(context.projection);
  const bundle = validateWindowsLpeHandleResolver({
    manifest: manifest.manifest,
    projection,
    resolver: context.resolver,
  });
  const expectedResolverSha256 = digest(context.expectedResolverSha256, "expectedResolverSha256");
  if (bundle.resolverSha256 !== expectedResolverSha256) {
    throw new Error("resolver does not match the independently pinned evaluator commitment");
  }
  const handle = opaque(context.handle, "context.handle");
  if (!projection.targets.some((target) => target.handle === handle)
    || !bundle.resolver.entries.some((entry) => entry.handle === handle)) {
    throw new Error("opaque handle is not bound by the evaluator projection");
  }

  const top = exact(value, "observation", [
    "schemaVersion", "pwnkit", "zeroverse", "counts", "rankRows", "evaluatorAggregate",
    "timing", "cost", "safety", "proofLimit",
  ]);
  if (top.schemaVersion !== WINDOWS_IOCTL_BENCHMARK_OBSERVATION_SCHEMA) {
    throw new Error("unsupported Windows IOCTL benchmark observation schema");
  }
  if (top.proofLimit !== WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT) {
    throw new Error("Windows IOCTL benchmark proof limit mismatch");
  }

  const pwnkit = exact(top.pwnkit, "pwnkit", [
    "corpusId", "corpusManifestSha256", "projectionSha256", "resolverSha256",
    "inventorySha256", "opaqueHandle",
  ]);
  const pwnkitBindings = {
    corpusId: pwnkit.corpusId,
    corpusManifestSha256: digest(pwnkit.corpusManifestSha256, "pwnkit.corpusManifestSha256"),
    projectionSha256: digest(pwnkit.projectionSha256, "pwnkit.projectionSha256"),
    resolverSha256: digest(pwnkit.resolverSha256, "pwnkit.resolverSha256"),
    inventorySha256: digest(pwnkit.inventorySha256, "pwnkit.inventorySha256"),
    opaqueHandle: opaque(pwnkit.opaqueHandle, "pwnkit.opaqueHandle"),
  };
  if (pwnkitBindings.corpusId !== manifest.manifest.corpusId
    || pwnkitBindings.corpusManifestSha256 !== manifest.manifestSha256
    || pwnkitBindings.projectionSha256 !== bundle.projectionSha256
    || pwnkitBindings.resolverSha256 !== bundle.resolverSha256
    || pwnkitBindings.inventorySha256 !== bundle.inventorySha256
    || pwnkitBindings.opaqueHandle !== handle) {
    throw new Error("observation does not bind the evaluator corpus/projection/resolver context");
  }

  const zeroverseRaw = exact(top.zeroverse, "zeroverse", [
    "driverSha256", "analysisSha256", "analysisReceiptSha256", "siteUniverseManifestSha256",
    "siteUniverseSha256", "rankResultSha256", "rankReceiptSha256", "evaluationSha256",
  ]);
  const zeroverse = Object.fromEntries(Object.entries(zeroverseRaw).map(([field, raw]) => [
    field, digest(raw, `zeroverse.${field}`),
  ])) as unknown as WindowsIoctlBenchmarkObservation["zeroverse"];
  if (new Set(Object.values(zeroverse)).size !== Object.keys(zeroverse).length) {
    throw new Error("0verse digest roles must not alias one another");
  }
  const expectedZeroverseRaw = exact(context.expectedZeroverse, "expectedZeroverse", [
    "driverSha256", "analysisSha256", "analysisReceiptSha256", "siteUniverseManifestSha256",
    "siteUniverseSha256", "rankResultSha256", "rankReceiptSha256", "evaluationSha256", "counts",
  ]);
  for (const field of Object.keys(zeroverse) as Array<keyof typeof zeroverse>) {
    if (digest(expectedZeroverseRaw[field], `expectedZeroverse.${field}`) !== zeroverse[field]) {
      throw new Error(`zeroverse.${field} does not match the upstream verified commitment`);
    }
  }

  const countsRaw = exact(top.counts, "counts", [
    "siteUniverse", "rankResult", "evaluation", "candidateCount",
  ]);
  const counts: WindowsIoctlBenchmarkObservation["counts"] = {
    siteUniverse: integer(countsRaw.siteUniverse, "counts.siteUniverse", 1, MAX_SITE_COUNT),
    rankResult: integer(countsRaw.rankResult, "counts.rankResult", 1, MAX_SITE_COUNT),
    evaluation: integer(countsRaw.evaluation, "counts.evaluation", 1, MAX_SITE_COUNT),
    candidateCount: integer(countsRaw.candidateCount, "counts.candidateCount", 0, MAX_CANDIDATE_COUNT),
  };
  if (counts.siteUniverse !== counts.rankResult || counts.siteUniverse !== counts.evaluation) {
    throw new Error("siteCount must be identical across universe, rank result, and evaluation");
  }
  if (counts.candidateCount > counts.siteUniverse) {
    throw new Error("candidateCount cannot exceed the complete site universe");
  }
  const expectedCountsRaw = exact(expectedZeroverseRaw.counts, "expectedZeroverse.counts", [
    "siteUniverse", "rankResult", "evaluation", "candidateCount",
  ]);
  for (const field of Object.keys(counts) as Array<keyof typeof counts>) {
    if (integer(expectedCountsRaw[field], `expectedZeroverse.counts.${field}`, 0, MAX_SITE_COUNT)
      !== counts[field]) {
      throw new Error(`counts.${field} does not match the upstream verified count`);
    }
  }
  const rankRows = parseRankRows(top.rankRows, counts.candidateCount);

  const policyRaw = exact(context.policy, "policy", [
    "rankCutoff", "minimumRecallPpm", "minimumControlSuppressionPpm",
    "maximumEmittedAbstentionRatePpm", "bestBaselineFoundAtCutoff", "minimumRecallLiftPpm",
  ]);
  const policy = {
    rankCutoff: integer(policyRaw.rankCutoff, "policy.rankCutoff", 1, MAX_CANDIDATE_COUNT),
    minimumRecallPpm: integer(policyRaw.minimumRecallPpm, "policy.minimumRecallPpm", 0, RATE_SCALE_PPM),
    minimumControlSuppressionPpm: integer(policyRaw.minimumControlSuppressionPpm, "policy.minimumControlSuppressionPpm", 0, RATE_SCALE_PPM),
    maximumEmittedAbstentionRatePpm: integer(policyRaw.maximumEmittedAbstentionRatePpm, "policy.maximumEmittedAbstentionRatePpm", 0, RATE_SCALE_PPM),
    bestBaselineFoundAtCutoff: integer(policyRaw.bestBaselineFoundAtCutoff, "policy.bestBaselineFoundAtCutoff", 0, MAX_SITE_COUNT),
    minimumRecallLiftPpm: integer(policyRaw.minimumRecallLiftPpm, "policy.minimumRecallLiftPpm", 0, 10 * RATE_SCALE_PPM),
  };

  const aggregateRaw = exact(top.evaluatorAggregate, "evaluatorAggregate", [
    "rankCutoff", "firstExpectedRank", "expectedCount", "expectedFoundAtCutoff", "controlCount", "controlsEmitted",
    "abstentionCount", "emittedAbstentionCount", "gates", "passed",
  ]);
  const aggregate = {
    rankCutoff: integer(aggregateRaw.rankCutoff, "evaluatorAggregate.rankCutoff", 1, MAX_CANDIDATE_COUNT),
    firstExpectedRank: nullableRank(aggregateRaw.firstExpectedRank, "evaluatorAggregate.firstExpectedRank"),
    expectedCount: integer(aggregateRaw.expectedCount, "evaluatorAggregate.expectedCount", 1, MAX_SITE_COUNT),
    expectedFoundAtCutoff: integer(aggregateRaw.expectedFoundAtCutoff, "evaluatorAggregate.expectedFoundAtCutoff", 0, MAX_SITE_COUNT),
    controlCount: integer(aggregateRaw.controlCount, "evaluatorAggregate.controlCount", 1, MAX_SITE_COUNT),
    controlsEmitted: integer(aggregateRaw.controlsEmitted, "evaluatorAggregate.controlsEmitted", 0, MAX_SITE_COUNT),
    abstentionCount: integer(aggregateRaw.abstentionCount, "evaluatorAggregate.abstentionCount", 0, MAX_SITE_COUNT),
    emittedAbstentionCount: integer(aggregateRaw.emittedAbstentionCount, "evaluatorAggregate.emittedAbstentionCount", 0, MAX_SITE_COUNT),
  };
  if (aggregate.rankCutoff !== policy.rankCutoff
    || policy.bestBaselineFoundAtCutoff > aggregate.expectedCount
    || aggregate.expectedCount + aggregate.controlCount + aggregate.abstentionCount !== counts.siteUniverse
    || aggregate.expectedFoundAtCutoff > Math.min(aggregate.expectedCount, aggregate.rankCutoff, counts.candidateCount)
    || aggregate.controlsEmitted > Math.min(aggregate.controlCount, counts.candidateCount)
    || aggregate.emittedAbstentionCount > Math.min(aggregate.abstentionCount, counts.candidateCount)
    || aggregate.controlsEmitted + aggregate.emittedAbstentionCount > counts.candidateCount
    || (aggregate.firstExpectedRank === null) !== (aggregate.expectedFoundAtCutoff === 0)
    || (aggregate.firstExpectedRank !== null
      && aggregate.firstExpectedRank > Math.min(aggregate.rankCutoff, counts.candidateCount))) {
    throw new Error("evaluator aggregate counts are inconsistent with the bound site universe");
  }
  const gatesRaw = exact(aggregateRaw.gates, "evaluatorAggregate.gates", [
    "recallAtCutoff", "controlSuppression", "emittedAbstentionRate", "baselineRecallLift", "staticOnly",
  ]);
  if (gatesRaw.staticOnly !== true) {
    throw new Error("evaluatorAggregate.gates.staticOnly must be true");
  }
  const gates = {
    recallAtCutoff: bool(gatesRaw.recallAtCutoff, "evaluatorAggregate.gates.recallAtCutoff"),
    controlSuppression: bool(gatesRaw.controlSuppression, "evaluatorAggregate.gates.controlSuppression"),
    emittedAbstentionRate: bool(gatesRaw.emittedAbstentionRate, "evaluatorAggregate.gates.emittedAbstentionRate"),
    baselineRecallLift: bool(gatesRaw.baselineRecallLift, "evaluatorAggregate.gates.baselineRecallLift"),
    staticOnly: true,
  } as const;
  const derivedGates = {
    recallAtCutoff: ratePass(aggregate.expectedFoundAtCutoff, aggregate.expectedCount, policy.minimumRecallPpm, true),
    controlSuppression: ratePass(
      aggregate.controlCount - aggregate.controlsEmitted,
      aggregate.controlCount,
      policy.minimumControlSuppressionPpm,
      true,
    ),
    emittedAbstentionRate: ratePass(
      aggregate.emittedAbstentionCount,
      counts.candidateCount,
      policy.maximumEmittedAbstentionRatePpm,
      false,
    ),
    baselineRecallLift: policy.bestBaselineFoundAtCutoff > 0
      && aggregate.expectedFoundAtCutoff > 0
      && aggregate.expectedFoundAtCutoff * RATE_SCALE_PPM
        >= policy.bestBaselineFoundAtCutoff * policy.minimumRecallLiftPpm,
    staticOnly: true,
  } as const;
  if (Object.keys(derivedGates).some((field) => gates[field as keyof typeof gates] !== derivedGates[field as keyof typeof derivedGates])) {
    throw new Error("evaluatorAggregate.gates do not match the trusted threshold policy");
  }
  const passed = bool(aggregateRaw.passed, "evaluatorAggregate.passed");
  if (passed !== Object.values(derivedGates).every((gate) => gate === true)) {
    throw new Error("evaluatorAggregate.passed does not equal the conjunction of its gates");
  }

  const timingRaw = exact(top.timing, "timing", ["startedAt", "completedAt", "durationMs"]);
  const startedAt = utcTimestamp(timingRaw.startedAt, "timing.startedAt");
  const completedAt = utcTimestamp(timingRaw.completedAt, "timing.completedAt");
  const durationMs = integer(timingRaw.durationMs, "timing.durationMs", 0, MAX_DURATION_MS);
  if (completedAt.milliseconds < startedAt.milliseconds
    || completedAt.milliseconds - startedAt.milliseconds !== durationMs) {
    throw new Error("timing.durationMs must exactly bind startedAt and completedAt");
  }

  const costRaw = exact(top.cost, "cost", ["modelCalls", "inputTokens", "outputTokens", "estimatedUsd"]);
  const cost: WindowsIoctlBenchmarkObservation["cost"] = {
    modelCalls: integer(costRaw.modelCalls, "cost.modelCalls", 0, 1_000_000),
    inputTokens: integer(costRaw.inputTokens, "cost.inputTokens", 0, Number.MAX_SAFE_INTEGER),
    outputTokens: integer(costRaw.outputTokens, "cost.outputTokens", 0, Number.MAX_SAFE_INTEGER),
    estimatedUsd: finiteCost(costRaw.estimatedUsd, "cost.estimatedUsd"),
  };
  const safety = parseSafety(top.safety);

  const observation: WindowsIoctlBenchmarkObservation = {
    schemaVersion: WINDOWS_IOCTL_BENCHMARK_OBSERVATION_SCHEMA,
    pwnkit: pwnkitBindings as WindowsIoctlBenchmarkObservation["pwnkit"],
    zeroverse,
    counts,
    rankRows,
    evaluatorAggregate: { ...aggregate, gates, passed },
    timing: { startedAt: startedAt.text, completedAt: completedAt.text, durationMs },
    cost,
    safety,
    proofLimit: WINDOWS_IOCTL_BENCHMARK_PROOF_LIMIT,
  };
  const expectedFound = aggregate.expectedFoundAtCutoff;
  const suppressedControls = aggregate.controlCount - aggregate.controlsEmitted;
  const emittedAbstentions = aggregate.emittedAbstentionCount;
  const mrrContributionPpm = aggregate.firstExpectedRank === null
    ? 0
    : Math.floor(
      (2 * RATE_SCALE_PPM + aggregate.firstExpectedRank) / (2 * aggregate.firstExpectedRank),
    );
  const baselineWasZero = policy.bestBaselineFoundAtCutoff === 0;
  const recallLiftPpm = baselineWasZero
    ? null
    : Math.floor(
      (2 * aggregate.expectedFoundAtCutoff * RATE_SCALE_PPM + policy.bestBaselineFoundAtCutoff)
        / (2 * policy.bestBaselineFoundAtCutoff),
    );
  return {
    observation,
    siteCount: counts.siteUniverse,
    metrics: {
      recallAtCutoff: expectedFound / aggregate.expectedCount,
      recallAtCutoffCi95: wilsonIntervalTuple(expectedFound, aggregate.expectedCount),
      controlSuppression: suppressedControls / aggregate.controlCount,
      controlSuppressionCi95: wilsonIntervalTuple(suppressedControls, aggregate.controlCount),
      emittedAbstentionRate: counts.candidateCount === 0 ? 0 : emittedAbstentions / counts.candidateCount,
      emittedAbstentionRateCi95: wilsonIntervalTuple(emittedAbstentions, counts.candidateCount),
      mrrContributionPpm,
      recallLiftPpm,
      baselineWasZero,
    },
  };
}
