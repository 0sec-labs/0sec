import { createHash } from "node:crypto";

import type { ResearchTournamentRun } from "./improvement.js";
import type { BenchVariant } from "./variant.js";

export interface ResearchExecutionLane {
  corpusDigest: string;
  artifactRef: string;
  tournamentDigest: string;
  caseIds: string[];
  championRuns: number;
  challengerRuns: number;
}

/** Portable execution receipt consumed by 0brain without importing 0sec code. */
export interface ResearchExecutionEvidence {
  schemaVersion: 2 | 3;
  candidateId: string;
  manifest: {
    id: string;
    digest: string;
    artifactRef: string;
  };
  evaluator: {
    bundleDigest: string;
    codeDigest: string;
    configDigest: string;
    bundleArtifactRef: string;
    codeArtifactRef: string;
    configArtifactRef: string;
  };
  producer?: { repository: string; commitSha: string; treeDigest: string };
  variantBinding?: {
    mode: "candidate_change";
    candidateChangeDigest: string;
    champion: { id: string; descriptorDigest: string };
    challenger: { id: string; descriptorDigest: string };
  };
  lanes: {
    development: ResearchExecutionLane;
    heldOut: ResearchExecutionLane;
    negativeControls: ResearchExecutionLane;
  };
  measured: {
    totalRuns: number;
    totalCostUsd: number;
    elapsedMs: number;
  };
}

export interface ResearchExecutionLaneInput {
  run: ResearchTournamentRun;
  artifactRef: string;
  tournamentDigest: string;
  corpusDigest: string;
  expectedCaseIds: string[];
  requireKnownNegative: boolean;
}

export interface ProjectResearchExecutionEvidenceOptions {
  candidateId: string;
  championVariantId: string;
  challengerVariantId: string;
  manifest: ResearchExecutionEvidence["manifest"];
  evaluator: ResearchExecutionEvidence["evaluator"];
  development: ResearchExecutionLaneInput;
  heldOut: ResearchExecutionLaneInput;
  negativeControls: ResearchExecutionLaneInput;
  elapsedMs: number;
  candidateChange?: { kind: string; knobs: Record<string, string | number | boolean> };
  producer?: { repository: string; commitSha: string; treeDigest: string };
}

export interface ResearchVariantDescriptor {
  schemaVersion: 1;
  id: string;
  harnessId: string | null;
  modelOverride: string | null;
  runtimeOverride: string | null;
  depthOverride: string | null;
  costCeilingUsdPerAttempt: number | null;
  promptOverrides: Record<string, string>;
  featureFlags: Record<string, boolean>;
}

const IMPLEMENTED_FEATURE_FLAGS: Record<string, true> = {
  agent_fanout: true,
  budget_warnings: true,
  cloud_sink: true,
  cloud_surface: true,
  consensus_verify: true,
  context_compaction: true,
  decoy_detection: true,
  dynamic_playbooks: true,
  dynamic_triage: true,
  early_stop: true,
  evidence_gate: true,
  execution_journal: true,
  external_memory: true,
  holding_it_wrong: true,
  inline_validation: true,
  jit_skills: true,
  journal_rehydrate: true,
  learned_router: true,
  loop_detection: true,
  loot_ledger: true,
  mongo_objectid_forge: true,
  multimodal: true,
  oast: true,
  per_item_orchestration: true,
  poc_gen_static: true,
  pov_gate: true,
  pre_recon_cve: true,
  preserve_critical_messages: true,
  progress_handoff: true,
  pty_session: true,
  publishability_gate: true,
  reachability_gate: true,
  script_templates: true,
  specialist_routing: true,
  target_history_preseed: true,
  web_recon: true,
  web_search: true,
  wp_fingerprint: true,
};

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, nested]) => [key, canonicalize(nested)]),
    );
  }
  return value;
}

function canonicalDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(`${JSON.stringify(canonicalize(value))}\n`).digest("hex")}`;
}

export function researchCandidateChangeDigest(change: { kind: string; knobs: Record<string, string | number | boolean> }): string {
  return canonicalDigest(change);
}

export function researchVariantDescriptor(value: BenchVariant): ResearchVariantDescriptor {
  return {
    schemaVersion: 1,
    id: value.id,
    harnessId: value.harnessId ?? null,
    modelOverride: value.model ?? null,
    runtimeOverride: value.runtime ?? null,
    depthOverride: value.depth ?? null,
    costCeilingUsdPerAttempt: value.costCeilingUsdPerAttempt ?? null,
    promptOverrides: Object.fromEntries(Object.entries(value.promptOverrides ?? {}).sort(([a], [b]) => a.localeCompare(b))),
    featureFlags: Object.fromEntries(Object.entries(value.featureFlags ?? {}).sort(([a], [b]) => a.localeCompare(b))),
  };
}

export function researchVariantDescriptorDigest(value: BenchVariant | ResearchVariantDescriptor): string {
  return canonicalDigest("schemaVersion" in value && "modelOverride" in value ? value : researchVariantDescriptor(value as BenchVariant));
}

function validateCandidateVariantChange(
  change: { kind: string; knobs: Record<string, string | number | boolean> },
  champion: ResearchVariantDescriptor,
  challenger: ResearchVariantDescriptor,
): void {
  const keys = Object.keys(change.knobs).sort();
  if (keys.length !== 1) throw new Error("0sec candidate changes must isolate exactly one knob");
  const expected = structuredClone(champion);
  expected.id = challenger.id;
  const key = keys[0];
  const value = change.knobs[key];
  if (change.kind === "prompt" && ["source_audit.hypothesis", "web.challenge_hint"].includes(key) && typeof value === "string" && value !== "" && value === value.trim()) {
    expected.promptOverrides[key] = value;
  } else if (change.kind === "feature_flag" && IMPLEMENTED_FEATURE_FLAGS[key] && typeof value === "boolean") {
    if (typeof champion.featureFlags[key] !== "boolean") throw new Error(`champion must explicitly bind feature flag ${key}`);
    expected.featureFlags[key] = value;
  } else if (change.kind === "routing" && key === "model" && typeof value === "string" && value !== "" && value === value.trim()) {
    expected.modelOverride = value;
  } else if (change.kind === "routing" && key === "runtime" && typeof value === "string" && ["api", "claude", "codex", "gemini", "ollama", "auto"].includes(value)) {
    expected.runtimeOverride = value;
  } else if (change.kind === "harness" && key === "harnessId" && typeof value === "string" && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)) {
    expected.harnessId = value;
  } else if (change.kind === "scheduler" && key === "depth" && typeof value === "string" && ["quick", "default", "deep"].includes(value)) {
    expected.depthOverride = value;
  } else {
    throw new Error(`unsupported ${change.kind} candidate knob: ${key}`);
  }
  if (JSON.stringify(canonicalize(expected)) !== JSON.stringify(canonicalize(challenger))) {
    throw new Error("executed challenger is not exactly the declared candidate change applied to champion");
  }
  if (researchVariantDescriptorDigest({ ...champion, id: "variant" }) === researchVariantDescriptorDigest({ ...challenger, id: "variant" })) {
    throw new Error("candidate change produced no effective descriptor difference");
  }
}

function variant(
  run: ResearchTournamentRun,
  variantId: string,
  label: string,
) {
  const found = run.tournament.variants.find((entry) => entry.variant.id === variantId);
  if (!found) throw new Error(`${label} tournament is missing variant "${variantId}"`);
  return found;
}

function sameStrings(actual: string[], expected: string[]): boolean {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

function projectLane(
  input: ResearchExecutionLaneInput,
  championVariantId: string,
  challengerVariantId: string,
  label: string,
): { lane: ResearchExecutionLane; totalCostUsd: number; elapsedMs: number } {
  if (input.run.tournament.manifestId !== input.run.manifest.id) {
    throw new Error(`${label} tournament manifest does not match its corpus`);
  }
  const manifestCaseIds = input.run.manifest.cases.map((entry) => entry.id);
  if (!sameStrings(manifestCaseIds, input.expectedCaseIds)) {
    throw new Error(`${label} manifest case ids do not exactly match the candidate`);
  }
  if (
    input.run.manifest.cases.some(
      (entry) => entry.knownNegative !== input.requireKnownNegative,
    )
  ) {
    throw new Error(
      `${label} corpus must contain only ${input.requireKnownNegative ? "known-negative" : "capability"} cases`,
    );
  }

  const champion = variant(input.run, championVariantId, label);
  const challenger = variant(input.run, challengerVariantId, label);
  const variantIds = input.run.tournament.variants.map((entry) => entry.variant.id);
  if (
    variantIds.length !== 2 ||
    !variantIds.includes(championVariantId) ||
    !variantIds.includes(challengerVariantId)
  ) {
    throw new Error(`${label} tournament must contain exactly the bound champion and challenger`);
  }
  const championCaseIds = champion.scorecard.cases.map((entry) => entry.id);
  const challengerCaseIds = challenger.scorecard.cases.map((entry) => entry.id);
  if (
    !sameStrings(championCaseIds, manifestCaseIds) ||
    !sameStrings(challengerCaseIds, manifestCaseIds)
  ) {
    throw new Error(`${label} scorecard case ids do not exactly match the manifest`);
  }

  const receiptTotals = (cases: typeof champion.scorecard.cases) =>
    cases.reduce(
      (totals, entry) => {
        const manifestCase = input.run.manifest.cases.find((item) => item.id === entry.id)!;
        const expectedPassAtK = manifestCase.passAtK ?? input.run.tournament.config.passAtK;
        if (
          entry.passAtK !== expectedPassAtK ||
          entry.attempts.length === 0 ||
          entry.attempts.length > entry.passAtK
        ) {
          throw new Error(`${label} attempt receipts do not cover their bound case`);
        }
        const caseTotals = entry.attempts.reduce(
          (attemptTotals, attempt) => {
            if (
              !Number.isFinite(attempt.costUsd) ||
              attempt.costUsd < 0 ||
              !Number.isSafeInteger(attempt.durationMs) ||
              attempt.durationMs < 0
            ) {
              throw new Error(`${label} contains an invalid attempt receipt`);
            }
            return {
              runs: attemptTotals.runs + 1,
              costUsd: attemptTotals.costUsd + attempt.costUsd,
              durationMs: attemptTotals.durationMs + attempt.durationMs,
            };
          },
          { runs: 0, costUsd: 0, durationMs: 0 },
        );
        if (entry.costUsd !== caseTotals.costUsd) {
          throw new Error(`${label} case cost does not equal its attempt receipts`);
        }
        return {
          runs: totals.runs + caseTotals.runs,
          costUsd: totals.costUsd + caseTotals.costUsd,
          durationMs: totals.durationMs + caseTotals.durationMs,
        };
      },
      { runs: 0, costUsd: 0, durationMs: 0 },
    );
  const championReceipts = receiptTotals(champion.scorecard.cases);
  const challengerReceipts = receiptTotals(challenger.scorecard.cases);
  const championRuns = championReceipts.runs;
  const challengerRuns = challengerReceipts.runs;
  if (championRuns < manifestCaseIds.length || challengerRuns < manifestCaseIds.length) {
    throw new Error(`${label} attempt evidence must cover every bound case`);
  }
  if (
    champion.scorecard.totalCostUsd !== championReceipts.costUsd ||
    challenger.scorecard.totalCostUsd !== challengerReceipts.costUsd
  ) {
    throw new Error(`${label} scorecard cost does not equal its attempt receipts`);
  }
  const elapsedMs = input.run.elapsedMs;
  if (!Number.isSafeInteger(elapsedMs) || (elapsedMs as number) < 0) {
    throw new Error(`${label} tournament is missing a valid outer elapsedMs`);
  }
  const activeDurationMs = championReceipts.durationMs + challengerReceipts.durationMs;
  if ((elapsedMs as number) < activeDurationMs) {
    throw new Error(`${label} outer elapsedMs is shorter than its sequential attempts`);
  }

  return {
    lane: {
      corpusDigest: input.corpusDigest,
      artifactRef: input.artifactRef,
      tournamentDigest: input.tournamentDigest,
      caseIds: [...manifestCaseIds],
      championRuns,
      challengerRuns,
    },
    totalCostUsd: championReceipts.costUsd + challengerReceipts.costUsd,
    elapsedMs: elapsedMs as number,
  };
}

export function projectResearchExecutionEvidence(
  options: ProjectResearchExecutionEvidenceOptions,
): ResearchExecutionEvidence {
  if (options.championVariantId === options.challengerVariantId) {
    throw new Error("champion and challenger variant ids must differ");
  }
  if (!Number.isSafeInteger(options.elapsedMs) || options.elapsedMs < 0) {
    throw new Error("elapsedMs must be a non-negative safe integer");
  }
  if ((options.candidateChange === undefined) !== (options.producer === undefined)) {
    throw new Error("candidateChange and producer must be supplied together for schema v3");
  }
  const roleRefs = [
    options.manifest.artifactRef,
    options.evaluator.bundleArtifactRef,
    options.evaluator.codeArtifactRef,
    options.evaluator.configArtifactRef,
    options.development.artifactRef,
    options.heldOut.artifactRef,
    options.negativeControls.artifactRef,
  ];
  if (new Set(roleRefs).size !== roleRefs.length) {
    throw new Error("execution evidence role artifact references must be unique");
  }

  const development = projectLane(
    options.development,
    options.championVariantId,
    options.challengerVariantId,
    "development",
  );
  const heldOut = projectLane(
    options.heldOut,
    options.championVariantId,
    options.challengerVariantId,
    "held-out",
  );
  const negativeControls = projectLane(
    options.negativeControls,
    options.championVariantId,
    options.challengerVariantId,
    "negative-control",
  );
  const allCaseIds = [
    ...development.lane.caseIds,
    ...heldOut.lane.caseIds,
    ...negativeControls.lane.caseIds,
  ];
  if (new Set(allCaseIds).size !== allCaseIds.length) {
    throw new Error("execution evidence corpus partitions must be disjoint");
  }
  const measuredElapsedMs =
    development.elapsedMs + heldOut.elapsedMs + negativeControls.elapsedMs;
  if (options.elapsedMs !== measuredElapsedMs) {
    throw new Error("elapsedMs must equal the sum of the sealed tournament wall-clock durations");
  }

  const lanes = {
    development: development.lane,
    heldOut: heldOut.lane,
    negativeControls: negativeControls.lane,
  };
  let variantBinding: ResearchExecutionEvidence["variantBinding"];
  if (options.candidateChange && options.producer) {
    if (options.producer.repository !== "0sec-labs/0sec") throw new Error("schema-v3 producer repository must be 0sec-labs/0sec");
    if (!/^[0-9a-f]{40}$/.test(options.producer.commitSha)) throw new Error("schema-v3 producer commit must be a full lowercase SHA");
    if (!/^sha256:[0-9a-f]{64}$/.test(options.producer.treeDigest)) throw new Error("schema-v3 producer tree digest is invalid");
    const descriptorPair = (run: ResearchTournamentRun) => ({
      champion: researchVariantDescriptor(variant(run, options.championVariantId, "variant binding").variant),
      challenger: researchVariantDescriptor(variant(run, options.challengerVariantId, "variant binding").variant),
    });
    const pairs = [descriptorPair(options.development.run), descriptorPair(options.heldOut.run), descriptorPair(options.negativeControls.run)];
    const championDigest = researchVariantDescriptorDigest(pairs[0].champion);
    const challengerDigest = researchVariantDescriptorDigest(pairs[0].challenger);
    for (const pair of pairs.slice(1)) {
      if (researchVariantDescriptorDigest(pair.champion) !== championDigest || researchVariantDescriptorDigest(pair.challenger) !== challengerDigest) {
        throw new Error("variant descriptors drift across tournament lanes");
      }
    }
    validateCandidateVariantChange(options.candidateChange, pairs[0].champion, pairs[0].challenger);
    variantBinding = {
      mode: "candidate_change",
      candidateChangeDigest: researchCandidateChangeDigest(options.candidateChange),
      champion: { id: options.championVariantId, descriptorDigest: championDigest },
      challenger: { id: options.challengerVariantId, descriptorDigest: challengerDigest },
    };
  }
  return {
    schemaVersion: variantBinding ? 3 : 2,
    candidateId: options.candidateId,
    manifest: { ...options.manifest },
    evaluator: { ...options.evaluator },
    ...(variantBinding ? { producer: { ...options.producer! }, variantBinding } : {}),
    lanes,
    measured: {
      totalRuns: Object.values(lanes).reduce(
        (total, lane) => total + lane.championRuns + lane.challengerRuns,
        0,
      ),
      totalCostUsd:
        development.totalCostUsd + heldOut.totalCostUsd + negativeControls.totalCostUsd,
      elapsedMs: options.elapsedMs,
    },
  };
}

export function researchExecutionEvidenceDigest(value: ResearchExecutionEvidence): string {
  const bytes = `${JSON.stringify(canonicalize(value))}\n`;
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function researchExecutionEvidenceRef(value: ResearchExecutionEvidence): string {
  return `execution-evidence:${researchExecutionEvidenceDigest(value)}`;
}
