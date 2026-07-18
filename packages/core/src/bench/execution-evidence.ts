import { createHash } from "node:crypto";

import type { ResearchTournamentRun } from "./improvement.js";

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
  schemaVersion: 2;
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
}

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
    throw new Error("schema-v2 role artifact references must be unique");
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
  return {
    schemaVersion: 2,
    candidateId: options.candidateId,
    manifest: { ...options.manifest },
    evaluator: { ...options.evaluator },
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
