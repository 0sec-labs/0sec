import { createHash } from "node:crypto";

import type { BenchManifest } from "./manifest.js";
import type { BenchScorecard } from "./scorecard.js";
import type { TournamentResult } from "./tournament.js";

export interface ResearchScoreSnapshot {
  cases: number;
  successRate: number;
  successRateCI95: [number, number];
  falsePositiveRate: number;
  costPerSuccessUsd: number | null;
  inconclusiveRate: number;
}

export interface ResearchNegativeControlSnapshot {
  cases: number;
  falsePositiveRate: number;
  inconclusiveRate: number;
}

/** Portable result consumed by 0brain without coupling pwnkit to the monorepo. */
export interface ResearchImprovementResult {
  schemaVersion: 1;
  candidateId: string;
  manifestId: string;
  developmentCorpusDigest: string;
  heldOutCorpusDigest: string;
  negativeControlCorpusDigest: string;
  evaluatorDigestBefore: string;
  evaluatorDigestAfter: string;
  ciPassed: boolean;
  development: { champion: ResearchScoreSnapshot; challenger: ResearchScoreSnapshot };
  heldOut: { champion: ResearchScoreSnapshot; challenger: ResearchScoreSnapshot };
  negativeControls: {
    champion: ResearchNegativeControlSnapshot;
    challenger: ResearchNegativeControlSnapshot;
  };
  evidenceRefs: string[];
}

export interface ResearchTournamentRun {
  manifest: BenchManifest;
  tournament: TournamentResult;
}

export interface ProjectResearchResultOptions {
  candidateId: string;
  manifestId: string;
  championVariantId: string;
  challengerVariantId: string;
  development: ResearchTournamentRun;
  heldOut: ResearchTournamentRun;
  negativeControls: ResearchTournamentRun;
  evaluatorDigestBefore: string;
  evaluatorDigestAfter: string;
  ciPassed: boolean;
  evidenceRefs: string[];
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

/** Content address a parsed manifest, independent of object-key insertion order. */
export function digestBenchManifest(manifest: BenchManifest): string {
  return `sha256:${createHash("sha256").update(canonicalJson(manifest)).digest("hex")}`;
}

function scorecardFor(
  run: ResearchTournamentRun,
  variantId: string,
  label: string,
): BenchScorecard {
  if (run.tournament.manifestId !== run.manifest.id) {
    throw new Error(
      `${label} tournament manifest "${run.tournament.manifestId}" does not match "${run.manifest.id}"`,
    );
  }
  const found = run.tournament.variants.find((entry) => entry.variant.id === variantId);
  if (!found) throw new Error(`${label} tournament is missing variant "${variantId}"`);
  if (found.scorecard.manifestId !== run.manifest.id) {
    throw new Error(`${label} scorecard manifest does not match its corpus`);
  }
  return found.scorecard;
}

function snapshot(scorecard: BenchScorecard): ResearchScoreSnapshot {
  return {
    cases: scorecard.totals.cases,
    successRate: scorecard.successRate,
    successRateCI95: scorecard.successRateCI95,
    falsePositiveRate: scorecard.fpRate,
    costPerSuccessUsd: scorecard.costPerSuccessUsd,
    inconclusiveRate:
      scorecard.totals.cases === 0
        ? 0
        : scorecard.totals.inconclusive / scorecard.totals.cases,
  };
}

function negativeControlSnapshot(scorecard: BenchScorecard): ResearchNegativeControlSnapshot {
  return {
    cases: scorecard.totals.cases,
    falsePositiveRate: scorecard.fpRate,
    inconclusiveRate:
      scorecard.totals.cases === 0
        ? 0
        : scorecard.totals.inconclusive / scorecard.totals.cases,
  };
}

/**
 * Project three sealed pwnkit tournaments into 0brain's improvement result.
 * Capability and precision remain separate: false-positive gates come from
 * the negative-control tournament, never from the held-out capability corpus.
 */
export function projectResearchImprovementResult(
  options: ProjectResearchResultOptions,
): ResearchImprovementResult {
  if (options.championVariantId === options.challengerVariantId) {
    throw new Error("champion and challenger variant ids must differ");
  }
  if (options.evidenceRefs.length === 0) throw new Error("evidenceRefs must not be empty");

  const pair = (run: ResearchTournamentRun, label: string) => ({
    champion: snapshot(scorecardFor(run, options.championVariantId, label)),
    challenger: snapshot(scorecardFor(run, options.challengerVariantId, label)),
  });

  return {
    schemaVersion: 1,
    candidateId: options.candidateId,
    manifestId: options.manifestId,
    developmentCorpusDigest: digestBenchManifest(options.development.manifest),
    heldOutCorpusDigest: digestBenchManifest(options.heldOut.manifest),
    negativeControlCorpusDigest: digestBenchManifest(options.negativeControls.manifest),
    evaluatorDigestBefore: options.evaluatorDigestBefore,
    evaluatorDigestAfter: options.evaluatorDigestAfter,
    ciPassed: options.ciPassed,
    development: pair(options.development, "development"),
    heldOut: pair(options.heldOut, "held-out"),
    negativeControls: {
      champion: negativeControlSnapshot(
        scorecardFor(options.negativeControls, options.championVariantId, "negative-control"),
      ),
      challenger: negativeControlSnapshot(
        scorecardFor(options.negativeControls, options.challengerVariantId, "negative-control"),
      ),
    },
    evidenceRefs: [...options.evidenceRefs],
  };
}
