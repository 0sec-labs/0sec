// Coverage gate for the file-review pipeline (deepsec evaluateCoverage):
// numeric policy that decides whether a scan's candidate set reaches the
// declared attack surface well enough to justify paid processing. Setup
// loops: propose matchers → scan → evaluate → repeat (≤2 attempts); never
// start `process` while coverage fails.

import type {
  ReviewCoveragePolicy,
  ReviewCoverageReport,
  ReviewCoverageReport as _Report,
  ReviewFileRecord,
  ReviewSurfaceInventory,
  ReviewSurfaceCoverage,
} from "./types.js";

export const DEFAULT_REVIEW_COVERAGE_POLICY: Readonly<ReviewCoveragePolicy> = Object.freeze({
  version: 1,
  smallSurfaceFileThreshold: 5,
  largeSurfaceRepresentativeRatio: 0.8,
  largeSurfaceUniverseRatio: 0.5,
  zeroCoverageKinds: ["http", "rpc", "queue", "cron", "webhook", "agent-tool"],
  zeroCoverageExposures: ["public"],
  dominantLanguageMinimumShare: 0.2,
  dominantLanguageMinimumFiles: 50,
  lowLanguageMatchRate: 0.01,
  matcherMaximumFiles: 500,
  matcherMaximumSourceRatio: 0.2,
  uncoveredExamplesLimit: 5,
} satisfies ReviewCoveragePolicy);

const ratio = (n: number, d: number): number => (d === 0 ? 0 : n / d);
const pct = (v: number): string => `${Math.round(v * 100)}%`;

export interface EvaluateReviewCoverageInput {
  inventory: ReviewSurfaceInventory;
  /** Records from the scan under evaluation (must carry candidates). */
  records: readonly ReviewFileRecord[];
  /** Optional: only count candidates stamped by this scan run. */
  runId?: string;
  languageStats?: Array<{ language: string; scannedFiles: number; candidates: number }>;
  /** Per-new-matcher hit file lists — explosion checks (built-ins exempt). */
  newMatcherHits?: Record<string, readonly string[]>;
  policy?: ReviewCoveragePolicy;
}

/** Evaluate whether a completed scan reaches the coverage gate. */
export function evaluateReviewCoverage(input: EvaluateReviewCoverageInput): ReviewCoverageReport {
  const policy = input.policy ?? DEFAULT_REVIEW_COVERAGE_POLICY;
  const sourceSet = new Set(input.inventory.sourceFiles);

  const candidateFiles = new Set<string>();
  for (const record of input.records) {
    if (input.runId && record.lastScannedRunId !== input.runId) continue;
    if (record.candidates.length === 0) continue;
    if (sourceSet.has(record.filePath)) candidateFiles.add(record.filePath);
  }

  const surfaces: ReviewSurfaceCoverage[] = input.inventory.items.map((surface) => {
    const files = (input.inventory.expanded[surface.id] ?? []).filter((f) => sourceSet.has(f));
    const reps = surface.representativeFiles;
    const coveredFiles = files.filter((f) => candidateFiles.has(f));
    const coveredReps = reps.filter((f) => candidateFiles.has(f));
    const fileCoverageRatio = ratio(coveredFiles.length, files.length);
    const representativeCoverageRatio = ratio(coveredReps.length, reps.length);
    const reasons: string[] = [];

    if (files.length < policy.smallSurfaceFileThreshold) {
      if (coveredReps.length < reps.length) {
        reasons.push(
          `small surface requires every representative file; covered ${coveredReps.length}/${reps.length}`,
        );
      }
    } else {
      if (representativeCoverageRatio < policy.largeSurfaceRepresentativeRatio) {
        reasons.push(
          `representative coverage ${pct(representativeCoverageRatio)} is below ${pct(policy.largeSurfaceRepresentativeRatio)}`,
        );
      }
      if (fileCoverageRatio < policy.largeSurfaceUniverseRatio) {
        reasons.push(
          `surface file coverage ${pct(fileCoverageRatio)} is below ${pct(policy.largeSurfaceUniverseRatio)}`,
        );
      }
    }

    const zeroCoverageMustFail =
      policy.zeroCoverageKinds.includes(surface.kind) ||
      policy.zeroCoverageExposures.includes(surface.exposure);
    if (coveredFiles.length === 0 && zeroCoverageMustFail) {
      reasons.push(`${surface.exposure} ${surface.kind} surface has zero covered files`);
    }
    if (files.length === 0) reasons.push("surface has no expanded source files");

    return {
      id: surface.id,
      kind: surface.kind,
      exposure: surface.exposure,
      fileCount: files.length,
      coveredFileCount: coveredFiles.length,
      fileCoverageRatio,
      representativeFileCount: reps.length,
      coveredRepresentativeFileCount: coveredReps.length,
      representativeCoverageRatio,
      uncoveredExamples: files.filter((f) => !candidateFiles.has(f)).slice(0, policy.uncoveredExamplesLimit),
      passed: reasons.length === 0,
      reasons,
    };
  });

  // Dominant-language blind spots: a big language with near-zero match rate
  // means a missing surface, not a clean repo.
  const languageWarnings: ReviewCoverageReport["languageWarnings"] = [];
  const knownLanguageFiles = (input.languageStats ?? []).reduce((sum, s) => sum + s.scannedFiles, 0);
  for (const stat of input.languageStats ?? []) {
    const sourceShare = ratio(stat.scannedFiles, knownLanguageFiles);
    const matchRate = ratio(stat.candidates, stat.scannedFiles);
    if (
      stat.scannedFiles >= policy.dominantLanguageMinimumFiles &&
      sourceShare >= policy.dominantLanguageMinimumShare &&
      matchRate < policy.lowLanguageMatchRate
    ) {
      languageWarnings.push({
        language: stat.language,
        scannedFiles: stat.scannedFiles,
        sourceShare,
        matchRate,
        reason: `${stat.language} is ${pct(sourceShare)} of known source files but has a ${pct(matchRate)} match rate; check for a missing surface`,
      });
    }
  }

  // Matcher explosion: one generated matcher may not swallow the repo.
  const explosionWarnings: ReviewCoverageReport["explosionWarnings"] = [];
  for (const [matcherSlug, rawFiles] of Object.entries(input.newMatcherHits ?? {})) {
    const matchedFiles = rawFiles.filter((f) => sourceSet.has(f)).length;
    const sourceRatio = ratio(matchedFiles, sourceSet.size);
    if (matchedFiles > policy.matcherMaximumFiles || sourceRatio > policy.matcherMaximumSourceRatio) {
      explosionWarnings.push({
        matcherSlug,
        matchedFiles,
        sourceRatio,
        reason: `${matcherSlug} matches ${matchedFiles} files (${pct(sourceRatio)} of sources), exceeding the ${policy.matcherMaximumFiles}-file or ${pct(policy.matcherMaximumSourceRatio)} limit`,
      });
    }
  }

  const failedSurfaces = surfaces.filter((s) => !s.passed);
  const reasons = failedSurfaces.map((s) => `${s.id}: ${s.reasons.join("; ")}`);
  reasons.push(...explosionWarnings.map((w) => w.reason));

  return {
    policyVersion: 1,
    passed: failedSurfaces.length === 0 && explosionWarnings.length === 0,
    sourceFileCount: sourceSet.size,
    candidateFileCount: candidateFiles.size,
    surfaces,
    languageWarnings,
    explosionWarnings,
    reasons,
  };
}
