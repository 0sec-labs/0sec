/**
 * Eligibility + presentation logic for the Findings screen's source-fix
 * action (`f`).
 *
 * This module is deliberately pure: no filesystem, no process, no imports
 * from `run.tsx`. It exists so the "can this finding actually be fixed?"
 * question and the "what did the fix run do?" question are unit-testable
 * without a renderer.
 *
 * The eligibility predicate is not invented here — it mirrors, in the same
 * order, the finding-level preconditions that `runSourceFix`
 * (`packages/core/src/fix/source-fix.ts`) enforces before it will touch a
 * repository:
 *
 *   1. `verification_result.status === "reproduced"` (its `isReproduced`)
 *   2. `finding.verificationSpec` is present
 *   3. `finding.verificationSpec.behavior` is absent (behavioural specs need
 *      a provisioned target and the source-fix runner refuses them)
 *   4. a scoped source file reference exists (its `sourcePathHint`)
 *
 * Anything that depends on the operator rather than the finding (the repo
 * root and the explicit regression command) is checked by
 * {@link fixInputEligibility} instead, mirroring the `<repo>` argument and
 * the required `--test-command` option of `0sec fix`.
 */

import type { SourceFixResult, SourceFixStatus, SourceFixTestResult } from "@0sec/core";

export type FixEligibility =
  | { eligible: true }
  | { eligible: false; reason: string };

/** Mirrors `sourcePathHint` in `packages/core/src/fix/source-fix.ts`. */
const SOURCE_PATH_PATTERN = /([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):\d+/;

const ELIGIBLE: FixEligibility = { eligible: true };

function ineligible(reason: string): FixEligibility {
  return { eligible: false, reason };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function statusOf(value: unknown): unknown {
  return asRecord(value)?.["status"];
}

/**
 * True when the finding carries the reproduced verdict `runSourceFix`
 * requires. Both spellings are accepted because core's `isReproduced`
 * accepts both.
 */
function isReproduced(finding: Record<string, unknown>): boolean {
  return (
    statusOf(finding["verification_result"]) === "reproduced" ||
    statusOf(finding["verificationResult"]) === "reproduced"
  );
}

/**
 * The source file `runSourceFix` would patch, or `undefined` when the
 * finding carries no scoped source reference. Same resolution order as
 * core's `sourcePathHint`: the review annotation first, then the first
 * `path:line` citation in evidence analysis, evidence request, description.
 */
export function findingSourcePath(finding: unknown): string | undefined {
  const record = asRecord(finding);
  if (!record) return undefined;

  const annotationPath = asRecord(record["reviewAnnotation"])?.["path"];
  if (typeof annotationPath === "string" && annotationPath.length > 0) {
    return annotationPath;
  }

  const evidence = asRecord(record["evidence"]);
  const haystacks = [evidence?.["analysis"], evidence?.["request"], record["description"]];
  for (const text of haystacks) {
    if (typeof text !== "string" || text.length === 0) continue;
    const match = text.match(SOURCE_PATH_PATTERN);
    if (match?.[1]) return match[1];
  }
  return undefined;
}

/**
 * Decide whether a finding can actually be source-fixed.
 *
 * Reasons are ordered exactly as `runSourceFix` checks them, so the reason
 * shown in the TUI is the one `0sec fix` would report first.
 */
export function fixEligibility(finding: unknown): FixEligibility {
  const record = asRecord(finding);
  if (!record) {
    return ineligible("no finding selected");
  }
  if (!isReproduced(record)) {
    return ineligible("finding is not reproduced (verification_result.status must be reproduced)");
  }
  const spec = asRecord(record["verificationSpec"]);
  if (!spec) {
    return ineligible("finding has no verificationSpec to re-test against");
  }
  if (spec["behavior"] !== undefined && spec["behavior"] !== null) {
    return ineligible("behavioural verificationSpec needs a provisioned target");
  }
  if (!findingSourcePath(record)) {
    return ineligible("no source file recorded on the finding");
  }
  return ELIGIBLE;
}

/**
 * Check the operator-supplied half of `runSourceFix`'s contract: the repo
 * to fix in, and the explicit regression command it runs after every
 * candidate patch. Mirrors the `<repo>` argument and required
 * `--test-command` option of `0sec fix`.
 */
export function fixInputEligibility(inputs: {
  repoRoot?: string | null;
  testCommand?: string | null;
}): FixEligibility {
  if (!inputs.repoRoot || inputs.repoRoot.trim().length === 0) {
    return ineligible("no repository path for this finding (set 0SEC_FIX_REPO)");
  }
  if (!inputs.testCommand || inputs.testCommand.trim().length === 0) {
    return ineligible("no regression command configured (set 0SEC_FIX_TEST_COMMAND)");
  }
  return ELIGIBLE;
}

const FIX_STATUS_HEADLINES: Record<SourceFixStatus | "running", string> = {
  running: "running — generating and re-testing a candidate patch",
  validated_candidate: "validated candidate patch — not applied",
  applied_and_retested: "patch applied and re-tested",
  not_fixed: "no candidate patch passed the re-check",
  precondition_failed: "precondition failed",
  error: "fix run failed",
};

/** Human verdict for the operator's regression command. */
function describeTest(test: SourceFixTestResult): string {
  if (test.timedOut) return "test command timed out";
  if (test.exitCode === 0) return "test command passed";
  if (test.exitCode === null) return "test command failed (no exit code)";
  return `test command failed (exit ${test.exitCode})`;
}

function pluralAttempts(count: number): string {
  return count === 1 ? "1 rejected attempt" : `${count} rejected attempts`;
}

/**
 * One-line status text for a fix result or in-flight state.
 *
 * Only fields `SourceFixResult` actually carries are used: no diff, no
 * confidence score, and never an "applied" claim beyond `result.applied`.
 * Error text is left to {@link fixResultLines} because it is unbounded.
 */
export function describeFixStatus(
  status: SourceFixStatus | "running",
  result?: SourceFixResult,
): string {
  const headline = FIX_STATUS_HEADLINES[status] ?? `unknown fix status ${String(status)}`;
  if (!result) return headline;

  const parts: string[] = [];
  if (result.test) parts.push(describeTest(result.test));
  if (result.patch) parts.push(result.applied ? "patch applied" : "patch not applied");
  if (result.attempts.length > 0) parts.push(pluralAttempts(result.attempts.length));
  return parts.length > 0 ? `${headline} · ${parts.join(" · ")}` : headline;
}

/**
 * Detail rows for the fix panel. Every row is derived from a field that
 * `SourceFixResult` really carries; the patch body itself is intentionally
 * not rendered (see the Findings screen for the note on why).
 */
export function fixResultLines(result: SourceFixResult): string[] {
  const lines: string[] = [];
  lines.push(result.sourceFile ? `source ${result.sourceFile}` : "source file not resolved");
  lines.push(result.test ? `${describeTest(result.test)} in ${result.test.durationMs}ms` : "test command did not run");
  lines.push(
    result.patch
      ? result.applied
        ? "patch applied to the working tree"
        : "patch produced, not applied — re-run `0sec fix --output` to write it out"
      : "no patch produced",
  );
  if (result.rationale) lines.push(`rationale ${result.rationale}`);
  for (const attempt of result.attempts) {
    lines.push(`attempt ${attempt.attempt} rejected: ${attempt.reason}`);
  }
  if (result.error) lines.push(`error ${result.error}`);
  return lines;
}
