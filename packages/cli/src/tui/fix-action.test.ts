import { describe, expect, it } from "vitest";
import type { SourceFixResult, SourceFixStatus } from "@0sec/core";

import {
  describeFixStatus,
  findingSourcePath,
  fixEligibility,
  fixInputEligibility,
  fixResultLines,
} from "./fix-action.js";

/**
 * A finding that satisfies every finding-level precondition `runSourceFix`
 * enforces: reproduced, has a code-only verificationSpec, and carries a
 * scoped source reference.
 */
function eligibleFinding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "finding-1",
    title: "Path traversal in the archive extractor",
    description: "Unsanitised member path is joined onto the output directory.",
    evidence: {
      request: "GET /download",
      response: "200 OK",
      analysis: "src/extract.ts:42 joins the member name without normalisation",
    },
    verification_result: { status: "reproduced" },
    verificationSpec: {
      code: [{ kind: "file-contains", path: "src/extract.ts", pattern: "join\\(" }],
    },
    ...overrides,
  };
}

function fixResult(overrides: Partial<SourceFixResult> = {}): SourceFixResult {
  return {
    status: "validated_candidate",
    findingId: "finding-1",
    sourceFile: "src/extract.ts",
    attempts: [],
    applied: false,
    ...overrides,
  };
}

describe("fixEligibility", () => {
  it("accepts a reproduced finding with a code-only spec and a source reference", () => {
    expect(fixEligibility(eligibleFinding())).toEqual({ eligible: true });
  });

  it("accepts the camelCase verificationResult spelling core also honours", () => {
    const finding = eligibleFinding({ verification_result: undefined, verificationResult: { status: "reproduced" } });
    expect(fixEligibility(finding)).toEqual({ eligible: true });
  });

  it("rejects a missing finding", () => {
    expect(fixEligibility(null)).toEqual({
      eligible: false,
      reason: "no finding selected",
    });
  });

  it("rejects a finding with no verification result", () => {
    const finding = eligibleFinding({ verification_result: undefined });
    expect(fixEligibility(finding)).toEqual({
      eligible: false,
      reason: "finding is not reproduced (verification_result.status must be reproduced)",
    });
  });

  it("rejects a finding whose verification result is not reproduced", () => {
    const finding = eligibleFinding({ verification_result: { status: "not_reproduced" } });
    expect(fixEligibility(finding)).toEqual({
      eligible: false,
      reason: "finding is not reproduced (verification_result.status must be reproduced)",
    });
  });

  it("rejects a finding with no verificationSpec", () => {
    const finding = eligibleFinding({ verificationSpec: undefined });
    expect(fixEligibility(finding)).toEqual({
      eligible: false,
      reason: "finding has no verificationSpec to re-test against",
    });
  });

  it("treats an unparsed (string) verificationSpec as missing", () => {
    const finding = eligibleFinding({ verificationSpec: '{"code":[]}' });
    expect(fixEligibility(finding)).toEqual({
      eligible: false,
      reason: "finding has no verificationSpec to re-test against",
    });
  });

  it("rejects a behavioural verificationSpec", () => {
    const finding = eligibleFinding({
      verificationSpec: { code: [], behavior: { kind: "http", request: {} } },
    });
    expect(fixEligibility(finding)).toEqual({
      eligible: false,
      reason: "behavioural verificationSpec needs a provisioned target",
    });
  });

  it("rejects a finding with no scoped source file reference", () => {
    const finding = eligibleFinding({
      description: "No file is cited anywhere in this finding.",
      evidence: { request: "GET /download", response: "200 OK", analysis: "no citation here" },
    });
    expect(fixEligibility(finding)).toEqual({
      eligible: false,
      reason: "no source file recorded on the finding",
    });
  });
});

describe("findingSourcePath", () => {
  it("prefers the review annotation path", () => {
    const finding = eligibleFinding({ reviewAnnotation: { path: "src/annotated.ts", startLine: 3 } });
    expect(findingSourcePath(finding)).toBe("src/annotated.ts");
  });

  it("falls back to the first path:line citation in the evidence analysis", () => {
    expect(findingSourcePath(eligibleFinding())).toBe("src/extract.ts");
  });

  it("falls back to the description when evidence carries no citation", () => {
    const finding = eligibleFinding({
      description: "See lib/unzip.js:7 for the vulnerable join.",
      evidence: { request: "GET /", response: "200", analysis: "no citation" },
    });
    expect(findingSourcePath(finding)).toBe("lib/unzip.js");
  });

  it("returns undefined for a non-record", () => {
    expect(findingSourcePath("src/extract.ts:1")).toBeUndefined();
  });
});

describe("fixInputEligibility", () => {
  it("accepts a repo root and a regression command", () => {
    expect(fixInputEligibility({ repoRoot: "/repo", testCommand: "pnpm test" })).toEqual({ eligible: true });
  });

  it("rejects a missing repo root", () => {
    expect(fixInputEligibility({ repoRoot: "  ", testCommand: "pnpm test" })).toEqual({
      eligible: false,
      reason: "no repository path for this finding (set 0SEC_FIX_REPO)",
    });
  });

  it("rejects a blank regression command", () => {
    expect(fixInputEligibility({ repoRoot: "/repo", testCommand: "   " })).toEqual({
      eligible: false,
      reason: "no regression command configured (set 0SEC_FIX_TEST_COMMAND)",
    });
  });
});

describe("describeFixStatus", () => {
  it("describes the in-flight state", () => {
    expect(describeFixStatus("running")).toBe("running — generating and re-testing a candidate patch");
  });

  it("describes a validated candidate", () => {
    expect(describeFixStatus("validated_candidate")).toBe("validated candidate patch — not applied");
  });

  it("describes an applied and re-tested patch", () => {
    expect(describeFixStatus("applied_and_retested")).toBe("patch applied and re-tested");
  });

  it("describes an unfixed finding", () => {
    expect(describeFixStatus("not_fixed")).toBe("no candidate patch passed the re-check");
  });

  it("describes a failed precondition", () => {
    expect(describeFixStatus("precondition_failed")).toBe("precondition failed");
  });

  it("describes an errored run", () => {
    expect(describeFixStatus("error")).toBe("fix run failed");
  });

  it("covers every SourceFixStatus variant", () => {
    const statuses: SourceFixStatus[] = [
      "validated_candidate",
      "applied_and_retested",
      "not_fixed",
      "precondition_failed",
      "error",
    ];
    for (const status of statuses) {
      expect(describeFixStatus(status)).not.toMatch(/^unknown fix status/);
    }
  });

  it("appends the real test verdict, patch state, and attempt count", () => {
    const result = fixResult({
      patch: "*** Begin Patch\n*** End Patch",
      attempts: [{ attempt: 1, reason: "patch rejected: no context" }],
      test: { command: "pnpm test", exitCode: 0, stdout: "", stderr: "", durationMs: 1200, timedOut: false },
    });
    expect(describeFixStatus(result.status, result)).toBe(
      "validated candidate patch — not applied · test command passed · patch not applied · 1 rejected attempt",
    );
  });

  it("reports an applied patch only when the result says so", () => {
    const result = fixResult({
      status: "applied_and_retested",
      applied: true,
      patch: "*** Begin Patch\n*** End Patch",
      test: { command: "pnpm test", exitCode: 0, stdout: "", stderr: "", durationMs: 5, timedOut: false },
    });
    expect(describeFixStatus(result.status, result)).toBe(
      "patch applied and re-tested · test command passed · patch applied",
    );
  });

  it("reports a timed-out test command", () => {
    const result = fixResult({
      status: "not_fixed",
      attempts: [
        { attempt: 1, reason: "post-patch test command timed out" },
        { attempt: 2, reason: "post-patch test command timed out" },
      ],
      test: { command: "pnpm test", exitCode: null, stdout: "", stderr: "", durationMs: 300_000, timedOut: true },
    });
    expect(describeFixStatus(result.status, result)).toBe(
      "no candidate patch passed the re-check · test command timed out · 2 rejected attempts",
    );
  });

  it("reports a non-zero test exit code", () => {
    const result = fixResult({
      test: { command: "pnpm test", exitCode: 1, stdout: "", stderr: "", durationMs: 9, timedOut: false },
    });
    expect(describeFixStatus(result.status, result)).toContain("test command failed (exit 1)");
  });
});

describe("fixResultLines", () => {
  it("renders only fields the result carries", () => {
    const result = fixResult({
      patch: "*** Begin Patch\n*** End Patch",
      rationale: "Normalise the member path before joining.",
      attempts: [{ attempt: 1, reason: "patch touches src/other.ts" }],
      test: { command: "pnpm test", exitCode: 0, stdout: "", stderr: "", durationMs: 1200, timedOut: false },
    });
    expect(fixResultLines(result)).toEqual([
      "source src/extract.ts",
      "test command passed in 1200ms",
      "patch produced, not applied — re-run `0sec fix --output` to write it out",
      "rationale Normalise the member path before joining.",
      "attempt 1 rejected: patch touches src/other.ts",
    ]);
  });

  it("says so when nothing ran and surfaces the error", () => {
    const result = fixResult({
      status: "precondition_failed",
      sourceFile: undefined,
      error: "refusing to fix a dirty worktree; commit or stash changes first",
    });
    expect(fixResultLines(result)).toEqual([
      "source file not resolved",
      "test command did not run",
      "no patch produced",
      "error refusing to fix a dirty worktree; commit or stash changes first",
    ]);
  });

  it("states an applied patch when the result reports one", () => {
    const result = fixResult({
      status: "applied_and_retested",
      applied: true,
      patch: "*** Begin Patch\n*** End Patch",
      test: { command: "pnpm test", exitCode: 0, stdout: "", stderr: "", durationMs: 4, timedOut: false },
    });
    expect(fixResultLines(result)).toContain("patch applied to the working tree");
  });
});
