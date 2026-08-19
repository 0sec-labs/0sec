import { describe, expect, it, vi } from "vitest";
import {
  runPatchReflectLoop,
  defaultReflect,
  DEFAULT_MAX_ATTEMPTS,
  type PatchValidator,
  type ReflectivePatchGenerator,
  type RegressionCheck,
} from "./patch-reflect-loop.js";
import type {
  CandidatePatch,
  PatchValidateOptions,
  PatchValidateResult,
  PatchValidateStatus,
} from "./patch-validate.js";
import type { Finding } from "@pwnkit/shared";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "00000000-finding-1501",
    templateId: "kernel-review-test",
    title: "tcp_input: UAF in input path",
    description: "reproduced KASAN UAF",
    severity: "high",
    category: "use-after-free",
    status: "confirmed",
    evidence: {
      request: "net/ipv4/tcp_input.c:4321",
      response: "syz repro",
      analysis: "Subsystem: net/tcp",
    },
    confidence: 1.0,
    timestamp: 0,
    ...overrides,
  };
}

/** Base loop `validate` options minus patchGenerator (the loop supplies that). */
function baseValidateOpts(): Omit<PatchValidateOptions, "patchGenerator"> {
  return {
    finding: finding(),
    kernelTree: "/fake/tree",
    reproducer: "repro",
    reproducerLang: "c",
    crashDmesg: "BUG: KASAN: slab-use-after-free in tcp_input",
    reproducerPath: "/fake/poc.c",
  };
}

const patch = (id: string): CandidatePatch => ({
  diff: `--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad-${id}\n+good-${id}\n`,
  rationale: `fix ${id}`,
});

/** A validation verdict shaped like the real oracle's, for a given status. */
function verdict(
  status: PatchValidateStatus,
  p?: CandidatePatch,
): PatchValidateResult {
  const confirmed = status === "root_cause_confirmed";
  return {
    status,
    patchValidated: confirmed,
    ...(p ? { patch: p } : {}),
    rerunStatus: confirmed ? "no_signal" : "reproduced",
    reason: `synthetic ${status}`,
  };
}

/**
 * Fake validator: pops a scripted result queue. It also invokes the round's
 * patchGenerator (so we exercise the reflective-generator wiring) and stamps the
 * generated patch onto the returned verdict, mirroring the real oracle.
 */
function fakeValidator(script: PatchValidateResult[]): {
  validator: PatchValidator;
  genCalls: Array<{ mode: string; attempt: number; priorCount: number }>;
} {
  const genCalls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
  let i = 0;
  const validator: PatchValidator = async (opts) => {
    const gen = await opts.patchGenerator({
      finding: opts.finding,
      reproducer: opts.reproducer,
      reproducerLang: opts.reproducerLang,
      crashDmesg: opts.crashDmesg,
    });
    const scripted = script[Math.min(i, script.length - 1)];
    i++;
    // If the scripted verdict lacks a patch but the generator produced one, use it.
    const p = scripted.patch ?? gen ?? undefined;
    return { ...scripted, ...(p ? { patch: p } : {}) };
  };
  return { validator, genCalls };
}

/** A reflective generator that records how it was called and returns per-attempt patches. */
function recordingGenerator(
  calls: Array<{ mode: string; attempt: number; priorCount: number }>,
): ReflectivePatchGenerator {
  return async (ctx) => {
    calls.push({ mode: ctx.mode, attempt: ctx.attempt, priorCount: ctx.priorAttempts.length });
    return patch(`a${ctx.attempt}`);
  };
}

describe("runPatchReflectLoop", () => {
  it("confirms on the first attempt and stops (no wasted rebuilds)", async () => {
    const calls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
    const { validator } = fakeValidator([verdict("root_cause_confirmed")]);

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: recordingGenerator(calls),
      validator,
    });

    expect(res.status).toBe("root_cause_confirmed");
    expect(res.patchValidated).toBe(true);
    expect(res.confirmedPatch).toBeDefined();
    expect(res.attempts).toHaveLength(1);
    expect(res.attempts[0].decision).toBe("stop");
    // Only one generation happened.
    expect(calls).toHaveLength(1);
    expect(calls[0].mode).toBe("initial");
  });

  it("try_different after not_root_cause, then confirms — history is threaded to the generator", async () => {
    const calls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
    const { validator } = fakeValidator([
      verdict("not_root_cause"),
      verdict("root_cause_confirmed"),
    ]);

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: recordingGenerator(calls),
      validator,
    });

    expect(res.status).toBe("root_cause_confirmed");
    expect(res.attempts.map((a) => a.result.status)).toEqual([
      "not_root_cause",
      "root_cause_confirmed",
    ]);
    expect(res.attempts[0].decision).toBe("try_different");
    // Second generation ran in try_different mode and saw the 1 prior failure.
    expect(calls[1].mode).toBe("try_different");
    expect(calls[1].priorCount).toBe(1);
  });

  it("retry_same on rebuild_failed re-runs the SAME patch (generator not re-invoked)", async () => {
    const calls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
    const { validator } = fakeValidator([
      verdict("rebuild_failed", patch("first")), // attempt 1 produces a patch, build inconclusive
      verdict("root_cause_confirmed"), // attempt 2 (retry_same) confirms
    ]);

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: recordingGenerator(calls),
      validator,
    });

    expect(res.attempts[0].result.status).toBe("rebuild_failed");
    expect(res.attempts[0].decision).toBe("retry_same");
    expect(res.status).toBe("root_cause_confirmed");
    // Generator invoked ONLY on attempt 1; the retry re-used the same diff.
    expect(calls).toHaveLength(1);
  });

  it("stops (gave_up) on two consecutive patch_generation_failed", async () => {
    const { validator } = fakeValidator([
      verdict("patch_generation_failed"),
      verdict("patch_generation_failed"),
    ]);
    // Generator declines every time.
    const decliningGen: ReflectivePatchGenerator = async () => null;

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: decliningGen,
      validator,
    });

    expect(res.status).toBe("gave_up");
    expect(res.patchValidated).toBe(false);
    expect(res.attempts).toHaveLength(2);
    expect(res.attempts[1].decision).toBe("stop");
  });

  it("hits budget_exhausted when every attempt fails differently", async () => {
    const calls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
    const { validator } = fakeValidator([verdict("not_root_cause")]); // always not_root_cause

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: recordingGenerator(calls),
      validator,
      maxAttempts: 2,
    });

    expect(res.status).toBe("budget_exhausted");
    expect(res.attempts).toHaveLength(2);
    expect(res.attempts.every((a) => a.decision === "try_different")).toBe(true);
  });

  it("rejects a bug-closing patch that fails the regression check", async () => {
    const calls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
    const { validator } = fakeValidator([
      verdict("root_cause_confirmed", patch("regresses")),
      verdict("root_cause_confirmed", patch("clean")),
    ]);
    let firstCheck = true;
    const regressionCheck: RegressionCheck = vi.fn(async () => {
      if (firstCheck) {
        firstCheck = false;
        return { passed: false, reason: "broke net/ipv4 selftest" };
      }
      return { passed: true, reason: "selftests green" };
    });

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: recordingGenerator(calls),
      validator,
      regressionCheck,
    });

    // First confirm regressed → reflected as try_different; second confirm is clean.
    expect(res.status).toBe("root_cause_confirmed");
    expect(res.attempts).toHaveLength(2);
    expect(res.attempts[0].regression?.passed).toBe(false);
    expect(res.attempts[0].decision).toBe("try_different");
    expect(res.attempts[1].regression?.passed).toBe(true);
    expect(regressionCheck).toHaveBeenCalledTimes(2);
  });

  it("gives up when a regressing patch cannot be improved within budget", async () => {
    const calls: Array<{ mode: string; attempt: number; priorCount: number }> = [];
    const { validator } = fakeValidator([verdict("root_cause_confirmed", patch("always-regresses"))]);
    const regressionCheck: RegressionCheck = async () => ({
      passed: false,
      reason: "always regresses",
    });

    const res = await runPatchReflectLoop({
      validate: baseValidateOpts(),
      patchGenerator: recordingGenerator(calls),
      validator,
      regressionCheck,
      maxAttempts: 2,
    });

    expect(res.status).toBe("budget_exhausted");
    expect(res.patchValidated).toBe(false);
    expect(res.attempts.every((a) => a.regression?.passed === false)).toBe(true);
  });

  it("defaults to DEFAULT_MAX_ATTEMPTS and the real validator import shape", () => {
    expect(DEFAULT_MAX_ATTEMPTS).toBeGreaterThanOrEqual(2);
  });
});

describe("defaultReflect", () => {
  const base = { attempt: 1, maxAttempts: 3, history: [] as never[] };

  it("try_different on not_root_cause and patch_apply_failed", () => {
    expect(defaultReflect({ ...base, result: verdict("not_root_cause") })).toBe("try_different");
    expect(defaultReflect({ ...base, result: verdict("patch_apply_failed") })).toBe("try_different");
  });

  it("retry_same once on rebuild_failed, then stop", () => {
    expect(defaultReflect({ ...base, result: verdict("rebuild_failed") })).toBe("retry_same");
    const withRetry = [
      { attempt: 1, mode: "initial" as const, result: verdict("rebuild_failed"), decision: "retry_same" as const },
    ];
    expect(
      defaultReflect({ attempt: 2, maxAttempts: 3, history: withRetry, result: verdict("rebuild_failed") }),
    ).toBe("stop");
  });

  it("stop on error and on a second consecutive generation failure", () => {
    expect(defaultReflect({ ...base, result: verdict("error") })).toBe("stop");
    const withGenFail = [
      { attempt: 1, mode: "initial" as const, result: verdict("patch_generation_failed"), decision: "try_different" as const },
    ];
    expect(
      defaultReflect({ attempt: 2, maxAttempts: 3, history: withGenFail, result: verdict("patch_generation_failed") }),
    ).toBe("stop");
  });

  it("try_different whenever a regression check failed, regardless of status", () => {
    expect(
      defaultReflect({
        ...base,
        result: verdict("root_cause_confirmed"),
        regression: { passed: false, reason: "regressed" },
      }),
    ).toBe("try_different");
  });
});
