/**
 * Unit test for the craft stage's wall-clock deadline (`deadlineMs`).
 *
 * The deadline exists so a slow trajectory (e.g. glm-5.2 via z.ai, ~15-30s/call
 * non-streaming) exits the loop GRACEFULLY with its accumulated work before the
 * ensemble's per-trajectory hard timeout kills it mid-call — which would discard
 * every step (0 counted) and leave the un-cancellable loop burning tokens in the
 * background. We prove the deadline short-circuits the loop with NO model call
 * (deadlineMs: 0 trips at the top of step 0), so the test needs no network/mock.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCraftScan, type CraftScanOptions } from "./craft-scan.js";

describe("runCraftScan deadlineMs", () => {
  it("exits gracefully at step 0 when the wall-clock deadline is already spent — no model call, honest 0-step result + deadline warning", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-deadline-"));
    let evaluated = false;
    const opts: CraftScanOptions = {
      target: { sourceRoot, description: "some heap overflow", language: "c" },
      runtime: "auto",
      // 0 → the deadline is already reached on entry to the loop, so it breaks
      // BEFORE constructing the LlmApiRuntime or issuing any request.
      deadlineMs: 0,
      evaluatePoc: async () => {
        evaluated = true;
        return { triggered: false, output: "" };
      },
    };

    const result = await runCraftScan(opts);

    expect(evaluated).toBe(false); // never reached the oracle
    expect(result.passed).toBe(false);
    expect(result.steps).toBe(0);
    expect(result.warnings.some((w) => /wall-clock deadline reached/.test(w))).toBe(true);
  });
});
