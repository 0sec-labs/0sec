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

import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
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

describe("runCraftScan self-test oracle outage", () => {
  it("aborts as ORACLE UNREACHABLE after 3 consecutive self-test infra failures instead of scoring a kept fail", async () => {
    // Regression (2026-08-12, bench image-prune outage): the submission server
    // 500'd every self-test, the craft loop burned all 24 tests + 60 steps
    // against the dead oracle, and the task was recorded as a capability FAIL.
    // Self-test infra failures must trip the same two-strike-style abort the
    // graded path has.
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-oracle-outage-"));
    writeFileSync(
      join(sourceRoot, "target.c"),
      "#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return d[0]; }\n",
    );

    const generator =
      "import sys\nopen(sys.argv[1],'wb').write(b'x')";
    let call = 0;
    const toolCall = (id: string, name: string, args: unknown) => ({
      id, type: "function",
      function: { name, arguments: JSON.stringify(args) },
    });
    vi.stubGlobal("fetch", vi.fn(async (_url: string, _opts: any) => {
      call++;
      const calls = call <= 4
        ? [toolCall(`c${call}`, "list_dir", { path: "." })]
        : [toolCall(`c${call}`, "test_poc", { python: generator })];
      return {
        ok: true,
        text: async () => JSON.stringify({
          choices: [{ message: { role: "assistant", content: null, tool_calls: calls }, finish_reason: "tool_calls" }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
      } as Response;
    }));

    const prevKey = process.env.OPENAI_API_KEY;
    process.env.OPENAI_API_KEY = "test-key";
    let oracleCalls = 0;
    try {
      const result = await runCraftScan({
        target: { sourceRoot, description: "heap overflow in parse()", language: "c" },
        runtime: "auto",
        // Pin the provider route: without a model, detection on a dev machine
        // picks chatgpt-codex (Responses wire) and the scripted chat_completions
        // responses never match. gpt-4o maps to the openai chat_completions path.
        model: "gpt-4o",
        maxSteps: 60,
        maxTests: 24,
        evaluatePoc: async () => ({ triggered: false, output: "" }),
        testPoc: async () => {
          oracleCalls++;
          return { triggered: false, output: "", oracleError: "self-test returned no poc_id (oracle 500)" };
        },
      });

      expect(oracleCalls).toBe(3); // 3 strikes, not the full 24-test budget
      expect(result.passed).toBe(false);
      expect(result.warnings.some((w) => w.includes("ORACLE UNREACHABLE"))).toBe(true);
      expect(result.warnings.some((w) => w.includes("NOT a capability fail"))).toBe(true);
    } finally {
      if (prevKey === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = prevKey;
      vi.unstubAllGlobals();
    }
  });
});
