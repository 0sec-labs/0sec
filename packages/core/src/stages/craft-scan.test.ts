/**
 * Unit tests for the craft stage's bounded scheduling and fail-closed oracle
 * handling. These use a mocked native runtime and never call a model.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { craftStepBudget, runCraftScan, type CraftScanOptions } from "./craft-scan.js";
import { LlmApiRuntime } from "../runtime/llm-api.js";

const roots: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("craftStepBudget", () => {
  it("reserves trigger-testing time in a short canary while preserving the long-run threshold", () => {
    expect(craftStepBudget(15)).toEqual({ reachabilityStepCap: 4, firstSelfTestStep: 6 });
    expect(craftStepBudget(40)).toEqual({ reachabilityStepCap: 4, firstSelfTestStep: 18 });
    expect(craftStepBudget(5)).toEqual({ reachabilityStepCap: 4, firstSelfTestStep: 5 });
  });
});

describe("runCraftScan infrastructure faults", () => {
  it("marks a self-test oracle failure inconclusive instead of returning a capability fail", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-oracle-error-"));
    roots.push(sourceRoot);
    writeFileSync(
      join(sourceRoot, "target.c"),
      [
        "#include <stddef.h>",
        "int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {",
        "  return size ? data[0] : 0;",
        "}",
      ].join("\n"),
    );

    vi.spyOn(LlmApiRuntime.prototype, "executeNative")
      .mockResolvedValueOnce({
        content: [{
          type: "tool_use",
          id: "advance-1",
          name: "advance_stage",
          input: { to: "trigger", citations: [{ path: "target.c", line: 2 }] },
        }],
        stopReason: "tool_use",
        usage: { inputTokens: 1, outputTokens: 1 },
        durationMs: 1,
      } as never)
      .mockResolvedValueOnce({
        content: [{
          type: "tool_use",
          id: "test-1",
          name: "test_poc",
          input: {
            python: [
              "from pathlib import Path",
              "import sys",
              "Path(sys.argv[1]).write_bytes(b'x')",
            ].join("\n"),
          },
        }],
        stopReason: "tool_use",
        usage: { inputTokens: 1, outputTokens: 1 },
        durationMs: 1,
      } as never);

    const graded = vi.fn();
    const selfTest = vi.fn(async () => ({
      triggered: false,
      output: "",
      oracleError: "pinned vulnerable image unavailable",
    }));
    const opts: CraftScanOptions = {
      target: { sourceRoot, description: "reachable parser overflow", language: "c", taskId: "fixture:1" },
      runtime: "api",
      model: "gpt-5.5",
      maxSteps: 15,
      evaluatePoc: graded,
      testPoc: selfTest,
    };

    const result = await runCraftScan(opts);

    expect(selfTest).toHaveBeenCalledTimes(1);
    expect(graded).not.toHaveBeenCalled();
    expect(result.passed).toBe(false);
    expect(result.steps).toBe(2);
    expect(result.warnings.some((warning) => /ORACLE UNREACHABLE.*NOT a capability fail/.test(warning))).toBe(true);
    expect(result.evidence?.some((record) => record.kind === "run-summary" && record.status === "inconclusive")).toBe(true);
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
