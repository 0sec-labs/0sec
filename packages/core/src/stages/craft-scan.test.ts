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

describe("runCraftScan cost ceiling", () => {
  it("stops before a provider call when the conservative next-call bound cannot fit", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-cost-ceiling-"));
    roots.push(sourceRoot);
    writeFileSync(
      join(sourceRoot, "target.c"),
      "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size ? data[0] : 0; }\n",
    );
    const executeNative = vi.spyOn(LlmApiRuntime.prototype, "executeNative");
    const savedForceProvider = process.env["0SEC_FORCE_PROVIDER"];
    const savedOpenAiKey = process.env.OPENAI_API_KEY;
    const savedSkipBanner = process.env["0SEC_SKIP_PROVIDER_BANNER"];
    process.env["0SEC_FORCE_PROVIDER"] = "openai";
    process.env.OPENAI_API_KEY = "test-key";
    process.env["0SEC_SKIP_PROVIDER_BANNER"] = "1";

    try {
      const result = await runCraftScan({
        target: { sourceRoot, description: "bounded parser target", language: "c" },
        runtime: "api",
        model: "gpt-5.5",
        maxSteps: 4,
        costCeilingUsd: 0.001,
        evaluatePoc: vi.fn(),
      });

      expect(executeNative).not.toHaveBeenCalled();
      expect(result.costCeilingExceeded).toBe(true);
      expect(result.steps).toBe(0);
      expect(result.warnings.join("\n")).toContain("would be exceeded before step 1");
    } finally {
      if (savedForceProvider === undefined) delete process.env["0SEC_FORCE_PROVIDER"];
      else process.env["0SEC_FORCE_PROVIDER"] = savedForceProvider;
      if (savedOpenAiKey === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = savedOpenAiKey;
      if (savedSkipBanner === undefined) delete process.env["0SEC_SKIP_PROVIDER_BANNER"];
      else process.env["0SEC_SKIP_PROVIDER_BANNER"] = savedSkipBanner;
    }
  });
});

describe("runCraftScan infrastructure faults", () => {
  it("keeps one oracle failure inconclusive without declaring the oracle unreachable", async () => {
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
    expect(result.warnings.some((warning) => /ORACLE UNREACHABLE.*NOT a capability fail/.test(warning))).toBe(false);
    expect(result.evidence?.some((record) => record.kind === "run-summary" && record.status === "inconclusive")).toBe(true);
  });
});

describe("runCraftScan self-test executor outage", () => {
  it("aborts after three consecutive executor failures instead of scoring a kept fail", async () => {
    // Regression: repeated local executor failures used to burn the full
    // self-test and step budgets against an unusable oracle path, then record a
    // capability fail. Transient executor errors get two retries; the third
    // stops the task as infrastructure-inconclusive.
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
          throw new Error("self-test executor transport failure");
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

describe("runCraftScan generator deadline", () => {
  it("refutes a non-terminating model generator without blocking the trajectory", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "craft-generator-timeout-"));
    roots.push(sourceRoot);
    writeFileSync(join(sourceRoot, "target.c"), [
      "#include <stddef.h>",
      "int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {",
      "  return size ? data[0] : 0;",
      "}",
      "",
    ].join("\n"));

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
          input: { python: "while True:\n    pass\n" },
        }],
        stopReason: "tool_use",
        usage: { inputTokens: 1, outputTokens: 1 },
        durationMs: 1,
      } as never);

    const selfTest = vi.fn();
    const result = await runCraftScan({
      target: { sourceRoot, description: "reachable parser overflow", language: "c", taskId: "fixture:timeout" },
      runtime: "api",
      model: "gpt-5.5",
      maxSteps: 2,
      generatorTimeoutMs: 250,
      evaluatePoc: vi.fn(),
      testPoc: selfTest,
    });

    expect(selfTest).not.toHaveBeenCalled();
    expect(result.steps).toBe(2);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: "self-test",
        status: "refuted",
        summary: "candidate generator failed before self-test",
      }),
    ]));
  });
});
