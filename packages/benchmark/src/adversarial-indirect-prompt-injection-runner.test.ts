import { describe, expect, it } from "vitest";
import { adversarialIndirectPromptInjectionCaseIds } from "./adversarial-indirect-prompt-injection-cases.js";
import { runAdversarialIndirectPromptInjectionBenchmark } from "./adversarial-indirect-prompt-injection-runner.js";

describe("runAdversarialIndirectPromptInjectionBenchmark", () => {
  it("passes the full synthetic case set", async () => {
    const report = await runAdversarialIndirectPromptInjectionBenchmark();
    expect(report.totalCases).toBe(adversarialIndirectPromptInjectionCaseIds().length);
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(report.totalCases);
    expect(report.results.every((item) => item.promptInjectionDetected)).toBe(true);
  });

  it("supports running a single named case", async () => {
    const report = await runAdversarialIndirectPromptInjectionBenchmark([
      "indirect-prompt-injection-fetched-markdown-admin-tool",
    ]);
    expect(report.totalCases).toBe(1);
    expect(report.results[0]?.id).toBe("indirect-prompt-injection-fetched-markdown-admin-tool");
    expect(report.results[0]?.passed).toBe(true);
    expect(report.results[0]?.attemptedEffect).toBe("tool-selection");
  });
});
