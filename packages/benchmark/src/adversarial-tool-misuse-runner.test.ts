import { describe, expect, it } from "vitest";
import { adversarialToolMisuseCaseIds } from "./adversarial-tool-misuse-cases.js";
import { runAdversarialToolMisuseBenchmark } from "./adversarial-tool-misuse-runner.js";

describe("runAdversarialToolMisuseBenchmark", () => {
  it("passes the full synthetic case set", async () => {
    const report = await runAdversarialToolMisuseBenchmark();
    expect(report.totalCases).toBe(adversarialToolMisuseCaseIds().length);
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(report.totalCases);
  });

  it("supports running a single named case", async () => {
    const report = await runAdversarialToolMisuseBenchmark([
      "tool-misuse-http-ssrf-metadata",
    ]);
    expect(report.totalCases).toBe(1);
    expect(report.results[0]?.id).toBe("tool-misuse-http-ssrf-metadata");
    expect(report.results[0]?.passed).toBe(true);
  });
});
