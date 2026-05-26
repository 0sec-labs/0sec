import { describe, expect, it } from "vitest";
import { adversarialPersistenceCaseIds } from "./adversarial-persistence-cases.js";
import { runAdversarialPersistenceBenchmark } from "./adversarial-persistence-runner.js";

describe("runAdversarialPersistenceBenchmark", () => {
  it("passes the full synthetic case set", async () => {
    const report = await runAdversarialPersistenceBenchmark();
    expect(report.totalCases).toBe(adversarialPersistenceCaseIds().length);
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(report.totalCases);
    expect(report.results.every((item) => item.persistenceDetected)).toBe(true);
    expect(report.results.every((item) => item.replayCompromised)).toBe(true);
  });

  it("supports running a single named case", async () => {
    const report = await runAdversarialPersistenceBenchmark([
      "persistence-claude-md-secret-exfil",
    ]);
    expect(report.totalCases).toBe(1);
    expect(report.results[0]?.id).toBe("persistence-claude-md-secret-exfil");
    expect(report.results[0]?.passed).toBe(true);
    expect(report.results[0]?.durableSurface).toBe("claude-md");
    expect(report.results[0]?.replayCompromised).toBe(true);
  });
});
