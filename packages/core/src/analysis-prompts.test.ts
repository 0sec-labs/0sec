import { describe, it, expect } from "vitest";
import { reviewAgentPrompt } from "./analysis-prompts.js";

describe("reviewAgentPrompt — hypothesis seeding (#467)", () => {
  it("injects operator hypothesis as a primary research direction", () => {
    const hypothesis =
      "The GraphQL resolver trusts the client-supplied 'depth' parameter without bounding recursion";
    const prompt = reviewAgentPrompt("/tmp/webapp", [], undefined, false, hypothesis);

    expect(prompt).toContain("OPERATOR HYPOTHESIS");
    expect(prompt).toContain("PRIMARY RESEARCH DIRECTION");
    expect(prompt).toContain(hypothesis);
    expect(prompt).toContain("60%");
  });

  it("omits the hypothesis block when no hypothesis is provided", () => {
    const prompt = reviewAgentPrompt("/tmp/webapp", []);
    expect(prompt).not.toContain("OPERATOR HYPOTHESIS");
    expect(prompt).not.toContain("PRIMARY RESEARCH DIRECTION");
  });

  it("places the hypothesis before the mission section so the agent sees it first", () => {
    const hypothesis = "Check the JWT validation in the auth middleware";
    const prompt = reviewAgentPrompt("/tmp/app", [], undefined, false, hypothesis);

    const hypothesisIdx = prompt.indexOf("OPERATOR HYPOTHESIS");
    const missionIdx = prompt.indexOf("## Your Mission");
    expect(hypothesisIdx).toBeGreaterThan(-1);
    expect(missionIdx).toBeGreaterThan(-1);
    expect(hypothesisIdx).toBeLessThan(missionIdx);
  });

  it("preserves diff context and changed-only behavior alongside hypothesis", () => {
    const hypothesis = "Check for SSRF in the webhook handler";
    const changedFiles = ["src/webhooks/handler.ts", "src/api/proxy.ts"];
    const prompt = reviewAgentPrompt("/tmp/app", [], changedFiles, true, hypothesis);

    expect(prompt).toContain("OPERATOR HYPOTHESIS");
    expect(prompt).toContain(hypothesis);
    expect(prompt).toContain("src/webhooks/handler.ts");
    expect(prompt).toContain("diff-aware review");
    expect(prompt).toContain("source_start_line");
    expect(prompt).toContain("added line in the changed delta");
  });
});
