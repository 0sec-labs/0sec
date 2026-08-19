/**
 * Tests for the SeedFinding -> SemgrepFinding converter used by the review
 * pipeline (`unified-pipeline.ts`). Closes 0sec#368: external seeds must
 * reach the agent's prompt-builder via the same shape semgrep produces.
 */
import { describe, it, expect } from "vitest";
import type { SeedFinding } from "@0sec/shared";
import { seedFindingsToSemgrepShape } from "./unified-pipeline.js";

function seed(overrides: Partial<SeedFinding> = {}): SeedFinding {
  return {
    file: "src/router.js",
    startLine: 38,
    endLine: 52,
    snippet: "db.query('SELECT * FROM u WHERE id=' + req.params.id)",
    cwe: "CWE-89",
    confidence: 0.93,
    source: "gemmaforge",
    metadata: { gemmaforge_layer: 17, model_id: "google/gemma-4-E2B-it" },
    ...overrides,
  };
}

describe("seedFindingsToSemgrepShape", () => {
  it("preserves file/line/snippet 1-to-1", () => {
    const [out] = seedFindingsToSemgrepShape([seed()]);
    expect(out.path).toBe("src/router.js");
    expect(out.startLine).toBe(38);
    expect(out.endLine).toBe(52);
    expect(out.snippet).toContain("SELECT * FROM");
  });

  it("encodes producer + CWE into ruleId", () => {
    const [out] = seedFindingsToSemgrepShape([seed()]);
    expect(out.ruleId).toBe("gemmaforge.CWE-89");
  });

  it("falls back to '<source>.lead' when no CWE is supplied", () => {
    const [out] = seedFindingsToSemgrepShape([seed({ cwe: undefined })]);
    expect(out.ruleId).toBe("gemmaforge.lead");
  });

  it("buckets confidence into severity (high/medium/low/info)", () => {
    const seeds = [
      seed({ confidence: 0.92 }),
      seed({ confidence: 0.65 }),
      seed({ confidence: 0.42 }),
      seed({ confidence: 0.1 }),
    ];
    const out = seedFindingsToSemgrepShape(seeds);
    expect(out.map((f) => f.severity)).toEqual(["high", "medium", "low", "info"]);
  });

  it("preserves full producer payload in metadata for downstream renderers", () => {
    const [out] = seedFindingsToSemgrepShape([seed()]);
    expect(out.metadata?.source).toBe("gemmaforge");
    expect(out.metadata?.gemmaforge_layer).toBe(17);
    expect(out.metadata?.model_id).toBe("google/gemma-4-E2B-it");
  });

  it("surfaces confidence inside the message string so the prompt cites it", () => {
    const [out] = seedFindingsToSemgrepShape([seed({ confidence: 0.93 })]);
    expect(out.message).toMatch(/confidence=0\.93/);
  });

  it("uses the producer's claim verbatim when supplied", () => {
    const [out] = seedFindingsToSemgrepShape([seed({ claim: "SQLi via id param" })]);
    expect(out.message).toContain("SQLi via id param");
  });

  it("synthesises a fallback claim when none is supplied", () => {
    const [out] = seedFindingsToSemgrepShape([seed({ claim: undefined })]);
    expect(out.message).toMatch(/External lead from gemmaforge/);
  });

  it("treats missing confidence as 0.5 (severity=low) and omits the [confidence=...] cite", () => {
    const [out] = seedFindingsToSemgrepShape([seed({ confidence: undefined })]);
    expect(out.severity).toBe("low");
    expect(out.message).not.toMatch(/confidence=/);
  });
});
