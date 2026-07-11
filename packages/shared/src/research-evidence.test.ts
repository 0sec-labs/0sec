import { describe, expect, it } from "vitest";
import {
  normalizeResearchNovelty,
  researchDisclosureReady,
  researchGradeAtLeast,
  type ResearchEvidenceEnvelope,
} from "./research-evidence.js";

function envelope(): ResearchEvidenceEnvelope {
  return {
    schemaVersion: 1,
    evidenceId: "e-1",
    findingId: "f-1",
    target: { kind: "source", locator: "/src" },
    provenance: { producer: "test", runId: "r-1", startedAt: "2026-07-11T00:00:00Z" },
    grade: "reproduced",
    novelty: { state: "novel", sources: ["git"], scanned: 12 },
    artifacts: [],
  };
}

describe("research evidence promotion", () => {
  it("keeps proof strength monotone", () => {
    expect(researchGradeAtLeast("impact-proven", "reproduced")).toBe(true);
    expect(researchGradeAtLeast("observed", "reproduced")).toBe(false);
  });

  it("fails novelty closed when no source records were actually checked", () => {
    expect(normalizeResearchNovelty({ state: "novel", sources: [], scanned: 0 }).state).toBe("unchecked");
  });

  it("requires both reproduction and a real novelty receipt for disclosure readiness", () => {
    expect(researchDisclosureReady(envelope())).toBe(true);
    expect(researchDisclosureReady({ ...envelope(), grade: "observed" })).toBe(false);
    expect(researchDisclosureReady({ ...envelope(), novelty: { state: "novel", sources: [], scanned: 0 } })).toBe(false);
  });
});
