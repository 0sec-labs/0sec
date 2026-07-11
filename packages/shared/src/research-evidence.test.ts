import { describe, expect, it } from "vitest";
import {
  normalizeResearchNovelty,
  researchDisclosureReady,
  researchGradeAtLeast,
  researchLpeDisclosureReady,
  researchZeroCapProven,
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

  it("requires runtime-attested non-root uid and zero capabilities for zero-cap proof", () => {
    const proven = {
      ...envelope(),
      executionContext: {
        privilege: "zero-cap" as const,
        basis: "runtime-attested" as const,
        realUid: 65534,
        effectiveUid: 65534,
        effectiveCapabilities: "0000000000000000",
        noNewPrivileges: true,
        attestationArtifact: { ref: "attestation.json", sha256: "a".repeat(64) },
      },
    };
    expect(researchZeroCapProven(proven)).toBe(true);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, basis: "campaign-config" } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, realUid: 0 } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, effectiveUid: 0 } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, effectiveCapabilities: "0000000000002000" } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, effectiveCapabilities: "0" } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, noNewPrivileges: false } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, realUid: Number.POSITIVE_INFINITY } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, attestationArtifact: undefined } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, grade: "candidate" })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: undefined })).toBe(false);
    expect(researchLpeDisclosureReady(proven)).toBe(true);
    expect(researchLpeDisclosureReady({ ...proven, novelty: { state: "unchecked" } })).toBe(false);
  });
});
