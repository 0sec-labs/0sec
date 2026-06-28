// #1051 — pins the hunt LEAD → cloud-sink CANDIDATE finding mapping. Hunt leads
// are HYPOTHESES gated by the adversarial skeptic, not confirmed bugs: the
// mapper must force `status: discovered` (never confirmed/sendable), preserve
// the finder's honest severity, mark provenance, and stamp a "this is a lead"
// note into evidence.analysis so the cloud ingests it as a verify candidate.

import { describe, it, expect } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { leadToCandidateFinding } from "../hunt.js";

function makeLead(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "lead-1",
    templateId: "variant-hunt",
    title: "Possible UAF in foo_release()",
    description: "The release path frees obj without clearing the dangling ref.",
    severity: "high",
    category: "memory-safety" as Finding["category"],
    status: "confirmed", // finder/skeptic-confirmed — must be downgraded
    evidence: {
      request: "n/a",
      response: "drivers/foo/foo.c:120",
      analysis: "skeptic survived the refute pass",
    },
    ...overrides,
  } as Finding;
}

describe("leadToCandidateFinding (#1051)", () => {
  it("forces status to 'discovered' — never confirmed/sendable", () => {
    const out = leadToCandidateFinding(makeLead(), "use-after-free", "abc123 fix");
    expect(out.status).toBe("discovered");
  });

  it("preserves the finder's honest severity (no inflation/deflation)", () => {
    expect(leadToCandidateFinding(makeLead({ severity: "high" }), "uaf", "ref").severity).toBe("high");
    expect(leadToCandidateFinding(makeLead({ severity: "medium" }), "uaf", "ref").severity).toBe("medium");
  });

  it("stamps lead provenance (bug class + seed) into evidence.analysis", () => {
    const out = leadToCandidateFinding(makeLead(), "use-after-free", "abc123 fix the UAF");
    const evidence = out.evidence as { analysis: string };
    expect(evidence.analysis).toContain("use-after-free");
    expect(evidence.analysis).toContain("abc123 fix the UAF");
    expect(evidence.analysis).toMatch(/LEAD|HYPOTHESIS/);
    // The original analysis is preserved alongside the provenance note.
    expect(evidence.analysis).toContain("skeptic survived the refute pass");
  });

  it("marks the candidate with the recency-hunt template id and keeps title/description", () => {
    const out = leadToCandidateFinding(makeLead(), "uaf", "ref");
    expect(out.templateId).toBe("recency-hunt-lead");
    expect(out.title).toBe("Possible UAF in foo_release()");
    expect(out.description).toContain("dangling ref");
  });

  it("never carries a 'confirmed' status through even when the lead has no analysis", () => {
    const lead = makeLead({ evidence: { request: "", response: "" } });
    const out = leadToCandidateFinding(lead, "uaf", "ref");
    expect(out.status).toBe("discovered");
    const evidence = out.evidence as { analysis: string };
    expect(evidence.analysis).toMatch(/LEAD|HYPOTHESIS/);
  });
});
