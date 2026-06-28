import { describe, expect, it } from "vitest";
import { extractSpecInvariants } from "./extract.js";

describe("extractSpecInvariants", () => {
  it("extracts cited normative invariants from arbitrary spec text", () => {
    const specText = `# Example Wire Protocol

1. Frame Format
The payload length MUST be between 0 and 16384 octets.
Implementations MUST reject frames whose declared length exceeds the remaining input.

2. State Machine
A DATA frame MUST NOT be sent before the session reaches the open state.
`;

    const result = extractSpecInvariants({ specName: "example-rfc.txt", specText });

    expect(result.mode).toBe("specdrift");
    expect(result.stage).toBe("extract");
    expect(result.invariants.length).toBeGreaterThanOrEqual(3);
    expect(result.invariants[0]).toMatchObject({
      kind: "range",
      securityRelevance: "medium",
      citations: [expect.objectContaining({ spec: "example-rfc.txt", lineStart: 4 })],
    });
    expect(result.invariants.map((i) => i.kind)).toContain("rejection");
    expect(result.invariants.map((i) => i.kind)).toContain("state");
  });

  it("emits an honest warning when no normative invariant is found", () => {
    const result = extractSpecInvariants({ specName: "notes.txt", specText: "This document describes background and examples only." });

    expect(result.invariants).toEqual([]);
    expect(result.warnings).toContain("no normative invariants found; spec may need OCR cleanup or LLM extraction");
  });

  it("caps extraction deterministically", () => {
    const specText = Array.from({ length: 5 }, (_, i) => `Field ${i} MUST be valid.`).join("\n");

    const result = extractSpecInvariants({ specName: "cap.txt", specText, maxInvariants: 2 });

    expect(result.invariants).toHaveLength(2);
    expect(result.warnings).toContain("capped invariants at 2; raise --max-invariants to widen extraction");
  });
});
