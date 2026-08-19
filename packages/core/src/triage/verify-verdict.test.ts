import { describe, it, expect } from "vitest";
import { isDisclosureWorthy, type VerifyVerdict } from "./verify-verdict.js";
import type { AttackCategory, Finding, Severity } from "@0sec/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    templateId: "audit-sink",
    title: "Example finding",
    description: "desc",
    severity: "low" as Severity,
    category: "security-misconfiguration" as AttackCategory,
    status: "discovered",
    evidence: { request: "GET / HTTP/1.1", response: "HTTP/1.1 200 OK" },
    confidence: 0.5,
    timestamp: 0,
    ...overrides,
  };
}

function verdict(v: VerifyVerdict["verdict"]): VerifyVerdict {
  return { verdict: v, confidence: 0.9, reasoning: `test ${v}`, signals: [] };
}

describe("isDisclosureWorthy", () => {
  it("keeps a finding on a confirmed verdict", () => {
    const d = isDisclosureWorthy(makeFinding(), verdict("confirmed"));
    expect(d.keep).toBe(true);
    expect(d.guard).toBeUndefined();
  });

  it("keeps a finding on an inconclusive verdict (never auto-drop on error)", () => {
    const d = isDisclosureWorthy(makeFinding({ severity: "low" }), verdict("inconclusive"));
    expect(d.keep).toBe(true);
  });

  it("drops a suppressible (low-severity, low-impact) finding on a rejection", () => {
    const d = isDisclosureWorthy(
      makeFinding({ severity: "low", category: "security-misconfiguration" as AttackCategory }),
      verdict("rejected"),
    );
    expect(d.keep).toBe(false);
  });

  it("holds a high-severity finding on a rejection (severity guard)", () => {
    const d = isDisclosureWorthy(makeFinding({ severity: "critical" }), verdict("rejected"));
    expect(d.keep).toBe(true);
    expect(d.guard).toBe("high_severity");
  });

  it("holds a high-impact-class finding even at low recorded severity", () => {
    const d = isDisclosureWorthy(
      makeFinding({ severity: "low", category: "command-injection" as AttackCategory }),
      verdict("rejected"),
    );
    expect(d.keep).toBe(true);
    expect(d.guard).toBe("high_impact_class");
  });

  it("accepts a bare outcome string as well as the full verdict object", () => {
    expect(isDisclosureWorthy(makeFinding({ severity: "low" }), "rejected").keep).toBe(false);
    expect(isDisclosureWorthy(makeFinding({ severity: "high" }), "rejected").keep).toBe(true);
    expect(isDisclosureWorthy(makeFinding({ severity: "low" }), "confirmed").keep).toBe(true);
  });
});
