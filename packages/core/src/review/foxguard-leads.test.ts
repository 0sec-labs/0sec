import { describe, expect, it } from "vitest";

import type { Finding, Severity } from "@0sec/shared";

import { rankAndDedupeFoxguardLeads } from "./foxguard-leads.js";

function lead(overrides: Partial<Finding> & { title: string }): Finding {
  return {
    id: overrides.id ?? `id-${overrides.title}`,
    templateId: overrides.templateId ?? `tpl-${overrides.title}`,
    title: overrides.title,
    description: overrides.description ?? "",
    severity: overrides.severity ?? ("medium" as Severity),
    category: overrides.category ?? ("other" as Finding["category"]),
    status: overrides.status ?? ("discovered" as Finding["status"]),
    evidence: overrides.evidence ?? ({} as Finding["evidence"]),
    ...overrides,
  };
}

describe("rankAndDedupeFoxguardLeads", () => {
  it("returns an empty array for empty input (no-op safety)", () => {
    expect(rankAndDedupeFoxguardLeads([])).toEqual([]);
  });

  it("orders leads by severity (critical → info)", () => {
    const out = rankAndDedupeFoxguardLeads([
      lead({ title: "low", severity: "low" }),
      lead({ title: "critical", severity: "critical" }),
      lead({ title: "info", severity: "info" }),
      lead({ title: "high", severity: "high" }),
      lead({ title: "medium", severity: "medium" }),
    ]);
    expect(out.map((f) => f.title)).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ]);
  });

  it("breaks severity ties by confidence descending", () => {
    const out = rankAndDedupeFoxguardLeads([
      lead({ title: "a", severity: "high", confidence: 0.4 }),
      lead({ title: "b", severity: "high", confidence: 0.9 }),
      lead({ title: "c", severity: "high", confidence: 0.6 }),
    ]);
    expect(out.map((f) => f.title)).toEqual(["b", "c", "a"]);
  });

  it("keeps original order for fully-tied leads (stable sort)", () => {
    const out = rankAndDedupeFoxguardLeads([
      lead({ title: "first", severity: "medium", confidence: 0.5 }),
      lead({ title: "second", severity: "medium", confidence: 0.5 }),
      lead({ title: "third", severity: "medium", confidence: 0.5 }),
    ]);
    expect(out.map((f) => f.title)).toEqual(["first", "second", "third"]);
  });

  it("dedupes by fingerprint, keeping the first occurrence", () => {
    const out = rankAndDedupeFoxguardLeads([
      lead({ title: "keep", severity: "high", fingerprint: "fp-1", confidence: 0.5 }),
      lead({ title: "drop", severity: "high", fingerprint: "fp-1", confidence: 0.9 }),
      lead({ title: "other", severity: "high", fingerprint: "fp-2" }),
    ]);
    expect(out.map((f) => f.title)).toEqual(["keep", "other"]);
  });

  it("falls back to templateId+title when a lead has no fingerprint", () => {
    const out = rankAndDedupeFoxguardLeads([
      lead({ title: "same", templateId: "tpl-x" }),
      lead({ title: "same", templateId: "tpl-x" }),
      lead({ title: "same", templateId: "tpl-y" }),
    ]);
    // Two identical templateId+title collapse; the differing templateId stays.
    expect(out).toHaveLength(2);
  });

  it("does not treat a blank fingerprint as a dedupe key", () => {
    const out = rankAndDedupeFoxguardLeads([
      lead({ title: "a", templateId: "tpl-a", fingerprint: "  " }),
      lead({ title: "b", templateId: "tpl-b", fingerprint: "" }),
    ]);
    expect(out).toHaveLength(2);
  });

  it("does not mutate the input array", () => {
    const input = [
      lead({ title: "low", severity: "low" }),
      lead({ title: "critical", severity: "critical" }),
    ];
    const snapshot = input.map((f) => f.title);
    rankAndDedupeFoxguardLeads(input);
    expect(input.map((f) => f.title)).toEqual(snapshot);
  });
});
