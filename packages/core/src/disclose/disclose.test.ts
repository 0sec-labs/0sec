import { describe, it, expect } from "vitest";
import type { Finding } from "@0sec/shared";
import { suggestCwesForCategory, suggestCvss, renderAdvisoryMarkdown, EmptyPocError } from "./index.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-abcdef123",
    templateId: "ssrf-template",
    title: "SSRF via /api/foo",
    description: "Attacker-controlled URL reaches server-side fetch without a hostname allowlist.",
    severity: "medium",
    category: "ssrf",
    status: "verified",
    evidence: {
      request: "GET /api/foo?url=http://169.254.169.254/ HTTP/1.1",
      response: '{"status":"reachable","httpStatus":200}',
      analysis: "Full SSRF with response reflection.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("suggestCwesForCategory", () => {
  it("returns a primary entry for every covered category", () => {
    const cats: Finding["category"][] = [
      "ssrf", "path-traversal", "command-injection", "xss", "prompt-injection", "prototype-pollution", "heap-overflow",
    ];
    for (const c of cats) {
      const entries = suggestCwesForCategory(c);
      expect(entries.length).toBeGreaterThan(0);
      expect(entries[0].role).toBe("primary");
      expect(entries[0].id).toMatch(/^CWE-\d+$/);
    }
  });

  it("maps ssrf to CWE-918 as primary", () => {
    const entries = suggestCwesForCategory("ssrf");
    expect(entries[0].id).toBe("CWE-918");
  });

  it("maps path-traversal to CWE-22 primary + CWE-73 secondary", () => {
    const entries = suggestCwesForCategory("path-traversal");
    expect(entries[0].id).toBe("CWE-22");
    expect(entries.some((e) => e.id === "CWE-73" && e.role === "secondary")).toBe(true);
  });
});

describe("suggestCvss", () => {
  it("passes through finding.cvssVector + cvssScore when present", () => {
    const finding = baseFinding({ cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvssScore: 9.8 });
    const suggestion = suggestCvss(finding);
    expect(suggestion.source).toBe("finding");
    expect(suggestion.score).toBe(9.8);
  });

  it("synthesises a heuristic vector when the finding has none", () => {
    const finding = baseFinding();
    const suggestion = suggestCvss(finding);
    expect(suggestion.source).toBe("heuristic");
    expect(suggestion.vector).toMatch(/^CVSS:3\.1\/AV:N\/AC:L\/PR:[NLH]\/UI:N\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/);
    expect(suggestion.score).toBeGreaterThan(0);
    expect(suggestion.score).toBeLessThanOrEqual(10);
  });

  it("produces a higher score for command-injection than for cors at the same severity", () => {
    const cmd = suggestCvss(baseFinding({ category: "command-injection", severity: "high" }));
    const cors = suggestCvss(baseFinding({ category: "cors", severity: "high" }));
    expect(cmd.score).toBeGreaterThan(cors.score);
  });
});

describe("renderAdvisoryMarkdown", () => {
  it("includes Title / Severity / CWE / Affected versions / Summary / PoC / Suggested fix / Patch status / Credits", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding);
    for (const header of ["# Title", "# Severity", "# CWE", "# Affected versions", "## Summary", "## PoC", "## Suggested fix", "## Patch status", "## Credits"]) {
      expect(markdown).toContain(header);
    }
  });

  it("embeds the evidence request and response in fenced blocks", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("GET /api/foo?url=http://169.254.169.254/");
    expect(markdown).toContain('"status":"reachable"');
  });

  it("embeds the primary CWE ID in the CWE section", () => {
    const finding = baseFinding({ category: "path-traversal" });
    const { markdown, primaryCwe } = renderAdvisoryMarkdown(finding);
    expect(primaryCwe).toBe("CWE-22");
    expect(markdown).toContain("CWE-22");
  });

  it("renders remediation.summary + steps + codeExample when provided", () => {
    const finding = baseFinding({
      remediation: {
        summary: "Allowlist hostnames.",
        steps: [
          "Resolve hostname before fetching.",
          "Reject private IPs after DNS.",
        ],
        codeExample: {
          language: "typescript",
          before: "await fetch(url);",
          after: "await fetch(url, { dispatcher: ssrfSafeAgent });",
        },
        references: [],
      },
    });
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("Allowlist hostnames.");
    expect(markdown).toContain("1. Resolve hostname before fetching.");
    expect(markdown).toContain("ssrfSafeAgent");
  });

  it("emits a stable filename slug prefixed by severity rank + severity label (no doubling)", () => {
    const finding = baseFinding({ severity: "high", title: "Auth gap: non-admin can mint tokens" });
    const { filename } = renderAdvisoryMarkdown(finding);
    expect(filename).toMatch(/^2-high-auth-gap/);
    expect(filename).not.toMatch(/high-high/);
  });

  it("sorts criticals before highs in a lexicographic sort of filenames", () => {
    const critical = renderAdvisoryMarkdown(baseFinding({ severity: "critical", title: "C" }));
    const high = renderAdvisoryMarkdown(baseFinding({ severity: "high", title: "H" }));
    const sorted = [high.filename, critical.filename].sort();
    expect(sorted[0]).toBe(critical.filename);
  });

  it("renders the pocSteps step graph block under ## PoC when finding.pocSteps is present", () => {
    const finding = baseFinding({
      pocSteps: [
        {
          id: "exploit-1",
          kind: "exploit",
          summary: "Hit the SSRF endpoint",
          action: { type: "http", method: "GET", url: "/api/foo?url=http://169.254.169.254/" },
          expect: { type: "http-status", status: 200 },
        },
      ],
    });
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("**Step graph:**");
    expect(markdown).toContain("**exploit** — Hit the SSRF endpoint");
    expect(markdown).toContain("GET /api/foo?url=http://169.254.169.254/");
    expect(markdown).toContain("Expected result: `http-status`");
  });

  it("appends a behavioural verdict line under ## Patch status when ctx.pocExecution is present", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding, {
      pocExecution: {
        findingId: finding.id,
        startedAt: "2026-05-06T17:00:00Z",
        endedAt: "2026-05-06T17:00:01Z",
        steps: [{ stepId: "exploit-1", kind: "passed", durationMs: 12 }],
        overallVerdict: "exploit_still_works",
      },
    });
    expect(markdown).toContain("**Behavioural check: exploit still reproducible.**");
    expect(markdown).toContain("`exploit_still_works`");
  });

  it("renders Code-verified footer ONLY when canary=still-vulnerable AND behavioural=exploit_still_works", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding, {
      scanId: "scan-aaaa1111",
      patchStatus: {
        status: "still-vulnerable",
        ref: "HEAD",
        notes: [],
        refsChecked: [],
        refsStillPresent: [],
        refsMissing: [],
      },
      pocExecution: {
        findingId: finding.id,
        startedAt: "2026-05-06T17:00:00Z",
        endedAt: "2026-05-06T17:00:01Z",
        steps: [{ stepId: "v1", kind: "passed", durationMs: 1 }],
        overallVerdict: "exploit_still_works",
      },
    });
    expect(markdown).toContain("> Code-verified by");
    expect(markdown).not.toContain("not behaviourally re-verified");
  });

  it("renders neutral footer when only scanId is present without verified canary+behavioural pair", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding, { scanId: "scan-aaaa1111" });
    expect(markdown).not.toContain("> Code-verified by");
    // Neutral footer makes no claim about behavioural re-verify state — the
    // dedicated Patch Status section conveys the actual verdict.
    expect(markdown).toContain("_Generated by");
    expect(markdown).not.toContain("not behaviourally re-verified");
  });

  it("renders neutral footer when canary fixed but behavioural says still-works", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding, {
      scanId: "scan-aaaa1111",
      patchStatus: {
        status: "fixed",
        ref: "HEAD",
        notes: [],
        refsChecked: [],
        refsStillPresent: [],
        refsMissing: [],
      },
      pocExecution: {
        findingId: finding.id,
        startedAt: "2026-05-06T17:00:00Z",
        endedAt: "2026-05-06T17:00:01Z",
        steps: [{ stepId: "v1", kind: "passed", durationMs: 1 }],
        overallVerdict: "exploit_still_works",
      },
    });
    expect(markdown).not.toContain("> Code-verified by");
    expect(markdown).toContain("_Generated by");
    expect(markdown).not.toContain("not behaviourally re-verified");
  });

  it("throws EmptyPocError when finding has no pocSteps, evidence, or screenshots (advisory quality gate: refuse to render placeholder PoC)", () => {
    const finding = baseFinding({
      evidence: { request: "", response: "", analysis: undefined },
    });
    expect(() => renderAdvisoryMarkdown(finding)).toThrow(EmptyPocError);
  });

  it("does not throw EmptyPocError when a screenshot is attached even without evidence text", () => {
    const finding = baseFinding({
      evidence: { request: "", response: "", analysis: undefined },
    });
    expect(() =>
      renderAdvisoryMarkdown(finding, {
        screenshots: [{ alt: "shot", relativePath: "./images/shot.png" }],
      }),
    ).not.toThrow();
  });

  it("does not throw EmptyPocError when pocSteps is non-empty even if evidence is empty", () => {
    const finding = baseFinding({
      evidence: { request: "", response: "", analysis: undefined },
      pocSteps: [
        {
          id: "exploit-1",
          kind: "exploit",
          summary: "Hit it",
          action: { type: "http", method: "GET", url: "/api" },
        },
      ],
    });
    expect(() => renderAdvisoryMarkdown(finding)).not.toThrow();
  });

  it("renders the siblingFix snippet under ## Suggested fix when there is no remediation.codeExample", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding, {
      siblingFix: {
        fileRef: { file: "src/handlers/safe.ts", line: 42 },
        snippet: "if (!isPrivateIp(host)) await fetch(host);",
        language: "typescript",
        confidence: 0.9,
        rationale: "uses the correct allowlist",
      },
    });
    expect(markdown).toContain("Correct pattern already present in the repo at `src/handlers/safe.ts:42`");
    expect(markdown).toContain("isPrivateIp");
  });
});
