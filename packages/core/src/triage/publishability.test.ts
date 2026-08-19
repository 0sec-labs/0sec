/**
 * Tests for the publishability triage layer (issue #537 / #539).
 *
 * Every decision is covered, including the critical fix_bypass exception
 * (advisory exists but reproduces on latest → fix_bypass, NOT duplicate) and
 * the canAutoSuppress high-severity protection (a protected finding the gate
 * wants to drop is held as needs_verify, never silently suppressed).
 *
 * All network is injected via seams — these tests are deterministic and
 * offline.
 */

import { describe, it, expect } from "vitest";
import {
  checkPublishability,
  checkThreatModelExclusion,
  classifyDedup,
  isLatestVersion,
  isPublicApiReachable,
  isPublishable,
  type AdvisoryRef,
} from "./publishability.js";
import { canAutoSuppressDetailed } from "./can-auto-suppress.js";
import type { AttackCategory, Finding, Severity } from "@0sec/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    templateId: "t1",
    title: "Prototype pollution in config merge",
    description: "deep merge of untrusted config pollutes Object.prototype",
    severity: "medium" as Severity,
    category: "prototype-pollution" as AttackCategory,
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" } as Finding["evidence"],
    timestamp: Date.now(),
    ...overrides,
  };
}

// ── Check 1: threat-model exclusion (pure) ──────────────────────────────────

describe("checkThreatModelExclusion", () => {
  it("flags 'don't run on untrusted config' (webpack burn)", () => {
    const policy =
      "Do not run webpack on untrusted config. Configuration is trusted input.";
    const r = checkThreatModelExclusion(policy);
    expect(r.excluded).toBe(true);
    expect(r.exclusion).toBeDefined();
  });

  it("flags 'caller's responsibility' wording (template engines)", () => {
    const r = checkThreatModelExclusion(
      "Escaping untrusted template input is the caller's responsibility.",
    );
    expect(r.excluded).toBe(true);
  });

  it("does not flag a normal security policy", () => {
    const r = checkThreatModelExclusion(
      "Report vulnerabilities to security@example.com. We patch within 90 days.",
    );
    expect(r.excluded).toBe(false);
  });

  it("returns not-excluded for null/empty policy", () => {
    expect(checkThreatModelExclusion(null).excluded).toBe(false);
    expect(checkThreatModelExclusion(undefined).excluded).toBe(false);
    expect(checkThreatModelExclusion("").excluded).toBe(false);
  });
});

// ── Check 2: dedup classification (pure) ────────────────────────────────────

describe("classifyDedup", () => {
  const patched: AdvisoryRef[] = [
    { id: "GHSA-3pj2-wmw4-qpcx", patchedVersion: "3.5.1", summary: "formidable" },
  ];

  it("novel when no advisory matches", () => {
    const r = classifyDedup([], false);
    expect(r.verdict).toBe("novel");
    expect(r.refs).toEqual([]);
  });

  it("duplicate when patched advisory exists and does NOT reproduce on latest", () => {
    const r = classifyDedup(patched, false);
    expect(r.verdict).toBe("duplicate");
    expect(r.refs).toContain("GHSA-3pj2-wmw4-qpcx");
  });

  it("FIX_BYPASS when advisory exists but PoC reproduces on latest (unzipper/mathjs/pug)", () => {
    const r = classifyDedup(patched, true);
    expect(r.verdict).toBe("fix_bypass");
    expect(r.refs).toContain("GHSA-3pj2-wmw4-qpcx");
  });

  it("does NOT drop an unpatched advisory as duplicate (still open upstream)", () => {
    const unpatched: AdvisoryRef[] = [{ id: "CVE-2026-9999" }];
    const r = classifyDedup(unpatched, false);
    expect(r.verdict).toBe("novel");
  });
});

// ── Checks 3 & 4: predicates ────────────────────────────────────────────────

describe("isLatestVersion", () => {
  it("true when reproduced version equals latest (ignoring v/^/~ prefixes)", () => {
    expect(isLatestVersion("1.2.3", "1.2.3")).toBe(true);
    expect(isLatestVersion("v1.2.3", "^1.2.3")).toBe(true);
  });
  it("false when reproduced on an older version (vm2 burn)", () => {
    expect(isLatestVersion("3.9.11", "3.9.19")).toBe(false);
  });
  it("undefined when latest is unknown (conservative)", () => {
    expect(isLatestVersion("1.0.0", undefined)).toBeUndefined();
    expect(isLatestVersion(undefined, "1.0.0")).toBeUndefined();
  });
});

describe("isPublicApiReachable", () => {
  it("passes the explicit value through", () => {
    expect(isPublicApiReachable(true)).toBe(true);
    expect(isPublicApiReachable(false)).toBe(false);
    expect(isPublicApiReachable(undefined)).toBeUndefined();
  });
});

// ── Orchestrator: checkPublishability — every decision ──────────────────────

describe("checkPublishability decisions", () => {
  it("by_design — SECURITY.md disclaims untrusted input (webpack)", async () => {
    const r = await checkPublishability(makeFinding(), "webpack", "5.90.0", {
      fetchSecurityPolicy: async () =>
        "webpack is a build tool. Do not run it on untrusted config.",
    });
    expect(r.decision).toBe("by_design");
    expect(r.threatModelExclusion).toBeDefined();
  });

  it("duplicate — patched advisory, does not reproduce on latest (formidable)", async () => {
    const r = await checkPublishability(makeFinding(), "formidable", "3.5.1", {
      lookupAdvisories: async () => [
        { id: "GHSA-3pj2-wmw4-qpcx", patchedVersion: "3.5.1" },
      ],
      reproducesOnLatest: false,
    });
    expect(r.decision).toBe("duplicate");
    expect(r.dedupRefs).toContain("GHSA-3pj2-wmw4-qpcx");
    expect(r.latestVersionFixed).toBe(true);
  });

  it("fix_bypass — advisory exists BUT reproduces on latest (unzipper) — NOT duplicate", async () => {
    const r = await checkPublishability(makeFinding(), "unzipper", "0.12.3", {
      knownAdvisoryRefs: [{ id: "GHSA-xxxx-unzipper", patchedVersion: "0.10.0" }],
      reproducesOnLatest: true,
    });
    expect(r.decision).toBe("fix_bypass");
    expect(r.decision).not.toBe("duplicate");
    expect(r.dedupRefs).toContain("GHSA-xxxx-unzipper");
    expect(r.latestVersionFixed).toBe(false);
    expect(isPublishable(r.decision)).toBe(true);
  });

  it("fixed — reproduced on old version, latest is newer (vm2)", async () => {
    const r = await checkPublishability(makeFinding(), "vm2", "3.9.11", {
      latestVersion: "3.9.19",
    });
    expect(r.decision).toBe("fixed");
    expect(r.latestVersionFixed).toBe(true);
  });

  it("unreachable — sink only reachable from dead/unexported code (node-forge form.js)", async () => {
    const r = await checkPublishability(makeFinding(), "node-forge", "1.3.1", {
      publicApiReachable: false,
    });
    expect(r.decision).toBe("unreachable");
    expect(r.publicApiReachable).toBe(false);
  });

  it("in_scope — no exclusion, no advisory, reachable on latest", async () => {
    const r = await checkPublishability(makeFinding(), "somepkg", "2.0.0", {
      fetchSecurityPolicy: async () => "Report bugs to security@somepkg.dev.",
      lookupAdvisories: async () => [],
      latestVersion: "2.0.0",
      publicApiReachable: true,
    });
    expect(r.decision).toBe("in_scope");
    expect(isPublishable(r.decision)).toBe(true);
  });

  it("in_scope — no seams at all (zero-config offline no-op default)", async () => {
    const r = await checkPublishability(makeFinding(), "anything", "");
    expect(r.decision).toBe("in_scope");
  });

  it("by_design takes priority over dedup (maintainer won't take it regardless)", async () => {
    const r = await checkPublishability(makeFinding(), "eta", "3.4.0", {
      fetchSecurityPolicy: async () =>
        "eta is a template engine; templates are trusted input only.",
      lookupAdvisories: async () => [{ id: "GHSA-eta", patchedVersion: "3.0.0" }],
      reproducesOnLatest: true,
    });
    expect(r.decision).toBe("by_design");
  });

  it("survives a network seam that throws (stays conservative, not by_design)", async () => {
    const r = await checkPublishability(makeFinding(), "pkg", "1.0.0", {
      fetchSecurityPolicy: async () => {
        throw new Error("offline");
      },
      lookupAdvisories: async () => {
        throw new Error("offline");
      },
    });
    expect(r.decision).toBe("in_scope");
  });
});

// ── canAutoSuppress high-severity protection (the load-bearing guard) ───────

describe("publishability + canAutoSuppress high-severity protection", () => {
  it("a HIGH-severity finding the gate marks duplicate is NOT auto-suppressible", async () => {
    const finding = makeFinding({ severity: "critical", category: "sql-injection" });
    const r = await checkPublishability(finding, "formidable", "3.5.1", {
      lookupAdvisories: async () => [
        { id: "GHSA-3pj2-wmw4-qpcx", patchedVersion: "3.5.1" },
      ],
      reproducesOnLatest: false,
    });
    expect(r.decision).toBe("duplicate");
    // The wiring routes suppression through canAutoSuppressDetailed; assert the
    // guard refuses to suppress this finding (→ needs_verify path, not a drop).
    const guard = canAutoSuppressDetailed(finding);
    expect(guard.canSuppress).toBe(false);
    expect(guard.guard).toBe("high_severity");
  });

  it("a high-IMPACT-class finding (low severity) is also protected from auto-drop", () => {
    const finding = makeFinding({ severity: "low", category: "command-injection" });
    const guard = canAutoSuppressDetailed(finding);
    expect(guard.canSuppress).toBe(false);
    expect(guard.guard).toBe("high_impact_class");
  });

  it("a low-severity, low-impact finding the gate marks unreachable IS suppressible", () => {
    const finding = makeFinding({ severity: "low", category: "information-disclosure" });
    const guard = canAutoSuppressDetailed(finding);
    expect(guard.canSuppress).toBe(true);
  });
});

// ── Multi-source dedup: declined / repo_issue / own_submission ──────────────

describe("classifyDedup — four sources", () => {
  it("declined — a maintainer-waved-off own submission (yaml uniqueKeys) is NOT novel/fix_bypass", () => {
    const refs: AdvisoryRef[] = [
      { id: "GHSA-3g7m-p75x-hpf6", source: "own_submission", status: "declined" },
    ];
    // even if it reproduces on latest, a declined report must not become fix_bypass.
    const r = classifyDedup(refs, true);
    expect(r.verdict).toBe("declined");
    expect(r.refs).toContain("GHSA-3g7m-p75x-hpf6");
  });

  it("duplicate — a repo issue by another researcher (js-yaml #739)", () => {
    const refs: AdvisoryRef[] = [
      { id: "nodeca/js-yaml#739", source: "repo_issue", status: "open" },
    ];
    const r = classifyDedup(refs, false);
    expect(r.verdict).toBe("duplicate");
    expect(r.refs).toContain("nodeca/js-yaml#739");
  });

  it("duplicate — a repo issue does NOT become fix_bypass just because it reproduces on latest", () => {
    const refs: AdvisoryRef[] = [
      { id: "nodeca/js-yaml#739", source: "repo_issue", status: "open" },
    ];
    const r = classifyDedup(refs, true);
    expect(r.verdict).toBe("duplicate"); // re-filing a known in-flight report
  });

  it("fix_bypass — a PUBLISHED PATCHED advisory whose fix we defeat on latest (unzipper)", () => {
    const refs: AdvisoryRef[] = [
      { id: "GHSA-884w-698f-927f", source: "global", status: "patched", patchedVersion: "0.8.13" },
    ];
    const r = classifyDedup(refs, true);
    expect(r.verdict).toBe("fix_bypass");
  });

  it("declined wins even when a benign global advisory is also present", () => {
    const refs: AdvisoryRef[] = [
      { id: "GHSA-3g7m-p75x-hpf6", source: "own_submission", status: "declined" },
      { id: "GHSA-other", source: "global", status: "patched", patchedVersion: "1.0.0" },
    ];
    const r = classifyDedup(refs, true);
    expect(r.verdict).toBe("declined");
  });
});

// ── Regression corpus — the real burns from the 2026-05-29 triage session ───
//
// Each case is wired through `checkPublishability` exactly as the live sources
// would feed it. Seams are stubbed (offline/deterministic). These prove the
// gate now catches the cases that previously slipped to send-time.

describe("publishability regression corpus (issue #537 / #539)", () => {
  it("yaml uniqueKeys → by_design (we filed GHSA-3g7m-p75x-hpf6, maintainer declined as perf)", async () => {
    const r = await checkPublishability(
      makeFinding({ category: "missing-validation", title: "yaml uniqueKeys O(n^2) map DoS" }),
      "yaml",
      "2.8.2",
      {
        lookupOwnSubmissions: async () => [
          { id: "GHSA-3g7m-p75x-hpf6", source: "own_submission", status: "declined" },
        ],
        // even if our PoC reproduces on the latest version, declined wins.
        reproducesOnLatest: true,
      },
    );
    expect(r.decision).toBe("by_design");
    expect(r.dedupRefs).toContain("GHSA-3g7m-p75x-hpf6");
    expect(isPublishable(r.decision)).toBe(false);
  });

  it("js-yaml stack DoS → duplicate (nodeca/js-yaml#739, another researcher, closed→Tidelift)", async () => {
    const r = await checkPublishability(
      makeFinding({ category: "missing-validation", title: "js-yaml stack overflow DoS via deep nesting" }),
      "js-yaml",
      "4.1.1",
      {
        lookupRepoIssues: async () => [
          { id: "nodeca/js-yaml#739", source: "repo_issue", status: "open", summary: "issue (closed): stack overflow" },
        ],
      },
    );
    expect(r.decision).toBe("duplicate");
    expect(r.dedupRefs).toContain("nodeca/js-yaml#739");
    expect(isPublishable(r.decision)).toBe(false);
  });

  it("formidable → duplicate (GHSA-3pj2-wmw4-qpcx, patched, does not reproduce on latest)", async () => {
    const r = await checkPublishability(
      makeFinding({ category: "path-traversal", title: "formidable createDirsFromUploads traversal" }),
      "formidable",
      "3.5.1",
      {
        lookupAdvisories: async () => [
          { id: "GHSA-3pj2-wmw4-qpcx", source: "global", status: "patched", patchedVersion: "3.5.1" },
        ],
        reproducesOnLatest: false,
      },
    );
    expect(r.decision).toBe("duplicate");
    expect(r.dedupRefs).toContain("GHSA-3pj2-wmw4-qpcx");
  });

  it("webpack → by_design (SECURITY.md disclaims untrusted config)", async () => {
    const r = await checkPublishability(
      makeFinding({ category: "prototype-pollution", title: "webpack processArguments proto pollution" }),
      "webpack",
      "5.99.0",
      {
        fetchSecurityPolicy: async () =>
          "webpack is a build tool. Do not run webpack on untrusted config — configuration is trusted input.",
      },
    );
    expect(r.decision).toBe("by_design");
    expect(r.threatModelExclusion).toBeDefined();
  });

  it("mathjs → by_design (SECURITY.md documents import as trusted-use)", async () => {
    const r = await checkPublishability(
      makeFinding({ category: "code-injection", title: "mathjs Chain.import sandbox escape" }),
      "mathjs",
      "14.0.0",
      {
        fetchSecurityPolicy: async () =>
          "mathjs evaluates expressions. Passing untrusted input to import/evaluate is the caller's responsibility.",
      },
    );
    expect(r.decision).toBe("by_design");
  });

  it("unzipper → fix_bypass (GHSA-884w-698f-927f patched 0.8.13 but reproduces on latest 0.12.3)", async () => {
    const r = await checkPublishability(
      makeFinding({ category: "path-traversal", title: "unzipper prefix-check sibling escape (zip-slip)" }),
      "unzipper",
      "0.12.3",
      {
        lookupAdvisories: async () => [
          { id: "GHSA-884w-698f-927f", source: "global", status: "patched", patchedVersion: "0.8.13" },
        ],
        reproducesOnLatest: true,
      },
    );
    expect(r.decision).toBe("fix_bypass");
    expect(r.decision).not.toBe("duplicate");
    expect(r.dedupRefs).toContain("GHSA-884w-698f-927f");
    expect(isPublishable(r.decision)).toBe(true);
  });
});
