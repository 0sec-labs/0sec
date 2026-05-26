import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScanEvent } from "./scanner.js";
import { buildTargetHistoryPreseedBlock } from "./review.js";
import type { IntelTargetHistory } from "./intel/index.js";

const history: IntelTargetHistory = {
  target: {
    repoPath: "/repo",
    repository: "org/zipper",
    ecosystem: "npm",
    packageName: "zipper",
    product: "zipper",
    vendor: "org",
    keywords: ["zipper", "org/zipper"],
  },
  generatedAt: "2026-05-25T00:00:00.000Z",
  summary: {
    advisoryCount: 1,
    playbookCount: 1,
    criticalCount: 0,
    highCount: 1,
    kevCount: 0,
    cweCount: 1,
    topSeverity: "high",
    matchedHints: ["org/zipper", "zipper"],
  },
  advisories: [],
  playbooks: [
    {
      id: "playbook:path-traversal",
      bugClass: "Path traversal / archive extraction escape",
      cwes: ["CWE-22"],
      priorVulnerabilityIds: ["CVE-2024-0001"],
      relevance: "Prior traversal shape applies to archive extraction paths.",
      steps: [
        {
          id: "trace-sinks",
          title: "Trace into dangerous sinks",
          rationale: "Find source-to-sink paths before reporting.",
          actions: ["Trace archive entry names to filesystem writes."],
          expectedEvidence: ["Source-to-sink path with function names."],
        },
      ],
    },
  ],
  auditGraph: {
    entrypointNodeIds: ["bug-class:playbook:path-traversal"],
    nodes: [
      { id: "prior:cve-2024-0001", kind: "prior_vulnerability", key: "CVE-2024-0001" },
      { id: "bug-class:playbook:path-traversal", kind: "bug_class", key: "playbook:path-traversal" },
      { id: "step:trace-sinks", kind: "investigation_step", key: "trace-sinks" },
      { id: "evidence:source-to-sink", kind: "evidence_query", key: "Source-to-sink path with function names." },
    ],
    edges: [
      { from: "prior:cve-2024-0001", to: "bug-class:playbook:path-traversal", kind: "INFORMS" },
      { from: "bug-class:playbook:path-traversal", to: "step:trace-sinks", kind: "HAS_STEP" },
      { from: "step:trace-sinks", to: "evidence:source-to-sink", kind: "SEEKS_EVIDENCE" },
    ],
  },
  graph: { nodes: [], edges: [] },
  provenance: { sources: ["nvd"] },
};

afterEach(() => {
  delete process.env.PWNKIT_FEATURE_TARGET_HISTORY_PRESEED;
});

describe("target-history preseed", () => {
  it("formats target-history playbooks into a source-review prompt block", async () => {
    const events: ScanEvent[] = [];
    const search = vi.fn(async () => history);

    const block = await buildTargetHistoryPreseedBlock("/repo", (event) => events.push(event), search);

    expect(search).toHaveBeenCalledWith(
      { repoPath: "/repo", limit: 8, ttlMs: 24 * 60 * 60 * 1000 },
      { timeoutMs: 6_000 },
    );
    expect(block).toContain("## Prior Vulnerability Audit Graph");
    expect(block).toContain("CVE-2024-0001");
    expect(block).toContain("Source-to-sink path with function names.");
    expect(events.at(-1)?.message).toContain("1 advisories, 1 playbooks");
  });

  it("does not block review when target-history lookup fails", async () => {
    const events: ScanEvent[] = [];
    const search = vi.fn(async () => {
      throw new Error("offline");
    });

    const block = await buildTargetHistoryPreseedBlock("/repo", (event) => events.push(event), search);

    expect(block).toBe("");
    expect(events.at(-1)?.message).toContain("Target-history preflight unavailable: offline");
  });

  it("skips lookup when the feature flag is disabled", async () => {
    process.env.PWNKIT_FEATURE_TARGET_HISTORY_PRESEED = "0";
    const events: ScanEvent[] = [];
    const search = vi.fn(async () => history);

    const block = await buildTargetHistoryPreseedBlock("/repo", (event) => events.push(event), search);

    expect(block).toBe("");
    expect(search).not.toHaveBeenCalled();
    expect(events.at(-1)?.message).toContain("skipped by feature flag");
  });
});
