import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@0sec/shared";
import type { HuntScanResult } from "../../stages/hunt-scan.js";
import { runResearch } from "../research-runner.js";
import { HuntResearchAdapter, type HuntResearchTarget } from "./hunt-adapter.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function finding(id: string): Finding {
  return {
    id,
    templateId: "hunt",
    title: `finding ${id}`,
    description: "candidate",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "lifetime bug" },
    timestamp: 1,
  };
}

function target(): HuntResearchTarget {
  return {
    kind: "hunt.agentic",
    id: "hunt-1",
    location: "/src",
    config: { options: { sourceRoot: "/src", candidates: [{ path: "/src/a.c" }], runtime: "api" } },
  };
}

describe("HuntResearchAdapter", () => {
  it("runs the native hunt once, preserves records, and applies native novelty without rechecking", async () => {
    const novel = finding("novel");
    const duplicate = finding("duplicate");
    const native: HuntScanResult = {
      findings: [novel, duplicate],
      confirmed: [novel],
      duplicates: [{
        finding: duplicate,
        novelty: {
          novel: false,
          duplicates: [{ subject: "fix", author: "dev", date: "now", messageId: "m1", list: "linux-kernel", why: "same bug" }],
          related: [],
          scanned: 3,
        },
      }],
      dropped: [],
      scanned: 2,
      finderCompleted: 2,
      finderTimedOut: 0,
      finderErrored: 0,
      warnings: [],
      records: [
        { candidatePath: "/src/a.c", attempt: 0, finding: novel, skepticConfirmed: true, skepticReason: "reproduced", duplicate: false },
        { candidatePath: "/src/b.c", attempt: 0, finding: duplicate, skepticConfirmed: true, skepticReason: "reproduced", duplicate: true },
      ],
    };
    const scan = vi.fn(async () => native);
    const artifactRoot = mkdtempSync(join(tmpdir(), "0sec-hunt-adapter-"));
    roots.push(artifactRoot);

    const result = await runResearch(new HuntResearchAdapter(scan), target(), { artifactRoot, runId: "hunt-run" });

    expect(scan).toHaveBeenCalledOnce();
    expect(result.candidates.map((candidate) => candidate.payload)).toEqual(native.records);
    expect(result.findings.map((item) => item.finding)).toEqual([novel]);
    expect(result.evidence.some((e) => e.stage === "novelty" && e.status === "failed")).toBe(true);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "passed")).toBe(true);
  });
});
