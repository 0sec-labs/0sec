/**
 * Unit tests for the archetype-sweep orchestration (`hunt-sweep.ts`).
 * `runHuntScan` is mocked at the module boundary (mirrors
 * `hunt-scan.test.ts`'s strategy for `agenticScan`) so these tests never make
 * a real LLM call or need a real kernel source tree.
 *
 * Coverage:
 *   - `guardCandidatesBySize` drops oversized candidate files before they
 *     reach the finder (the af_unix-run timeout guard).
 *   - `runArchetypeSweep` iterates N archetype plans and aggregates a
 *     per-archetype summary + totals.
 *   - An empty plan list is a clean no-op — not an error, no `runHuntScan` call.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ArchetypeSweepPlan, HuntScanResult } from "@0sec/core";
import type { Finding } from "@0sec/shared";

const runHuntScanMock = vi.fn();
vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@0sec/core")>();
  return { ...actual, runHuntScan: (...args: unknown[]) => runHuntScanMock(...args) };
});

const { guardCandidatesBySize, runArchetypeSweep, extractFileLine, pickModelForPlanIndex } = await import(
  "./hunt-sweep.js"
);

function mkFinding(id: string, title: string, analysis = ""): Finding {
  return {
    id,
    templateId: "hunt-sweep-test",
    title,
    description: "",
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
    timestamp: 1_700_000_000_000,
  };
}

function mkResult(overrides: Partial<HuntScanResult> = {}): HuntScanResult {
  return {
    findings: [],
    confirmed: [],
    duplicates: [],
    dropped: [],
    scanned: 0,
    finderCompleted: 0,
    finderTimedOut: 0,
    finderErrored: 0,
    warnings: [],
    records: [],
    ...overrides,
  };
}

function mkPlan(uid: string, name: string, candidatePaths: string[]): ArchetypeSweepPlan {
  return {
    archetype: {
      uid,
      id: uid.replace("kernel/", ""),
      name,
      cwe: "CWE-416",
      subsystem: "test",
      pattern: "test pattern",
      detectionSignature: "test_symbol_name",
      grounding: [],
      confirmableNote: "",
      engineLens: null,
      route: "kernel-static",
    },
    brief: { bugClass: `${name} (CWE-416)`, pattern: "test pattern" },
    candidates: candidatePaths.map((path) => ({ path, hint: `check ${path}` })),
    grepPatterns: ["\\b(test_symbol_name)\\b"],
  };
}

describe("guardCandidatesBySize", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "hunt-sweep-size-test-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("drops a candidate file over the line cap and keeps one under it", () => {
    writeFileSync(join(dir, "small.c"), Array.from({ length: 10 }, (_, i) => `// line ${i}`).join("\n"));
    writeFileSync(join(dir, "huge.c"), Array.from({ length: 3000 }, (_, i) => `// line ${i}`).join("\n"));

    const result = guardCandidatesBySize(
      [{ path: "small.c" }, { path: "huge.c" }],
      dir,
      2000,
    );

    expect(result.kept.map((c) => c.path)).toEqual(["small.c"]);
    expect(result.dropped).toHaveLength(1);
    expect(result.dropped[0]!.path).toBe("huge.c");
    expect(result.dropped[0]!.lines).toBeGreaterThan(2000);
  });

  it("keeps every candidate when none exceed the cap", () => {
    writeFileSync(join(dir, "a.c"), "int main() { return 0; }\n");
    const result = guardCandidatesBySize([{ path: "a.c" }], dir, 2000);
    expect(result.kept).toHaveLength(1);
    expect(result.dropped).toHaveLength(0);
  });

  it("fails open (keeps the candidate) when the file is unreadable/missing", () => {
    const result = guardCandidatesBySize([{ path: "does-not-exist.c" }], dir, 2000);
    expect(result.kept).toHaveLength(1);
    expect(result.dropped).toHaveLength(0);
  });

  it("respects a custom maxLines cap", () => {
    writeFileSync(join(dir, "mid.c"), Array.from({ length: 50 }, (_, i) => `// ${i}`).join("\n"));
    const result = guardCandidatesBySize([{ path: "mid.c" }], dir, 10);
    expect(result.dropped).toHaveLength(1);
  });
});

describe("extractFileLine", () => {
  it("pulls a path/to/file.c:123-shaped token out of the finding's evidence.analysis", () => {
    const f = mkFinding("f1", "bad memcpy", "the sink at net/nfc/digital.c:512 trusts an attacker length");
    expect(extractFileLine(f)).toBe("net/nfc/digital.c:512");
  });

  it("returns undefined when no file:line-shaped token is present", () => {
    const f = mkFinding("f1", "bad memcpy", "no location mentioned here");
    expect(extractFileLine(f)).toBeUndefined();
  });
});

describe("pickModelForPlanIndex", () => {
  it("returns undefined when the pool is undefined", () => {
    expect(pickModelForPlanIndex(undefined, 0)).toBeUndefined();
  });

  it("returns undefined when the pool is empty", () => {
    expect(pickModelForPlanIndex([], 3)).toBeUndefined();
  });

  it("round-robins across the pool by index", () => {
    const pool = ["gpt-5.5", "glm-5.2"];
    expect(pickModelForPlanIndex(pool, 0)).toBe("gpt-5.5");
    expect(pickModelForPlanIndex(pool, 1)).toBe("glm-5.2");
    expect(pickModelForPlanIndex(pool, 2)).toBe("gpt-5.5");
    expect(pickModelForPlanIndex(pool, 3)).toBe("glm-5.2");
  });

  it("wraps a single-entry pool onto every index", () => {
    expect(pickModelForPlanIndex(["gpt-5.5"], 0)).toBe("gpt-5.5");
    expect(pickModelForPlanIndex(["gpt-5.5"], 5)).toBe("gpt-5.5");
  });
});

describe("runArchetypeSweep", () => {
  beforeEach(() => {
    runHuntScanMock.mockReset();
  });

  it("empty plan list is a clean no-op: no runHuntScan call, zeroed totals, no warnings", async () => {
    const result = await runArchetypeSweep({
      sourceRoot: "/root/linux-6.12.93",
      plans: [],
      runtime: "api",
    });
    expect(runHuntScanMock).not.toHaveBeenCalled();
    expect(result.perArchetype).toEqual([]);
    expect(result.totals).toEqual({ scanned: 0, findings: 0, confirmed: 0 });
    expect(result.warnings).toEqual([]);
  });

  it("iterates N archetype plans, calling runHuntScan once per plan, and aggregates totals", async () => {
    const plans = [
      mkPlan("kernel/DRV-01", "double-free on error path", ["drivers/a.c"]),
      mkPlan("kernel/NF-03", "netlink attribute overflow", ["net/netfilter/b.c"]),
      mkPlan("kernel/BPF-02", "verifier bound bypass", ["kernel/bpf/c.c"]),
    ];

    runHuntScanMock.mockImplementation(async ({ brief }: { brief: { bugClass: string } }) => {
      if (brief.bugClass.includes("double-free")) {
        return mkResult({
          scanned: 2,
          findings: [mkFinding("f1", "finding 1")],
          confirmed: [mkFinding("f1", "finding 1")],
          records: [{ candidatePath: "drivers/a.c", attempt: 0, finding: mkFinding("f1", "finding 1"), duplicate: false }],
        });
      }
      if (brief.bugClass.includes("netlink")) {
        return mkResult({ scanned: 1, findings: [], confirmed: [], records: [] });
      }
      return mkResult({ scanned: 1, findings: [mkFinding("f2", "finding 2")], confirmed: [], records: [] });
    });

    const result = await runArchetypeSweep({
      sourceRoot: "/root/linux-6.12.93",
      plans,
      runtime: "api",
      concurrency: 2,
    });

    expect(runHuntScanMock).toHaveBeenCalledTimes(3);
    expect(result.perArchetype).toHaveLength(3);
    expect(result.perArchetype.map((r) => r.uid)).toEqual(["kernel/DRV-01", "kernel/NF-03", "kernel/BPF-02"]);
    const drv01 = result.perArchetype[0]!;
    expect(drv01.scanned).toBe(2);
    expect(drv01.confirmed).toBe(1);
    expect(drv01.confirmedFindings).toEqual([{ title: "finding 1", fileLine: undefined }]);
    expect(result.totals).toEqual({ scanned: 4, findings: 2, confirmed: 1 });
  });

  it("applies the file-size guard before invoking runHuntScan, and records the drop count", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hunt-sweep-run-test-"));
    try {
      writeFileSync(join(dir, "small.c"), "int x;\n");
      writeFileSync(join(dir, "huge.c"), Array.from({ length: 2500 }, (_, i) => `// ${i}`).join("\n"));

      runHuntScanMock.mockResolvedValue(mkResult({ scanned: 1 }));

      const plans = [mkPlan("kernel/DRV-01", "test archetype", ["small.c", "huge.c"])];
      const result = await runArchetypeSweep({
        sourceRoot: dir,
        plans,
        runtime: "api",
        maxFileLines: 2000,
      });

      expect(runHuntScanMock).toHaveBeenCalledTimes(1);
      const call = runHuntScanMock.mock.calls[0]![0] as { candidates: Array<{ path: string }> };
      expect(call.candidates).toHaveLength(1);
      expect(call.candidates[0]!.path).toBe(join(dir, "small.c"));
      expect(result.perArchetype[0]!.droppedForSize).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("skips runHuntScan entirely when every candidate is dropped for size, and warns", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hunt-sweep-allskip-test-"));
    try {
      writeFileSync(join(dir, "huge.c"), Array.from({ length: 2500 }, (_, i) => `// ${i}`).join("\n"));
      const plans = [mkPlan("kernel/DRV-01", "test archetype", ["huge.c"])];

      const result = await runArchetypeSweep({
        sourceRoot: dir,
        plans,
        runtime: "api",
        maxFileLines: 2000,
      });

      expect(runHuntScanMock).not.toHaveBeenCalled();
      expect(result.perArchetype[0]!.droppedForSize).toBe(1);
      expect(result.perArchetype[0]!.scanned).toBe(0);
      expect(result.warnings.some((w) => w.includes("kernel/DRV-01"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("default (no modelPool) never passes `models` to runHuntScan — reproduces pre-existing behavior exactly", async () => {
    const plans = [
      mkPlan("kernel/DRV-01", "a", ["drivers/a.c"]),
      mkPlan("kernel/NF-03", "b", ["net/b.c"]),
    ];
    runHuntScanMock.mockResolvedValue(mkResult({ scanned: 1 }));

    await runArchetypeSweep({ sourceRoot: "/root/linux-6.12.93", plans, runtime: "api" });

    for (const call of runHuntScanMock.mock.calls) {
      expect((call[0] as { models?: unknown }).models).toBeUndefined();
    }
  });

  it("modelPool round-robins ONE model per plan (splits load; does not multiply finder-call volume)", async () => {
    const plans = [
      mkPlan("kernel/DRV-01", "a", ["drivers/a.c"]),
      mkPlan("kernel/NF-03", "b", ["net/b.c"]),
      mkPlan("kernel/BPF-02", "c", ["kernel/bpf/c.c"]),
    ];
    runHuntScanMock.mockResolvedValue(mkResult({ scanned: 1 }));

    await runArchetypeSweep({
      sourceRoot: "/root/linux-6.12.93",
      plans,
      runtime: "api",
      modelPool: ["gpt-5.5", "glm-5.2"],
    });

    expect(runHuntScanMock).toHaveBeenCalledTimes(3);
    const models = runHuntScanMock.mock.calls.map((call) => (call[0] as { models?: string[] }).models);
    expect(models).toEqual([["gpt-5.5"], ["glm-5.2"], ["gpt-5.5"]]);
  });

  it("persists records to the corpus path via appendToCorpus when corpusPath is set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hunt-sweep-corpus-test-"));
    try {
      writeFileSync(join(dir, "a.c"), "int x;\n");
      const corpusPath = join(dir, "results", "hunt-variant-v1.jsonl");
      const record = { candidatePath: "a.c", attempt: 0, finding: mkFinding("f1", "finding 1"), duplicate: false };
      runHuntScanMock.mockResolvedValue(mkResult({ scanned: 1, records: [record] }));

      const plans = [mkPlan("kernel/DRV-01", "test archetype", ["a.c"])];
      await runArchetypeSweep({ sourceRoot: dir, plans, runtime: "api", corpusPath });

      const { readFileSync } = await import("node:fs");
      const lines = readFileSync(corpusPath, "utf8").trim().split("\n");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]!).id).toBe("a.c:f1");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
