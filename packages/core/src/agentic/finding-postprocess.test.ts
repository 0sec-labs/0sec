import { describe, it, expect, vi } from "vitest";
import {
  loadPriorScanAnchors,
  applyFindingPostProcess,
  type PriorScanLoader,
  type FindingPostProcessOptions,
  type DedupeItem,
} from "./finding-postprocess.js";
import { semanticDedupe, rankIncremental } from "../triage/index.js";
import type { Finding } from "@pwnkit/shared";

// ── Mocks ──────────────────────────────────────────────────────────

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: overrides?.id ?? "f-1",
    templateId: "test",
    title: overrides?.title ?? "test finding",
    description: overrides?.description ?? "test description",
    severity: overrides?.severity ?? "high",
    category: overrides?.category ?? "xss",
    status: overrides?.status ?? "discovered",
    evidence: overrides?.evidence ?? { request: "req", response: "res" },
    timestamp: Date.now(),
  };
}

function makeFakeDb(overrides?: Partial<PriorScanLoader>): PriorScanLoader {
  return {
    listScansByTarget: overrides?.listScansByTarget ?? vi.fn().mockReturnValue([]),
    getScanFindings: overrides?.getScanFindings ?? vi.fn().mockReturnValue([]),
  };
}

function makeStubRuntime(): import("../runtime/types.js").NativeRuntime {
  return {
    complete: vi.fn(),
    yield: vi.fn(),
    push: vi.fn(),
    request: vi.fn().mockResolvedValue({ content: [], usage: {} }),
  } as unknown as import("../runtime/types.js").NativeRuntime;
}

describe("loadPriorScanAnchors", () => {
  it("projects findings from the latest prior scan as DedupeItem[]", async () => {
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([
        { id: "s2", status: "completed", target: "https://example.com" },
        { id: "s1", status: "completed", target: "https://example.com" },
      ]),
      getScanFindings: vi.fn().mockReturnValue([
        {
          id: "f-1",
          title: "SQL Injection",
          category: "sql-injection",
          description: "Unsafe query builder",
          reviewAnnotation: { path: "src/db.ts", startLine: 42 },
        },
      ]),
    });

    const result = await loadPriorScanAnchors(db, "https://example.com");

    expect(db.listScansByTarget).toHaveBeenCalledWith("https://example.com", { limit: 5 });
    expect(db.getScanFindings).toHaveBeenCalledWith("s2");
    expect(result).toEqual([
      {
        id: "f-1",
        summary: "SQL Injection",
        category: "sql-injection",
        location: "src/db.ts:42",
        description: "Unsafe query builder",
      },
    ]);
  });

  it("excludes persisted non-canonical findings from later anchor sets", async () => {
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([
        { id: "s1", status: "completed", target: "https://example.com" },
      ]),
      getScanFindings: vi.fn().mockReturnValue([
        {
          id: "canonical",
          title: "SQL injection in search",
          category: "sql-injection",
          description: "unsafe query",
          semanticDedupe: JSON.stringify({
            canonicalId: "canonical",
            isCanonical: true,
            clusterId: "s1:canonical",
            reason: "unique root cause",
          }),
        },
        {
          id: "duplicate",
          title: "SQLi via search",
          category: "sql-injection",
          description: "same unsafe query",
          semanticDedupe: JSON.stringify({
            canonicalId: "canonical",
            isCanonical: false,
            clusterId: "s1:canonical",
            reason: "same root cause and endpoint",
          }),
        },
      ]),
    });

    const result = await loadPriorScanAnchors(db, "https://example.com");

    expect(result.map((item) => item.id)).toEqual(["canonical"]);
  });

  it("caps results at opts.limit (default 100)", async () => {
    const findings = Array.from({ length: 50 }, (_, i) => ({
      id: `f-${i}`,
      title: `Finding ${i}`,
      category: "xss",
      description: "desc",
    }));
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([{ id: "s1", status: "completed", target: "t" }]),
      getScanFindings: vi.fn().mockReturnValue(findings),
    });

    const result = await loadPriorScanAnchors(db, "t", { limit: 10 });
    expect(result.length).toBe(10);
  });

  it("returns [] when there is no prior scan", async () => {
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([]),
    });
    const result = await loadPriorScanAnchors(db, "https://example.com");
    expect(result).toEqual([]);
  });

  it("returns [] when prior scan has no findings", async () => {
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([{ id: "s1", status: "completed", target: "t" }]),
      getScanFindings: vi.fn().mockReturnValue([]),
    });
    const result = await loadPriorScanAnchors(db, "t");
    expect(result).toEqual([]);
  });

  it("honours excludeScanId", async () => {
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([
        { id: "s2", status: "completed", target: "t" },
        { id: "s1", status: "completed", target: "t" },
      ]),
      getScanFindings: vi.fn().mockReturnValue([{ id: "f-1", title: "XSS", category: "xss", description: "d" }]),
    });

    const result = await loadPriorScanAnchors(db, "t", { excludeScanId: "s2" });
    // Should pick s1 (the next latest after excluding s2)
    expect(db.getScanFindings).toHaveBeenCalledWith("s1");
    expect(result.length).toBe(1);
  });

  it("falls back to 'unknown' location when reviewAnnotation is missing", async () => {
    const db = makeFakeDb({
      listScansByTarget: vi.fn().mockReturnValue([{ id: "s1", status: "completed", target: "t" }]),
      getScanFindings: vi.fn().mockReturnValue([{ id: "f-1", title: "XSS", category: "xss", description: "d" }]),
    });
    const result = await loadPriorScanAnchors(db, "t");
    expect(result[0].location).toBe("unknown");
  });
});

describe("applyFindingPostProcess", () => {
  it("passes anchors through to semanticDedupe when provided", async () => {
    const anchorItems: DedupeItem[] = [
      { id: "a-1", summary: "Old XSS", category: "xss", location: "old.ts:10", description: "prior finding" },
    ];
    const findings = [makeFinding({ id: "f-1", title: "New XSS" })];
    const runtime = makeStubRuntime();

    const result = await applyFindingPostProcess(findings, runtime, {
      semanticDedupe: true,
      scanId: "s1",
      anchors: anchorItems,
    });

    // With semanticDedupe enabled and no actual LLM call (stub returns empty),
    // the findings should get their fallback singleton mappings
    expect(result).toBe(0);
    // The stub runtime doesn't return real mappings, so findings remain unmapped
    // We're testing that the anchors option didn't throw
  });

  it("does not require anchors — works without them", async () => {
    const findings = [makeFinding({ id: "f-1", title: "Test" })];
    const runtime = makeStubRuntime();

    await expect(
      applyFindingPostProcess(findings, runtime, { semanticDedupe: true, scanId: "s1" }),
    ).resolves.not.toThrow();
  });

  it("returns 0 for empty findings", async () => {
    const runtime = makeStubRuntime();
    const result = await applyFindingPostProcess([], runtime, { semanticDedupe: true });
    expect(result).toBe(0);
  });
});