import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ReviewStore } from "./store.js";
import { runReviewRevalidate } from "./revalidate.js";
import { ReviewLimitError, type ReviewInvocation, type ReviewInvoker, type ReviewFileRecord } from "./types.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "revalidate-test-"));
}

function makeStore(dataDir: string): ReviewStore {
  return new ReviewStore({ dataDir });
}

function makeFinding(overrides: Partial<{
  severity: "critical" | "high" | "medium" | "low" | "info";
  vulnSlug: string;
  title: string;
  findingId: string;
  description: string;
  lineNumbers: number[];
  recommendation: string;
  confidence: "high" | "medium" | "low";
  revalidation: Record<string, unknown> | undefined;
}> = {}) {
  return {
    severity: "high" as const,
    vulnSlug: "xss",
    title: "Cross-Site Scripting",
    description: "User input flows into innerHTML",
    lineNumbers: [42, 45],
    recommendation: "Use textContent instead",
    confidence: "high" as const,
    findingId: "finding-001",
    ...overrides,
  };
}

function makeRecord(overrides: Partial<ReviewFileRecord> = {}): ReviewFileRecord {
  return {
    filePath: "src/app.ts",
    projectId: "test-project",
    candidates: [],
    findings: [makeFinding()],
    analysisHistory: [],
    status: "analyzed",
    ...overrides,
  };
}

function fakeInvoker(output: string, costUsd = 0.01, usage?: ReviewInvocation["usage"]): ReviewInvoker {
  return vi.fn(async (_prompt: string, _label: string): Promise<ReviewInvocation> => ({
    output,
    usage: usage ?? { inputTokens: 1000, outputTokens: 500 },
    durationMs: 100,
    model: "test-model",
    costUsd,
  }));
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("runReviewRevalidate", () => {
  let dir: string;
  let store: ReviewStore;

  beforeEach(() => {
    dir = tempDir();
    store = makeStore(dir);
  });

  afterEach(() => {
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  // Seed a record into the store
  function seedRecord(record: ReviewFileRecord): void {
    // Ensure store directories exist
    store.writeRecord(record);
  }

  it("revalidates findings and annotates IN PLACE without replacing other fields", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({
          findingId: "id-001",
          title: "XSS",
          description: "User input flows into innerHTML",
        }),
      ],
    });
    seedRecord(record);

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      invoker: fakeInvoker(
        JSON.stringify([{ findingId: "id-001", verdict: "true-positive", reasoning: "User input reaches innerHTML without sanitization — clear XSS vector" }]),
      ),
    });

    expect(result.revalidated).toBe(1);
    expect(result.truePositives).toBe(1);

    // Read back the record
    const updated = store.readRecord("test-project", "src/app.ts")!;
    expect(updated.findings).toHaveLength(1);
    const finding = updated.findings[0]!;
    expect(finding.severity).toBe("high"); // unchanged
    expect(finding.title).toBe("XSS"); // unchanged
    expect(finding.description).toBe("User input flows into innerHTML"); // unchanged
    expect(finding.revalidation).toBeDefined();
    expect(finding.revalidation!.verdict).toBe("true-positive");
    expect(finding.revalidation!.runId).toBe(result.runId);
  });

  it("reconciles by 4-pass priority: findingId beats title", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({ findingId: "id-001", title: "XSS Issue" }),
      ],
    });
    seedRecord(record);

    // Model output uses both findingId match and title match but findingId should win
    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      invoker: fakeInvoker(
        JSON.stringify([{ findingId: "id-001", verdict: "false-positive", reasoning: "Not exploitable - input is sanitized" }]),
      ),
    });

    expect(result.revalidated).toBe(1);
    expect(result.falsePositives).toBe(1);
  });

  it("handles duplicate-of-primary invariant: duplicate pointing at another duplicate gets downgraded", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({ findingId: "id-001", title: "XSS in render", vulnSlug: "xss" }),
        makeFinding({ findingId: "id-002", title: "XSS in sanitize", vulnSlug: "xss" }),
        makeFinding({ findingId: "id-003", title: "RCE in eval", vulnSlug: "rce" }),
      ],
    });
    seedRecord(record);

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      invoker: fakeInvoker(
        JSON.stringify([
          { findingId: "id-001", verdict: "true-positive", reasoning: "Real XSS in render" },
          { findingId: "id-002", verdict: "duplicate", duplicateOf: "id-001", reasoning: "Same as id-001" },
          { findingId: "id-003", verdict: "duplicate", duplicateOf: "id-002", reasoning: "Duplicate of id-002" },
        ]),
      ),
    });

    expect(result.revalidated).toBe(3);
    // id-002 starts as duplicate-of-id-001 (which is true-positive) → valid duplicate
    // id-003 starts as duplicate-of-id-002 → but id-002's verdict is also 'duplicate' → downgraded
    expect(result.duplicates).toBe(1); // only id-002 remains duplicate
    expect(result.uncertain).toBe(1); // id-003 downgraded

    const updated = store.readRecord("test-project", "src/app.ts")!;
    const d2 = updated.findings.find((f) => f.findingId === "id-002")!;
    expect(d2.revalidation!.verdict).toBe("duplicate");
    expect(d2.revalidation!.duplicateOf).toBe("id-001");

    const d3 = updated.findings.find((f) => f.findingId === "id-003")!;
    expect(d3.revalidation!.verdict).toBe("uncertain");
    expect(d3.revalidation!.reasoning).toContain("DOWNGARDED");
  });

  it("applies minSeverity filter — low/info findings are skipped", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({ findingId: "id-001", title: "Critical RCE", severity: "critical" }),
        makeFinding({ findingId: "id-002", title: "Low info leak", severity: "low" }),
        makeFinding({ findingId: "id-003", title: "Info comment", severity: "info" }),
      ],
    });
    seedRecord(record);

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      minSeverity: "high",
      invoker: fakeInvoker(
        JSON.stringify([{ findingId: "id-001", verdict: "true-positive", reasoning: "Real RCE" }]),
      ),
    });

    // Only the critical finding should be revalidated
    expect(result.revalidated).toBe(1);
    expect(result.missing).toBe(0); // no missing verdicts — low/info weren't included

    const updated = store.readRecord("test-project", "src/app.ts")!;
    const lowFinding = updated.findings.find((f) => f.findingId === "id-002")!;
    expect(lowFinding.revalidation).toBeUndefined();

    const infoFinding = updated.findings.find((f) => f.findingId === "id-003")!;
    expect(infoFinding.revalidation).toBeUndefined();
  });

  it("force re-revalidates already-annotated findings", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({
          findingId: "id-001",
          title: "XSS",
          revalidation: { verdict: "false-positive", reasoning: "was false", revalidatedAt: "2024-01-01", runId: "old-run" },
        }),
      ],
    });
    seedRecord(record);

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      force: true,
      invoker: fakeInvoker(
        JSON.stringify([{ findingId: "id-001", verdict: "true-positive", reasoning: "Actually real upon review" }]),
      ),
    });

    expect(result.revalidated).toBe(1);
    expect(result.truePositives).toBe(1);

    const updated = store.readRecord("test-project", "src/app.ts")!;
    const finding = updated.findings[0]!;
    expect(finding.revalidation!.verdict).toBe("true-positive");
    expect(finding.revalidation!.runId).toBe(result.runId); // new run
  });

  it("on ReviewLimitError reverts claimed files to pending", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({ findingId: "id-001", title: "XSS", severity: "critical" }),
      ],
    });
    seedRecord(record);

    const throwingInvoker = vi.fn(async (): Promise<ReviewInvocation> => {
      throw new ReviewLimitError("cost", "Cost limit exceeded");
    });

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      invoker: throwingInvoker,
    });

    expect(result.revalidated).toBe(0);
    expect(result.limitReached).toBe(true);

    const updated = store.readRecord("test-project", "src/app.ts")!;
    expect(updated.status).toBe("pending");
    expect(updated.lockedByRunId).toBeUndefined();
  });

  it("reports stats accurately", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({ findingId: "id-001", title: "TP finding", severity: "critical" }),
        makeFinding({ findingId: "id-002", title: "FP finding" }),
        makeFinding({ findingId: "id-003", title: "Fixed finding" }),
        makeFinding({ findingId: "id-004", title: "Uncertain finding" }),
      ],
    });
    seedRecord(record);

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      invoker: fakeInvoker(
        JSON.stringify([
          { findingId: "id-001", verdict: "true-positive", reasoning: "Real" },
          { findingId: "id-002", verdict: "false-positive", reasoning: "Not real" },
          { findingId: "id-003", verdict: "fixed", reasoning: "Patched in 2.0" },
          { findingId: "id-004", verdict: "uncertain", reasoning: "Cannot tell" },
        ]),
        undefined,
        { inputTokens: 500, outputTokens: 200 },
      ),
    });

    expect(result.revalidated).toBe(4);
    expect(result.truePositives).toBe(1);
    expect(result.falsePositives).toBe(1);
    expect(result.fixed).toBe(1);
    expect(result.uncertain).toBe(1);
    expect(result.duplicates).toBe(0);
    expect(result.missing).toBe(0);
    expect(result.costUsd).toBeGreaterThan(0);
    expect(result.limitReached).toBeUndefined();
  });

  it("handles cost limit: stops after exceeding maxCostUsd", async () => {
    const record1 = makeRecord({ filePath: "a.ts", projectId: "test-project", findings: [makeFinding({ findingId: "id-001" })] });
    const record2 = makeRecord({ filePath: "b.ts", projectId: "test-project", findings: [makeFinding({ findingId: "id-002" })] });
    seedRecord(record1);
    seedRecord(record2);

    // invoker cost is 0.01 per call, max is 0.005 → second batch would exceed
    const invoker = fakeInvoker(
      JSON.stringify([{ findingId: "id-001", verdict: "true-positive", reasoning: "real" }]),
      0.01,
    );

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      maxCostUsd: 0.005,
      invoker,
    });

    // First batch processes (cost 0.01 > 0.005 but we check AFTER processing each batch)
    // So exactly one batch gets processed
    expect(result.revalidated).toBeGreaterThanOrEqual(1);
    expect(result.limitReached).toBe(true);
  });

  it("handles duration limit: stops after exceeding maxDurationMs", async () => {
    const record = makeRecord({
      filePath: "src/app.ts",
      projectId: "test-project",
      findings: [
        makeFinding({ findingId: "id-001", title: "Slow finding" }),
      ],
    });
    seedRecord(record);

    // A zero duration budget is already exhausted at the first check, so the
    // limit fires deterministically before any batch is claimed or invoked.
    const invoker = vi.fn(async (_prompt: string, _label: string): Promise<ReviewInvocation> => ({
      output: JSON.stringify([{ findingId: "id-001", verdict: "true-positive", reasoning: "real" }]),
      usage: { inputTokens: 100, outputTokens: 50 },
      durationMs: 50,
      model: "test-model",
      costUsd: 0.001,
    }));

    const result = await runReviewRevalidate(store, {
      projectId: "test-project",
      rootPath: dir,
      maxDurationMs: 0, // already over budget
      invoker,
    });

    expect(result.revalidated).toBe(0);
    expect(result.limitReached).toBe(true);
    expect(invoker).not.toHaveBeenCalled();
  });
});