import { describe, it, expect, beforeEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { ReviewStore } from "./store.js";
import { batchCandidates, runReviewProcess } from "./process.js";
import type { ReviewFileRecord, ReviewFinding, ReviewInvocation, ReviewInvoker } from "./types.js";

// ── Fixture helpers ────────────────────────────────────────────────────────

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "process-test-"));
}

const BASE_FINDING: ReviewFinding = {
  severity: "high",
  vulnSlug: "sql-injection",
  title: "SQL injection",
  description: "User input in raw query",
  lineNumbers: [10],
  recommendation: "Use parameterized queries",
  confidence: "high",
};

function makeRecord(filePath: string, overrides: Partial<ReviewFileRecord> = {}): ReviewFileRecord {
  return {
    filePath,
    projectId: "test-project",
    candidates: [
      { vulnSlug: "sql-injection", lineNumbers: [10], snippet: "SELECT * FROM", matchedPattern: "sql-query" },
    ],
    findings: [],
    analysisHistory: [],
    status: "pending",
    ...overrides,
  };
}

function makeInvocation(
  label: string,
  output: string,
  overrides: Partial<ReviewInvocation> = {},
): ReviewInvocation {
  return {
    output,
    usage: { inputTokens: 100, outputTokens: 50, cachedInputTokens: 0 },
    durationMs: 500,
    model: "test-model",
    sessionId: "test-session",
    ...overrides,
  };
}

/**
 * Build a fake invoker keyed by `label`. A function maps each label to output.
 */
function fakeInvoker(
  responseFor: (prompt: string, label: string) => string,
): ReviewInvoker {
  return (prompt: string, label: string) =>
    Promise.resolve(makeInvocation(label, responseFor(prompt, label)));
}

function happyInvestigator(prompt: string, label: string): string {
  if (label === "refusal") return JSON.stringify({ refused: false });
  if (label === "investigate") {
    expect(prompt).toContain("Source (untrusted):");
    expect(prompt).toContain("export const fixture = true;");
  }
  const targetBlock = prompt.match(
    /## Target Files\n([\s\S]*?)\n\n## Investigation Instructions/,
  );
  const filePaths = targetBlock
    ? [...targetBlock[1].matchAll(/^- `([^`]+)`$/gm)].map((match) => match[1])
    : [];
  return JSON.stringify(filePaths.map((filePath) => ({
    filePath,
    findings: [{
      ...BASE_FINDING,
      title: `Finding in ${filePath}`,
      description: `Vulnerability found in ${filePath}`,
    }],
  })));
}

function refusalInvestigator(prompt: string, label: string): string {
  if (label === "refusal") return JSON.stringify({ refused: true, reason: "Cannot analyze this code" });
  return happyInvestigator(prompt, label);
}

// ── batchCandidates ────────────────────────────────────────────────────────

describe("batchCandidates", () => {
  it("groups files by directory and respects batchSize", () => {
    const records = [
      makeRecord("src/auth/login.ts"),
      makeRecord("src/auth/register.ts"),
      makeRecord("src/auth/reset.ts"),
      makeRecord("src/db/query.ts"),
      makeRecord("src/db/migrate.ts"),
      makeRecord("src/api/handler.ts"),
      makeRecord("src/api/middleware.ts"),
    ];

    const batches = batchCandidates(records, 5);
    // 3 dirs: src/auth (3), src/db (2), src/api (2)
    // auth (3) + db (2) = 5 fits, api (2) = separate
    expect(batches).toHaveLength(2);

    // First batch: auth + db = 5 files
    const firstPaths = batches[0].map((r) => r.filePath);
    expect(firstPaths).toContain("src/auth/login.ts");
    expect(firstPaths).toContain("src/auth/register.ts");
    expect(firstPaths).toContain("src/auth/reset.ts");
    expect(firstPaths).toContain("src/db/query.ts");
    expect(firstPaths).toContain("src/db/migrate.ts");

    // Second batch: api = 2 files
    const secondPaths = batches[1].map((r) => r.filePath);
    expect(secondPaths).toContain("src/api/handler.ts");
    expect(secondPaths).toContain("src/api/middleware.ts");
  });

  it("splits oversized directory groups", () => {
    const records = Array.from({ length: 12 }, (_, i) =>
      makeRecord(`src/lib/file${i}.ts`),
    );
    const batches = batchCandidates(records, 5);
    expect(batches.length).toBeGreaterThanOrEqual(3);
    for (const batch of batches) {
      expect(batch.length).toBeLessThanOrEqual(5);
    }
  });

  it("returns empty for empty input", () => {
    expect(batchCandidates([], 5)).toEqual([]);
  });

  it("rejects non-positive batch sizes", () => {
    expect(() => batchCandidates([], 0)).toThrow("batchSize must be a positive integer");
    expect(() => batchCandidates([], 1.5)).toThrow("batchSize must be a positive integer");
  });
});

// ── runReviewProcess ───────────────────────────────────────────────────────

describe("runReviewProcess", () => {
  let dataDir: string;
  let store: ReviewStore;
  const projectId = "test-project";

  beforeEach(() => {
    dataDir = tmpDir();
    store = new ReviewStore({ dataDir });
    for (const filePath of [
      "src/auth/login.ts",
      "src/db/query.ts",
      "src/lib/file0.ts",
      "src/lib/file1.ts",
      "src/nothing.ts",
    ]) {
      const fullPath = path.join(dataDir, filePath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, "export const fixture = true;\n");
    }
  });

  it("rejects invalid process worker options before starting a run", async () => {
    await expect(runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      batchSize: 0,
    })).rejects.toThrow("batchSize must be a positive integer");
    await expect(runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      concurrency: 0,
    })).rejects.toThrow("concurrency must be a positive integer");
  });

  it("releases a failed sequential batch and marks its run error", async () => {
    const record = makeRecord("src/auth/login.ts");
    store.writeRecord(record);

    await expect(runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: async () => {
        throw new Error("model transport failed");
      },
      concurrency: 1,
    })).rejects.toThrow("model transport failed");

    const updated = store.readRecord(projectId, record.filePath)!;
    expect(updated.status).toBe("pending");
    expect(updated.lockedByRunId).toBeUndefined();

    const runFiles = fs.readdirSync(store.runsDir(projectId));
    expect(runFiles).toHaveLength(1);
    const meta = store.loadRunMeta(projectId, runFiles[0].replace(/\.json$/, ""))!;
    expect(meta.phase).toBe("error");
  });

  it("happy path: processes files and stores findings", async () => {
    const rec1 = makeRecord("src/auth/login.ts");
    const rec2 = makeRecord("src/db/query.ts");
    store.writeRecord(rec1);
    store.writeRecord(rec2);

    const result = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      concurrency: 1,
    });

    expect(result.runId).toBeTruthy();
    expect(result.filesInvestigated).toBe(2);
    expect(result.findingsAdded).toBeGreaterThanOrEqual(2);
    expect(result.costUsd).toBeGreaterThan(0);
    expect(result.refusals).toBe(0);
    expect(result.limitReached).toBeUndefined();

    // Verify records were updated
    const loginRecord = store.readRecord(projectId, "src/auth/login.ts");
    expect(loginRecord?.status).toBe("analyzed");
    expect(loginRecord?.findings.length).toBeGreaterThan(0);
    expect(loginRecord?.analysisHistory.length).toBe(1);
    expect(loginRecord?.analysisHistory[0].runId).toBe(result.runId);
    expect(loginRecord?.analysisHistory[0].costUsd).toBeGreaterThan(0);
    expect(loginRecord?.analysisHistory[0].agentType).toBe("native");

    const dbRecord = store.readRecord(projectId, "src/db/query.ts");
    expect(dbRecord?.status).toBe("analyzed");
    expect(dbRecord?.analysisHistory.length).toBe(1);
  });

  it("repair loop fixes invalid findings", async () => {
    const rec = makeRecord("src/auth/login.ts");
    store.writeRecord(rec);

    let callCount = 0;
    const invoker: ReviewInvoker = (prompt: string, label: string) => {
      callCount++;
      if (label === "refusal") return Promise.resolve(makeInvocation(label, JSON.stringify({ refused: false })));
      if (label === "field-repair") {
        // Return corrected findings
        return Promise.resolve(makeInvocation(label, JSON.stringify([
          { filePath: "src/auth/login.ts", findings: [BASE_FINDING] },
        ])));
      }
      // First investigate: return invalid finding
      return Promise.resolve(makeInvocation(label, JSON.stringify([
        {
          filePath: "src/auth/login.ts",
          findings: [{
            severity: "bad",
            vulnSlug: "",
            title: "",
            description: "",
            lineNumbers: [-1],
            confidence: "unknown",
            recommendation: "",
          }],
        },
      ])));
    };

    const result = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker,
      concurrency: 1,
    });

    // Repair round was called (3 calls: investigate, repair, refusal)
    expect(callCount).toBeGreaterThanOrEqual(3);

    // The file was still analyzed because repair succeeded
    const record = store.readRecord(projectId, "src/auth/login.ts");
    expect(record?.status).toBe("analyzed");
    expect(record?.findings.length).toBe(1);
    expect(record?.findings[0].title).toBe("SQL injection");
  });

  it("refusal keeps files pending", async () => {
    const rec = makeRecord("src/auth/login.ts");
    store.writeRecord(rec);

    const result = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(refusalInvestigator),
      concurrency: 1,
    });

    expect(result.refusals).toBe(1);

    // File status stays pending
    const record = store.readRecord(projectId, "src/auth/login.ts");
    expect(record?.status).toBe("pending");
    // Analysis entry still exists with refusal
    expect(record?.analysisHistory.length).toBe(1);
    expect(record?.analysisHistory[0].refusal?.refused).toBe(true);
  });

  it("reinvestigate wave marker skips already-marked files", async () => {
    const rec1 = makeRecord("src/auth/login.ts", {
      status: "analyzed" as const,
      fileHash: "abc",
      analyzedHash: "abc",
      analysisHistory: [{
        runId: "prev-run",
        investigatedAt: new Date().toISOString(),
        durationMs: 100,
        agentType: "native",
        findingCount: 1,
        reinvestigateMarker: 1,
        costUsd: 0.01,
        usage: { inputTokens: 10, outputTokens: 5 },
      }],
    });
    const rec2 = makeRecord("src/db/query.ts", {
      status: "analyzed" as const,
      fileHash: "def",
      analyzedHash: "def",
      analysisHistory: [{
        runId: "prev-run",
        investigatedAt: new Date().toISOString(),
        durationMs: 100,
        agentType: "native",
        findingCount: 0,
        costUsd: 0.01,
        usage: { inputTokens: 10, outputTokens: 5 },
      }],
    });
    store.writeRecord(rec1);
    store.writeRecord(rec2);

    const result = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      reinvestigate: 1,
      concurrency: 1,
    });

    // rec1 has marker → skipped, rec2 does not → investigated
    expect(result.filesInvestigated).toBe(1);

    const loginRecord = store.readRecord(projectId, "src/auth/login.ts");
    // Should still have only 1 history entry (no new investigation)
    expect(loginRecord?.analysisHistory.length).toBe(1);

    const queryRecord = store.readRecord(projectId, "src/db/query.ts");
    expect(queryRecord?.analysisHistory.length).toBe(2);
    expect(queryRecord?.analysisHistory[1].reinvestigateMarker).toBe(1);
  });

  it("cost cap preserves completed batches and leaves remaining work pending", async () => {
    const records = Array.from({ length: 2 }, (_, i) =>
      makeRecord(`src/lib/file${i}.ts`),
    );
    for (const record of records) store.writeRecord(record);

    const result = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      maxCostUsd: 0.000001,
      batchSize: 1,
      concurrency: 1,
    });

    expect(result.limitReached?.kind).toBe("cost");
    expect(result.filesInvestigated).toBe(1);
    expect(result.costUsd).toBeGreaterThanOrEqual(0.000001);

    const statuses = records.map((record) => store.readRecord(projectId, record.filePath)?.status);
    expect(statuses.filter((status) => status === "analyzed")).toHaveLength(1);
    expect(statuses.filter((status) => status === "pending")).toHaveLength(1);

    const resumed = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      batchSize: 1,
      concurrency: 1,
    });
    expect(resumed.limitReached).toBeUndefined();
    expect(resumed.filesInvestigated).toBe(1);
    expect(records.every((record) => store.readRecord(projectId, record.filePath)?.status === "analyzed")).toBe(true);
  });

  it("returns early when no candidate records exist", async () => {
    // Write a record with no candidates and status analyzed
    store.writeRecord({
      ...makeRecord("src/nothing.ts"),
      candidates: [],
      status: "analyzed",
    });

    const result = await runReviewProcess(store, {
      projectId,
      rootPath: dataDir,
      invoker: fakeInvoker(happyInvestigator),
      concurrency: 1,
    });

    expect(result.filesInvestigated).toBe(0);
    expect(result.findingsAdded).toBe(0);
  });
});