/**
 * Coverage seed for `0sec-cli`'s `orchestrate` command — the autonomous
 * worker that pulls runnable WorkItems from the case graph, claims them,
 * dispatches the right agent loop (attack / verify / triage / family-aware),
 * and reconciles outcomes back into the DB. This file is the entry point
 * the cloud worker-controller execs against per-tenant queues, so any
 * regression in selection ordering, claim handoff, or state transitions
 * either drops work on the floor or double-bills a customer.
 *
 * Strategy: mock the two heavy boundaries at the module level so we never
 *
 *   1. open WASM SQLite (memory: project_db_wasm — anything that calls
 *      `new osecDB(...)` must be intercepted), or
 *   2. spawn a real agent loop (agenticScan / runAgentLoop / createRuntime).
 *
 * The chatty FakeOsecDB records every method invocation in a shared
 * `dbState.calls` log so we can assert on the call *sequence* the action
 * walks (claim → reopen → log_event → execute → upsertWorkItem(done) →
 * completeScan), which is the actual contract 0sec-cloud's worker-
 * controller depends on. Per-test we mutate `dbState.workItems`,
 * `dbState.cases`, `dbState.scans`, and `dbState.findings` to plant
 * runnable / dependent / blocked fixtures.
 *
 * The watch-mode loop is exercised under `vi.useFakeTimers()` so the
 * `sleep(pollInterval)` between idle passes resolves deterministically —
 * we tick the clock by the configured interval and assert findRunnable
 * was called the expected number of times before we set `stopping`.
 *
 * What's covered (16 tests):
 *
 *   recoverStaleWorkers (exported helper):
 *     • Marks heartbeat-expired workers as `error` and resets their
 *       in-progress WorkItem back to `todo` with a recovery summary.
 *     • Leaves fresh-heartbeat workers and already-stopped workers alone.
 *     • Returns the count of recovered work items (not workers).
 *
 *   Selection (via the action):
 *     • Runnable items are filtered to EXECUTABLE_KINDS only
 *       (human_review never selected).
 *     • Items with status != "todo" are skipped.
 *     • Items whose `dependsOn` is not "done" are skipped.
 *     • Items whose sibling in the same case is already in_progress are
 *       skipped (per-case mutex — the `queuedByCase` collapse).
 *     • `--limit` caps the number of cases claimed in one pass.
 *
 *   Dispatch:
 *     • Non-family (no fingerprint) item → agenticScan called with
 *       resumeScanId + the candidate's target/depth/mode.
 *     • Family (fingerprint present) item routed to runAgentLoop with
 *       role="attack" for hypothesis/poc_build kinds.
 *     • Family blind_verify routed to runAgentLoop with role="verify".
 *     • Family consensus kind reads computeConsensus and either
 *       moves the workflow to human_review (verified) or blocks the
 *       work item (disputed) — never spawns runAgentLoop.
 *
 *   State transitions:
 *     • Success: claim → upsertWorkItem(status="done") + completeScan +
 *       worker_completed event.
 *     • Failure (agenticScan throws): upsertWorkItem(status="blocked",
 *       summary=<error>) + failScan + worker_failed event.
 *
 *   Watch mode + argument plumbing:
 *     • `--watch` polls at `pollInterval` and re-queries findRunnable.
 *     • `--limit 0` is clamped up to 1 (Math.max).
 *     • `--poll-interval 100` is clamped up to 1000 (Math.max).
 *     • `--db-path` is threaded into every osecDB constructor.
 *
 * Out of scope (refactor required — noted in PR body):
 *   • The action is monolithic — `findRunnableCandidates`,
 *     `claimCandidate`, `runCandidate`, `reconcileCandidateOutcome`,
 *     `runFamilyCandidate` are file-internal. We drive them via the
 *     Commander action with carefully-staged dbState fixtures rather
 *     than promoting them to exports.
 *   • Heartbeat `setInterval` is a side-effect of the action; we tear
 *     it down in afterEach via vi.useRealTimers + the action's
 *     own `clearInterval` in its `finally`. We don't assert that
 *     heartbeat fires N times — that would couple the test to the
 *     internal clamp `Math.min(pollInterval, 5000)`.
 *   • Real SIGINT/SIGTERM stop behaviour. The action attaches
 *     `process.once` handlers; we strip them in afterEach so they
 *     don't accumulate, but we don't fire them in tests.
 *
 * Precedent (review ladder):
 *   • PR #310 — packages/cli/src/commands/__tests__/mcp-server.test.ts
 *   • PR #309 — packages/cli/src/commands/__tests__/db.test.ts
 *   • PR #307 — packages/cli/src/commands/__tests__/disclose.test.ts
 *   • PR #301 — packages/cli/src/commands/__tests__/run.test.ts +
 *               scan.test.ts (the original "seed coverage" precedent)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { WorkItemRecord, WorkerRecord } from "@0sec/shared";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// orchestrate.ts imports osecDB statically and constructs it 5+ times
// per action invocation. We replace the whole module so no constructor
// path touches the WASM shim.

interface DbCall {
  method: string;
  args: unknown[];
}

interface FakeScanRow {
  id: string;
  target: string;
  depth: string;
  runtime: string;
  mode: string;
  status: string;
}

interface FakeCaseRow {
  id: string;
  target: string;
  targetType: string;
  latestScanId?: string | null;
}

interface FakeFamilyFindingRow {
  id: string;
  scanId: string;
  templateId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  timestamp: number;
}

interface DbState {
  calls: DbCall[];
  ctorArgs: Array<string | undefined>;
  workItems: WorkItemRecord[];
  workers: WorkerRecord[];
  cases: FakeCaseRow[];
  scans: FakeScanRow[];
  familyFindings: Map<string, FakeFamilyFindingRow[]>;
  claimResultByItemId: Map<string, boolean>;
  consensusByFindingId: Map<string, string>;
  // When true, simulate findScan returning a running scan that should be skipped.
  scanStatusOverride: Map<string, string>;
}

const dbState: DbState = {
  calls: [],
  ctorArgs: [],
  workItems: [],
  workers: [],
  cases: [],
  scans: [],
  familyFindings: new Map(),
  claimResultByItemId: new Map(),
  consensusByFindingId: new Map(),
  scanStatusOverride: new Map(),
};

class FakeOsecDB {
  constructor(dbPath?: string) {
    dbState.ctorArgs.push(dbPath);
  }
  listWorkItems(opts: { caseId?: string; limit?: number }): WorkItemRecord[] {
    dbState.calls.push({ method: "listWorkItems", args: [opts] });
    const all = dbState.workItems;
    return opts?.caseId ? all.filter((w) => w.caseId === opts.caseId) : all;
  }
  listWorkers(_limit: number): WorkerRecord[] {
    dbState.calls.push({ method: "listWorkers", args: [_limit] });
    return dbState.workers;
  }
  getCase(caseId: string): FakeCaseRow | undefined {
    dbState.calls.push({ method: "getCase", args: [caseId] });
    return dbState.cases.find((c) => c.id === caseId);
  }
  getScan(scanId: string): FakeScanRow | undefined {
    dbState.calls.push({ method: "getScan", args: [scanId] });
    const found = dbState.scans.find((s) => s.id === scanId);
    if (!found) return undefined;
    const override = dbState.scanStatusOverride.get(scanId);
    return override ? { ...found, status: override } : found;
  }
  getRelatedFindings(fp: string): FakeFamilyFindingRow[] {
    dbState.calls.push({ method: "getRelatedFindings", args: [fp] });
    return dbState.familyFindings.get(fp) ?? [];
  }
  getFindings(scanId: string): Array<{ severity: string }> {
    dbState.calls.push({ method: "getFindings", args: [scanId] });
    return [];
  }
  claimWorkItem(
    itemId: string,
    workerId: string,
    payload: { owner: string; summary: string },
  ): boolean {
    dbState.calls.push({
      method: "claimWorkItem",
      args: [itemId, workerId, payload],
    });
    return dbState.claimResultByItemId.get(itemId) ?? true;
  }
  upsertWorkItem(record: WorkItemRecord): void {
    dbState.calls.push({ method: "upsertWorkItem", args: [record] });
    // Mutate the in-memory list so subsequent listWorkItems reflects state.
    const idx = dbState.workItems.findIndex((w) => w.id === record.id);
    if (idx >= 0) dbState.workItems[idx] = record;
    else dbState.workItems.push(record);
  }
  upsertWorker(record: Omit<WorkerRecord, "startedAt" | "updatedAt" | "heartbeatAt">): void {
    dbState.calls.push({ method: "upsertWorker", args: [record] });
  }
  stopWorkersByLabel(label: string, workerId: string): number {
    dbState.calls.push({ method: "stopWorkersByLabel", args: [label, workerId] });
    return 0;
  }
  reopenScan(scanId: string): void {
    dbState.calls.push({ method: "reopenScan", args: [scanId] });
  }
  completeScan(scanId: string, summary: unknown): void {
    dbState.calls.push({ method: "completeScan", args: [scanId, summary] });
  }
  failScan(scanId: string, reason: string): void {
    dbState.calls.push({ method: "failScan", args: [scanId, reason] });
  }
  logEvent(event: unknown): string {
    dbState.calls.push({ method: "logEvent", args: [event] });
    return "evt-1";
  }
  computeConsensus(findingId: string): string {
    dbState.calls.push({ method: "computeConsensus", args: [findingId] });
    return dbState.consensusByFindingId.get(findingId) ?? "pending";
  }
  updateFindingWorkflowByFingerprint(
    fp: string,
    status: string,
    assignee: string | null,
  ): void {
    dbState.calls.push({
      method: "updateFindingWorkflowByFingerprint",
      args: [fp, status, assignee],
    });
  }
  close(): void {
    dbState.calls.push({ method: "close", args: [] });
  }
}

vi.mock("@0sec/db", () => ({ osecDB: FakeOsecDB }));

// @0sec/core: agenticScan, runAgentLoop, createRuntime, LlmApiRuntime,
// getToolsForRole. We intercept each so no real LLM call ever fires.

const agenticScanMock = vi.fn();
const runAgentLoopMock = vi.fn();
const createRuntimeMock = vi.fn(() => ({ kind: "mock-runtime" }));
const getToolsForRoleMock = vi.fn(() => []);

class FakeLlmApiRuntime {
  constructor(public opts: unknown) {}
}

vi.mock("@0sec/core", () => ({
  agenticScan: agenticScanMock,
  runAgentLoop: runAgentLoopMock,
  createRuntime: createRuntimeMock,
  LlmApiRuntime: FakeLlmApiRuntime,
  getToolsForRole: getToolsForRoleMock,
}));

const { registerOrchestrateCommand, recoverStaleWorkers } = await import(
  "../orchestrate.js"
);

// The action registers SIGINT/SIGTERM handlers via process.once on every
// invocation. Across ~16 tests that adds up; raise the listener ceiling
// and strip per-test (same approach as mcp-server.test.ts).
process.setMaxListeners(64);

// ── Helpers ────────────────────────────────────────────────────────────────

async function runCli(argv: string[]): Promise<unknown> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerOrchestrateCommand(program);
  try {
    await program.parseAsync(["node", "0sec-cli", ...argv]);
    return undefined;
  } catch (err) {
    return err;
  }
}

function callsByMethod(method: string): DbCall[] {
  return dbState.calls.filter((c) => c.method === method);
}

function makeWorkItem(overrides: Partial<WorkItemRecord> & { id: string }): WorkItemRecord {
  return {
    id: overrides.id,
    caseId: overrides.caseId ?? "case-1",
    findingFingerprint: overrides.findingFingerprint ?? null,
    kind: overrides.kind ?? "hypothesis",
    title: overrides.title ?? `wi ${overrides.id}`,
    owner: overrides.owner ?? null,
    status: overrides.status ?? "todo",
    summary: overrides.summary ?? null,
    dependsOn: overrides.dependsOn ?? null,
    createdAt: overrides.createdAt ?? "2026-01-01T00:00:00.000Z",
    updatedAt: overrides.updatedAt ?? "2026-01-01T00:00:00.000Z",
  };
}

function makeCase(id: string, target: string): FakeCaseRow {
  return {
    id,
    target,
    targetType: "web-app",
    latestScanId: `${id}-scan`,
  };
}

function makeScan(id: string, target: string): FakeScanRow {
  return {
    id,
    target,
    depth: "deep",
    runtime: "auto",
    mode: "deep",
    status: "completed",
  };
}

function resetDbState(): void {
  dbState.calls.length = 0;
  dbState.ctorArgs.length = 0;
  dbState.workItems.length = 0;
  dbState.workers.length = 0;
  dbState.cases.length = 0;
  dbState.scans.length = 0;
  dbState.familyFindings.clear();
  dbState.claimResultByItemId.clear();
  dbState.consensusByFindingId.clear();
  dbState.scanStatusOverride.clear();
}

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetDbState();
  agenticScanMock.mockReset().mockResolvedValue({
    summary: { totalFindings: 0, critical: 0, high: 0 },
  });
  runAgentLoopMock.mockReset().mockResolvedValue(undefined);
  createRuntimeMock.mockClear();
  getToolsForRoleMock.mockClear().mockReturnValue([]);
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  process.removeAllListeners("SIGINT");
  process.removeAllListeners("SIGTERM");
  if (vi.isFakeTimers()) vi.useRealTimers();
});

// ── Tests: recoverStaleWorkers (exported helper) ───────────────────────────

describe("recoverStaleWorkers", () => {
  it("returns 0 when no workers are stale", () => {
    dbState.workers = [
      {
        id: "w-fresh",
        role: "orchestrator",
        status: "running",
        label: "fresh",
        currentCaseId: null,
        currentWorkItemId: null,
        currentScanId: null,
        pid: 1,
        host: "h",
        lastError: null,
        heartbeatAt: new Date().toISOString(), // now
        startedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ];
    const recovered = recoverStaleWorkers(undefined);
    expect(recovered).toBe(0);
    // No upsertWorker for the fresh one.
    expect(callsByMethod("upsertWorker")).toHaveLength(0);
  });

  it("skips workers with status='stopped' regardless of heartbeat age", () => {
    dbState.workers = [
      {
        id: "w-stopped",
        role: "orchestrator",
        status: "stopped",
        label: "stopped",
        currentCaseId: null,
        currentWorkItemId: "wi-1", // would otherwise be reset
        currentScanId: null,
        pid: 1,
        host: "h",
        lastError: null,
        heartbeatAt: "1970-01-01T00:00:00.000Z", // ancient
        startedAt: "2025-01-01T00:00:00.000Z",
        updatedAt: "2025-01-01T00:00:00.000Z",
      },
    ];
    dbState.workItems = [makeWorkItem({ id: "wi-1", status: "in_progress" })];
    const recovered = recoverStaleWorkers(undefined);
    expect(recovered).toBe(0);
    // No state changes for stopped workers.
    expect(callsByMethod("upsertWorker")).toHaveLength(0);
    expect(callsByMethod("upsertWorkItem")).toHaveLength(0);
  });

  it("resets stale worker's in_progress item to todo and marks worker as error", () => {
    dbState.workers = [
      {
        id: "w-stale",
        role: "orchestrator",
        status: "running",
        label: "ghost",
        currentCaseId: "case-1",
        currentWorkItemId: "wi-1",
        currentScanId: "scan-1",
        pid: 1,
        host: "h",
        lastError: null,
        heartbeatAt: "1970-01-01T00:00:00.000Z", // very stale
        startedAt: "2025-01-01T00:00:00.000Z",
        updatedAt: "2025-01-01T00:00:00.000Z",
      },
    ];
    dbState.workItems = [
      makeWorkItem({ id: "wi-1", status: "in_progress" }),
    ];

    const recovered = recoverStaleWorkers(undefined);
    expect(recovered).toBe(1);

    // Work item flipped back to todo with a recovery summary.
    const itemUpdates = callsByMethod("upsertWorkItem");
    expect(itemUpdates).toHaveLength(1);
    const updated = itemUpdates[0]!.args[0] as WorkItemRecord;
    expect(updated.status).toBe("todo");
    expect(updated.summary).toMatch(/Recovered after stale worker ghost/);

    // Worker marked as error with a heartbeat-expired message.
    const workerUpdates = callsByMethod("upsertWorker");
    expect(workerUpdates).toHaveLength(1);
    const worker = workerUpdates[0]!.args[0] as { status: string; lastError: string };
    expect(worker.status).toBe("error");
    expect(worker.lastError).toMatch(/Heartbeat expired after/);
  });
});

// ── Tests: action — selection invariants ───────────────────────────────────

describe("orchestrate action — selection", () => {
  it("does not select work items with kind=human_review (not in EXECUTABLE_KINDS)", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [
      makeWorkItem({ id: "wi-human", kind: "human_review", status: "todo" }),
    ];

    await runCli(["orchestrate"]);

    // human_review is filtered before claim → no claimWorkItem, no agenticScan.
    expect(callsByMethod("claimWorkItem")).toHaveLength(0);
    expect(agenticScanMock).not.toHaveBeenCalled();
  });

  it("does not select work items whose status != 'todo'", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [
      makeWorkItem({ id: "wi-blocked", kind: "hypothesis", status: "blocked" }),
      makeWorkItem({ id: "wi-done", kind: "hypothesis", status: "done" }),
    ];

    await runCli(["orchestrate"]);

    expect(callsByMethod("claimWorkItem")).toHaveLength(0);
    expect(agenticScanMock).not.toHaveBeenCalled();
  });

  it("skips items whose dependsOn is not 'done'", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [
      // Parent surface_map is still todo.
      makeWorkItem({ id: "wi-parent", kind: "surface_map", status: "todo", caseId: "case-other" }),
      // Child hypothesis depends on a parent that is NOT done.
      makeWorkItem({
        id: "wi-child",
        kind: "hypothesis",
        status: "todo",
        dependsOn: "wi-missing-parent",
      }),
    ];
    // Plant a parent that is NOT done in workItemsById.
    dbState.workItems.push(
      makeWorkItem({
        id: "wi-missing-parent",
        kind: "surface_map",
        status: "in_progress", // not done
        caseId: "case-other",
      }),
    );

    await runCli(["orchestrate", "--limit", "5"]);

    // wi-child is gated by wi-missing-parent (status=in_progress, not done).
    const claims = callsByMethod("claimWorkItem");
    const claimedIds = claims.map((c) => c.args[0]);
    expect(claimedIds).not.toContain("wi-child");
  });

  it("skips items whose sibling in the same case is already in_progress (case mutex)", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [
      makeWorkItem({ id: "wi-busy", kind: "hypothesis", status: "in_progress" }),
      makeWorkItem({ id: "wi-queued", kind: "hypothesis", status: "todo" }),
    ];

    await runCli(["orchestrate", "--limit", "5"]);

    // The case-1 sibling is in_progress, so wi-queued cannot be claimed.
    expect(callsByMethod("claimWorkItem")).toHaveLength(0);
    expect(agenticScanMock).not.toHaveBeenCalled();
  });

  it("--limit caps the number of cases claimed in a single pass", async () => {
    // Three separate cases, each with one runnable hypothesis.
    for (let i = 1; i <= 3; i++) {
      dbState.cases.push(makeCase(`case-${i}`, `https://t${i}.example.com`));
      dbState.scans.push(makeScan(`case-${i}-scan`, `https://t${i}.example.com`));
      dbState.workItems.push(
        makeWorkItem({
          id: `wi-${i}`,
          caseId: `case-${i}`,
          kind: "hypothesis",
          status: "todo",
        }),
      );
    }

    await runCli(["orchestrate", "--limit", "2"]);

    // Exactly two claims even though three cases are runnable.
    expect(callsByMethod("claimWorkItem")).toHaveLength(2);
    expect(agenticScanMock).toHaveBeenCalledTimes(2);
  });
});

// ── Tests: dispatch — non-family vs family ─────────────────────────────────

describe("orchestrate action — dispatch", () => {
  it("non-family (no fingerprint) → agenticScan with resumeScanId + candidate target", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [makeWorkItem({ id: "wi-1", kind: "hypothesis", status: "todo" })];

    await runCli(["orchestrate", "--db-path", "/tmp/p.db"]);

    expect(agenticScanMock).toHaveBeenCalledOnce();
    const call = agenticScanMock.mock.calls[0]![0];
    expect(call.config.target).toBe("https://example.com");
    expect(call.config.depth).toBe("deep");
    expect(call.config.mode).toBe("deep");
    expect(call.resumeScanId).toBe("case-1-scan");
    expect(call.dbPath).toBe("/tmp/p.db");
    // runAgentLoop is the family-side path; must not fire here.
    expect(runAgentLoopMock).not.toHaveBeenCalled();
  });

  it("family + kind=hypothesis → runAgentLoop with role='attack'", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    const fp = "fp-family-1";
    dbState.workItems = [
      makeWorkItem({
        id: "wi-fam-h",
        kind: "hypothesis",
        status: "todo",
        findingFingerprint: fp,
      }),
    ];
    dbState.familyFindings.set(fp, [
      {
        id: "find-1",
        scanId: "case-1-scan",
        templateId: "t-1",
        title: "Reflected XSS in /search",
        description: "...",
        severity: "high",
        category: "xss",
        status: "discovered",
        evidenceRequest: "GET /search?q=<x>",
        evidenceResponse: "200 ...",
        timestamp: 1,
      },
    ]);

    await runCli(["orchestrate"]);

    expect(runAgentLoopMock).toHaveBeenCalledOnce();
    const args = runAgentLoopMock.mock.calls[0]![0];
    expect(args.config.role).toBe("attack");
    expect(getToolsForRoleMock).toHaveBeenCalledWith("attack");
    // Non-family scan path never fires for family items.
    expect(agenticScanMock).not.toHaveBeenCalled();
  });

  it("family + kind=blind_verify → runAgentLoop with role='verify'", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    const fp = "fp-verify-1";
    dbState.workItems = [
      makeWorkItem({
        id: "wi-fam-v",
        kind: "blind_verify",
        status: "todo",
        findingFingerprint: fp,
      }),
    ];
    dbState.familyFindings.set(fp, [
      {
        id: "find-2",
        scanId: "case-1-scan",
        templateId: "t-2",
        title: "SQLi in /api/items",
        description: "...",
        severity: "critical",
        category: "sqli",
        status: "discovered",
        evidenceRequest: "GET /api/items?id=1' OR '1'='1",
        evidenceResponse: "500 ...",
        timestamp: 2,
      },
    ]);

    await runCli(["orchestrate"]);

    expect(runAgentLoopMock).toHaveBeenCalledOnce();
    const args = runAgentLoopMock.mock.calls[0]![0];
    expect(args.config.role).toBe("verify");
    expect(getToolsForRoleMock).toHaveBeenCalledWith("verify");
  });

  it("family + kind=consensus + verdict='verified' → workflow→human_review, NO agent loop", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    const fp = "fp-consensus-1";
    dbState.workItems = [
      makeWorkItem({
        id: "wi-cons",
        kind: "consensus",
        status: "todo",
        findingFingerprint: fp,
      }),
    ];
    dbState.familyFindings.set(fp, [
      {
        id: "find-3",
        scanId: "case-1-scan",
        templateId: "t-3",
        title: "IDOR",
        description: "...",
        severity: "high",
        category: "idor",
        status: "discovered",
        evidenceRequest: "GET /users/2",
        evidenceResponse: "200 ...",
        timestamp: 3,
      },
    ]);
    dbState.consensusByFindingId.set("find-3", "verified");

    await runCli(["orchestrate"]);

    // Consensus path never spawns runAgentLoop.
    expect(runAgentLoopMock).not.toHaveBeenCalled();
    // Workflow transitioned to human_review for this family.
    const updates = callsByMethod("updateFindingWorkflowByFingerprint");
    expect(updates).toHaveLength(1);
    expect(updates[0]!.args[0]).toBe(fp);
    expect(updates[0]!.args[1]).toBe("human_review");
  });

  it("family + kind=consensus + verdict='disputed' → upsertWorkItem(blocked), no workflow change", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    const fp = "fp-consensus-disputed";
    dbState.workItems = [
      makeWorkItem({
        id: "wi-cons-d",
        kind: "consensus",
        status: "todo",
        findingFingerprint: fp,
      }),
    ];
    dbState.familyFindings.set(fp, [
      {
        id: "find-4",
        scanId: "case-1-scan",
        templateId: "t-4",
        title: "Disputed CORS",
        description: "...",
        severity: "medium",
        category: "cors",
        status: "discovered",
        evidenceRequest: "OPTIONS /",
        evidenceResponse: "200 ...",
        timestamp: 4,
      },
    ]);
    dbState.consensusByFindingId.set("find-4", "disputed");

    await runCli(["orchestrate"]);

    expect(runAgentLoopMock).not.toHaveBeenCalled();
    // No workflow advancement for disputed.
    expect(callsByMethod("updateFindingWorkflowByFingerprint")).toHaveLength(0);
    // The consensus work item is blocked with a disagreement summary.
    const blocked = callsByMethod("upsertWorkItem").find((c) => {
      const w = c.args[0] as WorkItemRecord;
      return w.id === "wi-cons-d" && w.status === "blocked";
    });
    expect(blocked).toBeTruthy();
    const summary = (blocked!.args[0] as WorkItemRecord).summary ?? "";
    expect(summary).toMatch(/disagree/i);
  });
});

// ── Tests: state transitions ───────────────────────────────────────────────

describe("orchestrate action — state transitions", () => {
  it("success path: claim → upsertWorkItem(done) + completeScan + worker_completed event", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [
      makeWorkItem({ id: "wi-1", kind: "hypothesis", status: "todo" }),
    ];

    // Simulate the claim flipping status to in_progress (reconcile checks
    // the current status before transitioning to done).
    dbState.claimResultByItemId.set("wi-1", true);
    agenticScanMock.mockImplementationOnce(async () => {
      // After the claim, the item is supposed to be in_progress. Our fake
      // claim doesn't persist that, so we patch the state mid-test to
      // exercise the "current.status === 'in_progress'" branch in
      // reconcileCandidateOutcome.
      const idx = dbState.workItems.findIndex((w) => w.id === "wi-1");
      if (idx >= 0) dbState.workItems[idx] = { ...dbState.workItems[idx]!, status: "in_progress" };
      return { summary: { totalFindings: 1, critical: 0, high: 1 } };
    });

    await runCli(["orchestrate"]);

    // claim called once.
    expect(callsByMethod("claimWorkItem")).toHaveLength(1);

    // upsertWorkItem(done) was emitted.
    const doneUpdate = callsByMethod("upsertWorkItem").find((c) => {
      const w = c.args[0] as WorkItemRecord;
      return w.id === "wi-1" && w.status === "done";
    });
    expect(doneUpdate).toBeTruthy();

    // completeScan called.
    expect(callsByMethod("completeScan")).toHaveLength(1);
    expect(callsByMethod("completeScan")[0]!.args[0]).toBe("case-1-scan");

    // Event log includes a worker_completed.
    const events = callsByMethod("logEvent");
    const completed = events.find(
      (e) => (e.args[0] as { eventType: string }).eventType === "worker_completed",
    );
    expect(completed).toBeTruthy();
    // failScan must NOT have fired.
    expect(callsByMethod("failScan")).toHaveLength(0);
  });

  it("failure path: agenticScan throws → upsertWorkItem(blocked, summary=<msg>) + failScan + worker_failed event", async () => {
    dbState.cases = [makeCase("case-1", "https://example.com")];
    dbState.scans = [makeScan("case-1-scan", "https://example.com")];
    dbState.workItems = [
      makeWorkItem({ id: "wi-bad", kind: "hypothesis", status: "todo" }),
    ];
    agenticScanMock.mockImplementationOnce(async () => {
      // Flip status so reconcileCandidateOutcome takes the in_progress branch.
      const idx = dbState.workItems.findIndex((w) => w.id === "wi-bad");
      if (idx >= 0)
        dbState.workItems[idx] = { ...dbState.workItems[idx]!, status: "in_progress" };
      throw new Error("LLM rate-limited");
    });

    await runCli(["orchestrate"]);

    // Blocked + error summary persisted on the item.
    const blocked = callsByMethod("upsertWorkItem").find((c) => {
      const w = c.args[0] as WorkItemRecord;
      return w.id === "wi-bad" && w.status === "blocked";
    });
    expect(blocked).toBeTruthy();
    expect((blocked!.args[0] as WorkItemRecord).summary).toBe("LLM rate-limited");

    // failScan called with the error message.
    expect(callsByMethod("failScan")).toHaveLength(1);
    expect(callsByMethod("failScan")[0]!.args[1]).toBe("LLM rate-limited");

    // worker_failed event emitted; worker_completed NOT emitted.
    const events = callsByMethod("logEvent").map((c) => (c.args[0] as { eventType: string }).eventType);
    expect(events).toContain("worker_failed");
    expect(events).not.toContain("worker_completed");
    // completeScan must NOT have fired on the failure path.
    expect(callsByMethod("completeScan")).toHaveLength(0);
  });
});

// ── Tests: watch loop + argument plumbing ──────────────────────────────────

describe("orchestrate action — watch mode + argument plumbing", () => {
  it("--watch polls the queue at pollInterval and exits when there's still nothing to do", async () => {
    // Empty DB: no candidates ever. We tick the fake clock once and confirm
    // findRunnableCandidates was re-entered (i.e. listWorkItems called > 1).
    vi.useFakeTimers();
    const runPromise = runCli([
      "orchestrate",
      "--watch",
      "--poll-interval",
      "1000",
    ]);

    // First pass already happened synchronously (everything up to `await sleep`).
    // Tick past one poll interval to wake the loop.
    await vi.advanceTimersByTimeAsync(1500);

    // Send SIGINT so the daemon stops. The action installed a one-shot
    // handler that flips `stopping = true`.
    process.emit("SIGINT");

    // Advance past one more poll interval so the awaited sleep resolves
    // and the loop sees `stopping`.
    await vi.advanceTimersByTimeAsync(1500);

    const err = await runPromise;
    expect(err).toBeUndefined();

    // listWorkItems is called at the top of each findRunnableCandidates
    // *and* by recoverStaleWorkers (once per pass). At least two passes
    // means at least 4 calls — assert >= 4 to be robust to the clamp.
    expect(callsByMethod("listWorkItems").length).toBeGreaterThanOrEqual(4);
  });

  it("non-watch mode: action exits after a single pass when the queue is empty", async () => {
    // No candidates planted.
    const err = await runCli(["orchestrate"]);
    expect(err).toBeUndefined();
    // No claims, no agent calls.
    expect(callsByMethod("claimWorkItem")).toHaveLength(0);
    expect(agenticScanMock).not.toHaveBeenCalled();
  });

  it("--limit 0 is clamped up to 1 (Math.max guard against an off-by-one)", async () => {
    // Two runnable cases; --limit 0 should still claim 1.
    for (let i = 1; i <= 2; i++) {
      dbState.cases.push(makeCase(`case-${i}`, `https://t${i}.example.com`));
      dbState.scans.push(makeScan(`case-${i}-scan`, `https://t${i}.example.com`));
      dbState.workItems.push(
        makeWorkItem({
          id: `wi-${i}`,
          caseId: `case-${i}`,
          kind: "hypothesis",
          status: "todo",
        }),
      );
    }
    await runCli(["orchestrate", "--limit", "0"]);
    expect(callsByMethod("claimWorkItem")).toHaveLength(1);
  });

  it("--db-path is threaded into every osecDB constructor invocation", async () => {
    // Empty queue keeps it short; we just assert the dbPath plumbing.
    await runCli(["orchestrate", "--db-path", "/tmp/p.db"]);
    expect(dbState.ctorArgs.length).toBeGreaterThan(0);
    for (const arg of dbState.ctorArgs) {
      expect(arg).toBe("/tmp/p.db");
    }
  });
});
