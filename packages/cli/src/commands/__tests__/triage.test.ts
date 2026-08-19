/**
 * Coverage seed for `0sec-cli`'s `triage` command — the Semgrep-style
 * false-positive memory surface. Operators run this to (a) hand-craft an
 * FP memory from an existing finding, (b) list and filter memories,
 * (c) remove a stale one, and (d) `mark-fp` a finding which both flips
 * the finding's triage status to `suppressed` and persists the memory.
 *
 * Strategy: mock the two boundaries triage.ts touches inside its actions —
 *
 *   1. `@0sec/db`'s `osecDB` (avoid opening real WASM SQLite — memory
 *      `project_db_wasm`).
 *   2. `@0sec/core`'s `MemoryStore` (avoid the second WASM open path
 *      `MemoryStore.db()` takes under the hood).
 *
 * Both modules are dynamically imported inside triage.ts (`await import(
 * "@0sec/db")`, `await import("@0sec/core")`), so vitest's hoisted
 * `vi.mock` covers both static and dynamic resolution.
 *
 * What's covered (15 tests):
 *
 *   resolveFindingByPrefix (via memory add / mark-fp):
 *     • Exact full-id match wins over prefix scan.
 *     • Unique prefix resolves to a single row.
 *     • Ambiguous prefix → action exits with stderr error, no memory written.
 *     • Unknown id → action exits with `Finding '<id>' not found.` error.
 *
 *   memory add:
 *     • Happy path: recordFp is called with the right finding + reason +
 *       default scope=target.
 *     • `--scope global` is threaded through (scopeValue stripped when
 *       MemoryStore normalizes — we just assert what we passed).
 *
 *   memory list:
 *     • Empty store prints the "No triage memories found." line.
 *     • Non-empty store prints one block per memory (id prefix in stdout).
 *     • `--scope target` filters out other scopes.
 *     • `--category xss` filters out other categories.
 *
 *   memory remove:
 *     • Missing id → exitCode=1 + red error to stderr.
 *     • Existing id → success line on stdout, no exit code set.
 *
 *   mark-fp:
 *     • Flips `updateFindingTriage(<row.id>, "suppressed", <reason>)` AND
 *       calls `recordFp` with the same reason.
 *     • `--db-path` is threaded into both the DB constructor and the
 *       MemoryStore constructor.
 *
 *   Argument validation:
 *     • `--reason` is required on `memory add` (commander rejects without it).
 *
 * Out of scope (refactor required — noted in PR body):
 *   • The internal `rowToFinding` / `openStore` / `loadFinding` helpers
 *     are not exported. We exercise them through observable side-effects
 *     (the payload threaded into the mocked MemoryStore.recordFp).
 *   • The chalk-coloured stdout is not asserted exactly — we only assert
 *     the substrings downstream parsers / relays rely on.
 *
 * Precedent (review ladder):
 *   • PR #313 — packages/cli/src/commands/__tests__/orchestrate.test.ts
 *   • PR #309 — packages/cli/src/commands/__tests__/db.test.ts
 *   • PR #307 — packages/cli/src/commands/__tests__/disclose.test.ts
 *   • PR #301 — packages/cli/src/commands/__tests__/run.test.ts +
 *               scan.test.ts (the original "seed coverage" precedent)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

// ── Module-level mocks ──────────────────────────────────────────────────────

interface FakeFindingRow {
  id: string;
  scanId: string;
  title: string;
  category: string;
  fingerprint?: string | null;
  description: string;
  severity: string;
  status: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  timestamp: number;
}

interface DbCall {
  method: string;
  args: unknown[];
}

const dbState: {
  rows: FakeFindingRow[];
  calls: DbCall[];
  ctorArgs: Array<string | undefined>;
  closed: boolean;
} = {
  rows: [],
  calls: [],
  ctorArgs: [],
  closed: false,
};

vi.mock("@0sec/db", () => {
  class FakeOsecDB {
    constructor(dbPath?: string) {
      dbState.ctorArgs.push(dbPath);
      dbState.closed = false;
    }
    listFindings(opts: { scanId?: string; limit?: number }): FakeFindingRow[] {
      dbState.calls.push({ method: "listFindings", args: [opts] });
      return dbState.rows;
    }
    updateFindingTriage(
      findingId: string,
      triageStatus: string,
      triageNote?: string,
    ): void {
      dbState.calls.push({
        method: "updateFindingTriage",
        args: [findingId, triageStatus, triageNote],
      });
    }
    close(): void {
      dbState.calls.push({ method: "close", args: [] });
      dbState.closed = true;
    }
  }
  return { osecDB: FakeOsecDB };
});

// ── MemoryStore mock (lives in @0sec/core) ────────────────────────────────

interface FakeMemory {
  id: string;
  scope: "global" | "target" | "package";
  scopeValue?: string;
  category: string;
  pattern: string;
  reasoning: string;
  createdAt: number;
  appliedCount: number;
}

interface MemoryStoreState {
  // Per-instance recorded constructor args (so we can prove --db-path plumbing).
  ctorArgs: Array<string | undefined>;
  // Returned by store.listAll().
  memories: FakeMemory[];
  // Result of store.remove(id): whether the row "existed".
  removeResultById: Map<string, boolean>;
  // Recorded recordFp / listAll / remove / close invocations.
  calls: DbCall[];
  // Next memory id minted by recordFp. Tests can plant a known id.
  nextRecordFpId: string;
}

const storeState: MemoryStoreState = {
  ctorArgs: [],
  memories: [],
  removeResultById: new Map(),
  calls: [],
  nextRecordFpId: "memid-aaaa-bbbb-cccc",
};

class FakeMemoryStore {
  constructor(dbPath?: string) {
    storeState.ctorArgs.push(dbPath);
  }
  async recordFp(
    finding: { id: string; title: string; category: string },
    reason: string,
    scope: "global" | "target" | "package",
    scopeValue?: string,
  ): Promise<FakeMemory> {
    storeState.calls.push({
      method: "recordFp",
      args: [finding, reason, scope, scopeValue],
    });
    return {
      id: storeState.nextRecordFpId,
      scope,
      scopeValue: scope === "global" ? undefined : scopeValue,
      category: finding.category,
      pattern: finding.title,
      reasoning: reason,
      createdAt: 1714521600000,
      appliedCount: 0,
    };
  }
  async listAll(): Promise<FakeMemory[]> {
    storeState.calls.push({ method: "listAll", args: [] });
    return storeState.memories;
  }
  async remove(id: string): Promise<boolean> {
    storeState.calls.push({ method: "remove", args: [id] });
    return storeState.removeResultById.get(id) ?? false;
  }
  async close(): Promise<void> {
    storeState.calls.push({ method: "close", args: [] });
  }
}

vi.mock("@0sec/core", () => ({
  MemoryStore: FakeMemoryStore,
}));

const { registerTriageCommand } = await import("../triage.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeRow(overrides: Partial<FakeFindingRow> = {}): FakeFindingRow {
  return {
    id: "f1234567abcd0000",
    scanId: "scan-0000000000000001",
    title: "Reflected XSS in search",
    category: "xss",
    fingerprint: null,
    description: "Reflected XSS via q= parameter",
    severity: "high",
    status: "discovered",
    evidenceRequest: "GET /?q=<script>",
    evidenceResponse: "200 OK <script>...",
    evidenceAnalysis: null,
    timestamp: 1714521600000,
    ...overrides,
  };
}

function makeMemory(overrides: Partial<FakeMemory> = {}): FakeMemory {
  return {
    id: "memid-default-abcdef",
    scope: "target",
    scopeValue: "https://example.com",
    category: "xss",
    pattern: "Reflected XSS in search",
    reasoning: "test reasoning",
    createdAt: 1714521600000,
    appliedCount: 0,
    ...overrides,
  };
}

function callsByMethod(method: string): DbCall[] {
  return dbState.calls.filter((c) => c.method === method);
}

function storeCallsByMethod(method: string): DbCall[] {
  return storeState.calls.filter((c) => c.method === method);
}

async function runCli(argv: string[]): Promise<unknown> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerTriageCommand(program);
  try {
    await program.parseAsync(["node", "0sec-cli", ...argv]);
    return undefined;
  } catch (err) {
    return err;
  }
}

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  dbState.rows = [];
  dbState.calls = [];
  dbState.ctorArgs = [];
  dbState.closed = false;

  storeState.ctorArgs = [];
  storeState.memories = [];
  storeState.removeResultById = new Map();
  storeState.calls = [];
  storeState.nextRecordFpId = "memid-aaaa-bbbb-cccc";

  process.exitCode = 0;

  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  process.exitCode = 0;
});

// ── Tests: resolveFindingByPrefix (via memory add / mark-fp) ───────────────

describe("triage — finding-id resolution", () => {
  it("memory add: ambiguous prefix → stderr error, no memory recorded", async () => {
    dbState.rows = [
      makeRow({ id: "f1234567abcd0000" }),
      makeRow({ id: "f1234567abcd0001" }),
    ];

    await runCli([
      "triage",
      "memory",
      "add",
      "--finding",
      "f1234567",
      "--reason",
      "vendor-known",
    ]);

    expect(process.exitCode).toBe(1);
    // ambiguous prefix message surfaced to stderr.
    const stderr = errSpy.mock.calls.flat().join("\n");
    expect(stderr).toMatch(/ambiguous/);
    // No memory ever recorded.
    expect(storeCallsByMethod("recordFp")).toHaveLength(0);
  });

  it("memory add: unknown id → 'not found' error on stderr, exitCode=1", async () => {
    dbState.rows = [makeRow({ id: "abcdef0000000001" })];

    await runCli([
      "triage",
      "memory",
      "add",
      "--finding",
      "deadbeef",
      "--reason",
      "n/a",
    ]);

    expect(process.exitCode).toBe(1);
    const stderr = errSpy.mock.calls.flat().join("\n");
    expect(stderr).toMatch(/not found/);
    expect(storeCallsByMethod("recordFp")).toHaveLength(0);
  });

  it("memory add: exact full-id match wins (does not look at prefix matches)", async () => {
    // Both rows share the same prefix; the exact-match path bypasses the
    // ambiguity check.
    dbState.rows = [
      makeRow({ id: "f1234567abcd0000", title: "exact-target" }),
      makeRow({ id: "f1234567abcd0001", title: "sibling" }),
    ];

    await runCli([
      "triage",
      "memory",
      "add",
      "--finding",
      "f1234567abcd0000",
      "--reason",
      "matches WAF rule",
    ]);

    expect(process.exitCode).toBe(0);
    const recordCalls = storeCallsByMethod("recordFp");
    expect(recordCalls).toHaveLength(1);
    const finding = recordCalls[0]!.args[0] as { id: string; title: string };
    expect(finding.id).toBe("f1234567abcd0000");
    expect(finding.title).toBe("exact-target");
  });
});

// ── Tests: memory add ──────────────────────────────────────────────────────

describe("triage memory add", () => {
  it("happy path: recordFp called with finding, reason, default scope=target", async () => {
    dbState.rows = [
      makeRow({ id: "f1234567abcd0000", title: "Reflected XSS in /search", category: "xss" }),
    ];

    await runCli([
      "triage",
      "memory",
      "add",
      "--finding",
      "f1234567",
      "--reason",
      "sanitized by WAF",
    ]);

    expect(process.exitCode).toBe(0);
    const recordCalls = storeCallsByMethod("recordFp");
    expect(recordCalls).toHaveLength(1);
    const [finding, reason, scope, scopeValue] = recordCalls[0]!.args as [
      { id: string; title: string; category: string },
      string,
      string,
      string | undefined,
    ];
    expect(finding.id).toBe("f1234567abcd0000");
    expect(finding.category).toBe("xss");
    expect(reason).toBe("sanitized by WAF");
    // Default from the option definition.
    expect(scope).toBe("target");
    expect(scopeValue).toBeUndefined();
  });

  it("--scope global + --scope-value is threaded through to recordFp", async () => {
    dbState.rows = [makeRow({ id: "f1234567abcd0000" })];

    await runCli([
      "triage",
      "memory",
      "add",
      "--finding",
      "f1234567",
      "--reason",
      "always-FP-in-this-project",
      "--scope",
      "global",
      "--scope-value",
      "ignored-for-global",
    ]);

    expect(process.exitCode).toBe(0);
    const recordCalls = storeCallsByMethod("recordFp");
    expect(recordCalls).toHaveLength(1);
    const [, , scope, scopeValue] = recordCalls[0]!.args as [
      unknown,
      string,
      string,
      string | undefined,
    ];
    expect(scope).toBe("global");
    // Triage CLI threads scopeValue through verbatim; MemoryStore is what
    // would normalize it to undefined for global scope.
    expect(scopeValue).toBe("ignored-for-global");
  });

  it("commander rejects `memory add` without --reason", async () => {
    dbState.rows = [makeRow({ id: "f1234567abcd0000" })];

    const err = await runCli([
      "triage",
      "memory",
      "add",
      "--finding",
      "f1234567",
    ]);

    // exitOverride() converts the missing-required-option into a thrown error.
    expect(err).toBeInstanceOf(Error);
    // No action body ever ran.
    expect(storeCallsByMethod("recordFp")).toHaveLength(0);
  });
});

// ── Tests: memory list ─────────────────────────────────────────────────────

describe("triage memory list", () => {
  it("empty store prints 'No triage memories found.'", async () => {
    storeState.memories = [];

    await runCli(["triage", "memory", "list"]);

    expect(process.exitCode).toBe(0);
    const stdout = logSpy.mock.calls.flat().join("\n");
    expect(stdout).toMatch(/No triage memories found/);
  });

  it("non-empty store prints one block per memory (id prefix visible)", async () => {
    storeState.memories = [
      makeMemory({ id: "mem-aaaaaaaa-1111", scope: "target", scopeValue: "https://a.example.com" }),
      makeMemory({ id: "mem-bbbbbbbb-2222", scope: "global", scopeValue: undefined }),
    ];

    await runCli(["triage", "memory", "list"]);

    expect(process.exitCode).toBe(0);
    const stdout = logSpy.mock.calls.flat().join("\n");
    // First 8 chars of each id should be in stdout (header line per memory).
    expect(stdout).toContain("mem-aaaa");
    expect(stdout).toContain("mem-bbbb");
    // Count header rendered with the filtered count.
    expect(stdout).toMatch(/triage memories \(2\)/);
  });

  it("--scope target filters out non-matching memories", async () => {
    storeState.memories = [
      makeMemory({ id: "mem-target-aaaa", scope: "target", scopeValue: "https://t.example.com" }),
      makeMemory({ id: "mem-global-bbbb", scope: "global", scopeValue: undefined }),
      makeMemory({ id: "mem-package-cccc", scope: "package", scopeValue: "lodash" }),
    ];

    await runCli(["triage", "memory", "list", "--scope", "target"]);

    const stdout = logSpy.mock.calls.flat().join("\n");
    expect(stdout).toContain("mem-targ");
    expect(stdout).not.toContain("mem-glob");
    expect(stdout).not.toContain("mem-pack");
    // Header reflects the filtered count.
    expect(stdout).toMatch(/triage memories \(1\)/);
  });

  it("--category xss filters out other categories", async () => {
    storeState.memories = [
      makeMemory({ id: "mem-xss-aaaaaa", category: "xss" }),
      makeMemory({ id: "mem-sqli-bbbbb", category: "sqli" }),
    ];

    await runCli(["triage", "memory", "list", "--category", "xss"]);

    const stdout = logSpy.mock.calls.flat().join("\n");
    expect(stdout).toContain("mem-xss-");
    expect(stdout).not.toContain("mem-sqli");
    expect(stdout).toMatch(/triage memories \(1\)/);
  });
});

// ── Tests: memory remove ───────────────────────────────────────────────────

describe("triage memory remove", () => {
  it("unknown id → exitCode=1 and red error on stderr", async () => {
    storeState.removeResultById.set("does-not-exist", false);

    await runCli(["triage", "memory", "remove", "does-not-exist"]);

    expect(process.exitCode).toBe(1);
    const stderr = errSpy.mock.calls.flat().join("\n");
    expect(stderr).toMatch(/No memory with id 'does-not-exist'/);
  });

  it("existing id → success line, no exit code set", async () => {
    storeState.removeResultById.set("mem-aaaaaaaa-1111", true);

    await runCli(["triage", "memory", "remove", "mem-aaaaaaaa-1111"]);

    expect(process.exitCode).toBe(0);
    const stdout = logSpy.mock.calls.flat().join("\n");
    expect(stdout).toMatch(/Removed memory/);
    // The "first 8 chars" id slug should appear in the line.
    expect(stdout).toContain("mem-aaaa");
  });
});

// ── Tests: mark-fp ─────────────────────────────────────────────────────────

describe("triage mark-fp", () => {
  it("flips updateFindingTriage(<row.id>, 'suppressed', <reason>) AND records memory", async () => {
    dbState.rows = [
      makeRow({ id: "f1234567abcd0000", title: "Reflected XSS", category: "xss" }),
    ];

    await runCli([
      "triage",
      "mark-fp",
      "f1234567",
      "--reason",
      "sanitised by central template",
    ]);

    expect(process.exitCode).toBe(0);

    // DB triage status flipped to suppressed with the operator's reason.
    const triageUpdates = callsByMethod("updateFindingTriage");
    expect(triageUpdates).toHaveLength(1);
    expect(triageUpdates[0]!.args[0]).toBe("f1234567abcd0000");
    expect(triageUpdates[0]!.args[1]).toBe("suppressed");
    expect(triageUpdates[0]!.args[2]).toBe("sanitised by central template");

    // Memory auto-created with the same reason.
    const recordCalls = storeCallsByMethod("recordFp");
    expect(recordCalls).toHaveLength(1);
    const [finding, reason] = recordCalls[0]!.args as [
      { id: string; category: string },
      string,
    ];
    expect(finding.id).toBe("f1234567abcd0000");
    expect(reason).toBe("sanitised by central template");
  });

  it("--db-path is threaded into osecDB AND MemoryStore constructors", async () => {
    dbState.rows = [makeRow({ id: "f1234567abcd0000" })];

    await runCli([
      "triage",
      "mark-fp",
      "f1234567",
      "--reason",
      "n/a",
      "--db-path",
      "/tmp/custom.db",
    ]);

    expect(process.exitCode).toBe(0);

    // osecDB constructed at least twice: once by loadFinding(), once by
    // the explicit `new osecDB(opts.dbPath)` in runMarkFp. Every ctorArg
    // must be the threaded path.
    expect(dbState.ctorArgs.length).toBeGreaterThanOrEqual(2);
    for (const arg of dbState.ctorArgs) {
      expect(arg).toBe("/tmp/custom.db");
    }

    // MemoryStore opened with the same path.
    expect(storeState.ctorArgs.length).toBeGreaterThanOrEqual(1);
    for (const arg of storeState.ctorArgs) {
      expect(arg).toBe("/tmp/custom.db");
    }
  });
});
