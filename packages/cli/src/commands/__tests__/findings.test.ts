/**
 * Coverage seed for `0sec-cli`'s `findings` command — the operator-facing
 * triage surface (`0sec findings`, `findings list`, `findings show <id>`,
 * `findings accept <id>`, `findings suppress <id>`, `findings reopen <id>`).
 * The file had zero tests before this seed; a regression here breaks the
 * core triage workflow that AGENTS.md documents and that the dashboard's
 * finding-family POST handlers mirror.
 *
 * Strategy: mock `@0sec/db` at the module boundary so no WASM SQLite
 * is ever opened (memory: project_db_wasm — every `new osecDB(...)`
 * path has to be intercepted) and stub the dynamic-import TUI runtime
 * so the OpenTUI fast-path is never selected during tests. Then drive
 * each subcommand through a fresh Commander program and assert on the
 * recorded DB call sequence.
 *
 * The chatty FakeOsecDB records every (method, args) tuple plus
 * constructor args so we can assert:
 *   • the right `--db-path` is threaded into every constructor,
 *   • `db.close()` always fires in `finally` (no leaked WASM handle),
 *   • triage transitions invoke `updateFindingTriage(id, status, note)`
 *     with the resolved-by-prefix finding id (not the operator's prefix),
 *   • `list` passes severity/category/status/triage/scan filters
 *     straight through to `listFindings`.
 *
 * What's covered (16 tests):
 *
 *   list:
 *     • Empty DB prints "No findings found." and never iterates.
 *     • Default (grouped) rendering — one log block per fingerprint family.
 *     • `--all` switches to raw-row rendering.
 *     • `--severity high` is threaded into listFindings filter.
 *     • `--scan <id>` is threaded as `scanId`.
 *     • `--category`, `--status`, `--triage` are threaded.
 *     • `--db-path` is threaded into the constructor.
 *
 *   show:
 *     • Resolves a finding by exact id and prints the detail block.
 *     • Resolves by unambiguous prefix.
 *     • Ambiguous prefix → process.exit(1) with a clear error.
 *     • Unknown id → process.exit(1) with a "not found" error.
 *
 *   accept / suppress / reopen (the state-transition trio):
 *     • Each calls `updateFindingTriage(resolvedId, <status>, note?)`
 *       with the right enum value ("accepted" / "suppressed" / "new").
 *     • `--note` is forwarded.
 *     • A prefix is resolved before `updateFindingTriage` fires (the
 *       DB never sees the operator's truncated id).
 *     • Unknown id throws "not found" via mutateTriage's guard.
 *     • DB is closed even when the lookup throws (finally invariant).
 *
 * Out of scope (refactor required — noted in PR body):
 *   • The OpenTUI bun-only path (`showOpenTuiFindings`) is exercised
 *     only via the runtime-probe stub returning false; we don't drive
 *     the @opentui/react render tree from a unit test.
 *   • Chalk-coloured stdout banners are not asserted byte-for-byte; we
 *     only assert the structural substrings (id, scan id, severity word,
 *     "Updated", "not found", etc.) that downstream relays would parse.
 *   • `groupFindings`, `resolveFindingByPrefix`, the colour helpers are
 *     file-internal. We exercise them through the Commander action.
 *
 * Precedent (review ladder):
 *   • PR #314 — packages/cli/src/commands/__tests__/dashboard.test.ts
 *   • PR #313 — packages/cli/src/commands/__tests__/orchestrate.test.ts
 *   • PR #309 — packages/cli/src/commands/__tests__/db.test.ts
 *   • PR #307 — packages/cli/src/commands/__tests__/disclose.test.ts
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { FindingTriageStatus } from "@0sec/shared";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// findings.ts uses `await import("@0sec/db")` per-action; vitest hoists
// vi.mock so the dynamic resolution still lands on FakeOsecDB.

interface DbCall {
  method: string;
  args: unknown[];
}

interface FakeFindingRow {
  id: string;
  scanId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  timestamp: number;
  score?: number | null;
  templateId: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
}

const dbState: {
  calls: DbCall[];
  ctorArgs: Array<string | undefined>;
  rows: FakeFindingRow[];
  // Optional: per-fingerprint family override so show's "Related" block can
  // diverge from the flat row list when needed.
  relatedByFingerprint: Map<string, FakeFindingRow[]>;
  closes: number;
  // When set, makes the next `listFindings` throw so we can prove the
  // `finally { db.close() }` invariant.
  listThrows: Error | null;
} = {
  calls: [],
  ctorArgs: [],
  rows: [],
  relatedByFingerprint: new Map(),
  closes: 0,
  listThrows: null,
};

vi.mock("@0sec/db", () => {
  class FakeOsecDB {
    constructor(dbPath?: string) {
      dbState.ctorArgs.push(dbPath);
    }
    listFindings(opts?: {
      scanId?: string;
      severity?: string;
      category?: string;
      status?: string;
      triageStatus?: string;
      limit?: number;
    }): FakeFindingRow[] {
      dbState.calls.push({ method: "listFindings", args: [opts] });
      if (dbState.listThrows) {
        const err = dbState.listThrows;
        dbState.listThrows = null;
        throw err;
      }
      let out = dbState.rows;
      if (opts?.scanId) out = out.filter((r) => r.scanId === opts.scanId);
      if (opts?.severity) out = out.filter((r) => r.severity === opts.severity);
      if (opts?.category) out = out.filter((r) => r.category === opts.category);
      if (opts?.status) out = out.filter((r) => r.status === opts.status);
      if (opts?.triageStatus) out = out.filter((r) => r.triageStatus === opts.triageStatus);
      return out;
    }
    updateFindingTriage(findingId: string, status: FindingTriageStatus, note?: string): void {
      dbState.calls.push({ method: "updateFindingTriage", args: [findingId, status, note] });
    }
    getRelatedFindings(fingerprint: string): FakeFindingRow[] {
      dbState.calls.push({ method: "getRelatedFindings", args: [fingerprint] });
      const override = dbState.relatedByFingerprint.get(fingerprint);
      if (override) return override;
      return dbState.rows.filter((r) => r.fingerprint === fingerprint);
    }
    close(): void {
      dbState.closes += 1;
      dbState.calls.push({ method: "close", args: [] });
    }
  }
  return {
    osecDB: FakeOsecDB,
    listOsecRunDatabasePaths: () => [],
    resolveOsecDbPath: () => undefined,
    resolveOsecRunStorage: () => ({ dbPath: undefined }),
  };
});

// Force the OpenTUI fast-path off so the action always lands on
// renderFindingsList. canUseOpenTui returning false is enough; isBunRuntime
// is also false under Node's vitest, but pin both to be safe.
vi.mock("../../tui/runtime.js", () => ({
  isBunRuntime: () => false,
  canUseOpenTui: () => false,
}));

const { registerFindingsCommand } = await import("../findings.js");

// ── Helpers ────────────────────────────────────────────────────────────────

async function runCli(argv: string[]): Promise<unknown> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerFindingsCommand(program);
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

function makeRow(overrides: Partial<FakeFindingRow> & { id: string }): FakeFindingRow {
  return {
    id: overrides.id,
    scanId: overrides.scanId ?? "scan-aaaaaaaaaaaaaaaa",
    title: overrides.title ?? `Finding ${overrides.id}`,
    severity: overrides.severity ?? "high",
    category: overrides.category ?? "xss",
    status: overrides.status ?? "verified",
    fingerprint: overrides.fingerprint ?? null,
    triageStatus: overrides.triageStatus ?? null,
    triageNote: overrides.triageNote ?? null,
    timestamp: overrides.timestamp ?? 1_714_521_600_000,
    score: overrides.score ?? null,
    templateId: overrides.templateId ?? "tpl-xss-reflected",
    description: overrides.description ?? "Reflected XSS via q= parameter",
    evidenceRequest: overrides.evidenceRequest ?? "GET /?q=<script>",
    evidenceResponse: overrides.evidenceResponse ?? "200 OK <script>...",
    evidenceAnalysis: overrides.evidenceAnalysis ?? null,
  };
}

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
// process.exit is typed as `(code?: number) => never`, which vitest's spyOn
// generic refuses to widen to `(...args: unknown[]) => unknown`. We hold
// the spy in `any` and only assert by re-reading process.exit through its
// (mocked) implementation behaviour — the throw is what the harness sees.
let exitSpy: ReturnType<typeof vi.spyOn> | null = null;

// When the action calls process.exit(1) we throw a tagged error instead so
// the test harness can assert on the exit and the action's finally still runs.
class ProcessExitError extends Error {
  constructor(public code: number) {
    super(`process.exit(${code})`);
    this.name = "ProcessExitError";
  }
}

beforeEach(() => {
  dbState.calls.length = 0;
  dbState.ctorArgs.length = 0;
  dbState.rows.length = 0;
  dbState.relatedByFingerprint.clear();
  dbState.closes = 0;
  dbState.listThrows = null;
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exitSpy = (vi.spyOn(process, "exit") as any).mockImplementation((code?: number) => {
    throw new ProcessExitError(code ?? 0);
  });
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  exitSpy?.mockRestore();
  exitSpy = null;
});

// ── Tests: `findings list` ──────────────────────────────────────────────────

describe("findings list — read surface", () => {
  it("empty DB prints 'No findings found.' and does not iterate", async () => {
    const err = await runCli(["findings", "list"]);
    expect(err).toBeUndefined();

    const empty = logSpy.mock.calls.find((c) => /No findings found\./.test(String(c[0])));
    expect(empty).toBeTruthy();
    // listFindings was called exactly once, close() always fires.
    expect(callsByMethod("listFindings")).toHaveLength(1);
    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("default (grouped) rendering: one block per fingerprint family", async () => {
    // Two rows sharing one fingerprint + one solo finding → 2 groups.
    dbState.rows.push(
      makeRow({ id: "a1b2c3d4e5f60001", fingerprint: "fp-shared", timestamp: 2 }),
      makeRow({ id: "a1b2c3d4e5f60002", fingerprint: "fp-shared", timestamp: 3 }),
      makeRow({ id: "ffffffffffff0000", fingerprint: null, severity: "medium" }),
    );

    const err = await runCli(["findings", "list"]);
    expect(err).toBeUndefined();

    // Header should mention "finding groups (2)" — two distinct fingerprints.
    const header = logSpy.mock.calls.find((c) => /finding groups \(2\)/.test(String(c[0])));
    expect(header).toBeTruthy();
    // close() always fires.
    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("--all on the parent action switches to raw-row rendering", async () => {
    dbState.rows.push(
      makeRow({ id: "row-1", fingerprint: "fp-shared" }),
      makeRow({ id: "row-2", fingerprint: "fp-shared" }),
    );
    const err = await runCli(["findings", "--all"]);
    expect(err).toBeUndefined();

    const allOutput = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(allOutput).not.toMatch(/finding groups/);
    // Raw rendering: both row ids should appear (one block per row).
    expect(allOutput).toContain("row-1");
    expect(allOutput).toContain("row-2");
  });

  // Regression for #325: `--all` used to be declared on both the parent
  // and the `list` subcommand. Commander merged them as
  // `{...inherited, ...local, ...opts}` so the subcommand's default-false
  // clobbered the parent's parsed-true and `findings list --all` silently
  // returned the grouped view. After the fix, `--all` is declared only on
  // the parent and the merge resolves cleanly regardless of position.
  it("--all is honoured on the `list` subcommand (regression #325)", async () => {
    dbState.rows.push(
      makeRow({ id: "row-pending-1", fingerprint: "fp-a", triageStatus: null }),
      makeRow({ id: "row-pending-2", fingerprint: "fp-b", triageStatus: null }),
      makeRow({ id: "row-accepted", fingerprint: "fp-c", triageStatus: "accepted" }),
      makeRow({ id: "row-suppressed", fingerprint: "fp-d", triageStatus: "suppressed" }),
    );

    const err = await runCli(["findings", "list", "--all"]);
    expect(err).toBeUndefined();

    const allOutput = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    // Raw row rendering: header says "findings (N)" not "finding groups (N)".
    expect(allOutput).not.toMatch(/finding groups/);
    expect(allOutput).toMatch(/findings \(4\)/);
    // All four ids should appear in raw mode.
    expect(allOutput).toContain("row-pending-1");
    expect(allOutput).toContain("row-pending-2");
    expect(allOutput).toContain("row-accepted");
    expect(allOutput).toContain("row-suppressed");
  });

  it("without --all the `list` subcommand renders grouped (regression #325 baseline)", async () => {
    dbState.rows.push(
      makeRow({ id: "row-pending-1", fingerprint: "fp-a", triageStatus: null }),
      makeRow({ id: "row-pending-2", fingerprint: "fp-b", triageStatus: null }),
    );

    const err = await runCli(["findings", "list"]);
    expect(err).toBeUndefined();

    const allOutput = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(allOutput).toMatch(/finding groups \(2\)/);
    expect(allOutput).not.toMatch(/findings \(2\)/);
  });

  it("--all works with the leading-flag form (`findings --all list`) too", async () => {
    dbState.rows.push(makeRow({ id: "row-leading" }));
    const err = await runCli(["findings", "--all", "list"]);
    expect(err).toBeUndefined();

    const allOutput = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(allOutput).not.toMatch(/finding groups/);
    expect(allOutput).toContain("row-leading");
  });

  it("--limit works with the leading-flag form (`findings --limit 1 list`)", async () => {
    dbState.rows.push(
      makeRow({ id: "row-limit-1", fingerprint: "fp-limit-1" }),
      makeRow({ id: "row-limit-2", fingerprint: "fp-limit-2" }),
    );

    const err = await runCli(["findings", "--limit", "1", "list"]);
    expect(err).toBeUndefined();

    const allOutput = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(allOutput).toContain("row-limit-1");
    expect(allOutput).not.toContain("row-limit-2");
  });

  it("--severity / --scan / --category / --status / --triage are threaded into listFindings", async () => {
    const err = await runCli([
      "findings",
      "list",
      "--severity",
      "high",
      "--scan",
      "scan-xyz",
      "--category",
      "sqli",
      "--status",
      "verified",
      "--triage",
      "accepted",
    ]);
    expect(err).toBeUndefined();

    const listCalls = callsByMethod("listFindings");
    expect(listCalls).toHaveLength(1);
    const opts = listCalls[0]!.args[0] as Record<string, unknown>;
    expect(opts.severity).toBe("high");
    expect(opts.scanId).toBe("scan-xyz");
    expect(opts.category).toBe("sqli");
    expect(opts.status).toBe("verified");
    expect(opts.triageStatus).toBe("accepted");
  });

  it("--db-path is threaded into the osecDB constructor", async () => {
    const err = await runCli(["findings", "list", "--db-path", "/tmp/p.db"]);
    expect(err).toBeUndefined();
    expect(dbState.ctorArgs).toEqual(["/tmp/p.db"]);
  });

  it("default action (no subcommand) renders the list view too", async () => {
    // `0sec findings` (no `list`) should hit the parent action, which
    // also routes to renderFindingsList when OpenTUI is unavailable.
    dbState.rows.push(makeRow({ id: "row-a" }));
    const err = await runCli(["findings"]);
    expect(err).toBeUndefined();
    expect(callsByMethod("listFindings")).toHaveLength(1);
    expect(callsByMethod("close")).toHaveLength(1);
  });
});

// ── Tests: `findings show <id>` ─────────────────────────────────────────────

describe("findings show — detail view", () => {
  it("resolves a finding by exact id and prints the detail block", async () => {
    const id = "deadbeefcafe0001";
    dbState.rows.push(
      makeRow({ id, title: "Reflected XSS in /search", severity: "critical", score: 87 }),
    );

    const err = await runCli(["findings", "show", id]);
    expect(err).toBeUndefined();

    // The detail block leads with title; the id appears verbatim in the
    // "ID:" line; score is printed when non-null.
    const titleLine = logSpy.mock.calls.find((c) =>
      /Reflected XSS in \/search/.test(String(c[0])),
    );
    const idLine = logSpy.mock.calls.find((c) => String(c[0]).includes(id));
    const scoreLine = logSpy.mock.calls.find((c) => /87\/100/.test(String(c[0])));
    expect(titleLine).toBeTruthy();
    expect(idLine).toBeTruthy();
    expect(scoreLine).toBeTruthy();

    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("resolves by unambiguous prefix", async () => {
    const full = "feedfacedeadbeef";
    dbState.rows.push(makeRow({ id: full, title: "Unique prefix target" }));
    const err = await runCli(["findings", "show", "feedface"]);
    expect(err).toBeUndefined();
    const titleLine = logSpy.mock.calls.find((c) =>
      /Unique prefix target/.test(String(c[0])),
    );
    expect(titleLine).toBeTruthy();
  });

  it("ambiguous prefix → process.exit(1) with a clear error and close still fires", async () => {
    dbState.rows.push(
      makeRow({ id: "abc1230000000001" }),
      makeRow({ id: "abc1230000000002" }),
    );

    const err = await runCli(["findings", "show", "abc123"]);
    // The action catches the throw and logs+exits; the harness sees the
    // ProcessExitError surfaced through exitSpy.
    expect(err).toBeInstanceOf(ProcessExitError);
    expect((err as ProcessExitError).code).toBe(1);

    // Error message routed through console.error.
    const ambiguous = errSpy.mock.calls.find((c) =>
      /ambiguous/i.test(String(c[0])),
    );
    expect(ambiguous).toBeTruthy();
    // close() still ran (finally invariant).
    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("unknown id → process.exit(1) with 'not found'", async () => {
    dbState.rows.push(makeRow({ id: "1111111111111111" }));
    const err = await runCli(["findings", "show", "no-such-id"]);
    expect(err).toBeInstanceOf(ProcessExitError);

    const notFound = errSpy.mock.calls.find((c) => /not found/i.test(String(c[0])));
    expect(notFound).toBeTruthy();
    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("renders Related Findings section when the family has siblings", async () => {
    const id = "aaaa11112222bbbb";
    const fp = "fp-related";
    dbState.rows.push(makeRow({ id, fingerprint: fp }));
    dbState.relatedByFingerprint.set(fp, [
      makeRow({ id, fingerprint: fp }),
      makeRow({ id: "aaaa11112222cccc", fingerprint: fp, scanId: "scan-bbbbbbbbbbbbbbbb" }),
    ]);

    const err = await runCli(["findings", "show", id]);
    expect(err).toBeUndefined();

    const related = logSpy.mock.calls.find((c) =>
      /Related Findings/.test(String(c[0])),
    );
    expect(related).toBeTruthy();
    // getRelatedFindings was actually invoked with the fingerprint.
    const calls = callsByMethod("getRelatedFindings");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.args[0]).toBe(fp);
  });

  it("threads parent-position --db-path into show", async () => {
    const id = "dbpathshow000001";
    dbState.rows.push(makeRow({ id }));

    const err = await runCli(["findings", "--db-path", "/tmp/show.db", "show", id]);
    expect(err).toBeUndefined();
    expect(dbState.ctorArgs).toEqual(["/tmp/show.db"]);
  });
});

// ── Tests: `findings accept` / `suppress` / `reopen` (the triage trio) ──────

describe("findings accept/suppress/reopen — triage transitions", () => {
  it("accept calls updateFindingTriage(resolvedId, 'accepted', note)", async () => {
    const id = "1111aaaa2222bbbb";
    dbState.rows.push(makeRow({ id, fingerprint: "fp-accept" }));

    const err = await runCli([
      "findings",
      "accept",
      "1111aaaa", // prefix
      "--note",
      "looked legit",
    ]);
    expect(err).toBeUndefined();

    const calls = callsByMethod("updateFindingTriage");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.args).toEqual([id, "accepted", "looked legit"]);
  });

  it("suppress calls updateFindingTriage with 'suppressed'", async () => {
    const id = "ccccddddeeeeffff";
    dbState.rows.push(makeRow({ id, fingerprint: "fp-suppress" }));
    const err = await runCli(["findings", "suppress", id, "--note", "duplicate of #42"]);
    expect(err).toBeUndefined();

    const calls = callsByMethod("updateFindingTriage");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.args).toEqual([id, "suppressed", "duplicate of #42"]);
  });

  it("reopen calls updateFindingTriage with 'new' (note optional, undefined when omitted)", async () => {
    const id = "9999888877776666";
    dbState.rows.push(makeRow({ id }));
    const err = await runCli(["findings", "reopen", id]);
    expect(err).toBeUndefined();

    const calls = callsByMethod("updateFindingTriage");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.args[0]).toBe(id);
    expect(calls[0]!.args[1]).toBe("new");
    expect(calls[0]!.args[2]).toBeUndefined();
  });

  it("triage resolves the prefix before calling updateFindingTriage (DB never sees the truncated id)", async () => {
    const id = "abcd1234efgh5678";
    dbState.rows.push(makeRow({ id, fingerprint: "fp-prefix" }));
    const err = await runCli(["findings", "accept", "abcd1234"]);
    expect(err).toBeUndefined();

    const calls = callsByMethod("updateFindingTriage");
    expect(calls).toHaveLength(1);
    // Critical: the first arg is the resolved full id, NOT the operator prefix.
    expect(calls[0]!.args[0]).toBe(id);
    expect(calls[0]!.args[0]).not.toBe("abcd1234");
  });

  it("triage on an unknown id throws 'not found' and still closes the DB", async () => {
    dbState.rows.push(makeRow({ id: "1234567890abcdef" }));
    const err = await runCli(["findings", "accept", "no-such-id"]);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/not found/i);
    // No update fired …
    expect(callsByMethod("updateFindingTriage")).toHaveLength(0);
    // … but close() still ran via finally.
    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("triage on an ambiguous prefix throws 'ambiguous' and closes the DB", async () => {
    dbState.rows.push(
      makeRow({ id: "deadbeef00000001" }),
      makeRow({ id: "deadbeef00000002" }),
    );
    const err = await runCli(["findings", "suppress", "deadbeef"]);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/ambiguous/i);
    expect(callsByMethod("updateFindingTriage")).toHaveLength(0);
    expect(callsByMethod("close")).toHaveLength(1);
  });

  it("triage updates the whole family: success log reports related count", async () => {
    const id = "11112222aaaa0001";
    const fp = "fp-family";
    dbState.rows.push(
      makeRow({ id, fingerprint: fp }),
      makeRow({ id: "11112222aaaa0002", fingerprint: fp }),
      makeRow({ id: "11112222aaaa0003", fingerprint: fp }),
    );
    const err = await runCli(["findings", "accept", id]);
    expect(err).toBeUndefined();

    // The CLI prints "Updated <N> findings in family ..." — N = related rows.
    const updateLog = logSpy.mock.calls.find((c) =>
      /Updated.*findings in family/.test(String(c[0])),
    );
    expect(updateLog).toBeTruthy();
    expect(String(updateLog![0])).toMatch(/3/);
  });

  it("triage logs the family fingerprint prefix in the success line", async () => {
    const id = "ccccaaaadddd1111";
    const fp = "fp-success-banner-1234";
    dbState.rows.push(makeRow({ id, fingerprint: fp }));
    const err = await runCli(["findings", "suppress", id]);
    expect(err).toBeUndefined();

    // Source slices the fingerprint to 10 chars in the success banner —
    // we assert on the visible prefix so any regression in the formatter
    // (e.g. dropping the fp display) is caught.
    const banner = logSpy.mock.calls.find((c) =>
      String(c[0]).includes("fp:fp-success"),
    );
    expect(banner).toBeTruthy();
    // The banner records the new triage status verbatim.
    expect(String(banner![0])).toContain("suppressed");
  });

  // Regression for #324: parent and subcommand both declared --db-path, so
  // Commander bound the parsed value to the parent's opts. The triage
  // handlers were reading `opts.dbPath` off the subcommand (always
  // undefined) and silently falling through to ~/.0sec/0sec.db.
  // After the fix, the value threads into the osecDB constructor whether
  // it's placed after the subcommand or after the parent.
  it("accept threads --db-path placed after the subcommand into the DB constructor (regression #324)", async () => {
    const id = "1111aaaa2222bbbb";
    dbState.rows.push(makeRow({ id, fingerprint: "fp-accept-dbpath" }));

    const err = await runCli(["findings", "accept", id, "--db-path", "/tmp/accept.db"]);
    expect(err).toBeUndefined();

    // Both reads (listFindings lookup + updateFindingTriage) use the same DB
    // handle, so a single constructor call with the right path is enough.
    expect(dbState.ctorArgs).toEqual(["/tmp/accept.db"]);
    expect(callsByMethod("updateFindingTriage")).toHaveLength(1);
  });

  it("suppress threads --db-path into the DB constructor (regression #324)", async () => {
    const id = "ccccddddeeeeffff";
    dbState.rows.push(makeRow({ id, fingerprint: "fp-suppress-dbpath" }));

    const err = await runCli(["findings", "suppress", id, "--db-path", "/tmp/suppress.db"]);
    expect(err).toBeUndefined();

    expect(dbState.ctorArgs).toEqual(["/tmp/suppress.db"]);
    expect(callsByMethod("updateFindingTriage")).toHaveLength(1);
  });

  it("reopen threads --db-path into the DB constructor (regression #324)", async () => {
    const id = "9999888877776666";
    dbState.rows.push(makeRow({ id }));

    const err = await runCli(["findings", "reopen", id, "--db-path", "/tmp/reopen.db"]);
    expect(err).toBeUndefined();

    expect(dbState.ctorArgs).toEqual(["/tmp/reopen.db"]);
    expect(callsByMethod("updateFindingTriage")).toHaveLength(1);
  });

  it("accept honours --db-path placed before the subcommand (parent-position form, regression #324)", async () => {
    const id = "abcdef0011223344";
    dbState.rows.push(makeRow({ id }));

    // `0sec findings --db-path /tmp/parent.db accept <id>` — the
    // parent-position form Commander binds to the parent opts. The
    // subcommand action must still resolve it.
    const err = await runCli(["findings", "--db-path", "/tmp/parent.db", "accept", id]);
    expect(err).toBeUndefined();

    expect(dbState.ctorArgs).toEqual(["/tmp/parent.db"]);
    expect(callsByMethod("updateFindingTriage")).toHaveLength(1);
  });

  it("triage with --note still forwards the note alongside the resolved --db-path", async () => {
    const id = "fedcba9988776655";
    dbState.rows.push(makeRow({ id }));

    const err = await runCli([
      "findings",
      "accept",
      id,
      "--db-path",
      "/tmp/note-and-db.db",
      "--note",
      "verified manually",
    ]);
    expect(err).toBeUndefined();

    expect(dbState.ctorArgs).toEqual(["/tmp/note-and-db.db"]);
    const updates = callsByMethod("updateFindingTriage");
    expect(updates).toHaveLength(1);
    expect(updates[0]!.args).toEqual([id, "accepted", "verified manually"]);
  });
});
