/**
 * Coverage seed for `0sec-cli`'s `disclose` command. This is the H1
 * disclosure pipeline — the place where 0sec drafts advisories from
 * findings, runs the filing-state gate (decideFilingState), and writes
 * the bundle (INDEX.md + advisories + _dropped/). The CLI side had zero
 * tests prior to this seed; a bug here ships bad advisories to external
 * programs.
 *
 * Strategy: mock the `@0sec/core` boundary (renderers, canary, poc-runtime,
 * bundle helpers) AND the `@0sec/db` boundary (so we never open SQLite),
 * register the command on a fresh Commander program, and `parseAsync` the
 * argv the operator would type. We assert on:
 *
 *   • The H1-readiness gate: `discovered` and `false-positive` rows MUST
 *     be filtered out in batch mode (AGENTS.md "/disclose pipeline").
 *   • The `--severity-floor` filter (drops below-floor rows).
 *   • Validation paths: `--target-timeout-ms`, `--reverify-rps`,
 *     `--reverify` without `--target-url`, malformed `--target-env`.
 *   • The `--keep-unrun` override threaded through to `decideFilingState`.
 *   • `--scope-allowlist` parsing (comma-split, trim, drop empty).
 *   • Single-finding mode bypasses the status filter (operator-confirmed
 *     workflow — load-bearing for "I want to draft this `discovered` one
 *     by hand" use case).
 *
 * Out of scope (refactor required — noted in PR body):
 *   • The internal `rowToFinding` / `parseTargetEnv` / `resolveOutputDir`
 *     helpers are not exported. We exercise them through observable
 *     side-effects (the call payload threaded into mocked core helpers).
 *   • The actual filesystem writes (advisory MD, INDEX, _dropped/) are
 *     covered by `packages/core/src/disclose/bundle.test.ts` —
 *     here we use `--dry-run` so the test stays hermetic.
 *   • Behavioural-reverify (executePocSteps) and canary (verifyAgainstRef)
 *     have their own core-side tests; here we just stub them out and
 *     check the CLI threads inputs through.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { Finding } from "@0sec/shared";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// `disclose.ts` does `await import("@0sec/db")` inside the action — vitest
// hoists `vi.mock` so the dynamic import also resolves to our stub.

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
  templateId: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  cvssVector?: string | null;
  cvssScore?: number | null;
  pocSteps?: string | null;
}

const dbState: {
  rows: FakeFindingRow[];
  closed: boolean;
  saveCalls: Array<{ id: string; report: unknown }>;
} = { rows: [], closed: false, saveCalls: [] };

vi.mock("@0sec/db", () => {
  class FakeOsecDB {
    constructor(_dbPath?: string) {
      dbState.closed = false;
    }
    listFindings(_opts: { scanId?: string; limit?: number }): FakeFindingRow[] {
      return dbState.rows;
    }
    saveFindingPocExecution(id: string, report: unknown): void {
      dbState.saveCalls.push({ id, report });
    }
    close(): void {
      dbState.closed = true;
    }
  }
  return { osecDB: FakeOsecDB };
});

// ── Core mocks ──────────────────────────────────────────────────────────────

const renderAdvisoryMarkdownMock = vi.fn();
const renderExploitScreenshotMock = vi.fn();
const isFreezeAvailableMock = vi.fn();
const verifyAgainstRefMock = vi.fn();
const detectVersionRangeMock = vi.fn();
const extractSiblingFixMock = vi.fn();
const executePocStepsMock = vi.fn();
const decideFilingStateMock = vi.fn();
const assembleBundleIndexMock = vi.fn();
const formatDroppedReasonMock = vi.fn();
const droppedFilenameMock = vi.fn();

class FakeEmptyPocError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "EmptyPocError";
  }
}

vi.mock("@0sec/core", () => ({
  renderAdvisoryMarkdown: renderAdvisoryMarkdownMock,
  renderExploitScreenshot: renderExploitScreenshotMock,
  isFreezeAvailable: isFreezeAvailableMock,
  verifyAgainstRef: verifyAgainstRefMock,
  detectVersionRange: detectVersionRangeMock,
  extractSiblingFix: extractSiblingFixMock,
  executePocSteps: executePocStepsMock,
  EmptyPocError: FakeEmptyPocError,
  decideFilingState: decideFilingStateMock,
  assembleBundleIndex: assembleBundleIndexMock,
  formatDroppedReason: formatDroppedReasonMock,
  droppedFilename: droppedFilenameMock,
}));

const { registerDiscloseCommand } = await import("../disclose.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeRow(overrides: Partial<FakeFindingRow> = {}): FakeFindingRow {
  return {
    id: "f1234567abcd0000",
    scanId: "scan-0000000000000001",
    title: "Reflected XSS in search",
    severity: "high",
    category: "xss",
    status: "verified",
    fingerprint: null,
    triageStatus: null,
    triageNote: null,
    timestamp: 1714521600000,
    templateId: "tpl-xss-reflected",
    description: "Reflected XSS via q= parameter",
    evidenceRequest: "GET /?q=<script>",
    evidenceResponse: "200 OK <script>...",
    evidenceAnalysis: null,
    cvssVector: null,
    cvssScore: null,
    pocSteps: null,
    ...overrides,
  };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerDiscloseCommand(program);
  try {
    await program.parseAsync(["node", "0sec-cli", ...argv]);
  } catch {
    // Commander throws on usage error; the action throws on validation
    // failures (which then surfaces as an unhandled rejection in
    // parseAsync). Either way: we want to inspect stdout/stderr after.
  }
}

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  dbState.rows = [];
  dbState.closed = false;
  dbState.saveCalls = [];

  renderAdvisoryMarkdownMock.mockReset().mockReturnValue({
    filename: "f1234567-xss.md",
    markdown: "# Advisory",
    primaryCwe: "CWE-79",
    cvssScore: 7.5,
  });
  renderExploitScreenshotMock.mockReset().mockReturnValue(null);
  isFreezeAvailableMock.mockReset().mockReturnValue(false);
  verifyAgainstRefMock.mockReset();
  detectVersionRangeMock.mockReset();
  extractSiblingFixMock.mockReset().mockReturnValue(null);
  executePocStepsMock.mockReset();
  decideFilingStateMock.mockReset().mockReturnValue({ filingState: "keep" });
  assembleBundleIndexMock.mockReset().mockReturnValue("# INDEX\n");
  formatDroppedReasonMock.mockReset().mockReturnValue("# dropped\n");
  droppedFilenameMock.mockReset().mockImplementation(
    (entry: { finding: Finding; patchStatus?: string; behaviouralVerdict?: string }) =>
      `${entry.finding.id.slice(0, 8)}-${entry.finding.severity}-${entry.patchStatus ?? entry.behaviouralVerdict ?? "dropped"}.md`,
  );

  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  warnSpy.mockRestore();
});

// ── Tests ───────────────────────────────────────────────────────────────────

describe("disclose — H1-readiness gate (AGENTS.md /disclose pipeline)", () => {
  it("batch mode: filters out `discovered` rows (LLM-hypothesised, not agent-confirmed)", async () => {
    dbState.rows = [
      makeRow({ id: "d0000000aaaa", status: "discovered" }),
      makeRow({ id: "v1111111bbbb", status: "verified" }),
    ];
    await runCli(["disclose", "--dry-run"]);
    // Only the verified row should reach the renderer.
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledOnce();
    const finding = renderAdvisoryMarkdownMock.mock.calls[0]![0] as Finding;
    expect(finding.id).toBe("v1111111bbbb");
    expect(finding.status).toBe("verified");
  });

  it("batch mode: filters out `false-positive` rows (explicitly rejected)", async () => {
    dbState.rows = [
      makeRow({ id: "fp00000ccc", status: "false-positive" }),
      makeRow({ id: "v11111dddd", status: "confirmed" }),
    ];
    await runCli(["disclose", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledOnce();
    const finding = renderAdvisoryMarkdownMock.mock.calls[0]![0] as Finding;
    expect(finding.id).toBe("v11111dddd");
  });

  it("batch mode: filters out triageStatus=suppressed rows", async () => {
    dbState.rows = [
      makeRow({ id: "s0000000eeee", status: "verified", triageStatus: "suppressed" }),
      makeRow({ id: "v1111111ffff", status: "verified" }),
    ];
    await runCli(["disclose", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledOnce();
    const finding = renderAdvisoryMarkdownMock.mock.calls[0]![0] as Finding;
    expect(finding.id).toBe("v1111111ffff");
  });

  it("batch mode: filters out rows below --severity-floor", async () => {
    dbState.rows = [
      makeRow({ id: "low00000aaaa", severity: "low", status: "verified" }),
      makeRow({ id: "med00000bbbb", severity: "medium", status: "verified" }),
      makeRow({ id: "hi000000cccc", severity: "high", status: "verified" }),
    ];
    await runCli(["disclose", "--severity-floor", "high", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledOnce();
    const finding = renderAdvisoryMarkdownMock.mock.calls[0]![0] as Finding;
    expect(finding.severity).toBe("high");
  });

  it("single-finding mode bypasses the status filter (operator-confirmed workflow)", async () => {
    // `discovered` row passed by ID prefix should still be drafted —
    // single-finding mode is the explicit-opt-in path per the gate's
    // commentary in disclose.ts.
    dbState.rows = [makeRow({ id: "deadbeefcafef00d", status: "discovered" })];
    await runCli(["disclose", "deadbeef", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledOnce();
    const finding = renderAdvisoryMarkdownMock.mock.calls[0]![0] as Finding;
    expect(finding.id).toBe("deadbeefcafef00d");
  });

  it("empty DB: emits 'No findings' message and exits clean (no renderer calls)", async () => {
    dbState.rows = [];
    await runCli(["disclose", "--dry-run"]);
    const out = logSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
    expect(out).toMatch(/No findings/i);
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
  });

  it("all rows filtered: emits 'No findings at or above severity ...' message", async () => {
    dbState.rows = [makeRow({ severity: "low", status: "verified" })];
    await runCli(["disclose", "--severity-floor", "high", "--dry-run"]);
    const out = logSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
    expect(out).toMatch(/No findings at or above severity 'high'/);
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
  });
});

describe("disclose — single-finding lookup", () => {
  it("exact ID match is preferred over prefix matches", async () => {
    dbState.rows = [
      makeRow({ id: "abc12345" }),
      makeRow({ id: "abc12345f00d" }),
    ];
    await runCli(["disclose", "abc12345", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledOnce();
    const finding = renderAdvisoryMarkdownMock.mock.calls[0]![0] as Finding;
    expect(finding.id).toBe("abc12345");
  });

  it("ambiguous prefix throws (and does not call the renderer)", async () => {
    dbState.rows = [
      makeRow({ id: "abc12345aaaa" }),
      makeRow({ id: "abc12345bbbb" }),
    ];
    await runCli(["disclose", "abc1234", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
    // Commander surfaces the throw via .parseAsync — we don't assert
    // exit code (exitOverride throws), only that we never advanced.
  });

  it("unknown ID throws (and does not call the renderer)", async () => {
    dbState.rows = [makeRow({ id: "abc12345aaaa" })];
    await runCli(["disclose", "deadbeef", "--dry-run"]);
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
  });
});

describe("disclose — argument validation", () => {
  beforeEach(() => {
    dbState.rows = [makeRow()];
  });

  it("rejects --reverify without --target-url", async () => {
    await runCli(["disclose", "--reverify", "--dry-run"]);
    // The renderer should never be reached.
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
    // executePocSteps should never be reached either.
    expect(executePocStepsMock).not.toHaveBeenCalled();
  });

  it("rejects malformed --target-env (missing '=')", async () => {
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3000",
      "--target-env",
      "JUSTAKEY",
      "--dry-run",
    ]);
    expect(executePocStepsMock).not.toHaveBeenCalled();
  });

  it("rejects --target-timeout-ms when non-positive", async () => {
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3000",
      "--target-timeout-ms",
      "0",
      "--dry-run",
    ]);
    expect(executePocStepsMock).not.toHaveBeenCalled();
  });

  it("rejects --reverify-rps when non-positive", async () => {
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3000",
      "--reverify-rps",
      "-1",
      "--dry-run",
    ]);
    expect(executePocStepsMock).not.toHaveBeenCalled();
  });

  it("rejects --reverify-rps when non-numeric", async () => {
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3000",
      "--reverify-rps",
      "fast",
      "--dry-run",
    ]);
    expect(executePocStepsMock).not.toHaveBeenCalled();
  });
});

describe("disclose — filing-state gate threading", () => {
  it("threads --keep-unrun=true through to decideFilingState", async () => {
    dbState.rows = [makeRow()];
    await runCli(["disclose", "--keep-unrun", "--dry-run"]);
    expect(decideFilingStateMock).toHaveBeenCalled();
    const inputs = decideFilingStateMock.mock.calls[0]![0];
    expect(inputs.keepUnrun).toBe(true);
  });

  it("threads --drop-fixed=true through to decideFilingState", async () => {
    dbState.rows = [makeRow()];
    await runCli(["disclose", "--drop-fixed", "--dry-run"]);
    expect(decideFilingStateMock).toHaveBeenCalled();
    const inputs = decideFilingStateMock.mock.calls[0]![0];
    expect(inputs.dropFixed).toBe(true);
  });

  it("defaults --keep-unrun and --drop-fixed to false", async () => {
    dbState.rows = [makeRow()];
    await runCli(["disclose", "--dry-run"]);
    const inputs = decideFilingStateMock.mock.calls[0]![0];
    expect(inputs.keepUnrun).toBe(false);
    expect(inputs.dropFixed).toBe(false);
  });

  it("filingState='drop' routes through dropped path, skipping the renderer", async () => {
    dbState.rows = [makeRow()];
    decideFilingStateMock.mockReturnValueOnce({
      filingState: "drop",
      dropReason: "behavioural reverify: exploit_broken",
    });
    await runCli(["disclose", "--dry-run"]);
    // When filingState=drop, renderAdvisoryMarkdown is NOT called for that
    // row — the loop `continue`s after routeDroppedFinding.
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
  });

  it("EmptyPocError from renderer routes the finding to dropped with emptyPoc=true", async () => {
    dbState.rows = [makeRow()];
    decideFilingStateMock.mockReturnValue({ filingState: "keep" });
    renderAdvisoryMarkdownMock.mockImplementationOnce(() => {
      throw new FakeEmptyPocError("no PoC content");
    });
    await runCli(["disclose", "--dry-run"]);
    // decideFilingState is called twice for an empty-PoC row: once for the
    // initial keep/drop decision, then again with emptyPoc=true from the
    // catch block — that second call drives the routeDroppedFinding shape.
    expect(decideFilingStateMock).toHaveBeenCalledTimes(2);
    const secondCall = decideFilingStateMock.mock.calls[1]![0];
    expect(secondCall.emptyPoc).toBe(true);
  });
});

describe("disclose — wiring sanity", () => {
  it("closes the database in the finally block (no leaked handle)", async () => {
    dbState.rows = [makeRow()];
    await runCli(["disclose", "--dry-run"]);
    expect(dbState.closed).toBe(true);
  });

  it("closes the database even when the loop short-circuits on empty DB", async () => {
    dbState.rows = [];
    await runCli(["disclose", "--dry-run"]);
    expect(dbState.closed).toBe(true);
  });

  it("passes --scope-allowlist as a host array to executePocSteps", async () => {
    dbState.rows = [
      makeRow({
        pocSteps: JSON.stringify([
          {
            id: "s1",
            kind: "exploit",
            summary: "fetch",
            action: { type: "http", method: "GET", url: "/" },
          },
        ]),
      }),
    ];
    executePocStepsMock.mockResolvedValueOnce({
      findingId: "x",
      startedAt: "2026-05-13T00:00:00.000Z",
      endedAt: "2026-05-13T00:00:00.001Z",
      steps: [],
      overallVerdict: "exploit_still_works",
    });
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3108",
      "--scope-allowlist",
      "example.com, *.example.org , ",
      "--dry-run",
    ]);
    expect(executePocStepsMock).toHaveBeenCalledOnce();
    const target = executePocStepsMock.mock.calls[0]![1];
    expect(target.scopeAllowlist).toEqual(["example.com", "*.example.org"]);
    expect(target.baseUrl).toBe("http://localhost:3108");
    expect(target.allowProcessActions).toBe(false);
  });

  it("passes --reverify-rps through as rpsPerHost on the PocExecutionTarget", async () => {
    dbState.rows = [
      makeRow({
        pocSteps: JSON.stringify([
          {
            id: "s1",
            kind: "exploit",
            summary: "fetch",
            action: { type: "http", method: "GET", url: "/" },
          },
        ]),
      }),
    ];
    executePocStepsMock.mockResolvedValueOnce({
      findingId: "x",
      startedAt: "2026-05-13T00:00:00.000Z",
      endedAt: "2026-05-13T00:00:00.001Z",
      steps: [],
      overallVerdict: "exploit_still_works",
    });
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3108",
      "--reverify-rps",
      "3",
      "--dry-run",
    ]);
    expect(executePocStepsMock).toHaveBeenCalledOnce();
    const target = executePocStepsMock.mock.calls[0]![1];
    expect(target.rpsPerHost).toBe(3);
  });

  it("passes repeated --target-env KEY=VAL into the PocExecutionTarget env map", async () => {
    dbState.rows = [
      makeRow({
        pocSteps: JSON.stringify([
          {
            id: "s1",
            kind: "exploit",
            summary: "shell",
            action: { type: "shell", cmd: "env" },
          },
        ]),
      }),
    ];
    executePocStepsMock.mockResolvedValueOnce({
      findingId: "x",
      startedAt: "2026-05-13T00:00:00.000Z",
      endedAt: "2026-05-13T00:00:00.001Z",
      steps: [],
      overallVerdict: "exploit_still_works",
    });
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3108",
      "--target-env",
      "TOKEN=abc",
      "--target-env",
      "ROLE=admin",
      "--dry-run",
    ]);
    expect(executePocStepsMock).toHaveBeenCalledOnce();
    const target = executePocStepsMock.mock.calls[0]![1];
    expect(target.env).toEqual({ TOKEN: "abc", ROLE: "admin" });
  });

  it("rejects --target-env where value contains '=' (preserves the suffix)", async () => {
    // KEY=foo=bar should map to KEY → "foo=bar" (split on FIRST '='),
    // not throw. This protects callers passing base64-ish secrets.
    dbState.rows = [
      makeRow({
        pocSteps: JSON.stringify([
          {
            id: "s1",
            kind: "exploit",
            summary: "shell",
            action: { type: "shell", cmd: "env" },
          },
        ]),
      }),
    ];
    executePocStepsMock.mockResolvedValueOnce({
      findingId: "x",
      startedAt: "2026-05-13T00:00:00.000Z",
      endedAt: "2026-05-13T00:00:00.001Z",
      steps: [],
      overallVerdict: "exploit_still_works",
    });
    await runCli([
      "disclose",
      "--reverify",
      "--target-url",
      "http://localhost:3108",
      "--target-env",
      "TOKEN=ab=cd==",
      "--dry-run",
    ]);
    expect(executePocStepsMock).toHaveBeenCalledOnce();
    const target = executePocStepsMock.mock.calls[0]![1];
    expect(target.env).toEqual({ TOKEN: "ab=cd==" });
  });
});

describe("disclose — multi-scan guardrail", () => {
  it("throws when selected findings span >1 scan and neither --scan nor --output-dir was passed", async () => {
    dbState.rows = [
      makeRow({ id: "row1aaaa", scanId: "scan-A" }),
      makeRow({ id: "row2bbbb", scanId: "scan-B" }),
    ];
    await runCli(["disclose", "--dry-run"]);
    // The throw happens before the renderer is reached.
    expect(renderAdvisoryMarkdownMock).not.toHaveBeenCalled();
  });

  it("accepts multi-scan when --output-dir overrides the scan-scoped path", async () => {
    dbState.rows = [
      makeRow({ id: "row1aaaa", scanId: "scan-A" }),
      makeRow({ id: "row2bbbb", scanId: "scan-B" }),
    ];
    await runCli([
      "disclose",
      "--output-dir",
      "/tmp/0sec-disclose-multi",
      "--dry-run",
    ]);
    // Both rows reach the renderer when the multi-scan guard is satisfied.
    expect(renderAdvisoryMarkdownMock).toHaveBeenCalledTimes(2);
  });
});
