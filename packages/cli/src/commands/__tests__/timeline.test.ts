/**
 * Coverage for `0sec timeline` — the forensic timeline export.
 *
 * This output is handed to a client's SOC to cross-reference against their own
 * detections, so the invariants under test are the ones that would make the
 * record unusable (or wrong) in that setting:
 *
 *   • An empty scan produces clean, valid, empty output in every format —
 *     not a crash and not a half-rendered table.
 *   • Rows come out in ascending timestamp order regardless of input order.
 *   • Every timestamp is UTC ISO-8601; epoch-ms never reaches the client.
 *   • `--attack-only` keeps exactly the technique-mapped events.
 *   • ATT&CK and ATLAS stay in separate fields and columns — the two matrices
 *     have disjoint id namespaces and must never be merged into one cell.
 *
 * Boundaries mocked at module level: `@0sec/db` (no native SQLite bindings,
 * no WAL files) and `@0sec/core`'s `techniquesForEvent` /
 * `atlasTechniquesForEvent` (the mappings are owned by
 * `packages/core/src/attack/mitre.ts` and `.../atlas.ts`; this suite tests how
 * the command *uses* them, not the mappings themselves).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

interface FakeEventRow {
  id: string;
  scanId: string;
  stage: string;
  eventType: string;
  findingId?: string | null;
  agentRole?: string | null;
  payload: string;
  timestamp: number;
}

const dbState: {
  scans: Array<{ id: string; target: string }>;
  events: FakeEventRow[];
  closes: number;
  ctorPaths: Array<string | undefined>;
} = { scans: [], events: [], closes: 0, ctorPaths: [] };

vi.mock("@0sec/db", () => {
  class FakeOsecDB {
    constructor(dbPath?: string) {
      dbState.ctorPaths.push(dbPath);
    }
    getScan(id: string): unknown {
      return dbState.scans.find((s) => s.id === id);
    }
    getEvents(id: string): unknown[] {
      return dbState.events.filter((e) => e.scanId === id);
    }
    close(): void {
      dbState.closes += 1;
    }
  }
  return { osecDB: FakeOsecDB };
});

const techniquesForEventMock = vi.fn();
const atlasTechniquesForEventMock = vi.fn();
vi.mock("@0sec/core", () => ({
  techniquesForEvent: techniquesForEventMock,
  atlasTechniquesForEvent: atlasTechniquesForEventMock,
}));

const { registerTimelineCommand } = await import("../timeline.js");

const SCAN_ID = "scan-abc-123";
const T0 = Date.UTC(2026, 6, 28, 9, 0, 0); // 2026-07-28T09:00:00.000Z

const T1190 = {
  id: "T1190",
  name: "Exploit Public-Facing Application",
  tactic: "initial-access",
  url: "https://attack.mitre.org/techniques/T1190/",
  role: "primary" as const,
};

const AML_T0051 = {
  id: "AML.T0051",
  name: "LLM Prompt Injection",
  tactic: "Execution",
  url: "https://atlas.mitre.org/techniques/AML.T0051",
  role: "primary" as const,
};

function event(row: Partial<FakeEventRow> & { eventType: string; timestamp: number }): FakeEventRow {
  return {
    id: `${row.eventType}-${row.timestamp}`,
    scanId: SCAN_ID,
    stage: "attack",
    payload: "{}",
    agentRole: null,
    findingId: null,
    ...row,
  };
}

/** scan_start → tool_artifact → tool_calls → scan_complete. */
function sampleEvents(): FakeEventRow[] {
  return [
    event({
      stage: "discovery",
      eventType: "scan_start",
      timestamp: T0,
      payload: JSON.stringify({ target: "https://target.example", depth: "deep", mode: "probe" }),
    }),
    event({
      stage: "attack",
      eventType: "tool_artifact",
      timestamp: T0 + 2_000,
      payload: JSON.stringify({
        tool: "http_request",
        request: { url: "https://target.example/login", method: "POST" },
        response: { status: 200, body: "ok" },
      }),
    }),
    event({
      stage: "attack",
      eventType: "tool_calls",
      agentRole: "attack",
      findingId: "finding-77",
      timestamp: T0 + 3_000,
      payload: JSON.stringify({ turn: 3, tools: ["http_request"], results: [{ success: true }] }),
    }),
    event({
      stage: "report",
      eventType: "scan_complete",
      timestamp: T0 + 10_000,
      payload: JSON.stringify({ totalFindings: 2, durationMs: 60_000 }),
    }),
  ];
}

function captureIO() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const o = vi.spyOn(console, "log").mockImplementation((...a) => stdout.push(a.map(String).join(" ")));
  const e = vi.spyOn(console, "error").mockImplementation((...a) => stderr.push(a.map(String).join(" ")));
  return {
    stdout,
    stderr,
    out: () => stdout.join("\n"),
    err: () => stderr.join("\n"),
    restore: () => {
      o.mockRestore();
      e.mockRestore();
    },
  };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerTimelineCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

beforeEach(() => {
  dbState.scans = [{ id: SCAN_ID, target: "https://target.example" }];
  dbState.events = [];
  dbState.closes = 0;
  dbState.ctorPaths = [];
  process.exitCode = undefined;
  techniquesForEventMock.mockReset();
  atlasTechniquesForEventMock.mockReset();
  // Only tool-bearing events carry a technique; lifecycle events are the
  // "noise" `--attack-only` is meant to drop.
  techniquesForEventMock.mockImplementation((eventType: string) =>
    eventType === "tool_artifact" || eventType === "tool_calls" ? [T1190] : [],
  );
  // ATLAS is sparser than ATT&CK by design: only actions against an AI system
  // get a tag, so here only the `send_prompt` tool resolves.
  atlasTechniquesForEventMock.mockImplementation((eventType: string, toolName?: string) =>
    (eventType === "tool_artifact" || eventType === "tool_calls") && toolName === "send_prompt"
      ? [AML_T0051]
      : [],
  );
});

afterEach(() => {
  process.exitCode = undefined;
  vi.restoreAllMocks();
});

describe("timeline — empty scan", () => {
  it("renders a clean, empty markdown record", async () => {
    const io = captureIO();
    await runCli(["timeline", SCAN_ID]);
    io.restore();

    expect(process.exitCode).toBeUndefined();
    expect(io.out()).toContain(`# Forensic timeline — scan \`${SCAN_ID}\``);
    expect(io.out()).toContain("No pipeline events recorded");
    expect(io.out()).not.toContain("| # |");
  });

  it("renders a header-only CSV", async () => {
    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "csv"]);
    io.restore();

    const lines = io.out().split("\n").filter((l) => l.length > 0);
    expect(lines).toEqual([
      "timestamp,stage,eventType,agentRole,findingId,action,attackTechniqueIds,attackTactics," +
        "atlasTechniqueIds,atlasTactics",
    ]);
  });

  it("renders an empty JSON entry list", async () => {
    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const parsed = JSON.parse(io.out());
    expect(parsed.scanId).toBe(SCAN_ID);
    expect(parsed.entries).toEqual([]);
    expect(parsed.eventCount).toBe(0);
    expect(parsed.totalEventCount).toBe(0);
  });
});

describe("timeline — ordering and timestamps", () => {
  it("emits events in ascending timestamp order even when the rows arrive shuffled", async () => {
    const rows = sampleEvents();
    dbState.events = [rows[3]!, rows[1]!, rows[0]!, rows[2]!];

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const parsed = JSON.parse(io.out());
    expect(parsed.entries.map((e: { eventType: string }) => e.eventType)).toEqual([
      "scan_start",
      "tool_artifact",
      "tool_calls",
      "scan_complete",
    ]);
    const times = parsed.entries.map((e: { timestamp: string }) => Date.parse(e.timestamp));
    expect(times).toEqual([...times].sort((a: number, b: number) => a - b));
  });

  it("emits UTC ISO-8601 timestamps and never epoch-ms", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const parsed = JSON.parse(io.out());
    expect(parsed.entries[0].timestamp).toBe("2026-07-28T09:00:00.000Z");
    for (const entry of parsed.entries as Array<{ timestamp: string }>) {
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(new Date(entry.timestamp).toISOString()).toBe(entry.timestamp);
    }
    // The raw epoch value must not leak into the client-facing record.
    expect(io.out()).not.toContain(String(T0));
  });

  it("keeps stage, eventType, agentRole and findingId on every row", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const toolCalls = JSON.parse(io.out()).entries.find(
      (e: { eventType: string }) => e.eventType === "tool_calls",
    );
    expect(toolCalls).toMatchObject({
      stage: "attack",
      eventType: "tool_calls",
      agentRole: "attack",
      findingId: "finding-77",
    });
  });
});

describe("timeline — ATT&CK tagging", () => {
  it("--attack-only keeps exactly the technique-bearing events", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json", "--attack-only"]);
    io.restore();

    const parsed = JSON.parse(io.out());
    expect(parsed.entries.map((e: { eventType: string }) => e.eventType)).toEqual([
      "tool_artifact",
      "tool_calls",
    ]);
    expect(parsed.eventCount).toBe(2);
    expect(parsed.totalEventCount).toBe(4);
    expect(parsed.filters.attackOnly).toBe(true);
    for (const entry of parsed.entries as Array<{ techniques: unknown[] }>) {
      expect(entry.techniques.length).toBeGreaterThan(0);
    }
  });

  it("passes the tool name through to the ATT&CK mapping and links techniques in markdown", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID]);
    io.restore();

    expect(techniquesForEventMock).toHaveBeenCalledWith("tool_artifact", "http_request");
    expect(techniquesForEventMock).toHaveBeenCalledWith("tool_calls", "http_request");
    expect(techniquesForEventMock).toHaveBeenCalledWith("scan_start");
    expect(io.out()).toContain("[T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)");
  });

  it("dedupes techniques shared by several tools in one turn", async () => {
    dbState.events = [
      event({
        eventType: "tool_calls",
        agentRole: "attack",
        timestamp: T0,
        payload: JSON.stringify({ turn: 1, tools: ["http_request", "browser"] }),
      }),
    ];

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    expect(JSON.parse(io.out()).entries[0].techniques).toEqual([T1190]);
  });
});

describe("timeline — ATLAS tagging", () => {
  /** An LLM-target turn alongside a conventional one. */
  function llmEvents(): FakeEventRow[] {
    return [
      event({
        eventType: "scan_start",
        timestamp: T0,
        payload: JSON.stringify({ target: "https://llm.example" }),
      }),
      event({
        eventType: "tool_calls",
        agentRole: "attack",
        timestamp: T0 + 1_000,
        payload: JSON.stringify({ turn: 1, tools: ["send_prompt"] }),
      }),
      event({
        eventType: "tool_calls",
        agentRole: "attack",
        timestamp: T0 + 2_000,
        payload: JSON.stringify({ turn: 2, tools: ["http_request"] }),
      }),
    ];
  }

  it("carries ATLAS techniques in a field separate from ATT&CK", async () => {
    dbState.events = llmEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const entries = JSON.parse(io.out()).entries as Array<{
      eventType: string;
      action: string;
      techniques: unknown[];
      atlasTechniques: unknown[];
    }>;

    const llmTurn = entries.find((e) => e.action.includes("send_prompt"))!;
    expect(llmTurn.techniques).toEqual([T1190]);
    expect(llmTurn.atlasTechniques).toEqual([AML_T0051]);

    // A conventional turn keeps its ATT&CK tag and gets no ATLAS tag — the
    // matrices are complementary, not interchangeable.
    const webTurn = entries.find((e) => e.action.includes("http_request"))!;
    expect(webTurn.techniques).toEqual([T1190]);
    expect(webTurn.atlasTechniques).toEqual([]);

    // Lifecycle events carry neither.
    const scanStart = entries.find((e) => e.eventType === "scan_start")!;
    expect(scanStart.techniques).toEqual([]);
    expect(scanStart.atlasTechniques).toEqual([]);
  });

  it("passes the tool name through to the ATLAS mapping", async () => {
    dbState.events = llmEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    expect(atlasTechniquesForEventMock).toHaveBeenCalledWith("tool_calls", "send_prompt");
    expect(atlasTechniquesForEventMock).toHaveBeenCalledWith("tool_calls", "http_request");
    expect(atlasTechniquesForEventMock).toHaveBeenCalledWith("scan_start");
  });

  it("renders ATT&CK and ATLAS as distinct markdown columns", async () => {
    dbState.events = llmEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID]);
    io.restore();

    expect(io.out()).toContain("| Action | ATT&CK | ATLAS |");
    expect(io.out()).toContain(
      "[AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)",
    );
    expect(io.out()).toContain(
      "[T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)",
    );
  });

  it("writes ATLAS ids and tactics to their own CSV columns", async () => {
    dbState.events = llmEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "csv"]);
    io.restore();

    const lines = io.out().split("\n").filter((l) => l.length > 0);
    const llmRow = lines.find((l) => l.includes("send_prompt"))!;
    const webRow = lines.find((l) => l.includes("http_request"))!;

    // ATT&CK columns then ATLAS columns, never one merged cell.
    expect(llmRow).toContain("T1190,initial-access,AML.T0051,Execution");
    // No AI target, so the two trailing ATLAS columns are empty.
    expect(webRow).toContain("T1190,initial-access,,");
  });

  it("--attack-only keeps a row that maps only in ATLAS", async () => {
    // ATT&CK has no word for this turn; ATLAS does. Filtering on ATT&CK alone
    // would delete the AI evidence the export exists to carry.
    techniquesForEventMock.mockImplementation(() => []);
    dbState.events = llmEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json", "--attack-only"]);
    io.restore();

    const entries = JSON.parse(io.out()).entries as Array<{ action: string }>;
    expect(entries).toHaveLength(1);
    expect(entries[0]!.action).toContain("send_prompt");
  });
});

describe("timeline — action summaries", () => {
  it("prefers the richer tool_artifact detail for a neighbouring tool_calls row", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const entries = JSON.parse(io.out()).entries as Array<{ eventType: string; action: string }>;
    const artifact = entries.find((e) => e.eventType === "tool_artifact")!;
    const toolCalls = entries.find((e) => e.eventType === "tool_calls")!;

    expect(artifact.action).toBe("http_request: POST https://target.example/login → HTTP 200");
    // Both rows survive — the audit trail is never collapsed — but the
    // tool_calls summary is enriched with what actually went out.
    expect(toolCalls.action).toContain("POST https://target.example/login");
    expect(toolCalls.action).toContain("turn 3");
  });

  it("summarises lifecycle events in plain language", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    const entries = JSON.parse(io.out()).entries as Array<{ eventType: string; action: string }>;
    expect(entries.find((e) => e.eventType === "scan_start")!.action).toContain("target https://target.example");
    expect(entries.find((e) => e.eventType === "scan_complete")!.action).toContain("2 finding(s)");
  });

  it("keeps an unparseable payload visible instead of rendering a blank action", async () => {
    dbState.events = [event({ eventType: "verdict_seeded", timestamp: T0, payload: "{not json" })];

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json"]);
    io.restore();

    expect(JSON.parse(io.out()).entries[0].action).toContain("{not json");
  });
});

describe("timeline — window filtering", () => {
  it("--since / --until bound the export", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli([
      "timeline",
      SCAN_ID,
      "--format",
      "json",
      "--since",
      "2026-07-28T09:00:01Z",
      "--until",
      "2026-07-28T09:00:05Z",
    ]);
    io.restore();

    const parsed = JSON.parse(io.out());
    expect(parsed.entries.map((e: { eventType: string }) => e.eventType)).toEqual([
      "tool_artifact",
      "tool_calls",
    ]);
    expect(parsed.totalEventCount).toBe(4);
    expect(parsed.filters.since).toBe("2026-07-28T09:00:01.000Z");
    expect(parsed.filters.until).toBe("2026-07-28T09:00:05.000Z");
  });

  it("rejects an unparseable --since", async () => {
    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--since", "last tuesday"]);
    io.restore();

    expect(process.exitCode).toBe(2);
    expect(io.err()).toContain("Invalid --since");
  });

  it("rejects a window that ends before it starts", async () => {
    const io = captureIO();
    await runCli([
      "timeline",
      SCAN_ID,
      "--since",
      "2026-07-28T10:00:00Z",
      "--until",
      "2026-07-28T09:00:00Z",
    ]);
    io.restore();

    expect(process.exitCode).toBe(2);
    expect(io.err()).toContain("Empty window");
  });
});

describe("timeline — argument handling and DB lifecycle", () => {
  it("supports all three formats", async () => {
    dbState.events = sampleEvents();

    for (const format of ["markdown", "json", "csv"]) {
      const io = captureIO();
      await runCli(["timeline", SCAN_ID, "--format", format]);
      io.restore();
      expect(process.exitCode).toBeUndefined();
      expect(io.out().length).toBeGreaterThan(0);
    }
  });

  it("writes one CSV row per event with quoted cells", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "csv"]);
    io.restore();

    const lines = io.out().split("\n").filter((l) => l.length > 0);
    expect(lines).toHaveLength(5); // header + 4 events
    expect(lines[1]).toContain("2026-07-28T09:00:00.000Z,discovery,scan_start");
    // The action holds a comma, so the cell must be quoted.
    expect(lines[1]).toContain('"');
  });

  it("rejects an unknown --format", async () => {
    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "pdf"]);
    io.restore();

    expect(process.exitCode).toBe(2);
    expect(io.err()).toContain("Invalid --format");
  });

  it("fails with a pointer to `0sec history` when the scan is unknown", async () => {
    const io = captureIO();
    await runCli(["timeline", "no-such-scan"]);
    io.restore();

    expect(process.exitCode).toBe(2);
    expect(io.err()).toContain("No scan 'no-such-scan'");
    expect(dbState.closes).toBe(1);
  });

  it("closes the database and honours --db-path", async () => {
    dbState.events = sampleEvents();

    const io = captureIO();
    await runCli(["timeline", SCAN_ID, "--format", "json", "--db-path", "/tmp/0sec-test.db"]);
    io.restore();

    expect(dbState.closes).toBe(1);
    expect(dbState.ctorPaths).toEqual(["/tmp/0sec-test.db"]);
  });
});
