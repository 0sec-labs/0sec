/**
 * Privacy-boundary regression tests for the operational NDJSON stderr sink.
 *
 * These tests verify that sensitive fields never escape into the NDJSON
 * output, and that non-allowlisted events produce zero work. They capture
 * NDJSON from stderr and assert field presence/absence on the decoded JSON.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eventBus } from "./bus.js";
import {
  createOperationalEventSink,
  maybeSubscribeOperationalEventSink,
  _resetOperationalSinkSubscriptionForTests,
} from "./operational-sink.js";
import type { EventSink } from "./bus.js";

/** Collect NDJSON lines written to stderr. */
function captureStderr(): {
  restore: () => void;
  lines: () => Record<string, unknown>[];
} {
  const chunks: Buffer[] = [];
  const mock = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: unknown) => {
      if (typeof chunk === "string") {
        chunks.push(Buffer.from(chunk));
      } else if (Buffer.isBuffer(chunk)) {
        chunks.push(chunk);
      }
      return true;
    });

  return {
    restore: () => mock.mockRestore(),
    lines: () =>
      Buffer.concat(chunks)
        .toString("utf-8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l)),
  };
}

describe("operational NDJSON sink — privacy boundary", () => {
  let sink: EventSink;
  let capture: ReturnType<typeof captureStderr>;

  beforeEach(() => {
    eventBus.clear();
    _resetOperationalSinkSubscriptionForTests();
    sink = createOperationalEventSink();
    eventBus.subscribe(sink);
    capture = captureStderr();
  });

  afterEach(() => {
    capture.restore();
    eventBus.clear();
    _resetOperationalSinkSubscriptionForTests();
    vi.unstubAllEnvs();
  });


  it("EXCLUDES summary text from scan_completed", () => {
    eventBus.emit("scan_completed", {
      exit_reason: "completed",
      findings: 3,
      duration_ms: 12_345,
      turns_used: 27,
      tool_calls_total: 41,
      summary:
        "extracted FLAG{abc} from login form — this is sensitive finding text",
      cost_usd: 0.42,
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].event).toBe("scan_completed");
    expect(lines[0]).toHaveProperty("duration_ms", 12_345);
    expect(lines[0]).toHaveProperty("findings", 3);
    // The sensitive summary MUST NOT appear
    expect(lines[0]).not.toHaveProperty("summary");
    expect(JSON.stringify(lines[0])).not.toContain("FLAG{abc}");
    expect(JSON.stringify(lines[0])).not.toContain("finding text");
  });

  it("EXCLUDES task, summary, and error from subagent_lifecycle", () => {
    eventBus.emit("subagent_lifecycle", {
      agent_id: "test-agent-42",
      name: "Explorer",
      parent_scan_id: "scan-1",
      status: "completed",
      max_turns: 25,
      turns: 7,
      findings: 2,
      task: "Audit /api/users for IDOR vulnerabilities — contains target info",
      summary:
        "Found 2 IDOR vulnerabilities in /api/users endpoint",
      error: "Bearer private-subagent-error-token",
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].agent_id).toBe("test-agent-42");
    expect(lines[0].status).toBe("completed");
    expect(lines[0].turns).toBe(7);
    // Task, summary, error MUST NOT be present
    expect(lines[0]).not.toHaveProperty("task");
    expect(lines[0]).not.toHaveProperty("summary");
    expect(lines[0]).not.toHaveProperty("error");
  });


  it("EXCLUDES note from subagent_progress", () => {
    eventBus.emit("subagent_progress", {
      agent_id: "child-1",
      parent_scan_id: "scan-1",
      turn: 3,
      max_turns: 25,
      tool: "read_file",
      note: "Auditing config.php for credentials — contains sensitive paths",
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].agent_id).toBe("child-1");
    expect(lines[0].tool).toBe("read_file");
    expect(lines[0].turn).toBe(3);
    // Note must not leak
    expect(lines[0]).not.toHaveProperty("note");
    expect(JSON.stringify(lines[0])).not.toContain("config.php");
  });

  it("EXCLUDES message and remedy from tool_health", () => {
    eventBus.emit("tool_health", {
      tool: "semgrep",
      category: "missing-binary",
      message: "semgrep not found in PATH at /usr/local/bin",
      count: 1,
      remedy: "Install semgrep with `brew install semgrep`",
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].tool).toBe("semgrep");
    expect(lines[0].category).toBe("missing-binary");
    expect(lines[0].count).toBe(1);
    expect(lines[0].level).toBe("warn");
    expect(lines[0]).not.toHaveProperty("message");
    expect(lines[0]).not.toHaveProperty("remedy");
  });

  it("EXCLUDES reason from oast_confirmed and pov_oracle", () => {
    eventBus.emit("oast_confirmed", {
      findingId: "finding-1",
      category: "ssrf",
      oracle: "oast-callback" as const,
      hasPov: true as const,
      protocol: "http",
      reason: "Callback received from http://oast.example/callback/abc123",
    });
    eventBus.emit("pov_oracle", {
      findingId: "finding-2",
      category: "xss",
      oracle: "headless-browser" as const,
      hasPov: true,
      inconclusive: false,
      reason: "Confirmed via headless reproduction with payload <script>alert(1)</script>",
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(line).not.toHaveProperty("reason");
    }
  });

  it("EXCLUDES todos content array, line, and revision", () => {
    eventBus.emit("todos", {
      todos: [
        { id: "t1", content: "Exploit SQL injection in /api/login", status: "completed" },
        { id: "t2", content: "Verify XSS in search bar", status: "in-progress" },
      ],
      done: 1,
      total: 2,
      line: "Todos · 1/2",
      revision: 3,
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].done).toBe(1);
    expect(lines[0].total).toBe(2);
    expect(lines[0]).not.toHaveProperty("todos");
    expect(lines[0]).not.toHaveProperty("line");
    expect(lines[0]).not.toHaveProperty("revision");
    expect(JSON.stringify(lines[0])).not.toContain("SQL injection");
  });

  it("EXCLUDES cross_validated_leads array details", () => {
    eventBus.emit("cross_validated_leads", {
      count: 2,
      leads: [
        {
          findingId: "f1",
          title: "SQL injection in login",
          severity: "critical",
          confidence: 0.95,
          foxguardMatches: 1,
        },
        {
          findingId: "f2",
          title: "XSS in search",
          severity: "high",
          confidence: 0.8,
          foxguardMatches: 0,
        },
      ],
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].count).toBe(2);
    expect(lines[0]).not.toHaveProperty("leads");
    expect(JSON.stringify(lines[0])).not.toContain("SQL injection");
    expect(JSON.stringify(lines[0])).not.toContain("findingId");
  });

  it("produce zero stderr writes for non-allowlisted events (delta, finding_ingested, etc.)", () => {
    // These carry raw content — must produce zero output
    eventBus.emit("delta", {
      turn: 1,
      scope: "assistant_response",
      text: "Let me analyze that SQL query...",
      seq: 0,
    });
    eventBus.emit("finding_ingested", {
      finding_id: "f1",
      severity: "critical",
      title: "SQL injection",
      description: "Vulnerable to SQL injection via unsanitized input",
      evidence_request: "POST /api/login",
      evidence_response: "HTTP/1.1 500 Internal Error",
    });
    eventBus.emit("tool_call_started", {
      tool: "read_file",
      turn: 1,
      args_preview: "read /etc/passwd -- contains sensitive paths",
      ts: Date.now(),
    });
    eventBus.emit("reasoning_summary", {
      turn: 1,
      summary: "User input flows directly into a SQL query without sanitization",
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(0);
  });

  it("rejects nonfinite numeric counters", () => {
    eventBus.emit("cost_update", {
      cost_usd: NaN,
      input_tokens: Infinity,
      output_tokens: 150,
      turn: 1,
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    // cost_usd and input_tokens are NaN/Infinity → dropped
    expect(lines[0]).not.toHaveProperty("cost_usd");
    expect(lines[0]).not.toHaveProperty("input_tokens");
    // output_tokens is valid → preserved
    expect(lines[0]).toHaveProperty("output_tokens", 150);
  });

  it("drops oversized identifier strings", () => {
    const longStr = "x".repeat(300);
    eventBus.emit("session_objective", {
      scanId: longStr,
    });

    const lines = capture.lines();
    expect(lines).toHaveLength(0);
  });

  it("redacts credential-like values inside metadata arrays", () => {
    eventBus.emit("untrusted_input_sanitized", {
      tool: "read_file",
      markers: [
        "instruction-override",
        "Authorization: Bearer private-marker-sentinel",
      ],
    });
    const lines = capture.lines();
    expect(lines).toHaveLength(1);
    expect(lines[0].markers).toContain("instruction-override");
    expect(JSON.stringify(lines)).not.toContain("private-marker-sentinel");
  });

  it("requires JSON format and subscribes only once", () => {
    eventBus.clear();
    _resetOperationalSinkSubscriptionForTests();
    vi.stubEnv("0SEC_LOG_FORMAT", "text");
    maybeSubscribeOperationalEventSink();
    eventBus.emit("step_started", { step: "analyze" });
    expect(capture.lines()).toEqual([]);

    vi.stubEnv("0SEC_LOG_FORMAT", "json");
    maybeSubscribeOperationalEventSink();
    maybeSubscribeOperationalEventSink();
    eventBus.emit("cost_update", { cost_usd: 0.42 });
    expect(capture.lines()).toEqual([
      expect.objectContaining({ event: "cost_update", cost_usd: 0.42 }),
    ]);
  });
});