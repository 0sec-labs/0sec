import { describe, it, expect } from "vitest";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeMessage,
  NativeToolDef,
  NativeRuntimeResult,
} from "../runtime/types.js";
import { generatePov, judgePovEvidence } from "./pov-gate.js";

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "pov-test",
    templateId: "audit-sink",
    title: "Blind SQLi in /search",
    description: "single-quote induces SQL error",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /search?q=foo HTTP/1.1\nHost: example.com\n\n",
      response: "",
      analysis: "Error on quote suggests SQLi",
    },
    confidence: 0.6,
    timestamp: Date.now(),
    ...overrides,
  };
}

/**
 * Builds a scripted NativeRuntime that returns a fixed sequence of
 * NativeRuntimeResult objects (one per turn).
 */
function scriptedRuntime(script: NativeRuntimeResult[]): NativeRuntime & { calls: number } {
  let i = 0;
  const rt: NativeRuntime & { calls: number } = {
    type: "api" as const,
    calls: 0,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      rt.calls = ++i;
      const step = script[i - 1] ?? script[script.length - 1];
      return step;
    },
    async isAvailable() {
      return true;
    },
  };
  return rt;
}

const EVIDENCE_SQL = [
  "HTTP/1.1 200 OK",
  "<html><body>",
  "ERROR 1064 (42000): You have an error in your SQL syntax near 'foo''",
  "MariaDB version: 10.6.12-MariaDB-ubuntu",
  "</body></html>",
].join("\n");

// ────────────────────────────────────────────────────────────────────
// judgePovEvidence
// ────────────────────────────────────────────────────────────────────

describe("judgePovEvidence", () => {
  it("accepts SQL error + version string for sql-injection", () => {
    const v = judgePovEvidence(makeFinding(), EVIDENCE_SQL);
    expect(v.passed).toBe(true);
    expect(v.label).toMatch(/sqli/i);
  });

  it("rejects a bare 200 OK for sql-injection", () => {
    const v = judgePovEvidence(makeFinding(), "HTTP/1.1 200 OK\n<html>ok</html>");
    expect(v.passed).toBe(false);
  });

  it("accepts /etc/passwd for path-traversal", () => {
    const v = judgePovEvidence(
      makeFinding({ category: "path-traversal" as AttackCategory }),
      "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin",
    );
    expect(v.passed).toBe(true);
  });

  it("accepts uid= output for command-injection", () => {
    const v = judgePovEvidence(
      makeFinding({ category: "command-injection" as AttackCategory }),
      "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    );
    expect(v.passed).toBe(true);
  });

  it("falls back to generic patterns for unknown categories", () => {
    const v = judgePovEvidence(
      makeFinding({ category: "prompt-injection" as AttackCategory }),
      "leaked flag{hackme_123}",
    );
    expect(v.passed).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// generatePov
// ────────────────────────────────────────────────────────────────────

describe("generatePov", () => {
  it("returns hasPov:true when the agent runs a working exploit and submits proof", async () => {
    const runtime = scriptedRuntime([
      // Turn 1: run a curl that hits the SQLi
      {
        content: [
          {
            type: "tool_use",
            id: "t1",
            name: "bash",
            input: {
              command: "curl -s 'http://example.com/search?q=foo%27'",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
      // Turn 2: submit the PoV with real evidence
      {
        content: [
          {
            type: "tool_use",
            id: "t2",
            name: "submit_pov",
            input: {
              artifact_type: "curl",
              artifact: "curl -s 'http://example.com/search?q=foo%27'",
              execution_evidence: EVIDENCE_SQL,
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(true);
    expect(result.artifactType).toBe("curl");
    expect(result.povArtifact).toContain("curl");
    expect(result.executionEvidence).toContain("SQL syntax");
    expect(result.confidence).toBeGreaterThan(0.7);
    expect(result.turnsUsed).toBe(2);
    expect(result.reason).toMatch(/PoV confirmed/);
  });

  it("returns hasPov:false when the agent only describes and never executes", async () => {
    const runtime = scriptedRuntime([
      // Agent just emits text — no tool calls
      {
        content: [
          {
            type: "text",
            text: "I believe this endpoint would be vulnerable to SQLi because the quote produces an error.",
          },
        ],
        stopReason: "end_turn",
        durationMs: 10,
      },
      // Second turn: still talking
      {
        content: [
          {
            type: "text",
            text: "Based on the prior evidence, the exploit would extract the version.",
          },
        ],
        stopReason: "end_turn",
        durationMs: 10,
      },
      // Third turn: give up
      {
        content: [
          {
            type: "tool_use",
            id: "g1",
            name: "give_up",
            input: { reason: "cannot reach target" },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    expect(result.artifactType).toBe("none");
    expect(result.povArtifact).toBeNull();
    expect(result.confidence).toBe(0);
    expect(result.reason).toMatch(/gave up/);
  });

  it("returns hasPov:false when the agent submits evidence that fails the judge", async () => {
    const runtime = scriptedRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "s1",
            name: "submit_pov",
            input: {
              artifact_type: "curl",
              artifact: "curl http://example.com/search?q=test",
              execution_evidence: "HTTP/1.1 200 OK\n<html>no proof here</html>",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    // The PoC artifact is still captured so the caller can see what was tried
    expect(result.povArtifact).toContain("curl");
    expect(result.reason).toMatch(/did not contain category-specific proof/);
  });

  it("returns hasPov:false when maxTurns is exceeded without submission", async () => {
    // Every turn the agent makes a useless bash call and never submits
    const turn: NativeRuntimeResult = {
      content: [
        {
          type: "tool_use",
          id: "b1",
          name: "bash",
          input: { command: "echo still trying" },
        },
      ],
      stopReason: "tool_use",
      durationMs: 5,
    };
    const runtime = scriptedRuntime([turn, turn, turn]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      3,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    expect(result.turnsUsed).toBe(3);
    expect(result.reason).toMatch(/max turns/);
    expect(result.confidence).toBe(0);
  });

  it("propagates runtime errors as hasPov:false", async () => {
    const runtime = scriptedRuntime([
      {
        content: [],
        stopReason: "error",
        durationMs: 1,
        error: "rate limited",
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      3,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    expect(result.reason).toMatch(/runtime error/);
  });

  it("accepts a custom judge for test overrides", async () => {
    const runtime = scriptedRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "s1",
            name: "submit_pov",
            input: {
              artifact_type: "python",
              artifact: "import requests; requests.get('...')",
              execution_evidence: "anything",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      {
        disableBash: true,
        disableHttp: true,
        judge: () => ({ passed: true, label: "test override" }),
      },
    );

    expect(result.hasPov).toBe(true);
    expect(result.artifactType).toBe("python");
  });
});
