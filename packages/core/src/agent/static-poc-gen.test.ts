import { describe, it, expect } from "vitest";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeMessage,
  NativeToolDef,
  NativeRuntimeResult,
} from "../runtime/types.js";
import type { OracleResult } from "../triage/oracles.js";
import type { PovResult } from "../triage/pov-gate.js";
import {
  generateStaticPoc,
  applyStaticPocResult,
  pocStepsFromPov,
  POC_NONE_MARKER,
} from "./static-poc-gen.js";

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/** A static / code-analysis finding: high severity, NO executable pocSteps. */
function staticFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "static-1",
    templateId: "audit-sink",
    title: "SQL injection in /search (static)",
    description: "Tainted req.query.q flows into a raw query string",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "",
      response: "",
      analysis: "Static code review: user input concatenated into SQL.",
    },
    confidence: 0.5,
    timestamp: Date.now(),
    // NOTE: pocSteps deliberately absent — this is the #666 population.
    ...overrides,
  };
}

const EVIDENCE_SQL = [
  "HTTP/1.1 200 OK",
  "ERROR 1064 (42000): You have an error in your SQL syntax near 'foo''",
  "MariaDB version: 10.6.12-MariaDB-ubuntu",
].join("\n");

/** Scripted NativeRuntime that returns a fixed sequence of results. */
function scriptedRuntime(
  script: NativeRuntimeResult[],
): NativeRuntime & { calls: number } {
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
      return script[i - 1] ?? script[script.length - 1];
    },
    async isAvailable() {
      return true;
    },
  };
  return rt;
}

/** A runtime that runs a curl then submits SQL proof — reproduces cleanly. */
function reproducingRuntime() {
  return scriptedRuntime([
    {
      content: [
        {
          type: "tool_use",
          id: "t1",
          name: "bash",
          input: { command: "curl -s 'http://tgt/search?q=foo%27'" },
        },
      ],
      stopReason: "tool_use",
      durationMs: 5,
    },
    {
      content: [
        {
          type: "tool_use",
          id: "t2",
          name: "submit_pov",
          input: {
            artifact_type: "curl",
            artifact: "curl -s 'http://tgt/search?q=foo%27'",
            execution_evidence: EVIDENCE_SQL,
          },
        },
      ],
      stopReason: "tool_use",
      durationMs: 5,
    },
  ]);
}

/** A runtime that just gives up — cannot reproduce. */
function givingUpRuntime() {
  return scriptedRuntime([
    {
      content: [
        {
          type: "tool_use",
          id: "g1",
          name: "give_up",
          input: { reason: "no reachable endpoint in static-only context" },
        },
      ],
      stopReason: "tool_use",
      durationMs: 5,
    },
  ]);
}

function povResult(overrides: Partial<PovResult> = {}): PovResult {
  return {
    hasPov: true,
    povArtifact: "curl -s 'http://tgt/search?q=foo%27'",
    artifactType: "curl",
    executionEvidence: EVIDENCE_SQL,
    confidence: 0.9,
    turnsUsed: 2,
    reason: "PoV confirmed",
    oracle: "regex-fallback",
    ...overrides,
  };
}

// ────────────────────────────────────────────────────────────────────
// pocStepsFromPov — synthesis
// ────────────────────────────────────────────────────────────────────

describe("pocStepsFromPov", () => {
  it("synthesizes a runnable exploit + verify graph from a curl artifact", () => {
    const steps = pocStepsFromPov(povResult());
    expect(steps.length).toBe(2);

    const [exploit, verify] = steps;
    expect(exploit.kind).toBe("exploit");
    expect(exploit.action).toEqual({
      type: "shell",
      cmd: "curl -s 'http://tgt/search?q=foo%27'",
    });

    expect(verify.kind).toBe("verify");
    // The first meaningful evidence line becomes a body-contains assertion.
    expect(verify.expect).toBeDefined();
    expect(verify.expect).toMatchObject({ type: "body-contains" });
  });

  it("wraps python source in a self-contained heredoc shell step", () => {
    const steps = pocStepsFromPov(
      povResult({ artifactType: "python", povArtifact: "import socket\nprint('x')" }),
    );
    const exploit = steps[0];
    expect(exploit.action.type).toBe("shell");
    expect((exploit.action as { cmd: string }).cmd).toContain("python3 - <<");
    expect((exploit.action as { cmd: string }).cmd).toContain("import socket");
  });

  it("always returns at least one step so the finding stops being 'no-PoC'", () => {
    const steps = pocStepsFromPov(
      povResult({ povArtifact: null, executionEvidence: "" }),
    );
    expect(steps.length).toBeGreaterThanOrEqual(1);
  });
});

// ────────────────────────────────────────────────────────────────────
// generateStaticPoc — a static finding always gets an attempt
// ────────────────────────────────────────────────────────────────────

describe("generateStaticPoc", () => {
  it("reproduced → reproduced:true with a populated pocSteps graph", async () => {
    const result = await generateStaticPoc(
      staticFinding(),
      "http://tgt",
      reproducingRuntime(),
      { disableBash: true, disableHttp: true },
    );

    expect(result.attempted).toBe(true);
    expect(result.reproduced).toBe(true);
    expect(result.pocSteps && result.pocSteps.length).toBeGreaterThan(0);
    expect(result.marker).toMatch(/^poc_reproduced\(curl\)/);
    expect(result.pov.hasPov).toBe(true);
  });

  it("could-not-reproduce → reproduced:false flagged poc:none (NOT dropped)", async () => {
    const result = await generateStaticPoc(
      staticFinding(),
      "http://tgt",
      givingUpRuntime(),
      { disableBash: true, disableHttp: true },
    );

    expect(result.attempted).toBe(true);
    expect(result.reproduced).toBe(false);
    expect(result.pocSteps).toBeUndefined();
    expect(result.marker.startsWith(POC_NONE_MARKER)).toBe(true);
  });

  it("inconclusive oracle → treated as poc:none, never a silent pass", async () => {
    // xss delegates to the headless-browser oracle; make it throw → inconclusive.
    const runtime = scriptedRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "s1",
            name: "submit_pov",
            input: {
              artifact_type: "javascript",
              artifact: "<script>alert(1)</script>",
              execution_evidence: "reflected <script>alert(1)</script>",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 5,
      },
    ]);

    const result = await generateStaticPoc(
      staticFinding({ category: "xss" as AttackCategory }),
      "http://tgt",
      runtime,
      {
        disableBash: true,
        disableHttp: true,
        oracle: async (): Promise<OracleResult> => {
          throw new Error("browser launch failed");
        },
      },
    );

    expect(result.reproduced).toBe(false);
    expect(result.marker.startsWith(POC_NONE_MARKER)).toBe(true);
    expect(result.marker).toMatch(/inconclusive/);
    expect(result.pov.inconclusive).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// applyStaticPocResult — mutation contract
// ────────────────────────────────────────────────────────────────────

describe("applyStaticPocResult", () => {
  it("reproduced → populates pocSteps, boosts confidence, records a PASS verdict", () => {
    const finding = staticFinding();
    const steps = pocStepsFromPov(povResult());
    applyStaticPocResult(
      finding,
      {
        attempted: true,
        reproduced: true,
        pocSteps: steps,
        pov: povResult(),
        marker: "poc_reproduced(curl)",
      },
      Date.now() - 10,
    );

    expect(finding.pocSteps).toBeDefined();
    expect(finding.pocSteps?.length).toBe(2);
    expect(finding.confidence).toBe(0.9);
    expect(finding.triageNote).toContain("poc_reproduced(curl)");
    expect(finding.evidence.analysis).toContain("## Generated PoC");

    const verdict = finding.layerVerdicts?.find((v) => v.layer === "poc_gen");
    expect(verdict?.verdict).toBe("pass");
  });

  it("not reproduced → flags poc:none, leaves severity intact, never drops pocSteps in", () => {
    const finding = staticFinding();
    const before = finding.severity;
    applyStaticPocResult(
      finding,
      {
        attempted: true,
        reproduced: false,
        pov: povResult({ hasPov: false, confidence: 0, reason: "agent gave up" }),
        marker: `${POC_NONE_MARKER}: agent gave up`,
      },
      Date.now() - 10,
    );

    // Flagged, not silently dropped.
    expect(finding.triageNote).toContain(POC_NONE_MARKER);
    // Severity untouched — no-PoC ≠ false positive (the #666 lesson).
    expect(finding.severity).toBe(before);
    // Still no executable PoC (so 0cloud routes it to manual, not auto-verify).
    expect(finding.pocSteps).toBeUndefined();

    const verdict = finding.layerVerdicts?.find((v) => v.layer === "poc_gen");
    expect(verdict?.verdict).toBe("skip");
    expect(verdict?.reason).toContain(POC_NONE_MARKER);
  });

  it("preserves an existing triageNote when appending the marker", () => {
    const finding = staticFinding({ triageNote: "reachable: handler" });
    applyStaticPocResult(
      finding,
      {
        attempted: true,
        reproduced: false,
        pov: povResult({ hasPov: false, confidence: 0 }),
        marker: `${POC_NONE_MARKER}: max turns`,
      },
      Date.now(),
    );
    expect(finding.triageNote).toBe(`reachable: handler; ${POC_NONE_MARKER}: max turns`);
  });
});
