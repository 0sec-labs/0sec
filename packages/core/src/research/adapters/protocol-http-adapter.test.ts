import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { NativeMessage, NativeRuntime, NativeRuntimeResult, NativeToolDef } from "../../runtime/types.js";
import { runResearch } from "../research-runner.js";
import { ProtocolHttpResearchAdapter, type ProtocolHttpTarget } from "./protocol-http-adapter.js";

const MODEL = {
  rules: [{
    id: "trace-must-405",
    specCitation: "RFC 9110 §9.3.8",
    level: "MUST",
    surface: "method",
    mandate: "MUST respond 405 to unsupported TRACE",
    exercise: { method: "TRACE", path: "/" },
  }],
  hypotheses: [{
    ruleId: "trace-must-405",
    specCitation: "RFC 9110 §9.3.8",
    level: "MUST",
    implLocation: "handle()",
    rationale: "returns 200 for every method",
    predictedObservable: { surface: "method", expectedStatusIn: [405], forbiddenStatusIn: [200] },
    exercise: { method: "TRACE", path: "/" },
    confidence: 0.5,
  }],
};

function mockLlm(): NativeRuntime {
  return {
    type: "api",
    async executeNative(_s: string, _m: NativeMessage[], _t: NativeToolDef[]): Promise<NativeRuntimeResult> {
      return { content: [{ type: "text", text: JSON.stringify(MODEL) }], stopReason: "end_turn", durationMs: 1 };
    },
    async isAvailable() { return true; },
  };
}

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function target(status: number): ProtocolHttpTarget {
  return {
    kind: "protocol.http-conformance",
    id: "http-trace",
    location: "https://target.test",
    config: {
      specExcerpt: "Unsupported TRACE MUST return 405.",
      implExcerpt: "function handle(){ return 200; }",
      llm: mockLlm(),
      send: async () => ({ success: true, output: { status } }),
      protocol: { name: "HTTP/1.1", version: "RFC 9110", specRef: "RFC 9110 §9" },
    },
  };
}

describe("ProtocolHttpResearchAdapter", () => {
  it("runs a non-kernel target through the shared research lifecycle and preserves oracle evidence", async () => {
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-research-"));
    roots.push(artifactRoot);
    const result = await runResearch(new ProtocolHttpResearchAdapter(), target(200), { artifactRoot, runId: "run-1" });

    expect(result.completed).toBe(true);
    expect(result.candidates).toHaveLength(1);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].finding.confidence).toBe(1);
    expect(result.findings[0].candidateId).toBe("trace-must-405:0");
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "passed")).toBe(true);
    expect(result.evidence.some((e) => e.stage === "novelty" && e.status === "skipped")).toBe(true);
  });

  it("records a deterministic refutation and emits no finding for a conformant target", async () => {
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-research-"));
    roots.push(artifactRoot);
    const result = await runResearch(new ProtocolHttpResearchAdapter(), target(405), { artifactRoot, runId: "run-2" });

    expect(result.candidates).toHaveLength(1);
    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "failed")).toBe(true);
  });
});
