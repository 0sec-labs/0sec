/**
 * Tests for the runtime validation schemas in `@pwnkit/core` that guard
 * the two highest-risk `JSON.parse(...) as T` sites in core:
 *
 *   - `mcpRpcEnvelopeSchema` — `mcp.ts` parses an external HTTP/RPC response
 *     into a JSON-RPC envelope. A malicious MCP server can return arbitrary
 *     JSON, so we validate envelope shape (jsonrpc/id/result/error) without
 *     pinning the per-method `result` payload.
 *
 *   - `layerVerdictArraySchema` — `agentic-scanner.ts` hydrates the
 *     `findings.layerVerdicts` DB column. The verdict surface evolves
 *     (#112 / #113), so each element is `.passthrough()` and unknown
 *     fields round-trip.
 *
 * Mirrors the precedent set by the CLI's `schemas.test.ts` (PR #300).
 */

import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  mcpRpcEnvelopeSchema,
  layerVerdictSchema,
  layerVerdictArraySchema,
  formatZodError,
} from "./schemas.js";

// ── McpRpcEnvelope ─────────────────────────────────────────────────────────

describe("mcpRpcEnvelopeSchema", () => {
  it("accepts a minimal envelope with only `jsonrpc` and `id`", () => {
    const parsed = mcpRpcEnvelopeSchema.parse({ jsonrpc: "2.0", id: "abc" });
    expect(parsed.jsonrpc).toBe("2.0");
    expect(parsed.id).toBe("abc");
  });

  it("accepts a tools/list-style success envelope", () => {
    const parsed = mcpRpcEnvelopeSchema.parse({
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "fetch_url" }] },
    });
    expect(parsed.result?.tools).toBeDefined();
  });

  it("accepts an error envelope", () => {
    const parsed = mcpRpcEnvelopeSchema.parse({
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32601, message: "Method not found" },
    });
    expect(parsed.error?.code).toBe(-32601);
    expect(parsed.error?.message).toBe("Method not found");
  });

  it("accepts an empty envelope (all fields optional)", () => {
    const parsed = mcpRpcEnvelopeSchema.parse({});
    expect(parsed).toEqual({});
  });

  it("rejects an envelope where `result` is not an object", () => {
    expect(() =>
      mcpRpcEnvelopeSchema.parse({ jsonrpc: "2.0", id: 1, result: "oops" }),
    ).toThrow(z.ZodError);
  });

  it("rejects an envelope where `error` is not an object", () => {
    expect(() =>
      mcpRpcEnvelopeSchema.parse({ jsonrpc: "2.0", id: 1, error: "boom" }),
    ).toThrow(z.ZodError);
  });

  it("rejects a top-level non-object (array, string, null)", () => {
    expect(() => mcpRpcEnvelopeSchema.parse([])).toThrow(z.ZodError);
    expect(() => mcpRpcEnvelopeSchema.parse("hello")).toThrow(z.ZodError);
    expect(() => mcpRpcEnvelopeSchema.parse(null)).toThrow(z.ZodError);
  });

  it("rejects an envelope where `id` is an object", () => {
    expect(() =>
      mcpRpcEnvelopeSchema.parse({ jsonrpc: "2.0", id: { nested: true } }),
    ).toThrow(z.ZodError);
  });

  it("permits unknown top-level fields (passthrough)", () => {
    const parsed = mcpRpcEnvelopeSchema.parse({
      jsonrpc: "2.0",
      id: 1,
      result: {},
      // forward-compatible extras
      meta: { traceId: "t-1" },
      latencyMs: 12,
    });
    expect((parsed as Record<string, unknown>).meta).toEqual({ traceId: "t-1" });
    expect((parsed as Record<string, unknown>).latencyMs).toBe(12);
  });
});

// ── LayerVerdict ───────────────────────────────────────────────────────────

describe("layerVerdictSchema", () => {
  function validVerdict(): Record<string, unknown> {
    return {
      layer: "evidence_gate",
      verdict: "pass",
      reason: "Evidence body contains the expected sentinel.",
      durationMs: 12,
      costUsd: 0,
    };
  }

  it("accepts a minimal verdict", () => {
    const parsed = layerVerdictSchema.parse(validVerdict());
    expect(parsed.layer).toBe("evidence_gate");
    expect(parsed.verdict).toBe("pass");
  });

  it("rejects a verdict with an unknown `verdict` kind", () => {
    const v = validVerdict();
    v.verdict = "almost-pass";
    expect(() => layerVerdictSchema.parse(v)).toThrow(z.ZodError);
  });

  it("rejects a verdict missing the required `reason`", () => {
    const v = validVerdict();
    delete v.reason;
    expect(() => layerVerdictSchema.parse(v)).toThrow(z.ZodError);
  });

  it("rejects a verdict with a non-numeric `durationMs`", () => {
    const v = validVerdict();
    v.durationMs = "12";
    expect(() => layerVerdictSchema.parse(v)).toThrow(z.ZodError);
  });

  it("accepts a verdict with a changedSeverity transition", () => {
    const v = validVerdict();
    v.verdict = "downgrade";
    v.changedSeverity = { from: "high", to: "low" };
    const parsed = layerVerdictSchema.parse(v);
    expect(parsed.changedSeverity?.from).toBe("high");
  });

  it("rejects a changedSeverity with an unknown severity", () => {
    const v = validVerdict();
    v.changedSeverity = { from: "high", to: "super-low" };
    expect(() => layerVerdictSchema.parse(v)).toThrow(z.ZodError);
  });

  it("permits unknown fields on a verdict (passthrough — telemetry evolves)", () => {
    const v = validVerdict();
    v.modelVersion = "claude-opus-4-7";
    v.experimentalSignal = { foo: 1 };
    const parsed = layerVerdictSchema.parse(v);
    expect((parsed as Record<string, unknown>).modelVersion).toBe("claude-opus-4-7");
    expect((parsed as Record<string, unknown>).experimentalSignal).toEqual({ foo: 1 });
  });

  it("accepts an unknown `layer` value (TriageLayerName evolves)", () => {
    const v = validVerdict();
    v.layer = "future_layer_not_yet_in_shared_types";
    const parsed = layerVerdictSchema.parse(v);
    expect(parsed.layer).toBe("future_layer_not_yet_in_shared_types");
  });
});

describe("layerVerdictArraySchema", () => {
  it("accepts an empty array", () => {
    expect(layerVerdictArraySchema.parse([])).toEqual([]);
  });

  it("accepts an array of valid verdicts", () => {
    const arr = [
      {
        layer: "evidence_gate",
        verdict: "pass",
        reason: "ok",
        durationMs: 1,
        costUsd: 0,
      },
      {
        layer: "oracle",
        verdict: "reject",
        reason: "no match",
        durationMs: 50,
        costUsd: 0.01,
        confidence: 0.92,
      },
    ];
    const parsed = layerVerdictArraySchema.parse(arr);
    expect(parsed).toHaveLength(2);
    expect(parsed[1].confidence).toBe(0.92);
  });

  it("rejects a non-array input", () => {
    expect(() => layerVerdictArraySchema.parse({ layer: "x" })).toThrow(z.ZodError);
    expect(() => layerVerdictArraySchema.parse("nope")).toThrow(z.ZodError);
    expect(() => layerVerdictArraySchema.parse(null)).toThrow(z.ZodError);
  });

  it("rejects an array containing a malformed verdict", () => {
    const arr = [
      { layer: "evidence_gate", verdict: "pass", reason: "ok", durationMs: 1, costUsd: 0 },
      { layer: "oracle", verdict: "kinda-pass", reason: "x", durationMs: 1, costUsd: 0 },
    ];
    expect(() => layerVerdictArraySchema.parse(arr)).toThrow(z.ZodError);
  });
});

// ── formatZodError ─────────────────────────────────────────────────────────

describe("formatZodError", () => {
  it("names the failing field path in the message", () => {
    try {
      mcpRpcEnvelopeSchema.parse({ jsonrpc: "2.0", id: 1, result: "not-an-object" });
      throw new Error("expected parse to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(z.ZodError);
      const msg = formatZodError(err as z.ZodError, "envelope");
      expect(msg).toContain("envelope");
      expect(msg).toContain("result");
    }
  });

  it("handles a root-level type mismatch", () => {
    try {
      layerVerdictArraySchema.parse("nope");
      throw new Error("expected parse to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(z.ZodError);
      const msg = formatZodError(err as z.ZodError, "layerVerdicts");
      expect(msg).toContain("layerVerdicts");
    }
  });
});
