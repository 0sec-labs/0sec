/**
 * Tests for the `scan_completed` event payload shape, with a focus on
 * the cost-surfacing fields added in 0sec#231 (`cost_usd`,
 * `cost_breakdown`, `cost_per_flag`).
 *
 * These tests exercise the bus mechanics — a sink subscribed before
 * `eventBus.emit("scan_completed", …)` should observe the full payload,
 * including any cost fields the producer attached. The bus does NOT
 * validate payloads; that's the producer's job. So instead of
 * round-tripping a synthesised payload, we mock the producer-side cost
 * tracker (`splitCost` from `agent/cost.ts`) and assert that a payload
 * built from those numbers passes through unchanged.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  eventBus,
  cloudEventSink,
  type ScanCompletedPayload,
  type CostBreakdownEntry,
  type OastConfirmedPayload,
  type EventType,
} from "./bus.js";
import { splitCost, modelProvider } from "../agent/cost.js";

describe("eventBus.emit('scan_completed', …) cost fields", () => {
  beforeEach(() => {
    eventBus.clear();
  });

  afterEach(() => {
    eventBus.clear();
  });

  it("fans the full payload — including cost_usd / cost_breakdown / cost_per_flag — to subscribers", () => {
    const observed: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        observed.push({ type, payload });
      },
    });

    const breakdown: CostBreakdownEntry[] = [
      { provider: "anthropic", model: "claude-opus-4-7", cost_in: 0.18, cost_out: 0.20, cost_cache_read: 0.04 },
    ];
    const payload: ScanCompletedPayload = {
      exit_reason: "completed",
      findings: 3,
      duration_ms: 12_345,
      turns_used: 27,
      tool_calls_total: 41,
      summary: "extracted FLAG{abc}",
      cost_usd: 0.42,
      cost_breakdown: breakdown,
      cost_per_flag: 0.42,
    };
    eventBus.emit("scan_completed", payload);

    expect(observed).toHaveLength(1);
    expect(observed[0]!.type).toBe("scan_completed");
    expect(observed[0]!.payload).toEqual(payload);
  });

  // 0sec#659 / 0cloud#1278 — the always-on OAST-confirmation event must flow
  // through the bus AND serialize to the exact 0SEC_EVENT line the worker
  // relays into scan_events (event_type='oast_confirmed'), which the cloud
  // verify-claim EXISTS + #570 badge correlate on.
  it("fans an oast_confirmed event to subscribers and cloudEventSink emits 0SEC_EVENT_OAST_CONFIRMED", () => {
    const observed: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => observed.push({ type, payload }),
    });
    const payload: OastConfirmedPayload = {
      findingId: "eng-abc123",
      category: "ssrf",
      oracle: "oast-callback",
      hasPov: true,
      reason: "DNS callback: host=abc.oast.0sec.ai",
    };

    const writes: string[] = [];
    const spy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        writes.push(String(chunk));
        return true;
      });
    try {
      eventBus.emit("oast_confirmed", payload);
      cloudEventSink.emit("oast_confirmed", payload as unknown as Record<string, unknown>);
    } finally {
      spy.mockRestore();
    }

    expect(observed).toHaveLength(1);
    expect(observed[0]!.type).toBe("oast_confirmed");
    expect(observed[0]!.payload).toEqual(payload);
    // The worker lowercases 0SEC_EVENT_<TYPE> → event_type='oast_confirmed'.
    const line = writes.join("");
    expect(line).toContain("0SEC_EVENT_OAST_CONFIRMED");
    expect(line).toContain('"findingId":"eng-abc123"');
  });

  it("supports a multi-model breakdown: discovery on Haiku + attack on Opus, summed cost", () => {
    const observed: ScanCompletedPayload[] = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "scan_completed") observed.push(payload as ScanCompletedPayload);
      },
    });

    // Mock the producer's cost tracker — `splitCost()` is what the
    // scanner uses to build entries. Discovery: 100k input + 20k output
    // on Haiku ($0.80/$4.00 per 1M). Attack: 1M input + 200k output on
    // Opus ($5.00/$25.00 per 1M).
    const haikuSplit = splitCost(
      { inputTokens: 100_000, outputTokens: 20_000 },
      "claude-haiku-4-5",
    );
    const opusSplit = splitCost(
      { inputTokens: 1_000_000, outputTokens: 200_000 },
      "claude-opus-4-7",
    );
    const breakdown: CostBreakdownEntry[] = [
      {
        provider: modelProvider("claude-haiku-4-5"),
        model: "claude-haiku-4-5",
        cost_in: haikuSplit.cost_in,
        cost_out: haikuSplit.cost_out,
      },
      {
        provider: modelProvider("claude-opus-4-7"),
        model: "claude-opus-4-7",
        cost_in: opusSplit.cost_in,
        cost_out: opusSplit.cost_out,
      },
    ];
    const cost_usd = breakdown.reduce(
      (sum, entry) => sum + entry.cost_in + entry.cost_out + (entry.cost_cache_read ?? 0),
      0,
    );

    eventBus.emit("scan_completed", {
      exit_reason: "completed",
      findings: 2,
      cost_usd,
      cost_breakdown: breakdown,
      cost_per_flag: cost_usd / 2,
    });

    expect(observed).toHaveLength(1);
    const got = observed[0]!;
    // Haiku 100k * $0.80 + 20k * $4.00 = $0.08 + $0.08 = $0.16
    // Opus 1M * $5.00 + 200k * $25.00 = $5.00 + $5.00 = $10.00
    // Total: $10.16
    expect(got.cost_usd).toBeCloseTo(10.16, 5);
    expect(got.cost_breakdown).toHaveLength(2);
    expect(got.cost_breakdown![0]!.provider).toBe("anthropic");
    expect(got.cost_breakdown![0]!.model).toBe("claude-haiku-4-5");
    expect(got.cost_breakdown![1]!.model).toBe("claude-opus-4-7");
    expect(got.cost_per_flag).toBeCloseTo(10.16 / 2, 5);
  });

  it("omits cost_per_flag when no flags were extracted (avoids divide-by-zero)", () => {
    const observed: ScanCompletedPayload[] = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "scan_completed") observed.push(payload as ScanCompletedPayload);
      },
    });

    eventBus.emit("scan_completed", {
      exit_reason: "completed",
      findings: 0,
      cost_usd: 0.42,
      cost_breakdown: [
        { provider: "anthropic", model: "claude-opus-4-7", cost_in: 0.21, cost_out: 0.21 },
      ],
      // cost_per_flag intentionally absent — the producer (agentic-scanner)
      // is responsible for omitting it when flagsExtracted == 0; the bus
      // just round-trips whatever shape it's given.
    });

    expect(observed).toHaveLength(1);
    expect(observed[0]!.cost_usd).toBe(0.42);
    expect(observed[0]!.cost_per_flag).toBeUndefined();
  });

  it("omits all cost fields when the runtime didn't track tokens (legacy CLI path)", () => {
    const observed: ScanCompletedPayload[] = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "scan_completed") observed.push(payload as ScanCompletedPayload);
      },
    });

    // Legacy CLI runtimes return `estimatedCostUsd: 0` and don't surface
    // a token tally — the producer skips cost fields entirely so
    // consumers can distinguish "tracked, $0" from "untracked".
    eventBus.emit("scan_completed", {
      exit_reason: "completed",
      findings: 1,
      duration_ms: 8_000,
      turns_used: 12,
      summary: "scan complete",
    });

    expect(observed).toHaveLength(1);
    const got = observed[0]!;
    expect(got.cost_usd).toBeUndefined();
    expect(got.cost_breakdown).toBeUndefined();
    expect(got.cost_per_flag).toBeUndefined();
    expect(got.exit_reason).toBe("completed");
    expect(got.findings).toBe(1);
  });

  it("includes cost_cache_read in the breakdown when the runtime tracked cached input", () => {
    const observed: ScanCompletedPayload[] = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "scan_completed") observed.push(payload as ScanCompletedPayload);
      },
    });

    // 1M total input, 600k cached — Sonnet pricing: $3 input, $0.30 cached.
    // Uncached: 400k * $3 = $1.20. Cached: 600k * $0.30 = $0.18.
    const split = splitCost(
      { inputTokens: 1_000_000, outputTokens: 0, cachedInputTokens: 600_000 },
      "claude-sonnet-4-6",
    );
    eventBus.emit("scan_completed", {
      exit_reason: "completed",
      findings: 1,
      cost_usd: split.cost_in + split.cost_out + (split.cost_cache_read ?? 0),
      cost_breakdown: [
        {
          provider: "anthropic",
          model: "claude-sonnet-4-6",
          cost_in: split.cost_in,
          cost_out: split.cost_out,
          cost_cache_read: split.cost_cache_read,
        },
      ],
    });

    expect(observed).toHaveLength(1);
    const entry = observed[0]!.cost_breakdown![0]!;
    expect(entry.cost_in).toBeCloseTo(1.20, 5);
    expect(entry.cost_out).toBeCloseTo(0, 5);
    expect(entry.cost_cache_read).toBeCloseTo(0.18, 5);
  });
});
