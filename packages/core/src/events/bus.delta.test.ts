/**
 * Tests for the `delta` event variant on the pluggable event bus.
 *
 * The cloud relay's wire format for these events is
 *   `PWNKIT_EVENT_DELTA {…json…}`
 * which is just the standard cloudEventSink projection of the typed event.
 * These tests cover the bus mechanics — round-tripping a `delta` payload
 * through `eventBus.emit()` and through the `cloudEventSink` to stdout.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  eventBus,
  cloudEventSink,
  isCloudEventSinkActive,
  maybeSubscribeCloudEventSink,
  _resetCloudSinkSubscriptionForTests,
  type DeltaPayload,
  type EventType,
} from "./bus.js";

describe("eventBus.emit('delta', …)", () => {
  beforeEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
    delete process.env.PWNKIT_CLOUD_EVENTS;
  });

  afterEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
    delete process.env.PWNKIT_CLOUD_EVENTS;
  });

  it("fans a delta event out to every subscribed sink with the payload intact", () => {
    const sink1: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    const sink2: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        sink1.push({ type, payload });
      },
    });
    eventBus.subscribe({
      emit: (type, payload) => {
        sink2.push({ type, payload });
      },
    });

    const payload: DeltaPayload = {
      turn: 3,
      role: "attack",
      scope: "assistant_response",
      text: "hello world",
      seq: 0,
    };
    eventBus.emit("delta", payload);

    expect(sink1).toHaveLength(1);
    expect(sink2).toHaveLength(1);
    expect(sink1[0]!.type).toBe("delta");
    expect(sink1[0]!.payload).toEqual(payload);
    expect(sink2[0]!.payload).toEqual(payload);
  });

  it("cloudEventSink projects a delta event onto a single PWNKIT_EVENT_DELTA stdout line", () => {
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      const payload: DeltaPayload = {
        turn: 7,
        role: "recon",
        scope: "reasoning",
        text: "considering whether to enumerate /admin",
        seq: 4,
      };
      cloudEventSink.emit("delta", payload as unknown as Record<string, unknown>);

      expect(writeSpy).toHaveBeenCalledTimes(1);
      const line = String(writeSpy.mock.calls[0]![0]);
      expect(line.startsWith("PWNKIT_EVENT_DELTA ")).toBe(true);
      const json = JSON.parse(line.slice("PWNKIT_EVENT_DELTA ".length));
      expect(json).toEqual(payload);
      expect(line.endsWith("\n")).toBe(true);
    } finally {
      writeSpy.mockRestore();
    }
  });

  it("isCloudEventSinkActive() reports the subscription state honestly", () => {
    expect(isCloudEventSinkActive()).toBe(false);
    process.env.PWNKIT_CLOUD_EVENTS = "1";
    maybeSubscribeCloudEventSink();
    expect(isCloudEventSinkActive()).toBe(true);
  });
});
