import { describe, expect, it } from "vitest";
import {
  presentationEventSink,
  type PresentationEventSink,
} from "./bus.js";

describe("presentationEventSink", () => {
  it("preserves core emission order and extracts known correlation ids", () => {
    const events: unknown[] = [];
    const sink: PresentationEventSink = {
      emit(event) {
        events.push(event);
      },
    };
    const adapter = presentationEventSink(sink, {
      now: () => "2026-08-26T00:00:00.000Z",
    });

    adapter.emit("tool_call_started", {
      tool: "read",
      scan_id: "scan-1",
      sessionId: "session-1",
    });
    adapter.emit("tool_call_completed", {
      tool: "read",
      status: "ok",
    });

    expect(events).toEqual([
      {
        protocol: "0sec.presentation/v1",
        kind: "event",
        source: "core",
        sequence: 1,
        at: "2026-08-26T00:00:00.000Z",
        eventType: "tool_call_started",
        payload: { tool: "read", scan_id: "scan-1", sessionId: "session-1" },
        scanId: "scan-1",
        sessionId: "session-1",
      },
      {
        protocol: "0sec.presentation/v1",
        kind: "event",
        source: "core",
        sequence: 2,
        at: "2026-08-26T00:00:00.000Z",
        eventType: "tool_call_completed",
        payload: { tool: "read", status: "ok" },
      },
    ]);
  });
});
