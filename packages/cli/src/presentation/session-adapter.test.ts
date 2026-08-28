import { describe, expect, it } from "vitest";
import { presentationEventBus } from "./event-bus.js";
import { createSessionPresentationAdapter } from "./session-adapter.js";

describe("createSessionPresentationAdapter", () => {
  it("emits ordered session-correlated semantic events", () => {
    const events: Array<{ eventType: string; sessionId?: string; payload: Record<string, unknown> }> = [];
    const unsubscribe = presentationEventBus.subscribe({
      emit(event) {
        events.push({ eventType: event.eventType, sessionId: event.sessionId, payload: event.payload });
      },
    });
    const adapter = createSessionPresentationAdapter("session-1");
    try {
      adapter.opened({ mode: "scan" });
      adapter.transcriptAppend({ id: "entry-1", kind: "notice", text: "opened", turn: 0 });
      adapter.reviewOpened();
      adapter.closed();
    } finally {
      unsubscribe();
    }

    expect(events).toEqual([
      { eventType: "session.opened", sessionId: "session-1", payload: { mode: "scan" } },
      {
        eventType: "session.transcript.append",
        sessionId: "session-1",
        payload: { entry: { id: "entry-1", kind: "notice", text: "opened", turn: 0 } },
      },
      { eventType: "review.opened", sessionId: "session-1", payload: {} },
      { eventType: "session.closed", sessionId: "session-1", payload: {} },
    ]);
  });
});
