import { describe, expect, it } from "vitest";
import type { PresentationEvent } from "@0sec/shared";
import { PresentationEventBus } from "./event-bus.js";

const event: PresentationEvent = {
  protocol: "0sec.presentation/v1",
  kind: "event",
  source: "cli",
  sequence: 1,
  at: "2026-08-26T00:00:00.000Z",
  eventType: "output.stdout",
  payload: { channel: "stdout", text: "hello" },
};

describe("PresentationEventBus", () => {
  it("fans out canonical records and removes unsubscribed listeners", () => {
    const bus = new PresentationEventBus();
    const received: PresentationEvent[] = [];
    const unsubscribe = bus.subscribe({ emit(value) { received.push(value); } });

    bus.emit(event);
    unsubscribe();
    bus.emit({ ...event, sequence: 2 });

    expect(received).toEqual([event]);
    expect(bus.size).toBe(0);
  });

  it("isolates a failing observer from later observers", () => {
    const bus = new PresentationEventBus();
    const received: PresentationEvent[] = [];
    bus.subscribe({ emit() { throw new Error("observer failure"); } });
    bus.subscribe({ emit(value) { received.push(value); } });

    bus.emit(event);

    expect(received).toEqual([event]);
  });
});
