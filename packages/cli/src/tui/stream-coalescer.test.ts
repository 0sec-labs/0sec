import { describe, expect, it } from "vitest";
import {
  applyStreamPatches,
  enqueueStreamPatch,
  type StreamPatch,
} from "./stream-coalescer.js";

type Entry = {
  id: string;
  kind: "assistant" | "reasoning" | "tool";
  text: string;
  turn: number;
  at: number;
};

const patch = (kind: StreamPatch["kind"], text: string, turn = 1, at = 100): StreamPatch => ({
  kind,
  text,
  turn,
  at,
});

const createEntry = (next: StreamPatch): Entry => ({
  id: `${next.kind}-${next.turn}`,
  kind: next.kind,
  text: next.text,
  turn: next.turn,
  at: next.at,
});

describe("enqueueStreamPatch", () => {
  it("retains only the newest unseen text for an adjacent live row", () => {
    const first = enqueueStreamPatch([], patch("assistant", "a", 3, 10));
    const second = enqueueStreamPatch(first, patch("assistant", "ab", 3, 20));

    expect(second).toEqual([patch("assistant", "ab", 3, 10)]);
  });

  it("preserves ordering across distinct stream rows", () => {
    const queued = [
      patch("assistant", "answer", 1),
      patch("reasoning", "thinking", 1),
      patch("assistant", "next answer", 1),
    ].reduce(enqueueStreamPatch, [] as StreamPatch[]);

    expect(queued.map((item) => [item.kind, item.text])).toEqual([
      ["assistant", "answer"],
      ["reasoning", "thinking"],
      ["assistant", "next answer"],
    ]);
  });
});

describe("applyStreamPatches", () => {
  it("updates the live tail without recreating its timestamp", () => {
    const entries: Entry[] = [{ id: "a", kind: "assistant", text: "old", turn: 1, at: 1 }];

    const result = applyStreamPatches(entries, [patch("assistant", "new", 1, 20)], createEntry);

    expect(result).toEqual([{ id: "a", kind: "assistant", text: "new", turn: 1, at: 1 }]);
  });

  it("starts a fresh row when a non-stream transcript item owns the tail", () => {
    const entries: Entry[] = [{ id: "tool", kind: "tool", text: "bash", turn: 1, at: 1 }];

    const result = applyStreamPatches(entries, [patch("assistant", "after tool", 1, 20)], createEntry);

    expect(result).toEqual([
      entries[0],
      { id: "assistant-1", kind: "assistant", text: "after tool", turn: 1, at: 20 },
    ]);
  });

  it("does not allocate a changed transcript for an identical tail", () => {
    const entries: Entry[] = [{ id: "a", kind: "assistant", text: "same", turn: 1, at: 1 }];

    expect(applyStreamPatches(entries, [patch("assistant", "same")], createEntry)).toBe(entries);
  });
});
