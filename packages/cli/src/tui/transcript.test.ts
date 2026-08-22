import { describe, expect, it } from "vitest";
import {
  appendTranscriptEntry,
  isConsecutiveDuplicate,
  repeatSuffix,
  type TranscriptEntry,
} from "./transcript.js";

const notice = (text: string, extra: Partial<TranscriptEntry> = {}): TranscriptEntry => ({
  kind: "notice",
  text,
  turn: 1,
  ...extra,
});

describe("appendTranscriptEntry", () => {
  it("appends a first entry", () => {
    expect(appendTranscriptEntry([], notice("a"))).toEqual([notice("a")]);
  });

  it("collapses consecutive identical entries and carries a count", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, notice("wait for the active turn"));
    entries = appendTranscriptEntry(entries, notice("wait for the active turn"));
    entries = appendTranscriptEntry(entries, notice("wait for the active turn"));
    expect(entries).toHaveLength(1);
    expect(entries[0].repeat).toBe(3);
    expect(entries[0].text).toBe("wait for the active turn");
  });

  it("keeps collapsing past the second repeat", () => {
    let entries: TranscriptEntry[] = [];
    for (let i = 0; i < 8; i += 1) entries = appendTranscriptEntry(entries, notice("x"));
    expect(entries).toHaveLength(1);
    expect(entries[0].repeat).toBe(8);
  });

  it("does NOT collapse non-consecutive duplicates", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, notice("a"));
    entries = appendTranscriptEntry(entries, notice("b"));
    entries = appendTranscriptEntry(entries, notice("a"));
    expect(entries.map((entry) => entry.text)).toEqual(["a", "b", "a"]);
    expect(entries.every((entry) => entry.repeat === undefined)).toBe(true);
  });

  it("does NOT collapse entries differing only in kind", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, notice("same text"));
    entries = appendTranscriptEntry(entries, { kind: "error", text: "same text", turn: 1 });
    expect(entries).toHaveLength(2);
  });

  it("does NOT collapse entries differing only in detail", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, notice("t", { detail: "one" }));
    entries = appendTranscriptEntry(entries, notice("t", { detail: "two" }));
    expect(entries).toHaveLength(2);
  });

  it("never collapses operator messages", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, { kind: "user", text: "again", turn: 1 });
    entries = appendTranscriptEntry(entries, { kind: "user", text: "again", turn: 2 });
    expect(entries).toHaveLength(2);
  });

  it("never collapses panels", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, { kind: "panel", text: "help", turn: 1 });
    entries = appendTranscriptEntry(entries, { kind: "panel", text: "help", turn: 1 });
    expect(entries).toHaveLength(2);
  });

  it("does not mutate the input array", () => {
    const original = [notice("a")];
    const next = appendTranscriptEntry(original, notice("a"));
    expect(original).toHaveLength(1);
    expect(original[0].repeat).toBeUndefined();
    expect(next[0].repeat).toBe(2);
  });

  it("treats a differing success flag as a different entry", () => {
    let entries: TranscriptEntry[] = [];
    entries = appendTranscriptEntry(entries, { kind: "tool", text: "read_file", turn: 1, success: true });
    entries = appendTranscriptEntry(entries, { kind: "tool", text: "read_file", turn: 1, success: false });
    expect(entries).toHaveLength(2);
  });
});

describe("isConsecutiveDuplicate", () => {
  it("is false with no previous entry", () => {
    expect(isConsecutiveDuplicate(undefined, notice("a"))).toBe(false);
  });
});

describe("repeatSuffix", () => {
  it("is empty for a single occurrence", () => {
    expect(repeatSuffix(undefined)).toBe("");
    expect(repeatSuffix(1)).toBe("");
  });

  it("renders a count for repeats", () => {
    expect(repeatSuffix(3)).toBe(" (x3)");
  });
});
