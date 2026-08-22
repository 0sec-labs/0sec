import { describe, expect, it } from "vitest";

import { HISTORY_LIMIT, pushHistory, recallNext, recallPrev } from "./composer-history.js";

describe("pushHistory", () => {
  it("appends oldest-first", () => {
    expect(pushHistory(["a"], "b")).toEqual(["a", "b"]);
  });

  it("drops empty and whitespace-only submissions", () => {
    expect(pushHistory(["a"], "")).toEqual(["a"]);
    expect(pushHistory(["a"], "   ")).toEqual(["a"]);
  });

  it("de-duplicates a submission identical to the most recent", () => {
    expect(pushHistory(["a", "b"], "b")).toEqual(["a", "b"]);
    // but a repeat that is not consecutive is kept
    expect(pushHistory(["b", "a"], "b")).toEqual(["b", "a", "b"]);
  });

  it("caps the ring by evicting from the front", () => {
    const full = Array.from({ length: HISTORY_LIMIT }, (_, i) => `m${i}`);
    const next = pushHistory(full, "new");
    expect(next).toHaveLength(HISTORY_LIMIT);
    expect(next[0]).toBe("m1");
    expect(next[next.length - 1]).toBe("new");
  });

  it("respects a custom limit", () => {
    expect(pushHistory(["a", "b"], "c", 2)).toEqual(["b", "c"]);
  });

  it("does not mutate the input", () => {
    const input = ["a"];
    pushHistory(input, "b");
    expect(input).toEqual(["a"]);
  });
});

describe("recallPrev", () => {
  const entries = ["first", "second", "third"];

  it("is a no-op on an empty history", () => {
    const r = recallPrev([], 0, "", "draft");
    expect(r.changed).toBe(false);
    expect(r.value).toBe("draft");
  });

  it("saves the live draft and lands on the newest entry", () => {
    const r = recallPrev(entries, entries.length, "", "typing…");
    expect(r).toEqual({ value: "third", index: 2, draft: "typing…", changed: true });
  });

  it("walks toward older entries", () => {
    // From index 2 (showing "third"), a further Up steps to index 1 ("second").
    const step = recallPrev(entries, 2, "typing…", "third");
    expect(step).toEqual({ value: "second", index: 1, draft: "typing…", changed: true });
  });

  it("stops at the oldest entry", () => {
    const r = recallPrev(entries, 0, "typing…", "first");
    expect(r.changed).toBe(false);
    expect(r.index).toBe(0);
  });
});

describe("recallNext", () => {
  const entries = ["first", "second", "third"];

  it("is a no-op when not browsing", () => {
    const r = recallNext(entries, entries.length, "draft");
    expect(r.changed).toBe(false);
    expect(r.value).toBe("draft");
  });

  it("walks toward newer entries", () => {
    const r = recallNext(entries, 0, "draft");
    expect(r).toEqual({ value: "second", index: 1, draft: "draft", changed: true });
  });

  it("restores the saved draft when stepping past the newest entry", () => {
    const r = recallNext(entries, 2, "typing…");
    expect(r).toEqual({ value: "typing…", index: entries.length, draft: "typing…", changed: true });
  });
});

describe("up then down round-trip", () => {
  it("returns to the original draft", () => {
    const entries = ["one", "two"];
    let index = entries.length;
    let draft = "";
    const buffer = "half-typed";

    const up1 = recallPrev(entries, index, draft, buffer);
    index = up1.index;
    draft = up1.draft;
    expect(up1.value).toBe("two");

    const up2 = recallPrev(entries, index, draft, up1.value);
    index = up2.index;
    draft = up2.draft;
    expect(up2.value).toBe("one");

    const down1 = recallNext(entries, index, draft);
    index = down1.index;
    expect(down1.value).toBe("two");

    const down2 = recallNext(entries, index, draft);
    index = down2.index;
    expect(down2.value).toBe("half-typed");
    expect(index).toBe(entries.length);
  });
});
