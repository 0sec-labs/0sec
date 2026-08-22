import { describe, expect, it } from "vitest";

import {
  createSelectorState,
  highlighted,
  reduceSelector,
  visibleItems,
  windowFor,
  type SelectorAction,
  type SelectorItem,
  type SelectorState,
} from "./selector.js";

const MODELS: SelectorItem[] = [
  { id: "gpt-5.5", label: "gpt-5.5", meta: "openai" },
  { id: "gpt-5.4", label: "gpt-5.4", meta: "openai" },
  { id: "claude-opus-4-7", label: "claude-opus-4-7", meta: "anthropic" },
  { id: "glm-5.3", label: "glm-5.3", meta: "z-ai" },
];

function ids(items: SelectorItem[]): string[] {
  return items.map((item) => item.id);
}

function make(items: SelectorItem[], initialId?: string): SelectorState {
  return createSelectorState("Select model", items, initialId);
}

describe("createSelectorState", () => {
  it("starts on the requested id", () => {
    expect(make(MODELS, "claude-opus-4-7").index).toBe(2);
    expect(highlighted(make(MODELS, "glm-5.3"))?.id).toBe("glm-5.3");
  });

  it("falls back to the first item when the id is absent or disabled", () => {
    expect(make(MODELS, "nope").index).toBe(0);
    const gated: SelectorItem[] = [
      { id: "a", label: "a", disabled: true },
      { id: "b", label: "b" },
    ];
    // A disabled initialId is not a legal landing spot — skip to the first
    // row the operator could actually commit.
    expect(make(gated, "a").index).toBe(1);
  });

  it("skips a leading disabled item when no id is given", () => {
    const gated: SelectorItem[] = [
      { id: "locked-1", label: "locked-1", disabled: true },
      { id: "locked-2", label: "locked-2", disabled: true },
      { id: "open", label: "open" },
    ];
    expect(make(gated).index).toBe(2);
  });

  it("stays at 0 when every item is disabled", () => {
    const all: SelectorItem[] = [
      { id: "a", label: "a", disabled: true },
      { id: "b", label: "b", disabled: true },
    ];
    expect(make(all).index).toBe(0);
    expect(make(all, "b").index).toBe(0);
  });

  it("does not alias the caller's array", () => {
    const source = MODELS.slice();
    const state = make(source);
    source.push({ id: "late", label: "late" });
    expect(state.items).toHaveLength(MODELS.length);
  });
});

describe("visibleItems", () => {
  it("returns everything for an empty query, in input order", () => {
    expect(ids(visibleItems(make(MODELS)))).toEqual(ids(MODELS));
  });

  it("matches case-insensitively", () => {
    const state = reduceSelector(make(MODELS), { type: "setQuery", query: "OPENAI" });
    expect(ids(visibleItems(state))).toEqual(["gpt-5.5", "gpt-5.4"]);
  });

  it("matches a subsequence, not just a substring", () => {
    const items: SelectorItem[] = [
      { id: "gpt-5.5", label: "gpt-5.5" },
      { id: "claude-opus-4-7", label: "claude-opus-4-7" },
    ];
    const state = reduceSelector(make(items), { type: "setQuery", query: "g55" });
    expect(ids(visibleItems(state))).toEqual(["gpt-5.5"]);
  });

  it("searches label and meta as one haystack", () => {
    const state = reduceSelector(make(MODELS), { type: "setQuery", query: "z-ai" });
    expect(ids(visibleItems(state))).toEqual(["glm-5.3"]);
  });

  it("ranks substring matches ahead of subsequence matches", () => {
    const items: SelectorItem[] = [
      { id: "loose", label: "gamma-5-5" },
      { id: "exact", label: "g55-turbo" },
    ];
    const state = reduceSelector(make(items), { type: "setQuery", query: "g55" });
    // "loose" is first in input order but only matches as a subsequence.
    expect(ids(visibleItems(state))).toEqual(["exact", "loose"]);
  });

  it("keeps input order for items of equal rank", () => {
    const state = reduceSelector(make(MODELS), { type: "setQuery", query: "gpt-5" });
    expect(ids(visibleItems(state))).toEqual(["gpt-5.5", "gpt-5.4"]);
  });

  it("returns nothing when the query matches nothing", () => {
    const state = reduceSelector(make(MODELS), { type: "setQuery", query: "zzzz" });
    expect(visibleItems(state)).toEqual([]);
    expect(highlighted(state)).toBeUndefined();
  });
});

describe("navigation", () => {
  it("moves down and up by one", () => {
    let state = make(MODELS);
    state = reduceSelector(state, { type: "down" });
    expect(state.index).toBe(1);
    state = reduceSelector(state, { type: "up" });
    expect(state.index).toBe(0);
  });

  it("wraps at both ends", () => {
    const top = make(MODELS);
    expect(reduceSelector(top, { type: "up" }).index).toBe(MODELS.length - 1);

    const bottom = make(MODELS, "glm-5.3");
    expect(bottom.index).toBe(MODELS.length - 1);
    expect(reduceSelector(bottom, { type: "down" }).index).toBe(0);
  });

  it("skips disabled items in both directions, including across the wrap", () => {
    const items: SelectorItem[] = [
      { id: "a", label: "a" },
      { id: "b", label: "b", disabled: true },
      { id: "c", label: "c", disabled: true },
      { id: "d", label: "d" },
      { id: "e", label: "e", disabled: true },
    ];
    let state = make(items);
    expect(state.index).toBe(0);
    state = reduceSelector(state, { type: "down" });
    expect(state.index).toBe(3);
    // Wrapping past the trailing disabled row lands back on "a".
    state = reduceSelector(state, { type: "down" });
    expect(state.index).toBe(0);
    state = reduceSelector(state, { type: "up" });
    expect(state.index).toBe(3);
    state = reduceSelector(state, { type: "up" });
    expect(state.index).toBe(0);
  });

  it("terminates and stays put when every item is disabled", () => {
    const items: SelectorItem[] = [
      { id: "a", label: "a", disabled: true },
      { id: "b", label: "b", disabled: true },
      { id: "c", label: "c", disabled: true },
    ];
    const state = { ...make(items), index: 1 };
    expect(reduceSelector(state, { type: "down" }).index).toBe(1);
    expect(reduceSelector(state, { type: "up" }).index).toBe(1);
    expect(reduceSelector(state, { type: "home" }).index).toBe(1);
    expect(reduceSelector(state, { type: "end" }).index).toBe(1);
  });

  it("is a no-op on an empty list", () => {
    const state = make([]);
    const actions: SelectorAction[] = [{ type: "up" }, { type: "down" }, { type: "home" }, { type: "end" }];
    for (const action of actions) {
      expect(reduceSelector(state, action).index).toBe(0);
    }
  });

  it("home and end land on enabled edges", () => {
    const items: SelectorItem[] = [
      { id: "a", label: "a", disabled: true },
      { id: "b", label: "b" },
      { id: "c", label: "c" },
      { id: "d", label: "d", disabled: true },
    ];
    const state = make(items);
    expect(reduceSelector(state, { type: "home" }).index).toBe(1);
    expect(reduceSelector(state, { type: "end" }).index).toBe(2);
  });
});

describe("query editing", () => {
  it("appends and backspaces one character at a time", () => {
    let state = make(MODELS);
    state = reduceSelector(state, { type: "append", char: "g" });
    state = reduceSelector(state, { type: "append", char: "l" });
    expect(state.query).toBe("gl");
    expect(ids(visibleItems(state))).toEqual(["glm-5.3"]);
    state = reduceSelector(state, { type: "backspace" });
    expect(state.query).toBe("g");
    state = reduceSelector(state, { type: "backspace" });
    expect(state.query).toBe("");
    // Backspacing an empty query must not underflow.
    state = reduceSelector(state, { type: "backspace" });
    expect(state.query).toBe("");
  });

  it("keeps the highlighted item when it survives the filter", () => {
    const state = make(MODELS, "gpt-5.4");
    expect(state.index).toBe(1);
    const filtered = reduceSelector(state, { type: "setQuery", query: "gpt" });
    expect(highlighted(filtered)?.id).toBe("gpt-5.4");
  });

  it("clamps the index into the new range when the highlight is filtered away", () => {
    const state = make(MODELS, "glm-5.3");
    expect(state.index).toBe(3);
    const filtered = reduceSelector(state, { type: "setQuery", query: "gpt" });
    expect(visibleItems(filtered)).toHaveLength(2);
    expect(filtered.index).toBe(1);
    expect(highlighted(filtered)?.id).toBe("gpt-5.4");
  });

  it("never leaves the index negative or out of bounds", () => {
    const queries = ["", "g", "gp", "gpt", "gpt-5.5", "zzz", "o", "openai", "5"];
    let state = make(MODELS, "glm-5.3");
    for (const query of queries) {
      state = reduceSelector(state, { type: "setQuery", query });
      const total = visibleItems(state).length;
      expect(state.index).toBeGreaterThanOrEqual(0);
      expect(state.index).toBeLessThanOrEqual(Math.max(0, total - 1));
    }
  });

  it("does not land on a disabled row after filtering", () => {
    const items: SelectorItem[] = [
      { id: "gpt-legacy", label: "gpt-legacy", disabled: true },
      { id: "gpt-5.5", label: "gpt-5.5" },
    ];
    const state = reduceSelector(make(items), { type: "setQuery", query: "gpt" });
    expect(highlighted(state)?.id).toBe("gpt-5.5");
  });
});

describe("purity", () => {
  it("returns a new object and leaves the input untouched", () => {
    const state = make(MODELS, "gpt-5.4");
    const before = JSON.stringify(state);
    const actions: SelectorAction[] = [
      { type: "down" },
      { type: "up" },
      { type: "home" },
      { type: "end" },
      { type: "append", char: "g" },
      { type: "backspace" },
      { type: "setQuery", query: "openai" },
    ];

    for (const action of actions) {
      const next = reduceSelector(state, action);
      expect(next).not.toBe(state);
      expect(JSON.stringify(state)).toBe(before);
    }
  });

  it("does not mutate the items array via visibleItems", () => {
    const state = make(MODELS);
    const list = visibleItems(state);
    list.reverse();
    expect(ids(state.items)).toEqual(ids(MODELS));
  });
});

describe("windowFor", () => {
  it("returns an empty window for non-positive maxRows", () => {
    const state = make(MODELS);
    expect(windowFor(state, 0)).toEqual({ start: 0, end: 0 });
    expect(windowFor(state, -5)).toEqual({ start: 0, end: 0 });
  });

  it("returns the whole list when it fits", () => {
    const state = make(MODELS);
    expect(windowFor(state, MODELS.length)).toEqual({ start: 0, end: MODELS.length });
    expect(windowFor(state, 999)).toEqual({ start: 0, end: MODELS.length });
  });

  it("returns an empty window for an empty list", () => {
    expect(windowFor(make([]), 10)).toEqual({ start: 0, end: 0 });
  });

  it("centres the highlight once scrolled and pins to the ends", () => {
    const items = Array.from({ length: 20 }, (_, i) => ({ id: `i${i}`, label: `i${i}` }));
    const base = make(items);
    expect(windowFor({ ...base, index: 0 }, 5)).toEqual({ start: 0, end: 5 });
    expect(windowFor({ ...base, index: 1 }, 5)).toEqual({ start: 0, end: 5 });
    expect(windowFor({ ...base, index: 10 }, 5)).toEqual({ start: 8, end: 13 });
    expect(windowFor({ ...base, index: 19 }, 5)).toEqual({ start: 15, end: 20 });
  });

  it("keeps sane bounds across list sizes and viewport heights", () => {
    for (const size of [0, 1, 2, 3, 5, 8, 13, 40, 200]) {
      const items = Array.from({ length: size }, (_, i) => ({ id: `i${i}`, label: `i${i}` }));
      const base = make(items);
      for (const maxRows of [-3, 0, 1, 2, 3, 7, 40, 500]) {
        for (const index of [0, Math.floor(size / 2), Math.max(0, size - 1)]) {
          const state = { ...base, index };
          const { start, end } = windowFor(state, maxRows);
          expect(start).toBeGreaterThanOrEqual(0);
          expect(end).toBeGreaterThanOrEqual(start);
          expect(end).toBeLessThanOrEqual(size);
          if (maxRows > 0 && size > 0) {
            expect(end - start).toBe(Math.min(maxRows, size));
            // The highlight must always be inside the painted window.
            expect(index).toBeGreaterThanOrEqual(start);
            expect(index).toBeLessThan(end);
          } else {
            expect({ start, end }).toEqual({ start: 0, end: 0 });
          }
        }
      }
    }
  });

  it("tracks the filtered list, not the full one", () => {
    const state = reduceSelector(make(MODELS), { type: "setQuery", query: "gpt" });
    expect(windowFor(state, 10)).toEqual({ start: 0, end: 2 });
  });
});
