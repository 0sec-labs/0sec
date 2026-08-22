import { describe, expect, it } from "vitest";

import {
  allocateColumns,
  allocateLabelValue,
  columnWidths,
  fitCells,
  fitRows,
  textCells,
  toCells,
  type ColumnSpec,
} from "./primitives.js";
import { fitTuiText } from "./text.js";

/**
 * The centrepiece of this file is the sweep in "column allocation invariants".
 *
 * Every rendering defect this module exists to prevent is one statement being
 * false: `sum(widths) + gaps <= available`. When it is false Yoga shrinks the
 * siblings instead of clipping them and they paint over each other, producing
 * "Showpavailableenslash commands", "target:cnone" and "runs12". So the sweep
 * asserts it across every width a terminal can plausibly have and across every
 * shape of column list the call sites in run.tsx and chat-screen.tsx use.
 */

/** Dense enough to catch off-by-one at every boundary the allocator has. */
const WIDTHS = Array.from({ length: 201 }, (_, index) => index);
const GAPS = [0, 1, 2, 3];

interface Case {
  name: string;
  columns: ColumnSpec[];
}

const CASES: Case[] = [
  { name: "empty", columns: [] },
  { name: "single fixed", columns: [{ fixed: 12 }] },
  {
    name: "single oversized fixed",
    columns: [{ fixed: 500 }],
  },
  {
    name: "single oversized content",
    columns: [{ content: "x".repeat(400) }],
  },
  {
    name: "all fixed",
    columns: [{ fixed: 4 }, { fixed: 8 }, { fixed: 12 }],
  },
  {
    name: "all flex, equal weight",
    columns: [{ flex: 1 }, { flex: 1 }, { flex: 1 }],
  },
  {
    name: "all flex, weighted",
    columns: [{ flex: 3 }, { flex: 1 }, { flex: 2 }],
  },
  {
    name: "flex with min and max",
    columns: [{ flex: 1, min: 10, max: 20 }, { flex: 2, max: 5 }, { fixed: 3 }],
  },
  {
    name: "zero-weight flex beside a real one",
    columns: [{ flex: 0 }, { flex: 1 }],
  },
  {
    name: "content sized, no max",
    columns: [{ content: "findings" }, { content: "12" }],
  },
  {
    name: "content sized, with max",
    columns: [{ content: "a very long caption indeed", max: 6 }, { flex: 1 }],
  },
  {
    name: "content sized, min above max",
    columns: [{ content: "hi", min: 30, max: 4 }, { flex: 1 }],
  },
  {
    // The real chat header: identity, engagement summary, autonomy mode.
    name: "mixed, prioritised (chat header)",
    columns: [
      { fixed: 4, priority: 2 },
      { flex: 1, priority: 0 },
      { content: "copilot", max: 10, priority: 1 },
    ],
  },
  {
    // The real composer footer: hint on the left, counters on the right.
    name: "mixed (composer footer)",
    columns: [
      { flex: 1, priority: 1 },
      { content: "sonnet · ~/src/0sec · main · 4 turns", max: 40, priority: 0 },
    ],
  },
  {
    name: "more columns than cells",
    columns: Array.from({ length: 12 }, () => ({ fixed: 1 }) as ColumnSpec),
  },
  {
    name: "many wide columns",
    columns: Array.from({ length: 20 }, (_, index) => ({ fixed: index + 1 }) as ColumnSpec),
  },
  {
    name: "garbage inputs",
    columns: [
      { fixed: -5 },
      { flex: Number.NaN },
      { content: "" },
      { flex: 1, min: -3, max: Number.POSITIVE_INFINITY },
      { content: "ok", min: 2.7, max: 9.9 },
    ],
  },
];

describe("column allocation invariants", () => {
  it("never claims more cells than it was given, at any width, for any shape", () => {
    for (const { name, columns } of CASES) {
      for (const gap of GAPS) {
        for (const available of WIDTHS) {
          const allocation = allocateColumns({ available, gap, columns });
          const sum = allocation.widths.reduce((total, width) => total + width, 0);
          const gaps = gap * Math.max(0, allocation.rendered.length - 1);

          expect(
            sum + gaps,
            `${name} overflowed at available=${available} gap=${gap}: ` +
              `${sum} cells + ${gaps} gap cells > ${available}`,
          ).toBeLessThanOrEqual(available);
          // `used` is what the component puts on the row's `width` prop, so
          // it has to agree with the arithmetic above, not approximate it.
          expect(allocation.used).toBe(sum + gaps);
          expect(allocation.gapCells).toBe(gaps);
        }
      }
    }
  });

  it("only ever produces non-negative integer widths", () => {
    for (const { name, columns } of CASES) {
      for (const gap of GAPS) {
        for (const available of WIDTHS) {
          for (const width of allocateColumns({ available, gap, columns }).widths) {
            expect(
              Number.isInteger(width),
              `${name} produced a fractional width ${width} at ${available}/${gap}`,
            ).toBe(true);
            expect(
              width,
              `${name} produced a negative width ${width} at ${available}/${gap}`,
            ).toBeGreaterThanOrEqual(0);
          }
        }
      }
    }
  });

  it("reports exactly the columns that received cells", () => {
    for (const { name, columns } of CASES) {
      for (const gap of GAPS) {
        for (const available of WIDTHS) {
          const allocation = allocateColumns({ available, gap, columns });
          const expected = allocation.widths
            .map((width, index) => (width > 0 ? index : -1))
            .filter((index) => index >= 0);
          expect(allocation.rendered, `${name} at ${available}/${gap}`).toEqual(expected);
          expect(allocation.widths).toHaveLength(columns.length);
        }
      }
    }
  });

  it("degrades instead of throwing at degenerate widths and garbage input", () => {
    const nonsense = [0, 1, 2, -1, -100, 3.7, Number.NaN, Number.POSITIVE_INFINITY];
    for (const { columns } of CASES) {
      for (const available of nonsense) {
        for (const gap of [0, 1, 2, -1, Number.NaN]) {
          expect(() =>
            allocateColumns({ available: available as number, gap: gap as number, columns }),
          ).not.toThrow();
          const allocation = allocateColumns({
            available: available as number,
            gap: gap as number,
            columns,
          });
          expect(allocation.used).toBeLessThanOrEqual(toCells(available));
        }
      }
    }
  });

  it("shows nothing rather than something corrupt when there is no room", () => {
    for (const { name, columns } of CASES) {
      const allocation = allocateColumns({ available: 0, gap: 1, columns });
      expect(allocation.rendered, name).toEqual([]);
      expect(allocation.used, name).toBe(0);
    }
    // One cell, two columns and a gap: one column wins, the other is dropped
    // outright. The alternative — two half-columns — is the overlap.
    const tight = allocateColumns({
      available: 1,
      gap: 1,
      columns: [{ content: "runs" }, { flex: 1 }],
    });
    expect(tight.rendered).toHaveLength(1);
    expect(tight.used).toBe(1);
  });
});

describe("column allocation behaviour", () => {
  it("spends every available cell when a flex column is present", () => {
    for (const available of WIDTHS) {
      const allocation = allocateColumns({
        available,
        gap: 1,
        columns: [{ fixed: 4 }, { flex: 1 }],
      });
      if (allocation.rendered.length === 2) {
        expect(allocation.used, `at available=${available}`).toBe(available);
      }
    }
  });

  it("splits a flex row by weight", () => {
    const allocation = allocateColumns({
      available: 30,
      gap: 0,
      columns: [{ flex: 3 }, { flex: 1 }],
    });
    // Each column is floored at one cell first; the 28-cell surplus is what
    // gets split 3:1.
    expect(allocation.widths).toEqual([22, 8]);
    expect(allocation.used).toBe(30);
  });

  it("sizes a content column to its own text and no further", () => {
    const allocation = allocateColumns({
      available: 60,
      gap: 1,
      columns: [{ content: "findings" }, { flex: 1 }],
    });
    expect(allocation.widths[0]).toBe(textCells("findings"));
    expect(allocation.used).toBe(60);
  });

  it("honours a content column's max", () => {
    const allocation = allocateColumns({
      available: 60,
      gap: 1,
      columns: [{ content: "a very long caption indeed", max: 6 }, { flex: 1 }],
    });
    expect(allocation.widths[0]).toBe(6);
  });

  it("drops a column that cannot have its declared min, rather than shrinking it", () => {
    // `min` is "below this I am noise" — a 1-cell column renders a lone "."
    // and still costs a gap, which is strictly worse than not being there.
    const columns: ColumnSpec[] = [{ content: "hint" }, { flex: 1, min: 20 }];
    expect(allocateColumns({ available: 12, gap: 1, columns }).widths[1]).toBe(0);
    expect(
      allocateColumns({ available: 40, gap: 1, columns }).widths[1],
    ).toBeGreaterThanOrEqual(20);
  });

  it("caps a flex column at its max and leaves the surplus unspent", () => {
    const allocation = allocateColumns({
      available: 60,
      gap: 0,
      columns: [{ flex: 1, max: 10 }],
    });
    expect(allocation.widths).toEqual([10]);
    expect(allocation.used).toBeLessThanOrEqual(60);
  });

  it("drops the lowest-priority column first, then the rightmost", () => {
    // The chat header: "0sec" and the mode badge outrank the engagement
    // summary, which is why "0sec / chat" never bleeds into "target: none".
    const columns: ColumnSpec[] = [
      { fixed: 4, priority: 2 },
      { flex: 1, min: 12, priority: 0 },
      { content: "copilot", max: 10, priority: 1 },
    ];
    const narrow = allocateColumns({ available: 8, gap: 1, columns });
    expect(narrow.widths[1]).toBe(0);
    expect(narrow.widths[0]).toBeGreaterThan(0);

    const narrower = allocateColumns({ available: 2, gap: 1, columns });
    expect(narrower.rendered).toEqual([0]);

    const wide = allocateColumns({ available: 100, gap: 1, columns });
    expect(wide.rendered).toEqual([0, 1, 2]);
    expect(wide.used).toBe(100);
  });

  it("keeps ties left-to-right when no priorities are given", () => {
    const allocation = allocateColumns({
      available: 4,
      gap: 1,
      columns: [{ fixed: 2 }, { fixed: 2 }, { fixed: 2 }],
    });
    expect(allocation.rendered).toEqual([0, 1]);
  });

  it("ignores columns that can never be worth a cell, gaps included", () => {
    // This replaces the `runsLabelWidth > 0 ? <text/> : null` guards at the
    // call sites: pass the column unconditionally and it costs nothing —
    // not a cell, and not a gap either.
    const allocation = allocateColumns({
      available: 20,
      gap: 2,
      columns: [{ content: "hint" }, { fixed: 0 }, { content: "" }, { flex: 1 }],
    });
    expect(allocation.widths[1]).toBe(0);
    expect(allocation.widths[2]).toBe(0);
    expect(allocation.rendered).toEqual([0, 3]);
    expect(allocation.gapCells).toBe(2); // one gap, not three
    expect(allocation.used).toBe(20);
  });

  it("columnWidths is the widths of allocateColumns", () => {
    const input = {
      available: 41,
      gap: 2,
      columns: [{ content: "scope" }, { flex: 1 }, { fixed: 6 }] as ColumnSpec[],
    };
    expect(columnWidths(input)).toEqual(allocateColumns(input).widths);
  });
});

describe("fitCells", () => {
  const SAMPLES = [
    "",
    " ",
    "runs",
    "runs ",
    " runs ",
    "0",
    "Show available slash commands",
    "target: https://example.invalid/a/very/long/path?with=query#and-fragment",
    "line one\nline two\tand\ta tab",
    "\u001b[31mred\u001b[0m",
    "A".repeat(400),
  ];

  it("always occupies exactly the cells it was allocated", () => {
    for (const sample of SAMPLES) {
      for (let width = 1; width <= 60; width += 1) {
        for (const align of ["left", "right", "center"] as const) {
          const cell = fitCells(sample, width, { align });
          expect(
            cell.length,
            `"${sample.slice(0, 12)}" at width ${width} (${align}) rendered ${cell.length} cells`,
          ).toBe(width);
        }
      }
    }
  });

  it("renders nothing at all for a zero or nonsense width", () => {
    for (const width of [0, -1, -40, Number.NaN, 0.4]) {
      expect(fitCells("anything", width as number)).toBe("");
    }
  });

  it("respects middle truncation for paths and urls", () => {
    const cell = fitCells("https://example.invalid/very/long/path", 20, { fit: "middle" });
    expect(cell).toHaveLength(20);
    expect(cell).toContain("...");
    expect(cell.startsWith("https")).toBe(true);
  });
});

describe("label / value separation (the trailing-space trap)", () => {
  it("documents the trap: fitTuiText trims, so a padded literal separator vanishes", () => {
    // This is the actual mechanism behind "runs12": the separator was baked
    // into the label as a trailing space, and sanitizeTuiText removed it.
    expect(fitTuiText("runs ", 8)).toBe("runs");
    expect(fitTuiText("runs ", 8) + fitTuiText("12", 4)).toBe("runs12");
  });

  it("keeps a real gap between label and value, so the trap cannot occur", () => {
    const allocation = allocateLabelValue({ available: 20, label: "runs", value: "12" });
    expect(allocation.labelWidth).toBe(4);
    expect(allocation.gap).toBeGreaterThanOrEqual(1);
    expect(allocation.valueWidth).toBeGreaterThan(0);
    expect(allocation.used).toBeLessThanOrEqual(20);

    // Mirrors what <LabelValue> renders: two Cells with a Yoga gap between
    // them. The separation lives in the layout, not in either string.
    const row =
      fitCells("runs", allocation.labelWidth) +
      " ".repeat(allocation.gap) +
      fitCells("12", allocation.valueWidth);
    expect(row.startsWith("runs 12")).toBe(true);
    expect(row).not.toContain("runs12");
  });

  it("never overflows, at any width, for realistic captions and values", () => {
    const pairs: Array<[string, string]> = [
      ["runs", "12"],
      ["findings", "0"],
      ["incidents", "1483"],
      ["target", "https://example.invalid/checkout"],
      ["", ""],
      ["a caption far longer than any sane terminal row would ever hold", "9"],
    ];
    for (const [label, value] of pairs) {
      for (const available of WIDTHS) {
        for (const gap of [1, 2, 3]) {
          const allocation = allocateLabelValue({ available, label, value, gap });
          const claimed =
            allocation.labelWidth +
            (allocation.labelWidth > 0 && allocation.valueWidth > 0 ? allocation.gap : 0) +
            allocation.valueWidth;
          expect(
            claimed,
            `"${label}"/"${value}" overflowed at ${available} (gap ${gap})`,
          ).toBeLessThanOrEqual(available);
          expect(allocation.used).toBeLessThanOrEqual(available);
          expect(Number.isInteger(allocation.labelWidth)).toBe(true);
          expect(Number.isInteger(allocation.valueWidth)).toBe(true);
          expect(allocation.labelWidth).toBeGreaterThanOrEqual(0);
          expect(allocation.valueWidth).toBeGreaterThanOrEqual(0);
        }
      }
    }
  });

  it("keeps the value when only one of the two fits", () => {
    const allocation = allocateLabelValue({ available: 2, label: "findings", value: "12" });
    expect(allocation.valueWidth).toBeGreaterThan(0);
    expect(allocation.gap).toBe(0);
    expect(allocation.used).toBeLessThanOrEqual(2);
  });

  it("gives an empty value no cells at all", () => {
    const allocation = allocateLabelValue({ available: 30, label: "runs", value: "" });
    expect(allocation.valueWidth).toBe(0);
    expect(allocation.gap).toBe(0);
    expect(allocation.labelWidth).toBe(4);
    expect(allocation.used).toBe(4);
  });

  it("clamps the caption when asked to", () => {
    const allocation = allocateLabelValue({
      available: 40,
      label: "a very long caption",
      value: "7",
      labelMax: 6,
    });
    expect(allocation.labelWidth).toBe(6);
  });
});

describe("fitRows", () => {
  const HEIGHTS = Array.from({ length: 101 }, (_, index) => index);

  it("never lets a box be taller than the rows it was given", () => {
    for (const available of HEIGHTS) {
      for (const chrome of [0, 1, 2, 4, 6]) {
        for (const rowsPerItem of [1, 2, 3]) {
          for (const items of [0, 1, 3, 9, 40]) {
            for (const maxShare of [undefined, 0.45, 1, 0]) {
              const fit = fitRows({ available, chrome, rowsPerItem, items, maxShare });
              expect(
                fit.boxHeight,
                `box ${fit.boxHeight} > available ${available} ` +
                  `(chrome ${chrome}, per ${rowsPerItem}, items ${items}, share ${maxShare})`,
              ).toBeLessThanOrEqual(available);
              expect(Number.isInteger(fit.boxHeight)).toBe(true);
              expect(Number.isInteger(fit.visible)).toBe(true);
              expect(fit.boxHeight).toBeGreaterThanOrEqual(0);
              expect(fit.visible).toBeGreaterThanOrEqual(0);
              expect(fit.visible).toBeLessThanOrEqual(items);
              expect(fit.itemRows).toBe(fit.visible * rowsPerItem);
              expect(fit.boxHeight).toBe(fit.visible > 0 ? chrome + fit.itemRows : 0);
              expect(fit.overflow).toBe(items - fit.visible);
              expect(fit.fits).toBe(fit.visible >= items);
            }
          }
        }
      }
    }
  });

  it("honours maxShare so the region above the box keeps real rows", () => {
    for (const available of HEIGHTS) {
      const fit = fitRows({ available, chrome: 4, rowsPerItem: 1, items: 100, maxShare: 0.45 });
      expect(fit.boxHeight).toBeLessThanOrEqual(Math.floor(available * 0.45));
    }
  });

  it("degrades instead of throwing on nonsense", () => {
    for (const available of [-10, Number.NaN, Number.POSITIVE_INFINITY, 7.6]) {
      for (const rowsPerItem of [0, -1, Number.NaN, 2.5]) {
        expect(() =>
          fitRows({
            available: available as number,
            chrome: -3,
            rowsPerItem: rowsPerItem as number,
            items: -4,
          }),
        ).not.toThrow();
        const fit = fitRows({
          available: available as number,
          chrome: -3,
          rowsPerItem: rowsPerItem as number,
          items: -4,
        });
        expect(fit.boxHeight).toBeLessThanOrEqual(toCells(available));
        expect(fit.visible).toBeGreaterThanOrEqual(0);
      }
    }
  });

  it("renders nothing rather than a box whose border crosses its content", () => {
    // Four rows of chrome (two borders, a title, a hint footer) simply do not
    // fit in three rows. The old code drew the box anyway, which is how the
    // command menu's bottom border ended up painted through "/clear" and
    // "/new" as "-/clear--------/new-".
    const fit = fitRows({ available: 3, chrome: 4, rowsPerItem: 2, items: 9 });
    expect(fit.visible).toBe(0);
    expect(fit.boxHeight).toBe(0);
    expect(fit.overflow).toBe(9);
    expect(fit.fits).toBe(false);
  });

  it("fills the height exactly when the items divide evenly", () => {
    const fit = fitRows({ available: 12, chrome: 4, rowsPerItem: 2, items: 9 });
    expect(fit.visible).toBe(4);
    expect(fit.boxHeight).toBe(12);
    expect(fit.overflow).toBe(5);
  });

  it("caps the item count independently of the height", () => {
    const fit = fitRows({ available: 100, chrome: 2, rowsPerItem: 1, items: 40, maxItems: 6 });
    expect(fit.visible).toBe(6);
    expect(fit.boxHeight).toBe(8);
  });

  it("treats minItems as a wish, never as a licence to overflow", () => {
    const roomy = fitRows({ available: 20, chrome: 2, rowsPerItem: 1, items: 9, minItems: 3 });
    expect(roomy.visible).toBe(9);

    const tight = fitRows({ available: 4, chrome: 2, rowsPerItem: 1, items: 9, minItems: 3 });
    expect(tight.visible).toBe(2);
    expect(tight.boxHeight).toBeLessThanOrEqual(4);

    const impossible = fitRows({ available: 2, chrome: 4, rowsPerItem: 1, items: 9, minItems: 3 });
    expect(impossible.boxHeight).toBe(0);
  });
});

describe("toCells / textCells", () => {
  it("normalises every kind of nonsense to a non-negative integer", () => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, -1, -0.5, null, undefined, "12"]) {
      const cells = toCells(value);
      expect(Number.isInteger(cells)).toBe(true);
      expect(cells).toBeGreaterThanOrEqual(0);
    }
    expect(toCells(7.9)).toBe(7);
    expect(toCells(undefined, 4)).toBe(4);
  });

  it("measures the sanitised string, not the raw one", () => {
    expect(textCells("  runs  ")).toBe(4);
    expect(textCells("a\tb")).toBe(3);
    expect(textCells("\u001b[31mred\u001b[0m")).toBe(3);
  });
});
