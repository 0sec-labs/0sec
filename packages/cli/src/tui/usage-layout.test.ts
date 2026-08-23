import { describe, expect, it } from "vitest";

import type { ToolHealthSummary } from "@0sec/core";

import {
  buildUsageReport,
  clipUsageRows,
  computeKvLayout,
  computeMeterLayout,
  computeUsageLayout,
  computeUsageTitleLayout,
  costUsd,
  formatCost,
  formatTokenCount,
  readCurrentUsage,
  resolveRates,
  shellChromeRows,
  usageFooterHint,
  usageMeterBar,
  usageTitle,
  usageTitleMeta,
  type UsageLayout,
  type UsageReportRow,
  type UsageSnapshot,
} from "./usage-layout.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/** Every cell and row count a layout exposes, flattened for the sweep. */
function layoutNumbers(layout: UsageLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["pane.width", layout.pane.width],
    ["pane.innerWidth", layout.pane.innerWidth],
    ["pane.height", layout.pane.height],
    ["pane.bodyRows", layout.pane.bodyRows],
    ["kv.width", layout.kv.width],
    ["kv.labelWidth", layout.kv.labelWidth],
    ["kv.gap", layout.kv.gap],
    ["kv.valueWidth", layout.kv.valueWidth],
    ["meter.width", layout.meter.width],
    ["meter.barCells", layout.meter.barCells],
    ["meter.gap", layout.meter.gap],
    ["meter.captionWidth", layout.meter.captionWidth],
    ["visibleRows", layout.visibleRows],
  ];
}

// ---------------------------------------------------------------------------

describe("computeUsageLayout — the sweep", () => {
  /**
   * The invariant this whole module exists for: no allocation may exceed the
   * container it was carved out of, on either axis, at any terminal size. Yoga
   * does not clip — a row of siblings claiming more cells than the row has is
   * shrunk, not truncated, and every sibling paints its full string into a box
   * that is now too small. A box claiming more rows than its column has paints
   * its own bottom border through its last line. Both are silent at compile time.
   */
  it("never lets the pane, a row or a column exceed what it was given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeUsageLayout({ width, height });
        const at = `${width}x${height}`;

        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
        }

        // -- horizontal --
        expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
          Math.max(0, width),
        );
        expect(layout.pane.width, `pane wider than content at ${at}`).toBeLessThanOrEqual(
          layout.contentWidth,
        );

        // -- key/value row columns --
        const kv = layout.kv;
        expect(kv.width, `kv row wider than the pane at ${at}`).toBe(layout.pane.innerWidth);
        expect(
          kv.labelWidth + kv.gap + kv.valueWidth,
          `kv claimed ${kv.labelWidth + kv.gap + kv.valueWidth} of ${kv.width} at ${at}`,
        ).toBe(kv.width);
        if (kv.valueWidth > 0) {
          expect(kv.gap, `kv value had no gap at ${at}`).toBe(1);
          expect(kv.labelWidth, `kv label squeezed out at ${at}`).toBeGreaterThan(0);
        }

        // -- meter row columns --
        const meter = layout.meter;
        expect(meter.width, `meter row wider than the pane at ${at}`).toBe(layout.pane.innerWidth);
        expect(
          meter.barCells + meter.gap + meter.captionWidth,
          `meter claimed ${meter.barCells + meter.gap + meter.captionWidth} of ${meter.width} at ${at}`,
        ).toBe(meter.width);
        if (meter.barCells > 0 && meter.captionWidth > 0) {
          expect(meter.gap, `meter bar had no gap at ${at}`).toBe(1);
        }

        // -- vertical --
        expect(layout.pane.height, `pane taller than the body at ${at}`).toBeLessThanOrEqual(
          layout.bodyRows,
        );
        expect(
          layout.visibleRows,
          `visibleRows exceeded the pane body at ${at}`,
        ).toBeLessThanOrEqual(layout.pane.bodyRows);

        // A rendered pane always has room for at least one row of content and
        // one cell of text; a pane below that is dropped, because a box one row
        // short of its content is corruption and an absent box is merely missing.
        if (layout.pane.width > 0) {
          expect(layout.pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
        }
        if (layout.pane.height > 0) {
          expect(layout.pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
          const chromeRows = (layout.bordered ? 2 : 0) + 1;
          expect(layout.pane.height - layout.pane.bodyRows, `pane chrome miscounted at ${at}`).toBe(
            chromeRows,
          );
          expect(layout.pane.width - layout.pane.innerWidth).toBe(layout.bordered ? 4 : 0);
        }
      }
    }
  });

  it("keeps the body inside the terminal once the shell has taken its chrome", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeUsageLayout({ width, height });
        expect(
          layout.bodyRows + shellChromeRows(width),
          `body plus chrome overflowed ${width}x${height}`,
        ).toBeLessThanOrEqual(Math.max(height, shellChromeRows(width)));
      }
    }
  });

  it("survives garbage geometry without throwing or producing garbage", () => {
    for (const width of [Number.NaN, Number.POSITIVE_INFINITY, -100, 0.5, -0]) {
      for (const height of [Number.NaN, Number.POSITIVE_INFINITY, -100, 0.5, -0]) {
        const layout = computeUsageLayout({ width, height });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${width}x${height}`).toBe(true);
        }
      }
    }
  });

  it("drops the pane border before it drops rows of content", () => {
    const tall = computeUsageLayout({ width: 100, height: 40 });
    const short = computeUsageLayout({ width: 100, height: 14 });
    expect(tall.bordered).toBe(true);
    expect(short.bordered).toBe(false);
    // Borderless panes hand the four horizontal chrome cells back to the text.
    expect(short.pane.innerWidth).toBe(short.pane.width);
  });

  it("gives more report rows to a taller terminal", () => {
    const short = computeUsageLayout({ width: 100, height: 24 });
    const tall = computeUsageLayout({ width: 100, height: 60 });
    expect(tall.visibleRows).toBeGreaterThan(short.visibleRows);
  });

  it("fits both reference terminal sizes without overflow", () => {
    for (const [width, height] of [
      [80, 24],
      [120, 40],
    ] as const) {
      const layout = computeUsageLayout({ width, height });
      expect(layout.pane.width).toBeLessThanOrEqual(layout.contentWidth);
      expect(layout.pane.height).toBeLessThanOrEqual(layout.bodyRows);
      expect(layout.kv.labelWidth + layout.kv.gap + layout.kv.valueWidth).toBe(layout.pane.innerWidth);
    }
  });
});

// ---------------------------------------------------------------------------

describe("computeKvLayout / computeMeterLayout", () => {
  it("splits a key/value row into label and value that sum to the width", () => {
    for (let inner = 0; inner <= 120; inner++) {
      const kv = computeKvLayout(inner);
      expect(kv.labelWidth + kv.gap + kv.valueWidth).toBe(kv.width);
      expect(kv.width).toBe(Math.max(0, Math.trunc(inner)));
    }
  });

  it("gives the value column its own cells on a wide row", () => {
    const kv = computeKvLayout(60);
    expect(kv.valueWidth).toBeGreaterThan(0);
    expect(kv.labelWidth).toBeGreaterThan(0);
    expect(kv.gap).toBe(1);
  });

  it("drops the value column before the label on a narrow row", () => {
    const kv = computeKvLayout(8);
    expect(kv.valueWidth).toBe(0);
    expect(kv.gap).toBe(0);
    expect(kv.labelWidth).toBe(8);
  });

  it("splits a meter row into a bar and caption that sum to the width", () => {
    for (let inner = 0; inner <= 120; inner++) {
      const meter = computeMeterLayout(inner);
      expect(meter.barCells + meter.gap + meter.captionWidth).toBe(meter.width);
    }
  });

  it("drops the bar before the caption on a narrow meter row", () => {
    expect(computeMeterLayout(10).barCells).toBe(0);
    expect(computeMeterLayout(60).barCells).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------

describe("usageMeterBar", () => {
  it("is always exactly the requested number of cells", () => {
    for (const cellCount of [0, 1, 6, 12, 24]) {
      for (const fraction of [-1, 0, 0.25, 0.5, 0.999, 1, 2, Number.NaN]) {
        expect(usageMeterBar(fraction, cellCount).length).toBe(Math.max(0, cellCount));
      }
    }
  });

  it("fills proportionally and never over- or under-runs", () => {
    expect(usageMeterBar(0, 6)).toBe("▱▱▱▱▱▱");
    expect(usageMeterBar(1, 6)).toBe("▰▰▰▰▰▰");
    expect(usageMeterBar(0.5, 6)).toBe("▰▰▰▱▱▱");
    // A rounding artefact can never paint a seventh cell or a negative one.
    expect(usageMeterBar(1.4, 6)).toBe("▰▰▰▰▰▰");
    expect(usageMeterBar(-0.4, 6)).toBe("▱▱▱▱▱▱");
  });
});

// ---------------------------------------------------------------------------

describe("cost resolution (mirrors status-bar.ts)", () => {
  it("resolves a priced model and prices its usage", () => {
    const rates = resolveRates("claude-sonnet-4-6");
    expect(rates).toBeDefined();
    const usd = costUsd({ inputTokens: 1_000_000, outputTokens: 0 }, rates!);
    expect(usd).toBeCloseTo(rates!.input, 5);
  });

  it("strips a vendor prefix, case-insensitively", () => {
    expect(resolveRates("anthropic/claude-sonnet-4-6")).toEqual(resolveRates("claude-sonnet-4-6"));
    expect(resolveRates("CLAUDE-SONNET-4-6")).toEqual(resolveRates("claude-sonnet-4-6"));
  });

  it("returns undefined for an unknown model rather than the fallback rate", () => {
    expect(resolveRates("not-a-real-model")).toBeUndefined();
    expect(resolveRates("default")).toBeUndefined();
    expect(resolveRates(undefined)).toBeUndefined();
  });

  it("prices cached input at the cached rate", () => {
    const rates = { input: 10, output: 30, cachedInput: 1 };
    const usd = costUsd({ inputTokens: 1_000_000, outputTokens: 0, cachedInputTokens: 1_000_000 }, rates);
    // All input was cached, so the cost is the cached rate, not the input rate.
    expect(usd).toBeCloseTo(1, 5);
  });

  it("formats cost with the sub-cent and zero conventions", () => {
    expect(formatCost(1.234)).toBe("$1.23");
    expect(formatCost(0.001)).toBe("<$0.01");
    expect(formatCost(0)).toBe("$0.00");
    expect(formatCost(-5)).toBe("$0.00");
  });

  it("formats token counts compactly", () => {
    expect(formatTokenCount(999)).toBe("999");
    expect(formatTokenCount(12_300)).toBe("12.3k");
    expect(formatTokenCount(1_200_000)).toBe("1.2M");
  });
});

// ---------------------------------------------------------------------------

const textOf = (rows: UsageReportRow[]): string =>
  rows.map((row) => `${row.label ?? ""} ${row.value ?? ""}`).join("\n");

describe("buildUsageReport", () => {
  it("returns an empty snapshot from the lazy default and never fabricates", () => {
    const rows = buildUsageReport(readCurrentUsage());
    const text = textOf(rows);
    // Every section header is present, so the screen has a stable shape.
    for (const section of ["CONTEXT", "TOKENS", "COST", "MODEL", "TOOL HEALTH"]) {
      expect(text).toContain(section);
    }
    // No invented numbers: unknown counts read as em-dashes, cost as "$—".
    expect(text).toContain("—");
    expect(text).toContain("$—");
    // No context meter without both a window and a reading.
    expect(rows.some((row) => row.kind === "meter")).toBe(false);
  });

  it("renders a context meter only when both window and usage are present", () => {
    const withBoth = buildUsageReport({ contextUsed: 50_000, contextWindow: 200_000 });
    const meter = withBoth.find((row) => row.kind === "meter");
    expect(meter).toBeDefined();
    expect(meter?.fraction).toBeCloseTo(0.25, 5);
    expect(meter?.value).toContain("25%");
    // A window with no reading produces no meter.
    expect(buildUsageReport({ contextWindow: 200_000 }).some((r) => r.kind === "meter")).toBe(false);
    expect(buildUsageReport({ contextUsed: 50_000 }).some((r) => r.kind === "meter")).toBe(false);
  });

  it("turns the context reading red only when over budget", () => {
    expect(buildUsageReport({ contextUsed: 10, contextWindow: 100 }).find((r) => r.kind === "meter")?.tone).toBe("ok");
    expect(buildUsageReport({ contextUsed: 90, contextWindow: 100 }).find((r) => r.kind === "meter")?.tone).toBe("warn");
    expect(buildUsageReport({ contextUsed: 100, contextWindow: 100 }).find((r) => r.kind === "meter")?.tone).toBe("error");
    expect(buildUsageReport({ contextUsed: 250, contextWindow: 100 }).find((r) => r.kind === "meter")?.tone).toBe("error");
  });

  it("shows turn and session token totals side by side", () => {
    const rows = buildUsageReport({
      turn: { inputTokens: 1000, outputTokens: 200 },
      session: { inputTokens: 5000, outputTokens: 900 },
    });
    const input = rows.find((row) => row.kind === "kv" && row.label === "input");
    expect(input?.value).toBe("1k / 5k");
    const output = rows.find((row) => row.kind === "kv" && row.label === "output");
    expect(output?.value).toBe("200 / 900");
  });

  it("only shows a reasoning row when reasoning tokens were tracked", () => {
    const without = buildUsageReport({ session: { inputTokens: 100, outputTokens: 10 } });
    expect(without.some((row) => row.label === "reasoning")).toBe(false);
    const withReasoning = buildUsageReport({
      session: { inputTokens: 100, outputTokens: 10, reasoningTokens: 42 },
    });
    expect(withReasoning.some((row) => row.label === "reasoning")).toBe(true);
  });

  it("prices the session against the active model, or says $— when unpriced", () => {
    const priced = buildUsageReport({
      model: "claude-sonnet-4-6",
      session: { inputTokens: 1_000_000, outputTokens: 0 },
    });
    const estimate = priced.find((row) => row.label === "session estimate");
    expect(estimate?.value).toMatch(/^\$\d/);

    const unpriced = buildUsageReport({
      model: "some-unlisted-model",
      session: { inputTokens: 1_000_000, outputTokens: 0 },
    });
    expect(unpriced.find((row) => row.label === "session estimate")?.value).toBe("$—");
  });

  it("prices per-model when the session used more than one model", () => {
    const rows = buildUsageReport({
      perModel: [
        { model: "claude-sonnet-4-6", inputTokens: 1_000_000, outputTokens: 0 },
        { model: "some-unlisted-model", inputTokens: 1_000_000, outputTokens: 0 },
      ],
    });
    expect(rows.find((row) => row.label === "claude-sonnet-4-6")?.value).toMatch(/^\$\d/);
    expect(rows.find((row) => row.label === "some-unlisted-model")?.value).toBe("$—");
    // With an unpriced model in the mix the total cannot be honestly summed.
    expect(rows.find((row) => row.label === "total")?.value).toBe("$—");
  });

  it("sums a per-model total when every model is priced", () => {
    const rows = buildUsageReport({
      perModel: [
        { model: "claude-sonnet-4-6", inputTokens: 1_000_000, outputTokens: 0 },
        { model: "claude-haiku-4-5", inputTokens: 1_000_000, outputTokens: 0 },
      ],
    });
    const total = rows.find((row) => row.label === "total");
    expect(total?.value).toMatch(/^\$\d/);
    expect(total?.value).not.toBe("$—");
  });

  it("names the active model and derives its provider", () => {
    const rows = buildUsageReport({ model: "claude-sonnet-4-6" });
    expect(rows.find((row) => row.label === "active")?.value).toBe("claude-sonnet-4-6");
    expect(rows.find((row) => row.label === "provider")?.value).toBe("anthropic");
  });

  it("summarises tool health, or says there are no issues", () => {
    const clean = buildUsageReport({});
    expect(textOf(clean)).toContain("no tool issues");

    const summary: ToolHealthSummary = {
      total: 2,
      occurrences: 3,
      byCategory: { "missing-binary": 1, "wrong-lockfile": 1 },
      missing: ["semgrep"],
      line: "2 tool issues (missing: semgrep; wrong-lockfile: run_command)",
      events: [
        {
          tool: "semgrep",
          category: "missing-binary",
          message: "not on PATH",
          count: 1,
          firstSeen: 0,
          lastSeen: 1,
        },
        {
          tool: "run_command",
          category: "wrong-lockfile",
          message: "npm audit on a pnpm repo",
          count: 2,
          firstSeen: 0,
          lastSeen: 2,
        },
      ],
    };
    const rows = buildUsageReport({ toolHealth: summary });
    const text = textOf(rows);
    expect(text).toContain("2 tool issues");
    expect(text).toContain("semgrep");
    expect(text).toContain("run_command");
    // A repeated event carries its occurrence count.
    expect(text).toContain("x2");
    expect(text).not.toContain("no tool issues");
  });
});

// ---------------------------------------------------------------------------

describe("clipUsageRows", () => {
  const rows = buildUsageReport({
    model: "claude-sonnet-4-6",
    contextUsed: 50_000,
    contextWindow: 200_000,
    session: { inputTokens: 1000, outputTokens: 200 },
  });

  it("keeps every row when they all fit", () => {
    expect(clipUsageRows(rows, rows.length + 5)).toHaveLength(rows.length);
  });

  it("clips to the pane and marks the cut", () => {
    const clipped = clipUsageRows(rows, 5);
    expect(clipped).toHaveLength(5);
    expect(clipped.at(-1)?.label).toContain("more");
    expect(clipUsageRows(rows, 0)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------

describe("computeUsageTitleLayout — the header sweep", () => {
  it("splits the header into a title and meta that sum to the width", () => {
    for (let inner = 0; inner <= 120; inner++) {
      for (const metaLength of [0, 1, 4, 12, 30, 200]) {
        const title = computeUsageTitleLayout(inner, metaLength);
        const at = `inner ${inner}, meta ${metaLength}`;
        expect(title.width, `header wider than the pane at ${at}`).toBe(Math.max(0, inner));
        expect(
          title.titleWidth + title.gap + title.metaWidth,
          `header claimed ${title.titleWidth + title.gap + title.metaWidth} of ${title.width} at ${at}`,
        ).toBe(title.width);
        expect(title.metaWidth).toBeLessThanOrEqual(Math.max(0, metaLength));
        if (title.metaWidth > 0) {
          expect(title.gap, `meta had no gap at ${at}`).toBe(1);
          expect(title.titleWidth, `title squeezed out at ${at}`).toBeGreaterThan(0);
        }
      }
    }
  });

  it("gives the meta its own cells on a wide header and drops it on a narrow one", () => {
    const wide = computeUsageTitleLayout(60, 12);
    expect(wide.metaWidth).toBe(12);
    expect(wide.titleWidth).toBeGreaterThan(0);
    expect(wide.gap).toBe(1);
    const narrow = computeUsageTitleLayout(6, 12);
    expect(narrow.metaWidth).toBe(0);
    expect(narrow.gap).toBe(0);
    expect(narrow.titleWidth).toBe(6);
  });
});

describe("usageTitleMeta", () => {
  it("prices a session summary against the active model", () => {
    const meta = usageTitleMeta({
      model: "claude-sonnet-4-6",
      session: { inputTokens: 1_000_000, outputTokens: 0 },
    });
    expect(meta).toMatch(/^\$\d.* session$/);
  });

  it("falls back to the model name when the session is unpriced or empty", () => {
    expect(usageTitleMeta({ model: "some-unlisted-model", session: { inputTokens: 1 } })).toBe(
      "some-unlisted-model",
    );
    expect(usageTitleMeta({ model: "claude-sonnet-4-6" })).toBe("claude-sonnet-4-6");
    expect(usageTitleMeta({})).toBe("");
  });

  it("sums a per-model total when every model is priced", () => {
    const meta = usageTitleMeta({
      perModel: [
        { model: "claude-sonnet-4-6", inputTokens: 1_000_000, outputTokens: 0 },
        { model: "claude-haiku-4-5", inputTokens: 1_000_000, outputTokens: 0 },
      ],
    });
    expect(meta).toMatch(/^\$\d.* session$/);
  });
});

describe("titles and hints", () => {
  it("titles the pane", () => {
    expect(usageTitle()).toBe("SESSION USAGE");
  });

  it("names only the keys this read-only screen actually handles", () => {
    const hint = usageFooterHint();
    for (const fragment of ["esc back", "ctrl+c exit"]) expect(hint).toContain(fragment);
    // The screen's keyboard only handles esc and ctrl+c, so it must not name a
    // history binding it does not implement.
    expect(hint).not.toContain("history");
  });

  it("accepts a fully-typed snapshot", () => {
    const snapshot: UsageSnapshot = {
      model: "claude-sonnet-4-6",
      provider: "anthropic",
      session: { inputTokens: 1, outputTokens: 1, cachedInputTokens: 0, reasoningTokens: 0 },
      turn: { inputTokens: 1, outputTokens: 1 },
      contextUsed: 1,
      contextWindow: 2,
    };
    expect(() => buildUsageReport(snapshot)).not.toThrow();
  });
});
