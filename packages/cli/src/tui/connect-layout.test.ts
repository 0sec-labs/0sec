import { describe, expect, it } from "vitest";

import {
  RECOMMENDED_IDS,
  authHintLabel,
  authKindFor,
  buildConnectRows,
  clampSelection,
  clipConnectDetailLines,
  computeConnectLayout,
  computeConnectTitleLayout,
  computeConnectWindow,
  connectDetailLines,
  connectDetailTitleLabel,
  connectDetailTitleMeta,
  connectFooterHint,
  connectInputMask,
  connectListMeta,
  connectListTitle,
  connectListTitleLabel,
  connectStatusLine,
  firstSelectableIndex,
  hasAnyConnection,
  indexOfProvider,
  isFilterKey,
  isInputKey,
  lastSelectableIndex,
  moveSelection,
  pastableChars,
  shellChromeRows,
  type ConnectLayout,
  type ConnectRow,
} from "./connect-layout.js";
import { PROVIDERS, providerStates } from "./provider-status.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/**
 * A swept axis: every `step`th value in `[min, max]`, plus the boundary sizes
 * (`min`, `min+1`, `min+2`, `max`) always tested explicitly. This keeps the
 * small/edge and large-end coverage of a dense 0..max loop while running a
 * fraction of the iterations.
 */
const sweepAxis = (min: number, max: number, step: number): number[] => {
  const seen = new Set<number>([min, min + 1, min + 2, max]);
  for (let v = min; v <= max; v += step) seen.add(v);
  return [...seen].filter((v) => v >= min && v <= max).sort((a, b) => a - b);
};

const EMPTY = providerStates({});
const LIT_PROVIDER = PROVIDERS.find((info) => info.id === "anthropic") ?? PROVIDERS[0];
const LIT = providerStates({ [LIT_PROVIDER?.envVars[0] ?? "ANTHROPIC_API_KEY"]: "sk-test" });

function layoutNumbers(layout: ConnectLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["paneGap", layout.paneGap],
    ["list.width", layout.list.width],
    ["list.innerWidth", layout.list.innerWidth],
    ["list.height", layout.list.height],
    ["list.bodyRows", layout.list.bodyRows],
    ["detail.width", layout.detail.width],
    ["detail.innerWidth", layout.detail.innerWidth],
    ["detail.height", layout.detail.height],
    ["detail.bodyRows", layout.detail.bodyRows],
    ["row.width", layout.row.width],
    ["row.markerWidth", layout.row.markerWidth],
    ["row.markerGap", layout.row.markerGap],
    ["row.checkWidth", layout.row.checkWidth],
    ["row.checkGap", layout.row.checkGap],
    ["row.labelWidth", layout.row.labelWidth],
    ["row.authGap", layout.row.authGap],
    ["row.authWidth", layout.row.authWidth],
    ["heading.width", layout.heading.width],
    ["heading.labelWidth", layout.heading.labelWidth],
    ["heading.gap", layout.heading.gap],
    ["heading.stateWidth", layout.heading.stateWidth],
    ["visibleRows", layout.visibleRows],
  ];
}

// ---------------------------------------------------------------------------

describe("computeConnectLayout — the sweep", () => {
  it("never lets a pane, a row or a column exceed what it was given", () => {
    for (const width of sweepAxis(0, 200, 3)) {
      for (const height of sweepAxis(0, 80, 2)) {
        for (const noticeRows of [0, 1]) {
          const layout = computeConnectLayout({ width, height, noticeRows });
          const at = `${width}x${height} (notice ${noticeRows})`;

          for (const [name, value] of layoutNumbers(layout)) {
            expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
          }

          // -- horizontal --
          expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
            Math.max(0, width),
          );
          if (layout.stacked) {
            expect(layout.list.width).toBeLessThanOrEqual(layout.contentWidth);
            expect(layout.detail.width).toBeLessThanOrEqual(layout.contentWidth);
            expect(layout.paneGap, `stacked panes had a gap at ${at}`).toBe(0);
          } else {
            const claimed = layout.list.width + layout.paneGap + layout.detail.width;
            expect(
              claimed,
              `panes claimed ${claimed} of ${layout.contentWidth} at ${at}`,
            ).toBeLessThanOrEqual(layout.contentWidth);
          }

          // -- list row columns sum EXACTLY to the row width --
          const row = layout.row;
          expect(row.width, `row wider than the list pane at ${at}`).toBe(layout.list.innerWidth);
          const rowClaimed =
            row.markerWidth +
            row.markerGap +
            row.checkWidth +
            row.checkGap +
            row.labelWidth +
            row.authGap +
            row.authWidth;
          expect(rowClaimed, `row claimed ${rowClaimed} of ${row.width} at ${at}`).toBe(row.width);

          // -- heading columns sum EXACTLY --
          const heading = layout.heading;
          expect(heading.width).toBe(layout.list.innerWidth);
          const headingClaimed = heading.labelWidth + heading.gap + heading.stateWidth;
          expect(
            headingClaimed,
            `heading claimed ${headingClaimed} of ${heading.width} at ${at}`,
          ).toBe(heading.width);
          if (heading.stateWidth > 0) {
            expect(heading.gap).toBe(1);
            expect(heading.labelWidth).toBeGreaterThan(0);
          }

          // -- vertical --
          expect(layout.list.height).toBeLessThanOrEqual(layout.bodyRows);
          expect(layout.detail.height).toBeLessThanOrEqual(layout.bodyRows);
          if (layout.stacked) {
            const rows = layout.list.height + layout.detail.height;
            expect(
              rows,
              `stacked panes claimed ${rows} of ${layout.bodyRows} rows at ${at}`,
            ).toBeLessThanOrEqual(layout.bodyRows);
          }
          expect(layout.visibleRows).toBeLessThanOrEqual(layout.list.bodyRows);

          for (const pane of [layout.list, layout.detail]) {
            if (pane.width > 0) expect(pane.innerWidth).toBeGreaterThan(0);
            if (pane.height > 0) expect(pane.bodyRows).toBeGreaterThan(0);
            expect(pane.innerWidth).toBeLessThanOrEqual(pane.width);
            expect(pane.bodyRows).toBeLessThanOrEqual(pane.height);
            if (pane.height > 0) {
              const paneChromeRows = (layout.bordered ? 2 : 0) + (pane.hasTitle ? 1 : 0);
              expect(pane.height - pane.bodyRows, `pane chrome miscounted at ${at}`).toBe(
                paneChromeRows,
              );
              expect(pane.width - pane.innerWidth).toBe(layout.bordered ? 4 : 0);
            }
          }
        }
      }
    }
  });

  it("keeps the body inside the terminal once the shell has taken its chrome", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeConnectLayout({ width, height, noticeRows: 1 });
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
        const layout = computeConnectLayout({ width, height });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${width}x${height}`).toBe(true);
        }
      }
    }
  });

  it("stacks the detail pane under the list on a narrow terminal, beside on a wide one", () => {
    expect(computeConnectLayout({ width: 60, height: 40 }).stacked).toBe(true);
    expect(computeConnectLayout({ width: 79, height: 40 }).stacked).toBe(true);
    expect(computeConnectLayout({ width: 80, height: 40 }).stacked).toBe(false);
    const wide = computeConnectLayout({ width: 120, height: 40 });
    expect(wide.paneGap).toBe(1);
    expect(wide.list.width + wide.paneGap + wide.detail.width).toBe(wide.contentWidth);
  });

  it("drops pane borders before it drops rows of content", () => {
    expect(computeConnectLayout({ width: 120, height: 40 }).bordered).toBe(true);
    const short = computeConnectLayout({ width: 120, height: 16 });
    expect(short.bordered).toBe(false);
    expect(short.detailCompact).toBe(true);
    expect(short.list.innerWidth).toBe(short.list.width);
  });

  it("degrades the row one column at a time as the pane narrows", () => {
    const at = (innerWidth: number) => computeConnectLayout({ width: innerWidth + 4, height: 40 }).row;
    const wide = at(120);
    expect(wide.markerWidth).toBe(1);
    expect(wide.checkWidth).toBe(1);
    expect(wide.authWidth).toBeGreaterThan(0);

    let sawNoAuth = false;
    let sawNoCheck = false;
    for (let innerWidth = 60; innerWidth >= 1; innerWidth--) {
      const row = at(innerWidth);
      if (row.authWidth === 0) sawNoAuth = true;
      if (row.checkWidth === 0) sawNoCheck = true;
      if (sawNoCheck) expect(row.authWidth, `auth outlived the check at ${innerWidth}`).toBe(0);
      if (row.width > 0) expect(row.labelWidth, `label vanished at ${innerWidth}`).toBeGreaterThan(0);
    }
    expect(sawNoAuth).toBe(true);
    expect(sawNoCheck).toBe(true);
  });

  it("spends a row on the status line only when there is one", () => {
    const quiet = computeConnectLayout({ width: 120, height: 40, noticeRows: 0 });
    const noisy = computeConnectLayout({ width: 120, height: 40, noticeRows: 1 });
    expect(noisy.bodyRows).toBe(quiet.bodyRows - 1);
  });
});

// ---------------------------------------------------------------------------

describe("computeConnectTitleLayout — the header sweep", () => {
  it("splits a header into a title and meta that sum to the width", () => {
    for (let inner = 0; inner <= 120; inner++) {
      for (const metaLength of [0, 1, 3, 12, 30, 200]) {
        const title = computeConnectTitleLayout(inner, metaLength);
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
    const wide = computeConnectTitleLayout(60, 12);
    expect(wide.metaWidth).toBe(12);
    expect(wide.titleWidth).toBeGreaterThan(0);
    expect(wide.gap).toBe(1);
    const narrow = computeConnectTitleLayout(6, 12);
    expect(narrow.metaWidth).toBe(0);
    expect(narrow.gap).toBe(0);
    expect(narrow.titleWidth).toBe(6);
  });
});

describe("pane header labels and meta", () => {
  const rows = buildConnectRows({ states: LIT });

  it("keeps a stable left label and a count/window meta for the list header", () => {
    expect(connectListTitleLabel()).toBe("PROVIDERS");
    const whole = computeConnectWindow({ rows, selected: 1, visible: rows.length });
    expect(connectListMeta(whole)).toBe(String(rows.length));
    // The label and meta recombine into the single-string title callers use.
    expect(connectListTitle(whole)).toBe(`PROVIDERS ${rows.length}`);
    const scrolled = computeConnectWindow({ rows, selected: 5, visible: 4, anchor: 3 });
    expect(connectListMeta(scrolled)).toMatch(/^\d+-\d+\/\d+$/);
    expect(connectListMeta(computeConnectWindow({ rows: [], selected: -1, visible: 4 }))).toBe("0");
  });

  it("summarises the highlighted provider's connection state for the detail header", () => {
    expect(connectDetailTitleLabel()).toBe("PROVIDER");
    const connected = rows.find(
      (r) => r.kind === "provider" && r.provider.id === LIT_PROVIDER?.id,
    );
    expect(connectDetailTitleMeta(connected)).toBe("connected");
    const dark = rows.find((r) => r.kind === "provider" && !r.provider.connected);
    expect(connectDetailTitleMeta(dark)).toBe("not connected");
    // No provider highlighted -> no meta.
    expect(connectDetailTitleMeta(rows.find((r) => r.kind === "heading"))).toBe("");
    expect(connectDetailTitleMeta(undefined)).toBe("");
  });
});

describe("buildConnectRows", () => {
  it("puts a Popular group first, then All providers, with disjoint membership", () => {
    const rows = buildConnectRows({ states: EMPTY });
    const headings = rows.filter(
      (row): row is Extract<ConnectRow, { kind: "heading" }> => row.kind === "heading",
    );
    expect(headings.map((row) => row.group.id)).toEqual(["popular", "all"]);

    const popular = rows
      .filter((row) => row.kind === "provider" && row.group.id === "popular")
      .map((row) => (row.kind === "provider" ? row.provider.id : ""));
    const all = rows
      .filter((row) => row.kind === "provider" && row.group.id === "all")
      .map((row) => (row.kind === "provider" ? row.provider.id : ""));

    expect(popular).toEqual(RECOMMENDED_IDS.filter((id) => PROVIDERS.some((p) => p.id === id)));
    // Disjoint, and together they cover every provider exactly once.
    expect(popular.filter((id) => all.includes(id))).toEqual([]);
    expect(new Set([...popular, ...all])).toEqual(new Set(PROVIDERS.map((p) => p.id)));
  });

  it("leads the Popular group with the recommended subscription option", () => {
    const rows = buildConnectRows({ states: EMPTY });
    const firstProvider = rows.find((row) => row.kind === "provider");
    expect(firstProvider?.kind).toBe("provider");
    if (firstProvider?.kind === "provider") {
      expect(firstProvider.provider.id).toBe(RECOMMENDED_IDS[0]);
      expect(firstProvider.provider.auth).toBe("subscription");
    }
  });

  it("emits a subtitle row under recommended providers that have one", () => {
    const rows = buildConnectRows({ states: EMPTY });
    const at = indexOfProvider(rows, RECOMMENDED_IDS[0]);
    expect(rows[at + 1]?.kind).toBe("subtitle");
    // Subtitles never appear in the All group.
    for (const row of rows) {
      if (row.kind === "subtitle") expect(row.group.id).toBe("popular");
    }
  });

  it("marks a provider connected when the environment holds a credential", () => {
    const rows = buildConnectRows({ states: LIT });
    const anthropic = rows.find(
      (row) => row.kind === "provider" && row.provider.id === LIT_PROVIDER?.id,
    );
    expect(anthropic?.kind).toBe("provider");
    if (anthropic?.kind === "provider") {
      expect(anthropic.provider.connected).toBe(true);
      expect(anthropic.provider.source).toBe("env");
      expect(anthropic.provider.via).toBe(LIT_PROVIDER?.envVars[0]);
    }
  });

  it("marks a provider connected when only the credential store holds it", () => {
    const rows = buildConnectRows({ states: EMPTY, stored: ["openai"] });
    const openai = rows.find((row) => row.kind === "provider" && row.provider.id === "openai");
    if (openai?.kind === "provider") {
      expect(openai.provider.connected).toBe(true);
      expect(openai.provider.source).toBe("stored");
    } else {
      throw new Error("openai row missing");
    }
  });

  it("prefers the environment source over the store when both hold a credential", () => {
    const rows = buildConnectRows({ states: LIT, stored: [LIT_PROVIDER?.id ?? ""] });
    const row = rows.find((r) => r.kind === "provider" && r.provider.id === LIT_PROVIDER?.id);
    if (row?.kind === "provider") expect(row.provider.source).toBe("env");
  });

  it("filters on id, label and auth hint, dropping empty headings", () => {
    const byLabel = buildConnectRows({ states: EMPTY, filter: "anthropic" });
    expect(byLabel.filter((row) => row.kind === "provider")).toHaveLength(1);
    // Every heading kept must have a provider under it.
    byLabel.forEach((row, index) => {
      if (row.kind === "heading") expect(byLabel[index + 1]?.kind).toBe("provider");
    });
    const bySubscription = buildConnectRows({ states: EMPTY, filter: "subscription" });
    expect(bySubscription.filter((row) => row.kind === "provider").length).toBeGreaterThan(0);
    for (const row of bySubscription) {
      if (row.kind === "provider") expect(row.provider.auth).toBe("subscription");
    }
    expect(buildConnectRows({ states: EMPTY, filter: "zzzznope" })).toEqual([]);
  });

  it("is stable for the same inputs", () => {
    expect(buildConnectRows({ states: LIT })).toEqual(buildConnectRows({ states: LIT }));
  });
});

// ---------------------------------------------------------------------------

describe("navigation", () => {
  const rows = buildConnectRows({ states: EMPTY });

  it("never lands on a heading or a subtitle, up or down through the list twice", () => {
    let index = firstSelectableIndex(rows);
    expect(rows[index]?.kind).toBe("provider");
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveSelection(rows, index, 1);
      expect(rows[index]?.kind, `down landed off a provider at step ${step}`).toBe("provider");
    }
    index = lastSelectableIndex(rows);
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveSelection(rows, index, -1);
      expect(rows[index]?.kind, `up landed off a provider at step ${step}`).toBe("provider");
    }
  });

  it("wraps from last to first and back", () => {
    const first = firstSelectableIndex(rows);
    const last = lastSelectableIndex(rows);
    expect(moveSelection(rows, last, 1)).toBe(first);
    expect(moveSelection(rows, first, -1)).toBe(last);
  });

  it("finds every provider by id and pulls stray selections onto a real row", () => {
    for (const info of PROVIDERS) {
      const at = indexOfProvider(rows, info.id);
      expect(at, `${info.id} unreachable`).toBeGreaterThanOrEqual(0);
      expect(rows[at]?.kind).toBe("provider");
    }
    expect(rows[clampSelection(rows, -50)]?.kind).toBe("provider");
    expect(clampSelection(rows, 9999)).toBe(lastSelectableIndex(rows));
    expect(rows[clampSelection(rows, Number.NaN)]?.kind).toBe("provider");
    expect(indexOfProvider(rows, undefined)).toBe(-1);
  });

  it("returns -1 for navigation over an empty list", () => {
    expect(firstSelectableIndex([])).toBe(-1);
    expect(clampSelection([], 3)).toBe(-1);
    expect(moveSelection([], 0, 1)).toBe(-1);
  });
});

// ---------------------------------------------------------------------------

describe("computeConnectWindow", () => {
  const rows = buildConnectRows({ states: EMPTY });

  it("keeps the highlighted row visible from any anchor at any capacity", () => {
    for (let visible = 0; visible <= rows.length + 4; visible++) {
      for (let selected = 0; selected < rows.length; selected++) {
        if (rows[selected]?.kind !== "provider") continue;
        for (const anchor of [0, 3, 7, rows.length, rows.length * 2]) {
          const win = computeConnectWindow({ rows, selected, visible, anchor });
          expect(win.count).toBeLessThanOrEqual(Math.max(0, visible));
          expect(win.count).toBe(win.end - win.start);
          expect(win.end).toBeLessThanOrEqual(rows.length);
          if (win.count === 0) continue;
          expect(
            selected >= win.start && selected < win.end,
            `row ${selected} outside ${win.start}..${win.end} (visible ${visible}, anchor ${anchor})`,
          ).toBe(true);
        }
      }
    }
  });

  it("brings the heading along when the cursor is the first provider of a group", () => {
    const headingIndex = rows.findIndex(
      (row, index) => row.kind === "heading" && rows[index + 1]?.kind === "provider" && index > 0,
    );
    if (headingIndex > 0) {
      const win = computeConnectWindow({
        rows,
        selected: headingIndex + 1,
        visible: 4,
        anchor: rows.length,
      });
      expect(win.start).toBe(headingIndex);
    }
  });

  it("titles the pane with the window it is showing", () => {
    expect(connectListTitle(computeConnectWindow({ rows, selected: 1, visible: rows.length }))).toBe(
      `PROVIDERS ${rows.length}`,
    );
    expect(
      connectListTitle(computeConnectWindow({ rows, selected: 5, visible: 4, anchor: 3 })),
    ).toMatch(/^PROVIDERS \d+-\d+\/\d+$/);
    expect(connectListTitle(computeConnectWindow({ rows: [], selected: -1, visible: 4 }))).toBe(
      "PROVIDERS 0",
    );
  });
});

// ---------------------------------------------------------------------------

describe("the detail pane", () => {
  const rows = buildConnectRows({ states: LIT });
  const textOf = (lines: { text: string }[]): string => lines.map((line) => line.text).join("\n");

  it("describes a connected provider with its live source", () => {
    const row = rows.find((r) => r.kind === "provider" && r.provider.id === LIT_PROVIDER?.id);
    const text = textOf(connectDetailLines({ row }, 60));
    expect(text).toContain(LIT_PROVIDER?.label ?? "");
    expect(text).toContain("Connected:");
    expect(text).toContain(LIT_PROVIDER?.envVars[0] ?? "");
  });

  it("gives the exact setup hint for a provider with no credentials", () => {
    const dark = PROVIDERS.find((info) => info.id !== LIT_PROVIDER?.id);
    const row = rows.find((r) => r.kind === "provider" && r.provider.id === dark?.id);
    const text = textOf(connectDetailLines({ row }, 80));
    expect(text).toContain("Not connected");
    for (const word of (dark?.hint ?? "").split(" ").slice(0, 3)) expect(text).toContain(word);
    expect(text).toContain(dark?.envVars[0] ?? "");
  });

  it("names the subscription path for the subscription provider", () => {
    const row = rows.find((r) => r.kind === "provider" && r.provider.auth === "subscription");
    const text = textOf(connectDetailLines({ row }, 80));
    expect(text.toLowerCase()).toContain("subscription");
  });

  it("keeps every detail line inside the pane it was measured for", () => {
    for (const row of rows) {
      for (const width of [0, 1, 8, 20, 30, 44, 56]) {
        for (const line of connectDetailLines({ row }, width)) {
          expect(line.text.length, `overflowed a ${width}-cell pane`).toBeLessThanOrEqual(width);
        }
      }
    }
    // Non-provider rows and empty input produce nothing.
    const heading = rows.find((row) => row.kind === "heading");
    expect(connectDetailLines({ row: heading }, 48)).toEqual([]);
    expect(connectDetailLines({}, 48)).toEqual([]);
  });

  it("spends no rows on blanks in compact mode", () => {
    const row = rows.find((r) => r.kind === "provider");
    const full = connectDetailLines({ row }, 40);
    const compact = connectDetailLines({ row, compact: true }, 40);
    expect(compact.some((line) => line.tone === "blank")).toBe(false);
    expect(compact.map((line) => line.text)).toEqual(
      full.filter((line) => line.tone !== "blank").map((line) => line.text),
    );
  });

  it("clips overflow and marks the cut", () => {
    const row = rows.find((r) => r.kind === "provider" && !r.provider.connected);
    const lines = connectDetailLines({ row }, 24);
    expect(lines.length).toBeGreaterThan(3);
    expect(clipConnectDetailLines(lines, 3)).toHaveLength(3);
    expect(clipConnectDetailLines(lines, 3).at(-1)?.text).toBe("...");
    expect(clipConnectDetailLines(lines, 0)).toEqual([]);
    expect(clipConnectDetailLines(lines, lines.length + 5)).toHaveLength(lines.length);
    const inline = clipConnectDetailLines(lines, 3, 24);
    expect(inline.at(-1)?.text.endsWith(" ...")).toBe(true);
    for (const line of inline) expect(line.text.length).toBeLessThanOrEqual(24);
  });
});

// ---------------------------------------------------------------------------

describe("connected reporting, masks and hints", () => {
  it("reports any connection across env and store", () => {
    expect(hasAnyConnection({ states: EMPTY })).toBe(false);
    expect(hasAnyConnection({ states: EMPTY, stored: [] })).toBe(false);
    expect(hasAnyConnection({ states: LIT })).toBe(true);
    expect(hasAnyConnection({ states: EMPTY, stored: ["openai"] })).toBe(true);
    expect(hasAnyConnection({ states: EMPTY, stored: new Set(["kimi"]) })).toBe(true);
  });

  it("summarises how many providers are connected", () => {
    expect(connectStatusLine(buildConnectRows({ states: EMPTY }))).toContain("no providers connected");
    const line = connectStatusLine(buildConnectRows({ states: LIT }));
    expect(line).toMatch(/connected: 1 of \d+ providers/);
    expect(connectStatusLine([])).toBe("no providers to connect");
  });

  it("never echoes the credential and caps the mask length it leaks", () => {
    expect(connectInputMask(0)).toBe("");
    expect(connectInputMask(3)).toBe("•••");
    expect(connectInputMask(8)).toBe("••••••••");
    // Past the cap the exact length is hidden behind an ellipsis.
    expect(connectInputMask(9)).toBe("••••••••…");
    expect(connectInputMask(500)).toBe("••••••••…");
    for (const length of [1, 5, 50, 500]) {
      expect(connectInputMask(length).replace(/[•…]/g, "")).toBe("");
    }
  });

  it("labels auth kinds in words", () => {
    expect(authKindFor("chatgpt-codex")).toBe("subscription");
    expect(authKindFor("openai")).toBe("api-key");
    expect(authHintLabel("subscription")).toBe("subscription");
    expect(authHintLabel("api-key")).toBe("API key");
    // The auth hint fits the 12-cell column it is budgeted for.
    for (const kind of ["subscription", "api-key"] as const) {
      expect(authHintLabel(kind).length).toBeLessThanOrEqual(12);
    }
  });

  it("names the real keys in the footer hints", () => {
    expect(connectFooterHint("browse")).toContain("enter connect");
    expect(connectFooterHint("browse")).toContain("↑↓ select");
    expect(connectFooterHint("browse", false)).toContain("esc back");
    expect(connectFooterHint("browse", true)).toContain("esc clear filter");
    expect(connectFooterHint("filter")).toContain("backspace");
    expect(connectFooterHint("input")).toContain("save");
    expect(connectFooterHint("input")).toContain("cancel");
  });

  it("routes printable characters to filter and input, control keys to neither", () => {
    for (const key of ["a", "Z", "5", "-", ".", " ", "s"]) {
      expect(isFilterKey(key)).toBe(true);
      expect(isInputKey(key)).toBe(true);
    }
    for (const key of ["\x1b", "\x7f", "\r", "ab", undefined]) {
      expect(isFilterKey(key)).toBe(false);
      expect(isInputKey(key)).toBe(false);
    }
  });

  it("keeps the printable characters of a pasted sequence and drops control bytes", () => {
    expect(pastableChars("sk-ant-abc123")).toBe("sk-ant-abc123");
    expect(pastableChars("sk-key\n")).toBe("sk-key");
    expect(pastableChars("a\x1bb\x7fc\r")).toBe("abc");
    expect(pastableChars("")).toBe("");
    expect(pastableChars(undefined)).toBe("");
    expect(pastableChars(123)).toBe("");
  });

  it("keeps every recommended id a real provider", () => {
    for (const id of RECOMMENDED_IDS) {
      expect(PROVIDERS.some((info) => info.id === id), `${id} is not a real provider`).toBe(true);
    }
  });
});
