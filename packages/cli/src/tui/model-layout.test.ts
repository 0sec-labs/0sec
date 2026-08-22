import { describe, expect, it } from "vitest";

import { buildModelCatalog, type CatalogModel } from "./model-catalog.js";
import {
  buildModelRows,
  clampSelection,
  clipModelDetailLines,
  computeModelLayout,
  computeModelWindow,
  configuredProviderLabels,
  credentialLabel,
  credentialSummary,
  firstSelectableIndex,
  indexOfModel,
  isFilterKey,
  lastSelectableIndex,
  modelDetailLines,
  modelFooterHint,
  modelListTitle,
  moveSelection,
  providerGroupFor,
  shellChromeRows,
  type ModelLayout,
  type ModelRow,
} from "./model-layout.js";
import { PROVIDERS, providerStates } from "./provider-status.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/** The live catalogue, exactly as the screen builds it. */
const CATALOG = buildModelCatalog();
const EMPTY_ENV = providerStates({});
/** One provider lit, chosen from the real table so the test tracks it. */
const LIT_PROVIDER = PROVIDERS.find((info) => info.id === "anthropic") ?? PROVIDERS[0];
const LIT_ENV = providerStates({ [LIT_PROVIDER?.envVars[0] ?? "ANTHROPIC_API_KEY"]: "sk-test" });

/** Every cell and row count a layout exposes, flattened for the sweep. */
function layoutNumbers(layout: ModelLayout): [string, number][] {
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
    ["row.activeWidth", layout.row.activeWidth],
    ["row.activeGap", layout.row.activeGap],
    ["row.labelWidth", layout.row.labelWidth],
    ["row.priceGap", layout.row.priceGap],
    ["row.priceWidth", layout.row.priceWidth],
    ["heading.width", layout.heading.width],
    ["heading.labelWidth", layout.heading.labelWidth],
    ["heading.gap", layout.heading.gap],
    ["heading.stateWidth", layout.heading.stateWidth],
    ["visibleRows", layout.visibleRows],
  ];
}

// ---------------------------------------------------------------------------

describe("computeModelLayout — the sweep", () => {
  /**
   * The invariant this whole module exists for: no allocation may exceed the
   * container it was carved out of, on either axis, at any terminal size.
   *
   * Yoga does not clip. A row of siblings claiming more cells than the row has
   * is shrunk, not truncated, and every sibling then paints its full string
   * into a box that is too small — the terminal shows the strings interleaved.
   * A box claiming more rows than its column has paints its own bottom border
   * through its last line of content. Both are silent at compile time.
   */
  it("never lets a pane, a row or a column exceed what it was given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        for (const noticeRows of [0, 1]) {
          const layout = computeModelLayout({ width, height, noticeRows });
          const at = `${width}x${height} (notice ${noticeRows})`;

          for (const [name, value] of layoutNumbers(layout)) {
            expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
          }

          // -- horizontal --
          expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
            Math.max(0, width),
          );
          if (layout.stacked) {
            expect(layout.list.width, `stacked list too wide at ${at}`).toBeLessThanOrEqual(
              layout.contentWidth,
            );
            expect(layout.detail.width, `stacked detail too wide at ${at}`).toBeLessThanOrEqual(
              layout.contentWidth,
            );
            expect(layout.paneGap, `stacked panes had a horizontal gap at ${at}`).toBe(0);
          } else {
            const claimed = layout.list.width + layout.paneGap + layout.detail.width;
            expect(
              claimed,
              `panes claimed ${claimed} of ${layout.contentWidth} at ${at}`,
            ).toBeLessThanOrEqual(layout.contentWidth);
          }

          // -- list row columns --
          const row = layout.row;
          expect(row.width, `row wider than the list pane at ${at}`).toBe(layout.list.innerWidth);
          const rowClaimed =
            row.markerWidth +
            row.markerGap +
            row.activeWidth +
            row.activeGap +
            row.labelWidth +
            row.priceGap +
            row.priceWidth;
          // Exactly, not merely "at most": a row that leaves cells unclaimed
          // is a row whose selection highlight stops short of its own edge.
          expect(rowClaimed, `row claimed ${rowClaimed} of ${row.width} at ${at}`).toBe(row.width);

          // -- provider heading columns --
          const heading = layout.heading;
          expect(heading.width, `heading wider than the list pane at ${at}`).toBe(
            layout.list.innerWidth,
          );
          const headingClaimed = heading.labelWidth + heading.gap + heading.stateWidth;
          expect(
            headingClaimed,
            `heading claimed ${headingClaimed} of ${heading.width} at ${at}`,
          ).toBe(heading.width);
          if (heading.stateWidth > 0) {
            expect(heading.gap, `heading state had no gap at ${at}`).toBe(1);
            expect(heading.labelWidth, `heading name squeezed out at ${at}`).toBeGreaterThan(0);
          }

          // -- vertical --
          expect(layout.list.height, `list taller than the body at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );
          expect(layout.detail.height, `detail taller than the body at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );
          if (layout.stacked) {
            const rows = layout.list.height + layout.detail.height;
            expect(
              rows,
              `stacked panes claimed ${rows} of ${layout.bodyRows} rows at ${at}`,
            ).toBeLessThanOrEqual(layout.bodyRows);
          }
          expect(
            layout.visibleRows,
            `visibleRows exceeded the list body at ${at}`,
          ).toBeLessThanOrEqual(layout.list.bodyRows);

          // A rendered pane always has room for at least one row of content
          // and one cell of text; a pane below that is dropped, because a box
          // one row short of its content is corruption and an absent box is
          // merely missing information.
          for (const pane of [layout.list, layout.detail]) {
            if (pane.width > 0) {
              expect(pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
            }
            if (pane.height > 0) {
              expect(pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
            }
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
        const layout = computeModelLayout({ width, height, noticeRows: 1 });
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
        const layout = computeModelLayout({ width, height });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${width}x${height}`).toBe(true);
        }
      }
    }
  });

  it("stacks the detail pane under the list on a narrow terminal", () => {
    expect(computeModelLayout({ width: 60, height: 40 }).stacked).toBe(true);
    expect(computeModelLayout({ width: 79, height: 40 }).stacked).toBe(true);
    expect(computeModelLayout({ width: 80, height: 40 }).stacked).toBe(false);
  });

  it("puts the detail pane beside the list once the terminal is wide enough", () => {
    const layout = computeModelLayout({ width: 120, height: 40 });
    expect(layout.stacked).toBe(false);
    expect(layout.paneGap).toBe(1);
    expect(layout.detail.width).toBeGreaterThanOrEqual(30);
    expect(layout.list.width).toBeGreaterThan(layout.detail.width);
    expect(layout.list.width + layout.paneGap + layout.detail.width).toBe(layout.contentWidth);
  });

  it("titles the list always and the detail pane only when it sits beside it", () => {
    const wide = computeModelLayout({ width: 120, height: 40 });
    expect(wide.list.hasTitle).toBe(true);
    expect(wide.detail.hasTitle).toBe(true);
    const narrow = computeModelLayout({ width: 60, height: 40 });
    expect(narrow.stacked).toBe(true);
    expect(narrow.list.hasTitle).toBe(true);
    expect(narrow.detail.hasTitle).toBe(false);
  });

  it("drops pane borders before it drops rows of content", () => {
    const tall = computeModelLayout({ width: 120, height: 40 });
    const short = computeModelLayout({ width: 120, height: 16 });
    expect(tall.bordered).toBe(true);
    expect(short.bordered).toBe(false);
    expect(short.detailCompact).toBe(true);
    // Borderless panes hand the four horizontal chrome cells back to the text.
    expect(short.list.innerWidth).toBe(short.list.width);
  });

  it("degrades the list row one column at a time as the pane narrows", () => {
    // Drive the real entry point rather than the private helper: the row is
    // only ever as wide as the list pane's inner width.
    const at = (innerWidth: number) => computeModelLayout({ width: innerWidth + 4, height: 40 }).row;
    const wide = at(120);
    expect(wide.markerWidth).toBe(1);
    expect(wide.activeWidth).toBe(1);
    expect(wide.priceWidth).toBeGreaterThan(0);

    // The price is the first thing to go, then the active marker; the id
    // column survives all the way down.
    let sawNoPrice = false;
    let sawNoActive = false;
    for (let innerWidth = 60; innerWidth >= 1; innerWidth--) {
      const row = at(innerWidth);
      if (row.priceWidth === 0) sawNoPrice = true;
      if (row.activeWidth === 0) sawNoActive = true;
      if (sawNoActive) expect(row.priceWidth, `price outlived the marker at ${innerWidth}`).toBe(0);
      if (row.width > 0) {
        expect(row.labelWidth, `id column vanished at ${innerWidth}`).toBeGreaterThan(0);
      }
    }
    expect(sawNoPrice).toBe(true);
    expect(sawNoActive).toBe(true);
  });

  it("gives more list rows to a taller terminal", () => {
    const short = computeModelLayout({ width: 120, height: 24 });
    const tall = computeModelLayout({ width: 120, height: 60 });
    expect(tall.visibleRows).toBeGreaterThan(short.visibleRows);
  });

  it("spends a row on the status line only when there is one", () => {
    const quiet = computeModelLayout({ width: 120, height: 40, noticeRows: 0 });
    const noisy = computeModelLayout({ width: 120, height: 40, noticeRows: 1 });
    expect(noisy.bodyRows).toBe(quiet.bodyRows - 1);
  });
});

// ---------------------------------------------------------------------------

describe("buildModelRows", () => {
  it("derives the entire list from the live catalogue", () => {
    const rows = buildModelRows();
    const models = rows.filter(
      (row): row is Extract<ModelRow, { kind: "model" }> => row.kind === "model",
    );
    // Not a fixture copy: every id the catalogue carries today is reachable,
    // so a model added to the pricing table tomorrow is covered by this
    // assertion without anyone editing this file.
    expect(models.map((row) => row.model.id).sort()).toEqual(
      CATALOG.map((model) => model.id).sort(),
    );
    expect(models.length).toBeGreaterThan(10);
  });

  it("emits one heading per provider present in the catalogue", () => {
    const rows = buildModelRows();
    const headings = rows.filter((row) => row.kind === "heading");
    const providers = new Set(CATALOG.map((model) => model.provider));
    expect(headings).toHaveLength(providers.size);
    expect(new Set(headings.map((row) => row.group.id))).toEqual(providers);
  });

  it("puts every model under its own provider heading, with a true count", () => {
    let group = "";
    let seen = 0;
    let expected = 0;
    for (const row of buildModelRows()) {
      if (row.kind === "heading") {
        if (group) expect(seen, `${group} miscounted`).toBe(expected);
        group = row.group.id;
        expected = row.count;
        seen = 0;
        continue;
      }
      expect(row.model.provider).toBe(group);
      seen++;
    }
    expect(seen).toBe(expected);
  });

  it("grows when the catalogue does, with no change to this module", () => {
    const probe: CatalogModel = { id: "probe-1", provider: "probe-vendor", price: "free" };
    const before = buildModelRows({ catalog: CATALOG });
    const after = buildModelRows({ catalog: [...CATALOG, probe] });
    // One new model row plus the heading for its new provider.
    expect(after).toHaveLength(before.length + 2);
    expect(after.at(-2)?.kind).toBe("heading");
    expect(after.at(-1)).toMatchObject({ kind: "model", model: probe });
  });

  it("floats the active model's provider first, then the ones holding credentials", () => {
    const rows = buildModelRows({ catalog: CATALOG, states: LIT_ENV, activeModel: "gpt-5.5" });
    const headings = rows
      .filter((row): row is Extract<ModelRow, { kind: "heading" }> => row.kind === "heading")
      .map((row) => row.group);
    expect(headings[0]?.id).toBe("openai");
    // The lit provider outranks every other unconfigured one.
    expect(headings[1]?.id).toBe(LIT_PROVIDER?.id);
    expect(headings[1]?.credential).toBe("ready");
    // And the vendors with no env path at all sink to the bottom.
    expect(headings.at(-1)?.credential).toBe("unmapped");
  });

  it("floats the active model to the top of its own provider group", () => {
    const rows = buildModelRows({ catalog: CATALOG, activeModel: "claude-sonnet-4-6" });
    const at = indexOfModel(rows, "claude-sonnet-4-6");
    expect(at).toBeGreaterThan(0);
    expect(rows[at - 1]?.kind).toBe("heading");
    expect(rows[at]).toMatchObject({ active: true });
    // Exactly one row is ever marked active.
    expect(rows.filter((row) => row.kind === "model" && row.active)).toHaveLength(1);
  });

  it("marks nothing active when the running model is not in the catalogue", () => {
    const rows = buildModelRows({ catalog: CATALOG, activeModel: "not-a-model" });
    expect(rows.filter((row) => row.kind === "model" && row.active)).toHaveLength(0);
    expect(indexOfModel(rows, "not-a-model")).toBe(-1);
  });

  it("is stable: the same inputs give the same order", () => {
    expect(buildModelRows({ catalog: CATALOG, states: LIT_ENV })).toEqual(
      buildModelRows({ catalog: CATALOG, states: LIT_ENV }),
    );
  });

  it("filters on the model id", () => {
    for (const model of CATALOG) {
      const rows = buildModelRows({ catalog: CATALOG, filter: model.id });
      expect(
        rows.some((row) => row.kind === "model" && row.model.id === model.id),
        `filtering on ${model.id} did not find it`,
      ).toBe(true);
    }
  });

  it("filters on the provider id and on the provider's human label", () => {
    const anthropic = buildModelRows({ catalog: CATALOG, filter: "anthropic" });
    expect(anthropic.filter((row) => row.kind === "heading")).toHaveLength(1);
    expect(anthropic.every((row) => row.group.id === "anthropic")).toBe(true);
    // "Moonshot" appears only in the PROVIDERS label for the `kimi` id.
    const moonshot = buildModelRows({ catalog: CATALOG, filter: "moonshot" });
    expect(moonshot.filter((row) => row.kind === "model").length).toBeGreaterThan(0);
    expect(moonshot.every((row) => row.group.id === "kimi")).toBe(true);
  });

  it("filters on the formatted price", () => {
    const free = CATALOG.filter((model) => model.price === "free");
    const rows = buildModelRows({ catalog: CATALOG, filter: "free" });
    expect(rows.filter((row) => row.kind === "model")).toHaveLength(free.length);
  });

  it("ANDs multiple filter terms", () => {
    const both = buildModelRows({ catalog: CATALOG, filter: "anthropic opus" });
    expect(both.filter((row) => row.kind === "model").length).toBeGreaterThan(0);
    expect(both.every((row) => row.kind === "heading" || row.model.id.includes("opus"))).toBe(true);
    expect(buildModelRows({ catalog: CATALOG, filter: "anthropic nonsensetoken" })).toEqual([]);
  });

  it("never leaves a heading with nothing under it, for any filter", () => {
    const queries = [
      "",
      "a",
      "e",
      "gpt",
      "claude",
      "free",
      "per m",
      "zzz",
      ...new Set(CATALOG.map((model) => model.provider)),
      ...CATALOG.map((model) => model.id),
    ];
    for (const query of queries) {
      const rows = buildModelRows({ catalog: CATALOG, filter: query });
      rows.forEach((row, index) => {
        if (row.kind !== "heading") return;
        expect(
          rows[index + 1]?.kind,
          `heading "${row.group.id}" had no children under filter "${query}"`,
        ).toBe("model");
      });
      const headings = rows.filter((row) => row.kind === "heading").map((row) => row.group.id);
      expect(new Set(headings).size, `duplicate heading under filter "${query}"`).toBe(
        headings.length,
      );
    }
  });

  it("returns an empty list rather than throwing when nothing matches", () => {
    const rows = buildModelRows({ catalog: CATALOG, filter: "zzzzz" });
    expect(rows).toEqual([]);
    expect(firstSelectableIndex(rows)).toBe(-1);
    expect(clampSelection(rows, 3)).toBe(-1);
    expect(moveSelection(rows, 0, 1)).toBe(-1);
  });

  it("survives a malformed catalogue entry rather than rendering a blank row", () => {
    const rows = buildModelRows({
      catalog: [
        ...CATALOG,
        { id: "", provider: "openai", price: "free" },
        { id: "orphan", provider: "", price: "free" },
      ],
    });
    expect(rows.some((row) => row.kind === "model" && row.model.id === "")).toBe(false);
    const orphan = rows.find((row) => row.kind === "model" && row.model.id === "orphan");
    expect(orphan?.group.id).toBe("unknown");
  });
});

// ---------------------------------------------------------------------------

describe("provider credential reporting", () => {
  /**
   * The rule this screen was rewritten around. A previous attempt annotated
   * each row with a per-model verdict derived from the pricing table's
   * provider; the runtime resolves a model's provider independently
   * (`providerForModel`), the two disagree, and working models were flagged
   * as broken. Nothing per-model may claim reachability.
   */
  it("never makes a per-model credential claim", () => {
    const rows = buildModelRows({ catalog: CATALOG, states: LIT_ENV });
    for (const row of rows) {
      if (row.kind !== "model") continue;
      // The row carries the id, the price and the group — and no per-model
      // usability flag of any kind.
      expect(Object.keys(row).sort()).toEqual(["active", "group", "kind", "model"]);
    }
  });

  it("reports a provider as ready only when an env var actually holds a credential", () => {
    for (const info of PROVIDERS) {
      expect(providerGroupFor(info.id, EMPTY_ENV).credential).toBe("missing");
      for (const envVar of info.envVars) {
        const lit = providerStates({ [envVar]: "value" });
        const group = providerGroupFor(info.id, lit);
        expect(group.credential, `${info.id} via ${envVar}`).toBe("ready");
        expect(group.via).toBe(envVar);
      }
      // An exported-but-empty variable is not a credential.
      expect(
        providerGroupFor(info.id, providerStates({ [info.envVars[0] ?? ""]: "  " })).credential,
      ).toBe("missing");
    }
  });

  it("calls a vendor with no runtime env path unmapped rather than unconfigured", () => {
    // These come from the pricing table and have no entry in PROVIDERS.
    for (const id of ["google", "meta", "mistral", "unknown"]) {
      const group = providerGroupFor(id, EMPTY_ENV);
      expect(group.credential, id).toBe("unmapped");
      expect(group.envVars).toEqual([]);
      expect(group.label.length).toBeGreaterThan(0);
    }
  });

  it("names every configured provider in the summary line", () => {
    expect(credentialSummary(EMPTY_ENV)).toContain("none detected");
    expect(credentialSummary(LIT_ENV)).toContain(LIT_PROVIDER?.label ?? "");
    const all = providerStates(
      Object.fromEntries(PROVIDERS.map((info) => [info.envVars[0] ?? "", "value"])),
    );
    expect(configuredProviderLabels(all)).toHaveLength(PROVIDERS.length);
    for (const info of PROVIDERS) expect(credentialSummary(all)).toContain(info.label);
  });

  it("labels each credential state in words an operator can act on", () => {
    expect(credentialLabel("ready")).toBe("ready");
    expect(credentialLabel("missing")).toBe("no credentials");
    expect(credentialLabel("unmapped")).toBe("no setup path");
    // The heading's state column is capped at 14 cells; none of these may be
    // truncated on a terminal wide enough to show the column at all.
    for (const state of ["ready", "missing", "unmapped"] as const) {
      expect(credentialLabel(state).length).toBeLessThanOrEqual(14);
    }
  });
});

// ---------------------------------------------------------------------------

describe("navigation", () => {
  const rows = buildModelRows({ catalog: CATALOG });
  const modelIndexes = rows
    .map((row, index) => (row.kind === "model" ? index : -1))
    .filter((index) => index >= 0);

  it("never lands on a provider heading, moving down through the whole list twice", () => {
    let index = firstSelectableIndex(rows);
    expect(rows[index]?.kind).toBe("model");
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveSelection(rows, index, 1);
      expect(rows[index]?.kind, `landed on a heading at step ${step}`).toBe("model");
    }
  });

  it("never lands on a provider heading, moving up through the whole list twice", () => {
    let index = lastSelectableIndex(rows);
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveSelection(rows, index, -1);
      expect(rows[index]?.kind, `landed on a heading at step ${step}`).toBe("model");
    }
  });

  it("visits every model in order before repeating, then wraps", () => {
    const visited: number[] = [];
    let index = firstSelectableIndex(rows);
    for (let step = 0; step < modelIndexes.length; step++) {
      visited.push(index);
      index = moveSelection(rows, index, 1);
    }
    expect(visited).toEqual(modelIndexes);
    expect(index).toBe(modelIndexes[0]);
  });

  it("wraps from the last model to the first and back", () => {
    const first = firstSelectableIndex(rows);
    const last = lastSelectableIndex(rows);
    expect(moveSelection(rows, last, 1)).toBe(first);
    expect(moveSelection(rows, first, -1)).toBe(last);
  });

  it("skips a run of consecutive headings", () => {
    const group = providerGroupFor("openai", EMPTY_ENV);
    const model: CatalogModel = { id: "x", provider: "openai", price: "free" };
    const sparse: ModelRow[] = [
      { kind: "heading", group, count: 0 },
      { kind: "heading", group, count: 0 },
      { kind: "heading", group, count: 1 },
      { kind: "model", group, model, active: false },
      { kind: "heading", group, count: 0 },
      { kind: "heading", group, count: 1 },
      { kind: "model", group, model, active: false },
    ];
    expect(moveSelection(sparse, 3, 1)).toBe(6);
    expect(moveSelection(sparse, 6, 1)).toBe(3);
    expect(moveSelection(sparse, 3, -1)).toBe(6);
    expect(moveSelection(sparse, 6, -1)).toBe(3);
  });

  it("terminates on a list of nothing but headings", () => {
    const group = providerGroupFor("openai", EMPTY_ENV);
    const headings: ModelRow[] = [
      { kind: "heading", group, count: 0 },
      { kind: "heading", group, count: 0 },
    ];
    expect(moveSelection(headings, 0, 1)).toBe(-1);
    expect(moveSelection(headings, 0, -1)).toBe(-1);
  });

  it("honours a multi-row jump", () => {
    const first = firstSelectableIndex(rows);
    let stepped = first;
    for (let i = 0; i < 4; i++) stepped = moveSelection(rows, stepped, 1);
    expect(moveSelection(rows, first, 4)).toBe(stepped);
  });

  it("pulls an out-of-range or heading selection onto a real row", () => {
    expect(rows[clampSelection(rows, 0)]?.kind).toBe("model");
    expect(clampSelection(rows, -50)).toBe(firstSelectableIndex(rows));
    expect(clampSelection(rows, 9999)).toBe(lastSelectableIndex(rows));
    expect(rows[clampSelection(rows, Number.NaN)]?.kind).toBe("model");
  });

  it("re-clamps the selection after a filter shortens the list", () => {
    const selected = lastSelectableIndex(rows);
    for (const provider of new Set(CATALOG.map((model) => model.provider))) {
      const filtered = buildModelRows({ catalog: CATALOG, filter: provider });
      const reclamped = clampSelection(filtered, selected);
      expect(reclamped, `no row survived the ${provider} filter`).toBeGreaterThanOrEqual(0);
      expect(reclamped).toBeLessThan(filtered.length);
      expect(filtered[reclamped]?.kind).toBe("model");
      // And the cursor is still usable — moving from it stays on a real row.
      expect(filtered[moveSelection(filtered, reclamped, 1)]?.kind).toBe("model");
    }
    const narrowest = [...new Set(CATALOG.map((model) => model.provider))]
      .map((provider) => buildModelRows({ catalog: CATALOG, filter: provider }))
      .reduce((shortest, current) => (current.length < shortest.length ? current : shortest));
    expect(clampSelection(narrowest, 9999)).toBe(lastSelectableIndex(narrowest));
  });

  it("finds a model by id so the screen can open on the running one", () => {
    for (const model of CATALOG) {
      const at = indexOfModel(rows, model.id);
      expect(at, `${model.id} was unreachable`).toBeGreaterThanOrEqual(0);
      expect(rows[at]).toMatchObject({ kind: "model" });
    }
    expect(indexOfModel(rows, undefined)).toBe(-1);
    expect(indexOfModel(rows, "")).toBe(-1);
  });
});

// ---------------------------------------------------------------------------

describe("computeModelWindow", () => {
  const rows = buildModelRows({ catalog: CATALOG });

  it("keeps the highlighted row visible, from any anchor, at any capacity", () => {
    for (let visible = 0; visible <= rows.length + 4; visible++) {
      for (let selected = 0; selected < rows.length; selected++) {
        if (rows[selected]?.kind !== "model") continue;
        for (const anchor of [0, 3, 7, rows.length, rows.length * 2]) {
          const win = computeModelWindow({ rows, selected, visible, anchor });
          expect(win.count).toBeLessThanOrEqual(Math.max(0, visible));
          expect(win.count).toBe(win.end - win.start);
          expect(win.end).toBeLessThanOrEqual(rows.length);
          if (win.count === 0) continue;
          expect(
            selected >= win.start && selected < win.end,
            `row ${selected} fell outside ${win.start}..${win.end} (visible ${visible}, anchor ${anchor})`,
          ).toBe(true);
        }
      }
    }
  });

  it("brings the provider heading along when the cursor is the first of its group", () => {
    const headingIndex = rows.findIndex(
      (row, index) => row.kind === "heading" && rows[index + 1]?.kind === "model" && index > 0,
    );
    expect(headingIndex).toBeGreaterThan(0);
    const win = computeModelWindow({
      rows,
      selected: headingIndex + 1,
      visible: 4,
      anchor: rows.length,
    });
    expect(win.start).toBe(headingIndex);
  });

  it("scrolls from the anchor rather than re-centring", () => {
    const win = computeModelWindow({ rows, selected: 4, visible: 6, anchor: 2 });
    expect(win.start).toBe(2);
    expect(win.end).toBe(8);
  });

  it("scrolls down by exactly one when the cursor steps past the last row", () => {
    const win = computeModelWindow({ rows, selected: 8, visible: 6, anchor: 2 });
    expect(win.start).toBe(3);
    expect(win.hasAbove).toBe(true);
  });

  it("reports overflow in both directions", () => {
    const whole = computeModelWindow({ rows, selected: 1, visible: rows.length });
    expect(whole.hasAbove).toBe(false);
    expect(whole.hasBelow).toBe(false);
    const middle = computeModelWindow({ rows, selected: 5, visible: 3, anchor: 4 });
    expect(middle.hasAbove).toBe(true);
    expect(middle.hasBelow).toBe(true);
  });

  it("renders nothing rather than overflowing when the pane has no rows", () => {
    expect(computeModelWindow({ rows, selected: 3, visible: 0 })).toMatchObject({
      start: 0,
      end: 0,
      count: 0,
    });
  });

  it("handles an empty list and a missing selection", () => {
    expect(computeModelWindow({ rows: [], selected: -1, visible: 10 }).count).toBe(0);
    const win = computeModelWindow({ rows, selected: -1, visible: 4, anchor: 2 });
    expect(win.start).toBe(2);
    expect(win.count).toBe(4);
  });

  it("titles the pane with the window it is showing", () => {
    expect(modelListTitle(computeModelWindow({ rows, selected: 1, visible: rows.length }))).toBe(
      `MODELS ${rows.length}`,
    );
    expect(modelListTitle(computeModelWindow({ rows, selected: 5, visible: 4, anchor: 3 }))).toMatch(
      /^MODELS \d+-\d+\/\d+$/,
    );
    expect(modelListTitle(computeModelWindow({ rows: [], selected: -1, visible: 4 }))).toBe(
      "MODELS 0",
    );
  });
});

// ---------------------------------------------------------------------------

describe("the detail pane", () => {
  const rowsLit = buildModelRows({ catalog: CATALOG, states: LIT_ENV });
  const configured = configuredProviderLabels(LIT_ENV);

  const textOf = (lines: { text: string }[]): string => lines.map((line) => line.text).join("\n");

  it("describes the highlighted model with its id, provider and price", () => {
    const row = rowsLit.find(
      (candidate) => candidate.kind === "model" && candidate.group.id === LIT_PROVIDER?.id,
    );
    expect(row?.kind).toBe("model");
    const text = textOf(modelDetailLines({ row, configured }, 48));
    expect(text).toContain(row?.kind === "model" ? row.model.id : "");
    expect(text).toContain(`Provider: ${LIT_PROVIDER?.label}`);
    expect(text).toContain("Price:");
  });

  it("names the env var behind a configured provider", () => {
    const row = rowsLit.find(
      (candidate) => candidate.kind === "model" && candidate.group.id === LIT_PROVIDER?.id,
    );
    const text = textOf(modelDetailLines({ row, configured }, 60));
    expect(text).toContain("Credentials: found in");
    expect(text).toContain(LIT_PROVIDER?.envVars[0] ?? "");
  });

  it("gives the exact setup hint for a provider with no credentials", () => {
    const dark = PROVIDERS.find(
      (info) => info.id !== LIT_PROVIDER?.id && CATALOG.some((m) => m.provider === info.id),
    );
    expect(dark).toBeDefined();
    const row = rowsLit.find(
      (candidate) => candidate.kind === "model" && candidate.group.id === dark?.id,
    );
    const text = textOf(modelDetailLines({ row, configured }, 80));
    expect(text).toContain("Credentials: not found");
    // The hint is reproduced from PROVIDERS, not paraphrased here.
    for (const word of (dark?.hint ?? "").split(" ").slice(0, 4)) expect(text).toContain(word);
    expect(text).toContain(dark?.envVars[0] ?? "");
    // And the providers that DO hold credentials are named, so the operator
    // can judge for themselves rather than being told the model is unusable.
    expect(text).toContain(configured.join(", "));
  });

  it("says an on-disk credential source was not checked", () => {
    const filed = PROVIDERS.find((info) => info.fileSource);
    expect(filed).toBeDefined();
    const group = providerGroupFor(filed?.id ?? "", EMPTY_ENV);
    const text = textOf(
      modelDetailLines(
        {
          row: {
            kind: "model",
            group,
            model: { id: "m", provider: group.id, price: "free" },
            active: false,
          },
        },
        80,
      ),
    );
    expect(text).toContain("not checked here");
  });

  it("never renders a per-model usability verdict", () => {
    // Every model, under an environment with exactly one provider lit.
    for (const row of rowsLit) {
      if (row.kind !== "model") continue;
      const text = textOf(modelDetailLines({ row, configured }, 80)).toLowerCase();
      for (const forbidden of ["cannot use", "unavailable", "unusable", "will fail", "not usable"]) {
        expect(text, `${row.model.id} claimed "${forbidden}"`).not.toContain(forbidden);
      }
      // And every model carries the caveat that the runtime may route it
      // somewhere other than the pricing table's provider.
      expect(text).toContain("may route this model elsewhere");
    }
  });

  it("marks the active model", () => {
    const rows = buildModelRows({ catalog: CATALOG, activeModel: "claude-opus-4-7" });
    const active = rows.find((row) => row.kind === "model" && row.active);
    expect(textOf(modelDetailLines({ row: active }, 48))).toContain("Currently active");
  });

  it("describes a provider heading too, so the cursor is never over nothing", () => {
    const heading = rowsLit.find((row) => row.kind === "heading");
    const text = textOf(modelDetailLines({ row: heading }, 48));
    expect(text).toContain(heading?.group.label ?? "");
    expect(text).toMatch(/\d+ models? priced/);
  });

  it("keeps every detail line inside the pane it was measured for", () => {
    for (const row of rowsLit) {
      for (const width of [0, 1, 8, 20, 30, 44, 56]) {
        for (const line of modelDetailLines({ row, configured }, width)) {
          expect(line.text.length, `overflowed a ${width}-cell pane`).toBeLessThanOrEqual(width);
        }
      }
    }
    expect(modelDetailLines({}, 48)).toEqual([]);
  });

  it("spends no rows on blanks in compact mode", () => {
    const row = rowsLit.find((candidate) => candidate.kind === "model");
    const full = modelDetailLines({ row, configured }, 40);
    const compact = modelDetailLines({ row, configured, compact: true }, 40);
    expect(compact.some((line) => line.tone === "blank")).toBe(false);
    expect(compact.map((line) => line.text)).toEqual(
      full.filter((line) => line.tone !== "blank").map((line) => line.text),
    );
  });

  it("clips the detail body to the rows the pane holds", () => {
    const row = rowsLit.find(
      (candidate) => candidate.kind === "model" && candidate.group.credential === "missing",
    );
    const lines = modelDetailLines({ row, configured }, 24);
    expect(lines.length).toBeGreaterThan(4);
    const clipped = clipModelDetailLines(lines, 4);
    expect(clipped).toHaveLength(4);
    expect(clipped.at(-1)?.text).toBe("...");
    expect(clipModelDetailLines(lines, 0)).toEqual([]);
    expect(clipModelDetailLines(lines, lines.length + 5)).toHaveLength(lines.length);

    // Given the pane's width, the marker rides on the last surviving line
    // rather than costing a row of its own.
    const inline = clipModelDetailLines(lines, 3, 24);
    expect(inline).toHaveLength(3);
    expect(inline.at(-1)?.text.endsWith(" ...")).toBe(true);
    for (const line of inline) expect(line.text.length).toBeLessThanOrEqual(24);
    expect(clipModelDetailLines(lines, 3, 6).at(-1)?.text).toBe("...");
  });
});

// ---------------------------------------------------------------------------

describe("hints and keys", () => {
  it("names the real keys in the footer hint", () => {
    const browse = modelFooterHint("browse");
    for (const fragment of ["up/down", "enter select", "/ filter", "ctrl+c exit"]) {
      expect(browse).toContain(fragment);
    }
    expect(modelFooterHint("browse", false)).toContain("esc back");
    expect(modelFooterHint("browse", true)).toContain("esc clear filter");
    expect(modelFooterHint("filter")).toContain("backspace");
  });

  it("gives every printable character to the filter", () => {
    // Unlike the settings screen, nothing is reserved: this screen has no
    // destructive key, so `r` reaches the filter like any other letter.
    for (const key of ["a", "Z", " ", "r", "R", "5", "-", "."]) {
      expect(isFilterKey(key), `${key} did not reach the filter`).toBe(true);
    }
    expect(isFilterKey("\x1b"), "escape").toBe(false);
    expect(isFilterKey("\x7f"), "delete").toBe(false);
    expect(isFilterKey("\r")).toBe(false);
    expect(isFilterKey("ab")).toBe(false);
    expect(isFilterKey(undefined)).toBe(false);
  });
});
