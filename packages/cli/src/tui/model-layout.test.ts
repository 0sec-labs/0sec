import { describe, expect, it } from "vitest";

import { buildModelCatalog, type CatalogModel } from "./model-catalog.js";
import {
  buildModelRows,
  clipModelDetailLines,
  configuredProviderLabels,
  credentialLabel,
  credentialSummary,
  indexOfModel,
  isFilterKey,
  modelDetailLines,
  modelFooterHint,
  providerGroupFor,
  type ModelRow,
} from "./model-layout.js";
import { PROVIDERS, providerStates } from "./provider-status.js";

/** The live catalogue, exactly as the screen builds it. */
const CATALOG = buildModelCatalog();
const EMPTY_ENV = providerStates({});
/** One provider lit, chosen from the real table so the test tracks it. */
const LIT_PROVIDER = PROVIDERS.find((info) => info.id === "anthropic") ?? PROVIDERS[0];
const LIT_ENV = providerStates({ [LIT_PROVIDER?.envVars[0] ?? "ANTHROPIC_API_KEY"]: "sk-test" });

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
    expect(indexOfModel(rows, CATALOG[0]?.id)).toBe(-1);
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
