/**
 * The selectable model list behind `/model`.
 *
 * There is deliberately no second hand-maintained list of models here: the
 * pricing table in @0sec/shared is already the one place that knows which
 * ids the tool understands, and a separate "menu" list would drift from it
 * the first time a model is added. So the catalog is derived — ids from
 * MODEL_PRICING, provider from `modelProvider`, price from `getRates` — and
 * this module only decides ordering and presentation.
 */

import { MODEL_PRICING, getRates, modelProvider } from "@0sec/shared";

import type { SelectorItem } from "./selector.js";
import { loadCatalogModels, type CatalogSyncOptions } from "./model-catalog-sync.js";

export interface CatalogModel {
  id: string;
  provider: string;
  /** "$5/30 per M", or "free" when both rates are zero. */
  price: string;
}

/**
 * `default` is the fallback rate row for unrecognised models, not a model an
 * operator can select — offering it would set the engine to a model id that
 * no provider answers to.
 */
const NON_MODEL_PRICING_KEYS = new Set(["default"]);

/** Byte-order compare: locale-independent so the menu order never shifts. */
function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * Rates are stored as plain numbers ($/1M) with inconsistent precision —
 * 5, 2.5, 0.075. Rendering them through toFixed would print "$5.00/30.00";
 * trimming to the significant digits keeps the column narrow enough to sit
 * beside the model id in a terminal.
 */
function formatRate(value: number): string {
  return String(Number(value.toFixed(4)));
}

export function formatModelPrice(input: number, output: number): string {
  if (input === 0 && output === 0) return "free";
  return `$${formatRate(input)}/${formatRate(output)} per M`;
}

export function buildModelCatalog(currentModel?: string): CatalogModel[] {
  const models = Object.keys(MODEL_PRICING)
    .filter((id) => !NON_MODEL_PRICING_KEYS.has(id))
    .map((id) => {
      const rates = getRates(id);
      return { id, provider: modelProvider(id), price: formatModelPrice(rates.input, rates.output) };
    });

  // The active model floats to the top: it is the row the operator most
  // often wants to confirm, and it doubles as the overlay's initial
  // highlight. Everything else groups by provider so the list reads as
  // vendor sections rather than as an alphabet soup of ids.
  return models.sort((a, b) => {
    if (a.id === currentModel) return b.id === currentModel ? 0 : -1;
    if (b.id === currentModel) return 1;
    return compareStrings(a.provider, b.provider) || compareStrings(a.id, b.id);
  });
}

export function modelSelectorItems(currentModel?: string): SelectorItem[] {
  return buildModelCatalog(currentModel).map((model) => ({
    id: model.id,
    label: model.id,
    meta: `${model.provider} · ${model.price}`,
    current: model.id === currentModel,
  }));
}

// ── Models.dev-synced superset ────────────────────────────────────────────────
//
// `buildModelCatalog` above is the priced core: exactly the ids @0sec/shared
// has rates for, in a stable order. The functions below widen the picker to
// every model the operator's provider offers by folding in the Models.dev
// catalog (cached, with a bundled offline floor — see model-catalog-sync.ts).
// Synced rows the pricing table already covers are dropped so a priced row is
// never shadowed by a rate-less duplicate.

/** Byte-order-stable sort used by both the priced and full catalogs. */
function compareCatalogRows(currentModel?: string) {
  return (a: CatalogModel, b: CatalogModel): number => {
    if (a.id === currentModel) return b.id === currentModel ? 0 : -1;
    if (b.id === currentModel) return 1;
    return compareStrings(a.provider, b.provider) || compareStrings(a.id, b.id);
  };
}

/**
 * Models present in the cached/offline Models.dev catalog but NOT already in
 * the pricing table. Price is shown only when the feed carried one; otherwise
 * a neutral placeholder, so the operator can still select the model (cost
 * accounting falls back to the `default` rate row, exactly as it does today
 * for any unrecognised id).
 */
export function catalogExtras(opts: CatalogSyncOptions = {}): CatalogModel[] {
  const priced = new Set(Object.keys(MODEL_PRICING).map((k) => k.toLowerCase()));
  const seen = new Set<string>();
  const out: CatalogModel[] = [];
  for (const m of loadCatalogModels(opts).models) {
    const key = m.id.toLowerCase();
    if (priced.has(key) || seen.has(key)) continue;
    seen.add(key);
    const price =
      typeof m.input === "number" && typeof m.output === "number"
        ? formatModelPrice(m.input, m.output)
        : "—";
    out.push({ id: m.id, provider: m.provider, price });
  }
  return out;
}

/**
 * The full picker list: the priced core plus every Models.dev-synced model we
 * don't already price, sorted into one provider-grouped list with the active
 * model floated to the top.
 */
export function buildFullModelCatalog(
  currentModel?: string,
  opts: CatalogSyncOptions = {},
): CatalogModel[] {
  const priced = buildModelCatalog(currentModel);
  const extras = catalogExtras(opts);
  return [...priced, ...extras].sort(compareCatalogRows(currentModel));
}

export function fullModelSelectorItems(
  currentModel?: string,
  opts: CatalogSyncOptions = {},
): SelectorItem[] {
  return buildFullModelCatalog(currentModel, opts).map((model) => ({
    id: model.id,
    label: model.id,
    meta: `${model.provider} · ${model.price}`,
    current: model.id === currentModel,
  }));
}
