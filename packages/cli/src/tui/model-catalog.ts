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
import type { HostedAllowanceModel, InferenceAccountResponse, InferenceModel } from "@0sec/core";

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
  const models = [...priced, ...extras];
  if (currentModel && !models.some((model) => model.id === currentModel)) {
    models.push({ id: currentModel, provider: modelProvider(currentModel), price: "—" });
  }
  return models.sort(compareCatalogRows(currentModel));
}

export interface HostedCatalogModel extends CatalogModel {
  catalog: InferenceModel;
  allowance: HostedAllowanceModel | null;
  contextTokens: number | null;
  maxOutputTokens: number | null;
  selectable: boolean;
  unavailableReason: string | null;
  recommended?: boolean;
}

/** Join estimates only when model and route identities agree. Never synthesize rates or context. */
export function buildHostedModelCatalog(
  models: readonly InferenceModel[],
  account: InferenceAccountResponse,
): HostedCatalogModel[] {
  const seen = new Set<string>();
  return models.map(model => {
    if (!model || typeof model.id !== "string" || !model.id || seen.has(model.id)) {
      throw new Error("Hosted model catalog contains missing or duplicate model IDs");
    }
    seen.add(model.id);
    const candidate = account.allowance?.models.find(row => row.id === model.id);
    const allowance = candidate && candidate.routeIdentity === model.routeIdentity
      && candidate.provider === model.provider && candidate.upstreamModel === model.upstream_model
      && candidate.wireApi === model.wire_api ? candidate : null;
    const readiness = model.readiness;
    const unavailableReason = !account.allowance ? "Allowance unavailable; reconnect or reload"
      : !allowance ? "Catalog and allowance route identities do not match"
      : model.state !== "available" ? `Catalog state: ${model.state ?? "unknown"}`
      : allowance.state !== "available" ? allowance.reason ?? `Allowance state: ${allowance.state}`
      : !readiness?.configured || !readiness.entitled ? readiness?.reason ?? "Catalog route readiness is not established"
      : readiness.qualification.status !== "passed" || readiness.qualification.routeIdentity !== model.routeIdentity ? "Catalog route qualification has not passed"
      : !allowance.readiness.configured || !allowance.readiness.entitled ? allowance.readiness.reason ?? "Allowance route is not ready"
      : allowance.qualification.status !== "passed" || allowance.qualification.routeIdentity !== model.routeIdentity
        || allowance.readiness.qualification.status !== "passed" || allowance.readiness.qualification.routeIdentity !== model.routeIdentity ? "Allowance route qualification has not passed"
      : account.allowance.subscription.state !== "active" ? `Subscription: ${account.allowance.subscription.state}`
      : !account.allowance.admission.allowed ? account.allowance.admission.reason ?? "Account admission is blocked"
      : null;
    const input = model.pricing?.input_per_million_usd;
    const output = model.pricing?.output_per_million_usd;
    return {
      id: model.id,
      provider: model.provider,
      price: typeof input === "number" && Number.isFinite(input) && input >= 0
        && typeof output === "number" && Number.isFinite(output) && output >= 0
        ? `$${input}/${output} per M` : "unknown",
      catalog: model,
      allowance,
      contextTokens: Number.isFinite(model.context_length) && model.context_length > 0 ? model.context_length : null,
      maxOutputTokens: Number.isFinite(model.max_output_tokens) && model.max_output_tokens > 0 ? model.max_output_tokens : null,
      selectable: unavailableReason === null,
      unavailableReason,
      recommended: unavailableReason === null && (model.recommended ?? allowance?.recommended) === true,
    };
  });
}

/** An offer changes the highlight, never a saved model or role assignment. */
export function preferredHostedModel(
  models: readonly HostedCatalogModel[],
  explicitModel: string | undefined,
): HostedCatalogModel | undefined {
  if (explicitModel) return models.find(model => model.id === explicitModel && model.selectable);
  return models.find(model => model.selectable && model.recommended) ??
    models.find(model => model.selectable);
}

/** Server-authored scenario estimates, not locally calculated request quotas or tariffs. */
export function hostedModelDetails(model: HostedCatalogModel): string[] {
  const { catalog, allowance } = model;
  const qualification = catalog.readiness?.qualification;
  const lines = [
    model.id,
    `State: ${catalog.state ?? "unknown"}${model.unavailableReason ? ` · ${model.unavailableReason}` : ""}`,
    `Route: ${catalog.routeIdentity ?? "unknown"}`,
    `Upstream: ${catalog.provider} / ${catalog.upstream_model}`,
    `Wire API: ${catalog.wire_api}`,
    `Context: ${model.contextTokens ?? "unknown"} · output limit: ${model.maxOutputTokens ?? "unknown"}`,
    `cost_basis: ${catalog.pricing?.cost_basis ?? "customer_tariff_usd (legacy)"}`,
    `Catalog rates: ${model.price}`,
    `Readiness: configured=${catalog.readiness?.configured ?? "unknown"}, entitled=${catalog.readiness?.entitled ?? "unknown"}`,
    `Readiness reason: ${catalog.readiness?.reason ?? "none reported"}`,
    `Qualification: ${qualification?.status ?? "unknown"} · route ${qualification?.routeIdentity ?? "unknown"}`,
    `Evidence: ${qualification?.evidenceRef ?? "unknown"}`,
    `Verified: ${qualification?.verifiedAt ?? "unknown"} · revision ${qualification?.sourceRevision ?? "unknown"}`,
  ];
  if (model.recommended) {
    lines.splice(1, 0, "Recommended: yes");
  }
  if (allowance) lines.push(
    `Allowance route: ${allowance.routeIdentity} · endpoint ${allowance.endpointIdentity ?? "unknown"}`,
    `Allowance qualification: ${allowance.qualification.status} · ${allowance.qualification.evidenceRef ?? "no evidence reference"}`,
    `Allowance readiness: configured=${allowance.readiness.configured}, entitled=${allowance.readiness.entitled}`,
    `Allowance reason: ${allowance.readiness.reason ?? allowance.reason ?? "none reported"}`,
    `Supplier rates / 1M: fresh $${allowance.supplierRatesUsdPerMillion.freshInput}, cache $${allowance.supplierRatesUsdPerMillion.cacheRead}, output $${allowance.supplierRatesUsdPerMillion.output}`,
    `Price version: ${allowance.priceVersion}`,
    `Server scenario: ${allowance.scenario.freshInput} fresh input + ${allowance.scenario.cacheRead} cache read + ${allowance.scenario.output} output tokens`,
    `Billed reasoning included: ${allowance.scenario.includesBilledReasoning}`,
    `Estimated supplier cost: ${allowance.estimatedSupplierCostUsd === null ? "unknown" : `$${allowance.estimatedSupplierCostUsd}`}`,
    `Requests / fresh five hours: ${allowance.requestsPerFreshFiveHours ?? "unknown"} (scenario estimate, not a quota)`,
  );
  return lines;
}

