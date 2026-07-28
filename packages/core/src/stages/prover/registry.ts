/**
 * The prover-plugin registry — the extension point.
 *
 * Same idiom as the engine's other catalogs (`stages/npm-detectors/registry.ts`,
 * `triage/router/layer-registry.ts`, `runtime/registry.ts`): a frozen `readonly`
 * array plus a `*_BY_ID` map for O(1) lookup, with a duplicate-id guard that
 * throws at module load rather than letting two plugins quietly shadow each
 * other. Adding a format means adding one file in this directory and one line
 * here.
 *
 * As in `npm-detectors`, the registry only CATALOGS. It cannot exempt a plugin
 * from the discipline in `types.ts` — the framing/semantics split, the purity
 * requirement, the "validate never grades" rule — because none of that is
 * enforced here. That is on purpose: a registry that also arbitrates behaviour
 * becomes the place every future exception gets added.
 *
 * ## Selection
 *
 * {@link selectProverPlugin} ranks by {@link ProverMatch.score} and breaks ties
 * by registry order. Scoring rather than first-match matters because contexts
 * legitimately satisfy more than one plugin — a JAR is a ZIP, a PNG can be a
 * ZIP entry — and the caller needs an answer it can explain. Magic bytes
 * (score 1.0) beat a name hint (0.75) every time, which is the right priority:
 * a fuzzer's name is a guess about the format, the first eight bytes are not.
 *
 * A plugin whose {@link ProverPlugin.requiresServices} the caller cannot
 * satisfy is skipped during selection rather than being handed a request it
 * will fail. Both plugins registered today are pure and require nothing.
 */

import { pngProverPlugin } from "./png.js";
import { zipProverPlugin } from "./zip.js";
import type { ProverContext, ProverMatch, ProverPlugin, ProverServices } from "./types.js";

/**
 * Registered prover plugins, in tie-break priority order.
 *
 * Both entries were chosen because checksum / length / offset framing is the
 * *actual* barrier for their format — the thing an LLM reliably gets wrong and
 * a deterministic function reliably gets right — and because
 * `stages/format-knowledge.ts` already documents them, so the plugins inherit
 * knowledge we had rather than knowledge we invented.
 */
export const PROVER_PLUGIN_REGISTRY: readonly ProverPlugin[] = Object.freeze([
  pngProverPlugin,
  zipProverPlugin,
]);

/** O(1) lookup by plugin id. Throws at load time on a duplicate id. */
export const PROVER_PLUGIN_BY_ID: Readonly<Record<string, ProverPlugin>> = Object.freeze(
  PROVER_PLUGIN_REGISTRY.reduce<Record<string, ProverPlugin>>((acc, p) => {
    if (acc[p.id]) throw new Error(`Duplicate prover plugin id "${p.id}" in PROVER_PLUGIN_REGISTRY`);
    acc[p.id] = p;
    return acc;
  }, {}),
);

/** All registered plugin ids, in registry order. */
export function listProverPluginIds(): string[] {
  return PROVER_PLUGIN_REGISTRY.map((p) => p.id);
}

/** Look up a plugin by exact id, or `undefined`. */
export function getProverPluginById(id: string): ProverPlugin | undefined {
  return PROVER_PLUGIN_BY_ID[id.trim().toLowerCase()];
}

/** A ranked selection result. */
export interface ProverSelection {
  plugin: ProverPlugin;
  match: ProverMatch;
}

/** Can the caller's services satisfy everything this plugin declared it needs? */
function servicesSatisfied(plugin: ProverPlugin, services: ProverServices | undefined): boolean {
  const required = plugin.requiresServices ?? [];
  if (required.length === 0) return true;
  if (!services) return false;
  return required.every((key) => services[key] !== undefined);
}

/**
 * Rank every plugin against `ctx`, best first. Plugins scoring 0, and plugins
 * whose required services are unavailable, are excluded. Ties keep registry
 * order, so selection is deterministic for a given registry.
 */
export function rankProverPlugins(ctx: ProverContext, services?: ProverServices): ProverSelection[] {
  const ranked: Array<ProverSelection & { order: number }> = [];
  PROVER_PLUGIN_REGISTRY.forEach((plugin, order) => {
    if (!servicesSatisfied(plugin, services)) return;
    const match = plugin.matches(ctx);
    if (match.score <= 0) return;
    ranked.push({ plugin, match, order });
  });
  ranked.sort((a, b) => (b.match.score - a.match.score) || (a.order - b.order));
  return ranked.map(({ plugin, match }) => ({ plugin, match }));
}

/** The single best plugin for `ctx`, or `undefined` when none applies. */
export function selectProverPlugin(ctx: ProverContext, services?: ProverServices): ProverSelection | undefined {
  return rankProverPlugins(ctx, services)[0];
}
