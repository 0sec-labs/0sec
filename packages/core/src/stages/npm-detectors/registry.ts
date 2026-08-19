/**
 * The npm dynamic-discovery **detector registry** — the extension point that
 * makes the stage a self-extending flywheel. Every confirmed novel bug class
 * (from ANY method) can become a new {@link Detector} that runs at ecosystem
 * scale by adding one file under this directory and registering it here.
 * Follow `docs/operations/detector-from-finding.md` to derive one from a
 * confirmed finding + its PoC.
 *
 * Same idiom as the engine's other catalogs (`runtime/registry.ts`,
 * `triage/router/layer-registry.ts`): a frozen `readonly` array plus a
 * `*_BY_ID` map for O(1) lookup. The shared discipline (assume-FP + dedup +
 * downloads-floor / freshness) is enforced in `base.ts`, NOT here — the
 * registry only catalogs; it cannot exempt a detector from the gates.
 */

import type { Detector, DetectorCandidate } from "./types.js";
import { ssppFuzzDetector } from "./sspp-fuzz.js";
import { readUnstableDetector } from "./read-unstable.js";
import { parserDiffDetector } from "./parser-diff.js";

/** A detector with its candidate type erased for uniform storage/iteration. */
export type AnyDetector = Detector<DetectorCandidate>;

// Each concrete detector only ever receives the candidates its own
// `identifyCandidates` produced, so erasing the candidate generic for storage
// is sound (the stage pairs identify→confirm on the same detector instance).
function asAny<C extends DetectorCandidate>(d: Detector<C>): AnyDetector {
  return d as unknown as AnyDetector;
}

/**
 * The registered detectors. Order is the default execution order used by the
 * stage when `--detectors` is not narrowed.
 */
export const DETECTOR_REGISTRY: readonly AnyDetector[] = Object.freeze([
  asAny(ssppFuzzDetector),
  asAny(readUnstableDetector),
  asAny(parserDiffDetector),
]);

/** O(1) lookup by detector id. */
export const DETECTOR_REGISTRY_BY_ID: Readonly<Record<string, AnyDetector>> = Object.freeze(
  DETECTOR_REGISTRY.reduce<Record<string, AnyDetector>>((acc, d) => {
    if (acc[d.id]) throw new Error(`Duplicate detector id "${d.id}" in DETECTOR_REGISTRY`);
    acc[d.id] = d;
    return acc;
  }, {}),
);

/** All registered detector ids, in execution order. */
export function listDetectorIds(): string[] {
  return DETECTOR_REGISTRY.map((d) => d.id);
}

/** Look up a detector by id, or undefined. */
export function getDetectorById(id: string): AnyDetector | undefined {
  return DETECTOR_REGISTRY_BY_ID[id];
}

/**
 * Resolve a requested detector-id list to registered detectors. Unknown ids
 * are returned in `unknown` (the caller decides whether to error or warn).
 * An empty/undefined request resolves to the full registry (all detectors).
 */
export function resolveDetectors(ids?: string[]): { detectors: AnyDetector[]; unknown: string[] } {
  if (!ids || ids.length === 0) return { detectors: [...DETECTOR_REGISTRY], unknown: [] };
  const detectors: AnyDetector[] = [];
  const unknown: string[] = [];
  for (const id of ids) {
    const d = getDetectorById(id);
    if (d) detectors.push(d);
    else unknown.push(id);
  }
  return { detectors, unknown };
}
