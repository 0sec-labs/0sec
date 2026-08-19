/**
 * Optional CPG localisation for the craft path.
 *
 * CyberGym hands the agent a source tree and a vulnerability description, but
 * flat file exploration cannot cheaply reconstruct an alloc → call → free path
 * across files. When a trusted caller has provisioned a Joern GraphSON export
 * for that exact pre-patch tree, this adapter turns description anchors into a
 * bounded reachability slice and injects it as evidence, never as a verdict.
 *
 * Missing or malformed CPG input fails open: the normal source-tool workflow
 * remains available. Joern itself stays outside the agent container.
 */

import { existsSync } from "node:fs";
import { truncateMiddle } from "../agent/output-truncation.js";
import { loadCpg, sliceAroundTargets, type SliceRenderStats } from "./graph-slice.js";

const MAX_BLOCK_BYTES = 12_000;
const FUNCTION_ANCHOR = /`([~A-Za-z_][\w:<>~]*)\s*(?:\(\))?`|\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(/g;
const NON_FUNCTIONS = new Set(["if", "for", "while", "switch", "return", "sizeof"]);

export interface CraftCpgLocalization {
  /** A pre-exported Joern GraphSON file for the exact source tree being crafted. */
  cpgPath: string;
  /** Optional explicit slice roots. Omit to derive function anchors from the description. */
  targetFunctions?: string[];
  /** Caller/callee hop radius. Defaults to 3. */
  hops?: number;
}

export interface CraftCpgContext {
  cpgPath: string;
  targetFunctions: string[];
  resolvedTargets: number;
  stats: SliceRenderStats;
  /** A bounded, model-ready evidence block. */
  promptBlock: string;
}

/** Extract likely function identifiers without treating generic C syntax as evidence. */
export function extractCraftCpgTargets(description: string): string[] {
  const targets = new Set<string>();
  for (const match of description.matchAll(FUNCTION_ANCHOR)) {
    const name = match[1] ?? match[2];
    if (name && !NON_FUNCTIONS.has(name)) targets.add(name);
  }
  return [...targets];
}

/**
 * Build a compact interprocedural evidence block for a craft target. Callers
 * must point `cpgPath` at a CPG generated from the same pre-patch tree; a CPG
 * from another revision is misleading evidence and is intentionally not
 * discovered implicitly.
 */
export function buildCraftCpgContext(
  description: string,
  localization: CraftCpgLocalization,
  log: (message: string) => void = () => {},
): CraftCpgContext | undefined {
  const targetFunctions = localization.targetFunctions?.filter(Boolean) ?? extractCraftCpgTargets(description);
  if (targetFunctions.length === 0) {
    log("[craft-cpg] no function anchors in the description — using source tools without a CPG slice");
    return undefined;
  }
  if (!existsSync(localization.cpgPath)) {
    log(`[craft-cpg] no CPG export at ${localization.cpgPath} — using source tools without a CPG slice`);
    return undefined;
  }

  try {
    const cpg = loadCpg(localization.cpgPath);
    const slice = sliceAroundTargets(cpg, targetFunctions, { hops: localization.hops ?? 3 });
    if (!slice) {
      log(`[craft-cpg] none of ${targetFunctions.join(", ")} resolved in ${localization.cpgPath} — using source tools without a CPG slice`);
      return undefined;
    }
    const bounded = truncateMiddle(slice.text, { limit: MAX_BLOCK_BYTES, mode: "bytes" }).text;
    return {
      cpgPath: localization.cpgPath,
      targetFunctions,
      resolvedTargets: slice.targetCount,
      stats: slice.stats,
      promptBlock:
        `## CPG reachability map (evidence, not a verdict)\n` +
        `The pre-patch GraphSON resolves ${slice.targetCount} description anchor(s): ${targetFunctions.join(", ")}. ` +
        `It covers ${slice.stats.functions} function(s), ${slice.stats.files.length} file(s), and ${slice.stats.callEdges} call edge(s).\n\n` +
        `${bounded}\n\n` +
        "Use this map to choose files and trace cross-function data/control flow. Confirm every claimed path in the source and with test_poc; the slice can be incomplete and is never proof that a candidate is reachable.",
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    log(`[craft-cpg] could not load ${localization.cpgPath}: ${reason.slice(0, 200)} — using source tools without a CPG slice`);
    return undefined;
  }
}
