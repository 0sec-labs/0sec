/**
 * Post-scan finding post-processing: intra-scan semantic dedupe and
 * incremental ranking (flag-gated, default OFF).
 *
 * Runs ONCE after the attack/triage/verify stages, on the final finding set,
 * before the report stage assembles the `ScanReport`. It mutates the
 * in-memory `Finding` objects in place (additive optional fields only):
 *
 *   - semantic dedupe → `finding.semanticDedupe` (canonical mapping + cluster
 *     reason), via `triage/semantic-dedupe.ts`
 *   - incremental ranking → `finding.findingRank` on canonicals, and a
 *     reorder that groups each duplicate directly after its canonical
 *     (cluster order = canonical rank), via `triage/incremental-rank.ts`
 *
 * Both are fail-soft by design: LLM failure never drops a finding (dedupe
 * falls back to singletons, ranking to input order) and the caller wraps the
 * whole pass in try/catch so a post-process error can never fail the scan.
 */

import type { Finding } from "@pwnkit/shared";
import type { NativeRuntime } from "../runtime/types.js";
import { semanticDedupe, rankIncremental, type DedupeItem } from "../triage/index.js";

/** Options for the post-scan post-process pass. */
export interface FindingPostProcessOptions {
  /** Run the semantic dedupe pass (PWNKIT_FEATURE_SEMANTIC_DEDUPE). */
  semanticDedupe?: boolean;
  /** Run the incremental ranking pass (PWNKIT_FEATURE_INCREMENTAL_RANK). */
  incrementalRank?: boolean;
  /** Scan identifier used to build stable cluster ids. */
  scanId?: string;
}

/**
 * Project a `Finding` into the compact `DedupeItem` shape the LLM post-pass
 * consumes. Location prefers the structured review annotation, else falls
 * back to a generic placeholder (never fabricates a path).
 */
function toDedupeItem(f: Finding): DedupeItem {
  const loc = f.reviewAnnotation
    ? `${f.reviewAnnotation.path}:${f.reviewAnnotation.startLine}`
    : "unknown";
  return {
    id: f.id,
    summary: f.title,
    category: f.category,
    location: loc,
    description: f.description ?? "",
  };
}

/**
 * Run the flag-gated post-pass over the final finding set.
 *
 * Order: dedupe first (canonical mapping), then rank ONLY the canonicals
 * (duplicates inherit their canonical's position via the sort key). Mutates
 * `findings` in place; returns the number of duplicates collapsed.
 */
export async function applyFindingPostProcess(
  findings: Finding[],
  runtime: NativeRuntime,
  opts: FindingPostProcessOptions = {},
): Promise<number> {
  if (findings.length === 0) return 0;

  let duplicateCount = 0;

  if (opts.semanticDedupe) {
    const items = findings.map(toDedupeItem);
    const result = await semanticDedupe(items, runtime, { scanId: opts.scanId });
    for (const f of findings) {
      const m = result.mappings[f.id];
      if (m) {
        f.semanticDedupe = m;
        if (!m.isCanonical) duplicateCount += 1;
      }
    }
  }

  if (opts.incrementalRank) {
    // Rank only canonical findings; duplicates inherit the canonical's rank
    // as the sort key so clusters stay grouped in report order.
    const canonicals = findings.filter((f) => f.semanticDedupe?.isCanonical ?? true);
    const { updates } = await rankIncremental(
      canonicals.map(toDedupeItem),
      runtime,
      {},
    );
    const rankById = new Map(updates.map((u) => [u.id, u.rank]));
    for (const f of canonicals) {
      const rank = rankById.get(f.id);
      if (rank !== undefined) f.findingRank = rank;
    }
    const clusterRankOf = (f: Finding): number => {
      const keyId = f.semanticDedupe?.canonicalId ?? f.id;
      return rankById.get(keyId) ?? Number.MAX_SAFE_INTEGER;
    };
    findings.sort((a, b) => clusterRankOf(a) - clusterRankOf(b));
  }

  return duplicateCount;
}
