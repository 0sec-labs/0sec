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

import type { Finding } from "@0sec/shared";
import type { NativeRuntime } from "../runtime/types.js";
import { semanticDedupe, rankIncremental, type DedupeItem } from "../triage/index.js";

export type { DedupeItem };

/**
 * Minimal interface for loading prior-scan findings from the local DB.
 * Accepts any object shaped like the osecDB subset so tests can fake it
 * without a real database.
 */
export interface PriorScanLoader {
  listScansByTarget(target: string, opts?: { limit?: number }): Array<{ id: string; status: string; target: string }>;
  getScanFindings(scanId: string): Array<{
    id: string;
    title: string;
    category: string;
    description: string;
    // Persisted as serialized JSON (see @0sec/db findings.reviewAnnotation);
    // accepted in both forms for the same reason semanticDedupe is.
    reviewAnnotation?: { path?: string; startLine?: number } | string | null;
    semanticDedupe?: { isCanonical?: boolean } | string | null;
  }>;
}

/** Options for the post-scan post-process pass. */
export interface FindingPostProcessOptions {
  /** Run the semantic dedupe pass (0SEC_FEATURE_SEMANTIC_DEDUPE). */
  semanticDedupe?: boolean;
  /** Run the incremental ranking pass (0SEC_FEATURE_INCREMENTAL_RANK). */
  incrementalRank?: boolean;
  /** Scan identifier used to build stable cluster ids. */
  scanId?: string;
  /** Anchors from prior runs — already-canonical findings presented as immutable. */
  anchors?: DedupeItem[];
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
 * The review annotation is stored as serialized JSON, so a row read
 * straight from the database hands it over as a string. Parse defensively:
 * a malformed payload must degrade to "no location", never throw during a
 * scan post-process pass.
 */
function parseReviewAnnotation(
  value: { path?: string; startLine?: number } | string | null | undefined,
): { path?: string; startLine?: number } | null {
  if (value == null) return null;
  let parsed: unknown = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  return parsed as { path?: string; startLine?: number };
}

function isPersistedDuplicate(
  semanticDedupe: { isCanonical?: boolean } | string | null | undefined,
): boolean {
  if (semanticDedupe == null) return false;
  let parsed: unknown = semanticDedupe;
  if (typeof semanticDedupe === "string") {
    try {
      parsed = JSON.parse(semanticDedupe);
    } catch {
      return false;
    }
  }
  return (
    typeof parsed === "object" &&
    parsed !== null &&
    "isCanonical" in parsed &&
    parsed.isCanonical === false
  );
}

/**
 * Load finding anchors from the most recent prior scan for the same target.
 * Returns up to `opts.limit` (default 100) `DedupeItem` projections, or []
 * when there is no prior scan or it has no findings.
 */
export async function loadPriorScanAnchors(
  db: PriorScanLoader,
  target: string,
  opts?: { excludeScanId?: string; limit?: number },
): Promise<DedupeItem[]> {
  const scans = db.listScansByTarget(target, { limit: 5 });
  // Find the latest prior scan excluding the given scanId
  const prior = opts?.excludeScanId
    ? scans.find((s) => s.id !== opts.excludeScanId)
    : scans[0];
  if (!prior) return [];

  const findings = db.getScanFindings(prior.id);
  if (!findings || findings.length === 0) return [];

  const limit = opts?.limit ?? 100;
  const items: DedupeItem[] = [];
  for (const f of findings) {
    // A persisted non-canonical finding is already represented by its cluster
    // anchor. Do not bloat later prompts or let it compete as a second anchor.
    if (isPersistedDuplicate(f.semanticDedupe)) continue;
    if (items.length >= limit) break;
    const annotation = parseReviewAnnotation(f.reviewAnnotation);
    const loc = annotation
      ? `${annotation.path ?? "unknown"}:${annotation.startLine ?? 0}`
      : "unknown";
    items.push({
      id: f.id,
      summary: f.title,
      category: f.category,
      location: loc,
      description: f.description ?? "",
    });
  }

  return items;
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
    const result = await semanticDedupe(items, runtime, {
      scanId: opts.scanId,
      anchors: opts.anchors,
    });
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