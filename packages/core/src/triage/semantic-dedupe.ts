/**
 * ANCHORED INCREMENTAL SEMANTIC DEDUPE
 *
 * Deduplicates scan findings via LLM-based semantic clustering. Uses an
 * anchored approach: already-canonicalized findings (anchors) are presented
 * alongside new findings (targets) in batches. After each batch, new
 * canonicals become anchors for subsequent batches — recursive anchoring
 * that scales to hundreds of findings without degrading quality.
 *
 * Design:
 * - Findings projected to compact DedupeItem for the LLM.
 * - Targets processed in batches of SEMANTIC_DEDUPE_BATCH_SIZE.
 * - Each batch sent to the LLM alongside the growing anchor set.
 * - LLM returns clusters: targets sharing the same root cause and location.
 * - On parse/validation failure, retry with error as feedback.
 * - On exhaustion, fail-soft: every remaining target becomes a singleton
 *   (never drop a finding).
 * - All exported functions are pure except the runtime.executeNative call.
 *
 * Algorithm/idea reference: open-kritt's post_processing.py (AGPL-3.0).
 * Reimplemented fresh — no source text or prompt wording copied.
 */

import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
  NativeRuntimeResult,
} from "../runtime/types.js";

// ── Constants ──

/** Maximum number of target findings per LLM call. */
export const SEMANTIC_DEDUPE_BATCH_SIZE = 50;

// ── Core Types ──

/**
 * A compact, LLM-friendly projection of a finding.
 */
export interface DedupeItem {
  /** Unique identifier (must match a Finding id for traceability). */
  id: string;
  /** Short title or summary of the finding. */
  summary: string;
  /** Vulnerability category (e.g. "use-after-free", "sql-injection"). */
  category: string;
  /** Source location: file path and line, e.g. "src/main.rs:120". */
  location: string;
  /** Full description or evidence, truncated to ~4000 chars. */
  description: string;
}

/** Options for the semantic dedupe process. */
export interface DedupeOptions {
  /** Anchors from prior runs — already-canonical findings presented as immutable. */
  anchors?: DedupeItem[];
  /** Max retries per batch on parse/validation failure (default 2). */
  maxRetries?: number;
  /** Scan identifier for building stable cluster ids. */
  scanId?: string;
}

/** Per-finding dedupe mapping. */
export interface FindingMapping {
  /** The id of the canonical finding this finding maps to. */
  canonicalId: string;
  /** Whether this finding IS the canonical for its cluster. */
  isCanonical: boolean;
  /** Stable cluster identifier: `${scanId}:${canonicalId}`. */
  clusterId: string;
  /** Human-readable reason for this dedupe decision. */
  reason: string;
}

/** Full result of a semantic dedupe run. */
export interface DedupeResult {
  /** Per-finding mapping keyed by finding id. */
  mappings: Record<string, FindingMapping>;
  /** Total LLM calls made (including retries). */
  modelCalls: number;
  /** Total retry attempts across all batches. */
  retries: number;
  /** Per-canonical cluster reason strings. */
  clusterReasons: Record<string, string>;
}

/** Raw LLM output shape for a dedupe response. */
export interface DedupePayload {
  clusters: Array<{
    ids: string[];
    reason: string;
  }>;
}

// ── Errors ──

/**
 * Thrown when the LLM response fails validation against the
 * known anchor/target id sets.
 */
export class DedupeValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DedupeValidationError";
  }
}

// ── Helpers ──

/**
 * Truncate a string to at most `max` characters, appending "..." if truncated.
 */
function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, Math.max(0, max - 3)) + "...";
}

// ── Prompt Building ──

/**
 * Build the system and user prompts for a dedupe LLM call.
 *
 * @param anchors - Already-canonical findings (immutable).
 * @param targets - New findings to classify.
 * @param feedback - Optional error message from a prior attempt to append as feedback.
 * @returns The system prompt and user prompt strings.
 */
export function buildDedupePrompt(
  anchors: DedupeItem[],
  targets: DedupeItem[],
  feedback?: string,
): { systemPrompt: string; userPrompt: string } {
  // Project items to compact JSON
  const anchorItems = anchors.map((a) => ({
    id: a.id,
    summary: a.summary,
    category: a.category,
    location: a.location,
    description: truncate(a.description, 4000),
  }));
  const targetItems = targets.map((t) => ({
    id: t.id,
    summary: t.summary,
    category: t.category,
    location: t.location,
    description: truncate(t.description, 4000),
  }));

  const systemPrompt = [
    "You are a senior security engineer performing semantic deduplication on scan findings.",
    "",
    "Your task: group findings that describe the SAME root cause at the SAME code location or entry point.",
    "",
    "Rules:",
    "- Cluster findings only when ONE fix would address the same root cause AND the same location or entrypoint.",
    "- NEVER cluster findings merely because they share the same vulnerability class (e.g., two different UAFs in different functions).",
    "- Existing anchors (previously-canonicalized findings) are immutable — they cannot be merged, demoted, or replaced.",
    "- Every target finding must appear exactly once across all clusters, including as singletons.",
    "- A singleton is a finding that has no semantic duplicate in the input.",
    "",
    `Output ONLY valid JSON with this exact structure (no markdown, no extra text):
${JSON.stringify({
  clusters: [
    { ids: ["target-id-1", "target-id-2"], reason: "Brief explanation of why these merge" },
    { ids: ["target-id-3"], reason: "No semantic duplicate found" },
  ],
}, null, 2)}`,
  ].join("\n");

  const anchorSection =
    anchors.length > 0
      ? `## Anchors (already-canonical findings — immutable)\n${JSON.stringify(anchorItems, null, 2)}\n`
      : "## Anchors\nNone.\n";

  let userPrompt = [
    anchorSection,
    "",
    "## Targets (findings to deduplicate)",
    JSON.stringify(targetItems, null, 2),
    "",
    "Group the target findings by semantic equivalence. A cluster may include an anchor id as the canonical — all target ids in that cluster become duplicates of that anchor. A cluster with only target ids creates a new canonical group (the first target id in the cluster becomes the canonical). Every target id must appear exactly once.",
  ].join("\n");

  if (feedback) {
    userPrompt += `\n\n## Previous Error\nYour previous response had an error. Please fix it:\n${feedback}`;
  }

  return { systemPrompt, userPrompt };
}

// ── Response Parsing ──

/**
 * Parse the LLM JSON response, stripping markdown code fences.
 * Throws on unparseable output.
 */
function parseDedupeResponse(raw: string): DedupePayload {
  const cleaned = raw
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```\s*$/, "")
    .trim();
  if (!cleaned) {
    throw new DedupeValidationError("Empty LLM response");
  }
  const parsed = JSON.parse(cleaned);
  if (!parsed || typeof parsed !== "object") {
    throw new DedupeValidationError("Response is not a JSON object");
  }
  if (!Array.isArray(parsed.clusters)) {
    throw new DedupeValidationError("Response missing 'clusters' array");
  }
  return parsed as DedupePayload;
}

// ── Validation ──

/**
 * Validate a dedupe payload against known anchor and target id sets.
 *
 * Checks:
 * - All ids are known (present in anchors ∪ targets).
 * - No id appears in more than one cluster.
 * - No cluster contains two different anchor ids (would merge anchors).
 * - Every cluster has at least one target id.
 * - Every target id appears in exactly one cluster.
 *
 * @throws DedupeValidationError on any violation.
 */
export function validateDedupePayload(
  payload: DedupePayload,
  anchorIds: Set<string>,
  targetIds: Set<string>,
): void {
  const knownIds = new Set([...anchorIds, ...targetIds]);
  const seenIds = new Set<string>();

  for (const cluster of payload.clusters) {
    // Cluster must have ids
    if (!Array.isArray(cluster.ids) || cluster.ids.length === 0) {
      throw new DedupeValidationError("Cluster has no ids");
    }

    // Cluster must have a reason
    if (typeof cluster.reason !== "string" || cluster.reason.trim().length === 0) {
      throw new DedupeValidationError(`Cluster [${cluster.ids.join(", ")}] missing reason`);
    }

    // Count anchor ids in this cluster
    const clusterAnchorIds = cluster.ids.filter((id) => anchorIds.has(id));
    if (clusterAnchorIds.length > 1) {
      throw new DedupeValidationError(
        `Cluster contains multiple anchor ids: ${clusterAnchorIds.join(", ")}`,
      );
    }

    // Cluster must have at least one target id
    const clusterTargetIds = cluster.ids.filter((id) => targetIds.has(id));
    if (clusterTargetIds.length === 0) {
      throw new DedupeValidationError(
        `Cluster [${cluster.ids.join(", ")}] has no target findings`,
      );
    }

    for (const id of cluster.ids) {
      // All ids must be known
      if (!knownIds.has(id)) {
        throw new DedupeValidationError(`Unknown id in cluster: ${id}`);
      }
      // No duplicates across clusters
      if (seenIds.has(id)) {
        throw new DedupeValidationError(`Duplicate id across clusters: ${id}`);
      }
      seenIds.add(id);
    }
  }

  // Every target must appear exactly once across all clusters
  const coveredTargets = new Set(
    payload.clusters.flatMap((c) => c.ids.filter((id) => targetIds.has(id))),
  );

  for (const id of targetIds) {
    if (!coveredTargets.has(id)) {
      throw new DedupeValidationError(`Target id not covered in any cluster: ${id}`);
    }
  }
}

// ── Mapping ──

/**
 * Convert validated clusters into per-finding mappings.
 *
 * @param clusters - Validated clusters from the LLM.
 * @param anchorIds - Known anchor id set.
 * @param targetIds - Known target id set.
 * @param scanId - Scan identifier for cluster ids.
 * @returns Mappings keyed by finding id and per-canonical cluster reasons.
 */
export function mappingFromClusters(
  clusters: DedupePayload["clusters"],
  anchorIds: Set<string>,
  targetIds: Set<string>,
  scanId: string,
): { mappings: Record<string, FindingMapping>; clusterReasons: Record<string, string> } {
  const mappings: Record<string, FindingMapping> = {};
  const clusterReasons: Record<string, string> = {};

  for (const cluster of clusters) {
    const anchorsInCluster = cluster.ids.filter((id) => anchorIds.has(id));
    const targetsInCluster = cluster.ids.filter((id) => targetIds.has(id));

    // Canonical: the single anchor in the cluster, or the first target
    const canonicalId =
      anchorsInCluster.length === 1 ? anchorsInCluster[0] : targetsInCluster[0];

    clusterReasons[canonicalId] = cluster.reason;

    for (const id of cluster.ids) {
      const isCanonical = id === canonicalId;
      mappings[id] = {
        canonicalId,
        isCanonical,
        clusterId: `${scanId}:${canonicalId}`,
        reason: isCanonical ? cluster.reason : `Duplicate of ${canonicalId}: ${cluster.reason}`,
      };
    }
  }

  return { mappings, clusterReasons };
}

/**
 * Build a fail-soft fallback mapping: each target becomes its own canonical
 * singleton with the error reason. Used when the LLM exhausts retries.
 */
function buildFallbackMappings(
  targets: DedupeItem[],
  scanId: string,
): {
  mappings: Record<string, FindingMapping>;
  clusterReasons: Record<string, string>;
} {
  const mappings: Record<string, FindingMapping> = {};
  const clusterReasons: Record<string, string> = {};

  for (const target of targets) {
    mappings[target.id] = {
      canonicalId: target.id,
      isCanonical: true,
      clusterId: `${scanId}:${target.id}`,
      reason: "dedupe-error-fallback",
    };
    clusterReasons[target.id] = "dedupe-error-fallback";
  }

  return { mappings, clusterReasons };
}

// ── Main Entrypoint ──

/**
 * Run anchored incremental semantic dedupe on scan findings.
 *
 * Splits inputs into anchors (from prior runs) and targets (new findings),
 * then processes targets in batches. After each batch, new canonicals become
 * anchors for the next batch — recursive anchoring that scales linearly.
 *
 * @param items - DedupeItems to deduplicate (projected from findings).
 * @param runtime - NativeRuntime for LLM calls.
 * @param opts - DedupeOptions (anchors, maxRetries, scanId).
 * @returns DedupeResult with per-finding mapping and provenance.
 */
export async function semanticDedupe(
  items: DedupeItem[],
  runtime: NativeRuntime,
  opts: DedupeOptions = {},
): Promise<DedupeResult> {
  const srcAnchors = opts.anchors ?? [];
  const maxRetries = opts.maxRetries ?? 2;
  const scanId = opts.scanId ?? "default";

  // Separate anchors from targets
  const anchorIdSet = new Set(srcAnchors.map((a) => a.id));
  const anchorMap = new Map(srcAnchors.map((a) => [a.id, a]));
  const targets = items.filter((t) => !anchorIdSet.has(t.id));

  // Pre-populate mappings for existing anchors
  const allMappings: Record<string, FindingMapping> = {};
  const allClusterReasons: Record<string, string> = {};

  for (const anchor of srcAnchors) {
    allMappings[anchor.id] = {
      canonicalId: anchor.id,
      isCanonical: true,
      clusterId: `${scanId}:${anchor.id}`,
      reason: "Existing anchor from prior run",
    };
  }

  let modelCalls = 0;
  let totalRetries = 0;
  let currentAnchorIds = new Set(anchorIdSet);
  let currentAnchors = [...srcAnchors];
  const currentAnchorMap = new Map(srcAnchors.map((a) => [a.id, a]));

  // Process targets in batches
  for (let batchStart = 0; batchStart < targets.length; batchStart += SEMANTIC_DEDUPE_BATCH_SIZE) {
    const batch = targets.slice(batchStart, batchStart + SEMANTIC_DEDUPE_BATCH_SIZE);
    const batchTargetIds = new Set(batch.map((t) => t.id));

    let lastError: string | undefined;
    let success = false;
    let clusters: DedupePayload["clusters"] = [];

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) totalRetries++;

      const { systemPrompt, userPrompt } = buildDedupePrompt(
        currentAnchors,
        batch,
        lastError,
      );

      const userMessage: NativeMessage = {
        role: "user",
        content: [{ type: "text", text: userPrompt }],
      };

      let result: NativeRuntimeResult;
      try {
        result = await runtime.executeNative(systemPrompt, [userMessage], []);
        modelCalls++;
      } catch (e) {
        lastError = `Runtime error: ${e instanceof Error ? e.message : String(e)}`;
        continue;
      }

      if (result.stopReason === "error") {
        lastError = `LLM call failed: ${result.error ?? "unknown error"}`;
        continue;
      }

      const textBlocks = result.content.filter(
        (b): b is NativeContentBlock & { type: "text" } => b.type === "text",
      );
      const responseText = textBlocks.map((b) => b.text).join("\n");

      if (!responseText.trim()) {
        lastError = "Empty LLM response";
        continue;
      }

      // Parse
      let payload: DedupePayload;
      try {
        payload = parseDedupeResponse(responseText);
      } catch (e) {
        lastError = `Parse error: ${e instanceof Error ? e.message : String(e)}`;
        continue;
      }

      // Validate
      try {
        validateDedupePayload(payload, currentAnchorIds, batchTargetIds);
        clusters = payload.clusters;
        success = true;
        break;
      } catch (e) {
        lastError = `Validation error: ${e instanceof Error ? e.message : String(e)}`;
        continue;
      }
    }

    if (!success) {
      // Fail-soft: every remaining target becomes its own canonical singleton
      const { mappings, clusterReasons } = buildFallbackMappings(batch, scanId);
      Object.assign(allMappings, mappings);
      Object.assign(allClusterReasons, clusterReasons);

      // Add all batch items as new anchors for subsequent batches
      for (const target of batch) {
        if (!currentAnchorIds.has(target.id)) {
          currentAnchorIds.add(target.id);
          currentAnchors.push(target);
          currentAnchorMap.set(target.id, target);
        }
      }
      continue;
    }

    // Process successful clusters
    const { mappings, clusterReasons } = mappingFromClusters(
      clusters,
      currentAnchorIds,
      batchTargetIds,
      scanId,
    );

    Object.assign(allMappings, mappings);
    Object.assign(allClusterReasons, clusterReasons);

    // Update anchors for the next batch: new canonicals become anchors
    for (const [id, mapping] of Object.entries(mappings)) {
      if (mapping.isCanonical && !currentAnchorIds.has(id)) {
        const item = batch.find((t) => t.id === id);
        if (item) {
          currentAnchorIds.add(id);
          currentAnchors.push(item);
          currentAnchorMap.set(id, item);
        }
      }
    }
  }

  return {
    mappings: allMappings,
    modelCalls,
    retries: totalRetries,
    clusterReasons: allClusterReasons,
  };
}