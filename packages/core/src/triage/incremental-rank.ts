/**
 * Incremental Finding Ranking via decimal insertion.
 *
 * Inspired by the bounty-rank approach from open-kritt research (AGPL-3.0
 * reference).  This is a fresh reimplementation: it ranks findings by their
 * comparative promise for a security researcher — exploitability × impact ×
 * evidence strength — and supports APPEND-only insertion of new findings
 * into an existing rank order using decimal positions.
 *
 * Key design choices:
 *   - Pure function exports; no env reads or flags.
 *   - Two-mode prompt: `full_rerank` (no anchors, 1..N) or `append` (decimal
 *     insertion into an existing anchor scale).
 *   - Validation rejects unknown ids, duplicates, missing targets, and anchor
 *     order inversion.
 *   - Retry-exhaustion FAIL-SOFT: input order appended after anchors, never
 *     dropping findings.
 *
 * @module
 */

import type { NativeRuntime, NativeMessage, NativeContentBlock } from "../runtime/types.js";

// ── Types ──

/**
 * A finding id already in the rank order.  These ids are treated as immutable
 * reference points: their RELATIVE order is fixed, though their numeric ranks
 * shift during renumbering.
 */
export interface RankedAnchor {
  id: string;
  rank: number;
}

/**
 * A ranking result for one finding.
 */
export interface RankedResult {
  id: string;
  rank: number;
  impactLevel?: "critical" | "high" | "medium" | "low" | "informational";
  reasoning?: string;
}

/**
 * Minimal item contract consumed by the ranking module.  Mappers from full
 * `Finding` objects are the caller's responsibility.
 */
export interface DedupeItem {
  id: string;
  summary: string;
  category: string;
  location: string;
  description: string;
}

// ── Option Types ──

export interface BuildRankPromptOptions {
  /** Override the default ranking rubric. */
  rubric?: string;
}

export interface RankIncrementalOptions {
  /**
   * Already-ranked anchors that define the existing order.  When non-empty,
   * the module operates in `append` mode (decimal insertion); when empty,
   * `full_rerank` mode assigns 1..N.
   */
  anchors?: RankedAnchor[];
  /** Maximum LLM retries on parse/validation failure.  Default 2. */
  maxRetries?: number;
  /** Extra rubric text appended to the system prompt. */
  rubric?: string;
}

// ── Prompt Builder ──

const DEFAULT_RUBRIC = `Rank each finding by its comparative promise for a security researcher.

Score the following dimensions equally:
  1. EXPLOITABILITY — how reliably can an attacker trigger this?  Requires
     no preconditions, no authentication bypass, no chained bugs?  Prefer
     direct trigger paths over multi-step chains.
  2. IMPACT — what is the worst realistic outcome?  Remote code execution
     and data exfiltration outrank denial of service or information leaks.
     Consider the confidentiality / integrity / availability trade-off.
  3. EVIDENCE STRENGTH — does the finding include a working reproduction
     (request + response, PoC code, crash trace)?  Weak evidence (speculative,
     theoretical, best-effort log) reduces practical value even if
     exploitation would be severe.`;

function serializeItems(items: DedupeItem[]): string {
  return items
    .map(
      (f) =>
        `[${f.id}]\n  Summary: ${f.summary}\n  Category: ${f.category}\n  Location: ${f.location}\n  Description: ${f.description}`,
    )
    .join("\n\n");
}

function serializeAnchors(anchors: RankedAnchor[]): string {
  return anchors.map((a) => `  ${a.rank}. ${a.id}`).join("\n");
}

const OUTPUT_SCHEMA = `{
  "rankings": [
    {
      "id": "finding-id-string",
      "rank": 1.0,
      "impact_level": "critical|high|medium|low|informational",
      "reasoning": "brief justification"
    }
  ]
}`;

/**
 * Build a system + user prompt pair for the ranking LLM call.
 *
 * @param anchors - Previously-ranked anchors (empty => full_rerank mode).
 * @param targets - The new findings to rank.
 * @param opts - Optional rubric override.
 */
export function buildRankPrompt(
  anchors: RankedAnchor[],
  targets: DedupeItem[],
  opts?: BuildRankPromptOptions,
): { systemPrompt: string; userPrompt: string } {
  const rubricText = opts?.rubric ?? DEFAULT_RUBRIC;
  const anchorSection =
    anchors.length > 0
      ? `## Existing Rank Order

The following findings are already ranked.  Their RELATIVE order is fixed and
MUST be preserved.  Place new findings BETWEEN existing ranks by assigning a
DECIMAL position that fits between the adjacent integer ranks (e.g., rank 2.5
places a finding between rank 2 and rank 3).

Current anchor ranks:
${serializeAnchors(anchors)}

RULES for append mode:
  - Every existing anchor rank MUST remain in its current relative position.
  - New findings MUST receive decimal ranks that slot them between existing
    integer ranks, or before rank 1 (use 0.0–0.999) or after the last rank
    (use last+0.0–0.999 or a fractional value > the last anchor rank).
  - Decimal precision: at most 3 decimal places.
  - Do NOT reassign or renumber any existing anchor rank value.`
      : `## Full Rerank Mode

No existing rank order is present.  Assign each finding a UNIQUE consecutive
integer rank from 1 to N, where N is the total number of findings.

RULES for full rerank mode:
  - Ranks MUST be consecutive integers 1, 2, 3, ... N.
  - No ties — every finding gets a unique rank.`;

  const systemPrompt = `You are a finding ranking agent.  Your task is to rank security findings by their comparative promise for a security researcher.

${rubricText}

${anchorSection}

## Expected JSON Output (NO markdown fencing, NO extra text)

You MUST respond with ONLY a JSON object exactly matching this schema:

${OUTPUT_SCHEMA}

Constraints:
  - Every target finding from the user message MUST appear in the "rankings" array exactly once.
  - No ids outside the target list may appear.
  - No extra fields beyond the schema above.`;

  const targetsText = serializeItems(targets);

  const modeLabel = anchors.length > 0 ? "append" : "full_rerank";
  const userPrompt = `Mode: ${modeLabel}
Target count: ${targets.length}

## Findings to Rank

${targetsText}

Assign ranks according to the system prompt rules.  Return only the JSON object with the "rankings" array.`;

  return { systemPrompt, userPrompt };
}

// ── Validation ──

/**
 * Rank payload returned by the LLM before applying back to anchors.
 */
export interface RankPayload {
  rankings: Array<{
    id: string;
    rank: number;
    impact_level?: "critical" | "high" | "medium" | "low" | "informational";
    reasoning?: string;
  }>;
}

/**
 * Validation error describing what went wrong.
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(`Rank validation: ${message}`);
    this.name = "ValidationError";
  }
}

/**
 * Hard-check a parsed rank payload for correctness.
 *
 * @param payload - Parsed LLM output.
 * @param anchors - Current anchors (may be empty for full_rerank mode).
 * @param targetIds - Set of known target finding ids.
 * @returns The validated payload on success.
 * @throws ValidationError on any violation.
 */
export function validateRankPayload(
  payload: RankPayload,
  anchors: RankedAnchor[],
  targetIds: Set<string>,
): RankPayload {
  if (!payload.rankings || !Array.isArray(payload.rankings)) {
    throw new ValidationError("rankings field must be an array");
  }

  // Build id -> assigned rank for lookup
  const assigned = new Map<string, number>();

  for (const r of payload.rankings) {
    if (!r.id || typeof r.id !== "string") {
      throw new ValidationError(`entry missing string 'id' field`);
    }

    // Must be a known target id
    if (!targetIds.has(r.id)) {
      throw new ValidationError(`unknown id "${r.id}" — not in target set`);
    }

    // Rank must be a finite number
    if (typeof r.rank !== "number" || !Number.isFinite(r.rank)) {
      throw new ValidationError(`non-finite rank for "${r.id}": ${r.rank}`);
    }

    // No duplicate ids
    if (assigned.has(r.id)) {
      throw new ValidationError(`duplicate id "${r.id}"`);
    }

    assigned.set(r.id, r.rank);
  }

  // Every target id must appear exactly once
  for (const id of targetIds) {
    if (!assigned.has(id)) {
      throw new ValidationError(`missing target id "${id}"`);
    }
  }

  // Append mode: anchors MUST keep their relative order after new targets are
  // interleaved.  Build the full sorted list and verify anchors appear
  // in their original relative order.
  if (anchors.length > 1) {
    const fullOrder = [...anchors, ...payload.rankings].sort(
      (a, b) => a.rank - b.rank,
    );

    let anchorIdx = 0;
    for (const entry of fullOrder) {
      if (anchorIdx < anchors.length && entry.id === anchors[anchorIdx].id) {
        anchorIdx++;
      }
    }

    if (anchorIdx < anchors.length) {
      throw new ValidationError(
        `anchor order NOT preserved: anchor "${anchors[anchorIdx].id}" appears earlier than expected relative to other anchors`,
      );
    }
  }

  return payload;
}

// ── Apply Updates ──

export interface ApplyResult {
  /** Ranks for all targets (renumbered to consecutive integers). */
  updates: RankedResult[];
  /**
   * Anchors with updated consecutive ranks.  The numeric values WILL change,
   * but the anchor ORDER is immutable — this is intentional.
   */
  renumberedAnchors: RankedAnchor[];
}

/**
 * Merge anchors + ranked targets, sort by (rank, anchor-before-target tie, id),
 * then renumber to 1..N consecutive integers.
 *
 * IMPORTANT: anchor NUMBERS change (they shift to the new consecutive
 * sequence), but anchor ORDER is never altered.  The caller should discard
 * the old numeric ranks and use the new ones.
 */
export function applyRankUpdates(
  anchors: RankedAnchor[],
  targets: DedupeItem[],
  payload: RankPayload,
): ApplyResult {
  const targetRankMap = new Map(payload.rankings.map((r) => [r.id, r]));

  // Merge anchors + target entries; sort by (rank, anchor-before-target, id)
  const anchorSet = new Set(anchors.map((a) => a.id));
  const merged = [
    ...anchors.map((a) => ({
      id: a.id,
      rank: a.rank,
      isAnchor: true,
      targetEntry: null as RankPayload["rankings"][number] | null,
    })),
    ...targets.map((t) => {
      const pr = targetRankMap.get(t.id)!;
      return {
        id: t.id,
        rank: pr.rank,
        isAnchor: false,
        targetEntry: pr,
      };
    }),
  ];

  // Sort: primary by rank ascending, tie-break anchors before targets,
  // secondary by id for determinism.
  merged.sort((a, b) => {
    const rankDiff = a.rank - b.rank;
    if (rankDiff !== 0) return rankDiff;
    if (a.isAnchor && !b.isAnchor) return -1;
    if (!a.isAnchor && b.isAnchor) return 1;
    return a.id.localeCompare(b.id);
  });

  // Renumber to 1..N consecutive integers
  const updates: RankedResult[] = [];
  const renumberedAnchors: RankedAnchor[] = [];

  merged.forEach((entry, i) => {
    const newRank = i + 1;

    if (entry.isAnchor) {
      renumberedAnchors.push({ id: entry.id, rank: newRank });
    } else if (entry.targetEntry) {
      updates.push({
        id: entry.id,
        rank: newRank,
        impactLevel: entry.targetEntry.impact_level,
        reasoning: entry.targetEntry.reasoning,
      });
    }
  });

  return { updates, renumberedAnchors };
}

// ── LLM Driver ──

/**
 * Rank new findings relative to (or starting from) the existing anchor order.
 *
 * Retry discipline:
 *   - maxRetries (default 2): on parse/validation failure, append error
 *     feedback and retry.
 *   - Exhaustion FAIL-SOFT: targets appended after anchors in their original
 *     input order; never drops a finding.
 *
 * @param targets - New findings to rank (deduplicated, canonical ids).
 * @param runtime - NativeRuntime for LLM calls.
 * @param opts - Anchors, maxRetries, and optional rubric.
 * @returns Merged, renumbered ranks for all items.
 */
export async function rankIncremental(
  targets: DedupeItem[],
  runtime: NativeRuntime,
  opts?: RankIncrementalOptions,
): Promise<ApplyResult> {
  const anchors = opts?.anchors ?? [];
  const maxRetries = opts?.maxRetries ?? 2;
  const rubric = opts?.rubric;

  const targetIds = new Set(targets.map((t) => t.id));

  let lastError: string | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const { systemPrompt, userPrompt } = buildRankPrompt(anchors, targets, {
      rubric: rubric ?? undefined,
    });

    const feedbackText =
      lastError !== null
        ? `${userPrompt}

Previous attempt failed with: ${lastError}

Correct the output and try again.`
        : userPrompt;

    const feedbackMessage: NativeMessage = {
      role: "user" as const,
      content: [{ type: "text" as const, text: feedbackText }],
    };

    const result = await runtime.executeNative(systemPrompt, [feedbackMessage], []);

    const textBlocks = result.content.filter(
      (b): b is NativeContentBlock & { type: "text" } => b.type === "text",
    );
    const responseText = textBlocks.map((b) => b.text).join("\n").trim();

    // Strip markdown fences if present
    const jsonText = responseText.replace(/^```(?:json)?\s*/, "").replace(/\s*```$/, "");

    let payload: RankPayload;
    try {
      payload = JSON.parse(jsonText) as RankPayload;
    } catch {
      lastError = `Failed to parse LLM response as JSON — raw text: "${responseText.slice(0, 500)}"`;
      continue;
    }

    try {
      validateRankPayload(payload, anchors, targetIds);
    } catch (err) {
      lastError = err instanceof ValidationError ? err.message : String(err);
      continue;
    }

    // Success — apply and return
    return applyRankUpdates(anchors, targets, payload);
  }

  // FAIL-SOFT: append targets after anchors in input order
  const fallbackAnchorEntries = anchors.map((a) => ({ id: a.id, rank: a.rank }));
  let nextRank = anchors.length + 1;
  const fallbackUpdates: RankedResult[] = targets.map((t) => ({
    id: t.id,
    rank: nextRank++,
  }));
  const fallbackRenumbered: RankedAnchor[] = fallbackAnchorEntries.map((a, i) => ({
    id: a.id,
    rank: i + 1,
  }));

  return { updates: fallbackUpdates, renumberedAnchors: fallbackRenumbered };
}