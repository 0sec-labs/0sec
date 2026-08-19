// Expected-findings aliases, verdict parsing, and 4-pass reconciliation
// for the file-review revalidation stage. All modules are runtime-agnostic
// and fully testable — no network, no process spawning.

import type { ReviewFileRecord, ReviewRevalidationVerdict } from "./types.js";
import type { Severity } from "@0sec/shared";

// ── Inline JSON extractor ───────────────────────────────────────────────────
// (parse.ts not yet created — extractFencedJson lives here for now)

function extractFencedJson(text: string): unknown {
  // Try fenced code block: ```json ... ``` or ``` ...
  const fencedMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (fencedMatch) {
    try {
      return JSON.parse(fencedMatch[1].trim());
    } catch {
      /* fall through to bare JSON attempt */
    }
  }
  // Bare JSON array as fallback
  const bareMatch = text.match(/\[[\s\S]*?\]/);
  if (bareMatch) {
    try {
      return JSON.parse(bareMatch[0]);
    } catch {
      /* fall through */
    }
  }
  return null;
}

// ── Exported types ──────────────────────────────────────────────────────────

export interface ExpectedFinding {
  /** findingId from the store record (empty string if unset). */
  findingId: string;
  /** Relative file path (POSIX separators). */
  filePath: string;
  /** Finding title as stored. */
  title: string;
  /** Prompt-order alias F1..Fn. */
  alias: string;
}

export interface RevalidateVerdictInput {
  findingId: string;
  verdict: ReviewRevalidationVerdict;
  adjustedSeverity?: Severity;
  duplicateOf?: string;
  reasoning: string;
}

export interface MatchedPair {
  expected: ExpectedFinding;
  verdict: RevalidateVerdictInput;
  matchedBy: "finding-id" | "exact-title" | "normalized-title" | "unique-remainder";
}

export interface ReconcileResult {
  matched: MatchedPair[];
  unmatched: RevalidateVerdictInput[];
  missing: ExpectedFinding[];
}

// ── Static lookups ──────────────────────────────────────────────────────────

const VALID_VERDICTS: Record<string, true> = {
  "true-positive": true,
  "false-positive": true,
  fixed: true,
  uncertain: true,
  duplicate: true,
};

const VALID_SEVERITIES: Record<string, true> = {
  critical: true,
  high: true,
  medium: true,
  low: true,
  info: true,
};

// ── Severity ordering (critical strongest) ─────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityAtLeast(s: Severity, min: Severity): boolean {
  return (SEVERITY_RANK[s] ?? 99) <= (SEVERITY_RANK[min] ?? 99);
}

// ── normalizeTitle ──────────────────────────────────────────────────────────

/**
 * Unicode NFKC normalize, strip markdown backticks and quotes, collapse
 * whitespace, lowercase, drop trailing punctuation.
 */
export function normalizeTitle(t: string): string {
  return t
    .normalize("NFKC")
    .replace(/[`'"]/g, "")
    .replace(/[()[\]]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/[.,!?;:]+$/, "");
}

// ── expectedFindingsForBatch ────────────────────────────────────────────────

/**
 * Collect findings needing revalidation across a batch of records.
 * Findings that already have a `revalidation` field are skipped unless
 * `opts.force` is true. Each entry is assigned a prompt-order alias
 * F1, F2, … Fn.
 */
export function expectedFindingsForBatch(
  records: ReviewFileRecord[],
  opts?: { force?: boolean; minSeverity?: Severity },
): ExpectedFinding[] {
  const out: ExpectedFinding[] = [];
  let aliasIdx = 1;
  for (const record of records) {
    for (const finding of record.findings) {
      // Findings below the severity floor are never revalidated — they were
      // never in scope, so they must not surface as "missing" verdicts.
      if (opts?.minSeverity && !severityAtLeast(finding.severity, opts.minSeverity)) {
        continue;
      }
      if (!finding.revalidation || opts?.force) {
        out.push({
          findingId: finding.findingId ?? "",
          filePath: record.filePath,
          title: finding.title,
          alias: `F${aliasIdx}`,
        });
        aliasIdx++;
      }
    }
  }
  return out;
}

// ── parseRevalidateVerdicts ─────────────────────────────────────────────────

/**
 * Parse a fenced or bare JSON array of verdicts from model output.
 * Items failing validation are silently dropped.
 */
export function parseRevalidateVerdicts(text: string): RevalidateVerdictInput[] {
  const data = extractFencedJson(text);
  if (!Array.isArray(data)) return [];

  return data.filter((item): item is RevalidateVerdictInput => {
    if (!item || typeof item !== "object") return false;
    if (typeof item.findingId !== "string") return false;
    if (typeof item.verdict !== "string") return false;
    if (!VALID_VERDICTS[item.verdict]) return false;
    if (item.adjustedSeverity !== undefined && !VALID_SEVERITIES[item.adjustedSeverity]) return false;
    if (item.duplicateOf !== undefined && typeof item.duplicateOf !== "string") return false;
    if (typeof item.reasoning !== "string") return false;
    return true;
  });
}

// ── reconcileVerdicts ───────────────────────────────────────────────────────

/**
 * Reconcile model verdicts against the expected findings list using a
 * 4-pass deterministic matching strategy. Each expected finding is matched
 * at most once.
 *
 * Pass 1 — findingId / alias exact match (trimmed, case-insensitive for
 *           F-aliases).
 * Pass 2 — exact title match (verdict.findingId === expected.title).
 * Pass 3 — normalized title match (normalizeTitle both sides).
 * Pass 4 — unique remainder (exactly 1 expected + 1 verdict left → paired).
 */
export function reconcileVerdicts(
  expected: ExpectedFinding[],
  verdicts: RevalidateVerdictInput[],
): ReconcileResult {
  const expPool = [...expected];
  const verPool = [...verdicts];
  const matched: MatchedPair[] = [];

  // ── Pass 1: findingId / alias exact ──────────────────────────────────
  for (let ei = expPool.length - 1; ei >= 0; ei--) {
    const exp = expPool[ei];
    const normAlias = exp.alias.trim().toLowerCase();
    const normId = exp.findingId.trim();
    const vi = verPool.findIndex((ver) => {
      const vid = (ver.findingId ?? "").trim();
      return vid.toLowerCase() === normAlias || vid === normId;
    });
    if (vi !== -1) {
      matched.push({ expected: exp, verdict: verPool[vi], matchedBy: "finding-id" });
      verPool.splice(vi, 1);
      expPool.splice(ei, 1);
    }
  }

  // ── Pass 2: exact title match ────────────────────────────────────────
  for (let ei = expPool.length - 1; ei >= 0; ei--) {
    const exp = expPool[ei];
    const vi = verPool.findIndex((ver) => (ver.findingId ?? "").trim() === exp.title);
    if (vi !== -1) {
      matched.push({ expected: exp, verdict: verPool[vi], matchedBy: "exact-title" });
      verPool.splice(vi, 1);
      expPool.splice(ei, 1);
    }
  }

  // ── Pass 3: normalized title match ───────────────────────────────────
  let normMap = new Map<string, number>();
  for (let ei = 0; ei < expPool.length; ei++) {
    normMap.set(normalizeTitle(expPool[ei].title), ei);
  }
  for (let vi = verPool.length - 1; vi >= 0; vi--) {
    const normId = normalizeTitle(verPool[vi].findingId);
    const ei = normMap.get(normId);
    if (ei !== undefined) {
      matched.push({ expected: expPool[ei], verdict: verPool[vi], matchedBy: "normalized-title" });
      expPool.splice(ei, 1);
      verPool.splice(vi, 1);
      normMap = new Map<string, number>();
      for (let i = 0; i < expPool.length; i++) {
        normMap.set(normalizeTitle(expPool[i].title), i);
      }
    }
  }

  // ── Pass 4: unique remainder ─────────────────────────────────────────
  // Pair only when the leftover verdict clearly cannot be a failed ID/alias
  // reference: an alias-shaped ref ("F3") or a digit-bearing ref in a batch
  // whose expected IDs bear digits was aimed at something specific —
  // attaching it to whatever remains would be a guess, so it stays
  // unmatched. Anything else, with exactly one finding left, has nothing
  // else it could mean.
  if (expPool.length === 1 && verPool.length === 1) {
    const ref = (verPool[0].findingId ?? "").trim();
    const aliasShaped = /^f\d+$/i.test(ref);
    const digitBearing = /\d/.test(ref) && expected.some((e) => /\d/.test(e.findingId));
    if (!aliasShaped && !digitBearing) {
      matched.push({
        expected: expPool[0],
        verdict: verPool[0],
        matchedBy: "unique-remainder",
      });
      expPool.splice(0, 1);
      verPool.splice(0, 1);
    }
  }

  return {
    matched,
    unmatched: [...verPool],
    missing: [...expPool],
  };
}