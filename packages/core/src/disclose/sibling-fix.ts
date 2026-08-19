import { existsSync, readFileSync } from "node:fs";
import { resolve, join, extname } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { extractFileRefs, type FileRef } from "./canary.js";

export interface SiblingFixCandidate {
  /** The file:line pair cited in the finding that appears to be the correct sibling. */
  fileRef: FileRef;
  /** The code block read from that location — N lines before, the cited line, N lines after. */
  snippet: string;
  /** Guessed language tag (typescript, python, …) for the markdown fence. Empty when unknown. */
  language: string;
  /** Heuristic confidence 0..1 — was this ref explicitly flagged as "correct" / "sibling" in the prose? */
  confidence: number;
  /** The specific cue phrase or signal class that flagged this ref. */
  rationale: string;
}

export interface SiblingFixOptions {
  repoPath: string;
  /** Lines of context above and below the cited line. Default 5. */
  linesOfContext?: number;
}

/**
 * Cues whose presence near a file ref strongly suggest "this is the *correct*
 * sibling pattern in the repo". Order matters only loosely; weights below are
 * what actually drives confidence.
 */
const SIBLING_CUES: Array<{ pattern: RegExp; weight: number; label: string }> = [
  { pattern: /\bthe\s+right\s+gate\s+is\b/i, weight: 0.95, label: "the right gate is" },
  { pattern: /\bcorrect\s+pattern\b/i, weight: 0.9, label: "correct pattern" },
  { pattern: /\buses?\s+the\s+correct\b/i, weight: 0.9, label: "uses the correct" },
  { pattern: /\bproperly\s+checks?\b/i, weight: 0.85, label: "properly checks" },
  { pattern: /\bsafely\s+handles?\b/i, weight: 0.85, label: "safely handles" },
  { pattern: /\bgated\s+on\b/i, weight: 0.8, label: "gated on" },
  { pattern: /\bsibling\b/i, weight: 0.8, label: "sibling" },
  { pattern: /\bcorrectly\s+(?:gated|checks?|handles?|validates?)\b/i, weight: 0.85, label: "correctly gated/checks/handles" },
  { pattern: /\bsafe\s+(?:handler|sibling|version)\b/i, weight: 0.8, label: "safe handler/sibling/version" },
  { pattern: /\bright\s+(?:check|guard|gate)\b/i, weight: 0.8, label: "right check/guard/gate" },
];

/**
 * Cues whose presence near a file ref classify it as the *vulnerable* ref —
 * we use these to rule out a candidate (or to lower its confidence if both
 * sibling and vulnerable cues happen to attach to the same ref).
 */
const VULNERABLE_CUES: RegExp[] = [
  /\bgates?\s+on\s+\w+\s+instead\s+of\b/i,
  /\bvulnerable\s+at\b/i,
  /\bwhere\s+the\s+\w+\s+(?:happens|occurs)\b/i,
  /\bmissing\s+\w+/i,
  /\bbug\s+is\s+at\b/i,
  /\binstead\s+of\s+\w+/i,
];

/**
 * Crude language map. Kept inline because no other helper exists today and
 * we don't want sibling-fix.ts owning a public language registry.
 */
const LANGUAGE_BY_EXT: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".rs": "rust",
  ".go": "go",
  ".rb": "ruby",
  ".java": "java",
  ".kt": "kotlin",
  ".swift": "swift",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".php": "php",
  ".sh": "bash",
  ".sql": "sql",
};

function languageFor(filePath: string): string {
  return LANGUAGE_BY_EXT[extname(filePath).toLowerCase()] ?? "";
}

/**
 * Build a haystack identical in shape to {@link extractFileRefs} so cue
 * detection runs against the same prose the file refs were pulled from.
 */
function buildHaystack(finding: Finding): string {
  return [
    finding.description,
    finding.evidence?.analysis,
    finding.evidence?.request,
    finding.evidence?.response,
  ]
    .filter((s): s is string => typeof s === "string" && s.length > 0)
    .join("\n\n");
}

/**
 * Slice the sentence(s) immediately around a file ref's first occurrence in
 * the haystack. We split on `.`/`!`/`?`/newline boundaries so that prose like
 *   "the bug is at a.ts:1. The correct pattern is at b.ts:2."
 * doesn't pollute the b.ts ref's window with a.ts's cues.
 */
function sentenceAround(haystack: string, refToken: string): string {
  const idx = haystack.indexOf(refToken);
  if (idx === -1) return "";

  // Find sentence start: nearest preceding terminator (.!?\n) or BoS.
  let start = idx;
  while (start > 0) {
    const c = haystack[start - 1];
    if (c === "." || c === "!" || c === "?" || c === "\n") break;
    start--;
  }
  // Find sentence end: nearest following terminator or EoS.
  let end = idx + refToken.length;
  while (end < haystack.length) {
    const c = haystack[end];
    if (c === "." || c === "!" || c === "?" || c === "\n") break;
    end++;
  }
  return haystack.slice(start, end + 1);
}

interface ClassifiedRef {
  ref: FileRef;
  /** Highest-weight sibling cue match, if any. */
  siblingHit?: { weight: number; label: string };
  /** True if any vulnerable-cue pattern matched the surrounding sentence. */
  vulnerableHit: boolean;
}

function classifyRef(haystack: string, ref: FileRef): ClassifiedRef {
  const token = `${ref.file}${ref.line !== undefined ? `:${ref.line}` : ""}`;
  const window = sentenceAround(haystack, token);

  let siblingHit: ClassifiedRef["siblingHit"];
  for (const cue of SIBLING_CUES) {
    if (cue.pattern.test(window)) {
      if (!siblingHit || cue.weight > siblingHit.weight) {
        siblingHit = { weight: cue.weight, label: cue.label };
      }
    }
  }

  const vulnerableHit = VULNERABLE_CUES.some((p) => p.test(window));

  return { ref, siblingHit, vulnerableHit };
}

/**
 * Read `linesOfContext` lines either side of `ref.line` from disk and emit a
 * snippet with the cited line in the middle. Returns null if the file is
 * unreadable or the cited line is out of range.
 */
function readSnippet(
  repoPath: string,
  ref: FileRef,
  linesOfContext: number,
): string | null {
  if (ref.line === undefined) return null;
  const abs = join(repoPath, ref.file);
  if (!existsSync(abs)) return null;
  let raw: string;
  try {
    raw = readFileSync(abs, "utf8");
  } catch {
    return null;
  }
  const lines = raw.split("\n");
  if (ref.line < 1 || ref.line > lines.length) return null;

  const start = Math.max(0, ref.line - 1 - linesOfContext);
  const end = Math.min(lines.length, ref.line + linesOfContext);
  return lines.slice(start, end).join("\n");
}

/**
 * Floor below which we'd rather emit nothing than a low-confidence guess —
 * the advisory's "Suggested fix" placeholder is more useful than a wrong
 * code snippet attributed to the repo.
 */
const CONFIDENCE_FLOOR = 0.6;

/**
 * Inspect a finding's prose, classify each cited file:line, and return the
 * highest-confidence "correct sibling" snippet read from the local repo
 * checkout. Returns null when no ref crosses the confidence floor, when the
 * winning ref's file can't be read, or when the cited line is out of range.
 *
 * Pure: no network, no git invocation. Only filesystem reads under repoPath.
 */
export function extractSiblingFix(
  finding: Finding,
  options: SiblingFixOptions,
): SiblingFixCandidate | null {
  if (!options.repoPath) return null;
  const repoPath = resolve(options.repoPath);
  if (!existsSync(repoPath)) return null;

  const linesOfContext = options.linesOfContext ?? 5;
  const refs = extractFileRefs(finding);
  if (refs.length === 0) return null;

  const haystack = buildHaystack(finding);
  const classified = refs.map((ref) => classifyRef(haystack, ref));

  // Score each ref. Sibling weight is the base. A simultaneous vulnerable cue
  // halves the score (it's ambiguous which side of the comparison this ref
  // sits on). Refs without any sibling hit are ineligible.
  let best: { c: ClassifiedRef; confidence: number; rationale: string } | null = null;
  for (const c of classified) {
    if (!c.siblingHit) continue;
    const base = c.siblingHit.weight;
    const confidence = c.vulnerableHit ? base * 0.5 : base;
    const rationale = c.vulnerableHit
      ? `Matched sibling cue "${c.siblingHit.label}" in surrounding prose, but also matched a vulnerable-ref cue — confidence halved.`
      : `Matched sibling cue "${c.siblingHit.label}" in the sentence containing the ref.`;
    if (!best || confidence > best.confidence) {
      best = { c, confidence, rationale };
    }
  }

  if (!best || best.confidence < CONFIDENCE_FLOOR) return null;

  const snippet = readSnippet(repoPath, best.c.ref, linesOfContext);
  if (snippet === null) return null;

  return {
    fileRef: best.c.ref,
    snippet,
    language: languageFor(best.c.ref.file),
    confidence: best.confidence,
    rationale: best.rationale,
  };
}
