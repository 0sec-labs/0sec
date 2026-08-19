/**
 * LLM Output Guard — safety refusal classification + debug artifact dumping.
 *
 * open-kritt lesson #5/#7: classify provider safety-refusals (cyber-limiting)
 * so we fail-soft without burning retry budget, and dump raw model output to
 * disk as a debug artifact on parse/validation failure.
 *
 * Written fresh — no source text copied.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { homeStateDir } from "@0sec/shared";
import { homedir } from "node:os";
import { join } from "node:path";

// ── Classifier ──

/**
 * Narrow classification patterns for provider safety-refusals / cyber-limiting.
 *
 * Deliberately narrow: false positives cost real retry budget, so each pattern
 * must strongly indicate a refusal, not a coincidental string match.
 */
const REFUSAL_PATTERNS: Array<{ regex: RegExp; label: string }> = [
  // Direct refusal to help/assist/complete
  {
    regex: /\b(?:i\s+)?(?:can'?t|cannot|won'?t|will\s+not)\s+(?:help|assist|complete|do|provide)\b/i,
    label: "direct-refusal",
  },
  // Cyber-safety policy citation
  {
    regex: /\bcyber[\s-]?safety\b/i,
    label: "cyber-safety",
  },
  // Safety policy mention
  {
    regex: /\bsafety\s+policy\b/i,
    label: "safety-policy",
  },
  // Harmful content shield
  {
    regex: /\bharmful\s+content\b/i,
    label: "harmful-content",
  },
  // Security research restriction
  {
    regex: /\bsecurity\s+research\s+(?:is|may\s+be)\s+(?:restricted|not\s+allowed)\b/i,
    label: "security-research-restricted",
  },
  // Policy violation
  {
    regex: /\bviolates\s+(?:our\s+)?(?:usage|safety|content)\s+polic\w+\b/i,
    label: "policy-violation",
  },
  // Refusal/decline within ~60 chars of a request/prompt/task/assist term
  {
    regex: /\b(?:refus|decline)[^.]{0,60}(?:task|request|prompt|assist)\b/i,
    label: "refusal-gesture",
  },
];

/**
 * Classify an LLM response as a provider safety-refusal.
 *
 * Returns `{ refused: false }` if no pattern matches, or
 * `{ refused: true, pattern: "<label>" }` with the matching label.
 * Never throws.
 */
export function classifyRefusal(raw: string): {
  refused: boolean;
  pattern?: string;
} {
  for (const { regex, label } of REFUSAL_PATTERNS) {
    if (regex.test(raw)) {
      return { refused: true, pattern: label };
    }
  }
  return { refused: false };
}

/**
 * Convenience shorthand — returns true when the response is a refusal.
 */
export function shouldSkipRetry(raw: string): boolean {
  return classifyRefusal(raw).refused;
}

// ── Debug Dump ──

export interface DumpModelOutputOpts {
  /** Raw model output text to persist. */
  raw: string;
  /** Which stage produced this output. */
  stage: "dedupe" | "rank";
  /** Zero-based attempt number within this batch call. */
  attempt: number;
  /** Artifacts output directory. Defaults to `~/.0sec/artifacts/`. */
  dir?: string;
  /** Optional scan identifier included in the filename and payload. */
  scanId?: string;
}

/**
 * Write raw model output to disk as a JSON debug artifact.
 *
 * Creates the directory if it does not exist (mkdir -p).
 * Never throws — returns the written path on success, or null on any failure
 * (permission error, read-only filesystem, etc.).
 */
export function dumpModelOutput(opts: DumpModelOutputOpts): string | null {
  const dir = opts.dir ?? join(homeStateDir(), "artifacts");
  const ts = Date.now();
  const scanPart = opts.scanId ? `-scan${opts.scanId}` : "";
  const filename = `${opts.stage}-${ts}-attempt${opts.attempt}${scanPart}.json`;
  const path = join(dir, filename);

  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path, JSON.stringify({
      stage: opts.stage,
      attempt: opts.attempt,
      timestamp: ts,
      raw: opts.raw,
    }, null, 2), "utf-8");
    return path;
  } catch {
    return null;
  }
}