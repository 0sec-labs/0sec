/**
 * Multi-Modal Agreement — foxguard × pwnkit cross-validation.
 *
 * Endor Labs achieves ~95% false-positive elimination by running BOTH a neural
 * classifier AND pattern-based rules, then requiring agreement before
 * auto-triaging. pwnkit (AI agent) + foxguard (Rust pattern scanner) is exactly
 * the same pattern: combine agentic discovery with deterministic scanner
 * agreement before auto-triage.
 *
 * For every finding pwnkit discovers, we also run foxguard against the same
 * source tree. If foxguard has a rule that fires on the same file (and ideally
 * the same category) → strong signal the finding is real. If foxguard scanned
 * the file but found nothing → likely false positive.
 *
 * pwnkit detects; foxguard cross-checks.
 */

import type { Finding } from "@pwnkit/shared";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync } from "node:fs";
import { promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename, resolve } from "node:path";
import { inferCategoryFromRule, parseFoxguardSarif, type FoxguardFinding } from "./foxguard-sarif.js";
export {
  inferCategoryFromRule,
  parseFoxguardSarif,
  type FoxguardFinding,
};

const execFileAsync = promisify(execFile);

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export type Agreement =
  | "both_fire"
  | "only_pwnkit"
  | "only_foxguard"
  | "neither";

export interface MultiModalResult {
  agreement: Agreement;
  /** 0-1 confidence that the pwnkit finding represents a real vulnerability. */
  confidence: number;
  /** Foxguard findings (parsed from SARIF) that matched the same file. */
  foxguardFindings: FoxguardFinding[];
  reasoning: string;
}

// ────────────────────────────────────────────────────────────────────
// Foxguard availability
// ────────────────────────────────────────────────────────────────────

const FOXGUARD_FALLBACK_PATHS = [
  "/usr/local/bin/foxguard",
  "/opt/homebrew/bin/foxguard",
  "/usr/bin/foxguard",
  `${process.env.HOME ?? ""}/.cargo/bin/foxguard`,
  `${process.env.HOME ?? ""}/.local/bin/foxguard`,
];

export async function detectFoxguard(): Promise<string | null> {
  // PATH lookup via `which`
  try {
    const { stdout } = await execFileAsync("which", ["foxguard"], {
      timeout: 5_000,
    });
    const p = stdout.trim();
    if (p && existsSync(p)) return p;
  } catch {
    // fall through to fallback paths
  }
  for (const p of FOXGUARD_FALLBACK_PATHS) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

// ────────────────────────────────────────────────────────────────────
// Finding → file path extraction
// ────────────────────────────────────────────────────────────────────

/**
 * Pull any file-ish tokens out of a pwnkit Finding. Findings don't carry a
 * structured file/line field today, so we scan title/description/analysis for
 * anything that looks like a source path.
 */
export function extractFilesFromFinding(finding: Finding): string[] {
  const haystack = [
    finding.title ?? "",
    finding.description ?? "",
    finding.evidence?.analysis ?? "",
    finding.evidence?.request ?? "",
  ].join("\n");

  // Match paths like src/foo/bar.ts, ./a/b.py, a/b/c.js:42
  const pattern =
    /(?:\.{1,2}\/)?(?:[\w.-]+\/)+[\w.-]+\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|sol|sh|c|cc|cpp|h|hpp)\b/g;
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(haystack)) !== null) {
    seen.add(m[0]);
  }
  return Array.from(seen);
}

// ────────────────────────────────────────────────────────────────────
// Agreement computation
// ────────────────────────────────────────────────────────────────────

function basenameOf(p: string): string {
  return basename(p.split(":")[0] ?? p);
}

export function computeAgreement(
  finding: Finding,
  foxguardFindings: FoxguardFinding[],
): MultiModalResult {
  const pwnkitFiles = extractFilesFromFinding(finding);
  const pwnkitBasenames = new Set(pwnkitFiles.map(basenameOf));

  // Match by basename (most portable across cwd / sandbox layouts).
  const matchedByFile = foxguardFindings.filter((f) =>
    pwnkitBasenames.has(basenameOf(f.file)),
  );

  if (matchedByFile.length === 0) {
    // Foxguard scanned but had no finding in pwnkit's file. Weak FP signal.
    return {
      agreement: "only_pwnkit",
      confidence: 0.4,
      foxguardFindings: [],
      reasoning:
        pwnkitFiles.length === 0
          ? "pwnkit finding has no extractable file path; foxguard has no matching rule"
          : `foxguard scanned but reported no finding in ${Array.from(pwnkitBasenames).join(", ")}`,
    };
  }

  // Is there a category match?
  const categoryMatch = matchedByFile.find(
    (f) => f.category && f.category === finding.category,
  );

  if (categoryMatch) {
    return {
      agreement: "both_fire",
      confidence: 0.95,
      foxguardFindings: matchedByFile,
      reasoning: `foxguard rule ${categoryMatch.ruleId} fired on ${categoryMatch.file} with matching category ${finding.category}`,
    };
  }

  return {
    agreement: "both_fire",
    confidence: 0.8,
    foxguardFindings: matchedByFile,
    reasoning: `foxguard fired on ${matchedByFile[0]!.file} (rule ${matchedByFile[0]!.ruleId}) but category differs from pwnkit's ${finding.category}`,
  };
}

// ────────────────────────────────────────────────────────────────────
// Main entry point
// ────────────────────────────────────────────────────────────────────

export interface CheckMultiModalOptions {
  /** Override foxguard binary path (testing / non-standard installs). */
  foxguardPath?: string;
  /** Inject SARIF text directly instead of invoking foxguard (testing). */
  sarifOverride?: string;
  /** Override the execFile function (testing). */
  runner?: (
    file: string,
    args: string[],
  ) => Promise<{ stdout: string; stderr: string }>;
  /** Timeout for the foxguard process in ms. Default 120s. */
  timeoutMs?: number;
}

export async function checkMultiModalAgreement(
  finding: Finding,
  sourceDir: string,
  options: CheckMultiModalOptions = {},
): Promise<MultiModalResult> {
  // Test-time short-circuit: caller supplies SARIF directly.
  if (options.sarifOverride !== undefined) {
    const foxguardFindings = parseFoxguardSarif(options.sarifOverride);
    return computeAgreement(finding, foxguardFindings);
  }

  const foxguardPath = options.foxguardPath ?? (await detectFoxguard());
  if (!foxguardPath) {
    return {
      agreement: "only_pwnkit",
      confidence: 0.5,
      foxguardFindings: [],
      reasoning: "foxguard not installed",
    };
  }

  if (!existsSync(sourceDir)) {
    return {
      agreement: "only_pwnkit",
      confidence: 0.5,
      foxguardFindings: [],
      reasoning: `sourceDir does not exist: ${sourceDir}`,
    };
  }

  const outPath = join(
    tmpdir(),
    `foxguard-scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.sarif`,
  );
  const args = [
    "scan",
    resolve(sourceDir),
    "--format",
    "sarif",
    "--output",
    outPath,
  ];

  const runner =
    options.runner ??
    ((file: string, a: string[]) =>
      execFileAsync(file, a, { timeout: options.timeoutMs ?? 120_000 }));

  try {
    await runner(foxguardPath, args);
  } catch (err) {
    // foxguard often exits non-zero when it has findings; try to read the SARIF anyway.
    if (!existsSync(outPath)) {
      return {
        agreement: "only_pwnkit",
        confidence: 0.5,
        foxguardFindings: [],
        reasoning: `foxguard failed to run: ${(err as Error).message}`,
      };
    }
  }

  let sarifText = "";
  try {
    sarifText = readFileSync(outPath, "utf8");
  } catch {
    return {
      agreement: "only_pwnkit",
      confidence: 0.5,
      foxguardFindings: [],
      reasoning: "foxguard produced no SARIF output",
    };
  } finally {
    // Best-effort cleanup.
    fsp.unlink(outPath).catch(() => {});
  }

  const foxguardFindings = parseFoxguardSarif(sarifText);
  return computeAgreement(finding, foxguardFindings);
}

// ────────────────────────────────────────────────────────────────────
// Signal fusion — combine with other triage signals
// ────────────────────────────────────────────────────────────────────

export interface FusedTriageSignals {
  multiModal?: MultiModalResult;
  holdingItWrong?: boolean;
  evidenceCompleteness?: number;
}

export type FusedDecision =
  | "auto_accept"
  | "auto_reject"
  | "verify"
  | "verify_priority";

export interface FusedTriageResult {
  decision: FusedDecision;
  confidence: number;
  reasoning: string;
}

/**
 * Fuse multi-modal agreement, holding-it-wrong, and evidence completeness into
 * a single triage decision. Used by the agentic scanner to decide whether to
 * send a finding to verify, auto-accept it, or auto-reject it.
 */
export function fuseTriageSignals(signals: FusedTriageSignals): FusedTriageResult {
  const { multiModal, holdingItWrong, evidenceCompleteness = 0 } = signals;

  if (holdingItWrong) {
    return {
      decision: "auto_reject",
      confidence: 0.95,
      reasoning: "holding-it-wrong filter fired",
    };
  }

  const agreement = multiModal?.agreement ?? "only_pwnkit";
  const mmConf = multiModal?.confidence ?? 0.5;

  // All signals agree it's real → auto-accept
  if (agreement === "both_fire" && mmConf >= 0.9 && evidenceCompleteness >= 0.7) {
    return {
      decision: "auto_accept",
      confidence: 0.95,
      reasoning: "multi-modal agreement + strong evidence — auto-accept",
    };
  }

  // Strong multi-modal signal → prioritize for verify
  if (agreement === "both_fire") {
    return {
      decision: "verify_priority",
      confidence: mmConf,
      reasoning: "foxguard cross-validation agrees — prioritize verify",
    };
  }

  // All signals disagree it's real → auto-reject
  if (agreement === "only_pwnkit" && mmConf <= 0.4 && evidenceCompleteness <= 0.4) {
    return {
      decision: "auto_reject",
      confidence: 0.8,
      reasoning: "foxguard disagrees AND evidence incomplete — likely FP",
    };
  }

  return {
    decision: "verify",
    confidence: mmConf,
    reasoning: `standard verify path (agreement=${agreement})`,
  };
}
