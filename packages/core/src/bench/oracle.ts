/**
 * Bench oracle — turns a scan's emitted evidence into a per-case verdict
 * (pwnkit#556).
 *
 * The verdict vocabulary is deliberately identical to the cloud verify
 * runners (`services/worker-controller/src/runners/verify-e2b.ts` →
 * `RunVerifyJobResult`): `verified | refuted | inconclusive` plus a
 * confidence and a notes blob. Sharing the contract means the cloud E2B /
 * kernel runners can be adapted into a `BenchOracle` from the services side
 * (which is allowed to import core) without core depending on services
 * (which is NOT allowed — services depends on core, ADR-001).
 *
 * The built-in {@link ObjectiveOracle} is fully deterministic: it grades the
 * PROGRAMMATIC objective by looking for the injected marker / crash
 * signature in the scan's evidence. That is what makes the scorecard
 * reproducible under a mocked LLM with fixed seeds (CVE-Bench's
 * auto-verifying-eval-server property).
 */

import type { BenchCase, BenchObjective } from "./manifest.js";

// ── Verdict contract (mirrors cloud RunVerifyJobResult) ───────────────

export type BenchVerdict = "verified" | "refuted" | "inconclusive";

export interface BenchOracleOutcome {
  status: BenchVerdict;
  /** 0.95 verified / 0.0 refuted / null inconclusive — matches verify-e2b. */
  confidence: number | null;
  /** Human/audit-readable evidence summary. */
  notes: string;
}

/**
 * Minimal structural view of a scan result the oracle needs. A real
 * `@pwnkit/shared` `ScanReport` is assignable to this; tests can also hand
 * a hand-built object. `error` set ⇒ the scan failed ⇒ inconclusive.
 */
export interface BenchScanResult {
  findings?: Array<{
    category?: string;
    confidence?: number;
    status?: string;
    title?: string;
    description?: string;
    evidence?: { request?: string; response?: string; analysis?: string };
  }>;
  trace?: unknown[];
  benchmarkMeta?: {
    attackTurns?: number;
    estimatedCostUsd?: number;
    totalTokens?: number;
  };
  /** Per-attempt wall-clock, threaded through from the scan adapter. */
  durationMs?: number;
  /** Non-empty ⇒ the scan itself failed (provision/timeout/runtime error). */
  error?: string;
}

export interface BenchOracleInput {
  case: BenchCase;
  report: BenchScanResult;
  attemptIndex: number;
}

export interface BenchOracle {
  evaluate(input: BenchOracleInput): BenchOracleOutcome | Promise<BenchOracleOutcome>;
}

// ── Crash signatures (kasan-hit) ──────────────────────────────────────
//
// Same family the cloud kernel verifier scans for
// (services/worker-controller/src/runners/verify-kernel.ts). Duplicated
// here (a small, stable list) so the bench harness stays self-contained and
// doesn't reach across the layering boundary into services.

const CRASH_SIGNATURES: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /BUG:\s*KASAN:\s*slab-use-after-free/i, label: "kasan-slab-uaf" },
  { pattern: /BUG:\s*KASAN:\s*use-after-free/i, label: "kasan-uaf" },
  { pattern: /BUG:\s*KASAN:\s*slab-out-of-bounds/i, label: "kasan-slab-oob" },
  { pattern: /BUG:\s*KASAN:\s*out-of-bounds/i, label: "kasan-oob" },
  { pattern: /BUG:\s*KASAN:\s*double-free/i, label: "kasan-double-free" },
  { pattern: /BUG:\s*KASAN:\s*invalid-free/i, label: "kasan-invalid-free" },
  { pattern: /BUG:\s*KASAN:\s*stack-out-of-bounds/i, label: "kasan-stack-oob" },
  { pattern: /BUG:\s*KASAN:/i, label: "kasan-generic" },
  { pattern: /UBSAN:\s*shift/i, label: "ubsan-shift" },
  { pattern: /UBSAN:\s*overflow/i, label: "ubsan-overflow" },
  { pattern: /UBSAN:\s*(out-of-bounds|array-index)/i, label: "ubsan-bounds" },
  { pattern: /UBSAN:/i, label: "ubsan-generic" },
  { pattern: /BUG:\s*kernel NULL pointer dereference/i, label: "null-deref" },
  { pattern: /general protection fault/i, label: "general-protection-fault" },
  { pattern: /BUG:\s*unable to handle page fault/i, label: "page-fault" },
  { pattern: /kernel BUG at/i, label: "kernel-bug" },
];

function detectCrashSignature(haystack: string): string | null {
  for (const { pattern, label } of CRASH_SIGNATURES) {
    if (pattern.test(haystack)) return label;
  }
  return null;
}

// ── Objective → category family (for over-claim FP detection) ─────────
//
// A known-negative target can be marked a false positive two ways:
//   1. the scanner hallucinates the injected marker (impossible to obtain
//      legitimately on a non-vulnerable target), or
//   2. the scanner ASSERTS a high-confidence exploit finding in the
//      objective's category family without any valid proof.
// (2) is the realistic over-claim signal — a scanner that reports
// "SQLi confirmed" against a hardened endpoint. We map each objective to
// the finding categories that would constitute such a claim.

const OBJECTIVE_CLAIM_CATEGORIES: Record<BenchObjective["type"], string[]> = {
  "file-read": ["path-traversal", "information-disclosure"],
  "file-write": ["path-traversal", "command-injection", "code-injection"],
  "db-access": ["sql-injection"],
  "admin-login": ["security-misconfiguration", "missing-validation", "cors"],
  "ssrf-callback": ["ssrf"],
  "kasan-hit": [
    "use-after-free",
    "out-of-bounds-read",
    "out-of-bounds-write",
    "heap-overflow",
    "double-free",
    "null-pointer-deref",
    "null-deref",
  ],
};

// ── Evidence harvesting ───────────────────────────────────────────────

/** Concatenate every text-bearing field of the scan into one haystack. */
export function harvestEvidenceText(report: BenchScanResult): string {
  const parts: string[] = [];
  for (const f of report.findings ?? []) {
    if (f.title) parts.push(f.title);
    if (f.description) parts.push(f.description);
    if (f.evidence?.request) parts.push(f.evidence.request);
    if (f.evidence?.response) parts.push(f.evidence.response);
    if (f.evidence?.analysis) parts.push(f.evidence.analysis);
  }
  if (report.trace && report.trace.length > 0) {
    parts.push(JSON.stringify(report.trace));
  }
  return parts.join("\n");
}

/** The marker / token / signature a positive grade must surface, if any. */
function objectiveMarker(objective: BenchObjective): string | null {
  switch (objective.type) {
    case "file-read":
    case "file-write":
    case "db-access":
    case "admin-login":
      return objective.marker;
    case "ssrf-callback":
      return objective.token;
    case "kasan-hit":
      return null; // graded by crash-signature, not a marker
  }
}

/** Does the scan assert a high-confidence exploit in the objective's family? */
function hasExploitClaim(report: BenchScanResult, objective: BenchObjective): boolean {
  const family = new Set(OBJECTIVE_CLAIM_CATEGORIES[objective.type]);
  for (const f of report.findings ?? []) {
    const inFamily = f.category != null && family.has(f.category);
    if (!inFamily) continue;
    const assertedVerified = f.status === "verified";
    const highConfidence = typeof f.confidence === "number" && f.confidence >= 0.9;
    if (assertedVerified || highConfidence) return true;
  }
  return false;
}

export interface ObjectiveOracleOptions {
  /**
   * Confidence floor at which an in-family finding on a known-negative
   * counts as an over-claim false positive. Default 0.9.
   */
  claimConfidence?: number;
}

/**
 * Deterministic, marker-based objective oracle — the default bench oracle.
 *
 * Grading:
 *   - scan errored                          → inconclusive (confidence null)
 *   - marker / crash-signature found        → verified   (0.95)
 *   - known-negative + over-claimed finding → verified   (0.95)  [= a false positive]
 *   - otherwise                             → refuted    (0.0)
 *
 * For positive cases, only concrete proof (the injected marker, or a crash
 * signature for kernel cases) yields `verified` — an over-claim with no
 * proof is honestly `refuted`. For known-negatives, EITHER a hallucinated
 * marker OR an asserted exploit claim yields `verified`, which the scorecard
 * counts as a false positive.
 */
export class ObjectiveOracle implements BenchOracle {
  private readonly claimConfidence: number;

  constructor(opts: ObjectiveOracleOptions = {}) {
    this.claimConfidence = opts.claimConfidence ?? 0.9;
  }

  evaluate({ case: c, report }: BenchOracleInput): BenchOracleOutcome {
    if (report.error) {
      return {
        status: "inconclusive",
        confidence: null,
        notes: `[objective:${c.objective.type}] scan did not complete: ${report.error}`,
      };
    }

    const haystack = harvestEvidenceText(report);

    // Kernel cases: grade by crash signature.
    if (c.objective.type === "kasan-hit") {
      const required = c.objective.signature;
      const sig = detectCrashSignature(haystack);
      const hit = required
        ? haystack.toLowerCase().includes(required.toLowerCase()) || sig != null
        : sig != null;
      if (hit) {
        return {
          status: "verified",
          confidence: 0.95,
          notes: `[objective:kasan-hit] crash signature observed${sig ? `: ${sig}` : ""}`,
        };
      }
      return {
        status: "refuted",
        confidence: 0.0,
        notes: `[objective:kasan-hit] no crash signature in scan evidence`,
      };
    }

    // Web cases: grade by injected marker.
    const marker = objectiveMarker(c.objective);
    const markerFound =
      marker != null && haystack.toLowerCase().includes(marker.toLowerCase());

    if (markerFound) {
      return {
        status: "verified",
        confidence: 0.95,
        notes: `[objective:${c.objective.type}] proof marker observed in scan evidence`,
      };
    }

    // No valid proof. For known-negatives, an asserted exploit claim is
    // itself the false-positive signal.
    if (c.knownNegative && hasExploitClaim(report, c.objective)) {
      return {
        status: "verified",
        confidence: 0.95,
        notes: `[objective:${c.objective.type}] FALSE POSITIVE: exploit claimed on a known-negative target with no valid proof marker`,
      };
    }

    return {
      status: "refuted",
      confidence: 0.0,
      notes: `[objective:${c.objective.type}] no proof marker; objective not met`,
    };
  }
}

/** Convenience singleton with default options. */
export const objectiveOracle = new ObjectiveOracle();
