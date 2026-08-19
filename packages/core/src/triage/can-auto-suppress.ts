/**
 * Auto-suppression guardrail (issue #518)
 *
 * Standing operator rule: **never auto-drop or auto-submit a finding on a
 * classifier/heuristic score alone.** Several triage paths in the scanner are
 * flag-gated and, when enabled, can mark a finding `false-positive` and skip
 * all remaining triage/verification purely on a score or pattern heuristic
 * (evidence_gate, the learned XGBoost router's `auto_reject`, and the dynamic
 * triage router's empty-layer-set Rule-3).
 *
 * For a disclosure-grade pipeline, silently burying a real RCE / kernel
 * memory-corruption / auth-bypass is far worse than carrying a few extra false
 * positives into a verification pass. This module is the single chokepoint that
 * decides whether a finding is even *eligible* to be auto-suppressed by a
 * score/heuristic path. Every such path must route through
 * {@link canAutoSuppress} so a future 4th path cannot bypass the severity/class
 * guard.
 *
 * What this does NOT change:
 *   - Default-OFF flag behavior. When a flag is off, nothing here runs.
 *   - Low/medium-severity findings: they may still be deprioritized/suppressed
 *     by the score/heuristic paths exactly as before.
 *   - Verification-verdict suppressions (reachability analysis, multi-modal
 *     cross-validation, self-consistency vote). Those are real verification
 *     results, not score-only heuristics, and are out of scope for this guard.
 *
 * SINGLE SOURCE / PARITY (#650): the 0cloud side keeps the same predicate +
 * severity/class guard in `@0cloud/cloud-contracts` `disclosure-worthiness.ts`
 * (the orchestrator can't import this engine package, and vice versa — the two
 * are decoupled by design). This module stays the engine's authoritative copy;
 * `can-auto-suppress.parity.test.ts` asserts the two `PROTECTED_SEVERITIES` /
 * `HIGH_IMPACT_CATEGORIES` lists agree. When you change a list here, update the
 * 0cloud copy + both parity fixtures.
 */

import type { AttackCategory, Finding, Severity } from "@pwnkit/shared";

/**
 * Severities that always get at least one verification pass and may never be
 * auto-dropped by a score/heuristic path. `critical` and `high` are the
 * disclosure-grade tiers where a missed finding is a credibility risk.
 */
const PROTECTED_SEVERITIES: ReadonlySet<Severity> = new Set<Severity>([
  "critical",
  "high",
]);

/**
 * High-impact vulnerability classes that always get at least one verification
 * pass regardless of the finding's *recorded* severity. A scanner can emit, or
 * an earlier heuristic can downgrade, a finding's severity incorrectly; the
 * class is the more durable signal of blast radius. Anything that yields code
 * execution, data-store compromise, authentication/authorization bypass, server
 * pivot (SSRF), arbitrary file access (path traversal), or memory/kernel
 * corruption is protected here.
 *
 * Derived from the `AttackCategory` union in `@pwnkit/shared`. Kept as a typed
 * set so adding a new high-impact category to `AttackCategory` surfaces here at
 * review time rather than silently defaulting to "suppressible".
 */
const HIGH_IMPACT_CATEGORIES: ReadonlySet<AttackCategory> = new Set<AttackCategory>([
  // Remote code / command / code execution
  "command-injection",
  "code-injection",
  // Injection into the data store
  "sql-injection",
  // Unsafe deserialization is a classic RCE primitive
  "unsafe-deserialization",
  // Server-side request forgery (pivot / internal network reach)
  "ssrf",
  // Arbitrary file read/write
  "path-traversal",
  // Memory corruption / binary / kernel classes
  "heap-overflow",
  "out-of-bounds-read",
  "out-of-bounds-write",
  "use-after-free",
  "stack-buffer-overflow",
  "integer-overflow",
  "type-confusion",
  "double-free",
  "format-string",
  "uninitialized-memory",
  "race-condition",
  "toctou",
  // Supply-chain compromise (known-vulnerable / malicious package)
  "known-vulnerable-package",
  "supply-chain",
  // Prototype-pollution gadget → auth bypass / RCE when chained. We actively
  // disclose these (e.g. the jsonwebtoken verify() gadget), so they must never
  // be auto-dropped on a score alone.
  "prototype-pollution",
  // Cryptographic misuse — hardcoded keys/IVs, JWT alg-confusion (alg=none /
  // HS-vs-RS), and predictable RNG for secrets are direct key-leak / auth-bypass
  // primitives, so the class is protected from score-only auto-drop.
  "crypto-misuse",
  // AI-system adversarial classes — the core 0sec "adversarial reliability"
  // thesis (authorization-boundary break, unsafe tool use, data exfiltration,
  // prompt hijack). A missed one of these is a disclosure-grade loss.
  "prompt-injection",
  "data-exfiltration",
  "tool-misuse",
]);

/** Why a finding may not be auto-suppressed. Stable strings for the audit trail. */
export type AutoSuppressGuard = "high_severity" | "high_impact_class";

export interface AutoSuppressDecision {
  /** True when a score/heuristic path is allowed to mark this finding false-positive. */
  canSuppress: boolean;
  /** Set when `canSuppress` is false — which guard fired. */
  guard?: AutoSuppressGuard;
  /** Human-readable reason for logs / `triageNote`. */
  reason: string;
}

/**
 * Decide whether `finding` may be auto-suppressed by a score/heuristic triage
 * path. Returns a structured decision so callers can record *which* guard fired
 * in the audit trail (`triageNote` + layer verdict), not just a boolean.
 *
 * A finding is protected (NOT suppressible) when it is high/critical severity OR
 * belongs to a high-impact class. Such findings must instead proceed to
 * verification (or be flagged for human review). All other findings remain
 * suppressible exactly as before.
 */
export function canAutoSuppressDetailed(finding: Finding): AutoSuppressDecision {
  if (PROTECTED_SEVERITIES.has(finding.severity)) {
    return {
      canSuppress: false,
      guard: "high_severity",
      reason: `severity=${finding.severity} is disclosure-grade; routed to verification instead of auto-drop`,
    };
  }
  if (HIGH_IMPACT_CATEGORIES.has(finding.category)) {
    return {
      canSuppress: false,
      guard: "high_impact_class",
      reason: `category=${finding.category} is a high-impact class; routed to verification instead of auto-drop`,
    };
  }
  return {
    canSuppress: true,
    reason: `severity=${finding.severity}, category=${finding.category} eligible for score/heuristic auto-suppression`,
  };
}

/**
 * Convenience boolean form of {@link canAutoSuppressDetailed}. Use the detailed
 * form when you need the guard reason for the audit trail.
 */
export function canAutoSuppress(finding: Finding): boolean {
  return canAutoSuppressDetailed(finding).canSuppress;
}

/** Exposed for tests / introspection. Do not mutate. */
export const AUTO_SUPPRESS_PROTECTED_SEVERITIES = PROTECTED_SEVERITIES;
export const AUTO_SUPPRESS_HIGH_IMPACT_CATEGORIES = HIGH_IMPACT_CATEGORIES;
