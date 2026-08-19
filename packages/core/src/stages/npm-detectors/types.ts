/**
 * npm-ecosystem dynamic-discovery — the extensible **Detector** contract.
 *
 * This is the durable enabler behind the operator's "self-extending flywheel"
 * requirement: every future confirmed novel bug class (from ANY method) should
 * be able to become a new Detector that runs at ecosystem scale, automatically.
 * A Detector is a small, self-contained plugin registered in
 * {@link ./registry.ts DETECTOR_REGISTRY}; the stage
 * (`../npm-dynamic-discovery.ts`) drives it, and the shared discipline
 * (assume-FP + dedup + downloads-floor / freshness) lives in `./base.ts` so
 * every detector inherits it — you cannot register a detector that skips it.
 *
 * The recipe for deriving a new Detector from a confirmed finding + its PoC is
 * `docs/operations/detector-from-finding.md`.
 *
 * Design invariants (load-bearing, not decoration):
 *   - **Deterministic confirm.** `confirm()` may run untrusted package code in
 *     an isolated env, but the *verdict* is computed from an OBSERVED runtime
 *     consequence (a prototype actually polluted, a validator actually bypassed,
 *     a socket target that actually diverges). LLM proposal is allowed ONLY in
 *     `identifyCandidates` (candidate shape ranking / expansion) and is never
 *     load-bearing for a confirmation. Assume-FP everywhere else.
 *   - **One finding shape.** A confirmation is promoted to the canonical
 *     `Finding` by the stage, so every existing renderer / sink / DB / verify /
 *     disclosure path works unchanged. No parallel finding type.
 */

import type { AttackCategory, Severity } from "@pwnkit/shared";

/** A package under evaluation, plus registry-derived guard metadata. */
export interface PackageRef {
  /** npm package name, e.g. `es-toolkit`. */
  name: string;
  /** Resolved installed version, e.g. `1.39.0`. Optional pre-install. */
  version?: string;
  /** Weekly downloads (npm registry). Feeds the downloads-floor guard. */
  weeklyDownloads?: number;
  /** ISO-8601 last-publish timestamp. Feeds the freshness guard. */
  lastPublishedAt?: string;
  /**
   * Free-form category tags the worklist builder attached (e.g. `merge`,
   * `validation`, `ssrf-filter`, `fork-lineage`). Detectors may narrow on these
   * in `appliesTo`, but must not DEPEND on them — a missing tag never suppresses
   * a real confirmation, it only saves work.
   */
  tags?: string[];
}

/**
 * The execution env a detector runs against — the isolation seam. In the
 * single-host / test path this loads modules in-process from `baseDir`
 * (the prototype's `worker.js` analog). In production the stage supplies a
 * sandbox-backed probe (e2b exec: `npm install --ignore-scripts` in a
 * throwaway dir, run the harness core, return structured JSON). Detectors are
 * written against this interface and never care which backing they got.
 */
export interface PackageProbe {
  readonly pkg: PackageRef;
  /** Absolute base dir the package is installed under (for `require.resolve`). */
  readonly baseDir: string;
  /**
   * Load a module id resolvable from `baseDir` (the package, a subpath export
   * like `pkg/compat`, or a dependency). Returns `undefined` if it cannot be
   * resolved/loaded — detectors treat that as "candidate not present", never a
   * confirmation. MUST run inside the same isolation domain as `confirm` so a
   * detector that mutates a live prototype cannot corrupt siblings.
   */
  load(moduleId: string): unknown | undefined;
  /** Structured note sink for probe-level diagnostics (missing subpath, etc.). */
  note?(msg: string): void;
}

/** Base fields every detector candidate carries; detectors extend this. */
export interface DetectorCandidate {
  /** Stable-ish id for dedup/logging within a run, e.g. `merge@es-toolkit/compat`. */
  id: string;
  /** Human label surfaced in evidence. */
  label: string;
}

/**
 * A CONFIRMED runtime consequence, or an explicit non-confirmation. The stage
 * only ever promotes `confirmed === true` to a finding; everything else is
 * assume-FP (dropped, not disclosed).
 */
export interface DetectorConfirmation {
  /** True ONLY when a runtime consequence was directly observed. */
  confirmed: boolean;
  /** Confirmed severity. Defaults to the detector's `severityFloor`. */
  severity?: Severity;
  /**
   * The observed-consequence evidence. `observation` is the machine-checkable
   * fact that makes this not-an-FP (e.g. "Object.prototype.<marker> set at
   * runtime", "validator returned ok but app-observed role=admin", "socket
   * target 127.0.0.1 while filter classified PUBLIC"). Free of the raw package
   * source; carries the reproducing payload/input.
   */
  evidence: {
    /** One-line, machine-checkable observed consequence. Empty ⇒ not confirmed. */
    observation: string;
    /** The payload / input that produced the consequence. */
    payload?: string;
    /** Human analysis: what fired, calling convention, why it's real. */
    analysis?: string;
    /** Optional escalation (e.g. SSPP → RCE via NODE_OPTIONS gadget). */
    escalation?: { kind: string; achieved: boolean; note?: string };
  };
  /** The candidate label that fired (for the finding fingerprint). */
  source?: string;
}

/** Novelty verdict from the dedup step. */
export interface DedupVerdict {
  /** True when no live advisory (OSV/npm) or fork-twin/prior-report matches. */
  novel: boolean;
  /** Where the dedup signal came from. */
  source:
    | "novel"
    | "osv"
    | "npm-audit"
    | "fork-cve-twin"
    | "prior-report"
    | "unknown";
  /** Advisory / CVE / GHSA references backing a non-novel verdict. */
  advisories: string[];
}

/**
 * A detector-contributed dedup input — the durable "we already know this class
 * lives under an unadvised fork name" knowledge the sspp prototype learned the
 * hard way (`radash` ↔ radashi CVE-2025-48054). Baked into base dedup so every
 * detector benefits.
 */
export interface DedupHints {
  /** Package names 0sec has already reported for this detector's class. */
  priorReports?: string[];
  /**
   * name → advisory reference: packages whose vulnerable code is identical to a
   * sibling/fork that carries a PUBLIC advisory but has none under its own name.
   */
  forkTwins?: Record<string, string>;
}

/**
 * The Detector plugin contract. A registered detector is a small file under
 * `./detectors-*`; the 3 first-class instances are sspp-fuzz, read-unstable,
 * and parser-diff. Add a new one by following
 * `docs/operations/detector-from-finding.md`.
 */
export interface Detector<C extends DetectorCandidate = DetectorCandidate> {
  /** Stable identifier, e.g. `sspp-fuzz`. Unique across the registry. */
  id: string;
  /** Human title used in finding titles/reports. */
  title: string;
  /** CWE this detector confirms, e.g. `CWE-1321`. */
  cwe: string;
  /** Canonical finding category. */
  category: AttackCategory;
  /** Baseline severity a confirmation gets unless the detector escalates. */
  severityFloor: Severity;
  /** One-sentence description (surfaced in `list-detectors`). */
  description: string;
  /**
   * Cheap static relevance gate. MUST be conservative: a `true` here only
   * schedules the (isolated) dynamic confirm; a `false` skips work. Never let
   * a missing tag hide a real bug — when unsure, return true.
   */
  appliesTo(pkg: PackageRef): boolean;
  /**
   * Deterministically enumerate candidates from the loaded package surface.
   * LLM ranking/expansion MAY pre-seed `hints` but is never load-bearing.
   */
  identifyCandidates(probe: PackageProbe): C[] | Promise<C[]>;
  /**
   * Deterministic confirm — assume-FP. Runs the candidate's harness in the
   * probe's isolation domain and returns a confirmation ONLY on an observed
   * runtime consequence.
   */
  confirm(candidate: C, probe: PackageProbe): DetectorConfirmation | Promise<DetectorConfirmation>;
  /** Dedup knowledge specific to this class (fork-twins, prior 0sec reports). */
  dedupHints?: DedupHints;
}
