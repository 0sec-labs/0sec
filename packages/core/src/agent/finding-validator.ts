/**
 * Structural validation at the report-creation boundary (0sec#409).
 *
 * Background — Strix's `tools/reporting/reporting_actions.py:201-339` rejects
 * malformed vulnerability reports at the agent boundary BEFORE they enter the
 * pipeline: CVE/CWE shape-check, CVSS vector validation, evidence path
 * traversal guard. 0sec used to trust the LLM's structured output: a
 * hallucinated `CVE-9999-FAKE` or an evidence path of `/etc/passwd` would land
 * in the finding store unchallenged and propagate downstream into disclosure,
 * the dashboard, and (worst) cloud-side dedup keys.
 *
 * This module is the boundary check. Call `validateFindingDraft()` from any
 * tool that persists a finding (today: `save_finding` in `tools.ts`). On
 * failure, the caller returns the structured `ValidationError[]` to the agent
 * as a tool result with a `"validation_failed"` discriminator — same shape as
 * `flag-validator` / the empty-PoC gate — so the agent can fix and re-submit
 * within the same turn. We deliberately do NOT auto-correct (e.g. uppercase
 * `cve-2024-1`): the agent needs to learn, and silent correction hides bugs
 * in the upstream prompt.
 *
 * Out of scope (separate issues):
 *   - LLM-based semantic dedup (Strix does this; 0sec#281 covers the
 *     structural dedup we actually need)
 *   - Changing the `Finding` schema (we read draft fields here, the schema
 *     stays put)
 *   - Auto-fix PR generation (shipped per closed 0sec#377)
 */

import { existsSync, lstatSync, realpathSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

/**
 * Shape of a finding the agent submits via `save_finding` (or any future
 * report-creation tool). Intentionally narrow — we only validate the
 * structurally checkable fields. Anything else on the wire (free-form
 * severity, prose, etc.) is passed through; validating it requires semantic
 * judgement the validator can't make.
 */
export interface FindingDraft {
  /** Optional CVE identifier the agent claims this finding maps to. */
  cve?: string | null;
  /** Optional CWE identifier the agent claims this finding maps to. */
  cwe?: string | null;
  /** Optional CVSS v3.1 vector string. */
  cvss?: string | null;
  /**
   * Optional numeric CVSS base score. When set alongside `cvss`, validated
   * to fall in [0.0, 10.0]. The vector string is the authoritative form;
   * the numeric score is a convenience field.
   */
  cvssScore?: number | null;
  /**
   * Optional list of evidence references the agent wants to attach. Each
   * one may carry a filesystem path the operator should be able to open
   * later (e.g. a screenshot, a captured request blob). Paths get
   * traversal- and symlink-escape-checked against `scanWorkspaceRoot`.
   *
   * The shape is permissive on `path` because at the wire boundary the
   * LLM may pass an object or just a bare path string in an adjacent
   * field. Wire those into this list before calling the validator.
   */
  evidence?: Array<{ path?: string | null }>;
}

export interface ValidationError {
  /** Dotted field path the error refers to (e.g. `cve`, `evidence[0].path`). */
  field: string;
  /** Short, agent-readable explanation of what's wrong. */
  reason: string;
  /** Optional remediation hint (e.g. an example of the expected shape). */
  hint?: string;
}

export type ValidationResult =
  | { ok: true }
  | { ok: false; errors: ValidationError[] };

export interface ValidateFindingDraftContext {
  /**
   * Absolute root the agent is allowed to reference evidence paths inside.
   * Typically the scan workspace dir (`ToolContext.scopePath`). Required.
   *
   * Paths get resolved relative to this root; absolute paths outside it,
   * paths containing `..` segments, and symlink-escapes all get rejected.
   */
  scanWorkspaceRoot: string;
}

// ────────────────────────────────────────────────────────────────────
// Regexes (the structural part)
// ────────────────────────────────────────────────────────────────────

/**
 * CVE ID — uppercase, 4-digit year in 1900s or 2000s, ≥4-digit sequence.
 * This is the canonical MITRE shape; matches `normaliseCveId` in
 * `cve/artifact-scraper.ts` but tightens the year prefix.
 */
const CVE_REGEX = /^CVE-(19|20)\d{2}-\d{4,}$/;

/** CWE ID — uppercase prefix, integer suffix. */
const CWE_REGEX = /^CWE-\d+$/;

/**
 * CVSS v3.1 vector string — `CVSS:3.1/` prefix plus the 8 base metrics in
 * order (AV / AC / PR / UI / S / C / I / A). Each base metric must use a
 * valid value letter. Optional temporal / environmental metrics are not
 * required and not parsed here — we only validate the base vector is
 * well-formed. A heavier `cvss` npm dep would buy us scoring math, but
 * shape-check is what catches LLM hallucinations.
 */
const CVSS_V31_REGEX =
  /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/;

// ────────────────────────────────────────────────────────────────────
// Path guard — extracted from journal/replay.ts:resolveArtifactPath.
// Same algorithm, returned as a boolean+reason pair so the validator
// can collect structured errors instead of throwing. Symlink-escape
// check (realpath) layered on top — journal artifacts are write-only
// from inside the harness so they don't need it; agent-submitted
// evidence paths can point at anything on disk and DO.
// ────────────────────────────────────────────────────────────────────

/**
 * Check whether `inputPath` resolves to a location inside `root`, after
 * normalising both with `path.resolve` and (when the path exists) with
 * `fs.realpathSync` to follow symlinks. Returns a non-empty reason string
 * on rejection, or `null` when the path is safe.
 *
 * Exported for reuse — keep the algorithm in one place. The journal's
 * `resolveArtifactPath` predates this and stays as-is (throws an Error
 * unconditionally; its callers want that). New call sites should use this.
 */
export function pathEscapeReason(
  root: string,
  inputPath: string,
): string | null {
  // 1. Raw input check — `..` segments must be rejected BEFORE resolve()
  //    silently collapses them. The journal helper doesn't need this
  //    because journal refs are minted by the harness; agent-submitted
  //    paths are untrusted.
  if (/(^|[\\/])\.\.([\\/]|$)/.test(inputPath)) {
    return `path contains parent-directory ('..') segment: ${inputPath}`;
  }

  const resolvedRoot = resolve(root);
  const resolved = isAbsolute(inputPath)
    ? resolve(inputPath)
    : resolve(resolvedRoot, inputPath);

  // 2. Lexical containment — mirrors journal/replay.ts:205.
  if (
    resolved !== resolvedRoot &&
    !resolved.startsWith(`${resolvedRoot}${sep}`)
  ) {
    return `path resolves outside scan workspace: ${inputPath}`;
  }

  // 3. Symlink-escape — realpath() the parts that exist. We use lstat
  //    to detect whether the path itself is a symlink so we can give a
  //    clearer error message. We also realpath the root once for an
  //    apples-to-apples comparison (root may itself live under a
  //    symlinked /tmp on macOS, etc.).
  let realRoot: string;
  try {
    realRoot = realpathSync(resolvedRoot);
  } catch {
    // Root doesn't exist — treat as a programming bug upstream; reject
    // rather than silently passing.
    return `scan workspace root does not exist: ${root}`;
  }

  if (existsSync(resolved)) {
    let real: string;
    try {
      real = realpathSync(resolved);
    } catch {
      // The path exists per `existsSync` but realpath blew up — e.g. a
      // dangling symlink whose target was just unlinked. Refuse rather
      // than guess. `lstatSync` lets us name the failure mode clearly.
      const symlink = (() => {
        try {
          return lstatSync(resolved).isSymbolicLink();
        } catch {
          return false;
        }
      })();
      return symlink
        ? `evidence path is a dangling or unreadable symlink: ${inputPath}`
        : `evidence path cannot be resolved: ${inputPath}`;
    }
    if (real !== realRoot && !real.startsWith(`${realRoot}${sep}`)) {
      return `evidence path symlink escapes scan workspace: ${inputPath}`;
    }
  }
  // Non-existent paths are allowed past the symlink check — the agent may
  // be referencing an artifact that hasn't been written yet. The lexical
  // containment check above is the line of defence in that case.

  return null;
}

// ────────────────────────────────────────────────────────────────────
// The validator
// ────────────────────────────────────────────────────────────────────

/**
 * Validate a finding draft submitted by the agent. Returns
 * `{ ok: true }` on success or a structured list of errors the caller
 * can hand back to the agent as a tool result.
 *
 * Validation rules (each independently configurable; all currently on):
 *   1. `cve`  — must match `/^CVE-(19|20)\d{2}-\d{4,}$/` when set.
 *   2. `cwe`  — must match `/^CWE-\d+$/` when set.
 *   3. `cvss` — must be a CVSS v3.1 vector string when set.
 *   4. `cvssScore` — must be in [0.0, 10.0] when set.
 *   5. `evidence[].path` — each path must resolve inside
 *      `ctx.scanWorkspaceRoot` (no `..`, no absolute escapes, no
 *      symlink-escapes).
 *
 * Empty / unset optional fields are NOT errors — callers may legitimately
 * file a finding with no CVE assigned yet.
 */
export function validateFindingDraft(
  draft: FindingDraft,
  ctx: ValidateFindingDraftContext,
): ValidationResult {
  const errors: ValidationError[] = [];

  // ── CVE ──
  if (isPresent(draft.cve)) {
    const v = draft.cve as string;
    if (typeof v !== "string") {
      errors.push({
        field: "cve",
        reason: `cve must be a string, got ${typeof v}`,
        hint: "Example: CVE-2024-1086",
      });
    } else if (!CVE_REGEX.test(v)) {
      errors.push({
        field: "cve",
        reason: `cve does not match CVE-YYYY-N (YYYY in 1900s/2000s, N ≥ 4 digits): ${JSON.stringify(v)}`,
        hint: "Example: CVE-2024-1086. IDs are uppercase. Hallucinated IDs (e.g. CVE-9999-FAKE) and lowercase variants are rejected.",
      });
    }
  }

  // ── CWE ──
  if (isPresent(draft.cwe)) {
    const v = draft.cwe;
    if (typeof v !== "string") {
      errors.push({
        field: "cwe",
        reason: `cwe must be a string, got ${typeof v}`,
        hint: "Example: CWE-89",
      });
    } else if (!CWE_REGEX.test(v)) {
      errors.push({
        field: "cwe",
        reason: `cwe does not match CWE-N: ${JSON.stringify(v)}`,
        hint: "Example: CWE-89 (SQL injection). Uppercase prefix, integer suffix, no spaces.",
      });
    }
  }

  // ── CVSS ──
  if (isPresent(draft.cvss)) {
    const v = draft.cvss;
    if (typeof v !== "string") {
      errors.push({
        field: "cvss",
        reason: `cvss must be a string, got ${typeof v}`,
        hint: "Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      });
    } else if (!CVSS_V31_REGEX.test(v)) {
      errors.push({
        field: "cvss",
        reason: `cvss is not a valid CVSS v3.1 base vector: ${JSON.stringify(v)}`,
        hint: "Must begin with 'CVSS:3.1/' and include all 8 base metrics (AV/AC/PR/UI/S/C/I/A) in order. Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      });
    }
  }

  // ── CVSS numeric score ──
  if (isPresent(draft.cvssScore)) {
    const n = draft.cvssScore;
    if (typeof n !== "number" || !Number.isFinite(n)) {
      errors.push({
        field: "cvssScore",
        reason: `cvssScore must be a finite number, got ${typeof n}`,
        hint: "Range: 0.0–10.0",
      });
    } else if (n < 0 || n > 10) {
      errors.push({
        field: "cvssScore",
        reason: `cvssScore must be in [0.0, 10.0], got ${n}`,
      });
    }
  }

  // ── Evidence paths ──
  if (Array.isArray(draft.evidence)) {
    for (let i = 0; i < draft.evidence.length; i++) {
      const entry = draft.evidence[i];
      if (!entry || typeof entry !== "object") continue;
      const path = entry.path;
      if (!isPresent(path)) continue;
      if (typeof path !== "string") {
        errors.push({
          field: `evidence[${i}].path`,
          reason: `evidence path must be a string, got ${typeof path}`,
        });
        continue;
      }
      const reason = pathEscapeReason(ctx.scanWorkspaceRoot, path);
      if (reason) {
        errors.push({
          field: `evidence[${i}].path`,
          reason,
          hint: "Evidence paths must live inside the scan workspace; use a path relative to the workspace root (or an absolute path inside it). '../foo', '/etc/passwd', and symlinks that point outside the workspace are rejected.",
        });
      }
    }
  }

  if (errors.length === 0) return { ok: true };
  return { ok: false, errors };
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/**
 * True when a draft field is "present" — not undefined, not null, not the
 * empty string. Numeric zero IS present (matters for cvssScore=0.0).
 */
function isPresent(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "string" && v.trim().length === 0) return false;
  return true;
}
