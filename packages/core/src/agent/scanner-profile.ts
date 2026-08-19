// Authorized-engagement scanner profile (0sec#926).
//
// The structured scanner wrappers (run_sqlmap/run_nmap/run_ffuf/run_nuclei,
// 0sec#555) are powerful but loud: they fingerprint themselves on the wire
// and fan many requests internally. The stealthy default (0sec#217) is to
// keep them OFF — `allowScanners` is unset, so the wrappers aren't even in the
// tool set. That default is correct and MUST NOT change.
//
// This module is the single gate that decides, per scanner invocation, whether
// the engagement is an *authorized* one in which the suite may run. It bundles
// the "authorized-engagement profile" contract into one pure verdict function
// so the four scanner handlers share identical discipline (no per-handler
// drift) and tools.ts stays surgical.
//
// The contract reuses the existing http_audit / scope constraint vocabulary
// (ScopePolicy host allowlist, EnforcementTracker's PathPolicy + wall-clock
// kill switch, per-host RateLimiter) and mirrors the deny-by-default rails the
// active-subdomain brute-force adopted (recon/active-subdomains.ts):
//
//   1. ENABLED      — `allowScanners === true`. Default OFF: with the flag
//                     unset the wrappers are absent from the tool set AND this
//                     gate hard-refuses (defense-in-depth).
//   2. SCOPED       — an engagement `ScopePolicy` MUST be present. With NO
//                     scope policy the gate refuses (deny-by-default): an
//                     authorized engagement is always an explicitly scoped one,
//                     so an un-scoped scanner run is a configuration error, not
//                     a free-for-all. This closes the prior gap where
//                     `allowScanners` alone (no scope) let a scanner hit any
//                     host.
//   3. IN-SCOPE     — the per-invocation target host must match the scope
//                     policy, and (when an EnforcementTracker carries a path
//                     allowlist) the target path must match a permitted prefix.
//   4. NOT-KILLED   — the wall-clock kill switch (EnforcementTracker) must not
//                     have fired; a time-boxed engagement that has run out of
//                     budget refuses further scanner launches.
//
// Rate limiting stays where it already lives (the caller acquires a per-host
// token after this gate passes); this module only renders the allow/deny
// decision so it is trivially unit-testable without IO.

import type { ScopePolicy } from "../scope/scope.js";
import type { EnforcementTracker } from "../scope/enforcement.js";

/** Inputs the gate inspects. A subset of `ToolContext`, narrowed for testability. */
export interface ScannerEngagementContext {
  /** 0sec#217 opt-out / 0sec#926 profile master switch. Default OFF. */
  allowScanners?: boolean;
  /** Engagement host allowlist (0sec#215). REQUIRED for the gate to pass. */
  scope?: ScopePolicy;
  /** http_audit path allowlist + wall-clock kill switch (0sec#218). Optional. */
  enforcement?: EnforcementTracker;
}

export interface ScannerGateVerdict {
  allowed: boolean;
  /**
   * Why the run was refused, suitable for surfacing as a `ToolResult.error`.
   * Empty string when `allowed` is true.
   */
  reason: string;
  /**
   * True when the refusal is an out-of-scope / out-of-path / kill-switch event
   * that should be tallied into the enforcement counters by the caller. (We do
   * NOT mutate the tracker here — the gate stays pure; the caller notes it.)
   */
  countsAsBlocked: boolean;
}

const ALLOW: ScannerGateVerdict = { allowed: true, reason: "", countsAsBlocked: false };

/**
 * Decide whether `tool` may run against `scopeUrl` under the engagement
 * profile. Pure: no IO, no mutation. The caller acts on the verdict (refuse +
 * note-blocked, or proceed to acquire a rate-limit token and spawn).
 *
 * `scopeUrl` is an absolute http(s) URL built by the caller for the scope
 * check (nmap/nuclei targets that are bare hosts are wrapped to `http://host`
 * upstream), so both the host (ScopePolicy) and path (PathPolicy) matchers see
 * a parseable URL.
 */
export function scannerEngagementGate(
  tool: string,
  scopeUrl: string,
  ctx: ScannerEngagementContext,
): ScannerGateVerdict {
  // Rail 1: master switch. Default OFF — the suppression default (0sec#217).
  if (ctx.allowScanners !== true) {
    return {
      allowed: false,
      reason:
        `${tool} is disabled: generic scanners are suppressed unless the engagement was ` +
        `started with --allow-scanners (0sec#217). Use http_request/crawl for manual probing.`,
      countsAsBlocked: false,
    };
  }

  // Rail 2: an authorized engagement is an explicitly SCOPED one. With no
  // scope policy we refuse (deny-by-default) rather than scan an unbounded
  // target set — mirrors recon/active-subdomains.ts and cloud-surface gating.
  if (!ctx.scope) {
    return {
      allowed: false,
      reason:
        `${tool} refused: no engagement scope is configured (deny-by-default). The scanner ` +
        `profile only runs the suite inside an explicitly scoped engagement — load a --scope policy.`,
      countsAsBlocked: false,
    };
  }

  // Rail 3a: per-invocation host scope.
  const hostVerdict = ctx.scope.match(scopeUrl);
  if (!hostVerdict.allowed) {
    return {
      allowed: false,
      reason: `${tool} refused: target out-of-scope '${scopeUrl}' (${hostVerdict.reason})`,
      countsAsBlocked: true,
    };
  }

  // Rail 3b: per-invocation path allowlist (http_audit profile only — when an
  // EnforcementTracker with a PathPolicy is present). Empty allowlist = all
  // paths, so this is a no-op for non-http_audit scoped engagements.
  // Rail 4: wall-clock kill switch — a time-boxed engagement that has burned
  // its budget refuses further launches.
  if (ctx.enforcement) {
    if (ctx.enforcement.isKillExpired()) {
      return {
        allowed: false,
        reason:
          `${tool} refused: engagement wall-clock kill switch has fired ` +
          `(${ctx.enforcement.wallClockSec().toFixed(1)}s elapsed). No further scanner launches.`,
        countsAsBlocked: false,
      };
    }
    const pathVerdict = ctx.enforcement.pathPolicy.match(scopeUrl);
    if (!pathVerdict.allowed) {
      return {
        allowed: false,
        reason: `${tool} refused: target out-of-path '${scopeUrl}' (${pathVerdict.reason})`,
        countsAsBlocked: true,
      };
    }
  }

  return ALLOW;
}
