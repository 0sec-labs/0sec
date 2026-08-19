/**
 * http_audit enforcement primitives.
 *
 * The `http_audit` scan mode (worker-driven, env-configured) layers three
 * NEW guarantees on top of the existing host-only `ScopePolicy` (#215) and
 * per-host `RateLimiter` (#214):
 *
 *   1. Path-PREFIX allowlist — `ScopePolicy` only matches HOSTS. In
 *      http_audit mode the worker may additionally restrict egress to a set
 *      of path prefixes (e.g. only `/api/`). Empty list = allow all paths.
 *
 *   2. Wall-clock kill switch — abort the agent loop cleanly after N seconds
 *      so a runaway scan can't burn budget indefinitely. The abort flushes
 *      partial findings through the normal report-assembly path (NOT
 *      process.exit).
 *
 *   3. Enforcement counters — every scope verdict (in/out), every rate-limit
 *      throttle, and the peak observed RPS are tallied into the frozen
 *      `enforcement_summary` block the worker contract requires.
 *
 * All three are carried on a single mutable `EnforcementTracker` instance,
 * created once per scan and threaded down through `AgentConfig` →
 * `NativeAgentConfig`/legacy `AgentConfig` → `ToolContext` so every fetch
 * chokepoint mutates the same counters.
 */

import type { AuthConfig, EnforcementSummary } from "@pwnkit/shared";

/**
 * The frozen `enforcement_summary` block emitted in the http_audit report.
 * Defined canonically in `@pwnkit/shared` (so `ScanReport` can carry it
 * without a core→shared dependency inversion); re-exported here for the
 * core call sites that build it.
 */
export type { EnforcementSummary };

export interface PathMatch {
  allowed: boolean;
  reason: string;
}

/**
 * Path-PREFIX allowlist matcher. Sibling to `ScopePolicy` (which only
 * matches hosts). Prefixes are matched against the URL pathname only.
 *
 * Matching rules:
 *   - Empty allowlist  → allow ALL paths (the host check still applies).
 *   - A prefix `/api`  → matches `/api`, `/api/`, `/api/v1/users`, but NOT
 *     `/apixyz` (we treat the prefix as a path-segment boundary so that
 *     `/api` does not silently admit `/apifoo`). The boundary is satisfied
 *     when the pathname equals the prefix, or the next char after the
 *     prefix is `/`, or the prefix itself ends in `/`.
 *   - Trailing slashes on the prefix are normalised away before comparison
 *     so `/api/` and `/api` behave identically.
 */
export class PathPolicy {
  // Defaults to allow-all (empty list). The constructor may early-return on
  // a root ("" / "/") prefix, which must leave the policy in this allow-all
  // state — hence the field initializer rather than relying solely on the
  // constructor assignment below.
  private readonly prefixes: string[] = [];

  constructor(prefixes: string[]) {
    // Normalise: ensure leading slash, strip trailing slash (except root),
    // drop empties. An entry of "" or "/" means "allow all" — represented
    // by an empty prefix list so `match` short-circuits.
    const cleaned: string[] = [];
    for (const raw of prefixes) {
      if (typeof raw !== "string") continue;
      let p = raw.trim();
      if (p === "" || p === "/") {
        // A root prefix means allow-all; collapse the whole policy to empty
        // (the field initializer already set prefixes = []).
        return;
      }
      if (!p.startsWith("/")) p = "/" + p;
      // strip a single trailing slash for canonical comparison
      if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
      cleaned.push(p);
    }
    this.prefixes = cleaned;
  }

  /** True when no path restriction is configured (allow every path). */
  get allowAll(): boolean {
    return !this.prefixes || this.prefixes.length === 0;
  }

  /**
   * Decide whether a URL's pathname is admitted by the prefix allowlist.
   * Empty allowlist always allows. Unparseable URL → blocked (defensive;
   * the host-level scope check would also reject it, but we never want to
   * fail open here).
   */
  match(url: string): PathMatch {
    if (this.allowAll) return { allowed: true, reason: "no path restriction" };
    let pathname: string;
    try {
      pathname = new URL(url).pathname || "/";
    } catch {
      return { allowed: false, reason: `out-of-scope path: not a valid URL (${url})` };
    }
    for (const prefix of this.prefixes) {
      if (pathname === prefix) return { allowed: true, reason: `path '${pathname}' matches prefix '${prefix}'` };
      if (pathname.startsWith(prefix + "/")) {
        return { allowed: true, reason: `path '${pathname}' matches prefix '${prefix}'` };
      }
    }
    return {
      allowed: false,
      reason: `out-of-scope path: '${pathname}' matches none of the allowed prefixes [${this.prefixes.join(", ")}]`,
    };
  }
}

function authModeOf(auth: AuthConfig | undefined): EnforcementSummary["auth_mode_used"] {
  if (!auth) return "none";
  switch (auth.type) {
    case "bearer":
      return "bearer";
    case "header":
      return "header";
    case "cookie":
      return "cookie";
    case "basic":
      return "basic";
    default:
      return "none";
  }
}

/**
 * Per-scan mutable enforcement state. One instance is created at the top of
 * an http_audit scan and shared by every agent loop / tool executor so the
 * counters aggregate across discovery + attack + verify stages.
 */
export class EnforcementTracker {
  readonly pathPolicy: PathPolicy;
  private readonly authMode: EnforcementSummary["auth_mode_used"];
  private readonly killAfterSec: number;
  private readonly startedAtMs: number;
  private readonly nowFn: () => number;

  private requestsInScope = 0;
  private requestsOutOfScopeBlocked = 0;
  private rateLimitedCount = 0;
  private killSwitchTriggered = false;

  /**
   * Timestamps (ms) of in-scope egress requests, used to compute peak RPS
   * over any sliding 1-second window. Pruned to the trailing window on each
   * record so the array can't grow unbounded on a long scan.
   */
  private readonly requestTimes: number[] = [];
  private peakRps = 0;

  constructor(opts: {
    pathPolicy: PathPolicy;
    auth?: AuthConfig;
    killAfterSec: number;
    nowFn?: () => number;
  }) {
    this.pathPolicy = opts.pathPolicy;
    this.authMode = authModeOf(opts.auth);
    this.killAfterSec = opts.killAfterSec;
    this.nowFn = opts.nowFn ?? (() => Date.now());
    this.startedAtMs = this.nowFn();
  }

  /** Record a request that passed host + path scope and was dispatched. */
  noteInScope(): void {
    this.requestsInScope += 1;
    this.recordRequestTimestamp();
  }

  /** Record a request refused by host scope OR path scope. */
  noteOutOfScopeBlocked(): void {
    this.requestsOutOfScopeBlocked += 1;
  }

  /** Record a rate-limit throttle event (an acquire that had to wait, or a 429). */
  noteRateLimited(): void {
    this.rateLimitedCount += 1;
  }

  /** Stamp an egress timestamp and update the running peak-RPS figure. */
  private recordRequestTimestamp(): void {
    const now = this.nowFn();
    this.requestTimes.push(now);
    // Prune anything older than the 1s window.
    const cutoff = now - 1000;
    while (this.requestTimes.length > 0 && this.requestTimes[0] < cutoff) {
      this.requestTimes.shift();
    }
    // Count in the trailing 1s window is the instantaneous rps; track the max.
    if (this.requestTimes.length > this.peakRps) {
      this.peakRps = this.requestTimes.length;
    }
  }

  /**
   * True once the wall-clock budget is exhausted. The agent loop polls this
   * at turn boundaries and breaks out cleanly (preserving partial findings)
   * when it flips. killAfterSec <= 0 disables the kill switch.
   */
  isKillExpired(): boolean {
    if (this.killAfterSec <= 0) return false;
    const expired = (this.nowFn() - this.startedAtMs) / 1000 >= this.killAfterSec;
    if (expired) this.killSwitchTriggered = true;
    return expired;
  }

  /** Whether the kill switch has fired at least once. */
  get triggered(): boolean {
    return this.killSwitchTriggered;
  }

  /** Mark the kill switch as triggered (used by the loop break path). */
  markKilled(): void {
    this.killSwitchTriggered = true;
  }

  /** Elapsed wall-clock seconds since the tracker was constructed. */
  wallClockSec(): number {
    return (this.nowFn() - this.startedAtMs) / 1000;
  }

  /** Assemble the frozen `enforcement_summary` block. */
  summarize(): EnforcementSummary {
    return {
      auth_mode_used: this.authMode,
      requests_in_scope: this.requestsInScope,
      requests_out_of_scope_blocked: this.requestsOutOfScopeBlocked,
      peak_rps: this.peakRps,
      rate_limited_count: this.rateLimitedCount,
      kill_switch_triggered: this.killSwitchTriggered,
      wall_clock_sec: Math.round(this.wallClockSec() * 1000) / 1000,
    };
  }
}
