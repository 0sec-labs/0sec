import { describe, expect, it } from "vitest";
import { scannerEngagementGate } from "./scanner-profile.js";
import { ScopePolicy } from "../scope/scope.js";
import { EnforcementTracker, PathPolicy } from "../scope/enforcement.js";

// ── Authorized-engagement scanner profile gate (0sec#926) ──
//
// Pure verdict function: no IO. We exercise the four rails (ENABLED / SCOPED /
// IN-SCOPE / NOT-KILLED) directly, plus the http_audit path-allowlist leg.

const scope = ScopePolicy.fromJson({ in_scope: ["*.example.com"] });

describe("scannerEngagementGate — default OFF (0sec#217 stealth preserved)", () => {
  it("refuses when allowScanners is unset (the safe default)", () => {
    const v = scannerEngagementGate("run_sqlmap", "https://api.example.com/?id=1", {
      scope,
    });
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/--allow-scanners/);
    expect(v.countsAsBlocked).toBe(false);
  });

  it("refuses when allowScanners is explicitly false", () => {
    const v = scannerEngagementGate("run_nuclei", "https://api.example.com/", {
      allowScanners: false,
      scope,
    });
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/suppressed/);
  });
});

describe("scannerEngagementGate — deny-by-default scope (0sec#926)", () => {
  it("refuses when allowScanners is true but NO scope policy is configured", () => {
    const v = scannerEngagementGate("run_sqlmap", "https://anything.test/?id=1", {
      allowScanners: true,
      // scope intentionally omitted
    });
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/no engagement scope|deny-by-default/i);
    expect(v.countsAsBlocked).toBe(false);
  });

  it("allows an in-scope target when enabled AND scoped", () => {
    const v = scannerEngagementGate("run_sqlmap", "https://api.example.com/?id=1", {
      allowScanners: true,
      scope,
    });
    expect(v.allowed).toBe(true);
    expect(v.reason).toBe("");
    expect(v.countsAsBlocked).toBe(false);
  });

  it("refuses an out-of-scope host even when enabled + scoped (counts as blocked)", () => {
    const v = scannerEngagementGate("run_nmap", "http://evil.attacker.test", {
      allowScanners: true,
      scope,
    });
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/out-of-scope/);
    expect(v.countsAsBlocked).toBe(true);
  });
});

describe("scannerEngagementGate — http_audit path allowlist + kill switch", () => {
  function tracker(opts: { paths?: string[]; killAfterSec?: number; nowFn?: () => number }) {
    return new EnforcementTracker({
      pathPolicy: new PathPolicy(opts.paths ?? []),
      killAfterSec: opts.killAfterSec ?? 0,
      nowFn: opts.nowFn,
    });
  }

  it("allows an in-path target when a path allowlist is set", () => {
    const enforcement = tracker({ paths: ["/api"] });
    const v = scannerEngagementGate("run_ffuf", "https://api.example.com/api/users", {
      allowScanners: true,
      scope,
      enforcement,
    });
    expect(v.allowed).toBe(true);
  });

  it("refuses an out-of-path target (counts as blocked)", () => {
    const enforcement = tracker({ paths: ["/api"] });
    const v = scannerEngagementGate("run_ffuf", "https://api.example.com/admin", {
      allowScanners: true,
      scope,
      enforcement,
    });
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/out-of-path/);
    expect(v.countsAsBlocked).toBe(true);
  });

  it("an empty path allowlist (allow-all) does not block any in-scope path", () => {
    const enforcement = tracker({ paths: [] });
    const v = scannerEngagementGate("run_ffuf", "https://api.example.com/anything/here", {
      allowScanners: true,
      scope,
      enforcement,
    });
    expect(v.allowed).toBe(true);
  });

  it("refuses once the wall-clock kill switch has fired (time-boxed engagement)", () => {
    // killAfterSec=1, but the clock has already advanced 5s past the start.
    let t = 1_000;
    const enforcement = tracker({ killAfterSec: 1, nowFn: () => t });
    t = 1_000 + 5_000; // 5s elapsed > 1s budget
    const v = scannerEngagementGate("run_nuclei", "https://api.example.com/", {
      allowScanners: true,
      scope,
      enforcement,
    });
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/kill switch/i);
  });

  it("still allows while inside the wall-clock budget", () => {
    let t = 1_000;
    const enforcement = tracker({ killAfterSec: 60, nowFn: () => t });
    t = 1_000 + 5_000; // 5s elapsed < 60s budget
    const v = scannerEngagementGate("run_nuclei", "https://api.example.com/", {
      allowScanners: true,
      scope,
      enforcement,
    });
    expect(v.allowed).toBe(true);
  });
});
