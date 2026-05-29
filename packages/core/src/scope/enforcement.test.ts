import { describe, it, expect } from "vitest";
import { PathPolicy, EnforcementTracker } from "./enforcement.js";

/**
 * Virtual clock so peak-RPS / kill-switch assertions are deterministic and
 * don't depend on wall time. Mirrors the harness in `rate-limit.test.ts`.
 */
function virtualClock(start = 1_000_000) {
  let now = start;
  return {
    nowFn: () => now,
    advance: (ms: number) => { now += ms; },
  };
}

describe("PathPolicy", () => {
  it("empty allowlist allows all paths (allowAll)", () => {
    const p = new PathPolicy([]);
    expect(p.allowAll).toBe(true);
    expect(p.match("https://t/").allowed).toBe(true);
    expect(p.match("https://t/anything/here").allowed).toBe(true);
  });

  it("a root prefix collapses to allow-all", () => {
    expect(new PathPolicy(["/"]).allowAll).toBe(true);
    expect(new PathPolicy([""]).allowAll).toBe(true);
    // even mixed with other prefixes, a root entry means allow-all
    expect(new PathPolicy(["/api", "/"]).allowAll).toBe(true);
  });

  it("matches an exact prefix and its descendants", () => {
    const p = new PathPolicy(["/api"]);
    expect(p.match("https://t/api").allowed).toBe(true);
    expect(p.match("https://t/api/").allowed).toBe(true);
    expect(p.match("https://t/api/v1/users").allowed).toBe(true);
  });

  it("enforces a path-segment boundary (no /apifoo leak)", () => {
    const p = new PathPolicy(["/api"]);
    expect(p.match("https://t/apixyz").allowed).toBe(false);
    expect(p.match("https://t/apifoo/bar").allowed).toBe(false);
    expect(p.match("https://t/other").allowed).toBe(false);
  });

  it("normalises leading and trailing slashes", () => {
    // missing leading slash + trailing slash both normalised to "/api"
    const p = new PathPolicy(["api/"]);
    expect(p.match("https://t/api").allowed).toBe(true);
    expect(p.match("https://t/api/v1").allowed).toBe(true);
    expect(p.match("https://t/apixyz").allowed).toBe(false);
  });

  it("supports multiple prefixes (OR)", () => {
    const p = new PathPolicy(["/api", "/admin"]);
    expect(p.match("https://t/api/x").allowed).toBe(true);
    expect(p.match("https://t/admin").allowed).toBe(true);
    expect(p.match("https://t/public").allowed).toBe(false);
  });

  it("fails closed on an unparseable URL", () => {
    const p = new PathPolicy(["/api"]);
    expect(p.match("not a url").allowed).toBe(false);
  });

  it("returns a human-readable reason on block", () => {
    const p = new PathPolicy(["/api"]);
    const v = p.match("https://t/secret");
    expect(v.allowed).toBe(false);
    expect(v.reason).toMatch(/out-of-scope path/);
  });
});

describe("EnforcementTracker counters", () => {
  it("tallies in-scope / out-of-scope requests independently", () => {
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      killAfterSec: 0,
    });
    t.noteInScope();
    t.noteInScope();
    t.noteOutOfScopeBlocked();
    const s = t.summarize();
    expect(s.requests_in_scope).toBe(2);
    expect(s.requests_out_of_scope_blocked).toBe(1);
  });

  it("counts rate-limit throttles", () => {
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      killAfterSec: 0,
    });
    t.noteRateLimited();
    t.noteRateLimited();
    t.noteRateLimited();
    expect(t.summarize().rate_limited_count).toBe(3);
  });

  it("tracks peak RPS over a sliding 1s window", () => {
    const clock = virtualClock();
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      killAfterSec: 0,
      nowFn: clock.nowFn,
    });
    // 5 requests inside the same second → peak 5
    for (let i = 0; i < 5; i++) {
      clock.advance(100); // 5 * 100ms = 500ms, all within 1s
      t.noteInScope();
    }
    expect(t.summarize().peak_rps).toBe(5);
    // Advance well past the window; 2 more requests → window holds only 2,
    // but the peak (5) is sticky.
    clock.advance(5_000);
    t.noteInScope();
    clock.advance(100);
    t.noteInScope();
    expect(t.summarize().peak_rps).toBe(5);
  });

  it("reports the auth mode used", () => {
    const bearer = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      auth: { type: "bearer", token: "x" },
      killAfterSec: 0,
    });
    expect(bearer.summarize().auth_mode_used).toBe("bearer");

    const none = new EnforcementTracker({ pathPolicy: new PathPolicy([]), killAfterSec: 0 });
    expect(none.summarize().auth_mode_used).toBe("none");

    const header = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      auth: { type: "header", name: "X-API-Key", value: "x" },
      killAfterSec: 0,
    });
    expect(header.summarize().auth_mode_used).toBe("header");
  });
});

describe("EnforcementTracker kill switch", () => {
  it("never expires when killAfterSec <= 0", () => {
    const clock = virtualClock();
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      killAfterSec: 0,
      nowFn: clock.nowFn,
    });
    clock.advance(10_000_000);
    expect(t.isKillExpired()).toBe(false);
    expect(t.triggered).toBe(false);
  });

  it("expires once the wall-clock budget is exhausted and stays triggered", () => {
    const clock = virtualClock();
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      killAfterSec: 30,
      nowFn: clock.nowFn,
    });
    clock.advance(29_000);
    expect(t.isKillExpired()).toBe(false);
    clock.advance(2_000); // now 31s elapsed
    expect(t.isKillExpired()).toBe(true);
    expect(t.triggered).toBe(true);
    expect(t.summarize().kill_switch_triggered).toBe(true);
  });

  it("markKilled flips the flag without the clock", () => {
    const t = new EnforcementTracker({ pathPolicy: new PathPolicy([]), killAfterSec: 1800 });
    expect(t.triggered).toBe(false);
    t.markKilled();
    expect(t.triggered).toBe(true);
  });

  it("reports elapsed wall-clock seconds", () => {
    const clock = virtualClock();
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy([]),
      killAfterSec: 1800,
      nowFn: clock.nowFn,
    });
    clock.advance(12_500);
    expect(t.wallClockSec()).toBeCloseTo(12.5, 3);
  });
});

describe("EnforcementTracker.summarize shape (frozen contract)", () => {
  it("emits exactly the contract keys", () => {
    const t = new EnforcementTracker({
      pathPolicy: new PathPolicy(["/api"]),
      auth: { type: "cookie", value: "s=1" },
      killAfterSec: 1800,
    });
    const s = t.summarize();
    expect(Object.keys(s).sort()).toEqual(
      [
        "auth_mode_used",
        "kill_switch_triggered",
        "peak_rps",
        "rate_limited_count",
        "requests_in_scope",
        "requests_out_of_scope_blocked",
        "wall_clock_sec",
      ].sort(),
    );
    expect(s.auth_mode_used).toBe("cookie");
    expect(typeof s.wall_clock_sec).toBe("number");
    expect(typeof s.peak_rps).toBe("number");
  });
});
