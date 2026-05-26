import { describe, it, expect } from "vitest";
import {
  TokenBucket,
  RateLimiter,
  parseRateLimitFlag,
  parseRetryAfter,
} from "./rate-limit.js";

/**
 * Virtual time harness. We do NOT depend on real `setTimeout` /
 * `Date.now` for any of the bucket-math tests — every "wait" in the
 * limiter is intercepted and replaced with an instantaneous clock
 * advance. This keeps the test suite deterministic and finishes the
 * full "burst N + (N+1)th waits" assertion in microseconds, not
 * seconds.
 */
function virtualClock(start = 1_000_000) {
  let now = start;
  let observedSleeps: number[] = [];
  return {
    nowFn: () => now,
    advance: (ms: number) => { now += ms; },
    sleepFn: async (ms: number) => {
      observedSleeps.push(ms);
      now += ms;
    },
    sleeps: () => observedSleeps,
    reset: () => { observedSleeps = []; },
  };
}

describe("TokenBucket", () => {
  it("rejects non-positive rps / capacity", () => {
    expect(() => new TokenBucket(0)).toThrow(/positive/);
    expect(() => new TokenBucket(-1)).toThrow(/positive/);
    expect(() => new TokenBucket(NaN)).toThrow(/positive/);
    expect(() => new TokenBucket(5, 0)).toThrow(/positive/);
  });

  it("starts full at capacity", () => {
    const c = virtualClock();
    const b = new TokenBucket(5, 5, c.nowFn, c.sleepFn);
    expect(b._peek().tokens).toBe(5);
  });

  it("burst N requests succeed instantly via tryConsume", () => {
    const c = virtualClock();
    const b = new TokenBucket(5, 5, c.nowFn, c.sleepFn);
    for (let i = 0; i < 5; i++) {
      expect(b.tryConsume()).toBe(true);
    }
    expect(b.tryConsume()).toBe(false);
    expect(c.sleeps()).toEqual([]);
  });

  it("acquire blocks (sleeps) for the (N+1)th request at ~1/rps", async () => {
    const c = virtualClock();
    const b = new TokenBucket(10, 10, c.nowFn, c.sleepFn);
    // Drain the bucket.
    for (let i = 0; i < 10; i++) {
      expect(b.tryConsume()).toBe(true);
    }
    // 11th: must wait. 10 rps → 1 token / 100ms.
    await b.acquire();
    const total = c.sleeps().reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThanOrEqual(99);
    expect(total).toBeLessThanOrEqual(101);
  });

  it("refills at the configured rate after a wait", async () => {
    const c = virtualClock();
    const b = new TokenBucket(5, 5, c.nowFn, c.sleepFn);
    // Drain.
    for (let i = 0; i < 5; i++) b.tryConsume();
    expect(b.tryConsume()).toBe(false);
    // Advance virtual time by 1 second → bucket should be full again.
    c.advance(1000);
    for (let i = 0; i < 5; i++) {
      expect(b.tryConsume()).toBe(true);
    }
    expect(b.tryConsume()).toBe(false);
  });

  it("fractional refill is accumulated correctly", async () => {
    const c = virtualClock();
    const b = new TokenBucket(2, 2, c.nowFn, c.sleepFn);
    b.tryConsume();
    b.tryConsume();
    expect(b.tryConsume()).toBe(false);
    // 250ms at 2 rps = 0.5 tokens — not enough.
    c.advance(250);
    expect(b.tryConsume()).toBe(false);
    // Another 250ms → 0.5 + 0.5 = 1 token.
    c.advance(250);
    expect(b.tryConsume()).toBe(true);
  });

  it("does not refill above capacity", async () => {
    const c = virtualClock();
    const b = new TokenBucket(5, 5, c.nowFn, c.sleepFn);
    c.advance(60_000); // sit idle for a minute
    expect(b._peek().tokens).toBe(5);
  });

  it("markRetryUntil parks acquire/tryConsume", async () => {
    const c = virtualClock();
    const b = new TokenBucket(5, 5, c.nowFn, c.sleepFn);
    b.markRetryUntil(c.nowFn() + 5000);
    expect(b.tryConsume()).toBe(false);
    await b.acquire();
    // The acquire must have slept past the park deadline.
    const total = c.sleeps().reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThanOrEqual(5000);
  });

  it("acquire(n) clamps n to capacity instead of looping forever", async () => {
    const c = virtualClock();
    const b = new TokenBucket(2, 2, c.nowFn, c.sleepFn);
    // Asking for 100 should NOT loop forever; it gets clamped to 2.
    await b.acquire(100);
    // Bucket should now be empty.
    expect(b.tryConsume()).toBe(false);
  });
});

describe("RateLimiter", () => {
  it("per-host isolation: throttling A does not affect B", async () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 1 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    // Drain host A by acquiring once (capacity = 1).
    await rl.acquire("https://a.example.com/");
    // tryAcquire on A is false (cooling down).
    expect(rl.tryAcquire("https://a.example.com/")).toBe(false);
    // tryAcquire on B (fresh bucket) is true.
    expect(rl.tryAcquire("https://b.example.com/")).toBe(true);
  });

  it("uses per-host override over default", async () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      {
        default: { rps: 1 },
        perHost: { "fast.example.com": { rps: 100, burst: 100 } },
      },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    // 50 burst should fly through the fast host without blocking.
    for (let i = 0; i < 50; i++) {
      expect(rl.tryAcquire("https://fast.example.com/path")).toBe(true);
    }
    // The slow default host: 1 burst then cooldown.
    expect(rl.tryAcquire("https://slow.example.com/")).toBe(true);
    expect(rl.tryAcquire("https://slow.example.com/")).toBe(false);
  });

  it("normalizes host: case and port", () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 1 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    expect(rl.tryAcquire("https://Example.com/x")).toBe(true);
    // Same bucket as Example.com.
    expect(rl.tryAcquire("https://EXAMPLE.com:443/y")).toBe(false);
  });

  it("noteResponse(429) parks the host bucket past Retry-After", async () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 100, burst: 100 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    // Prime the bucket.
    expect(rl.tryAcquire("https://api.example.com/")).toBe(true);
    // Simulate a 429 with a 5s Retry-After.
    const headers = new Headers({ "retry-after": "5" });
    rl.noteResponse("https://api.example.com/", { status: 429, headers });
    // Bucket should be parked.
    expect(rl.tryAcquire("https://api.example.com/")).toBe(false);
    // Acquire should sleep through the floor (60s) — Retry-After is
    // floored at 60s for safety.
    await rl.acquire("https://api.example.com/");
    const total = c.sleeps().reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThanOrEqual(60_000);
  });

  it("noteResponse on non-429 is a no-op", () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 100, burst: 100 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    expect(rl.tryAcquire("https://api.example.com/")).toBe(true);
    rl.noteResponse("https://api.example.com/", {
      status: 200,
      headers: new Headers({ "retry-after": "60" }),
    });
    // Still acquireable: no park.
    expect(rl.tryAcquire("https://api.example.com/")).toBe(true);
  });

  it("noteResponse with HTTP-date Retry-After parks until that moment", () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 100, burst: 100 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    // Set virtualClock to a real-ish epoch for a sane Date string.
    const baseEpoch = Date.UTC(2024, 0, 1, 0, 0, 0);
    const c2 = virtualClock(baseEpoch);
    const rl2 = new RateLimiter(
      { default: { rps: 100, burst: 100 } },
      { nowFn: c2.nowFn, sleepFn: c2.sleepFn },
    );
    const future = new Date(baseEpoch + 120_000).toUTCString();
    rl2.noteResponse("https://api.example.com/", {
      status: 429,
      headers: new Headers({ "retry-after": future }),
    });
    expect(rl2.tryAcquire("https://api.example.com/")).toBe(false);
    // After 120s the bucket should be acquireable again (well past floor).
    c2.advance(125_000);
    expect(rl2.tryAcquire("https://api.example.com/")).toBe(true);
  });

  it("acquire on unparseable target is a no-op", async () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 1 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    await rl.acquire("");
    await rl.acquire("not a url at all !!!"); // returns immediately
    // No buckets created, no sleeps recorded.
    expect(c.sleeps()).toEqual([]);
  });

  it("burst then refill end-to-end with acquire", async () => {
    const c = virtualClock();
    const rl = new RateLimiter(
      { default: { rps: 5, burst: 5 } },
      { nowFn: c.nowFn, sleepFn: c.sleepFn },
    );
    const start = c.nowFn();
    for (let i = 0; i < 5; i++) {
      await rl.acquire("https://x.example.com/");
    }
    // Burst: no sleeping.
    expect(c.sleeps()).toEqual([]);
    // 6th call: must sleep ~200ms (1 token / (5/1000) ms = 200ms).
    await rl.acquire("https://x.example.com/");
    const total = c.nowFn() - start;
    expect(total).toBeGreaterThanOrEqual(199);
    expect(total).toBeLessThanOrEqual(201);
  });
});

describe("parseRateLimitFlag", () => {
  it("plain rps becomes the default", () => {
    expect(parseRateLimitFlag("10")).toEqual({
      default: { rps: 10 },
    });
  });

  it("plain rps:burst", () => {
    expect(parseRateLimitFlag("10:25")).toEqual({
      default: { rps: 10, burst: 25 },
    });
  });

  it("per-host overrides + default", () => {
    expect(
      parseRateLimitFlag("api.example.com=5,*.example.com=3:6,2"),
    ).toEqual({
      default: { rps: 2 },
      perHost: {
        "api.example.com": { rps: 5 },
        "*.example.com": { rps: 3, burst: 6 },
      },
    });
  });

  it("per-host only uses fallback default", () => {
    expect(parseRateLimitFlag("api.example.com=5", 7)).toEqual({
      default: { rps: 7 },
      perHost: { "api.example.com": { rps: 5 } },
    });
  });

  it("empty string uses fallback default", () => {
    expect(parseRateLimitFlag("", 5)).toEqual({ default: { rps: 5 } });
  });

  it("rejects malformed: empty host", () => {
    expect(() => parseRateLimitFlag("=5")).toThrow(/empty host/);
  });

  it("rejects malformed: non-numeric rps", () => {
    expect(() => parseRateLimitFlag("api.example.com=fast")).toThrow(/invalid rps/);
  });

  it("rejects malformed: zero or negative rps", () => {
    expect(() => parseRateLimitFlag("0")).toThrow(/invalid rps/);
    expect(() => parseRateLimitFlag("-3")).toThrow(/invalid rps/);
  });

  it("rejects malformed: non-numeric burst", () => {
    expect(() => parseRateLimitFlag("5:fast")).toThrow(/invalid burst/);
  });

  it("lowercases host keys", () => {
    expect(parseRateLimitFlag("API.Example.COM=5")).toEqual({
      default: { rps: 5 },
      perHost: { "api.example.com": { rps: 5 } },
    });
  });
});

describe("parseRetryAfter", () => {
  it("parses delta-seconds", () => {
    expect(parseRetryAfter("5", 1_000_000)).toBe(5000);
    expect(parseRetryAfter("0", 1_000_000)).toBe(0);
  });

  it("parses HTTP-date", () => {
    const now = Date.UTC(2024, 0, 1, 0, 0, 0);
    const future = new Date(now + 30_000).toUTCString();
    expect(parseRetryAfter(future, now)).toBe(30_000);
  });

  it("HTTP-date in the past clamps to 0", () => {
    const now = Date.UTC(2024, 6, 1, 0, 0, 0);
    const past = new Date(now - 60_000).toUTCString();
    expect(parseRetryAfter(past, now)).toBe(0);
  });

  it("returns 0 for null / empty / garbage", () => {
    expect(parseRetryAfter(null, 1_000_000)).toBe(0);
    expect(parseRetryAfter("", 1_000_000)).toBe(0);
    expect(parseRetryAfter("not-a-date", 1_000_000)).toBe(0);
  });
});
