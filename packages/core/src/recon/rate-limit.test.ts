import { describe, expect, it } from "vitest";
import {
  DEFAULT_BURST,
  MAX_BURST,
  clampBurst,
  probeRateLimit,
} from "./rate-limit.js";

/**
 * Build a request thunk that returns `status` for every call, while counting
 * how many times it was invoked (to assert the burst cap is enforced).
 */
function constantStatus(status: number): {
  request: (i: number) => Promise<{ status: number }>;
  calls: () => number;
} {
  let calls = 0;
  return {
    request: async () => {
      calls++;
      return { status };
    },
    calls: () => calls,
  };
}

describe("clampBurst (safety bound)", () => {
  it("defaults to DEFAULT_BURST when unset or non-finite", () => {
    expect(clampBurst()).toBe(DEFAULT_BURST);
    expect(clampBurst(Number.NaN)).toBe(DEFAULT_BURST);
    expect(clampBurst(Infinity)).toBe(DEFAULT_BURST); // non-finite -> safe default
  });

  it("never exceeds the hard cap, never goes below 1", () => {
    expect(clampBurst(1000)).toBe(MAX_BURST);
    expect(clampBurst(MAX_BURST + 1)).toBe(MAX_BURST);
    expect(clampBurst(0)).toBe(1);
    expect(clampBurst(-5)).toBe(1);
  });

  it("passes through in-range values (floored)", () => {
    expect(clampBurst(10)).toBe(10);
    expect(clampBurst(7.9)).toBe(7);
  });
});

describe("probeRateLimit", () => {
  it("all-200, no 429 => throttled:false ('no rate limiting' finding)", async () => {
    const { request } = constantStatus(200);
    const res = await probeRateLimit({ request, burst: 12 });
    expect(res.sent).toBe(12);
    expect(res.statuses).toHaveLength(12);
    expect(res.saw429).toBe(false);
    expect(res.throttled).toBe(false);
    expect(res.note).toMatch(/no rate limiting/);
  });

  it("mirrors the pilot: 20 rapid 404s, no 429, no slowdown => throttled:false", async () => {
    const { request } = constantStatus(404);
    const res = await probeRateLimit({ request, burst: 20 });
    expect(res.sent).toBe(20);
    expect(res.saw429).toBe(false);
    expect(res.throttled).toBe(false);
  });

  it("returns 429 after N requests => throttled:true", async () => {
    let i = 0;
    const res = await probeRateLimit({
      request: async () => {
        // first 5 succeed, then the endpoint starts rejecting with 429
        const status = i++ < 5 ? 200 : 429;
        return { status };
      },
      burst: 15,
    });
    expect(res.saw429).toBe(true);
    expect(res.throttled).toBe(true);
    expect(res.note).toMatch(/429/);
  });

  it("treats a clear mid-burst status change as throttling (no 429 needed)", async () => {
    let i = 0;
    const res = await probeRateLimit({
      request: async () => ({ status: i++ < 3 ? 200 : 503 }),
      burst: 9,
    });
    expect(res.saw429).toBe(false);
    expect(res.throttled).toBe(true);
    expect(res.note).toMatch(/status changed/);
  });

  it("does not treat a single flaky response as throttling", async () => {
    let i = 0;
    const res = await probeRateLimit({
      // one blip at index 4, otherwise stable 200 — must NOT read as throttled
      request: async () => ({ status: i++ === 4 ? 502 : 200 }),
      burst: 10,
    });
    expect(res.throttled).toBe(false);
  });

  it("enforces the hard cap: never issues more than MAX_BURST requests", async () => {
    const { request, calls } = constantStatus(200);
    const res = await probeRateLimit({ request, burst: 10_000 });
    expect(res.sent).toBe(MAX_BURST);
    expect(calls()).toBe(MAX_BURST);
  });

  it("defaults to DEFAULT_BURST when burst is omitted", async () => {
    const { request, calls } = constantStatus(200);
    const res = await probeRateLimit({ request });
    expect(res.sent).toBe(DEFAULT_BURST);
    expect(calls()).toBe(DEFAULT_BURST);
  });
});
