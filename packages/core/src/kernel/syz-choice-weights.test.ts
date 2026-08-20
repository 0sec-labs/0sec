import { describe, expect, it } from "vitest";
import { syzChoiceWeightsFromPlan } from "./syz-choice-weights.js";

const baseOpts = { target: "6.12.101" };

describe("syzChoiceWeightsFromPlan", () => {
  it("produces a schema-complete weights file from a valid plan", () => {
    const plan = JSON.stringify({
      weights: { "socket$nl_route": 90, "sendmsg$nl_xfrm": 80, socket: 65, setsockopt: 60, mmap: 40 },
      rationale: "netlink focus",
    });
    const { file, rationale } = syzChoiceWeightsFromPlan(plan, baseOpts);
    expect(file.version).toBe(1);
    expect(file.target.label).toBe("linux/amd64");
    expect(Object.keys(file.weights).sort()).toEqual(["sendmsg$nl_xfrm", "setsockopt", "socket", "socket$nl_route", "mmap"].sort());
    expect([...file.allowed_names].sort()).toEqual(Object.keys(file.weights).sort());
    expect(file.provenance.provider.length).toBeGreaterThan(0);
    expect(file.provenance.plan_hash).toHaveLength(64);
    expect(file.provenance.source_hash).toHaveLength(64);
    expect(rationale).toBe("netlink focus");
  });

  it("drops unknown-shape names and non-positive weights", () => {
    const plan = JSON.stringify({
      weights: {
        "socket$nl_route": 90, "sendmsg$nl_xfrm": 80, socket: 65, setsockopt: 60, mmap: 40,
        "BAD NAME": 10, "io_uring_setup": -5, "nan": Number.NaN, "1bad": 3,
      },
    });
    const { file } = syzChoiceWeightsFromPlan(plan, baseOpts);
    expect(Object.keys(file.weights)).toHaveLength(5);
    expect(file.weights).not.toHaveProperty("io_uring_setup");
    expect(file.weights).not.toHaveProperty("BAD NAME");
  });

  it("clamps weights into [0.1, 100] and caps entry count", () => {
    const weights: Record<string, number> = {};
    for (let i = 0; i < 60; i++) weights[`call${i}`] = i === 0 ? 10_000 : 50;
    const { file } = syzChoiceWeightsFromPlan(JSON.stringify({ weights }), { ...baseOpts, maxEntries: 10 });
    expect(Object.keys(file.weights)).toHaveLength(10);
    expect(Math.max(...Object.values(file.weights))).toBeLessThanOrEqual(100);
  });

  it("rejects plans with too few valid entries", () => {
    const plan = JSON.stringify({ weights: { socket: 50, mmap: 10 } });
    expect(() => syzChoiceWeightsFromPlan(plan, baseOpts)).toThrow(/too few valid entries/);
  });

  it("rejects non-JSON and accepts fence-wrapped JSON", () => {
    expect(() => syzChoiceWeightsFromPlan("not json at all", baseOpts)).toThrow();
    const fenced = "```json\n" + JSON.stringify({ weights: { a: 1, b: 2, c: 3, d: 4 } }) + "\n```";
    const { file } = syzChoiceWeightsFromPlan(fenced, baseOpts);
    expect(Object.keys(file.weights)).toHaveLength(4);
  });
});
