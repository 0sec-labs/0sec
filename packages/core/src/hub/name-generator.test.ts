import { describe, expect, it } from "vitest";

import {
  PRIMARY_AGENT_NAME,
  assignAgentName,
  baseAgentName,
  uniquifyAgentName,
} from "./name-generator.js";

describe("baseAgentName", () => {
  it("is a stable AdjectiveNoun for an id", () => {
    const a = baseAgentName("subagent-abc");
    expect(a).toBe(baseAgentName("subagent-abc"));
    expect(a).toMatch(/^[A-Z][a-z]+[A-Z][a-z]+$/);
  });

  it("varies across ids", () => {
    const names = new Set(
      Array.from({ length: 50 }, (_, i) => baseAgentName(`agent-${i}`)),
    );
    // Not necessarily 50 distinct (hash collisions possible), but should be many.
    expect(names.size).toBeGreaterThan(30);
  });

  it("never throws on a degenerate id", () => {
    expect(baseAgentName("")).toMatch(/^[A-Z][a-z]+[A-Z][a-z]+$/);
  });
});

describe("uniquifyAgentName", () => {
  it("returns the name unchanged when free", () => {
    expect(uniquifyAgentName("Explorer", ["Main"])).toBe("Explorer");
  });

  it("suffixes on a case-insensitive collision", () => {
    expect(uniquifyAgentName("Main", ["main"])).toBe("Main-2");
    expect(uniquifyAgentName("Scout", ["Scout", "scout-2"])).toBe("Scout-3");
  });
});

describe("assignAgentName", () => {
  it("never collides with Main", () => {
    // Find an id whose base name would be Main-ish is impossible (Main isn't in
    // the banks), but assigning against a taken set including Main is safe.
    const name = assignAgentName("x", [PRIMARY_AGENT_NAME]);
    expect(name).not.toBe(PRIMARY_AGENT_NAME);
  });

  it("dot-qualifies a child under a non-Main parent", () => {
    const name = assignAgentName("child-1", ["Main"], "Explorer");
    expect(name.startsWith("Explorer.")).toBe(true);
  });

  it("does not dot-qualify direct children of Main", () => {
    const name = assignAgentName("child-1", ["Main"], "Main");
    expect(name.includes(".")).toBe(false);
  });

  it("uniquifies siblings that hash to the same base", () => {
    // Two different ids, force a taken set that already holds the first's name.
    const first = assignAgentName("id-1", ["Main"]);
    const second = assignAgentName("id-1", ["Main", first]); // same id → same base → must suffix
    expect(second).toBe(`${first}-2`);
  });
});
