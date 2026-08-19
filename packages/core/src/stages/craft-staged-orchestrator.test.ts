import { describe, expect, it } from "vitest";
import {
  CraftStagedOrchestrator,
  parseCraftStageCitations,
} from "./craft-staged-orchestrator.js";

describe("CraftStagedOrchestrator", () => {
  it("requires an observed reachability citation before enabling trigger design", () => {
    const stages = new CraftStagedOrchestrator({ requiresSelfTest: true });

    expect(stages.advance([], "trigger")).toMatchObject({
      accepted: false,
      from: "reachability",
      to: "reachability",
    });
    stages.observeSource("fuzz/entry.cc", 10, 30);
    expect(stages.advance([{ path: "fuzz/entry.cc", line: 20 }], "trigger")).toMatchObject({
      accepted: true,
      from: "reachability",
      to: "trigger",
    });
    expect(stages.allowsTool("test_poc")).toBe(true);
    expect(stages.allowsTool("submit_poc")).toBe(false);
  });

  it("promotes only a self-tested candidate and returns rejected candidates to trigger design", () => {
    const stages = new CraftStagedOrchestrator({ requiresSelfTest: true });
    stages.observeSource("parser.c", 1, 10);
    stages.advance([{ path: "parser.c", line: 4 }], "trigger");

    expect(stages.candidateValidated()).toMatchObject({
      from: "trigger",
      to: "counterexample",
      accepted: true,
    });
    expect(stages.allowsTool("submit_poc")).toBe(true);
    expect(stages.candidateRejected()).toMatchObject({
      from: "counterexample",
      to: "trigger",
      accepted: true,
    });
  });

  it("allows an explicit review handoff only for submit-only targets", () => {
    const stages = new CraftStagedOrchestrator({ requiresSelfTest: false });
    stages.observeSource("parser.c", 1, 10);
    stages.advance([{ path: "parser.c", line: 4 }], "trigger");

    expect(stages.advance([], "counterexample")).toMatchObject({
      accepted: true,
      from: "trigger",
      to: "counterexample",
    });
  });

  it("drops malformed model-provided citations", () => {
    expect(parseCraftStageCitations([
      { path: "parser.c", line: 8 },
      { path: "", line: 9 },
      { path: "parser.c", line: 0 },
      null,
      "not an object",
    ])).toEqual([{ path: "parser.c", line: 8 }]);
  });
});
