/**
 * Flag-boundary tests for the SOP surfaces: dynamic playbooks and the `plan`
 * tool.
 *
 * These exist because every one of these features is a getter reading an env
 * var at call time (so the CLI `--features` flag, which mutates the env AFTER
 * this module is imported, is honored). That pattern is easy to regress into a
 * const, at which point the flag silently stops working — and a silently
 * ignored feature flag is worse than no flag, because ablation runs would
 * report a difference that was never applied.
 */

import { describe, it, expect, afterEach } from "vitest";
import { features } from "./features.js";
import { detectPlaybooks, buildPlaybookInjection, PLAYBOOKS } from "./playbooks.js";
import { getToolsForRole, TOOL_DEFINITIONS } from "./tools.js";

const TOUCHED_ENV = [
  "PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS",
  "PWNKIT_FEATURE_AGENT_PLAN",
  "PWNKIT_FEATURE_DRIFT_DETECTION",
];

afterEach(() => {
  for (const key of TOUCHED_ENV) delete process.env[key];
});

describe("feature-flag boundaries", () => {
  it("dynamicPlaybooks defaults OFF and honors a late env mutation", () => {
    expect(features.dynamicPlaybooks).toBe(false);
    process.env.PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS = "1";
    expect(features.dynamicPlaybooks).toBe(true);
    process.env.PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS = "0";
    expect(features.dynamicPlaybooks).toBe(false);
  });

  it("agentPlan defaults OFF and can be opted into", () => {
    // Default OFF per the features.ts convention: the plan tool adds a tool to
    // every scan's tool list, a system-prompt block and a per-turn injected
    // block. That changes agent behaviour, so it must be A/B'd before it
    // ships on — and shipping it on would silently invalidate every existing
    // benchmark baseline.
    expect(features.agentPlan).toBe(false);
    process.env.PWNKIT_FEATURE_AGENT_PLAN = "1";
    expect(features.agentPlan).toBe(true);
  });

  it("driftDetection defaults OFF and can be opted into", () => {
    expect(features.driftDetection).toBe(false);
    process.env.PWNKIT_FEATURE_DRIFT_DETECTION = "1";
    expect(features.driftDetection).toBe(true);
  });
});

describe("`plan` tool exposure follows the agentPlan flag", () => {
  it("is offered to the attack role when on and withheld when off", () => {
    process.env.PWNKIT_FEATURE_AGENT_PLAN = "1";
    const on = getToolsForRole("attack").map((t) => t.name);
    expect(on).toContain("plan");

    process.env.PWNKIT_FEATURE_AGENT_PLAN = "0";
    const off = getToolsForRole("attack").map((t) => t.name);
    expect(off).not.toContain("plan");
  });

  it("is kept out of the audit/review everything-set when off", () => {
    // Regression guard matching the use_loot / JIT-skill gating: tools that
    // enumerate Object.keys(TOOL_DEFINITIONS) would otherwise leak `plan` into
    // roles regardless of the flag.
    process.env.PWNKIT_FEATURE_AGENT_PLAN = "0";
    for (const role of ["audit", "review"]) {
      expect(getToolsForRole(role).map((t) => t.name)).not.toContain("plan");
    }
    process.env.PWNKIT_FEATURE_AGENT_PLAN = "1";
    for (const role of ["audit", "review"]) {
      expect(getToolsForRole(role).map((t) => t.name)).toContain("plan");
    }
  });

  it("declares a schema whose required set matches the discriminated union", () => {
    const def = TOOL_DEFINITIONS.plan;
    expect(def).toBeDefined();
    // `action` is the only unconditionally-required field; everything else is
    // conditional on the action and is enforced by Zod, not by the schema.
    expect(def?.required).toEqual(["action"]);
    expect(def?.parameters.action?.enum).toEqual([
      "add",
      "start",
      "complete",
      "drop",
      "note",
      "list",
    ]);
  });
});

describe("playbook injection behavior at the flag boundary", () => {
  /**
   * The flag gates the CALL SITE (native-loop.ts), not these functions — they
   * are pure and always work. What is asserted here is the contract the call
   * site depends on: detection needs >=2 indicator hits, caps at 3 playbooks,
   * and returns empty (so the loop injects nothing) when nothing matches.
   */
  it("returns nothing to inject when tool output matches no indicators", () => {
    const types = detectPlaybooks(["200 OK", "hello world", "<h1>Welcome</h1>"]);
    expect(types).toEqual([]);
    expect(buildPlaybookInjection(types)).toBe("");
  });

  it("requires two indicator hits, not one", () => {
    // A single SQL-flavored string is not enough to commit 500+ tokens of
    // methodology to the context.
    const single = detectPlaybooks(["You have an error in your SQL syntax"]);
    expect(single).not.toContain("sqli");
  });

  it("detects a class from richer evidence and builds an injection for it", () => {
    const types = detectPlaybooks([
      "You have an error in your SQL syntax near '1''",
      "mysql_fetch_array() expects parameter 1",
      "SELECT * FROM users WHERE id=",
    ]);
    expect(types.length).toBeGreaterThan(0);
    const text = buildPlaybookInjection(types);
    expect(text).toContain("Dynamic Playbook Injection");
    expect(text).toContain(PLAYBOOKS[types[0]!]);
  });

  it("caps at three playbooks so the injection stays bounded", () => {
    // Feed evidence for many classes at once; the cap is what keeps the
    // worst-case injection size predictable.
    const kitchenSink = [
      "You have an error in your SQL syntax",
      "mysql_fetch_array() expects parameter 1",
      "<script>alert(1)</script> reflected in response",
      "Content-Type: text/html; charset=utf-8",
      "{{7*7}} rendered as 49",
      "jinja2.exceptions.TemplateSyntaxError",
      "/api/users/1 returned another user's record",
      "id parameter changed to 2 returned 200 OK",
      "failed to open stream: /etc/passwd",
      "include(): Failed opening required",
    ];
    expect(detectPlaybooks(kitchenSink).length).toBeLessThanOrEqual(3);
  });

  it("keeps the worst-case injection inside a predictable context budget", () => {
    // Guards the cost side of the default-ON question: if someone adds a
    // 20k-character playbook, the top-3 injection silently doubles the
    // context cost of every scan that trips it.
    const sizes = Object.values(PLAYBOOKS)
      .map((p) => p.length)
      .sort((a, b) => b - a);
    const worstCaseChars = sizes.slice(0, 3).reduce((a, b) => a + b, 0);
    // ~4 chars/token → ~3.6k tokens today. The assertion is a ratchet, not a
    // measurement: it fails loudly if the worst case grows a lot.
    expect(worstCaseChars).toBeLessThan(20_000);
  });
});
