/**
 * Tests for task-drift detection.
 *
 * The two tests that matter are the pair at the top: a genuinely drifting
 * trajectory must fire, and a focused one must NOT. Everything after them
 * pins the specific mechanisms that buy down the false-positive rate
 * (streak requirement, progress-tool reset, ambient subtraction, thin-anchor
 * inertness, warning cap), because those are the parts a future change is
 * most likely to break without noticing.
 *
 * Trajectories are written as literal tool-call sequences rather than
 * generated, so it is possible to read a test and judge for yourself whether
 * the trajectory really is drifting — which is the only honest way to assert
 * anything about a heuristic like this.
 */

import { describe, it, expect } from "vitest";
import { DriftMonitor, contentTerms } from "./drift.js";
import { TaskLedger } from "./task-ledger.js";

const OBJECTIVE =
  "You are an attack agent. Assess the shop application for injection and access-control flaws in its checkout and order endpoints.";
const TARGET = "http://shop.internal.example.com:8080";

function monitor(overrides: Partial<ConstructorParameters<typeof DriftMonitor>[0]> = {}) {
  return new DriftMonitor({ objective: OBJECTIVE, target: TARGET, ...overrides });
}

/** Shorthand for a tool call. */
function call(name: string, args: unknown): { name: string; arguments: unknown } {
  return { name, arguments: args };
}

describe("drift fires on a genuinely drifting trajectory", () => {
  it("fires after a sustained run of turns unrelated to the plan or objective", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    plan.add("Probe order lookup for broken access control", undefined, 1);
    plan.start("task-1", 1);
    const planText = plan.openText();

    const m = monitor();

    // Turn 1: on-task — the agent is probing checkout, which is in the plan.
    m.record([call("http_request", { url: `${TARGET}/checkout?id=1'` })], planText);
    expect(m.detect()).toBeNull();

    // Turns 2-5: the agent wanders off into unrelated infrastructure poking.
    // None of this touches checkout, orders, injection, or access control.
    m.record([call("bash", { command: "nslookup mail.example.org" })], planText);
    expect(m.detect()).toBeNull();
    m.record([call("bash", { command: "whois example.org" })], planText);
    expect(m.detect()).toBeNull();
    m.record([call("http_request", { url: "https://cdn.jsdelivr.example/lib.js" })], planText);
    expect(m.detect()).toBeNull(); // streak 3 — still under threshold

    m.record([call("bash", { command: "cat /proc/cpuinfo" })], planText);
    const warning = m.detect();

    expect(warning).not.toBeNull();
    expect(warning).toContain("drift check");
    expect(warning).toContain("checkout"); // the message restates the open plan
    expect(m.state.streak).toBe(4);
    expect(m.state.warningsIssued).toBe(1);
  });

  it("fires against the objective alone when no plan has been recorded", () => {
    const m = monitor();
    for (let i = 0; i < 4; i++) {
      m.record([call("bash", { command: `nslookup host${i}.unrelated.org` })], "");
    }
    // The objective supplies enough anchor terms (shop, application, injection,
    // access, control, checkout, order, endpoints) to judge against.
    expect(m.detect()).not.toBeNull();
  });
});

describe("drift does NOT fire on a focused trajectory", () => {
  it("stays silent across a long run that keeps contacting the plan", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    plan.start("task-1", 1);
    const planText = plan.openText();

    const m = monitor();
    const focused = [
      call("http_request", { url: `${TARGET}/checkout?id=1'` }),
      call("http_request", { url: `${TARGET}/checkout?id=1 OR 1=1` }),
      call("bash", { command: `curl -s '${TARGET}/checkout?id=1 UNION SELECT null'` }),
      call("http_request", { url: `${TARGET}/checkout?id=1 AND SLEEP(5)` }),
      call("bash", { command: "python3 blind_injection_timing.py --param id" }),
      call("http_request", { url: `${TARGET}/checkout?id=2` }),
      call("bash", { command: `sqlmap-style manual probe against checkout` }),
      call("http_request", { url: `${TARGET}/checkout?id=3'--` }),
    ];
    for (const c of focused) {
      m.record([c], planText);
      expect(m.detect()).toBeNull();
    }
    expect(m.state.streak).toBe(0);
    expect(m.state.warningsIssued).toBe(0);
  });

  it("does not fire on a short exploratory detour", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor();
    m.record([call("http_request", { url: `${TARGET}/checkout?id=1` })], planText);
    // Three off-plan turns — genuine exploration, below the streak threshold.
    m.record([call("bash", { command: "nslookup mail.example.org" })], planText);
    m.record([call("bash", { command: "whois example.org" })], planText);
    m.record([call("http_request", { url: "https://cdn.example/lib.js" })], planText);
    expect(m.detect()).toBeNull();
    expect(m.state.streak).toBe(3);

    // Back on task — the streak resets and the detour cost nothing.
    m.record([call("http_request", { url: `${TARGET}/checkout?id=2'` })], planText);
    expect(m.detect()).toBeNull();
    expect(m.state.streak).toBe(0);
  });

  it("does not fire when the agent is recording progress, whatever the vocabulary", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor();
    // Off-plan vocabulary throughout, but the agent keeps saving findings —
    // direct evidence it is engaged, so the lexical signal is overridden.
    for (let i = 0; i < 6; i++) {
      m.record(
        [
          call("bash", { command: `probe unrelated-service-${i}` }),
          call("save_finding", { title: `something at unrelated-service-${i}` }),
        ],
        planText,
      );
      expect(m.detect()).toBeNull();
    }
    expect(m.state.streak).toBe(0);
  });

  it("stays inert when the anchor set is too thin to judge against", () => {
    // A generic objective and no plan: nothing to drift FROM.
    const m = new DriftMonitor({ objective: "Find bugs.", target: TARGET });
    for (let i = 0; i < 10; i++) {
      m.record([call("bash", { command: `some command ${i}` })], "");
    }
    expect(m.detect()).toBeNull();
    expect(m.state.anchorSize).toBeLessThan(3);
  });
});

describe("ambient subtraction — the target must not anchor", () => {
  /**
   * The failure this guards against is a false NEGATIVE, and it is the single
   * easiest way to make the whole detector useless: `config.target` appears in
   * essentially every tool call, so leaving its tokens in the anchor set would
   * mean contact is always true and drift never fires. Here the agent is doing
   * something completely off-plan but still against the target host.
   */
  it("still detects drift when off-plan activity hits the target host", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor();
    for (let i = 0; i < 4; i++) {
      m.record([call("http_request", { url: `${TARGET}/static/img/logo${i}.png` })], planText);
    }
    expect(m.detect()).not.toBeNull();
  });

  it("excludes target tokens from the anchor even when the objective repeats them", () => {
    const terms = contentTerms(TARGET);
    expect(terms.has("shop")).toBe(true);
    expect(terms.has("internal")).toBe(true);
    // `http`, `com` and the port number are noise/numeric and never terms.
    expect(terms.has("http")).toBe(false);
    expect(terms.has("com")).toBe(false);
    expect(terms.has("8080")).toBe(false);
  });
});

describe("neutral and empty turns", () => {
  it("treats a bookkeeping-only turn as neither drift nor focus", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor();
    m.record([call("bash", { command: "nslookup unrelated.org" })], planText);
    expect(m.state.streak).toBe(1);
    // query_findings / use_loot say nothing about focus either way.
    m.record([call("query_findings", { limit: 20 })], planText);
    m.record([call("use_loot", { kind: "credential" })], planText);
    expect(m.state.streak).toBe(1);
  });

  it("ignores a turn with no tool calls", () => {
    const m = monitor();
    m.record([], "");
    m.record([], "");
    expect(m.state.streak).toBe(0);
  });
});

describe("re-arming and the warning cap", () => {
  it("warns once per episode, not once per turn", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor();
    for (let i = 0; i < 4; i++) {
      m.record([call("bash", { command: `nslookup host${i}.unrelated.org` })], planText);
    }
    expect(m.detect()).not.toBeNull();
    // Still drifting, but the episode has already been reported.
    for (let i = 0; i < 5; i++) {
      m.record([call("bash", { command: `whois host${i}.unrelated.org` })], planText);
      expect(m.detect()).toBeNull();
    }
    expect(m.state.warningsIssued).toBe(1);
  });

  it("re-arms after the agent returns to the plan", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor();
    for (let i = 0; i < 4; i++) {
      m.record([call("bash", { command: `nslookup host${i}.unrelated.org` })], planText);
    }
    expect(m.detect()).not.toBeNull();

    // Back on task — the latch clears.
    m.record([call("http_request", { url: `${TARGET}/checkout?id=1'` })], planText);
    expect(m.state.streak).toBe(0);

    // A second, distinct drift episode gets its own warning.
    for (let i = 0; i < 4; i++) {
      m.record([call("bash", { command: `traceroute node${i}.elsewhere.org` })], planText);
    }
    expect(m.detect()).not.toBeNull();
    expect(m.state.warningsIssued).toBe(2);
  });

  it("never exceeds maxWarnings, so it cannot become a nag", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor({ maxWarnings: 2 });
    for (let episode = 0; episode < 5; episode++) {
      for (let i = 0; i < 4; i++) {
        m.record([call("bash", { command: `probe-${episode}-${i} elsewhere.org` })], planText);
      }
      m.detect();
      m.record([call("http_request", { url: `${TARGET}/checkout?id=1'` })], planText);
    }
    expect(m.state.warningsIssued).toBe(2);
  });
});

describe("completing tasks changes what counts as drift", () => {
  /**
   * Directly tests the coupling between the two modules: a completed task must
   * stop anchoring, otherwise finished work suppresses drift for the rest of
   * the run. Same trajectory, different plan state, opposite verdicts.
   *
   * The objective used here deliberately does NOT name the checkout endpoint,
   * so the plan is the only anchor and completing a task can actually change
   * the verdict. With the module-level OBJECTIVE (which does say "checkout")
   * this trajectory correctly never drifts, because the objective anchor is
   * permanent and outranks the plan — an accurate and useful property, just not
   * the one under test here.
   */
  it("work on a COMPLETED task no longer counts as contact", () => {
    const planOnlyObjective =
      "You are an attack agent. Work through the tasks you have recorded on your plan.";
    const plan = new TaskLedger();
    plan.add("Test checkout parameters for SQL injection", undefined, 1);
    plan.add("Review the newsletter signup form", undefined, 1);

    const stillOpen = new DriftMonitor({ objective: planOnlyObjective, target: TARGET });
    for (let i = 0; i < 4; i++) {
      stillOpen.record(
        [call("http_request", { url: `${TARGET}/checkout?id=${i}'` })],
        plan.openText(),
      );
    }
    expect(stillOpen.detect()).toBeNull(); // checkout is open — on task

    plan.complete("task-1", undefined, 5);
    const afterComplete = new DriftMonitor({ objective: planOnlyObjective, target: TARGET });
    for (let i = 0; i < 4; i++) {
      afterComplete.record(
        [call("http_request", { url: `${TARGET}/checkout?id=${i}'` })],
        plan.openText(),
      );
    }
    // The only open task is now the newsletter form; continuing to grind on
    // checkout is drift, and the detector says so.
    expect(afterComplete.detect()).not.toBeNull();
  });

  /**
   * The complement, stated as its own test because it is a real and
   * intentional limitation rather than an oversight: a term that appears in the
   * OBJECTIVE anchors for the whole run and no amount of plan bookkeeping can
   * retire it. That is why the objective anchor is deliberately built from a
   * bounded prefix of the system prompt in native-loop.ts — the wider the
   * objective, the less this detector can ever see.
   */
  it("objective terms keep anchoring even after every plan task is closed", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout parameters for SQL injection", undefined, 1);
    plan.complete("task-1", undefined, 2);

    const m = monitor(); // module OBJECTIVE names checkout
    for (let i = 0; i < 6; i++) {
      m.record([call("http_request", { url: `${TARGET}/checkout?id=${i}'` })], plan.openText());
    }
    expect(m.detect()).toBeNull();
  });
});

describe("the source-navigation false-positive case", () => {
  /**
   * The specific FP mode worth pinning: an agent reading unfamiliar code in
   * order to REACH the objective. Both halves are asserted because the honest
   * position is that one of them is a real, accepted false positive rather
   * than a solved problem.
   */
  it("tolerates an orientation pass that reaches an anchored file in time", () => {
    const plan = new TaskLedger();
    plan.add("Audit the payment processor for injection flaws", undefined, 1);
    const planText = plan.openText();

    const m = monitor({ streakThreshold: 4 });
    // Three turns of unfamiliar-tree navigation — no anchor contact at all.
    m.record([call("list_dir", { path: "src/internal/bootstrap" })], planText);
    m.record([call("read_file", { path: "src/internal/bootstrap/registry.ts" })], planText);
    m.record([call("grep", { pattern: "registerHandler", path: "src" })], planText);
    expect(m.detect()).toBeNull();
    expect(m.state.streak).toBe(3);

    // The fourth turn opens a file belonging to the subsystem the plan names,
    // which is the normal shape of orientation reading: it converges.
    m.record([call("read_file", { path: "src/payment/processor.ts" })], planText);
    expect(m.detect()).toBeNull();
    expect(m.state.streak).toBe(0);
  });

  it("DOES fire on a long orientation pass that never reaches the objective (accepted FP)", () => {
    const plan = new TaskLedger();
    plan.add("Audit the payment processor for injection flaws", undefined, 1);
    const planText = plan.openText();

    const m = monitor({ streakThreshold: 4 });
    for (const path of [
      "src/internal/bootstrap/registry.ts",
      "src/internal/telemetry/exporter.ts",
      "src/internal/config/loader.ts",
      "src/internal/logging/format.ts",
    ]) {
      m.record([call("read_file", { path })], planText);
    }
    // Documented behavior, not an accident: four consecutive turns of source
    // navigation with zero anchor contact trips the detector even though the
    // agent may still be orienting. The intervention is advisory, so the cost
    // is one message telling it to record what it is doing on the plan.
    expect(m.detect()).not.toBeNull();
  });
});

describe("robustness", () => {
  it("does not throw on unstringifiable tool arguments", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const m = monitor();
    expect(() => m.record([call("bash", circular)], "")).not.toThrow();
  });

  it("honors a custom streak threshold", () => {
    const plan = new TaskLedger();
    plan.add("Test checkout endpoint for SQL injection", undefined, 1);
    const planText = plan.openText();

    const m = monitor({ streakThreshold: 2 });
    m.record([call("bash", { command: "nslookup a.unrelated.org" })], planText);
    expect(m.detect()).toBeNull();
    m.record([call("bash", { command: "nslookup b.unrelated.org" })], planText);
    expect(m.detect()).not.toBeNull();
  });
});
