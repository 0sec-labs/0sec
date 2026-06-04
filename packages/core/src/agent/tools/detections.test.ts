// #774/#775 — detection tools registry + async-driver parity.
//
// The dispatch.test.ts suite already guards definition↔dispatch↔handler
// consistency for every tool. Here we pin (a) the two new tools are in the
// canonical registry, and (b) runStructuralSqliProbeAsync is byte-identical to
// the tested sync runStructuralSqliProbe over the same oracle sequence — so the
// live HTTP tool inherits the sync version's verified decision logic.

import { describe, it, expect } from "vitest";
import { TOOL_DEFINITIONS } from "./index.js";
import {
  runStructuralSqliProbe,
  runStructuralSqliProbeAsync,
  type KeyPayload,
  type ProbeObservation,
} from "../structural-sqli.js";

// An oracle for a genuinely injectable JSON-key surface: a broken (unbalanced)
// key triggers a MySQL parse error; a balanced key parses cleanly.
function injectableOracle(payload: KeyPayload): ProbeObservation {
  return {
    payloadKey: payload.key,
    responseText: payload.balanced
      ? '{"ok":true,"rows":[]}'
      : "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
  };
}

// A non-injectable (parameterised) surface: never errors.
function safeOracle(payload: KeyPayload): ProbeObservation {
  return { payloadKey: payload.key, responseText: '{"ok":true}' };
}

describe("detection tools registry (#774/#775)", () => {
  it("registers structural_sqli_probe and prompt_layer_probe", () => {
    expect(TOOL_DEFINITIONS.structural_sqli_probe).toBeDefined();
    expect(TOOL_DEFINITIONS.structural_sqli_probe.required).toContain("url");
    expect(TOOL_DEFINITIONS.structural_sqli_probe.required).toContain("base_key");
    expect(TOOL_DEFINITIONS.prompt_layer_probe).toBeDefined();
    expect(TOOL_DEFINITIONS.prompt_layer_probe.required).toContain("writable");
  });
});

describe("runStructuralSqliProbeAsync parity with sync", () => {
  it("confirms structural SQLi on an injectable surface, identically to sync", async () => {
    const sync = runStructuralSqliProbe({ baseKey: "sort" }, injectableOracle);
    const async = await runStructuralSqliProbeAsync(
      { baseKey: "sort" },
      async (p) => injectableOracle(p),
    );
    expect(sync.verdict).toBe("confirmed");
    expect(async.verdict).toBe("confirmed");
    expect(async.dialect).toBe(sync.dialect);
    expect(async.dialect).toBe("mysql");
    expect(async.trail.length).toBe(sync.trail.length);
  });

  it("exhausts on a non-injectable surface, identically to sync", async () => {
    const sync = runStructuralSqliProbe({ baseKey: "sort", maxIterations: 4 }, safeOracle);
    const async = await runStructuralSqliProbeAsync(
      { baseKey: "sort", maxIterations: 4 },
      async (p) => safeOracle(p),
    );
    expect(sync.verdict).toBe("exhausted");
    expect(async.verdict).toBe("exhausted");
    expect(async.trail.length).toBe(sync.trail.length);
  });

  it("propagates the iteration cap (bounded loop)", async () => {
    const res = await runStructuralSqliProbeAsync(
      { baseKey: "sort", maxIterations: 3 },
      async (p) => safeOracle(p),
    );
    expect(res.trail.length).toBeLessThanOrEqual(3);
  });
});
