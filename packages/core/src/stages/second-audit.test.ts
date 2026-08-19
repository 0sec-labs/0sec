/**
 * Offline unit tests for the second-audit stage. The engine LLM is INJECTED (a
 * fake `SecondAuditModel` returning a canned tool_use block), so these run in
 * plain `vitest run` — no network, no keys. Covers the audit output shape, the
 * deeper-root-cause refinement, the fix-bypass-detection path, and the safe
 * degrade when the model returns nothing usable.
 */

import { describe, it, expect } from "vitest";
import type { Finding } from "@pwnkit/shared";
import type { NativeRuntimeResult, NativeToolDef } from "../runtime/types.js";
import {
  runSecondAudit,
  makeSecondAuditRefiner,
  type SecondAuditModel,
} from "./second-audit.js";

/** A fake model that returns one canned emit_second_audit tool call. */
function fakeModel(input: Record<string, unknown>): SecondAuditModel {
  return async () => ({
    content: [{ type: "tool_use", id: "t1", name: "emit_second_audit", input }],
    stopReason: "tool_use",
    durationMs: 1,
  });
}

/** A fake model that emits plain text and no tool call (the garbled-reply case). */
const noToolModel: SecondAuditModel = async (): Promise<NativeRuntimeResult> => ({
  content: [{ type: "text", text: "I could not decide." }],
  stopReason: "end_turn",
  durationMs: 1,
});

const baseInput = {
  observation: {
    title: "slab-use-after-free READ in tipc_conn_close",
    report: "BUG: KASAN: slab-use-after-free in tipc_conn_close+0x2a/0x120\nRead of size 8 ...",
  },
  source: "void tipc_conn_close(struct tipc_conn *con) { /* ... */ kfree(con); }",
  runtime: "local" as const,
};

describe("runSecondAudit — output shape", () => {
  it("passes system + one tool named emit_second_audit to the model", async () => {
    let seenTools: NativeToolDef[] = [];
    let seenSystem = "";
    const spy: SecondAuditModel = async (system, _messages, tools) => {
      seenSystem = system;
      seenTools = tools;
      return {
        content: [
          { type: "tool_use", id: "t", name: "emit_second_audit", input: { verdict: "first-order", fixIsBypassable: false, confidence: 0.7, rationale: "ok" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      };
    };
    const res = await runSecondAudit(baseInput, spy);
    expect(seenTools).toHaveLength(1);
    expect(seenTools[0].name).toBe("emit_second_audit");
    expect(seenSystem.toLowerCase()).toContain("shallow");
    expect(res.verdict).toBe("first-order");
    expect(res.warnings).toHaveLength(0);
  });

  it("returns a deeper-root-cause candidate with the deepened hint, not the fault site", async () => {
    const model = fakeModel({
      verdict: "deeper-root-cause",
      deeperRootCause: "con refcount dropped on error path in tipc_conn_recv_work; the read site is only a symptom",
      fixIsBypassable: false,
      refinedTargetPath: "net/tipc/topsrv.c:210",
      confidence: 0.82,
      rationale: "The faulting read is downstream of a missed conn_get on the error path.",
    });
    const res = await runSecondAudit(baseInput, model);
    expect(res.verdict).toBe("deeper-root-cause");
    expect(res.deeperRootCause).toContain("refcount");
    expect(res.confidence).toBeCloseTo(0.82);
    expect(res.refinedCandidate).toBeDefined();
    expect(res.refinedCandidate!.path).toBe("net/tipc/topsrv.c:210");
    // The deepened hint chases the root cause AND records the original symptom.
    expect(res.refinedCandidate!.hint).toContain("Deeper root cause");
    expect(res.refinedCandidate!.hint).toContain("slab-use-after-free READ in tipc_conn_close");
  });
});

describe("runSecondAudit — fix-bypass detection", () => {
  const withFix = {
    ...baseInput,
    existingFix: {
      diff: "--- a/net/tipc/topsrv.c\n+++ b/net/tipc/topsrv.c\n@@\n+ if (con->active) conn_get(con);\n",
      reference: "commit deadbeef",
    },
  };

  it("flags a bypassable fix and emits the sibling-path hypothesis + refined candidate", async () => {
    const model = fakeModel({
      verdict: "first-order",
      fixIsBypassable: true,
      fixBypassHypothesis: "the guard only covers con->active; the con->probing path reaches the same free without conn_get",
      refinedTargetPath: "net/tipc/topsrv.c:188",
      confidence: 0.66,
      rationale: "sibling path bypasses the added active-only guard",
    });
    const res = await runSecondAudit(withFix, model);
    expect(res.fixIsBypassable).toBe(true);
    expect(res.fixBypassHypothesis).toContain("con->probing");
    expect(res.refinedCandidate).toBeDefined();
    expect(res.refinedCandidate!.hint).toContain("Fix-bypass hypothesis");
    expect(res.refinedCandidate!.path).toBe("net/tipc/topsrv.c:188");
  });

  it("IGNORES a bypass claim when no fix was supplied to judge", async () => {
    // Same bypassable=true reply, but the input carries no existingFix.
    const model = fakeModel({
      verdict: "first-order",
      fixIsBypassable: true,
      fixBypassHypothesis: "hallucinated bypass",
      confidence: 0.9,
      rationale: "x",
    });
    const res = await runSecondAudit(baseInput, model);
    expect(res.fixIsBypassable).toBe(false);
    expect(res.fixBypassHypothesis).toBe("");
    // first-order + no real bypass => no refined candidate; original stands.
    expect(res.refinedCandidate).toBeUndefined();
  });

  it("clamps confidence into [0,1]", async () => {
    const res = await runSecondAudit(
      withFix,
      fakeModel({ verdict: "first-order", fixIsBypassable: false, confidence: 5, rationale: "x" }),
    );
    expect(res.confidence).toBe(1);
  });
});

describe("runSecondAudit — safe degrade", () => {
  it("returns first-order (never invents a deeper bug) when the model emits no tool call", async () => {
    const res = await runSecondAudit(baseInput, noToolModel);
    expect(res.verdict).toBe("first-order");
    expect(res.refinedCandidate).toBeUndefined();
    expect(res.confidence).toBe(0);
    expect(res.warnings.join(" ")).toContain("did not call emit_second_audit");
  });

  it("returns first-order with a warning when the model throws", async () => {
    const throwing: SecondAuditModel = async () => {
      throw new Error("network down");
    };
    const res = await runSecondAudit(baseInput, throwing);
    expect(res.verdict).toBe("first-order");
    expect(res.warnings.join(" ")).toContain("model call failed");
  });
});

describe("makeSecondAuditRefiner — runHuntScan adapter", () => {
  const finding: Finding = {
    id: "f1",
    templateId: "t",
    title: "OOB read in parse_tlv",
    description: "KASAN OOB read of size 4",
    severity: "high",
    category: "out-of-bounds-read",
    status: "discovered",
    evidence: {} as Finding["evidence"],
  } as Finding;
  const candidate = { path: "drivers/foo/bar.c", hint: "original hint" };

  it("returns the DEEPENED candidate when the audit finds a deeper cause", async () => {
    const refine = makeSecondAuditRefiner({
      runtime: "local",
      loadSource: async () => "int parse_tlv(u8 *p){ return p[len]; }",
      model: fakeModel({
        verdict: "deeper-root-cause",
        deeperRootCause: "len is attacker-controlled and never bounded against buffer size",
        fixIsBypassable: false,
        refinedTargetPath: "drivers/foo/bar.c:42",
        confidence: 0.75,
        rationale: "missing bound on len",
      }),
    });
    const out = await refine(finding, candidate);
    expect(out.path).toBe("drivers/foo/bar.c:42");
    expect(out.hint).toContain("Deeper root cause");
  });

  it("returns the ORIGINAL candidate when the audit confirms first-order", async () => {
    const refine = makeSecondAuditRefiner({
      runtime: "local",
      loadSource: async () => "safe code",
      model: fakeModel({ verdict: "first-order", fixIsBypassable: false, confidence: 0.9, rationale: "genuinely the root" }),
    });
    const out = await refine(finding, candidate);
    expect(out).toEqual(candidate);
  });
});
