import { describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { runDifferential } from "./differential-runner.js";
import { checkResearchNovelty } from "./novelty-provider.js";
import { createDefaultResearchRegistry, ResearchAdapterRegistry } from "./adapter-registry.js";

const finding = {
  id: "f", templateId: "t", title: "x", description: "x", severity: "high",
  category: "other", status: "discovered", evidence: { request: "", response: "" }, timestamp: 1,
} as Finding;

describe("research control-plane primitives", () => {
  it("reports a deterministic target-pair divergence", async () => {
    const result = await runDifferential({
      pair: { baseline: { id: "fixed", target: 405 }, candidate: { id: "head", target: 200 } },
      input: "TRACE",
      execute: async (status) => ({ status }),
      compare: (a, b) => ({ status: a.status === b.status ? "same" : "divergent", summary: `${a.status} vs ${b.status}` }),
    });
    expect(result.comparison.status).toBe("divergent");
  });

  it("keeps failed differential execution inconclusive", async () => {
    const result = await runDifferential({
      pair: { baseline: { id: "a", target: true }, candidate: { id: "b", target: false } },
      input: null,
      execute: async (ok) => { if (!ok) throw new Error("boot failed"); return 1; },
      compare: () => ({ status: "divergent", summary: "should not run" }),
    });
    expect(result.comparison.status).toBe("inconclusive");
  });

  it("fails novelty closed when providers check no records", async () => {
    const result = await checkResearchNovelty(finding, {}, [{ id: "git", async check() { return { source: "git", checked: 0, duplicates: [] }; } }]);
    expect(result.receipt.state).toBe("unchecked");
  });

  it("aggregates duplicate receipts across ecosystem providers", async () => {
    const result = await checkResearchNovelty(finding, {}, [
      { id: "git", async check() { return { source: "git", checked: 5, duplicates: ["commit:abc"] }; } },
      { id: "issues", async check() { return { source: "issues", checked: 3, duplicates: [] }; } },
    ]);
    expect(result.receipt).toMatchObject({ state: "duplicate", scanned: 8, refs: ["commit:abc"] });
  });

  it("registers every shipped research adapter in the default registry", () => {
    expect(createDefaultResearchRegistry().kinds()).toEqual([
      "hunt.agentic",
      "linux.kernel-boot-matrix-import",
      "linux.kernel-reproducer",
      "live.agentic-scan",
      "mobile.static-intake",
      "pipeline.unified",
      "protocol.http-conformance",
      "userspace.memsafety",
      "windows.hyperv-prover-import",
      "xnu.iokit-fuzz",
    ]);
  });

  it("refuses duplicate adapter registrations", () => {
    const registry = new ResearchAdapterRegistry().register("x", () => ({ kind: "x" } as never));
    expect(() => registry.register("x", () => ({ kind: "x" } as never))).toThrow(/already registered/);
  });
});
