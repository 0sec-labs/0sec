/**
 * `generateVariantCandidates` candidate-selection: the kernelCTF-reachability
 * gate must apply BEFORE the `maxCandidates` cap (opt-in via
 * `reachableOnly`/`reachablePrefer`; default OFF -> today's density-only
 * ranking byte-identical, see the backward-compat test below).
 *
 * Mock-at-module-boundary for `node:child_process` (controls grep results
 * without needing a real source tree) and `../runtime/llm-api.js` (no real
 * LLM call) — mirrors `hunt-scan.test.ts`'s strategy.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const execFileSyncMock = vi.fn();
vi.mock("node:child_process", () => ({
  execFileSync: (...args: unknown[]) => execFileSyncMock(...args),
}));

const executeNativeMock = vi.fn();
vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative(...args: unknown[]) {
      return executeNativeMock(...args);
    }
  },
}));

const { generateVariantCandidates } = await import("./variant-candidates.js");

/** Two grep patterns: P1 matches both files, P2 matches only the infiniband
 *  one — so density-only ranking (today's default) ranks the UNREACHABLE
 *  file (2 hits) above the REACHABLE one (1 hit), reproducing the exact
 *  problem this gate fixes. */
function mockGrepAndLlm(): void {
  execFileSyncMock.mockReset().mockImplementation((cmd: string, args: string[]) => {
    if (cmd !== "grep") throw new Error(`unexpected exec: ${cmd}`);
    const pattern = args[args.length - 2];
    const filesByPattern: Record<string, string[]> = {
      P1: ["drivers/infiniband/core/verbs.c", "crypto/algif_aead.c"],
      P2: ["drivers/infiniband/core/verbs.c"],
    };
    return (filesByPattern[pattern] ?? []).join("\n");
  });
  executeNativeMock.mockReset().mockResolvedValue({
    content: [
      {
        type: "tool_use",
        name: "emit_variant_plan",
        input: { bugClass: "test bug class", pattern: "test pattern", grepPatterns: ["P1", "P2"] },
      },
    ],
  });
}

beforeEach(() => {
  mockGrepAndLlm();
});

describe("generateVariantCandidates — kernelCTF-reachability gate", () => {
  it("default (both flags unset) reproduces today's density-only ranking byte-identically", async () => {
    const plan = await generateVariantCandidates({
      sourceRoot: "/src",
      fix: { diff: "+++ b/other.c\n" },
      runtime: "api",
      maxCandidates: 1,
    });

    // Density-only: the infiniband file has 2 pattern hits vs crypto's 1, so
    // it wins the cap even though it's unreachable on kernelCTF — this is the
    // exact problem the gate exists to fix, reproduced here to prove the
    // default leaves it unchanged.
    expect(plan.candidates.map((c) => c.path)).toEqual(["drivers/infiniband/core/verbs.c"]);
    expect(plan.warnings.some((w) => w.includes("unreachable"))).toBe(false);
  });

  it("reachablePrefer reorders so the reachable candidate survives the cap", async () => {
    const plan = await generateVariantCandidates({
      sourceRoot: "/src",
      fix: { diff: "+++ b/other.c\n" },
      runtime: "api",
      maxCandidates: 1,
      reachablePrefer: true,
    });

    expect(plan.candidates.map((c) => c.path)).toEqual(["crypto/algif_aead.c"]);
    expect(plan.warnings.some((w) => w.includes("deprioritized 1 unreachable candidate"))).toBe(true);
  });

  it("reachableOnly drops the unreachable candidate entirely, even with room under the cap", async () => {
    const plan = await generateVariantCandidates({
      sourceRoot: "/src",
      fix: { diff: "+++ b/other.c\n" },
      runtime: "api",
      maxCandidates: 40, // no room pressure — the unreachable file is dropped, not just outranked
      reachableOnly: true,
    });

    expect(plan.candidates.map((c) => c.path)).toEqual(["crypto/algif_aead.c"]);
    expect(plan.warnings.some((w) => w.includes("dropped 1 unreachable candidate"))).toBe(true);
  });
});
