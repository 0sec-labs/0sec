import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Integration tests for the kernel review seed wiring added to `sourceReview`:
 *   - Step 2d: the cross-subsystem data-flow block (#469) reaches the agent prompt.
 *   - Step 2e: auto-anchors derived from recent fix commits (#7) populate
 *     `config.anchors`, turning on variant-anchored mode without operator input.
 *
 * We stub the LLM agent (`runAnalysisAgent`) and the DB so the test exercises
 * only the seed/prompt-assembly path — no network, no model call.
 */

// Capture the prompt handed to the analysis agent.
const runAnalysisAgent = vi.fn(async (opts: any) => {
  capturedAgentPrompt = opts.agentSystemPrompt as string;
  capturedCliPrompt = opts.cliPrompt as string;
  return { findings: [], usage: { inputTokens: 0, outputTokens: 0 }, estimatedCostUsd: 0 };
});
let capturedAgentPrompt = "";
let capturedCliPrompt = "";

vi.mock("./agent-runner.js", () => ({ runAnalysisAgent: (o: any) => runAnalysisAgent(o) }));
// No DB in test.
vi.mock("@pwnkit/db", () => ({}));
// Keep the static scanner cheap/deterministic.
vi.mock("./shared-analysis.js", () => ({ runSelectedStaticScan: () => [] }));
// Kernel variant hunting is separately tested. Keep this prompt-wiring suite
// hermetic: it must never resolve or execute a host Foxguard binary.
vi.mock("./kernel/variant-hunt.js", () => ({
  runKernelVariantHunt: async (options: { tree: string }) => ({
    tree: options.tree,
    startedAt: "1970-01-01T00:00:00.000Z",
    completedAt: "1970-01-01T00:00:00.000Z",
    durationMs: 0,
    foxguardFindings: [],
    findings: [],
    warnings: [],
  }),
}));

let sourceReview: typeof import("./review.js").sourceReview;
let tree: string;

beforeEach(async () => {
  ({ sourceReview } = await import("./review.js"));
  // Build a tiny git tree with a crypto/ file and a security fix commit so
  // mineFixCommits (and therefore the auto-anchor step) has something to find.
  tree = mkdtempSync(join(tmpdir(), "pwnkit-kernel-seed-"));
  // Look enough like a kernel tree for any tree-shape heuristics; the recipes
  // don't require it but it keeps the fixture honest.
  writeFileSync(join(tree, "MAINTAINERS"), "Linux kernel\n");
  writeFileSync(join(tree, "Kconfig"), "# kconfig\n");
  mkdirSync(join(tree, "crypto"), { recursive: true });
  const algif = join(tree, "crypto", "algif_aead.c");
  writeFileSync(algif, "int algif_aead_recvmsg(void) { crypto_aead_decrypt(); return 0; }\n");

  const git = (args: string[]) =>
    execFileSync("git", args, { cwd: tree, stdio: "ignore" });
  git(["init", "-q"]);
  git(["config", "user.email", "t@t.t"]);
  git(["config", "user.name", "t"]);
  git(["add", "."]);
  git(["commit", "-q", "-m", "initial"]);
  // A security fix commit so mineFixCommits returns a security-relevant record.
  writeFileSync(algif, "int algif_aead_recvmsg(void) { if (skb_cow_data()) return -1; crypto_aead_decrypt(); return 0; }\n");
  git(["add", "."]);
  git([
    "commit",
    "-q",
    "-m",
    "crypto: algif_aead - fix use-after-free in recvmsg\n\nFixes: 0123456789ab (\"crypto: algif_aead - init\")",
  ]);
});

afterEach(() => {
  vi.clearAllMocks();
  capturedAgentPrompt = "";
  capturedCliPrompt = "";
  if (tree) rmSync(tree, { recursive: true, force: true });
});

describe("sourceReview kernel seeds (#469 cross-subsystem + #7 auto-anchor)", () => {
  it("threads the cross-subsystem data-flow block into the agent prompt", async () => {
    await sourceReview({
      config: { repo: tree, depth: "deep", format: "json", profile: "linux-kernel" } as any,
    });

    expect(runAnalysisAgent).toHaveBeenCalledTimes(1);
    // The dormant cross-subsystem-flow module now has a live consumer.
    expect(capturedAgentPrompt).toContain("Cross-Subsystem Data Flow Tracing Instructions");
    expect(capturedAgentPrompt).toMatch(/Known vulnerable cross-subsystem flow patterns/);
  });

  it("auto-populates config.anchors from recent fix commits (variant-anchored mode on)", async () => {
    const config: any = { repo: tree, depth: "deep", format: "json", profile: "linux-kernel" };
    await sourceReview({ config });

    // The auto-anchor step mutated config.anchors from the security fix commit.
    expect(Array.isArray(config.anchors)).toBe(true);
    expect(config.anchors.length).toBeGreaterThan(0);
    expect(config.anchors[0].pattern).toMatch(/use-after-free|security fix/i);

    // And that anchoring reframed the agent prompt into variant-anchored mode.
    expect(capturedAgentPrompt).toContain("VARIANT-ANCHORED REVIEW");
  });

  it("does not overwrite operator-supplied anchors", async () => {
    const operatorAnchor = { pattern: "operator-named root cause", id: "OP-1" };
    const config: any = {
      repo: tree,
      depth: "deep",
      format: "json",
      profile: "linux-kernel",
      anchors: [operatorAnchor],
    };
    await sourceReview({ config });

    expect(config.anchors).toEqual([operatorAnchor]);
    expect(capturedAgentPrompt).toContain("operator-named root cause");
  });
});
