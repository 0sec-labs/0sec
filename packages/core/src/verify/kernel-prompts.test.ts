import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import {
  buildKernelVerifyInitialPrompt,
  buildReachabilityHint,
  buildSyzlangSpecContext,
  type KernelFindingMetadata,
} from "./kernel-prompts.js";
import type { Finding } from "@0sec/shared";
import type { NativeRuntime } from "../runtime/types.js";

// Shared fixture: the same fake kernel tree the reachability ranker tests use.
//   SYSCALL_DEFINE2(vuln_open) -> vuln_dispatch -> vuln_copy_payload [SINK]
const FIXTURE_TREE = resolve(__dirname, "../kernel/__fixtures__/fake-kernel-tree");

function sinkMetadata(): KernelFindingMetadata {
  return {
    subsystem: "drivers/char",
    filePath: "drivers/char/vuln_dev.c",
    fileLine: 20,
    faultingFunction: "vuln_copy_payload",
  };
}

describe("buildReachabilityHint (technique #5 wiring)", () => {
  it("injects the top ranked entry syscall for a reachable sink", async () => {
    const hint = await buildReachabilityHint({
      metadata: sinkMetadata(),
      kernelTree: FIXTURE_TREE,
    });
    expect(hint).toBeDefined();
    expect(hint).toContain("Reachable entry syscalls");
    expect(hint).toContain("vuln_open");
    // It must be framed as a hint, not a soundness claim.
    expect(hint).toMatch(/ranked HINTS/i);
  });

  it("honours topK", async () => {
    const hint = await buildReachabilityHint({
      metadata: sinkMetadata(),
      kernelTree: FIXTURE_TREE,
      topK: 1,
    });
    expect(hint).toBeDefined();
    const bulletCount = (hint!.match(/^ {2}- /gm) ?? []).length;
    expect(bulletCount).toBe(1);
  });

  it("returns undefined when the finding has no file location", async () => {
    const hint = await buildReachabilityHint({
      metadata: { subsystem: "drivers/char" },
      kernelTree: FIXTURE_TREE,
    });
    expect(hint).toBeUndefined();
  });

  it("fails soft (undefined) when the kernel tree does not exist", async () => {
    const hint = await buildReachabilityHint({
      metadata: sinkMetadata(),
      kernelTree: "/tmp/does-not-exist-kvfy",
    });
    expect(hint).toBeUndefined();
  });
});

function fakeFinding(): Finding {
  return {
    id: "abcdef12-0000-0000-0000-000000000000",
    templateId: "kernel-review-test",
    title: "vuln_copy_payload: missing bounds check",
    description: "static-only hypothesis",
    severity: "high",
    category: "out-of-bounds-write",
    status: "discovered",
    evidence: {
      request: "drivers/char/vuln_dev.c:20",
      response: "static-only",
      analysis: "Subsystem: drivers/char\nHypothesis: true",
    },
    confidence: 0.4,
    timestamp: 0,
  };
}

describe("buildKernelVerifyInitialPrompt reachability injection", () => {
  it("embeds the rendered reachability hint when supplied", async () => {
    const hint = await buildReachabilityHint({
      metadata: sinkMetadata(),
      kernelTree: FIXTURE_TREE,
    });
    const prompt = buildKernelVerifyInitialPrompt({
      finding: fakeFinding(),
      metadata: sinkMetadata(),
      subsystemSlice: [],
      attempts: 5,
      wallClockMs: 1_800_000,
      ...(hint ? { reachabilityHint: hint } : {}),
    });
    expect(prompt).toContain("Reachable entry syscalls");
    expect(prompt).toContain("vuln_open");
  });

  it("omits the block entirely when no hint is supplied", () => {
    const prompt = buildKernelVerifyInitialPrompt({
      finding: fakeFinding(),
      metadata: sinkMetadata(),
      subsystemSlice: [],
      attempts: 5,
      wallClockMs: 1_800_000,
    });
    expect(prompt).not.toContain("Reachable entry syscalls");
  });
});

describe("buildSyzlangSpecContext (opt-in)", () => {
  it("renders an inferred-spec block from a valid spec", async () => {
    const llm: NativeRuntime = {
      executeNative: async () => ({
        content: [
          {
            type: "text",
            text: "```\nresource fd_vuln[fd]\nopenat$vuln(fd const[AT_FDCWD], path ptr[in, string]) fd_vuln\n```",
          },
        ],
      }),
    } as unknown as NativeRuntime;

    const block = await buildSyzlangSpecContext({
      metadata: sinkMetadata(),
      subsystemSlice: [{ relativePath: "drivers/char/vuln_dev.c", content: "int x;" }],
      llm,
    });
    expect(block).toBeDefined();
    expect(block).toContain("Inferred syzlang description");
    expect(block).toContain("openat$vuln");
  });

  it("returns undefined for an unknown subsystem / empty slice", async () => {
    const llm = { executeNative: async () => ({ content: [] }) } as unknown as NativeRuntime;
    const block = await buildSyzlangSpecContext({
      metadata: { filePath: "x.c" },
      subsystemSlice: [],
      llm,
    });
    expect(block).toBeUndefined();
  });
});
