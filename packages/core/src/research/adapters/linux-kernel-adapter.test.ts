import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { researchZeroCapProven, type Finding } from "@pwnkit/shared";
import { runResearch } from "../research-runner.js";
import { LinuxKernelResearchAdapter, type LinuxKernelTarget } from "./linux-kernel-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function setup(): { target: LinuxKernelTarget; artifactRoot: string } {
  const root = mkdtempSync(join(tmpdir(), "pwnkit-linux-adapter-"));
  roots.push(root);
  const kernelTree = join(root, "linux");
  mkdirSync(kernelTree);
  const reproducerPath = join(root, "repro.c");
  writeFileSync(reproducerPath, "int main(void){return 0;}");
  const finding: Finding = {
    id: "kernel-f", templateId: "kernel", title: "Kernel UAF", description: "UAF",
    severity: "high", category: "use-after-free", status: "discovered",
    evidence: { request: "", response: "" }, timestamp: 1,
  };
  return {
    artifactRoot: join(root, "artifacts"),
    target: {
      kind: "linux.kernel-reproducer",
      id: "linux-test",
      location: kernelTree,
      config: { finding, verify: { reproducerPath, boots: 3, minHits: 2, expectedSignature: "KASAN: slab-use-after-free" } },
    },
  };
}

describe("LinuxKernelResearchAdapter", () => {
  it("promotes only a stable repeated kernel signature", async () => {
    const { target, artifactRoot } = setup();
    const verifier = vi.fn(async (opts) => ({
      status: "reproduced" as const,
      signature: "kasan-uaf",
      dmesg_path: opts.dmesgOutPath!,
      build_cache_hit: true,
      bootHits: 2,
      bootTotal: 3,
      nbootStable: true,
      bootStatuses: ["reproduced", "no_signal", "reproduced"] as const,
      bootResults: [
        { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true },
        { status: "no_signal" as const, dmesg_path: opts.dmesgOutPath!, build_cache_hit: true },
        { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true },
      ],
    }));
    const emitted: Finding[] = [];
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, {
      artifactRoot,
      runId: "linux-run",
      emitFinding: async (finding) => { emitted.push(finding); },
    });

    expect(result.findings).toHaveLength(1);
    expect(result.envelopes).toHaveLength(1);
    expect(result.envelopes[0]).toMatchObject({ grade: "reproduced", novelty: { state: "unchecked" } });
    expect(result.envelopes[0]).toMatchObject({
      executionContext: { privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 },
    });
    expect(researchZeroCapProven(result.envelopes[0]!)).toBe(false);
    expect(result.findings[0].finding.researchEvidence).toEqual(result.envelopes);
    expect(emitted[0]?.researchEvidence).toEqual(result.envelopes);
    expect(existsSync(result.envelopePath!)).toBe(true);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "passed")).toBe(true);
    expect(verifier).toHaveBeenCalledWith(expect.objectContaining({ kernelTree: target.location, boots: 3, minHits: 2 }));
  });

  it("keeps an unstable no-signal run inconclusive", async () => {
    const { target, artifactRoot } = setup();
    const verifier = vi.fn(async (opts) => ({
      status: "no_signal" as const,
      dmesg_path: opts.dmesgOutPath!,
      build_cache_hit: false,
      bootHits: 0,
      bootTotal: 3,
      nbootStable: false,
      bootStatuses: ["no_signal", "no_signal"] as const,
      bootResults: [
        { status: "no_signal" as const, dmesg_path: opts.dmesgOutPath!, build_cache_hit: false },
        { status: "no_signal" as const, dmesg_path: opts.dmesgOutPath!, build_cache_hit: false },
      ],
    }));
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-no" });

    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "inconclusive")).toBe(true);
  });

  it("fails discovery closed when the claimed signature is not bound", async () => {
    const { target, artifactRoot } = setup();
    delete target.config.verify.expectedSignature;
    const verifier = vi.fn();
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-no-oracle" });
    expect(result.candidates).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ stage: "discover", status: "failed" }),
    ]));
    expect(verifier).not.toHaveBeenCalled();
  });
});
