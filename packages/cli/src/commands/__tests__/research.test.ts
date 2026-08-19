import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const runResearchMock = vi.fn();
class LinuxKernelResearchAdapterMock {}

vi.mock("@0sec/core", () => ({
  LinuxKernelResearchAdapter: LinuxKernelResearchAdapterMock,
  runResearch: runResearchMock,
  postFinding: vi.fn(),
}));

const { registerResearchCommand } = await import("../research.js");

const roots: string[] = [];
let logSpy: { mockRestore(): void };

function fixture(): { kernelTree: string; reproducer: string; finding: string; artifactRoot: string } {
  const root = mkdtempSync(join(tmpdir(), "0sec-research-cli-"));
  roots.push(root);
  const kernelTree = join(root, "linux");
  mkdirSync(kernelTree);
  const reproducer = join(root, "repro.c");
  writeFileSync(reproducer, "int main(void){return 0;}");
  const finding = join(root, "finding.json");
  writeFileSync(finding, JSON.stringify({
    id: "kernel-f", templateId: "kernel", title: "Kernel UAF", description: "UAF",
    severity: "high", category: "use-after-free", status: "discovered",
    evidence: { request: "", response: "" }, timestamp: 1,
  }));
  return { kernelTree, reproducer, finding, artifactRoot: join(root, "artifacts") };
}

async function runCli(args: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerResearchCommand(program);
  await program.parseAsync(["node", "0sec", ...args]);
}

beforeEach(() => {
  runResearchMock.mockReset();
  logSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  logSpy.mockRestore();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("0sec research linux oracle binding", () => {
  it("threads the required literal signature into the N-boot verifier", async () => {
    const files = fixture();
    runResearchMock.mockResolvedValue({ findings: [{ id: "verified" }], candidates: [], evidence: [] });
    await runCli([
      "research", "linux", "--kernel-tree", files.kernelTree, "--reproducer", files.reproducer,
      "--finding", files.finding, "--expected-signature", "KASAN: slab-use-after-free in claimed_fn",
      "--boots", "3", "--min-hits", "2", "--artifact-root", files.artifactRoot,
    ]);
    expect(runResearchMock).toHaveBeenCalledWith(
      expect.any(LinuxKernelResearchAdapterMock),
      expect.objectContaining({ config: expect.objectContaining({ verify: expect.objectContaining({
        expectedSignature: "KASAN: slab-use-after-free in claimed_fn", boots: 3, minHits: 2,
      }) }) }),
      expect.any(Object),
    );
  });

  it("returns a failing command when the expected signature did not reproduce", async () => {
    const files = fixture();
    runResearchMock.mockResolvedValue({ findings: [], candidates: [{ id: "hypothesis" }], evidence: [] });
    await expect(runCli([
      "research", "linux", "--kernel-tree", files.kernelTree, "--reproducer", files.reproducer,
      "--finding", files.finding, "--expected-signature", "claimed signature",
    ])).rejects.toThrow(/did not reproduce the expected signature/);
  });
});
