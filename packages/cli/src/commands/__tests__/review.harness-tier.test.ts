/**
 * `0sec review --harness-tier` dispatch tests.
 *
 * We stub both `runUnified` (the agent pipeline) and `runHarnessTier2`
 * (the Tier-2 scaffolder) so neither actually runs. The contract under
 * test: --harness-tier 1 keeps the existing review agent path,
 * --harness-tier 2 short-circuits to the Tier-2 scaffolder, and
 * --harness-tier 3 reports cleanly that it isn't wired yet.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const runUnifiedMock = vi.fn<(opts: unknown) => Promise<undefined>>(
  async () => undefined,
);
const runHarnessTier2Mock = vi.fn<(args: unknown) => Promise<undefined>>(
  async () => undefined,
);
const runHarnessTier3Mock = vi.fn<(args: unknown) => Promise<undefined>>(
  async () => undefined,
);

vi.mock("../run.js", () => ({
  runUnified: runUnifiedMock,
}));
vi.mock("../review-harness-tier2.js", () => ({
  runHarnessTier2: runHarnessTier2Mock,
}));
vi.mock("../review-harness-tier3.js", () => ({
  runHarnessTier3: runHarnessTier3Mock,
}));

const { registerReviewCommand } = await import("../review.js");

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerReviewCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec review --harness-tier", () => {
  beforeEach(() => {
    runUnifiedMock.mockClear();
    runUnifiedMock.mockResolvedValue(undefined);
    runHarnessTier2Mock.mockClear();
    runHarnessTier2Mock.mockResolvedValue(undefined);
    runHarnessTier3Mock.mockClear();
    runHarnessTier3Mock.mockResolvedValue(undefined);
    process.exitCode = 0;
  });

  afterEach(() => {
    runUnifiedMock.mockReset();
    runHarnessTier2Mock.mockReset();
    runHarnessTier3Mock.mockReset();
    process.exitCode = 0;
  });

  it("default (no --harness-tier) preserves the existing review path", async () => {
    await runCli(["review", "./somerepo"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runHarnessTier2Mock).not.toHaveBeenCalled();
  });

  it("--harness-tier 1 preserves the existing review path", async () => {
    await runCli(["review", "./somerepo", "--harness-tier", "1"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runHarnessTier2Mock).not.toHaveBeenCalled();
  });

  it("--harness-tier 2 short-circuits to the Tier-2 scaffolder", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--harness-tier",
      "2",
      "--harness-function",
      "foo_decode",
      "--harness-header",
      "foo.h",
      "--harness-build-system",
      "cmake",
      "--harness-sanitizers",
      "asan,ubsan",
      "--harness-out",
      "/tmp/out",
    ]);
    expect(runHarnessTier2Mock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock).not.toHaveBeenCalled();
    const args = runHarnessTier2Mock.mock.calls[0]![0] as {
      repo: string;
      functionName?: string;
      header?: string;
      buildSystem: string;
      sanitizers?: string;
      outputDir?: string;
    };
    expect(args.repo).toBe("./somerepo");
    expect(args.functionName).toBe("foo_decode");
    expect(args.header).toBe("foo.h");
    expect(args.buildSystem).toBe("cmake");
    expect(args.sanitizers).toBe("asan,ubsan");
    expect(args.outputDir).toBe("/tmp/out");
  });

  it("--harness-tier 3 short-circuits to the Tier-3 chain (Tier-2 build → QEMU validate)", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--harness-tier",
      "3",
      "--harness-function",
      "foo_decode",
      "--harness-qemu-kernel",
      "/tmp/bzImage",
      "--harness-qemu-disk",
      "/tmp/rootfs.img",
      "--harness-wall-clock-ms",
      "30000",
    ]);
    expect(runHarnessTier3Mock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock).not.toHaveBeenCalled();
    expect(runHarnessTier2Mock).not.toHaveBeenCalled();
    const args = runHarnessTier3Mock.mock.calls[0]![0] as {
      repo: string;
      functionName?: string;
      qemuKernel?: string;
      qemuDisk?: string;
      wallClockMs?: number;
    };
    expect(args.repo).toBe("./somerepo");
    expect(args.functionName).toBe("foo_decode");
    expect(args.qemuKernel).toBe("/tmp/bzImage");
    expect(args.qemuDisk).toBe("/tmp/rootfs.img");
    expect(args.wallClockMs).toBe(30000);
  });

  it("--harness-tier with an invalid value errors out", async () => {
    await expect(
      runCli(["review", "./somerepo", "--harness-tier", "9"]),
    ).rejects.toThrow(/Invalid --harness-tier/);
    expect(runUnifiedMock).not.toHaveBeenCalled();
    expect(runHarnessTier2Mock).not.toHaveBeenCalled();
  });
});
