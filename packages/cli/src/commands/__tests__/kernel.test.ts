import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { KernelVariantHuntReport } from "@0sec/core";

const runKernelVariantHuntMock = vi.fn<() => Promise<KernelVariantHuntReport>>();
const mineSyzbotQueueMock = vi.fn();

vi.mock("@0sec/core", () => ({
  runKernelVariantHunt: runKernelVariantHuntMock,
  defaultSyzbotFetcher: vi.fn(),
  mineSyzbotQueue: mineSyzbotQueueMock,
  toHuntCandidates: vi.fn(() => [{ path: "net/l2tp", hint: "reproduce" }]),
}));

const { registerKernelCommand, variantReportToScanReport } = await import("../kernel.js");

function makeReport(): KernelVariantHuntReport {
  return {
    tree: "/linux",
    advisory: "dirty-frag.md",
    rules: "/rules/kernel/dirty-frag-class",
    foxguardPath: "/bin/foxguard",
    startedAt: "2026-05-11T00:00:00.000Z",
    completedAt: "2026-05-11T00:00:01.000Z",
    durationMs: 1000,
    foxguardFindings: [
      {
        ruleId: "kernel/dirty-frag-class/skb-inplace-aead-no-cow",
        message: "in-place decrypt without cow",
        file: "net/ipv4/esp4.c",
        startLine: 512,
      },
    ],
    findings: [
      {
        id: "finding-1",
        templateId: "kernel-variant-dirty-frag-skb-inplace-aead-no-cow",
        title: "Linux kernel variant candidate",
        description: "candidate",
        severity: "high",
        category: "information-disclosure",
        status: "discovered",
        evidence: {
          request: "foxguard scan /linux",
          response: "hit",
          analysis: "Variant status: suspect",
        },
        timestamp: 1778457600000,
      },
    ],
    warnings: [],
  };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerKernelCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec kernel variant-hunt", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let previousExitCode: string | number | null | undefined;

  beforeEach(() => {
    previousExitCode = process.exitCode;
    process.exitCode = undefined;
    runKernelVariantHuntMock.mockReset();
    runKernelVariantHuntMock.mockResolvedValue(makeReport());
    mineSyzbotQueueMock.mockReset();
    mineSyzbotQueueMock.mockResolvedValue({ candidates: [], brief: {}, scanned: 19086, warnings: [] });
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    process.exitCode = previousExitCode;
  });

  it("forwards variant-hunt options to core and prints JSON", async () => {
    await runCli([
      "kernel",
      "variant-hunt",
      "--tree",
      "/linux",
      "--advisory",
      "dirty-frag.md",
      "--rules",
      "/rules/kernel/dirty-frag-class",
      "--foxguard",
      "/bin/foxguard",
      "--sarif-input",
      "/tmp/foxguard.sarif",
      "--timeout",
      "1000",
      "--output",
      "json",
    ]);

    expect(runKernelVariantHuntMock).toHaveBeenCalledWith({
      tree: "/linux",
      advisory: "dirty-frag.md",
      rules: "/rules/kernel/dirty-frag-class",
      foxguardPath: "/bin/foxguard",
      sarifPath: "/tmp/foxguard.sarif",
      timeoutMs: 1000,
    });
    expect(JSON.parse(String(logSpy.mock.calls[0]![0])).tree).toBe("/linux");
  });

  it("adapts variant-hunt reports to ScanReport for SARIF output", () => {
    const scanReport = variantReportToScanReport(makeReport());
    expect(scanReport.target).toBe("/linux");
    expect(scanReport.summary.totalAttacks).toBe(1);
    expect(scanReport.summary.totalFindings).toBe(1);
    expect(scanReport.summary.high).toBe(1);
  });

  it("mines syzbot with bounded detail enrichment and emits hunt handoffs", async () => {
    await runCli(["kernel", "syzbot-mine", "--subsystems", "net,xfrm", "--limit", "12", "--details", "4"]);
    expect(mineSyzbotQueueMock).toHaveBeenCalledWith(expect.objectContaining({
      subsystems: ["net", "xfrm"], limit: 12, maxDetailFetches: 4, detailDelayMs: 750,
      fetchRepro: expect.any(Function),
    }));
    expect(JSON.parse(String(logSpy.mock.calls[0]![0]))).toMatchObject({
      scanned: 19086,
      huntCandidates: [{ path: "net/l2tp", hint: "reproduce" }],
    });
  });
});
