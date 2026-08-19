import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const prepareKernelVmArtifactsMock = vi.fn();
const verifyStandaloneKernelReproducerMock = vi.fn();

vi.mock("@0sec/core", () => ({
  prepareKernelVmArtifacts: prepareKernelVmArtifactsMock,
  verifyStandaloneKernelReproducer: verifyStandaloneKernelReproducerMock,
  ingestArtifactsFromFile: vi.fn(() => []),
  ingestArtifactsFromDirectory: vi.fn(() => []),
  reviewKernelCrashSubsystems: vi.fn(),
  verifyKernelCrash: vi.fn(),
}));

const { registerIngestCommand } = await import("../ingest.js");

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerIngestCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec ingest standalone kernel reproducers", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let previousExitCode: string | number | null | undefined;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    previousExitCode = process.exitCode;
    process.exitCode = undefined;
    process.env = { ...originalEnv };
    prepareKernelVmArtifactsMock.mockReset();
    verifyStandaloneKernelReproducerMock.mockReset();
    prepareKernelVmArtifactsMock.mockReturnValue({
      kernelImage: "/cache/bzImage",
      diskImage: "/cache/rootfs.img",
      kernelConfig: "/cache/kernel.config",
      cacheKey: "abc",
      cacheDir: "/cache",
      cacheStatus: "hit",
      configProfile: "kasan",
    });
    verifyStandaloneKernelReproducerMock.mockResolvedValue({
      verified: true,
      confidence: 0.8,
      evidence: "standalone reproducer triggered kasan-uaf",
      reason: "",
      reproduced: true,
      crashMatch: false,
      originalCrashType: "unknown",
      reproducedCrashType: "kasan-uaf",
    });
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    process.exitCode = previousExitCode;
    process.env = { ...originalEnv };
  });

  it("runs a standalone C reproducer and prints JSON", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-ingest-repro-"));
    const repro = join(dir, "poc.c");
    writeFileSync(repro, "int main(void) { return 0; }\n");

    await runCli([
      "ingest",
      "--reproducer",
      repro,
      "--kernel-tree",
      dir,
      "--output",
      "json",
    ]);

    expect(prepareKernelVmArtifactsMock).toHaveBeenCalledWith({
      kernelTree: dir,
      configProfile: "kasan",
      cacheDir: undefined,
      force: undefined,
    });
    expect(verifyStandaloneKernelReproducerMock).toHaveBeenCalledWith(
      expect.objectContaining({
        reproducer: "int main(void) { return 0; }\n",
        reproducerLanguage: "c",
      }),
    );
    const payload = JSON.parse(String(logSpy.mock.calls.at(-1)![0]));
    expect(payload.reproducerLanguage).toBe("c");
    expect(payload.verification.verified).toBe(true);
  });

  it("rejects ambiguous direct reproducer inputs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-ingest-repro-"));
    const repro = join(dir, "poc.c");
    writeFileSync(repro, "int main(void) { return 0; }\n");

    await runCli(["ingest", "--reproducer", repro, "--syz", repro]);

    expect(process.exitCode).toBe(1);
    expect(String(errorSpy.mock.calls[0]![0])).toContain("Use only one");
  });

  it("rejects mixing a crash-dump path with a direct reproducer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-ingest-repro-"));
    const repro = join(dir, "poc.c");
    const crashDump = join(dir, "crash.txt");
    writeFileSync(repro, "int main(void) { return 0; }\n");
    writeFileSync(crashDump, "BUG: KASAN: out-of-bounds\n");

    await runCli([
      "ingest",
      crashDump,
      "--reproducer",
      repro,
      "--kernel-tree",
      dir,
    ]);

    expect(process.exitCode).toBe(1);
    expect(String(errorSpy.mock.calls[0]![0])).toContain("Do not pass a crash-report path");
  });

  it("rejects --reproducer without --kernel-tree", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-ingest-repro-"));
    const repro = join(dir, "poc.c");
    writeFileSync(repro, "int main(void) { return 0; }\n");

    await runCli(["ingest", "--reproducer", repro]);

    expect(process.exitCode).toBe(1);
    expect(String(errorSpy.mock.calls[0]![0])).toContain("--kernel-tree");
  });

  it("passes --kernel-config through to prepareKernelVmArtifacts", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-ingest-repro-"));
    const repro = join(dir, "poc.syz");
    writeFileSync(repro, "r0 = openat$sysfs(0)\n");

    await runCli([
      "ingest",
      "--syz",
      repro,
      "--kernel-tree",
      dir,
      "--kernel-config",
      "defconfig+kasan",
      "--output",
      "json",
    ]);

    expect(prepareKernelVmArtifactsMock).toHaveBeenCalledWith({
      kernelTree: dir,
      configProfile: "defconfig+kasan",
      cacheDir: undefined,
      force: undefined,
    });
    expect(verifyStandaloneKernelReproducerMock).toHaveBeenCalledWith(
      expect.objectContaining({ reproducerLanguage: "syz" }),
    );
  });

  it("treats the legacy --config flag as a --kernel-config alias", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-ingest-repro-"));
    const repro = join(dir, "poc.c");
    writeFileSync(repro, "int main(void) { return 0; }\n");

    await runCli([
      "ingest",
      "--reproducer",
      repro,
      "--kernel-tree",
      dir,
      "--config",
      "kasan",
      "--output",
      "json",
    ]);

    expect(prepareKernelVmArtifactsMock).toHaveBeenCalledWith(
      expect.objectContaining({ configProfile: "kasan" }),
    );
  });
});
