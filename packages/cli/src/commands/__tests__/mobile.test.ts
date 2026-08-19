import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const loadScopeMock = vi.fn();
const runMobileStaticIntakeMock = vi.fn();

vi.mock("@0sec/core", () => ({
  loadScope: loadScopeMock,
  runMobileStaticIntake: runMobileStaticIntakeMock,
}));

const { registerMobileCommand } = await import("../mobile.js");

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerMobileCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec mobile intake", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let previousExitCode: string | number | null | undefined;

  beforeEach(() => {
    previousExitCode = process.exitCode;
    process.exitCode = undefined;
    loadScopeMock.mockReset().mockReturnValue({ tag: "scope" });
    runMobileStaticIntakeMock.mockReset().mockReturnValue({
      target: "/tmp/app",
      platform: "android",
      android: {
        packageName: "ch.sbb.mobile.android.b2c",
        versionName: "1",
        minSdkVersion: undefined,
        targetSdkVersion: undefined,
        permissions: [],
        exportedComponents: [],
        deepLinks: [],
      },
      endpoints: [
        {
          value: "app.sbbmobile.ch",
          kind: "host",
          sources: ["/tmp/app/AndroidManifest.xml"],
          scope: { allowed: true, reason: "in-scope" },
        },
      ],
      warnings: [],
    });
    logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    process.exitCode = previousExitCode;
  });

  it("threads scope and max file size into core and emits JSON", async () => {
    await runCli([
      "mobile",
      "intake",
      "/tmp/app",
      "--scope",
      "/tmp/scope.json",
      "--max-file-bytes",
      "4096",
      "--output",
      "json",
    ]);

    expect(loadScopeMock).toHaveBeenCalledWith("/tmp/scope.json");
    expect(runMobileStaticIntakeMock).toHaveBeenCalledWith("/tmp/app", {
      scope: { tag: "scope" },
      maxFileBytes: 4096,
    });
    expect(JSON.parse(String(logSpy.mock.calls[0]![0])).platform).toBe("android");
    expect(process.exitCode).toBe(0);
  });

  it("rejects invalid output format without running core", async () => {
    await runCli(["mobile", "intake", "/tmp/app", "--output", "sarif"]);

    expect(runMobileStaticIntakeMock).not.toHaveBeenCalled();
    expect(String(errorSpy.mock.calls[0]![0])).toContain("Invalid output format");
    expect(process.exitCode).toBe(1);
  });

  it("rejects missing APKs before unpack", async () => {
    await runCli(["mobile", "unpack", "/tmp/not-present.apk", "--output", "json"]);

    expect(String(errorSpy.mock.calls[0]![0])).toContain("APK not found");
    expect(process.exitCode).toBe(1);
  });

  it("rejects existing unpack output without --force", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-mobile-cli-"));
    const apk = join(root, "app.apk");
    const out = join(root, "out");
    writeFileSync(apk, "not a real apk");
    writeFileSync(out, "occupied");

    await runCli(["mobile", "unpack", apk, "--out", out, "--output", "json"]);

    expect(String(errorSpy.mock.calls[0]![0])).toContain("Output directory already exists");
    expect(process.exitCode).toBe(1);
  });
});
