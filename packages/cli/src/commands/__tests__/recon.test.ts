import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const runReconMock = vi.fn();

vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@0sec/core")>();
  return {
    ...actual,
    runRecon: runReconMock,
  };
});

const { registerReconCommand } = await import("../recon.js");

function captureIO() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const o = vi.spyOn(console, "log").mockImplementation((...a) => stdout.push(a.map(String).join(" ")));
  const e = vi.spyOn(console, "error").mockImplementation((...a) => stderr.push(a.map(String).join(" ")));
  return { stdout, stderr, restore: () => { o.mockRestore(); e.mockRestore(); } };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerReconCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

const EMPTY_RESULT = { domain: "https://example.com", generatedAt: "t", assets: [], summary: { total: 0, byKind: {} }, warnings: [] };

describe("0sec recon --active", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "recon-test-"));
    runReconMock.mockResolvedValue(EMPTY_RESULT);
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    io.restore();
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses --active without --scope (deny-by-default)", async () => {
    await runCli(["recon", "example.com", "--active"]);
    expect(runReconMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("--active requires --scope");
  });

  it("passes activeSubdomains{enabled,scope} to runRecon when --scope is supplied", async () => {
    const scopePath = join(dir, "scope.json");
    writeFileSync(scopePath, JSON.stringify({ in_scope: ["*.example.com"], out_of_scope: [] }));
    await runCli(["recon", "example.com", "--active", "--scope", scopePath, "--json"]);
    expect(runReconMock).toHaveBeenCalledTimes(1);
    const opts = runReconMock.mock.calls[0][1];
    expect(opts.activeSubdomains.enabled).toBe(true);
    expect(opts.activeSubdomains.scope).toBeDefined();
  });

  it("stays passive (no activeSubdomains) without --active", async () => {
    await runCli(["recon", "example.com", "--json"]);
    expect(runReconMock).toHaveBeenCalledTimes(1);
    expect(runReconMock.mock.calls[0][1].activeSubdomains).toBeUndefined();
  });

  it("fails on an unreadable --scope file", async () => {
    await runCli(["recon", "example.com", "--active", "--scope", join(dir, "missing.json")]);
    expect(runReconMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Failed to load --scope");
  });
});
