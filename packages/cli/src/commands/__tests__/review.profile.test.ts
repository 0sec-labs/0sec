/**
 * `0sec review --profile` / `--target` validator tests. We register the command on
 * a fresh Commander program, mock `runUnified` so the action never
 * actually runs, then `parseAsync` argv. We just want to assert that
 * the validator accepts the expected workflow selector values and rejects typos.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const runUnifiedMock = vi.fn<(opts: { reviewProfile?: string }) => Promise<undefined>>(
  async () => undefined,
);

vi.mock("../run.js", () => ({
  runUnified: runUnifiedMock,
}));

// Imported AFTER the mock so the action picks up the mocked runUnified.
const { registerReviewCommand } = await import("../review.js");

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerReviewCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec review --profile validator", () => {
  beforeEach(() => {
    runUnifiedMock.mockClear();
    runUnifiedMock.mockResolvedValue(undefined);
  });

  afterEach(() => {
    runUnifiedMock.mockReset();
  });

  it("accepts --profile default and forwards it to runUnified", async () => {
    await runCli(["review", "./somerepo", "--profile", "default"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("default");
  });

  it("routes --depth deep through the validated lens strategy", async () => {
    await runCli(["review", "./somerepo", "--depth", "deep"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0]).toMatchObject({
      depth: "deep",
      reviewStrategy: "lenses",
    });
  });

  it("accepts --profile c-library and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "c-library"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("c-library");
  });

  it("accepts --target c-library as the issue-facing workflow alias", async () => {
    await runCli(["review", "./somerepo", "--target", "c-library"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("c-library");
  });

  it("accepts --target app as an alias for the default application profile", async () => {
    await runCli(["review", "./somerepo", "--target", "app"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("default");
  });

  it("accepts --profile linux-kernel and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "linux-kernel"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("linux-kernel");
  });

  it("accepts --profile cardano-onchain and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "cardano-onchain"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("cardano-onchain");
  });

  it("accepts --profile solana-onchain and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "solana-onchain"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("solana-onchain");
  });

  it("accepts --profile evm-onchain and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "evm-onchain"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("evm-onchain");
  });

  it("accepts --profile cairo-onchain and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "cairo-onchain"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("cairo-onchain");
  });

  it("accepts --profile move-onchain and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "move-onchain"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("move-onchain");
  });

  it("accepts --profile cardano-haskell and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "cardano-haskell"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("cardano-haskell");
  });

  it("accepts --profile xnu-kernel and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "xnu-kernel"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("xnu-kernel");
  });

  it("accepts --profile xnu-re and forwards it", async () => {
    await runCli(["review", "./somerepo", "--profile", "xnu-re"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].reviewProfile).toBe("xnu-re");
  });

  it("rejects --profile linux-kernel-typo with a clear error", async () => {
    await expect(
      runCli(["review", "./somerepo", "--profile", "linux-kernel-typo"]),
    ).rejects.toThrow(/Invalid review profile/);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("rejects --profile c-libary (typo of c-library) with a clear error", async () => {
    await expect(
      runCli(["review", "./somerepo", "--profile", "c-libary"]),
    ).rejects.toThrow(/Invalid review profile/);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("rejects --target typos with a clear error", async () => {
    await expect(runCli(["review", "./somerepo", "--target", "c-libary"])).rejects.toThrow(
      /Invalid review target/,
    );
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("rejects conflicting explicit --profile and --target values", async () => {
    await expect(
      runCli(["review", "./somerepo", "--profile", "linux-kernel", "--target", "c-library"]),
    ).rejects.toThrow(/Conflicting review profile options/);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("threads --emit pr + --base + --dry-run into runUnified (0sec#377)", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--emit",
      "pr",
      "--base",
      "develop",
      "--dry-run",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    const opts = runUnifiedMock.mock.calls[0]![0] as Record<string, unknown>;
    expect(opts.emit).toBe("pr");
    expect(opts.emitPrBase).toBe("develop");
    expect(opts.emitPrDryRun).toBe(true);
  });

  it("loads valid --prior-findings JSON and forwards it unchanged", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-prior-findings-"));
    const input = join(dir, "prior-findings.json");
    const findings = [
      {
        id: "prior-sqli",
        title: "SQL injection in search",
        category: "sql-injection",
        description: "Unsafe interpolation",
        location: "src/search.ts:42",
      },
    ];
    try {
      writeFileSync(input, JSON.stringify(findings));
      await runCli(["review", "./somerepo", "--prior-findings", input]);
      expect(runUnifiedMock).toHaveBeenCalledOnce();
      const opts = runUnifiedMock.mock.calls[0]![0] as Record<string, unknown>;
      expect(opts.priorFindings).toEqual(findings);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects malformed --prior-findings data before starting a review", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-prior-findings-"));
    const input = join(dir, "prior-findings.json");
    try {
      writeFileSync(input, JSON.stringify([{ title: "missing id and category" }]));
      await expect(
        runCli(["review", "./somerepo", "--prior-findings", input]),
      ).rejects.toThrow(/Invalid --prior-findings/);
      expect(runUnifiedMock).not.toHaveBeenCalled();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects an unknown --emit target with a clear error", async () => {
    await expect(
      runCli(["review", "./somerepo", "--emit", "junk"]),
    ).rejects.toThrow(/Unknown --emit target/);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });

  it("error message lists all supported profiles", async () => {
    let caught: Error | undefined;
    try {
      await runCli(["review", "./somerepo", "--profile", "nope"]);
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeDefined();
    expect(caught?.message).toMatch(/default/);
    expect(caught?.message).toMatch(/c-library/);
    expect(caught?.message).toMatch(/linux-kernel/);
  });
});
