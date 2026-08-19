/**
 * `0sec review --subsystem` flag tests (0sec#466).
 *
 * Validates that the `--subsystem` flag is threaded through to `runUnified`
 * and that validation logic works correctly.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const runUnifiedMock = vi.fn<(opts: Record<string, unknown>) => Promise<undefined>>(
  async () => undefined,
);

vi.mock("../run.js", () => ({
  runUnified: runUnifiedMock,
}));

const { registerReviewCommand } = await import("../review.js");

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerReviewCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec review --subsystem", () => {
  beforeEach(() => {
    runUnifiedMock.mockClear();
    runUnifiedMock.mockResolvedValue(undefined);
  });

  afterEach(() => {
    runUnifiedMock.mockReset();
  });

  it("threads --subsystem to runUnified", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--profile",
      "linux-kernel",
      "--subsystem",
      "crypto/",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.subsystem).toBe("crypto/");
    expect(opts.reviewProfile).toBe("linux-kernel");
  });

  it("threads comma-separated --subsystem values", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--profile",
      "linux-kernel",
      "--subsystem",
      "crypto/,net/xfrm/",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.subsystem).toBe("crypto/,net/xfrm/");
  });

  it("threads --hypothesis to runUnified", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--profile",
      "linux-kernel",
      "--hypothesis",
      "Look for missing skb_cow_data calls in ESP decrypt",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.hypothesis).toBe(
      "Look for missing skb_cow_data calls in ESP decrypt",
    );
  });

  it("threads both --subsystem and --hypothesis together", async () => {
    await runCli([
      "review",
      "./somerepo",
      "--profile",
      "linux-kernel",
      "--subsystem",
      "crypto/",
      "--hypothesis",
      "Check AEAD decrypt for missing length validation",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.subsystem).toBe("crypto/");
    expect(opts.hypothesis).toBe("Check AEAD decrypt for missing length validation");
    expect(opts.reviewProfile).toBe("linux-kernel");
  });

  it("allows --subsystem without --profile linux-kernel (no validation)", async () => {
    // The flag is accepted without error even with the default profile.
    // The prompt injection simply doesn't apply when profile !== linux-kernel.
    await runCli([
      "review",
      "./somerepo",
      "--subsystem",
      "src/",
    ]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.subsystem).toBe("src/");
  });
});
