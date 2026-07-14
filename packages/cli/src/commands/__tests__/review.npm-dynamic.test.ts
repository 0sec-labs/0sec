/**
 * `pwnkit review --npm-dynamic` flag wiring. Mocks `runUnified` so the action
 * never runs; asserts the opt-in dynamic-discovery flag is off by default and
 * forwarded as `npmDynamicDiscovery: true` when set.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const runUnifiedMock = vi.fn<(opts: { npmDynamicDiscovery?: boolean }) => Promise<undefined>>(
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
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

describe("pwnkit review --npm-dynamic", () => {
  beforeEach(() => {
    runUnifiedMock.mockClear();
    runUnifiedMock.mockResolvedValue(undefined);
  });
  afterEach(() => {
    runUnifiedMock.mockReset();
  });

  it("defaults to false (off) — no dynamic sweep unless asked", async () => {
    await runCli(["review", "es-toolkit", "--ecosystem", "npm"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].npmDynamicDiscovery).toBe(false);
  });

  it("forwards --npm-dynamic as npmDynamicDiscovery: true", async () => {
    await runCli(["review", "es-toolkit", "--ecosystem", "npm", "--npm-dynamic"]);
    expect(runUnifiedMock).toHaveBeenCalledTimes(1);
    expect(runUnifiedMock.mock.calls[0]![0].npmDynamicDiscovery).toBe(true);
  });
});
