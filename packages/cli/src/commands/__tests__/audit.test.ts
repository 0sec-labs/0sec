import { beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

// `audit.ts` -> `run.ts` -> dynamic `import("@0sec/core")`. We stub
// `runUnified` at the module boundary so the gated-off (npm) path
// doesn't actually try to spin up the unified pipeline. Use
// `vi.hoisted` so the mock function reference exists when vitest hoists
// the `vi.mock` factory above all imports.
const { runUnifiedMock } = vi.hoisted(() => ({
  runUnifiedMock: vi.fn(),
}));
vi.mock("../run.js", () => ({
  runUnified: runUnifiedMock,
}));

// Imported after the mock declaration so the action handler resolves the
// stubbed `runUnified` rather than the real one. (Top-level await is
// allowed in vitest's ESM transform.)
const { registerAuditCommand } = await import("../audit.js");

function buildProgram(): Command {
  const program = new Command();
  // Disable Commander's own exit-on-error so action errors propagate up
  // as exceptions we can assert against.
  program.exitOverride();
  registerAuditCommand(program);
  return program;
}

describe("registerAuditCommand — package ecosystem dispatch", () => {
  beforeEach(() => {
    runUnifiedMock.mockReset();
    runUnifiedMock.mockResolvedValue(undefined);
  });

  it("npm targets dispatch normally without the gate firing", async () => {
    const program = buildProgram();
    await program.parseAsync(
      ["audit", "lodash", "--ecosystem", "npm", "--format", "json"],
      { from: "user" },
    );
    expect(runUnifiedMock).toHaveBeenCalledOnce();
    const opts = runUnifiedMock.mock.calls[0]![0];
    expect(opts.targetType).toBe("npm-package");
  });

  for (const [ecosystem, targetType] of [
    ["pypi", "pypi-package"],
    ["cargo", "cargo-package"],
    ["oci", "oci-image"],
  ] as const) {
    it(`--ecosystem ${ecosystem} dispatches to ${targetType} without an opt-in env var`, async () => {
      const program = buildProgram();
      await program.parseAsync(
        ["audit", "examplepkg", "--ecosystem", ecosystem, "--format", "json"],
        { from: "user" },
      );

      expect(runUnifiedMock).toHaveBeenCalledOnce();
      const opts = runUnifiedMock.mock.calls[0]![0];
      expect(opts.targetType).toBe(targetType);
    });
  }

  it("garbage ecosystem name surfaces the unsupported ecosystem error", async () => {
    const program = buildProgram();
    await expect(
      program.parseAsync(
        ["audit", "x", "--ecosystem", "deb", "--format", "json"],
        { from: "user" },
      ),
    ).rejects.toThrow(/Unsupported ecosystem 'deb'/);
    expect(runUnifiedMock).not.toHaveBeenCalled();
  });
});
