import type * as Core from "@0sec/core";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CONSOLE_AUTONOMY_MODES,
  resolveConsoleAutonomyMode,
  registerConsoleCommand,
} from "../console.js";

const startup = vi.hoisted(() => ({
  bun: true,
  interactive: true,
  showConsole: vi.fn(),
}));

vi.mock("../../tui/runtime.js", () => ({
  isBunRuntime: () => startup.bun,
  canUseOpenTui: () => startup.interactive,
}));
vi.mock("../../tui/run.js", () => ({
  showOpenTuiConsole: startup.showConsole,
  showOpenTuiResume: vi.fn(),
}));
vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof Core>();
  return { ...actual, connectMcpServers: async () => undefined };
});

describe("console launch authorization", () => {
  let previousExitCode: typeof process.exitCode;

  beforeEach(() => {
    previousExitCode = process.exitCode;
    process.exitCode = undefined;
    startup.bun = true;
    startup.interactive = true;
    startup.showConsole.mockReset();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    process.exitCode = previousExitCode;
    vi.restoreAllMocks();
  });

  async function launch(args: string[] = []) {
    const program = new Command();
    registerConsoleCommand(program);
    await program.parseAsync(["console", ...args], { from: "user" });
  }

  it("opens interactive YOLO without scope so the operator can approve targets", async () => {
    await launch();
    expect(startup.showConsole).toHaveBeenCalledOnce();
    expect(process.exitCode).toBeUndefined();
  });

  it("retains configured-scope requirements for the Node fallback", async () => {
    startup.bun = false;
    await launch();
    expect(process.exitCode).toBe(2);
    expect(startup.showConsole).not.toHaveBeenCalled();
  });

  it("does not treat headless prompts as an interactive approval channel", async () => {
    await launch(["--print", "inspect this target"]);
    expect(process.exitCode).toBe(2);
    expect(startup.showConsole).not.toHaveBeenCalled();
  });
});

describe("resolveConsoleAutonomyMode", () => {
  it("defaults to yolo when no flag is given", () => {
    // The commander option no longer carries a default; the resolver
    // fallback is the shared constant.
    expect(resolveConsoleAutonomyMode({})).toEqual({ ok: true, mode: "yolo" });
    expect(resolveConsoleAutonomyMode({ autonomy: "yolo" })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("accepts every valid --mode value", () => {
    for (const mode of CONSOLE_AUTONOMY_MODES) {
      expect(resolveConsoleAutonomyMode({ mode })).toEqual({ ok: true, mode });
    }
  });

  it("maps --yolo to autonomyMode yolo", () => {
    expect(resolveConsoleAutonomyMode({ yolo: true, autonomy: "recon" })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("rejects an invalid --mode with a message listing the choices", () => {
    const result = resolveConsoleAutonomyMode({ mode: "foo" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Invalid --mode 'foo'");
      expect(result.error).toContain("standard, recon, copilot, yolo");
    }
  });

  it("rejects an invalid --autonomy alias value", () => {
    const result = resolveConsoleAutonomyMode({ autonomy: "bogus" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Invalid --autonomy 'bogus'");
    }
  });

  it("lets --mode win over the --autonomy alias", () => {
    expect(resolveConsoleAutonomyMode({ mode: "recon", autonomy: "copilot" })).toEqual({
      ok: true,
      mode: "recon",
    });
  });

  it("lets --yolo win over the --autonomy alias", () => {
    expect(resolveConsoleAutonomyMode({ yolo: true, autonomy: "copilot" })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("allows the redundant but non-conflicting --mode yolo --yolo", () => {
    expect(resolveConsoleAutonomyMode({ mode: "yolo", yolo: true })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("errors when --mode conflicts with --yolo", () => {
    const result = resolveConsoleAutonomyMode({ mode: "copilot", yolo: true });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Conflicting flags");
    }
  });
});
