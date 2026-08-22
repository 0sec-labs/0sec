import { describe, expect, it } from "vitest";
import { Command } from "commander";
import {
  registerBinaryCommand,
  resolveBinaryRun,
  buildOverseArgv,
  setupGuidanceLines,
} from "../binary.js";

describe("binary command", () => {
  it("registers with the mode + passthrough surface", () => {
    const program = new Command();
    registerBinaryCommand(program);

    const binaryCommand = program.commands.find((command) => command.name() === "binary");
    expect(binaryCommand).toBeDefined();
    const help = binaryCommand!.helpInformation();
    expect(help).toContain("--mode <mode>");
    expect(help).toContain("--format <format>");
    expect(help).toContain("--backend <backend>");
    expect(help).toContain("--llm <llm>");
    expect(help).toContain("<target>");
  });

  it("fails with guidance and a non-zero code when uv is unavailable", () => {
    const resolution = resolveBinaryRun(
      "./target",
      { mode: "triage" },
      [],
      {
        isUvAvailable: () => false,
        locateOverseDir: () => "/repo/0verse",
      },
    );

    expect(resolution.ok).toBe(false);
    expect(resolution.exitCode).toBeGreaterThan(0);
    const guidance = (resolution.guidance ?? []).join("\n");
    expect(guidance).toContain("uv");
    expect(guidance).toContain("astral.sh/uv/install.sh");
    expect(guidance).toContain("uv sync --frozen");
  });

  it("fails with guidance and a non-zero code when the 0verse dir is missing", () => {
    const resolution = resolveBinaryRun(
      "./target",
      { mode: "triage" },
      [],
      {
        isUvAvailable: () => true,
        locateOverseDir: () => null,
      },
    );

    expect(resolution.ok).toBe(false);
    expect(resolution.exitCode).toBeGreaterThan(0);
    const guidance = (resolution.guidance ?? []).join("\n");
    expect(guidance).toContain("0verse/ engine checkout");
  });

  it("resolves the engine dir and argv when the toolchain is present", () => {
    const resolution = resolveBinaryRun(
      "./target",
      { mode: "scan", format: "ndjson", backend: "rizin" },
      ["--extra"],
      {
        isUvAvailable: () => true,
        locateOverseDir: () => "/repo/0verse",
      },
    );

    expect(resolution.ok).toBe(true);
    expect(resolution.exitCode).toBe(0);
    expect(resolution.overseDir).toBe("/repo/0verse");
    expect(resolution.argv).toEqual([
      "scan",
      "./target",
      "--format",
      "ndjson",
      "--backend",
      "rizin",
      "--extra",
    ]);
  });

  it("rejects an unknown --mode before any subprocess", () => {
    expect(() =>
      resolveBinaryRun("./target", { mode: "bogus" }, [], {
        isUvAvailable: () => true,
        locateOverseDir: () => "/repo/0verse",
      }),
    ).toThrow(/invalid --mode/);
  });

  it("builds argv defaulting to the bare mode + target", () => {
    expect(buildOverseArgv("triage", "./bin", {})).toEqual(["triage", "./bin"]);
    expect(buildOverseArgv("run", "./bin", { llm: "claude" })).toEqual([
      "run",
      "./bin",
      "--llm",
      "claude",
    ]);
  });

  it("names both remediation steps in the setup guidance", () => {
    const lines = setupGuidanceLines({ uvMissing: true, overseDir: null }).join("\n");
    expect(lines).toContain("uv sync --frozen");
    expect(lines).toContain("curl -LsSf https://astral.sh/uv/install.sh | sh");
  });
});
