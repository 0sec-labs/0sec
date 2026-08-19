import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  detectMemSafetyBuild,
  registerMemsafetyCommand,
  resolveArtifactDir,
} from "../memsafety.js";

const core = vi.hoisted(() => ({
  getCloudSinkConfig: vi.fn(),
  postFinding: vi.fn(),
  prepare: vi.fn(),
  runMemSafetyScan: vi.fn(),
}));
vi.mock("@0sec/core", () => core);

/** Build an `exists` probe that returns true only for the given relative paths. */
function existsFor(root: string, present: string[]): (path: string) => boolean {
  const set = new Set(present.map((p) => `${root}/${p}`));
  return (path: string) => set.has(path);
}

const temporaryDirs: string[] = [];

afterEach(() => {
  for (const dir of temporaryDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
  core.getCloudSinkConfig.mockReset();
  core.postFinding.mockReset();
  core.prepare.mockReset();
  core.runMemSafetyScan.mockReset();
  process.exitCode = undefined;
});

describe("detectMemSafetyBuild", () => {
  const root = "/work/src";

  it("detects a Rust cargo crate from Cargo.toml", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["Cargo.toml"]));
    expect(d).toEqual({ language: "rust", buildSystem: "cargo" });
  });

  it("prefers cargo when both Cargo.toml and a Makefile are present", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["Cargo.toml", "Makefile"]));
    expect(d).toEqual({ language: "rust", buildSystem: "cargo" });
  });

  it("detects a C++ CMake tree from CMakeLists.txt", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["CMakeLists.txt"]));
    expect(d).toEqual({ language: "cpp", buildSystem: "cmake" });
  });

  it("detects a meson tree", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["meson.build"]));
    expect(d).toEqual({ language: "c", buildSystem: "meson" });
  });

  it("detects an autotools tree from configure.ac", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["configure.ac"]));
    expect(d).toEqual({ language: "c", buildSystem: "autotools" });
  });

  it("detects a plain make tree from a Makefile", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["Makefile"]));
    expect(d).toEqual({ language: "c", buildSystem: "make" });
  });

  it("returns null when no recognisable build system is present", () => {
    const d = detectMemSafetyBuild(root, existsFor(root, ["README.md"]));
    expect(d).toBeNull();
  });
});

describe("registerMemsafetyCommand", () => {
  it("accepts a bounded artifact destination without exposing credentials", () => {
    const program = new Command();
    registerMemsafetyCommand(program);
    const command = program.commands.find((entry) => entry.name() === "memsafety");
    expect(command).toBeDefined();
    const flags = command!.options.map((option) => option.flags);
    expect(flags).toContain("--artifact-dir <path>");
    expect(flags).toContain("--artifact-max-bytes <bytes>");
  });

  it("forwards a paired bounded artifact destination to the fuzz stage", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "0sec-memsafety-cli-"));
    temporaryDirs.push(sourceRoot);
    writeFileSync(join(sourceRoot, "Cargo.toml"), "[package]\nname = \"fixture\"\n");
    core.prepare.mockResolvedValue({
      resolvedTarget: sourceRoot,
      cleanup: vi.fn(),
    });
    core.getCloudSinkConfig.mockReturnValue(null);
    core.runMemSafetyScan.mockResolvedValue({
      findings: [],
      details: [],
      loop: { iterations: 1, crashes: [], corpusSize: 0, durationMs: 1 },
      toolingMissing: [],
      warnings: [],
    });
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const program = new Command();
    registerMemsafetyCommand(program);

    await program.parseAsync(
      [
        "memsafety",
        sourceRoot,
        "--artifact-dir",
        "./proof",
        "--artifact-max-bytes",
        "131072",
      ],
      { from: "user" },
    );

    expect(core.runMemSafetyScan).toHaveBeenCalledWith(
      expect.objectContaining({
        fuzz: expect.objectContaining({
          artifactDir: resolve("./proof"),
          artifactMaxBytes: 131072,
        }),
      }),
    );
    expect(stdout).toHaveBeenCalled();
  });
});

describe("resolveArtifactDir", () => {
  it("rejects a symlinked artifact root that resolves into prepared source", () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-memsafety-artifact-"));
    const sourceRoot = join(root, "source");
    const outsideRoot = join(root, "outside");
    const artifactLink = join(outsideRoot, "retained");
    try {
      mkdirSync(sourceRoot);
      mkdirSync(outsideRoot);
      symlinkSync(sourceRoot, artifactLink);

      expect(() => resolveArtifactDir(artifactLink, sourceRoot)).toThrow(
        /outside the prepared source tree/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps an ordinary external artifact root", () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-memsafety-artifact-"));
    const sourceRoot = join(root, "source");
    const artifactRoot = join(root, "artifacts");
    try {
      mkdirSync(sourceRoot);
      expect(resolveArtifactDir(artifactRoot, sourceRoot)).toBe(realpathSync(artifactRoot));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
