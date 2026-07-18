import { describe, expect, it } from "vitest";

// Pure helper only — no @pwnkit/core load needed (the fuzz loop / prepare paths
// are exercised e2e in the sandbox, not in unit tests; live memcorruption-repro
// validation of the role is tracked in #702).
import { detectMemSafetyBuild } from "../memsafety.js";

/** Build an `exists` probe that returns true only for the given relative paths. */
function existsFor(root: string, present: string[]): (path: string) => boolean {
  const set = new Set(present.map((p) => `${root}/${p}`));
  return (path: string) => set.has(path);
}

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
