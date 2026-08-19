import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveSubsystemScope } from "./unified-pipeline.js";

// Regression: `--subsystem` used to be honored only for the linux-kernel
// profile, so scoping a large monorepo (e.g. dotnet/runtime) under a default
// review was ignored and the oversized-review guard rejected the whole repo.
describe("resolveSubsystemScope", () => {
  let root: string;
  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "subscope-"));
    mkdirSync(join(root, "src/libraries/System.Text.Json"), { recursive: true });
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("narrows to an existing single subsystem for a default review", () => {
    expect(
      resolveSubsystemScope(root, "src/libraries/System.Text.Json", undefined),
    ).toBe(join(root, "src/libraries/System.Text.Json/"));
  });

  it("narrows regardless of a non-kernel profile (e.g. c-library)", () => {
    expect(
      resolveSubsystemScope(root, "src/libraries/System.Text.Json", "c-library"),
    ).toBe(join(root, "src/libraries/System.Text.Json/"));
  });

  it("returns null when the subsystem subtree does not exist", () => {
    expect(resolveSubsystemScope(root, "src/does/not/exist", undefined)).toBeNull();
  });

  it("returns null for kernel profiles (they have dedicated subsystem handling)", () => {
    expect(
      resolveSubsystemScope(root, "src/libraries/System.Text.Json", "linux-kernel"),
    ).toBeNull();
    expect(
      resolveSubsystemScope(root, "src/libraries/System.Text.Json", "xnu-kernel"),
    ).toBeNull();
  });

  it("returns null for multiple subsystems (kept whole-repo)", () => {
    expect(resolveSubsystemScope(root, "a/,b/", undefined)).toBeNull();
  });

  it("returns null when no subsystem is provided", () => {
    expect(resolveSubsystemScope(root, undefined, undefined)).toBeNull();
  });
});
