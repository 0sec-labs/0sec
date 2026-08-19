import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { VERSION } from "@pwnkit/shared";

const here = dirname(fileURLToPath(import.meta.url));
// packages/core/src/ -> packages/core -> packages -> repo root
const rootPackageJson = resolve(here, "..", "..", "..", "package.json");

describe("VERSION loader (from @pwnkit/shared/constants)", () => {
  // Smoke test for the version loader. After the v0.7.2 fix, VERSION is
  // sourced from the root package.json (either via esbuild's `define` in
  // bundled mode or via a one-time fs read in source/test mode), so this
  // test trivially passes — but it still serves as the canary that the
  // loader logic is wired up correctly. If anyone re-introduces a hardcoded
  // VERSION constant in constants.ts, this test will catch the drift.
  it("equals the root package.json version field", () => {
    const pkg = JSON.parse(readFileSync(rootPackageJson, "utf8"));
    expect(pkg.version).toBe(VERSION);
  });

  it("returns a non-empty semver-shaped string", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
