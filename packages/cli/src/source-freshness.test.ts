import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { checkSourceDistFreshness } from "./source-freshness.js";

const OLD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function makeRepo(): { repoRoot: string; bundlePath: string } {
  const repoRoot = mkdtempSync(join(tmpdir(), "pwnkit-freshness-"));
  mkdirSync(join(repoRoot, ".git"));
  mkdirSync(join(repoRoot, "dist"));
  const bundlePath = join(repoRoot, "dist", "pwnkit.js");
  writeFileSync(bundlePath, "#!/usr/bin/env node\n");
  return { repoRoot: realpathSync(repoRoot), bundlePath: realpathSync(bundlePath) };
}

describe("source dist freshness guard", () => {
  it("reports stale root dist bundles in a source checkout", () => {
    const { repoRoot, bundlePath } = makeRepo();
    const result = checkSourceDistFreshness({
      entryPath: bundlePath,
      buildCommit: OLD,
      execGit: (_cwd, args) => {
        if (args.join(" ") === "rev-parse --show-toplevel") return repoRoot;
        if (args.join(" ") === "rev-parse HEAD") return HEAD;
        throw new Error("unexpected git args");
      },
    });

    expect(result.checked).toBe(true);
    expect(result.stale).toBe(true);
    expect(result.message).toContain("dist/pwnkit.js was built from aaaaaaaaaaaa");
    expect(result.message).toContain("checkout HEAD is bbbbbbbbbbbb");
    expect(result.message).toContain("pnpm run build");
  });

  it("accepts matching build and HEAD commits", () => {
    const { repoRoot, bundlePath } = makeRepo();
    const result = checkSourceDistFreshness({
      entryPath: bundlePath,
      buildCommit: HEAD,
      execGit: (_cwd, args) => {
        if (args.join(" ") === "rev-parse --show-toplevel") return repoRoot;
        if (args.join(" ") === "rev-parse HEAD") return HEAD;
        throw new Error("unexpected git args");
      },
    });

    expect(result.checked).toBe(true);
    expect(result.stale).toBe(false);
  });

  it("skips explicit bypasses and non-root dist paths", () => {
    const { bundlePath } = makeRepo();
    const bypassed = checkSourceDistFreshness({
      entryPath: bundlePath,
      buildCommit: OLD,
      env: { PWNKIT_ALLOW_STALE_SOURCE_DIST: "1" },
    });
    expect(bypassed.reason).toBe("bypassed");

    const otherBundlePath = join(dirname(bundlePath), "not-pwnkit.js");
    writeFileSync(otherBundlePath, "#!/usr/bin/env node\n");
    const nonRootDist = checkSourceDistFreshness({
      entryPath: otherBundlePath,
      buildCommit: OLD,
    });
    expect(nonRootDist.reason).toBe("not-root-dist-bundle");
  });

  it("skips when the bundle has no embedded commit", () => {
    const { bundlePath } = makeRepo();
    const result = checkSourceDistFreshness({
      entryPath: bundlePath,
      buildCommit: "",
    });

    expect(result.reason).toBe("missing-build-commit");
    expect(result.stale).toBe(false);
  });
});
