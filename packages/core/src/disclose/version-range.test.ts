import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@0sec/shared";
import { detectVersionRange, formatVersionRangeLine } from "./version-range.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-vr-0001",
    templateId: "auth-gap-template",
    title: "Shape",
    description: "src/vulnerable.ts:1 — the shape.",
    severity: "high",
    category: "tool-misuse",
    status: "verified",
    evidence: { request: "", response: "", analysis: undefined },
    timestamp: 1712345678,
    ...overrides,
  };
}

/**
 * Build a synthetic repo with three tagged releases:
 *   v1.0 — file doesn't exist yet
 *   v2.0 — file with the vulnerable shape
 *   v3.0 — file with the vulnerable shape (still)
 *   v4.0 — file removed
 * HEAD — file removed (matches v4.0)
 */
function buildFourTagRepo(): string {
  const repoPath = mkdtempSync(join(tmpdir(), "0sec-vr-"));
  execFileSync("git", ["init", "-q"], { cwd: repoPath });
  execFileSync("git", ["config", "user.email", "t@t"], { cwd: repoPath });
  execFileSync("git", ["config", "user.name", "t"], { cwd: repoPath });
  mkdirSync(join(repoPath, "src"), { recursive: true });

  // v1.0 — unrelated commit, no vulnerable file
  writeFileSync(join(repoPath, "README.md"), "hello");
  execFileSync("git", ["add", "."], { cwd: repoPath });
  execFileSync("git", ["commit", "-q", "-m", "v1"], { cwd: repoPath });
  execFileSync("git", ["tag", "v1.0.0"], { cwd: repoPath });

  // v2.0 — introduce the vulnerable file
  writeFileSync(join(repoPath, "src/vulnerable.ts"), "line1\nline2\nline3\n");
  execFileSync("git", ["add", "."], { cwd: repoPath });
  execFileSync("git", ["commit", "-q", "-m", "add shape"], { cwd: repoPath });
  execFileSync("git", ["tag", "v2.0.0"], { cwd: repoPath });

  // v3.0 — unrelated change; still vulnerable
  writeFileSync(join(repoPath, "README.md"), "updated");
  execFileSync("git", ["add", "."], { cwd: repoPath });
  execFileSync("git", ["commit", "-q", "-m", "readme"], { cwd: repoPath });
  execFileSync("git", ["tag", "v3.0.0"], { cwd: repoPath });

  // v4.0 — remove the vulnerable file
  rmSync(join(repoPath, "src/vulnerable.ts"));
  execFileSync("git", ["add", "-A"], { cwd: repoPath });
  execFileSync("git", ["commit", "-q", "-m", "remove shape"], { cwd: repoPath });
  execFileSync("git", ["tag", "v4.0.0"], { cwd: repoPath });

  return repoPath;
}

describe("detectVersionRange", () => {
  let repoPath: string;
  beforeAll(() => {
    repoPath = buildFourTagRepo();
  });
  afterAll(() => {
    if (repoPath) rmSync(repoPath, { recursive: true, force: true });
  });

  it("reports removed-upstream with correct introducedIn and fixedIn", () => {
    const result = detectVersionRange(baseFinding(), { repoPath });
    expect(result.status).toBe("removed-upstream");
    expect(result.affectedTags).toEqual(["v3.0.0", "v2.0.0"]);
    expect(result.introducedIn).toBe("v2.0.0");
    expect(result.fixedIn).toBe("v4.0.0");
    expect(result.presentOnHead).toBe(false);
  });

  it("returns indeterminate when no file:line refs can be extracted", () => {
    const result = detectVersionRange(
      baseFinding({
        description: "No refs.",
        evidence: { request: "", response: "", analysis: undefined },
      }),
      { repoPath },
    );
    expect(result.status).toBe("indeterminate");
    expect(result.affectedTags).toEqual([]);
  });

  it("reports no-tags when the repo has no tags", () => {
    const bare = mkdtempSync(join(tmpdir(), "0sec-vr-bare-"));
    execFileSync("git", ["init", "-q"], { cwd: bare });
    execFileSync("git", ["config", "user.email", "t@t"], { cwd: bare });
    execFileSync("git", ["config", "user.name", "t"], { cwd: bare });
    writeFileSync(join(bare, "x"), "x");
    execFileSync("git", ["add", "."], { cwd: bare });
    execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: bare });
    const result = detectVersionRange(baseFinding(), { repoPath: bare });
    expect(result.status).toBe("no-tags");
    rmSync(bare, { recursive: true, force: true });
  });
});

describe("formatVersionRangeLine", () => {
  it("renders `>= X, < Y` for removed-upstream with both bounds", () => {
    const line = formatVersionRangeLine({
      status: "removed-upstream",
      affectedTags: ["v3.0.0", "v2.0.0"],
      introducedIn: "v2.0.0",
      fixedIn: "v4.0.0",
      presentOnHead: false,
      notes: [],
    });
    expect(line).toContain("`>= v2.0.0`");
    expect(line).toContain("`< v4.0.0`");
    expect(line).toContain("v3.0.0");
  });

  it("renders `>= X, HEAD` for present-on-head", () => {
    const line = formatVersionRangeLine({
      status: "present-on-head",
      affectedTags: ["v4.0.0", "v3.0.0"],
      introducedIn: "v3.0.0",
      presentOnHead: true,
      notes: [],
    });
    expect(line).toContain("`>= v3.0.0`");
    expect(line).toContain("HEAD");
  });

  it("renders an italic note for no-tags / indeterminate", () => {
    expect(formatVersionRangeLine({ status: "no-tags", affectedTags: [], presentOnHead: false, notes: [] })).toMatch(/^_/);
    expect(formatVersionRangeLine({ status: "indeterminate", affectedTags: [], presentOnHead: false, notes: [] })).toMatch(/^_/);
  });
});
