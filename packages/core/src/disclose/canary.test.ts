import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import type { Finding } from "@0sec/shared";
import { extractFileRefs, verifyAgainstRef, formatPatchStatusSection } from "./canary.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-abcd1234",
    templateId: "auth-gap-template",
    title: "Auth gap on /adapters/install",
    description: "server/src/routes/adapters.ts:221 gates on assertBoard instead of assertInstanceAdmin. See also packages/db/src/schema/plugin_config.ts for the underlying storage.",
    severity: "high",
    category: "tool-misuse",
    status: "verified",
    evidence: {
      request: "POST /api/adapters/install",
      response: "200 OK",
      analysis: "The correct pattern is used at server/src/routes/plugins.ts:1270.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("extractFileRefs", () => {
  it("pulls file:line pairs out of the description and analysis", () => {
    const refs = extractFileRefs(baseFinding());
    const byPath = new Map(refs.map((r) => [r.file, r.line]));
    expect(byPath.get("server/src/routes/adapters.ts")).toBe(221);
    expect(byPath.get("server/src/routes/plugins.ts")).toBe(1270);
    expect(byPath.get("packages/db/src/schema/plugin_config.ts")).toBeUndefined();
  });

  it("captures file-only refs (no line number) too", () => {
    const finding = baseFinding({ description: "See packages/shared/src/types.ts for the AttackCategory enum." });
    const refs = extractFileRefs(finding);
    expect(refs.some((r) => r.file === "packages/shared/src/types.ts" && r.line === undefined)).toBe(true);
  });

  it("ignores http(s) URLs that look like file:line", () => {
    const finding = baseFinding({ description: "See https://example.com/foo.ts:3 for details." });
    const refs = extractFileRefs(finding);
    expect(refs.find((r) => r.file.startsWith("http"))).toBeUndefined();
  });

  it("returns an empty array for a finding with no parseable refs", () => {
    const finding = baseFinding({
      description: "No files cited here.",
      evidence: { request: "", response: "", analysis: "Still nothing." },
    });
    const refs = extractFileRefs(finding);
    expect(refs).toEqual([]);
  });
});

describe("verifyAgainstRef (filesystem)", () => {
  let repoPath: string;

  beforeAll(() => {
    repoPath = mkdtempSync(join(tmpdir(), "0sec-canary-"));
    mkdirSync(join(repoPath, "server/src/routes"), { recursive: true });
    // Large enough that line 221 is valid (so the finding's cited adapters.ts:221
    // still resolves — we're not testing line-out-of-range here).
    const lines = Array.from({ length: 400 }, (_, i) => `line${i + 1}`);
    writeFileSync(join(repoPath, "server/src/routes/adapters.ts"), lines.join("\n") + "\n");
    // Don't create plugins.ts — simulate the cited sibling being patched away.
  });

  afterAll(() => {
    if (repoPath) rmSync(repoPath, { recursive: true, force: true });
  });

  it("returns partial-fix when some refs resolve and others are missing", () => {
    const result = verifyAgainstRef(baseFinding(), { repoPath, ref: "test-ref" });
    expect(result.status).toBe("partial-fix");
    expect(result.refsStillPresent.some((r) => r.file === "server/src/routes/adapters.ts")).toBe(true);
    expect(result.refsMissing.some((r) => r.file === "server/src/routes/plugins.ts")).toBe(true);
    expect(result.ref).toBe("test-ref");
  });

  it("returns still-vulnerable when every cited file exists", () => {
    const result = verifyAgainstRef(
      baseFinding({
        description: "server/src/routes/adapters.ts:2 — still the same.",
        evidence: { request: "", response: "", analysis: undefined },
      }),
      { repoPath, ref: "canary-ref" },
    );
    expect(result.status).toBe("still-vulnerable");
    expect(result.refsMissing).toEqual([]);
  });

  it("flags line-out-of-range refs as missing", () => {
    const result = verifyAgainstRef(
      baseFinding({
        description: "server/src/routes/adapters.ts:9999 — way past EOF.",
        evidence: { request: "", response: "", analysis: undefined },
      }),
      { repoPath },
    );
    expect(result.status).toBe("fixed");
    expect(result.refsMissing.some((r) => r.line === 9999)).toBe(true);
  });

  it("returns unknown when no refs are extractable", () => {
    const result = verifyAgainstRef(
      baseFinding({ description: "No refs.", evidence: { request: "", response: "", analysis: undefined } }),
      { repoPath },
    );
    expect(result.status).toBe("unknown");
    expect(result.notes[0]).toMatch(/could not extract/i);
  });
});

describe("verifyAgainstRef (git-backed)", () => {
  let repoPath: string;

  beforeAll(() => {
    repoPath = mkdtempSync(join(tmpdir(), "0sec-canary-git-"));
    execFileSync("git", ["init", "-q"], { cwd: repoPath });
    execFileSync("git", ["config", "user.email", "test@0sec.test"], { cwd: repoPath });
    execFileSync("git", ["config", "user.name", "0sec-test"], { cwd: repoPath });
    mkdirSync(join(repoPath, "src"), { recursive: true });
    writeFileSync(join(repoPath, "src/vulnerable.ts"), "line1\nline2\nline3\n");
    execFileSync("git", ["add", "."], { cwd: repoPath });
    execFileSync("git", ["commit", "-q", "-m", "initial"], { cwd: repoPath });
    execFileSync("git", ["tag", "v-initial"], { cwd: repoPath });
    // Now "fix" the file on main by removing it.
    rmSync(join(repoPath, "src/vulnerable.ts"));
    execFileSync("git", ["add", "-A"], { cwd: repoPath });
    execFileSync("git", ["commit", "-q", "-m", "remove vulnerable file"], { cwd: repoPath });
    execFileSync("git", ["tag", "v-fixed"], { cwd: repoPath });
  });

  afterAll(() => {
    if (repoPath) rmSync(repoPath, { recursive: true, force: true });
  });

  it("checks out the requested ref and sees still-vulnerable at v-initial", () => {
    const result = verifyAgainstRef(
      baseFinding({ description: "src/vulnerable.ts:1 — here.", evidence: { request: "", response: "", analysis: undefined } }),
      { repoPath, ref: "v-initial", checkout: true },
    );
    expect(result.status).toBe("still-vulnerable");
    expect(result.ref).toBe("v-initial");
  });

  it("reports fixed on v-fixed when the file has been removed", () => {
    const result = verifyAgainstRef(
      baseFinding({ description: "src/vulnerable.ts:1 — here.", evidence: { request: "", response: "", analysis: undefined } }),
      { repoPath, ref: "v-fixed", checkout: true },
    );
    expect(["fixed", "file-removed"]).toContain(result.status);
    expect(result.ref).toBe("v-fixed");
  });
});

describe("formatPatchStatusSection", () => {
  it("includes a banner for each status and lists refs with ✓/✗ markers", () => {
    const section = formatPatchStatusSection({
      status: "partial-fix",
      ref: "canary/v2026.420.0-canary.9",
      notes: ["Some file changed upstream."],
      refsChecked: [
        { file: "a.ts", line: 1 },
        { file: "b.ts" },
      ],
      refsStillPresent: [{ file: "a.ts", line: 1 }],
      refsMissing: [{ file: "b.ts" }],
    });
    expect(section).toContain("Partial fix");
    expect(section).toContain("canary/v2026.420.0-canary.9");
    expect(section).toContain("✓ `a.ts:1`");
    expect(section).toContain("✗ `b.ts`");
    expect(section).toContain("> Some file changed upstream.");
  });
});
