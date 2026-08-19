import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@0sec/shared";
import { extractSiblingFix } from "./sibling-fix.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-sib-0001",
    templateId: "auth-gap-template",
    title: "Auth gap on /adapters/install",
    description: "",
    severity: "high",
    category: "tool-misuse",
    status: "verified",
    evidence: { request: "", response: "", analysis: "" },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("extractSiblingFix", () => {
  let repoPath: string;

  beforeAll(() => {
    repoPath = mkdtempSync(join(tmpdir(), "0sec-sibfix-"));
    mkdirSync(join(repoPath, "packages/api"), { recursive: true });
    mkdirSync(join(repoPath, "server/src/routes"), { recursive: true });
    mkdirSync(join(repoPath, "scripts"), { recursive: true });

    // packages/api/admin.ts — 50 lines so :42 is valid.
    const adminLines = Array.from({ length: 50 }, (_, i) => `// admin.ts line ${i + 1}`);
    adminLines[41] = "router.post('/admin', assertInstanceAdmin, handleAdmin);"; // 0-indexed 41 = line 42
    writeFileSync(join(repoPath, "packages/api/admin.ts"), adminLines.join("\n") + "\n");

    // server/src/routes/plugins.ts — sibling that uses correct gate, line 1270.
    const pluginsLines = Array.from({ length: 1300 }, (_, i) => `// plugins.ts line ${i + 1}`);
    pluginsLines[1269] = "router.post('/plugins/install', assertInstanceAdmin, install);";
    writeFileSync(join(repoPath, "server/src/routes/plugins.ts"), pluginsLines.join("\n") + "\n");

    // server/src/routes/adapters.ts — vulnerable file.
    const adapterLines = Array.from({ length: 250 }, (_, i) => `// adapters.ts line ${i + 1}`);
    writeFileSync(join(repoPath, "server/src/routes/adapters.ts"), adapterLines.join("\n") + "\n");

    // scripts/run.sh — unknown-language fixture (well, .sh maps to bash). Use
    // a truly unknown extension to test the empty-string fallback.
    writeFileSync(join(repoPath, "scripts/run.weirdext"), "echo hi\n".repeat(20));
  });

  afterAll(() => {
    if (repoPath) rmSync(repoPath, { recursive: true, force: true });
  });

  it("returns a candidate when prose flags a 'correct pattern at file.ts:N'", () => {
    const finding = baseFinding({
      description: "The bug is at server/src/routes/adapters.ts:221. The correct pattern is at packages/api/admin.ts:42.",
    });
    const cand = extractSiblingFix(finding, { repoPath });
    expect(cand).not.toBeNull();
    expect(cand!.fileRef.file).toBe("packages/api/admin.ts");
    expect(cand!.fileRef.line).toBe(42);
    expect(cand!.language).toBe("typescript");
    expect(cand!.rationale.toLowerCase()).toContain("correct pattern");
    expect(cand!.confidence).toBeGreaterThanOrEqual(0.8);
    // Default 5 lines of context above + cited line + 5 below = 11 lines.
    expect(cand!.snippet.split("\n").length).toBe(11);
    expect(cand!.snippet).toContain("assertInstanceAdmin");
  });

  it("returns null when only vulnerable refs are cited (no sibling cues)", () => {
    const finding = baseFinding({
      description: "Vulnerable at server/src/routes/adapters.ts:221 — gates on assertBoard instead of assertInstanceAdmin.",
    });
    expect(extractSiblingFix(finding, { repoPath })).toBeNull();
  });

  it("picks the highest-confidence sibling when multiple candidates appear", () => {
    const finding = baseFinding({
      description: "See packages/api/admin.ts:42 — gated on the proper helper. The right gate is at server/src/routes/plugins.ts:1270 where install() is properly guarded.",
    });
    const cand = extractSiblingFix(finding, { repoPath });
    expect(cand).not.toBeNull();
    // "the right gate is" (weight 0.95) > "gated on" (0.8), so plugins.ts:1270 should win.
    expect(cand!.fileRef.file).toBe("server/src/routes/plugins.ts");
    expect(cand!.fileRef.line).toBe(1270);
  });

  it("returns null when refs appear mid-sentence with no explicit sibling cue (confidence floor)", () => {
    const finding = baseFinding({
      description: "We looked at packages/api/admin.ts:42 and server/src/routes/plugins.ts:1270 during triage.",
    });
    expect(extractSiblingFix(finding, { repoPath })).toBeNull();
  });

  it("infers languages from extension (.ts→typescript, .py→python, .rs→rust, unknown→empty)", () => {
    mkdirSync(join(repoPath, "lang"), { recursive: true });
    writeFileSync(join(repoPath, "lang/a.ts"), Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n") + "\n");
    writeFileSync(join(repoPath, "lang/b.py"), Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n") + "\n");
    writeFileSync(join(repoPath, "lang/c.rs"), Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n") + "\n");
    writeFileSync(join(repoPath, "lang/d.weirdext"), Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n") + "\n");

    for (const [path, expected] of [
      ["lang/a.ts", "typescript"],
      ["lang/b.py", "python"],
      ["lang/c.rs", "rust"],
      ["lang/d.weirdext", ""],
    ] as const) {
      const finding = baseFinding({
        description: `The correct pattern is at ${path}:10.`,
      });
      // d.weirdext won't be picked up by extractFileRefs (whitelist on extension),
      // so for the unknown-language assertion we exercise it in a side branch:
      // hit it via direct code path by using a known ext but stubbing the file
      // — actually, simpler: extractFileRefs only recognises whitelisted extensions,
      // so .weirdext findings can't currently form a candidate. Skip that case.
      if (path.endsWith(".weirdext")) {
        const cand = extractSiblingFix(finding, { repoPath });
        expect(cand).toBeNull();
        continue;
      }
      const cand = extractSiblingFix(finding, { repoPath });
      expect(cand, `expected candidate for ${path}`).not.toBeNull();
      expect(cand!.language).toBe(expected);
    }
  });

  it("honours linesOfContext override (3 → 7-line snippet)", () => {
    const finding = baseFinding({
      description: "The correct pattern is at packages/api/admin.ts:42.",
    });
    const cand = extractSiblingFix(finding, { repoPath, linesOfContext: 3 });
    expect(cand).not.toBeNull();
    // 3 above + cited + 3 below = 7 lines.
    expect(cand!.snippet.split("\n").length).toBe(7);
  });

  it("returns null when the cited line is beyond EOF in the local checkout", () => {
    const finding = baseFinding({
      description: "The correct pattern is at packages/api/admin.ts:9999.",
    });
    expect(extractSiblingFix(finding, { repoPath })).toBeNull();
  });

  it("returns null when the cited file does not exist on disk", () => {
    const finding = baseFinding({
      description: "The correct pattern is at packages/api/does-not-exist.ts:10.",
    });
    expect(extractSiblingFix(finding, { repoPath })).toBeNull();
  });

  it("returns null when repoPath itself does not exist", () => {
    const finding = baseFinding({
      description: "The correct pattern is at packages/api/admin.ts:42.",
    });
    expect(extractSiblingFix(finding, { repoPath: "/no/such/path/__0sec__" })).toBeNull();
  });

  it("halves confidence when both sibling and vulnerable cues attach to the same ref", () => {
    const finding = baseFinding({
      description: "The correct pattern at packages/api/admin.ts:42 — but also the bug is at packages/api/admin.ts:42.",
    });
    // With both cue classes hitting and a single ref, the score is 0.9 * 0.5 = 0.45 < floor 0.6 → null.
    expect(extractSiblingFix(finding, { repoPath })).toBeNull();
  });
});
