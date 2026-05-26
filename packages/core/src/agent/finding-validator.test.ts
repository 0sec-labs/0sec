import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";

import {
  pathEscapeReason,
  validateFindingDraft,
  type FindingDraft,
} from "./finding-validator.js";
import { ToolExecutor } from "./tools.js";
import type { ToolContext } from "./types.js";

// ────────────────────────────────────────────────────────────────────
// Standalone validator
// ────────────────────────────────────────────────────────────────────

describe("validateFindingDraft", () => {
  let workspace: string;
  let outside: string;

  beforeEach(() => {
    workspace = mkdtempSync(join(tmpdir(), "pwnkit-validator-ws-"));
    outside = mkdtempSync(join(tmpdir(), "pwnkit-validator-outside-"));
    // Seed an in-workspace file so realpath() resolves cleanly.
    writeFileSync(join(workspace, "evidence.txt"), "ok");
    mkdirSync(join(workspace, "sub"));
    writeFileSync(join(workspace, "sub", "blob.json"), "{}");
  });

  afterEach(() => {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });

  // ── Happy path ──

  it("returns ok:true for a fully-valid draft", () => {
    const draft: FindingDraft = {
      cve: "CVE-2024-1086",
      cwe: "CWE-416",
      cvss: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      cvssScore: 7.8,
      evidence: [
        { path: "evidence.txt" },
        { path: "sub/blob.json" },
      ],
    };
    const result = validateFindingDraft(draft, { scanWorkspaceRoot: workspace });
    expect(result).toEqual({ ok: true });
  });

  it("returns ok:true when all optional fields are unset", () => {
    expect(
      validateFindingDraft({}, { scanWorkspaceRoot: workspace }),
    ).toEqual({ ok: true });
  });

  it("treats empty strings as absent for optional fields", () => {
    expect(
      validateFindingDraft(
        { cve: "", cwe: "  ", cvss: "" },
        { scanWorkspaceRoot: workspace },
      ),
    ).toEqual({ ok: true });
  });

  // ── CVE ──

  it("rejects a malformed CVE (CVE-9999-FAKE)", () => {
    const result = validateFindingDraft(
      { cve: "CVE-9999-FAKE" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].field).toBe("cve");
    expect(result.errors[0].reason).toContain("CVE-YYYY-N");
    expect(result.errors[0].hint).toContain("CVE-2024-1086");
  });

  it("rejects CVE-25-1 (year not 4 digits)", () => {
    const result = validateFindingDraft(
      { cve: "CVE-25-1" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
  });

  it("rejects lowercase cve-2024-12345", () => {
    const result = validateFindingDraft(
      { cve: "cve-2024-12345" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("cve");
  });

  it("rejects CVE-1899-1234 (year outside 1900s/2000s)", () => {
    const result = validateFindingDraft(
      { cve: "CVE-1899-1234" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
  });

  it("accepts a canonical CVE-2024-12345", () => {
    const result = validateFindingDraft(
      { cve: "CVE-2024-12345" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result).toEqual({ ok: true });
  });

  // ── CWE ──

  it("rejects a malformed CWE", () => {
    const result = validateFindingDraft(
      { cwe: "CWE-abc" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("cwe");
  });

  it("rejects lowercase cwe-89", () => {
    expect(
      validateFindingDraft(
        { cwe: "cwe-89" },
        { scanWorkspaceRoot: workspace },
      ).ok,
    ).toBe(false);
  });

  // ── CVSS ──

  it("rejects a malformed CVSS vector", () => {
    const result = validateFindingDraft(
      { cvss: "CVSS:3.1/garbage" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("cvss");
    expect(result.errors[0].hint).toContain("CVSS:3.1/");
  });

  it("rejects CVSS v3.0 vectors (we only accept v3.1)", () => {
    const result = validateFindingDraft(
      { cvss: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
  });

  it("rejects CVSS vector with bogus metric value", () => {
    // PR:X is not valid
    const result = validateFindingDraft(
      { cvss: "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H" },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
  });

  it("rejects cvssScore outside [0,10]", () => {
    const result = validateFindingDraft(
      { cvssScore: 11.5 },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("cvssScore");
  });

  it("accepts cvssScore at boundaries (0 and 10)", () => {
    expect(
      validateFindingDraft(
        { cvssScore: 0 },
        { scanWorkspaceRoot: workspace },
      ),
    ).toEqual({ ok: true });
    expect(
      validateFindingDraft(
        { cvssScore: 10 },
        { scanWorkspaceRoot: workspace },
      ),
    ).toEqual({ ok: true });
  });

  // ── Evidence paths ──

  it("rejects an evidence path containing '..'", () => {
    const result = validateFindingDraft(
      { evidence: [{ path: "../etc/passwd" }] },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("evidence[0].path");
    expect(result.errors[0].reason).toContain("..");
  });

  it("rejects an absolute path outside the workspace", () => {
    const result = validateFindingDraft(
      { evidence: [{ path: join(outside, "secret.txt") }] },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("evidence[0].path");
    expect(result.errors[0].reason).toContain("outside scan workspace");
  });

  it("rejects /etc/passwd", () => {
    const result = validateFindingDraft(
      { evidence: [{ path: "/etc/passwd" }] },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a symlink that escapes the workspace", () => {
    // Real symlink inside the workspace pointing at /etc/passwd-ish file
    // outside it. Use the per-test `outside` dir so the test stays
    // hermetic (don't ever target /etc/passwd directly — it might not be
    // readable by the test runner and we don't want false negatives).
    const escapeTarget = join(outside, "leaked.txt");
    writeFileSync(escapeTarget, "secret");
    const symlinkPath = join(workspace, "escape-link");
    symlinkSync(escapeTarget, symlinkPath);

    const result = validateFindingDraft(
      { evidence: [{ path: "escape-link" }] },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0].field).toBe("evidence[0].path");
    expect(result.errors[0].reason).toContain("symlink escapes");
  });

  it("accepts a symlink that points INSIDE the workspace", () => {
    const target = join(workspace, "sub", "blob.json");
    const symlinkPath = join(workspace, "inside-link");
    symlinkSync(target, symlinkPath);

    const result = validateFindingDraft(
      { evidence: [{ path: "inside-link" }] },
      { scanWorkspaceRoot: workspace },
    );
    expect(result).toEqual({ ok: true });
  });

  it("accepts a non-existent (not-yet-written) path inside the workspace", () => {
    const result = validateFindingDraft(
      { evidence: [{ path: "artifacts/not-yet.png" }] },
      { scanWorkspaceRoot: workspace },
    );
    expect(result).toEqual({ ok: true });
  });

  // ── Multi-error aggregation ──

  it("returns ALL errors, not just the first", () => {
    const result = validateFindingDraft(
      {
        cve: "bad-cve",
        cwe: "bad-cwe",
        cvss: "bad-cvss",
        cvssScore: 99,
        evidence: [{ path: "../escape" }],
      },
      { scanWorkspaceRoot: workspace },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const fields = result.errors.map((e) => e.field);
    expect(fields).toContain("cve");
    expect(fields).toContain("cwe");
    expect(fields).toContain("cvss");
    expect(fields).toContain("cvssScore");
    expect(fields).toContain("evidence[0].path");
  });
});

// ────────────────────────────────────────────────────────────────────
// pathEscapeReason (the extracted helper) directly
// ────────────────────────────────────────────────────────────────────

describe("pathEscapeReason", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "pwnkit-path-guard-"));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("returns null for a path inside the root", () => {
    expect(pathEscapeReason(root, "foo/bar.txt")).toBeNull();
  });

  it("returns a reason for parent-dir traversal", () => {
    expect(pathEscapeReason(root, "../x")).toMatch(/parent-directory/);
  });

  it("normalises Windows-style separators in the '..' check", () => {
    // Use sep-aware regex; on POSIX `\` is just a char, but the regex
    // still fires on `..` segments with platform separators.
    const reason = pathEscapeReason(root, `a${sep}..${sep}b`);
    expect(reason).toMatch(/parent-directory/);
  });

  it("returns a reason for an absolute path outside root", () => {
    expect(pathEscapeReason(root, "/etc/passwd")).toMatch(/outside/);
  });
});

// ────────────────────────────────────────────────────────────────────
// Tool integration — `save_finding` returns validation_failed and the
// agent's retry on the same turn succeeds. No real LLM calls.
// ────────────────────────────────────────────────────────────────────

describe("save_finding validation integration", () => {
  let workspace: string;
  let ctx: ToolContext;
  let executor: ToolExecutor;

  beforeEach(() => {
    workspace = mkdtempSync(join(tmpdir(), "pwnkit-save-finding-ws-"));
    ctx = {
      target: "https://example.com",
      scanId: "test-scan-409",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scopePath: workspace,
    };
    executor = new ToolExecutor(ctx, null);
  });

  afterEach(() => {
    rmSync(workspace, { recursive: true, force: true });
  });

  it("rejects malformed CVE with structured validation_failed result", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Some finding",
        severity: "high",
        category: "sql-injection",
        evidence_request: "GET /api",
        evidence_response: "leak",
        cve: "CVE-9999-FAKE",
      },
    });

    expect(result.success).toBe(false);
    expect(ctx.findings).toHaveLength(0);
    const output = result.output as {
      kind: string;
      errors: Array<{ field: string }>;
    } | null;
    expect(output?.kind).toBe("validation_failed");
    expect(output?.errors[0].field).toBe("cve");
  });

  it("agent self-corrects within the same turn — second call succeeds", async () => {
    // Call 1: malformed CVE → validation_failed
    const bad = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "SQLi in /users",
        severity: "high",
        category: "sql-injection",
        evidence_request: "GET /users?id=1' OR '1'='1",
        evidence_response: "all rows leaked",
        cve: "cve-2024-12345", // lowercase — rejected
      },
    });
    expect(bad.success).toBe(false);
    expect(ctx.findings).toHaveLength(0);

    // Call 2: agent reads the error, uppercases the CVE, re-submits
    const good = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "SQLi in /users",
        severity: "high",
        category: "sql-injection",
        evidence_request: "GET /users?id=1' OR '1'='1",
        evidence_response: "all rows leaked",
        cve: "CVE-2024-12345",
      },
    });
    expect(good.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].title).toBe("SQLi in /users");
  });

  it("rejects evidence path with parent-dir traversal", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Path-leak finding",
        severity: "medium",
        category: "information-disclosure",
        evidence_request: "GET /file",
        evidence_response: "...",
        evidence_paths: ["../etc/passwd"],
      },
    });
    expect(result.success).toBe(false);
    const output = result.output as {
      kind: string;
      errors: Array<{ field: string; reason: string }>;
    } | null;
    expect(output?.kind).toBe("validation_failed");
    expect(output?.errors[0].field).toContain("evidence");
  });

  it("happy path: no CVE/CWE/CVSS at all still saves cleanly", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Generic finding",
        severity: "low",
        category: "info",
        evidence_request: "GET /",
        evidence_response: "200 OK",
      },
    });
    expect(result.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
  });
});
