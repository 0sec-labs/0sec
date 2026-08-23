import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ToolExecutor,
  detectPackageManager,
  resolveDependencyAuditCommand,
} from "./tools.js";
import type { ToolContext } from "./types.js";

// ── Fix 2: package-manager detection from the lockfile ───────────────────────

describe("detectPackageManager (0sec#tool-reliability)", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "0sec-pm-detect-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("detects pnpm from pnpm-lock.yaml", () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    expect(detectPackageManager(root)).toBe("pnpm");
  });

  it("detects yarn from yarn.lock", () => {
    writeFileSync(join(root, "yarn.lock"), "# yarn\n");
    expect(detectPackageManager(root)).toBe("yarn");
  });

  it("detects npm from package-lock.json", () => {
    writeFileSync(join(root, "package-lock.json"), "{}\n");
    expect(detectPackageManager(root)).toBe("npm");
  });

  it("prefers pnpm when multiple lockfiles are present", () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    writeFileSync(join(root, "package-lock.json"), "{}\n");
    expect(detectPackageManager(root)).toBe("pnpm");
  });

  it("returns null when no lockfile is present", () => {
    expect(detectPackageManager(root)).toBeNull();
  });
});

describe("resolveDependencyAuditCommand (0sec#tool-reliability)", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "0sec-audit-resolve-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("redirects `npm audit` to `pnpm audit` on a pnpm repo", () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    const res = resolveDependencyAuditCommand([["npm", "audit"]], root);
    expect(res.kind).toBe("run");
    if (res.kind === "run") {
      expect(res.tokens).toEqual(["pnpm", "audit"]);
      expect(res.redirectedFrom).toBe("npm");
      expect(res.note).toMatch(/redirected to 'pnpm audit'/);
    }
  });

  it("preserves flags when redirecting", () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    const res = resolveDependencyAuditCommand([["npm", "audit", "--json"]], root);
    expect(res.kind).toBe("run");
    if (res.kind === "run") expect(res.tokens).toEqual(["pnpm", "audit", "--json"]);
  });

  it("runs unchanged when the requested PM matches the lockfile", () => {
    writeFileSync(join(root, "package-lock.json"), "{}\n");
    const res = resolveDependencyAuditCommand([["npm", "audit"]], root);
    expect(res.kind).toBe("run");
    if (res.kind === "run") {
      expect(res.tokens).toEqual(["npm", "audit"]);
      expect(res.redirectedFrom).toBeUndefined();
    }
  });

  it("skips non-fatally when no lockfile exists", () => {
    const res = resolveDependencyAuditCommand([["npm", "audit"]], root);
    expect(res.kind).toBe("skip");
    if (res.kind === "skip") {
      expect(res.requested).toBe("npm");
      expect(res.message).toMatch(/no npm lockfile found/);
      expect(res.remedy).toBeTruthy();
    }
  });

  it("leaves non-audit and piped commands untouched", () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    expect(resolveDependencyAuditCommand([["npm", "view", "lodash"]], root).kind).toBe("not-audit");
    expect(resolveDependencyAuditCommand([["grep", "foo"]], root).kind).toBe("not-audit");
    // piped: multiple segments are left alone
    expect(
      resolveDependencyAuditCommand([["npm", "audit"], ["jq", "."]], root).kind,
    ).toBe("not-audit");
  });
});

// ── Executor-level integration for the four fixes ────────────────────────────

describe("ToolExecutor reliability fixes (0sec#tool-reliability)", () => {
  let root: string;
  let ctx: ToolContext;
  let executor: ToolExecutor;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "0sec-reliability-"));
    ctx = {
      target: "https://example.com",
      scanId: "reliability-scan",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scopePath: root,
    };
    executor = new ToolExecutor(ctx, null);
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  // Fix 3: command policy now allows pnpm/yarn audit.
  it("allows `pnpm audit` (not rejected as a disallowed command)", async () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    const result = await executor.execute({
      name: "run_command",
      arguments: { command: "pnpm audit" },
    });
    // pnpm may or may not be installed on the runner, but it must NOT be
    // rejected by the allowlist. Either it ran, or it was a graceful
    // missing-binary skip — never "not allowed".
    if (!result.success) {
      expect(result.error).not.toContain("not allowed");
    }
    expect(JSON.stringify(result)).not.toContain("not allowed");
  });

  it("allows `yarn audit` through the policy", async () => {
    writeFileSync(join(root, "yarn.lock"), "# yarn\n");
    const result = await executor.execute({
      name: "run_command",
      arguments: { command: "yarn audit" },
    });
    if (!result.success) expect(result.error).not.toContain("not allowed");
  });

  it("still rejects state-mutating package-manager subcommands", async () => {
    for (const cmd of ["pnpm install", "yarn add lodash", "pnpm exec foo", "npm run build"]) {
      const result = await executor.execute({
        name: "run_command",
        arguments: { command: cmd },
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain("not allowed");
    }
  });

  // Fix 2 (integration): npm audit on a pnpm repo records a wrong-lockfile
  // health event (redirected), never ENOLOCK.
  it("redirects `npm audit` on a pnpm repo and records a wrong-lockfile event", async () => {
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    await executor.execute({
      name: "run_command",
      arguments: { command: "npm audit" },
    });
    const summary = executor.toolHealthSummary();
    expect(summary.byCategory["wrong-lockfile"]).toBeGreaterThanOrEqual(1);
  });

  it("skips a dependency audit non-fatally when no lockfile is present", async () => {
    const result = await executor.execute({
      name: "run_command",
      arguments: { command: "npm audit" },
    });
    expect(result.success).toBe(true);
    expect(result.output).toMatchObject({ skipped: true });
    expect(executor.toolHealthSummary().byCategory["wrong-lockfile"]).toBeGreaterThanOrEqual(1);
  });

  // Fix 4: a missing optional binary is a graceful skip, not a throw.
  it("returns a graceful skip for a missing binary and records missing-binary", async () => {
    // `semgrep` is allow-listed but not installed on the test runner, so the
    // spawn ENOENTs. Guard for the rare runner that does have it installed.
    const installed = spawnSync("semgrep", ["--version"]).error == null;
    const result = await executor.execute({
      name: "run_command",
      arguments: { command: "semgrep --version" },
    });
    // Either way this must NOT be a hard failure.
    expect(result.success).toBe(true);
    if (!installed) {
      expect(result.output).toMatchObject({ skipped: true });
      const summary = executor.toolHealthSummary();
      expect(summary.missing).toContain("semgrep");
      expect(summary.byCategory["missing-binary"]).toBeGreaterThanOrEqual(1);
    }
  });

  // Fix 1: output larger than the OLD 1MB buffer no longer crashes with ENOBUFS.
  it("returns results for output that would have blown the old 1MB buffer", async () => {
    // ~4MB file — far past the previous 1MiB maxBuffer, well under the new 64MiB.
    const big = "a".repeat(4 * 1024 * 1024) + "\n";
    writeFileSync(join(root, "big.txt"), big);
    const result = await executor.execute({
      name: "run_command",
      arguments: { command: "cat big.txt" },
    });
    expect(result.success).toBe(true);
    // No ENOBUFS surfaced as an error.
    expect(JSON.stringify(result)).not.toContain("ENOBUFS");
  });

  it("records a policy-denied event when the allowlist rejects a command", async () => {
    await executor.execute({
      name: "run_command",
      arguments: { command: "curl https://evil.com" },
    });
    expect(executor.toolHealthSummary().byCategory["policy-denied"]).toBeGreaterThanOrEqual(1);
  });

  it("reports a clean bill of health when nothing degraded", () => {
    expect(executor.toolHealthSummary().total).toBe(0);
    expect(executor.toolHealthSummary().line).toBe("");
  });
});
