/**
 * Coverage seed for `runPipeline` in `unified-pipeline.ts` — the package-audit
 * + source-review dispatcher (1.27k LoC). This complements:
 *
 *   • `unified-pipeline.restore.test.ts`     — resume-from-scan-id + the
 *                                              `restorePersistedFinding`
 *                                              wire-roundtrip path.
 *   • `unified-pipeline.research-loop.test.ts` — `runPerFileResearch` exit
 *                                              shape, per-file invariants,
 *                                              error isolation.
 *
 * This file covers the *outer* pipeline: which prepare/install helper gets
 * dispatched per `targetType`, how the analyze stage threads semgrep +
 * dependency-audit results, how `--diff-base` / `--changed-only` flow into
 * the agent prompt, how review profile (`c-library`, `linux-kernel`) gets
 * selected, and how the verify-phase short-circuits to a clean report
 * envelope when no findings exist.
 *
 * Strategy: mock-at-module-boundary (mirrors `run.test.ts` PR #301 and
 * `dashboard.test.ts` PR #314):
 *
 *   • `./package-ecosystems.js` — fake install + dependency-audit (no
 *     real `npm install` / `pip install` / `cargo install` / OCI pulls).
 *   • `./shared-analysis.js`    — fake semgrep (no real binary probe).
 *   • `./agent-runner.js`       — fake LLM agent (no real API calls).
 *   • `./source-files.js`       — fake file walk (no real fs traversal).
 *   • `./runtime/registry.js`   — fake CLI-runtime detection.
 *   • `./runtime/llm-api.js`    — stubbed `LlmApiRuntime` whose diagnostics
 *                                  report a valid API config (so the
 *                                  pipeline takes the AI-runtime branch
 *                                  without needing a real env var).
 *
 * The real `@0sec/db` is used with a tmp file (same shape as the restore
 * test) so persistence side effects round-trip honestly.
 *
 * Out of scope (deliberately skipped):
 *   • Real semgrep / npm-audit / pip-audit / cargo-audit invocations.
 *   • Real LLM agent loops (already covered by `agentic-scanner.events`,
 *     native-loop, etc.).
 *   • Network — no `git clone`, no registry hits.
 *   • Verify-phase confirm/reject path with non-empty findings — the
 *     blind-verify code branch deserves its own seed with its own
 *     `runAnalysisAgent` mock shape (separate PR).
 *   • Per-file orchestration loop — already covered by the research-loop
 *     test. We force `0SEC_FEATURE_PER_ITEM_ORCHESTRATION=0` to keep
 *     these tests on the single-shot dispatch.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, NpmAuditFinding, SemgrepFinding } from "@0sec/shared";
import { osecDB } from "@0sec/db";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// `vi.mock` is hoisted to the top of the file, so the imports below see
// the stubs. We expose hand-rolled spies (`*Mock`) so each test can assert
// dispatch + argument plumbing without leaning on `vi.mocked()` typing.

const installPackageMock = vi.fn();
const runDependencyAuditMock = vi.fn();
vi.mock("./package-ecosystems.js", () => ({
  installPackageForEcosystem: installPackageMock,
  runDependencyAuditForEcosystem: runDependencyAuditMock,
}));

const runSemgrepScanMock = vi.fn();
const runFoxguardScanMock = vi.fn();
vi.mock("./shared-analysis.js", () => ({
  runFoxguardScan: runFoxguardScanMock,
  runSemgrepScan: runSemgrepScanMock,
  selectedStaticScanner: () => process.env["0SEC_STATIC"] === "semgrep" ? "semgrep" : "foxguard",
  runSelectedStaticScan: (...args: unknown[]) =>
    process.env["0SEC_STATIC"] === "semgrep"
      ? runSemgrepScanMock(...args)
      : runFoxguardScanMock(...args),
}));

const runAnalysisAgentMock = vi.fn();
vi.mock("./agent-runner.js", () => ({
  runAnalysisAgent: runAnalysisAgentMock,
}));

const collectScopeFilesMock = vi.fn();
const countScopeFilesUpToMock = vi.fn();
vi.mock("./source-files.js", () => ({
  collectScopeFiles: collectScopeFilesMock,
  countScopeFilesUpTo: countScopeFilesUpToMock,
}));

const detectAvailableRuntimesMock = vi.fn();
vi.mock("./runtime/registry.js", () => ({
  detectAvailableRuntimes: detectAvailableRuntimesMock,
}));

// `LlmApiRuntime` is a class the pipeline `new`s up. We replace it with a
// stub whose `getConfigurationDiagnostics()` returns `{ valid: true }` so
// the pipeline takes the AI-runtime branch (otherwise it short-circuits
// with a "no runtime available" warning before ever calling
// `runAnalysisAgent`). The constructor records its config so we can
// assert the apiKey / model / timeout plumbing.
const apiRuntimeConstructorCalls: Array<Record<string, unknown>> = [];
vi.mock("./runtime/llm-api.js", () => {
  class FakeLlmApiRuntime {
    private readonly config: Record<string, unknown>;
    constructor(config: Record<string, unknown>) {
      this.config = config;
      apiRuntimeConstructorCalls.push(config);
    }
    getConfigurationDiagnostics() {
      return {
        valid: true,
        provider: "anthropic",
        providerLabel: "Anthropic",
      };
    }
    // Mirrors the real class's resolved-model getter: the requested model
    // when one was passed, otherwise a provider default stand-in.
    resolvedModel() {
      return (this.config.model as string | undefined) ?? "claude-fake-default";
    }
  }
  return { LlmApiRuntime: FakeLlmApiRuntime };
});

// ── Imports (after mocks) ───────────────────────────────────────────────────

const { runPipeline } = await import("./unified-pipeline.js");
const { eventBus } = await import("./events/bus.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

const tempDirs: string[] = [];

function freshTmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `0sec-unified-pipeline-${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function freshDbPath(): string {
  return join(freshTmpDir("db"), "0sec.db");
}

/** Build an InstalledPackage shape — what installPackageForEcosystem returns. */
function fakeInstalledPackage(
  ecosystem: "npm" | "pypi" | "cargo" | "oci",
  name: string,
  version: string,
) {
  const tempDir = freshTmpDir(`install-${ecosystem}`);
  return {
    ecosystem,
    name,
    version,
    path: tempDir,
    tempDir,
  };
}

function fakeFinding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    templateId: "tpl",
    title: `Finding ${id}`,
    description: `desc ${id}`,
    severity: "medium",
    category: "code-injection",
    status: "discovered",
    evidence: { request: "src/a.ts", response: "PoC body", analysis: "analysis" },
    timestamp: 0,
    ...overrides,
  };
}

function fakeSemgrepFinding(path = "src/a.ts"): SemgrepFinding {
  return {
    ruleId: "javascript.eval",
    message: "eval call",
    path,
    startLine: 1,
    severity: "high",
    snippet: "",
  } as SemgrepFinding;
}

function fakeNpmAudit(name = "lodash"): NpmAuditFinding {
  return {
    name,
    severity: "high",
    title: "prototype pollution",
    via: [],
    fixAvailable: false,
  } as NpmAuditFinding;
}

// ── Test harness lifecycle ──────────────────────────────────────────────────

let originalPerItemEnv: string | undefined;
let originalApiKey: string | undefined;
let originalStaticAnalyzer: string | undefined;
let originalCloudEvents: string | undefined;

beforeEach(() => {
  installPackageMock.mockReset();
  runDependencyAuditMock.mockReset();
  runSemgrepScanMock.mockReset();
  runFoxguardScanMock.mockReset();
  runAnalysisAgentMock.mockReset();
  collectScopeFilesMock.mockReset();
  countScopeFilesUpToMock.mockReset();
  detectAvailableRuntimesMock.mockReset();
  apiRuntimeConstructorCalls.length = 0;

  // Sensible defaults — tests can override per-test.
  runSemgrepScanMock.mockReturnValue([]);
  runFoxguardScanMock.mockReturnValue([]);
  runDependencyAuditMock.mockReturnValue([]);
  runAnalysisAgentMock.mockResolvedValue({ findings: [] });
  collectScopeFilesMock.mockReturnValue([]);
  // Default: under the review cap (the oversized-review guard only trips when
  // the count exceeds the cap). Individual tests override to exercise the guard.
  countScopeFilesUpToMock.mockReturnValue(0);
  detectAvailableRuntimesMock.mockResolvedValue(new Set<string>());

  // Force the single-shot agent path. Per-file orchestration is covered
  // by `unified-pipeline.research-loop.test.ts`; mixing both branches in
  // a single seed would obscure dispatch assertions.
  originalPerItemEnv = process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"];
  process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"] = "0";

  // Some upstream prompt code reads keys for banner logic; we already
  // short-circuited the runtime, but unset to keep tests deterministic.
  originalApiKey = process.env.ANTHROPIC_API_KEY;
  originalStaticAnalyzer = process.env["0SEC_STATIC"];
  originalCloudEvents = process.env["0SEC_CLOUD_EVENTS"];
  delete process.env["0SEC_STATIC"];
  delete process.env["0SEC_CLOUD_EVENTS"];
});

afterEach(() => {
  if (originalPerItemEnv === undefined) {
    delete process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"];
  } else {
    process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"] = originalPerItemEnv;
  }
  if (originalApiKey === undefined) {
    delete process.env.ANTHROPIC_API_KEY;
  } else {
    process.env.ANTHROPIC_API_KEY = originalApiKey;
  }
  if (originalStaticAnalyzer === undefined) {
    delete process.env["0SEC_STATIC"];
  } else {
    process.env["0SEC_STATIC"] = originalStaticAnalyzer;
  }
  if (originalCloudEvents === undefined) {
    delete process.env["0SEC_CLOUD_EVENTS"];
  } else {
    process.env["0SEC_CLOUD_EVENTS"] = originalCloudEvents;
  }
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
});

// ── Dispatch by targetType ──────────────────────────────────────────────────

describe("runPipeline — targetType dispatch", () => {
  it("npm-package: routes through installPackageForEcosystem('npm', …) and resolves to npm:name@version", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock).toHaveBeenCalledTimes(1);
    expect(installPackageMock.mock.calls[0]![0]).toBe("npm");
    expect(installPackageMock.mock.calls[0]![1]).toBe("lodash");
    expect(report.targetType).toBe("npm-package");
    // Backwards-compat extras populated for npm-package.
    expect(report.package).toBe("lodash");
    expect(report.version).toBe("4.17.21");
  });

  it("npm-package: explicit packageVersion option threads into the installer", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "node-forge", "0.10.0"));

    await runPipeline({
      target: "node-forge",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      packageVersion: "0.10.0",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock).toHaveBeenCalledWith(
      "npm",
      "node-forge",
      "0.10.0",
      expect.any(Function),
    );
  });

  it("npm-package: 'name@version' string is split before reaching the installer (latest fallback shape)", async () => {
    // The npm path has its own split logic *before* installPackageForEcosystem,
    // matching the public CLI contract `0sec run node-forge@0.10.0`.
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "node-forge", "0.10.0"));

    await runPipeline({
      target: "node-forge@0.10.0",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    // After the split: name == "node-forge", version == "0.10.0".
    expect(installPackageMock).toHaveBeenCalledWith(
      "npm",
      "node-forge",
      "0.10.0",
      expect.any(Function),
    );
  });

  it("pypi-package: routes through installPackageForEcosystem('pypi', …)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("pypi", "requests", "2.31.0"));

    const report = await runPipeline({
      target: "requests",
      targetType: "pypi-package",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock.mock.calls[0]![0]).toBe("pypi");
    expect(report.targetType).toBe("pypi-package");
    expect(report.package).toBe("requests");
    expect(report.version).toBe("2.31.0");
  });

  it("cargo-package: routes through installPackageForEcosystem('cargo', …)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("cargo", "serde", "1.0.0"));

    const report = await runPipeline({
      target: "serde",
      targetType: "cargo-package",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock.mock.calls[0]![0]).toBe("cargo");
    expect(report.targetType).toBe("cargo-package");
  });

  it("oci-image: routes through installPackageForEcosystem('oci', …)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("oci", "nginx", "1.25.0"));

    const report = await runPipeline({
      target: "nginx:1.25.0",
      targetType: "oci-image",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock.mock.calls[0]![0]).toBe("oci");
    expect(report.targetType).toBe("oci-image");
  });

  it("source-code (local path): skips installPackageForEcosystem and resolves to repo:<abs-path>", async () => {
    const repoDir = freshTmpDir("repo");
    // Drop a marker file so the source-code prepare step's existsSync check passes.
    writeFileSync(join(repoDir, "README.md"), "# fixture");

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock).not.toHaveBeenCalled();
    expect(report.targetType).toBe("source-code");
    expect(report.repo).toBe(repoDir);
    expect(report.semgrepFindings).toBe(0);
  });

  it("source-code: missing local path throws a structured 'Prepare failed' error", async () => {
    const ghostPath = join(freshTmpDir("ghost"), "does-not-exist");

    await expect(
      runPipeline({
        target: ghostPath,
        targetType: "source-code",
        depth: "quick",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        dbPath: freshDbPath(),
      }),
    ).rejects.toThrow(/Prepare failed.*Repository path not found/);
  });
});

// ── Oversized-review guard ──────────────────────────────────────────────────
//
// A whole-repo `review` (source-code target) feeds the tree to a single agent
// session under a fixed time budget. On an oversized target (the Linux kernel
// is ~80k source files) the session burns the entire budget producing 0 tokens
// + 0 findings, then times out silently. The guard counts the scope files up
// front and fails fast with an actionable error instead.

describe("runPipeline — oversized-review guard", () => {
  function reviewRepo() {
    const repoDir = freshTmpDir("oversized-repo");
    writeFileSync(join(repoDir, "README.md"), "# fixture");
    return repoDir;
  }

  it("source-code review over the file cap fails fast with a clear, actionable error (no agent run)", async () => {
    // Simulate the kernel: the count walker reports it blew past the cap.
    countScopeFilesUpToMock.mockReturnValue(5001);

    await expect(
      runPipeline({
        target: reviewRepo(),
        targetType: "source-code",
        depth: "quick",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        dbPath: freshDbPath(),
      }),
    ).rejects.toThrow(/review target too large.*5000 review cap.*scope to a subsystem/);

    // The expensive agent loop never ran — we failed before research.
    expect(runAnalysisAgentMock).not.toHaveBeenCalled();
  });

  it("source-code review under the file cap proceeds unchanged (agent runs)", async () => {
    // Under the cap — the guard is a no-op and the review proceeds.
    countScopeFilesUpToMock.mockReturnValue(42);

    const report = await runPipeline({
      target: reviewRepo(),
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.targetType).toBe("source-code");
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
  });

  it("linux-kernel review with --subsystem applies the file cap to the scoped path", async () => {
    countScopeFilesUpToMock.mockReturnValue(42);

    const repo = reviewRepo();
    const report = await runPipeline({
      target: repo,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
      reviewProfile: "linux-kernel",
      subsystem: "drivers/hid",
    });

    expect(report.targetType).toBe("source-code");
    expect(countScopeFilesUpToMock).toHaveBeenCalledWith(
      join(repo, "drivers/hid/"),
      5000,
    );
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
  });

  it("0SEC_REVIEW_MAX_FILES overrides the cap (count above the override trips the guard)", async () => {
    const prev = process.env["0SEC_REVIEW_MAX_FILES"];
    process.env["0SEC_REVIEW_MAX_FILES"] = "10";
    try {
      // 11 > the overridden cap of 10.
      countScopeFilesUpToMock.mockReturnValue(11);

      await expect(
        runPipeline({
          target: reviewRepo(),
          targetType: "source-code",
          depth: "quick",
          format: "json",
          runtime: "api",
          apiKey: "sk-fake",
          dbPath: freshDbPath(),
        }),
      ).rejects.toThrow(/review target too large.*10 review cap/);

      expect(runAnalysisAgentMock).not.toHaveBeenCalled();
    } finally {
      if (prev === undefined) delete process.env["0SEC_REVIEW_MAX_FILES"];
      else process.env["0SEC_REVIEW_MAX_FILES"] = prev;
    }
  });

  it("package audit (npm) is unaffected by the review cap (guard is source-code only)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));
    // Even an absurd count must not trip the guard for a package audit.
    countScopeFilesUpToMock.mockReturnValue(999999);

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.targetType).toBe("npm-package");
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
  });
});

// ── Analyze phase: static scanner + dependency-audit ────────────────────────

describe("runPipeline — analyze phase", () => {
  it("npm-package: invokes foxguard with noGitIgnore and a runDependencyAudit for 'npm' by default", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "left-pad", "1.0.0"));
    runFoxguardScanMock.mockReturnValue([fakeSemgrepFinding("index.js")]);
    runDependencyAuditMock.mockReturnValue([fakeNpmAudit("left-pad")]);

    const report = await runPipeline({
      target: "left-pad",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    // foxguard called with `{ noGitIgnore: true }` for package targets.
    expect(runFoxguardScanMock).toHaveBeenCalledTimes(1);
    const foxguardOpts = runFoxguardScanMock.mock.calls[0]![2];
    expect(foxguardOpts).toEqual({ noGitIgnore: true });

    // dep audit called with ecosystem='npm' and the package's tempDir.
    expect(runDependencyAuditMock).toHaveBeenCalledTimes(1);
    expect(runDependencyAuditMock.mock.calls[0]![0]).toBe("npm");

    expect(report.semgrepFindings).toBe(1);
    expect(report.npmAuditFindings).toHaveLength(1);
    expect(report.npmAuditFindings![0]!.name).toBe("left-pad");
  });

  it("source-code: dependency-audit is skipped (no tempDir / no ecosystem) but static scanner still runs", async () => {
    const repoDir = freshTmpDir("repo-src");
    writeFileSync(join(repoDir, "index.ts"), "// fixture");

    runFoxguardScanMock.mockReturnValue([fakeSemgrepFinding("index.ts")]);

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(runFoxguardScanMock).toHaveBeenCalledTimes(1);
    expect(runDependencyAuditMock).not.toHaveBeenCalled();
    expect(report.semgrepFindings).toBe(1);
  });

  it("source-code: foxguard is the default static analyzer", async () => {
    const repoDir = freshTmpDir("repo-src");
    const dbPath = freshDbPath();
    writeFileSync(join(repoDir, "index.ts"), "// fixture");

    runFoxguardScanMock.mockReturnValue([fakeSemgrepFinding("index.ts")]);

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
    });

    expect(runFoxguardScanMock).toHaveBeenCalledTimes(1);
    expect(runSemgrepScanMock).not.toHaveBeenCalled();
    expect(report.semgrepFindings).toBe(1);

    const db = new osecDB(dbPath);
    try {
      const [scan] = db.listScans(1) as Array<{ id: string }>;
      const events = db.getEvents(scan!.id, {
        stage: "analyze",
        eventType: "stage_complete",
      }) as Array<{ payload: string }>;
      const payload = JSON.parse(events[0]!.payload) as {
        staticScanner: string;
        staticScannerRan: boolean;
        staticScannerFindings: number;
        semgrepFindings: number;
      };
      expect(payload).toMatchObject({
        staticScanner: "foxguard",
        staticScannerRan: true,
        staticScannerFindings: 1,
        semgrepFindings: 1,
      });
    } finally {
      db.close();
    }
  });

  it("emits cloud-bus provenance for package analyze completion", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "is-number", "7.0.0"));
    runFoxguardScanMock.mockReturnValue([fakeSemgrepFinding("index.js")]);
    runDependencyAuditMock.mockReturnValue([fakeNpmAudit("is-number")]);
    process.env["0SEC_CLOUD_EVENTS"] = "1";
    const events: Array<{ type: string; payload: Record<string, unknown> }> = [];
    const unsubscribe = eventBus.subscribe({
      emit(type, payload) {
        events.push({ type, payload });
      },
    });

    try {
      await runPipeline({
        target: "is-number",
        targetType: "npm-package",
        depth: "quick",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        dbPath: freshDbPath(),
      });
    } finally {
      unsubscribe();
    }

    expect(events).toContainEqual({
      type: "analyze:stage_complete",
      payload: {
        stage: "static-analysis",
        staticScanner: "foxguard",
        staticScannerRan: true,
        staticScannerFindings: 1,
        semgrepFindings: 1,
        npmAuditFindings: 1,
      },
    });
    expect(events).toContainEqual({
      type: "scan_completed",
      payload: expect.objectContaining({
        exit_reason: "completed",
        findings: 0,
      }),
    });
  });

  it("source-code: 0SEC_STATIC=semgrep routes static analysis to semgrep", async () => {
    process.env["0SEC_STATIC"] = "semgrep";
    const repoDir = freshTmpDir("repo-semgrep");
    const dbPath = freshDbPath();
    writeFileSync(join(repoDir, "index.ts"), "// fixture");

    runSemgrepScanMock.mockReturnValue([fakeSemgrepFinding("index.ts")]);

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
    });

    expect(runSemgrepScanMock).toHaveBeenCalledTimes(1);
    expect(runFoxguardScanMock).not.toHaveBeenCalled();
    expect(report.semgrepFindings).toBe(1);

    const db = new osecDB(dbPath);
    try {
      const [scan] = db.listScans(1) as Array<{ id: string }>;
      const events = db.getEvents(scan!.id, {
        stage: "analyze",
        eventType: "stage_complete",
      }) as Array<{ payload: string }>;
      const payload = JSON.parse(events[0]!.payload) as {
        staticScanner: string;
        staticScannerRan: boolean;
        staticScannerFindings: number;
        semgrepFindings: number;
      };
      expect(payload).toMatchObject({
        staticScanner: "semgrep",
        staticScannerRan: true,
        staticScannerFindings: 1,
        semgrepFindings: 1,
      });
    } finally {
      db.close();
    }
  });

  it("package targets route static leads to foxguard by default", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "left-pad", "1.0.0"));

    await runPipeline({
      target: "left-pad",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(runFoxguardScanMock).toHaveBeenCalledTimes(1);
    expect(runFoxguardScanMock.mock.calls[0]![2]).toEqual({ noGitIgnore: true });
    expect(runSemgrepScanMock).not.toHaveBeenCalled();
    expect(runDependencyAuditMock).toHaveBeenCalledTimes(1);
  });

  it("foxguard failure is captured as a warning but does not abort the pipeline", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "leftpad", "1.0.0"));
    runFoxguardScanMock.mockImplementation(() => {
      throw new Error("foxguard binary missing");
    });

    const report = await runPipeline({
      target: "leftpad",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    const warning = report.warnings.find((w) =>
      w.message.includes("Foxguard scan failed"),
    );
    expect(warning).toBeDefined();
    expect(warning!.stage).toBe("analyze");
  });

  it("dependency-audit failure is captured as a warning but does not abort the pipeline", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("pypi", "requests", "2.31.0"));
    runDependencyAuditMock.mockImplementation(() => {
      throw new Error("pip-audit not installed");
    });

    const report = await runPipeline({
      target: "requests",
      targetType: "pypi-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    const warning = report.warnings.find((w) =>
      w.message.includes("dependency audit failed"),
    );
    expect(warning).toBeDefined();
    expect(warning!.stage).toBe("analyze");
  });
});

// ── Research phase: agent dispatch + review profile ─────────────────────────

describe("runPipeline — research phase + review profile", () => {
  it("source-code default profile: agent role='review', prompt mentions repo scope", async () => {
    const repoDir = freshTmpDir("repo-default");
    writeFileSync(join(repoDir, "index.ts"), "// fixture");

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.role).toBe("review");
    expect(args.scopePath).toBe(repoDir);
    // Default profile uses `reviewAgentPrompt`, not the kernel/cpp variants.
    // The c-cpp / kernel prompts have distinctive substrings we can negate.
    expect(args.agentSystemPrompt).not.toMatch(/Linux kernel/i);
    expect(args.agentSystemPrompt).not.toMatch(/C\/C\+\+ foundational/i);
  });

  it("source-code reviewProfile='c-library': c-cpp profile prompt reaches the agent", async () => {
    const repoDir = freshTmpDir("repo-cpp");
    writeFileSync(join(repoDir, "lib.c"), "// fixture");

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      reviewProfile: "c-library",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    const prompt = runAnalysisAgentMock.mock.calls[0]![0].agentSystemPrompt as string;
    // The c-cpp profile prompt builder includes language about memory
    // safety / allocation paths. Pin on a stable substring so this won't
    // shatter on minor wording changes.
    expect(prompt.toLowerCase()).toMatch(/memory safety|allocation|integer/);
  });

  it("source-code reviewProfile='linux-kernel': kernel profile prompt reaches the agent", async () => {
    const repoDir = freshTmpDir("repo-kernel");
    writeFileSync(join(repoDir, "core.c"), "// fixture");

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      reviewProfile: "linux-kernel",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    const prompt = runAnalysisAgentMock.mock.calls[0]![0].agentSystemPrompt as string;
    // The kernel profile prompt mentions syscall/copy_from_user/skb shape.
    expect(prompt.toLowerCase()).toMatch(/kernel|syscall|copy_from_user|skb/);
  });

  it("npm-package: agent role='audit' and the cliPrompt mentions the resolved npm target", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.role).toBe("audit");
    expect(args.target).toBe("npm:lodash@4.17.21");
    expect(args.cliPrompt).toContain("npm");
    expect(args.cliPrompt).toContain("lodash");
  });

  it("source-code + reviewPackageEcosystem='npm': installs the package but runs the REVIEW agent (role='review'), not audit", async () => {
    // Package-source review: the bare name is installed via the shared
    // ecosystem installer, then the EXTRACTED SOURCE is reviewed. This is
    // the fix for npm/pypi targets queued as scan_mode='review' — without
    // it the engine treated the package name as a repo path and died with
    // "Repository path not found".
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "ws", "8.16.0"));

    const report = await runPipeline({
      target: "ws",
      targetType: "source-code",
      reviewPackageEcosystem: "npm",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    // The package source was installed via the shared ecosystem installer…
    expect(installPackageMock).toHaveBeenCalledTimes(1);
    expect(installPackageMock.mock.calls[0]![0]).toBe("npm");
    expect(installPackageMock.mock.calls[0]![1]).toBe("ws");
    // …but the analysis ran as a REVIEW (role='review'), not an audit —
    // and resolvedType stays source-code so the review report path drives.
    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.role).toBe("review");
    expect(report.targetType).toBe("source-code");
  });

  it("source-code + reviewPackageEcosystem + packageVersion pins the installed version", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("pypi", "pillow", "10.2.0"));

    await runPipeline({
      target: "pillow",
      targetType: "source-code",
      reviewPackageEcosystem: "pypi",
      packageVersion: "10.2.0",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(installPackageMock).toHaveBeenCalledWith(
      "pypi",
      "pillow",
      "10.2.0",
      expect.any(Function),
    );
  });

  it("apiKey + model + timeout + costCeilingUsd are threaded into runAnalysisAgent.config", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "deep",
      format: "json",
      runtime: "api",
      apiKey: "sk-explicit",
      model: "claude-3-5-sonnet",
      timeout: 90_000,
      costCeilingUsd: 1.5,
      dbPath: freshDbPath(),
    });

    const config = runAnalysisAgentMock.mock.calls[0]![0].config;
    expect(config.apiKey).toBe("sk-explicit");
    expect(config.model).toBe("claude-3-5-sonnet");
    expect(config.timeout).toBe(90_000);
    expect(config.depth).toBe("deep");
    expect(config.costCeilingUsd).toBe(1.5);
  });

  it("agent failure becomes a warning rather than throwing through the pipeline", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));
    runAnalysisAgentMock.mockRejectedValue(new Error("api 500 transient"));

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.findings).toEqual([]);
    const w = report.warnings.find((x) => x.message.includes("AI analysis failed"));
    expect(w).toBeDefined();
    expect(w!.stage).toBe("research");
  });
});

// ── Scan-wide cost ceiling (0review $3 binding) ─────────────────────────────

describe("runPipeline — scan-wide cost ceiling", () => {
  /**
   * Regression for the prod 0review escape: the $3 ZERO_REVIEW_COST_CEILING_USD
   * reached the sandbox as 0SEC_COST_CEILING_USD, the review command resolved
   * it — and then runUnified dropped it before core.runPipeline, so review
   * scans ran UNCAPPED and landed at $4.99 / $6.36. Even where a ceiling did
   * reach the pipeline, it was enforced per agent SESSION, so research($3) +
   * N×verify($3) of real spend fit "under the ceiling". The fix: one
   * ScanCostLedger threaded through every session + a pre-verify budget gate.
   *
   * The runAnalysisAgent mock simulates spend by adding token usage to the
   * shared ledger the pipeline threads into each session's config — the same
   * object every call must receive.
   */
  type MockAgentArgs = {
    purpose?: "research" | "verify";
    config: {
      costLedger?: {
        add(usage: { inputTokens: number; outputTokens: number }): void;
      };
    };
  };

  it("threads ONE shared cost ledger into every agent session (research + verify)", async () => {
    const repoDir = freshTmpDir("repo-ledger-shared");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");
    runAnalysisAgentMock.mockResolvedValue({ findings: [fakeFinding("f1")] });

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      costCeilingUsd: 3,
      dbPath: freshDbPath(),
    });

    // research + 1 verify session (the finding needs blind-verifying).
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(2);
    const ledgers = runAnalysisAgentMock.mock.calls.map(
      (c) => (c[0] as MockAgentArgs).config.costLedger,
    );
    expect(ledgers[0]).toBeDefined();
    expect(ledgers[1]).toBe(ledgers[0]);
  });

  it("research exhausting the ceiling SKIPS the verify wave and stamps costCeilingExceeded", async () => {
    const repoDir = freshTmpDir("repo-ceiling-skip");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");

    // Research session spends past the $3 ceiling via the shared ledger
    // (default pricing $3/$15 per 1M: 900k in = $2.70, 60k out = $0.90 →
    // $3.60 ≥ $3) and terminates on the ceiling.
    runAnalysisAgentMock.mockImplementation(async (args: MockAgentArgs) => {
      args.config.costLedger?.add({ inputTokens: 900_000, outputTokens: 60_000 });
      return {
        findings: [fakeFinding("f1")],
        usage: { inputTokens: 900_000, outputTokens: 60_000 },
        turns: 3,
        costCeilingExceeded: true,
      };
    });

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      costCeilingUsd: 3,
      dbPath: freshDbPath(),
    });

    // The verify wave never launched — pre-fix it would have burned up to
    // $3 per finding ON TOP of the research spend.
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    expect(report.costCeilingExceeded).toBe(true);
    expect(report.exitReason).toBe("cost_ceiling_exceeded");
    // Fail-closed but honest: the unverified finding is HELD for review —
    // never silently confirmed, never falsely rejected on budget.
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.status).not.toBe("false-positive");
    expect(report.findings[0]!.publishability).toBe("needs_verify");
    const w = report.warnings.find((x) => x.message.includes("cost ceiling"));
    expect(w).toBeDefined();
    expect(w!.stage).toBe("verify");
  });

  it("mid-wave budget trip holds the finding as inconclusive (never a false rejection)", async () => {
    const repoDir = freshTmpDir("repo-ceiling-midwave");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");

    let call = 0;
    runAnalysisAgentMock.mockImplementation(async (args: MockAgentArgs) => {
      call++;
      if (call === 1) {
        // Research: one finding, comfortably under budget ($0.45).
        args.config.costLedger?.add({ inputTokens: 100_000, outputTokens: 10_000 });
        return {
          findings: [fakeFinding("f1")],
          usage: { inputTokens: 100_000, outputTokens: 10_000 },
          turns: 2,
        };
      }
      // Verify session: the collective spend crosses the ceiling mid-wave —
      // the verifier stopped on budget, NOT on a reproduction attempt.
      args.config.costLedger?.add({ inputTokens: 900_000, outputTokens: 60_000 });
      return {
        findings: [],
        usage: { inputTokens: 900_000, outputTokens: 60_000 },
        turns: 1,
        costCeilingExceeded: true,
      };
    });

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      costCeilingUsd: 3,
      dbPath: freshDbPath(),
    });

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(2); // research + 1 verify
    expect(report.costCeilingExceeded).toBe(true);
    expect(report.exitReason).toBe("cost_ceiling_exceeded");
    // A budget-truncated verifier returning zero findings must NOT read as
    // "could not reproduce" (→ false-positive): the finding is held.
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.status).not.toBe("false-positive");
    expect(report.findings[0]!.publishability).toBe("needs_verify");
  });

  it("stays a clean completion when total spend fits under the ceiling", async () => {
    const repoDir = freshTmpDir("repo-ceiling-under");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");

    // Research $0.45 + verify confirms the finding ($0.45) → $0.90 < $3.
    runAnalysisAgentMock.mockImplementation(async (args: MockAgentArgs) => {
      args.config.costLedger?.add({ inputTokens: 100_000, outputTokens: 10_000 });
      if (args.purpose === "verify") {
        return {
          findings: [fakeFinding("f1", { status: "verified" })],
          usage: { inputTokens: 100_000, outputTokens: 10_000 },
          turns: 1,
        };
      }
      return {
        findings: [fakeFinding("f1")],
        usage: { inputTokens: 100_000, outputTokens: 10_000 },
        turns: 2,
      };
    });

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "default",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      costCeilingUsd: 3,
      dbPath: freshDbPath(),
    });

    expect(report.costCeilingExceeded).toBeUndefined();
    expect(report.exitReason).toBeUndefined();
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.status).toBe("verified");
  });
});

// ── scan_completed event stream (cloud scan-detail population) ─────────────

describe("runPipeline — scan_completed event stream", () => {
  /**
   * Prod review scans showed cost_usd but NEVER model / turns_used /
   * tool_calls_total / cost_breakdown (0/6 in the DB): the pipeline only
   * emitted scan_completed on cost-trips, and with exit_reason alone. The
   * cloud's scan-detail tiles are populated from this event
   * (orchestrator events.ts → updateScanSummaryMetrics), so a NORMAL
   * completion must emit the full field set the audit path
   * (agentic-scanner.ts emitScanCompleted) emits.
   */
  type MockAgentArgs = {
    purpose?: "research" | "verify";
    config: {
      model?: string;
      costLedger?: {
        add(usage: { inputTokens: number; outputTokens: number }, model?: string): void;
      };
    };
  };

  function captureBusEvents(): {
    events: Array<{ type: string; payload: Record<string, unknown> }>;
    unsubscribe: () => void;
  } {
    const events: Array<{ type: string; payload: Record<string, unknown> }> = [];
    const unsubscribe = eventBus.subscribe({
      emit(type, payload) {
        events.push({ type, payload });
      },
    });
    return { events, unsubscribe };
  }

  it("normal review completion emits scan_completed with model + turns + tool calls + cost + breakdown", async () => {
    const repoDir = freshTmpDir("repo-scan-completed");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");
    process.env["0SEC_CLOUD_EVENTS"] = "1";

    // Research (2 turns) + one verify (1 turn), each folding usage into the
    // shared ledger under the session's pricing model — exactly what the
    // native loop does in production.
    runAnalysisAgentMock.mockImplementation(async (args: MockAgentArgs) => {
      const usage = { inputTokens: 100_000, outputTokens: 10_000 };
      args.config.costLedger?.add(usage, args.config.model);
      if (args.purpose === "verify") {
        return { findings: [fakeFinding("f1", { status: "verified" })], usage, turns: 1 };
      }
      return { findings: [fakeFinding("f1")], usage, turns: 2 };
    });

    const { events, unsubscribe } = captureBusEvents();
    try {
      await runPipeline({
        target: repoDir,
        targetType: "source-code",
        depth: "default",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        model: "claude-sonnet-4-6",
        dbPath: freshDbPath(),
      });
    } finally {
      unsubscribe();
    }

    const completed = events.filter((e) => e.type === "scan_completed");
    expect(completed).toHaveLength(1);
    const p = completed[0]!.payload;
    expect(p.exit_reason).toBe("completed");
    // The operator's model pick is stamped verbatim.
    expect(p.model).toBe("claude-sonnet-4-6");
    // Cross-session totals: research 2 turns + verify 1 turn.
    expect(p.turns_used).toBe(3);
    expect(typeof p.tool_calls_total).toBe("number");
    expect(p.findings).toBe(1);
    expect(p.findings_count).toBe(1);
    expect(typeof p.duration_ms).toBe("number");
    // True cross-session cost: 2 sessions × (100k in @ $3/M + 10k out @
    // $15/M) = 2 × $0.45 = $0.90 at claude-sonnet-4-6 rates.
    expect(p.cost_usd).toBeCloseTo(0.9, 5);
    const breakdown = p.cost_breakdown as Array<Record<string, unknown>>;
    expect(breakdown).toHaveLength(1);
    expect(breakdown[0]).toMatchObject({
      provider: "anthropic",
      model: "claude-sonnet-4-6",
    });
    expect(breakdown[0]!.cost_in as number).toBeCloseTo(0.6, 5);
    expect(breakdown[0]!.cost_out as number).toBeCloseTo(0.3, 5);
  });

  it("threads the API runtime's resolved default model into scan pricing", async () => {
    const repoDir = freshTmpDir("repo-scan-completed-default-model");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");
    process.env["0SEC_CLOUD_EVENTS"] = "1";
    runAnalysisAgentMock.mockImplementation(async (args: MockAgentArgs) => {
      expect(args.config.model).toBe("claude-fake-default");
      const usage = { inputTokens: 100_000, outputTokens: 10_000 };
      args.config.costLedger?.add(usage, args.config.model);
      return { findings: [], usage, turns: 1 };
    });

    const { events, unsubscribe } = captureBusEvents();
    try {
      await runPipeline({
        target: repoDir,
        targetType: "source-code",
        depth: "default",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        dbPath: freshDbPath(),
      });
    } finally {
      unsubscribe();
    }

    const completed = events.filter((e) => e.type === "scan_completed");
    expect(completed).toHaveLength(1);
    // FakeLlmApiRuntime.resolvedModel() stands in for an env/provider default.
    // The same resolved id must key the cost ledger, not only the completion
    // metadata; otherwise env-selected Azure scans fall back to $3/$15.
    const payload = completed[0]!.payload;
    expect(payload.model).toBe("claude-fake-default");
    expect(payload.cost_usd).toBeCloseTo(0.45, 5);
    expect(payload.cost_breakdown).toEqual([
      expect.objectContaining({
        provider: "anthropic",
        model: "claude-fake-default",
      }),
    ]);
  });

  it("cost-trip completions also carry the full field set", async () => {
    const repoDir = freshTmpDir("repo-scan-completed-cost-trip");
    writeFileSync(join(repoDir, "app.ts"), "// fixture");
    process.env["0SEC_CLOUD_EVENTS"] = "1";

    runAnalysisAgentMock.mockImplementation(async (args: MockAgentArgs) => {
      const usage = { inputTokens: 900_000, outputTokens: 60_000 };
      args.config.costLedger?.add(usage, args.config.model);
      return {
        findings: [fakeFinding("f1")],
        usage,
        turns: 4,
        costCeilingExceeded: true,
      };
    });

    const { events, unsubscribe } = captureBusEvents();
    try {
      await runPipeline({
        target: repoDir,
        targetType: "source-code",
        depth: "default",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        model: "claude-sonnet-4-6",
        costCeilingUsd: 3,
        dbPath: freshDbPath(),
      });
    } finally {
      unsubscribe();
    }

    const completed = events.filter((e) => e.type === "scan_completed");
    expect(completed).toHaveLength(1);
    const p = completed[0]!.payload;
    expect(p.exit_reason).toBe("cost_exceeded");
    expect(p.model).toBe("claude-sonnet-4-6");
    expect(p.turns_used).toBe(4);
    expect(p.cost_usd).toBeCloseTo(3.6, 5);
    expect(Array.isArray(p.cost_breakdown)).toBe(true);
  });
});

// ── Diff-aware review ───────────────────────────────────────────────────────

describe("runPipeline — diff-aware review", () => {
  /**
   * Make a real git repo with two commits and a changed file between
   * HEAD~ and HEAD. We need a real repo because `listChangedFiles`
   * shells out to `git diff` — there's no clean mock seam, and the cost
   * of `git init` in a tmp dir is negligible.
   */
  function makeRepoWithDiff(): { repoDir: string; changedFile: string } {
    const { execFileSync } = require("node:child_process") as typeof import("node:child_process");
    const repoDir = freshTmpDir("repo-diff");

    execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repoDir });
    execFileSync("git", ["config", "user.email", "test@example.invalid"], { cwd: repoDir });
    execFileSync("git", ["config", "user.name", "test"], { cwd: repoDir });
    execFileSync("git", ["config", "commit.gpgsign", "false"], { cwd: repoDir });

    writeFileSync(join(repoDir, "stable.ts"), "export const x = 1;\n");
    execFileSync("git", ["add", "."], { cwd: repoDir });
    execFileSync("git", ["commit", "-q", "-m", "base"], { cwd: repoDir });

    writeFileSync(join(repoDir, "changed.ts"), "export const y = req.body;\n");
    execFileSync("git", ["add", "."], { cwd: repoDir });
    execFileSync("git", ["commit", "-q", "-m", "feat"], { cwd: repoDir });

    return { repoDir, changedFile: "changed.ts" };
  }

  it("--diff-base threads changed-files context into the agent prompt", async () => {
    const { repoDir, changedFile } = makeRepoWithDiff();

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      diffBase: "HEAD~",
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    // The review agent prompt should include the changed file name.
    expect(args.agentSystemPrompt).toContain(changedFile);
    // CLI prompt also carries the changed-files block.
    expect(args.cliPrompt).toContain(changedFile);
  });

  it("0SEC_STATIC=semgrep with --changed-only scopes semgrep to changed files only", async () => {
    process.env["0SEC_STATIC"] = "semgrep";
    const { repoDir, changedFile } = makeRepoWithDiff();

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      diffBase: "HEAD~",
      changedOnly: true,
      dbPath: freshDbPath(),
    });

    expect(runSemgrepScanMock).toHaveBeenCalledTimes(1);
    const opts = runSemgrepScanMock.mock.calls[0]![2];
    expect(opts).toBeTruthy();
    expect((opts as { paths: string[] }).paths).toEqual([
      join(repoDir, changedFile),
    ]);
  });

  it("default foxguard with --changed-only scopes foxguard to changed files only", async () => {
    const { repoDir, changedFile } = makeRepoWithDiff();

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      diffBase: "HEAD~",
      changedOnly: true,
      dbPath: freshDbPath(),
    });

    expect(runFoxguardScanMock).toHaveBeenCalledTimes(1);
    expect(runSemgrepScanMock).not.toHaveBeenCalled();
    const opts = runFoxguardScanMock.mock.calls[0]![2];
    expect(opts).toEqual({ paths: [join(repoDir, changedFile)] });
  });

  it("missing diff-base produces a warning but the pipeline still completes", async () => {
    const repoDir = freshTmpDir("repo-baddiff");
    writeFileSync(join(repoDir, "f.ts"), "// fixture");

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      // Not a git repo → `git diff` will error → warning, not throw.
      diffBase: "nonexistent-branch",
      dbPath: freshDbPath(),
    });

    const w = report.warnings.find((x) =>
      x.message.includes("Failed to compute changed files"),
    );
    expect(w).toBeDefined();
    expect(w!.stage).toBe("analyze");
    // Pipeline did not throw — the report has a normal summary block.
    expect(report.summary.totalFindings).toBe(0);
  });
});

describe("runPipeline — conversation threading", () => {
  it("--conversation threads into the agent prompt", async () => {
    const repoDir = freshTmpDir("repo-conv");
    writeFileSync(join(repoDir, "f.ts"), "// fixture");

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      conversation: "User: Check the login handler for SQL injection",
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.agentSystemPrompt).toContain("## REVIEW CONVERSATION (UNTRUSTED)");
    expect(args.agentSystemPrompt).toContain("User: Check the login handler for SQL injection");
    expect(args.agentSystemPrompt).toContain("UNTRUSTED DATA");
  });

  it("omits conversation block when conversation is not provided", async () => {
    const repoDir = freshTmpDir("repo-noconv");
    writeFileSync(join(repoDir, "g.ts"), "// fixture");

    // Reset the mock to clear prior calls
    runAnalysisAgentMock.mockClear();

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.agentSystemPrompt).not.toContain("REVIEW CONVERSATION (UNTRUSTED)");
  });

  it("preserves hypothesis alongside conversation in the agent prompt", async () => {
    const repoDir = freshTmpDir("repo-both");
    writeFileSync(join(repoDir, "h.ts"), "// fixture");

    runAnalysisAgentMock.mockClear();

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      hypothesis: "Check the JWT validation middleware",
      conversation: "User: Look at the password reset flow",
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.agentSystemPrompt).toContain("OPERATOR HYPOTHESIS");
    expect(args.agentSystemPrompt).toContain("Check the JWT validation middleware");
    expect(args.agentSystemPrompt).toContain("## REVIEW CONVERSATION (UNTRUSTED)");
    expect(args.agentSystemPrompt).toContain("User: Look at the password reset flow");
  });
});

describe("runPipeline — prior findings context", () => {
  it("treats prior findings as untrusted variant-hunting context", async () => {
    const repoDir = freshTmpDir("repo-prior-findings");
    writeFileSync(join(repoDir, "search.ts"), "// fixture");

    runAnalysisAgentMock.mockClear();
    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      priorFindings: [
        {
          id: "prior-sqli",
          title: "SQL injection in search",
          category: "sql-injection",
          description: "Unsafe interpolation at src/search.ts:42",
          location: "src/search.ts:42",
        },
      ],
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.agentSystemPrompt).toContain("## PRIOR FINDINGS (UNTRUSTED CONTEXT)");
    expect(args.agentSystemPrompt).toContain("SQL injection in search");
    expect(args.agentSystemPrompt).toContain("Do not repeat or promote them without fresh evidence");
    expect(args.agentSystemPrompt).toContain("adjacent entry points");
    expect(args.agentSystemPrompt).not.toContain("## REVIEW CONVERSATION (UNTRUSTED)");
  });

  it("threads prior findings into profile-specific source prompts", async () => {
    const repoDir = freshTmpDir("repo-prior-findings-c-library");
    writeFileSync(join(repoDir, "parser.c"), "// fixture");

    runAnalysisAgentMock.mockClear();
    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      reviewProfile: "c-library",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      priorFindings: [
        {
          id: "prior-oob",
          title: "Out-of-bounds read in parser",
          category: "memory-safety",
          location: "src/parser.c:10",
        },
      ],
      dbPath: freshDbPath(),
    });

    const args = runAnalysisAgentMock.mock.calls[0]![0];
    expect(args.agentSystemPrompt).toContain("C/C++");
    expect(args.agentSystemPrompt).toContain("## PRIOR FINDINGS (UNTRUSTED CONTEXT)");
    expect(args.agentSystemPrompt).toContain("Out-of-bounds read in parser");
  });
});

// ── Report envelope shape ───────────────────────────────────────────────────

describe("runPipeline — report envelope", () => {
  it("empty-findings case still produces a well-formed report with zero counts", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.findings).toEqual([]);
    expect(report.summary.totalFindings).toBe(0);
    expect(report.summary.critical).toBe(0);
    expect(report.summary.high).toBe(0);
    expect(report.summary.medium).toBe(0);
    expect(report.summary.low).toBe(0);
    expect(report.summary.info).toBe(0);
    expect(typeof report.durationMs).toBe("number");
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
    expect(typeof report.startedAt).toBe("string");
    expect(typeof report.completedAt).toBe("string");
  });

  it("backwards-compat extras present for npm/pypi/cargo/oci (package + version + npmAuditFindings + semgrepFindings)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("pypi", "requests", "2.31.0"));
    runFoxguardScanMock.mockReturnValue([fakeSemgrepFinding("requests/__init__.py")]);
    runDependencyAuditMock.mockReturnValue([fakeNpmAudit("urllib3")]);

    const report = await runPipeline({
      target: "requests",
      targetType: "pypi-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    // The backwards-compat shim populates these fields for any package
    // ecosystem — downstream relays (cloud-sink, formatters) parse them.
    expect(report.package).toBe("requests");
    expect(report.version).toBe("2.31.0");
    expect(report.semgrepFindings).toBe(1);
    expect(report.npmAuditFindings).toBeDefined();
    expect(report.npmAuditFindings!).toHaveLength(1);
    // The `repo` field is NPM-side absent and source-code-side present.
    expect(report.repo).toBeUndefined();
  });

  it("findings with status='false-positive' are stripped from the final report.findings", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    // Returned in research phase; the verify phase then re-runs the agent
    // per finding. Our shared mock returns `findings: []` on the verify
    // call, which marks every research finding as `false-positive`.
    // (See unified-pipeline.ts: empty verify → rejected, routed through the
    // disclosure predicate.) These findings are low-severity / low-impact, so
    // the predicate allows the drop.
    runAnalysisAgentMock.mockResolvedValueOnce({
      findings: [
        fakeFinding("a", { severity: "low", category: "security-misconfiguration" }),
        fakeFinding("b", { severity: "low", category: "security-misconfiguration" }),
      ],
    });
    // Subsequent calls (the per-finding verify wave) default to `findings: []`
    // via the beforeEach.

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    // Both findings were rejected by the (empty-result) verify wave.
    expect(report.findings).toEqual([]);
    expect(report.summary.totalFindings).toBe(0);
  });

  it("holds a disclosure-grade finding rejected by blind verify instead of dropping it (#599)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    // Research surfaces a high-impact-class finding; the per-finding verify
    // wave returns empty (= rejected). A disclosure-grade finding must NOT be
    // silently dropped on that verdict — it is held for human review.
    runAnalysisAgentMock.mockResolvedValueOnce({
      findings: [fakeFinding("a", { severity: "critical", category: "command-injection" })],
    });

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.status).not.toBe("false-positive");
    expect(report.findings[0]!.publishability).toBe("needs_verify");
  });

  it("LlmApiRuntime constructor receives apiKey + model + timeout from PipelineOptions", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-pipeline",
      model: "test-model",
      timeout: 45_000,
      dbPath: freshDbPath(),
    });

    expect(apiRuntimeConstructorCalls).toHaveLength(1);
    expect(apiRuntimeConstructorCalls[0]).toMatchObject({
      type: "api",
      apiKey: "sk-pipeline",
      model: "test-model",
      timeout: 45_000,
    });
  });

  it("explicit local codex runtime does not construct API diagnostics", async () => {
    detectAvailableRuntimesMock.mockResolvedValue(new Set<string>(["codex"]));
    const repoDir = freshTmpDir("repo-codex-no-api");
    writeFileSync(join(repoDir, "index.ts"), "// fixture");

    await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "codex",
      dbPath: freshDbPath(),
    });

    expect(apiRuntimeConstructorCalls).toHaveLength(0);
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    expect(runAnalysisAgentMock.mock.calls[0]![0].config.runtime).toBe("codex");
  });
});
