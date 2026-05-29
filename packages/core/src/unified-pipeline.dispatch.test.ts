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
 * The real `@pwnkit/db` is used with a tmp file (same shape as the restore
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
 *     test. We force `PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION=0` to keep
 *     these tests on the single-shot dispatch.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, NpmAuditFinding, SemgrepFinding } from "@pwnkit/shared";
import { pwnkitDB } from "@pwnkit/db";

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
  selectedStaticScanner: () => process.env.PWNKIT_STATIC === "semgrep" ? "semgrep" : "foxguard",
  runSelectedStaticScan: (...args: unknown[]) =>
    process.env.PWNKIT_STATIC === "semgrep"
      ? runSemgrepScanMock(...args)
      : runFoxguardScanMock(...args),
}));

const runAnalysisAgentMock = vi.fn();
vi.mock("./agent-runner.js", () => ({
  runAnalysisAgent: runAnalysisAgentMock,
}));

const collectScopeFilesMock = vi.fn();
vi.mock("./source-files.js", () => ({
  collectScopeFiles: collectScopeFilesMock,
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
    constructor(config: Record<string, unknown>) {
      apiRuntimeConstructorCalls.push(config);
    }
    getConfigurationDiagnostics() {
      return {
        valid: true,
        provider: "anthropic",
        providerLabel: "Anthropic",
      };
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
  const dir = mkdtempSync(join(tmpdir(), `pwnkit-unified-pipeline-${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function freshDbPath(): string {
  return join(freshTmpDir("db"), "pwnkit.db");
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
  detectAvailableRuntimesMock.mockReset();
  apiRuntimeConstructorCalls.length = 0;

  // Sensible defaults — tests can override per-test.
  runSemgrepScanMock.mockReturnValue([]);
  runFoxguardScanMock.mockReturnValue([]);
  runDependencyAuditMock.mockReturnValue([]);
  runAnalysisAgentMock.mockResolvedValue({ findings: [] });
  collectScopeFilesMock.mockReturnValue([]);
  detectAvailableRuntimesMock.mockResolvedValue(new Set<string>());

  // Force the single-shot agent path. Per-file orchestration is covered
  // by `unified-pipeline.research-loop.test.ts`; mixing both branches in
  // a single seed would obscure dispatch assertions.
  originalPerItemEnv = process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION;
  process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION = "0";

  // Some upstream prompt code reads keys for banner logic; we already
  // short-circuited the runtime, but unset to keep tests deterministic.
  originalApiKey = process.env.ANTHROPIC_API_KEY;
  originalStaticAnalyzer = process.env.PWNKIT_STATIC;
  originalCloudEvents = process.env.PWNKIT_CLOUD_EVENTS;
  delete process.env.PWNKIT_STATIC;
  delete process.env.PWNKIT_CLOUD_EVENTS;
});

afterEach(() => {
  if (originalPerItemEnv === undefined) {
    delete process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION;
  } else {
    process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION = originalPerItemEnv;
  }
  if (originalApiKey === undefined) {
    delete process.env.ANTHROPIC_API_KEY;
  } else {
    process.env.ANTHROPIC_API_KEY = originalApiKey;
  }
  if (originalStaticAnalyzer === undefined) {
    delete process.env.PWNKIT_STATIC;
  } else {
    process.env.PWNKIT_STATIC = originalStaticAnalyzer;
  }
  if (originalCloudEvents === undefined) {
    delete process.env.PWNKIT_CLOUD_EVENTS;
  } else {
    process.env.PWNKIT_CLOUD_EVENTS = originalCloudEvents;
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
    // matching the public CLI contract `pwnkit run node-forge@0.10.0`.
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

    const db = new pwnkitDB(dbPath);
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
    process.env.PWNKIT_CLOUD_EVENTS = "1";
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

  it("source-code: PWNKIT_STATIC=semgrep routes static analysis to semgrep", async () => {
    process.env.PWNKIT_STATIC = "semgrep";
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

    const db = new pwnkitDB(dbPath);
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

  it("PWNKIT_STATIC=semgrep with --changed-only scopes semgrep to changed files only", async () => {
    process.env.PWNKIT_STATIC = "semgrep";
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
