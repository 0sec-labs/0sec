/**
 * Regression coverage for #402: `--runtime codex` parity across the
 * non-web ecosystems (npm / pypi / cargo audit + linux-kernel review).
 *
 * Before the fix, `runPipeline` short-circuited with
 *
 *    "Requested runtime 'codex' is not available. AI analysis skipped."
 *
 * whenever the operator passed `--runtime codex` without the `codex` CLI
 * binary on PATH — even if `0SEC_CHATGPT_ACCESS_TOKEN` or
 * `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` was set. That gate lived in
 * `hasRequestedAnalysisRuntime` (and the parallel verify-stage selector),
 * which only consulted the installed-CLI registry and ignored the direct
 * ChatGPT Codex provider that the API runtime supports.
 *
 * These tests pin the post-fix invariant: when the LlmApiRuntime reports
 * `provider: "chatgpt-codex"`, the pipeline accepts `--runtime codex`
 * and reaches the agent stage for every package-ecosystem target and
 * the linux-kernel review path. We do not exercise a real Codex
 * subprocess — the agent runner is mocked, so we're verifying *gate
 * survival*, not the loop body. The native-loop wiring is covered by
 * `agentic-scanner.events.test.ts` ("routes explicit codex live scans
 * through the direct ChatGPT Codex provider when configured").
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// Same shape as `unified-pipeline.dispatch.test.ts`, with one swap:
// `LlmApiRuntime.getConfigurationDiagnostics()` returns the
// chatgpt-codex provider so the pipeline takes the "direct ChatGPT Codex
// provider is configured" branch added in #402.

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

vi.mock("./runtime/llm-api.js", () => {
  // Crucial difference vs `unified-pipeline.dispatch.test.ts`: this mock
  // reports `provider: "chatgpt-codex"`, which is what the operator's
  // 0SEC_CHATGPT_*_TOKEN env produces in real life. The new gate in
  // unified-pipeline.ts treats this as "codex is available via the
  // direct ChatGPT provider" and proceeds even when the codex CLI
  // binary is absent.
  class FakeLlmApiRuntime {
    constructor() {}
    getConfigurationDiagnostics() {
      return {
        valid: true,
        provider: "chatgpt-codex",
        providerLabel: "ChatGPT (Codex backend)",
      };
    }
    // Mirror of the real class's resolved-model getter (chatgpt-codex
    // provider default stand-in).
    resolvedModel() {
      return "gpt-fake-codex";
    }
  }
  return { LlmApiRuntime: FakeLlmApiRuntime };
});

const { runPipeline } = await import("./unified-pipeline.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

const tempDirs: string[] = [];

function freshTmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `0sec-codex-runtime-${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function freshDbPath(): string {
  return join(freshTmpDir("db"), "0sec.db");
}

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

// ── Lifecycle ───────────────────────────────────────────────────────────────

let originalPerItemEnv: string | undefined;
let originalStaticAnalyzer: string | undefined;

beforeEach(() => {
  installPackageMock.mockReset();
  runDependencyAuditMock.mockReset();
  runSemgrepScanMock.mockReset();
  runFoxguardScanMock.mockReset();
  runAnalysisAgentMock.mockReset();
  collectScopeFilesMock.mockReset();
  countScopeFilesUpToMock.mockReset();
  detectAvailableRuntimesMock.mockReset();

  runSemgrepScanMock.mockReturnValue([]);
  runFoxguardScanMock.mockReturnValue([]);
  runDependencyAuditMock.mockReturnValue([]);
  runAnalysisAgentMock.mockResolvedValue({ findings: [] });
  collectScopeFilesMock.mockReturnValue([]);
  countScopeFilesUpToMock.mockReturnValue(0);
  // CRITICAL: simulate "codex CLI binary not installed". The whole point
  // of #402 is that subscription auth alone should be enough — the
  // pipeline must NOT need the `codex` CLI on PATH to honour
  // `--runtime codex`.
  detectAvailableRuntimesMock.mockResolvedValue(new Set<string>());

  originalPerItemEnv = process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"];
  process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"] = "0";

  originalStaticAnalyzer = process.env["0SEC_STATIC"];
  delete process.env["0SEC_STATIC"];
});

afterEach(() => {
  if (originalPerItemEnv === undefined) {
    delete process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"];
  } else {
    process.env["0SEC_FEATURE_PER_ITEM_ORCHESTRATION"] = originalPerItemEnv;
  }
  if (originalStaticAnalyzer === undefined) {
    delete process.env["0SEC_STATIC"];
  } else {
    process.env["0SEC_STATIC"] = originalStaticAnalyzer;
  }
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
});

// ── Per-ecosystem parity ────────────────────────────────────────────────────

describe("runPipeline — --runtime codex parity (#402)", () => {
  it("npm: --runtime codex reaches the agent stage when chatgpt-codex provider is configured", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "codex",
      dbPath: freshDbPath(),
    });

    // The agent stage was reached — the codex gate did not abort the pipeline.
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    expect(runAnalysisAgentMock.mock.calls[0]![0].config.runtime).toBe("codex");
    // No "Requested runtime 'codex' is not available" warning was emitted.
    const skipWarning = report.warnings.find((w) =>
      w.message.includes("Requested runtime 'codex' is not available"),
    );
    expect(skipWarning).toBeUndefined();
  });

  it("pypi: --runtime codex reaches the agent stage when chatgpt-codex provider is configured", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("pypi", "requests", "2.31.0"));

    const report = await runPipeline({
      target: "requests",
      targetType: "pypi-package",
      depth: "quick",
      format: "json",
      runtime: "codex",
      dbPath: freshDbPath(),
    });

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    expect(runAnalysisAgentMock.mock.calls[0]![0].config.runtime).toBe("codex");
    const skipWarning = report.warnings.find((w) =>
      w.message.includes("Requested runtime 'codex' is not available"),
    );
    expect(skipWarning).toBeUndefined();
  });

  it("cargo: --runtime codex reaches the agent stage when chatgpt-codex provider is configured", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("cargo", "tokio", "1.35.0"));

    const report = await runPipeline({
      target: "tokio",
      targetType: "cargo-package",
      depth: "quick",
      format: "json",
      runtime: "codex",
      dbPath: freshDbPath(),
    });

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    expect(runAnalysisAgentMock.mock.calls[0]![0].config.runtime).toBe("codex");
    const skipWarning = report.warnings.find((w) =>
      w.message.includes("Requested runtime 'codex' is not available"),
    );
    expect(skipWarning).toBeUndefined();
  });

  it("kernel review: --profile linux-kernel + --runtime codex reaches the review agent", async () => {
    const repoDir = freshTmpDir("kernel-repo");
    writeFileSync(join(repoDir, "core.c"), "// fixture");

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "codex",
      reviewProfile: "linux-kernel",
      dbPath: freshDbPath(),
    } as any);

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    const call = runAnalysisAgentMock.mock.calls[0]![0];
    expect(call.role).toBe("review");
    expect(call.config.runtime).toBe("codex");
    // The kernel review profile still applies — its prompt mentions
    // distinctive kernel-aware terms.
    expect(call.agentSystemPrompt.toLowerCase()).toMatch(/kernel|syscall|copy_from_user/);
    const skipWarning = report.warnings.find((w) =>
      w.message.includes("Requested runtime 'codex' is not available"),
    );
    expect(skipWarning).toBeUndefined();
  });

  it("default source-code review: --runtime codex reaches the review agent", async () => {
    const repoDir = freshTmpDir("default-repo");
    writeFileSync(join(repoDir, "index.ts"), "// fixture");

    const report = await runPipeline({
      target: repoDir,
      targetType: "source-code",
      depth: "quick",
      format: "json",
      runtime: "codex",
      dbPath: freshDbPath(),
    });

    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(1);
    expect(runAnalysisAgentMock.mock.calls[0]![0].role).toBe("review");
    expect(runAnalysisAgentMock.mock.calls[0]![0].config.runtime).toBe("codex");
    const skipWarning = report.warnings.find((w) =>
      w.message.includes("Requested runtime 'codex' is not available"),
    );
    expect(skipWarning).toBeUndefined();
  });
});

// ── Verify-stage parity ─────────────────────────────────────────────────────

describe("runPipeline — verify stage runtime selection under --runtime codex", () => {
  it("verify uses 'codex' when chatgpt-codex is configured (does not collapse to null)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", "lodash", "4.17.21"));

    // Research returns one finding; the verify stage then re-invokes
    // `runAnalysisAgent` per finding. With the #402 fix, the verify
    // runtime should be "codex" (routed through the API runtime by
    // `agent-runner.ts`), not `null` (which would mark the finding
    // false-positive without verification).
    runAnalysisAgentMock.mockResolvedValueOnce({
      findings: [
        {
          id: "f1",
          templateId: "tpl",
          title: "finding 1",
          description: "d",
          severity: "high",
          category: "code-injection",
          status: "discovered",
          evidence: { request: "src/a.ts", response: "PoC", analysis: "a" },
          timestamp: 0,
        } as any,
      ],
    });
    // Second call = verify wave; return an empty finding list so the
    // pipeline marks the finding false-positive *after* actually
    // running verification (not because no verifier exists).
    runAnalysisAgentMock.mockResolvedValueOnce({ findings: [] });

    const report = await runPipeline({
      target: "lodash",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "codex",
      dbPath: freshDbPath(),
    });

    // Two agent calls: research + verify (per-finding).
    expect(runAnalysisAgentMock).toHaveBeenCalledTimes(2);
    const verifyCall = runAnalysisAgentMock.mock.calls[1]![0];
    expect(verifyCall.purpose).toBe("verify");
    expect(verifyCall.config.runtime).toBe("codex");
    // No "no verifier runtime available" warning.
    const noVerifierWarn = report.warnings.find((w) =>
      w.message.includes("no verifier runtime is available"),
    );
    expect(noVerifierWarn).toBeUndefined();
  });
});
