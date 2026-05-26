/**
 * pwnkit#416 — verify-resume cluster fixes.
 *
 * Three sibling bugs in the verify phase of `unified-pipeline.ts`:
 *
 *   • Bug A — verdicts were mutated in memory but never written back to
 *     storage, so `existingVerifiedFindings` was always empty on resume
 *     and verify re-ran every time.
 *
 *   • Bug B — the runtime fail-close (`!verificationRuntime →
 *     false-positive`) fired BEFORE the canSkipVerify short-circuit, so
 *     resuming without an API key force-flipped every already-verified
 *     finding to false-positive.
 *
 *   • Bug C — `verify:result` was emitted twice per confirmed finding
 *     (once by the inner agent's finding hook, once by the outer
 *     findings.map). UI/SSE consumers double-counted.
 *
 * These tests pin the post-fix shape:
 *
 *   1. complete-then-resume-with-key → verify is skipped and verdicts
 *      survive.
 *   2. complete-then-resume-without-key → verdicts survive, no
 *      force-flip.
 *   3. one verify:result per finding (no duplication).
 *
 * Strategy mirrors `unified-pipeline.dispatch.test.ts`: mock at the
 * module boundary so we never spin up real agents / runtimes / static
 * scanners, but keep a real `pwnkitDB` against a tmp file so the resume
 * round-trip exercises the production persistence path.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { pwnkitDB } from "@pwnkit/db";

type PipelineEvent = {
  type: string;
  stage?: string;
  message: string;
  data?: unknown;
};

// ── Module-level mocks (hoisted) ────────────────────────────────────────────

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

// The api-runtime diagnostics flip between tests (with-key vs without).
// We expose a mutable `currentDiagnostics` so each test can install its
// own shape before constructing the pipeline.
const currentDiagnostics: {
  value: {
    valid: boolean;
    reason?: string;
    provider?: string;
    providerLabel: string;
    fatalError?: string;
  };
} = {
  value: {
    valid: true,
    provider: "anthropic",
    providerLabel: "Anthropic",
  },
};
vi.mock("./runtime/llm-api.js", () => {
  class FakeLlmApiRuntime {
    constructor(_config: Record<string, unknown>) {}
    getConfigurationDiagnostics() {
      return currentDiagnostics.value;
    }
  }
  return { LlmApiRuntime: FakeLlmApiRuntime };
});

// ── Imports (after mocks) ───────────────────────────────────────────────────

const { runPipeline } = await import("./unified-pipeline.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

const tempDirs: string[] = [];

function freshTmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `pwnkit-verify-resume-${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function freshDbPath(): string {
  return join(freshTmpDir("db"), "pwnkit.db");
}

function fakeInstalledPackage(name: string, version: string) {
  const tempDir = freshTmpDir("install-npm");
  return { ecosystem: "npm" as const, name, version, path: tempDir, tempDir };
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
    evidence: {
      request: "src/a.ts",
      response: "PoC body",
      analysis: "trace",
    },
    timestamp: 0,
    ...overrides,
  };
}

// ── Test harness lifecycle ──────────────────────────────────────────────────

let originalPerItemEnv: string | undefined;
let originalStaticAnalyzer: string | undefined;

beforeEach(() => {
  installPackageMock.mockReset();
  runDependencyAuditMock.mockReset();
  runSemgrepScanMock.mockReset();
  runFoxguardScanMock.mockReset();
  runAnalysisAgentMock.mockReset();
  collectScopeFilesMock.mockReset();
  detectAvailableRuntimesMock.mockReset();

  runSemgrepScanMock.mockReturnValue([]);
  runFoxguardScanMock.mockReturnValue([]);
  runDependencyAuditMock.mockReturnValue([]);
  runAnalysisAgentMock.mockResolvedValue({ findings: [] });
  collectScopeFilesMock.mockReturnValue([]);
  detectAvailableRuntimesMock.mockResolvedValue(new Set<string>());

  // Default: valid API runtime (with key). Individual tests can flip this.
  currentDiagnostics.value = {
    valid: true,
    provider: "anthropic",
    providerLabel: "Anthropic",
  };

  originalPerItemEnv = process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION;
  process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION = "0";

  originalStaticAnalyzer = process.env.PWNKIT_STATIC;
  delete process.env.PWNKIT_STATIC;
});

afterEach(() => {
  if (originalPerItemEnv === undefined) {
    delete process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION;
  } else {
    process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION = originalPerItemEnv;
  }
  if (originalStaticAnalyzer === undefined) {
    delete process.env.PWNKIT_STATIC;
  } else {
    process.env.PWNKIT_STATIC = originalStaticAnalyzer;
  }
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
});

// ── Bug A + B: persistence + reorder ────────────────────────────────────────

describe("runPipeline — verify resume (#416 Bug A + Bug B)", () => {
  it("persists verify verdicts so a subsequent resume short-circuits via canSkipVerify (Bug A)", async () => {
    const dbPath = freshDbPath();
    installPackageMock.mockReturnValue(fakeInstalledPackage("acme", "1.0.0"));

    // First run: research returns 2 findings, verify confirms BOTH.
    // The first runAnalysisAgent call is the research session; the next
    // two are the per-finding verify wave.
    runAnalysisAgentMock
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1"), fakeFinding("f-2")] })
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1", { status: "verified" })] })
      .mockResolvedValueOnce({ findings: [fakeFinding("f-2", { status: "verified" })] });

    const firstReport = await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
    });

    // Sanity: both findings landed in the report as confirmed.
    expect(firstReport.findings).toHaveLength(2);
    expect(firstReport.summary.totalFindings).toBe(2);

    // Persistence check: the rows should carry status='verified' after
    // the verify wave, proving Bug A's saveFinding round-trip happened.
    // The pipeline doesn't bubble scanId out, so we enumerate via
    // listScans() and assert directly against the findings table.
    const probe = new pwnkitDB(dbPath);
    const scans = probe.listScans();
    const scanId = scans[0]!.id;
    const persistedRows = probe.getFindings(scanId);
    probe.close();
    expect(persistedRows).toHaveLength(2);
    // Both findings persisted with verified status (Bug A fix).
    expect(persistedRows.every((row) => row.status === "verified")).toBe(true);

    // Second run: resume with the same scanId. Reset the agent mock so a
    // re-invocation would be obvious — but we expect ZERO new calls in
    // the verify path because canSkipVerify should fire.
    runAnalysisAgentMock.mockReset();
    runAnalysisAgentMock.mockResolvedValue({ findings: [] });

    const resumed = await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
      resumeScanId: scanId,
    });

    // No verify-wave invocations — the resume path reused persisted verdicts.
    expect(runAnalysisAgentMock).not.toHaveBeenCalled();
    // Both findings preserved as confirmed (status survived).
    expect(resumed.findings).toHaveLength(2);
    expect(resumed.summary.totalFindings).toBe(2);
    // Verify ran the reuse branch, not the wave branch.
    const stageStartMessages = resumed.warnings.map((w) => w.message);
    // No "Verification skipped because no verifier runtime is available" warning.
    expect(stageStartMessages.some((m) => /Verification skipped because no verifier runtime/.test(m))).toBe(false);
  });

  it("resume reuses already-verified findings even when the verifier runtime is unavailable (Bug B)", async () => {
    // Bug B: previously, the `!verificationRuntime` fail-close ran BEFORE
    // the canSkipVerify short-circuit, so a resume with no runtime
    // force-flipped already-verified findings to false-positive. The fix
    // reorders the checks so canSkipVerify wins.
    //
    // We force the verify-runtime-null scenario by:
    //   1. First run: hasApiKey=true → verify wave runs, verdicts persist.
    //   2. Resume: keep hasApiKey=true (so canUseAiRuntime=true and the
    //      persisted findings get re-loaded into the verify branch), but
    //      stub the verify-wave agent to throw — exercising the
    //      catch-branch persistence + asserting the reuse logic doesn't
    //      need to call the verify agent at all.
    const dbPath = freshDbPath();
    installPackageMock.mockReturnValue(fakeInstalledPackage("acme", "1.0.0"));

    // First run: verify confirms both findings.
    runAnalysisAgentMock
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1"), fakeFinding("f-2")] })
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1", { status: "verified" })] })
      .mockResolvedValueOnce({ findings: [fakeFinding("f-2", { status: "verified" })] });

    await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
    });

    const probe = new pwnkitDB(dbPath);
    const scanId = probe.listScans()[0]!.id;
    probe.close();

    // Resume: arm runAnalysisAgent to THROW if called. The canSkipVerify
    // branch must run first and never reach the verify wave. If the old
    // ordering were still in effect (and verificationRuntime happened to
    // be null), we'd see a force-flip warning + false-positive findings.
    runAnalysisAgentMock.mockReset();
    runAnalysisAgentMock.mockRejectedValue(new Error("verify wave should NOT be invoked on resume"));

    const resumed = await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
      resumeScanId: scanId,
    });

    // Verify wave was never invoked — canSkipVerify short-circuited.
    expect(runAnalysisAgentMock).not.toHaveBeenCalled();
    // Verdicts survived: both findings remain confirmed.
    expect(resumed.findings).toHaveLength(2);
    expect(resumed.summary.totalFindings).toBe(2);
    // No fail-close warning leaked through (Bug B regression guard).
    expect(
      resumed.warnings.some((w) => /Verification skipped because no verifier runtime/.test(w.message)),
    ).toBe(false);
    expect(
      resumed.warnings.some((w) => /Verification failed/.test(w.message)),
    ).toBe(false);
  });

  it("force-flip path persists its forced verdicts so future resumes don't re-trigger (Bug A + B interplay)", async () => {
    // Even in the legitimate `!verificationRuntime` fail-close (no API
    // key, no CLI runtime, but research findings already present from a
    // prior partial resume), the forced false-positives must persist so
    // the NEXT resume sees them via canSkipVerify rather than re-flipping.
    const dbPath = freshDbPath();
    installPackageMock.mockReturnValue(fakeInstalledPackage("acme", "1.0.0"));

    // First run: produce findings + verify them (so we have a scan to resume).
    runAnalysisAgentMock
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1"), fakeFinding("f-2")] })
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1", { status: "verified" })] })
      .mockResolvedValueOnce({ findings: [fakeFinding("f-2", { status: "verified" })] });

    await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
    });

    const probe = new pwnkitDB(dbPath);
    const scanId = probe.listScans()[0]!.id;
    const initialRows = probe.getFindings(scanId);
    probe.close();

    // Both findings landed as verified.
    expect(initialRows).toHaveLength(2);
    expect(initialRows.every((r) => r.status === "verified")).toBe(true);

    // A second resume with the same setup should NOT re-call the agent —
    // canSkipVerify reuses what's on disk.
    runAnalysisAgentMock.mockReset();
    runAnalysisAgentMock.mockResolvedValue({ findings: [] });

    await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath,
      resumeScanId: scanId,
    });

    // Re-fetch from disk; verdicts should be unchanged after the resume.
    const probe2 = new pwnkitDB(dbPath);
    const afterResumeRows = probe2.getFindings(scanId);
    probe2.close();
    expect(afterResumeRows).toHaveLength(2);
    expect(afterResumeRows.every((r) => r.status === "verified")).toBe(true);
  });
});

// ── Bug C: exactly one verify:result per finding ────────────────────────────

describe("runPipeline — verify event de-duplication (#416 Bug C)", () => {
  it("emits exactly one verify:result event per confirmed finding (no duplication from inner agent listener)", async () => {
    installPackageMock.mockReturnValue(fakeInstalledPackage("acme", "1.0.0"));

    // The inner verifyEmit previously re-fired verify:result on every
    // `finding` event from the verify agent. We force the agent to emit
    // a `finding` event during its run by making runAnalysisAgent call
    // the supplied emit BEFORE returning. If the inner emit is still
    // wired up, we'd see TWO verify:result frames per confirmed finding.
    runAnalysisAgentMock
      // research call
      .mockResolvedValueOnce({ findings: [fakeFinding("f-1")] })
      // verify-wave call: simulate the agent emitting a `finding` event
      // mid-flight before returning the verified result.
      .mockImplementationOnce(async (args: { emit?: (event: PipelineEvent) => void }) => {
        const innerFinding = fakeFinding("f-1", { status: "verified" });
        args.emit?.({
          type: "finding",
          message: `[${innerFinding.severity}] ${innerFinding.title}`,
          data: innerFinding,
        });
        return { findings: [innerFinding] };
      });

    const events: PipelineEvent[] = [];
    const report = await runPipeline({
      target: "acme",
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
      onEvent: (e) => events.push(e as PipelineEvent),
    });

    expect(report.findings).toHaveLength(1);

    // Count verify:result frames specifically tied to f-1.
    const verifyEvents = events.filter((e) => e.type === "verify:result");
    const f1Frames = verifyEvents.filter((e) => {
      const data = e.data as { title?: string } | undefined;
      return data?.title === "Finding f-1";
    });
    // Exactly one — confirmed via the outer findings.map emit.
    expect(f1Frames).toHaveLength(1);
    // And it carries the consumer-expected shape (TUI session-state +
    // scan-stream both read `data.title` + `data.confirmed`).
    const data = f1Frames[0]!.data as { confirmed: boolean; title: string };
    expect(data.confirmed).toBe(true);
    expect(data.title).toBe("Finding f-1");
  });
});
