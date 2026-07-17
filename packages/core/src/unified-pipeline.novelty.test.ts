/**
 * Public-advisory novelty gate on the OSS-package scan path (issue #851).
 *
 * The novelty gate's PRODUCER originally only ran inside `agenticScan`
 * (agentic-scanner.ts), which the CLI invokes ONLY for url/web-app targets —
 * mostly private, so the gate no-ops there. The findings that actually need the
 * gate are OSS PACKAGE findings (npm/pypi/cargo), which route through
 * `runPipeline` in unified-pipeline.ts and never hit it.
 *
 * This seed proves the wiring closed that gap: a confirmed npm-package finding
 * emerges from `runPipeline` carrying a `noveltyVerdict` + `advisoryMatches`
 * resolved against a stubbed OSV `/v1/query` response. It also asserts the two
 * guardrails that keep it safe — the gate stays OFF when the feature flag is
 * off, and no-ops (no verdict) for a non-OSV ecosystem (`oci`).
 *
 * Harness mirrors `unified-pipeline.dispatch.test.ts` (mock-at-module-boundary:
 * fake install / fake static scan / fake LLM agent / fake runtime detection),
 * plus a stubbed `globalThis.fetch` so the REAL `resolveNovelty` →
 * `queryOsvAdvisories` → `fetchJson` path runs end-to-end without a network
 * call. A unique package name avoids any stale on-disk intel cache; the home
 * intel-cache entry written for it is cleaned up in `afterEach`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { Finding } from "@pwnkit/shared";

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
  selectedStaticScanner: () => "foxguard",
  runSelectedStaticScan: (...args: unknown[]) => runFoxguardScanMock(...args),
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

// `features.publishabilityGate` is evaluated ONCE at module import (plain
// property, not a getter), so setting the env var inside a test is too late.
// Re-export the real features object but replace `publishabilityGate` with a
// live getter so each test can flip PWNKIT_FEATURE_PUBLISHABILITY_GATE and have
// the gate honor it at runtime — exactly the seam the CLI `--features` flag
// relies on for the getter-backed flags.
vi.mock("./agent/features.js", async () => {
  const actual = await vi.importActual<typeof import("./agent/features.js")>("./agent/features.js");
  return {
    ...actual,
    features: new Proxy(actual.features, {
      get(target, prop, receiver) {
        if (prop === "publishabilityGate") {
          const v = process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE;
          return v !== undefined && v !== "0" && v !== "false";
        }
        return Reflect.get(target, prop, receiver);
      },
    }),
  };
});

vi.mock("./runtime/llm-api.js", () => {
  class FakeLlmApiRuntime {
    getConfigurationDiagnostics() {
      return { valid: true, provider: "anthropic", providerLabel: "Anthropic" };
    }
    // Mirror of the real class's resolved-model getter (provider default stand-in).
    resolvedModel() {
      return "claude-fake-default";
    }
  }
  return { LlmApiRuntime: FakeLlmApiRuntime };
});

// ── Imports (after mocks) ───────────────────────────────────────────────────

const { runPipeline } = await import("./unified-pipeline.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

const tempDirs: string[] = [];

function freshTmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `pwnkit-novelty-pipeline-${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function freshDbPath(): string {
  return join(freshTmpDir("db"), "pwnkit.db");
}

function fakeInstalledPackage(
  ecosystem: "npm" | "pypi" | "cargo" | "oci",
  name: string,
  version: string,
) {
  const tempDir = freshTmpDir(`install-${ecosystem}`);
  return { ecosystem, name, version, path: tempDir, tempDir };
}

/** A high-impact finding that survives the (empty) verify wave as "held". */
function fakeHeldFinding(id: string): Finding {
  return {
    id,
    templateId: "tpl",
    title: `Finding ${id}`,
    description: `desc ${id}`,
    severity: "critical",
    category: "command-injection",
    status: "discovered",
    evidence: { request: "src/a.ts", response: "PoC body", analysis: "analysis" },
    timestamp: 0,
  };
}

/** A real-shaped OSV /v1/query hit (version-scoped): one CVE-keyed GHSA. */
const OSV_HIT = {
  vulns: [
    {
      id: "GHSA-f82v-jwr5-mffw",
      aliases: ["CVE-2025-29927"],
      summary: "Authorization Bypass",
      database_specific: { severity: "CRITICAL" },
      references: [
        { type: "ADVISORY", url: "https://github.com/advisories/GHSA-f82v-jwr5-mffw" },
      ],
      affected: [{ package: { ecosystem: "npm", name: "pwnkit-novelty-851-fixture" } }],
    },
  ],
};

/** Stub `globalThis.fetch` so the REAL resolveNovelty path hits no network. */
function stubGlobalFetch(json: unknown): typeof fetch {
  return (async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    if (/api\.osv\.dev/.test(u)) {
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        async json() { return json; },
        async text() { return JSON.stringify(json); },
      } as unknown as Response;
    }
    return { ok: false, status: 404, async json() { return {}; }, async text() { return ""; } } as unknown as Response;
  }) as unknown as typeof fetch;
}

// The unique fixture package name keeps the on-disk intel cache from colliding
// with any real entry; clean up its cache file after each test.
const FIXTURE_PKG = "pwnkit-novelty-851-fixture";

// ── Lifecycle ───────────────────────────────────────────────────────────────

let savedFetch: typeof fetch;
let savedFlag: string | undefined;
let savedPerItem: string | undefined;
let savedApiKey: string | undefined;

beforeEach(() => {
  installPackageMock.mockReset();
  runDependencyAuditMock.mockReset();
  runSemgrepScanMock.mockReset();
  runFoxguardScanMock.mockReset();
  runAnalysisAgentMock.mockReset();
  collectScopeFilesMock.mockReset();
  countScopeFilesUpToMock.mockReset();
  detectAvailableRuntimesMock.mockReset();

  runFoxguardScanMock.mockReturnValue([]);
  runDependencyAuditMock.mockReturnValue([]);
  collectScopeFilesMock.mockReturnValue([]);
  countScopeFilesUpToMock.mockReturnValue(0);
  detectAvailableRuntimesMock.mockResolvedValue(new Set<string>());
  // Research wave surfaces one high-impact finding; verify wave returns empty
  // (held, not dropped — mirrors the #599 dispatch-test path), so the finding
  // lands non-false-positive in report.findings where the gate stamps it.
  runAnalysisAgentMock.mockResolvedValueOnce({ findings: [fakeHeldFinding("a")] });
  runAnalysisAgentMock.mockResolvedValue({ findings: [] });

  savedPerItem = process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION;
  process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION = "0";
  savedApiKey = process.env.ANTHROPIC_API_KEY;
  savedFlag = process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE;

  savedFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = savedFetch;
  if (savedPerItem === undefined) delete process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION;
  else process.env.PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION = savedPerItem;
  if (savedApiKey === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = savedApiKey;
  if (savedFlag === undefined) delete process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE;
  else process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE = savedFlag;

  // Prune the fixture's intel-cache entry so a re-run never reads a stale OSV
  // body for the unique fixture package (digest = sha256 of the cache key).
  const key = JSON.stringify({ ecosystem: "npm", packageName: FIXTURE_PKG, version: "1.0.0" });
  const digest = createHash("sha256").update(key).digest("hex");
  const cacheFile = join(homedir(), ".pwnkit", "intel-cache", "osv-query", `${digest}.json`);
  if (existsSync(cacheFile)) rmSync(cacheFile, { force: true });

  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

// ── Tests ───────────────────────────────────────────────────────────────────

describe("runPipeline — novelty gate on OSS package scans (#851)", () => {
  it("stamps noveltyVerdict + advisoryMatches on a confirmed npm-package finding", async () => {
    process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE = "1";
    globalThis.fetch = stubGlobalFetch(OSV_HIT);
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", FIXTURE_PKG, "1.0.0"));

    const report = await runPipeline({
      target: FIXTURE_PKG,
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      packageVersion: "1.0.0",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.findings).toHaveLength(1);
    const finding = report.findings[0]!;
    expect(finding.status).not.toBe("false-positive");
    expect(finding.noveltyVerdict).toBe("matches-CVE-2025-29927");
    expect(finding.advisoryMatches?.[0]).toMatchObject({
      source: "CVE",
      id: "CVE-2025-29927",
    });
  });

  it("leaves the verdict unset when the publishability gate flag is off", async () => {
    delete process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE;
    // fetch would throw if the gate erroneously fired — proves no resolve ran.
    globalThis.fetch = (async () => {
      throw new Error("network must not be touched when the gate is off");
    }) as unknown as typeof fetch;
    installPackageMock.mockReturnValue(fakeInstalledPackage("npm", FIXTURE_PKG, "1.0.0"));

    const report = await runPipeline({
      target: FIXTURE_PKG,
      targetType: "npm-package",
      depth: "quick",
      format: "json",
      runtime: "api",
      packageVersion: "1.0.0",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.noveltyVerdict).toBeUndefined();
  });

  it("no-ops for an oci image (not an OSV ecosystem) — never queries the advisory DB", async () => {
    process.env.PWNKIT_FEATURE_PUBLISHABILITY_GATE = "1";
    let fetched = false;
    globalThis.fetch = (async () => {
      fetched = true;
      throw new Error("oci must not reach the public advisory DB");
    }) as unknown as typeof fetch;
    installPackageMock.mockReturnValue(fakeInstalledPackage("oci", "ghcr.io/x/y", "sha256-deadbeef"));

    const report = await runPipeline({
      target: "ghcr.io/x/y:latest",
      targetType: "oci-image",
      depth: "quick",
      format: "json",
      runtime: "api",
      apiKey: "sk-fake",
      dbPath: freshDbPath(),
    });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.noveltyVerdict).toBeUndefined();
    expect(fetched).toBe(false);
  });
});
