import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import type {
  ScanDepth,
  OutputFormat,
  RuntimeMode,
  ScanMode,
  Finding,
  FindingWorkflowStatus,
  LayerVerdict,
  NpmAuditFinding,
  PocStep,
  SeedFinding,
  SemgrepFinding,
  ScanConfig,
} from "@pwnkit/shared";
import type { InferSelectModel } from "drizzle-orm";
import type * as dbSchema from "@pwnkit/db";
import type { ScanListener } from "./scanner.js";
import { runAnalysisAgent } from "./agent-runner.js";
import { cloneGitRepo } from "./repo-clone.js";
import { ScanCostLedger } from "./agent/cost-ledger.js";
import { auditAgentPrompt, reviewAgentPrompt } from "./analysis-prompts.js";
import { cppReviewAgentPrompt } from "./review/c-cpp-profile.js";
import { kernelReviewAgentPrompt } from "./review/linux-kernel-profile.js";
import { cardanoOnchainReviewAgentPrompt } from "./review/cardano-onchain-profile.js";
import { solanaOnchainReviewAgentPrompt } from "./review/solana-onchain-profile.js";
import { cardanoHaskellReviewAgentPrompt } from "./review/cardano-haskell-profile.js";
import { evmOnchainReviewAgentPrompt } from "./review/evm-onchain-profile.js";
import { cairoOnchainReviewAgentPrompt } from "./review/cairo-onchain-profile.js";
import { moveOnchainReviewAgentPrompt } from "./review/move-onchain-profile.js";
import { generateHaskellSeeds } from "./review/haskell-seeds.js";
import { generateEvmSeeds } from "./review/evm-seeds.js";
import { xnuKernelReviewAgentPrompt } from "./review/xnu-kernel-profile.js";
import { xnuReReviewAgentPrompt } from "./review/xnu-re-profile.js";
import { enumerateAttackSurfaces, formatAttackSurfaceForPrompt } from "./kernel/index.js";
import { researchPrompt, researchPromptSingleFile, blindVerifyPrompt } from "./agent/prompts.js";
import { isDisclosureWorthy, evidenceKindForFinding } from "./triage/verify-verdict.js";
import type { VerifyVerdict } from "./triage/verify-verdict.js";
import { runNpmDynamicDiscovery } from "./stages/npm-dynamic-discovery.js";
import { createSandboxPackageRunner } from "./stages/npm-detectors/sandbox-probe.js";
import type { NpmPackageRunner } from "./stages/npm-detectors/sandbox-probe.js";
import { resolveNovelty } from "./triage/index.js";
import { runSelectedStaticScan, selectedStaticScanner } from "./shared-analysis.js";
import { collectScopeFiles, countScopeFilesUpTo } from "./source-files.js";
import { features as agentFeatures } from "./agent/features.js";
import { relative as pathRelative } from "node:path";
import { detectAvailableRuntimes } from "./runtime/registry.js";
import type { RuntimeType } from "./runtime/types.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import type { ApiRuntimeDiagnostics } from "./runtime/llm-api.js";
import {
  installPackageForEcosystem,
  runDependencyAuditForEcosystem,
  type InstalledPackage,
} from "./package-ecosystems.js";
import {
  isExistingLocalTargetPath,
  isExplicitLocalTargetPath,
  resolveLocalTargetPath,
} from "./path-resolution.js";
import { eventBus, isCloudEventSinkActive } from "./events/bus.js";

/**
 * Default ceiling on how many source files a `review` (source-code) target may
 * contain before the pipeline refuses to run. A whole-repo review feeds the
 * tree to a single agent session under a fixed time budget (default 300s); on
 * an oversized target (e.g. `torvalds/linux`, ~80k source files) the session
 * burns the entire budget producing 0 tokens + 0 findings, then times out
 * silently. We'd rather fail fast with an actionable error telling the
 * operator to scope to a subsystem/path. Overridable via
 * `PWNKIT_REVIEW_MAX_FILES`. 5000 catches the kernel while leaving any normal
 * library / service repo (typically well under ~2k source files) untouched.
 */
const REVIEW_MAX_FILES = 5000;

/** Resolve the review file-count cap, honoring `PWNKIT_REVIEW_MAX_FILES`. */
function reviewMaxFiles(): number {
  const raw = process.env.PWNKIT_REVIEW_MAX_FILES;
  if (raw !== undefined) {
    const parsed = Number.parseInt(raw, 10);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return REVIEW_MAX_FILES;
}

// ── Public types ──

export interface PipelineOptions {
  target: string;
  targetType?: "npm-package" | "pypi-package" | "cargo-package" | "oci-image" | "source-code" | "url" | "web-app";
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  mode?: ScanMode;
  resumeScanId?: string;
  diffBase?: string;
  changedOnly?: boolean;
  onEvent?: (event: { type: string; stage?: string; message: string; data?: unknown }) => void;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  timeout?: number;
  packageVersion?: string;
  costCeilingUsd?: number;
  /**
   * Review profile (only consulted when targetType === "source-code").
   * - `default`: web/JS/TS/Python application-layer review.
   * - `c-library`: foundational C/C++ libraries — memory safety, integer
   *   bugs, allocation paths. Pairs with the tier-1/2/3 harness scaffolder.
   * - `linux-kernel`: Linux kernel source review — syscall/ioctl/netlink
   *   surface, copy_from_user discipline, refcount races, skb cow/share
   *   violations (Dirty Frag class). Static-only; verification via #271/#272.
   */
  reviewProfile?: "default" | "c-library" | "linux-kernel" | "cardano-onchain" | "solana-onchain" | "evm-onchain" | "cairo-onchain" | "move-onchain" | "cardano-haskell" | "xnu-kernel" | "xnu-re";
  /**
   * Review the SOURCE of a published package. When set, `target` is a
   * package NAME (not a repo path / git URL): the pipeline installs the
   * package via the ecosystem installer (npm/pypi/cargo/oci), then reviews
   * its extracted source tree. Crucially `resolvedType` stays
   * `"source-code"` so the full review pipeline applies (profile prompt,
   * review report, "review" resume-session key) — unlike `targetType`
   * package kinds, which key the analysis to the audit path. Only consulted
   * when `targetType === "source-code"` (the `review` command sets both).
   * `packageVersion` pins the version; unset installs latest.
   */
  reviewPackageEcosystem?: "npm" | "pypi" | "cargo" | "oci";
  /**
   * Restrict the kernel-review agent to files under this subdirectory
   * (e.g. `crypto/`, `net/tcp/`). Only meaningful when
   * `reviewProfile === "linux-kernel"`. Injected into the agent prompt
   * as a hard scope restriction.
   */
  subsystem?: string;
  /**
   * Operator hypothesis to seed the agent with a specific research direction.
   * Injected at the top of the agent's system prompt as a priority investigation
   * target. Works with all review profiles (default, c-library, linux-kernel).
   * Modeled after Xint Code's operator prompt that found CVE-2026-31431.
   */
  hypothesis?: string;
  /**
   * External candidate vulnerable spans (e.g. from `gemmaforge scan`) to seed
   * the review agent's worklist alongside — or instead of — semgrep. Each
   * record carries its own source tag, so provenance survives into the agent
   * prompt and downstream reports. Closes pwnkit#368.
   */
  seedFindings?: SeedFinding[];
  /**
   * Skip semgrep entirely and let `seedFindings` be the sole source of leads.
   * No-op when `seedFindings` is empty (the pipeline falls back to semgrep
   * automatically, since "no leads" is worse than "best-effort leads").
   */
  seedOnly?: boolean;
  /**
   * OPT-IN: run the npm dynamic-discovery detector sweep (SSPP fuzz /
   * validation read-stability / SSRF parser-diff) over the target package, in
   * addition to the static review agent. Only effective for npm-ecosystem
   * targets (`--ecosystem npm` package-source reviews or `npm-package` audits).
   * Off by default (extra install + untrusted-exec cost); also enabled by the
   * `PWNKIT_NPM_DYNAMIC_DISCOVERY` env toggle for cloud config. Confirmed leads
   * join `findings` so they flow into the same verify → disclosure path.
   */
  npmDynamicDiscovery?: boolean;
  /**
   * Test/worker seam: inject the per-package sandbox runner the dynamic-discovery
   * stage uses. Unset ⇒ the default local sandbox runner (fresh temp dir +
   * child-process harness). The cloud worker injects an e2b-backed runner.
   */
  npmDynamicRunner?: NpmPackageRunner;
}

export interface PipelineReport {
  target: string;
  targetType: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  summary: {
    totalAttacks: number;
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: Finding[];
  warnings: Array<{ stage: string; message: string }>;
  /**
   * True when the run terminated early because the shared per-scan cost
   * ceiling (`--cost-ceiling` / PWNKIT_COST_CEILING_USD) was reached —
   * research tripped it or the verify wave was skipped/truncated on budget.
   * The CLI maps this to exit code 4 and the cloud lands the scan
   * `cost_exceeded` (never a clean pass). Absent on normal completions.
   */
  costCeilingExceeded?: boolean;
  /** Terminal reason; mirrors the agentic-scanner report contract. */
  exitReason?: "completed" | "cost_ceiling_exceeded";
  // Extras for backwards compat
  package?: string;
  version?: string;
  repo?: string;
  semgrepFindings?: number;
  npmAuditFindings?: NpmAuditFinding[];
}

// ── Internal helpers ──

/**
 * Parse the `--subsystem` flag value into an array of subsystem directory
 * paths. Supports comma-separated values (e.g. `crypto/,net/xfrm/`) for
 * cross-subsystem hypotheses. Each path is normalised: leading/trailing
 * whitespace is stripped, and a trailing `/` is ensured.
 *
 * Exported for tests.
 */
export function parseSubsystems(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => (s.endsWith("/") ? s : `${s}/`));
}

/**
 * Resolve the effective review scope when a single `--subsystem` path is given
 * on a NON-kernel source review. Narrows `<scopePath>/<subsystem>` when that
 * subtree exists, so the oversized-review guard, semgrep, and the review agent
 * all operate on the subsystem instead of the whole monorepo.
 *
 * Previously the subsystem hint was applied only for the linux-kernel profile
 * (which does its own semgrep path-scoping + prompt threading), so a
 * `--subsystem` on a large monorepo under any other profile was silently
 * ignored — scopePath stayed the whole repo and the file-count guard rejected
 * targets like `dotnet/runtime`. Returns null when no narrowing applies: no
 * subsystem, multiple subsystems (kept whole-repo), a kernel profile, or a
 * missing subtree. Exported for tests.
 */
export function resolveSubsystemScope(
  scopePath: string,
  subsystem: string | undefined,
  reviewProfile: string | undefined,
): string | null {
  if (!subsystem) return null;
  if (reviewProfile === "linux-kernel" || reviewProfile === "xnu-kernel") {
    return null;
  }
  const subs = parseSubsystems(subsystem);
  if (subs.length !== 1) return null;
  const subPath = join(scopePath, subs[0]);
  return existsSync(subPath) ? subPath : null;
}

function shouldEmitPipelineCloudEvents(): boolean {
  if (isCloudEventSinkActive()) return true;
  const flag = process.env.PWNKIT_CLOUD_EVENTS;
  return !!flag && flag !== "0" && flag.toLowerCase() !== "false";
}

/**
 * Convert external `SeedFinding[]` (from `--seed-findings`) into the
 * `SemgrepFinding` shape the review pipeline already consumes everywhere
 * downstream (prompt builders, persistence, the finding-table renderer).
 *
 * This keeps the agent-prompt code path uniform: the agent sees a single
 * ranked list of leads and doesn't care which producer they came from.
 * Provenance is preserved in two places:
 *   - `ruleId` is prefixed with the producer source (e.g.
 *     `gemmaforge.CWE-89`) so the prompt visibly cites it.
 *   - `metadata` carries the full producer payload (gemmaforge_confidence,
 *     gemmaforge_layer, model_id) for any downstream renderer that wants
 *     to surface it.
 *
 * Severity is bucketed from the producer's confidence (0–1) so that the
 * agent's existing severity-aware triage logic gives the most-likely
 * leads more attention. The mapping is deliberately conservative —
 * "critical" is reserved for findings the agent has actually confirmed.
 *
 * Closes pwnkit#368.
 */
export function seedFindingsToSemgrepShape(seeds: SeedFinding[]): SemgrepFinding[] {
  return seeds.map((s) => {
    const confidence = typeof s.confidence === "number" ? s.confidence : 0.5;
    let severity: string;
    if (confidence >= 0.8) severity = "high";
    else if (confidence >= 0.6) severity = "medium";
    else if (confidence >= 0.4) severity = "low";
    else severity = "info";

    const cwePart = s.cwe ?? "lead";
    const ruleId = `${s.source}.${cwePart}`;
    const claim = s.claim ?? `External lead from ${s.source}${s.cwe ? ` (${s.cwe})` : ""}`;
    const messageWithConfidence =
      typeof s.confidence === "number"
        ? `${claim} [confidence=${s.confidence.toFixed(2)}]`
        : claim;

    return {
      ruleId,
      message: messageWithConfidence,
      severity,
      path: s.file,
      startLine: s.startLine,
      endLine: s.endLine,
      snippet: s.snippet,
      metadata: {
        source: s.source,
        confidence: s.confidence,
        cwe: s.cwe,
        ...(s.metadata ?? {}),
      },
    };
  });
}

interface PrepareResult {
  scopePath: string;
  resolvedTarget: string;
  resolvedType: "npm-package" | "pypi-package" | "cargo-package" | "oci-image" | "source-code" | "url" | "web-app";
  packageName?: string;
  packageVersion?: string;
  packageEcosystem?: "npm" | "pypi" | "cargo" | "oci";
  tempDir?: string;
  needsCleanup: boolean;
}

/**
 * Detect target type from the raw target string if not explicitly provided.
 */
function detectTargetType(target: string): "npm-package" | "source-code" | "url" | "web-app" {
  // Git URL patterns
  if (
    target.startsWith("git@") ||
    target.startsWith("git://") ||
    target.endsWith(".git") ||
    target.startsWith("https://github.com/")
  ) {
    return "source-code";
  }
  if (target.startsWith("http://") || target.startsWith("https://")) {
    return "url";
  }
  // Local directory
  if (isExplicitLocalTargetPath(target) || isExistingLocalTargetPath(target)) {
    return "source-code";
  }
  // Default: treat as npm package name
  return "npm-package";
}

/**
 * Phase 1: Prepare the target for analysis.
 *
 * - npm-package / pypi-package: install in temp dir
 * - source-code: clone if URL, resolve if local path
 * - url/web-app: no-op (target is the URL itself)
 */
function prepareTarget(
  opts: PipelineOptions,
  emit: ScanListener,
): PrepareResult {
  const targetType = opts.targetType ?? detectTargetType(opts.target);

  if (targetType === "npm-package") {
    return prepareNpmPackage(opts.target, opts.packageVersion, emit);
  }

  if (targetType === "pypi-package") {
    return preparePythonPackage(opts.target, opts.packageVersion, emit);
  }

  if (targetType === "cargo-package") {
    return prepareCargoPackage(opts.target, opts.packageVersion, emit);
  }

  if (targetType === "oci-image") {
    return prepareOciImage(opts.target, opts.packageVersion, emit);
  }

  if (targetType === "source-code") {
    // Package-source review (#317 follow-up): when `reviewPackageEcosystem`
    // is set, `target` is a package NAME — install it and review its
    // extracted source, keeping `resolvedType: "source-code"` so the review
    // pipeline (profile prompt + review report) drives instead of audit.
    if (opts.reviewPackageEcosystem) {
      return prepareReviewPackage(
        opts.target,
        opts.reviewPackageEcosystem,
        opts.packageVersion,
        emit,
      );
    }
    return prepareSourceCode(opts.target, emit);
  }

  // url or web-app — nothing to install/clone
  return {
    scopePath: opts.target,
    resolvedTarget: opts.target,
    resolvedType: targetType,
    needsCleanup: false,
  };
}

function prepareNpmPackage(
  rawPackageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): PrepareResult {
  // Split "node-forge@0.10.0" into name + version
  let packageName = rawPackageName;
  let version = requestedVersion;
  const atIdx = rawPackageName.startsWith("@")
    ? rawPackageName.indexOf("@", 1)
    : rawPackageName.indexOf("@");
  if (atIdx > 0) {
    packageName = rawPackageName.slice(0, atIdx);
    version = version ?? rawPackageName.slice(atIdx + 1);
  }

  const pkg = installPackageForEcosystem("npm", packageName, version, emit);

  return {
    scopePath: pkg.path,
    resolvedTarget: `npm:${pkg.name}@${pkg.version}`,
    resolvedType: "npm-package",
    packageName: pkg.name,
    packageVersion: pkg.version,
    packageEcosystem: "npm",
    tempDir: pkg.tempDir,
    needsCleanup: true,
  };
}

function preparePythonPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): PrepareResult {
  const pkg = installPackageForEcosystem("pypi", packageName, requestedVersion, emit);
  return {
    scopePath: pkg.path,
    resolvedTarget: `pypi:${pkg.name}@${pkg.version}`,
    resolvedType: "pypi-package",
    packageName: pkg.name,
    packageVersion: pkg.version,
    packageEcosystem: "pypi",
    tempDir: pkg.tempDir,
    needsCleanup: true,
  };
}

function prepareCargoPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): PrepareResult {
  const pkg = installPackageForEcosystem("cargo", packageName, requestedVersion, emit);
  return {
    scopePath: pkg.path,
    resolvedTarget: `cargo:${pkg.name}@${pkg.version}`,
    resolvedType: "cargo-package",
    packageName: pkg.name,
    packageVersion: pkg.version,
    packageEcosystem: "cargo",
    tempDir: pkg.tempDir,
    needsCleanup: true,
  };
}

function prepareOciImage(
  imageRef: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): PrepareResult {
  const pkg = installPackageForEcosystem("oci", imageRef, requestedVersion, emit);
  return {
    scopePath: pkg.path,
    resolvedTarget: `oci:${pkg.name}@${pkg.version}`,
    resolvedType: "oci-image",
    packageName: pkg.name,
    packageVersion: pkg.version,
    packageEcosystem: "oci",
    tempDir: pkg.tempDir,
    needsCleanup: true,
  };
}

/**
 * Acquire a published package's source for REVIEW. Installs the package via
 * the shared ecosystem installer (same code the audit path uses) but reports
 * `resolvedType: "source-code"` so the downstream pipeline runs the review
 * agent + emits a review report rather than the package-audit flow. Install
 * progress streams through `emit`, so the cloud relay sees heartbeat events
 * during install (the reaper's no-event window stays satisfied). The temp
 * install dir is cleaned up by the caller via `needsCleanup`.
 */
function prepareReviewPackage(
  rawPackageName: string,
  ecosystem: "npm" | "pypi" | "cargo" | "oci",
  requestedVersion: string | undefined,
  emit: ScanListener,
): PrepareResult {
  const pkg = installPackageForEcosystem(ecosystem, rawPackageName, requestedVersion, emit);
  return {
    scopePath: pkg.path,
    resolvedTarget: `${ecosystem}:${pkg.name}@${pkg.version}`,
    resolvedType: "source-code",
    packageName: pkg.name,
    packageVersion: pkg.version,
    packageEcosystem: ecosystem,
    tempDir: pkg.tempDir,
    needsCleanup: true,
  };
}

function prepareSourceCode(target: string, emit: ScanListener): PrepareResult {
  const isUrl =
    target.startsWith("https://") ||
    target.startsWith("http://") ||
    target.startsWith("git@") ||
    target.startsWith("git://");

  if (!isUrl) {
    const absPath = resolveLocalTargetPath(target);
    if (!existsSync(absPath)) {
      throw new Error(`Repository path not found: ${absPath}`);
    }
    return {
      scopePath: absPath,
      resolvedTarget: `repo:${absPath}`,
      resolvedType: "source-code",
      needsCleanup: false,
    };
  }

  const tempDir = join(tmpdir(), `pwnkit-pipeline-${randomUUID().slice(0, 8)}`);
  mkdirSync(tempDir, { recursive: true });

  emit({ type: "stage:start", stage: "prepare", message: `Cloning ${target}...` });

  try {
    // Parses an optional `<url>.git@<ref>` version suffix (kernel/source
    // targets) and clones the pinned ref, not the default branch.
    cloneGitRepo(target, `${tempDir}/repo`);
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to clone ${target}: ${msg}`);
  }

  const repoPath = join(tempDir, "repo");

  emit({ type: "stage:end", stage: "prepare", message: `Cloned ${basename(target.replace(/\.git$/, ""))}` });

  return {
    scopePath: repoPath,
    resolvedTarget: `repo:${target}`,
    resolvedType: "source-code",
    tempDir,
    needsCleanup: true,
  };
}

// ── CLI prompt builders (for CLI runtime fast path) ──

function buildCliPrompt(
  scopePath: string,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
  label: string,
  advisoryLabel: string,
  changedFiles?: string[],
  changedOnly = false,
): string {
  const semgrepContext = semgrepFindings.length > 0
    ? semgrepFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None.";

  const npmContext = npmAuditFindings.length > 0
    ? npmAuditFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.name}: ${f.title}`)
        .join("\n")
    : "  None.";

  const changedFilesContext =
    changedFiles && changedFiles.length > 0
      ? `\nChanged files to prioritize:\n${changedFiles.slice(0, 200).map((path) => `  - ${path}`).join("\n")}\n`
      : "";

  return `Audit the ${label} at ${scopePath}.

Read the source code, look for: prototype pollution, ReDoS, path traversal, injection, unsafe deserialization, missing validation. Map data flow from untrusted input to sensitive operations. Report any security findings with severity and PoC suggestions.
Start by reading the ecosystem manifest and entry points when present: package.json, pyproject.toml, setup.cfg, setup.py, Cargo.toml, go.mod, composer.json, or /etc/os-release for extracted images.
${changedFilesContext}
${changedOnly ? "\nThis is a diff-aware review. Focus findings on vulnerabilities introduced by or reachable from the changed files above. You may inspect surrounding files for context.\n" : ""}

The static scanner already found these leads:
${semgrepContext}

${advisoryLabel} found these advisories:
${npmContext}

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
suggested_replacement: <optional exact replacement for the cited source line or range>
---END---

Output as many ---FINDING--- blocks as needed. Be precise and honest about severity.`;
}


// ── Build summary from findings ──

function buildSummary(findings: Finding[], totalAttacks: number) {
  return {
    totalAttacks,
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
}

/**
 * Strict shape of a persisted findings-table row, inferred directly from
 * the drizzle schema. We thread this through `restorePersistedFinding`
 * (rather than `any`) so the *next* column added to `schema.findings`
 * fails to compile in the rehydrator instead of being silently dropped
 * on resume. See pwnkit#414 / pwnkit#382 — historical regressions where
 * `verificationSpec`, `pocSteps`, `layerVerdicts`, `pocExecution`, the
 * `workflow*` fields, and `score` were each added to the writer/schema
 * but never threaded back through the loader.
 */
type PersistedFindingRow = InferSelectModel<typeof dbSchema.findings>;
/**
 * Same shape as the strict drizzle row, but with JSON-text columns also
 * permitted as their already-parsed object form. Cloud sinks and the
 * in-memory test doubles hand back the parsed objects directly; production
 * SQLite rows are always strings.
 */
type RestorablePersistedFindingRow = Omit<
  PersistedFindingRow,
  "verificationSpec" | "pocSteps" | "layerVerdicts" | "pocExecution"
> & {
  verificationSpec: PersistedFindingRow["verificationSpec"] | Finding["verificationSpec"];
  pocSteps: PersistedFindingRow["pocSteps"] | Finding["pocSteps"];
  layerVerdicts: PersistedFindingRow["layerVerdicts"] | Finding["layerVerdicts"];
  pocExecution: PersistedFindingRow["pocExecution"] | Finding["pocExecution"];
};

/**
 * Parse a JSON-text column from a persisted row. Returns the parsed value
 * when the column is a non-empty string of valid JSON, the value itself
 * when it is already an object (sink-shim / test-double path), or
 * `undefined` otherwise. Malformed JSON is non-fatal: the finding still
 * restores, just without that field. See pwnkit#414.
 */
function parseJsonColumn<T>(value: string | T | null | undefined): T | undefined {
  if (value == null) return undefined;
  if (typeof value === "string") {
    if (value.length === 0) return undefined;
    try {
      return JSON.parse(value) as T;
    } catch {
      return undefined;
    }
  }
  // Already-parsed object handed in by a shim/test double.
  return value;
}

/**
 * Rehydrate a persisted findings-table row into a {@link Finding}.
 *
 * Exported for tests so the wire round-trip (verificationSpec, evidence,
 * triage flags, etc.) can be exercised without a full pipeline run.
 * Production callers reach this through the `getFindings(...).map(...)`
 * inside `runPipeline`.
 */
export function restorePersistedFinding(row: RestorablePersistedFindingRow): Finding {
  // pwnkit#193 — `verificationSpec` is the deterministic re-check contract
  // produced by the OSS engine and consumed by cloud's canary watcher.
  // It is persisted as JSON text and must be threaded through every
  // reload path; otherwise findings restored from storage silently lose
  // the contract before cloud re-checks can run.
  let verificationSpec: Finding["verificationSpec"];
  if (typeof row.verificationSpec === "string" && row.verificationSpec.length > 0) {
    try {
      const parsed = JSON.parse(row.verificationSpec);
      // Defensive: only accept the shape we expect. Older rows that
      // stored something malformed get dropped silently rather than
      // breaking the resume path.
      if (parsed && typeof parsed === "object" && Array.isArray(parsed.code)) {
        verificationSpec = parsed;
      }
    } catch {
      // Malformed JSON in the column is non-fatal; the finding still
      // restores, just without a verification contract.
    }
  } else if (row.verificationSpec && typeof row.verificationSpec === "object") {
    // Some shims (cloud sinks, in-memory test doubles) hand back the
    // already-parsed object. Pass it through unchanged.
    if (Array.isArray(row.verificationSpec.code)) {
      verificationSpec = row.verificationSpec;
    }
  }

  // pwnkit#414 — mirror the verificationSpec thread for every other
  // JSON-text column the writer persists. Each defaults to `undefined`
  // when missing or malformed; the typed `RestorablePersistedFindingRow`
  // parameter ensures any new column added to the schema fails to
  // compile here instead of being dropped.
  const pocSteps = parseJsonColumn<PocStep[]>(row.pocSteps);
  const layerVerdicts = parseJsonColumn<LayerVerdict[]>(row.layerVerdicts);
  const pocExecution = parseJsonColumn<Finding["pocExecution"]>(row.pocExecution);

  return {
    id: row.id,
    templateId: row.templateId,
    title: row.title,
    description: row.description,
    severity: row.severity as Finding["severity"],
    category: row.category as Finding["category"],
    status: row.status as Finding["status"],
    fingerprint: row.fingerprint ?? undefined,
    triageStatus: row.triageStatus as Finding["triageStatus"],
    triageNote: row.triageNote ?? undefined,
    // pwnkit#414 — workflow + score fields were persisted by saveFinding
    // but silently dropped on resume. Thread the scalar columns directly.
    workflowStatus: (row.workflowStatus ?? undefined) as FindingWorkflowStatus | undefined,
    workflowAssignee: row.workflowAssignee ?? undefined,
    workflowUpdatedAt: row.workflowUpdatedAt ?? undefined,
    score: row.score ?? undefined,
    confidence: row.confidence ?? undefined,
    cvssVector: row.cvssVector ?? undefined,
    cvssScore: row.cvssScore ?? undefined,
    evidence: {
      request: row.evidenceRequest,
      response: row.evidenceResponse,
      analysis: row.evidenceAnalysis ?? undefined,
    },
    layerVerdicts,
    pocSteps,
    verificationSpec,
    pocExecution,
    timestamp: row.timestamp,
  };
}

function listChangedFiles(scopePath: string, diffBase: string): string[] {
  const output = execFileSync(
    "git",
    ["diff", "--name-only", "--diff-filter=ACMR", `${diffBase}...HEAD`],
    {
      cwd: scopePath,
      timeout: 30_000,
      stdio: "pipe",
      encoding: "utf-8",
    },
  );

  return output
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((path) => existsSync(join(scopePath, path)));
}

/**
 * `--runtime codex` is a special case: it can resolve through either the
 * local `codex` CLI binary (subscription path, source-analysis only) OR
 * through the direct ChatGPT Codex provider when one of
 * `PWNKIT_CHATGPT_ACCESS_TOKEN` / `PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN` is
 * set. In the latter mode `LlmApiRuntime` reports `provider:
 * "chatgpt-codex"`, and the pipeline must route the codex request through
 * the API runtime instead of bailing with "Requested runtime 'codex' is
 * not available." This mirrors the routing already in `agentic-scanner.ts`
 * (the web/url scan path); without it, kernel reviews + npm/pypi/cargo
 * audits with `--runtime codex` were skipped on machines where the
 * operator had configured subscription auth but not installed the codex
 * CLI binary. See #402.
 */
function hasDirectChatGptCodexProvider(
  diagnostics: ApiRuntimeDiagnostics,
): boolean {
  return diagnostics.valid && diagnostics.provider === "chatgpt-codex";
}

function selectVerificationRuntime(
  preferredRuntime: RuntimeMode | undefined,
  hasApiKey: boolean,
  availableRuntimes: Set<RuntimeType>,
  apiDiagnostics: ApiRuntimeDiagnostics,
): RuntimeMode | null {
  if (preferredRuntime === "api") {
    return hasApiKey ? "api" : null;
  }

  if (preferredRuntime && preferredRuntime !== "auto") {
    if (availableRuntimes.has(preferredRuntime)) return preferredRuntime;
    // Explicit `--runtime codex` with the direct ChatGPT Codex provider
    // configured (PWNKIT_CHATGPT_*_TOKEN env). Route verification through
    // the API runtime — agent-runner.ts will pick up the same env vars
    // and run the native tool_use loop against chatgpt.com.
    if (preferredRuntime === "codex" && hasDirectChatGptCodexProvider(apiDiagnostics)) {
      return "codex";
    }
    return null;
  }

  if (hasApiKey) {
    return "api";
  }

  if (availableRuntimes.size > 0) {
    return "auto";
  }

  return null;
}

function hasRequestedAnalysisRuntime(
  preferredRuntime: RuntimeMode | undefined,
  hasApiKey: boolean,
  availableRuntimes: Set<RuntimeType>,
  apiDiagnostics: ApiRuntimeDiagnostics,
): boolean {
  if (preferredRuntime === "api") {
    return hasApiKey;
  }

  if (preferredRuntime && preferredRuntime !== "auto") {
    if (availableRuntimes.has(preferredRuntime)) return true;
    // Direct ChatGPT Codex provider unlocks `--runtime codex` even when
    // the codex CLI binary is absent. See `hasDirectChatGptCodexProvider`.
    if (preferredRuntime === "codex" && hasDirectChatGptCodexProvider(apiDiagnostics)) {
      return true;
    }
    return false;
  }

  return hasApiKey || availableRuntimes.size > 0;
}

function assertApiRuntimeSelection(
  preferredRuntime: RuntimeMode | undefined,
  diagnostics: ApiRuntimeDiagnostics,
): void {
  if (preferredRuntime === "api" && diagnostics.reason === "invalid_config") {
    throw new Error(diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is not available.`);
  }

  if ((preferredRuntime === "auto" || preferredRuntime === undefined) && diagnostics.reason === "invalid_config") {
    throw new Error(diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is misconfigured.`);
  }
}

function isRepairableDbError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /database disk image is malformed|file is not a database|malformed|invalid page number|database main|btree|b-tree|database corrupt/i.test(message);
}

// ── Per-file research orchestration (#285) ──

export interface PerFileResearchOptions {
  scopePath: string;
  target: string;
  scanId: string;
  files: string[];
  semgrepFindings: SemgrepFinding[];
  npmAuditFindings: NpmAuditFinding[];
  targetLabel: string;
  advisoryLabel: string;
  /** Per-file agent invoker. Injected so tests can drive the loop without
   *  spinning up real runtimes; production passes `runAnalysisAgent`. */
  invoke: (perFile: {
    file: string;
    fileRel: string;
    systemPrompt: string;
    cliSystemPrompt: string;
  }) => Promise<{
    findings: Finding[];
    usage?: { inputTokens: number; outputTokens: number };
    turns?: number;
  }>;
  /** Optional per-file usage sink so the caller can attribute tokens/turns to
   *  the research phase. Fires once per file with that file's agent result. */
  onUsage?: (
    result: { usage?: { inputTokens: number; outputTokens: number }; turns?: number },
  ) => void;
  /** Optional per-file lifecycle hook for stage-progress emission. */
  onFileStart?: (fileRel: string, index: number, total: number) => void;
  /** Optional handler for per-file errors (logged + recorded but does not
   *  abort the overall research pass). */
  onFileError?: (fileRel: string, error: Error) => void;
}

/**
 * Runs the per-file research loop. One agent session per file, findings
 * aggregated into a single `Finding[]`.
 *
 * Reference pattern: `pov-gate.ts:367 buildPovSystemPrompt` — one finding /
 * file per agent session, deterministic outer loop, tight per-call budget.
 *
 * Closes #285 H2 (control-flow audit): the prior shared-session research
 * walked nominally but skipped past the first ~30 files. Per-file
 * iteration guarantees full coverage.
 */
export async function runPerFileResearch(
  opts: PerFileResearchOptions,
): Promise<Finding[]> {
  const aggregated: Finding[] = [];
  for (let i = 0; i < opts.files.length; i++) {
    const fileAbs = opts.files[i];
    const fileRel = pathRelative(opts.scopePath, fileAbs);
    const filePrompt = researchPromptSingleFile(
      opts.scopePath,
      fileRel,
      opts.semgrepFindings.map(f => ({ ruleId: f.ruleId, message: f.message, path: f.path, startLine: f.startLine })),
      opts.npmAuditFindings.map(f => ({ name: f.name, severity: f.severity, title: f.title })),
      opts.targetLabel,
      opts.advisoryLabel,
    );
    const cliSystemPrompt =
      `You are a security researcher analyzing the single file ${fileRel}. For EACH vulnerability you find in THIS file, output it using the exact ---FINDING--- / ---END--- format. Do NOT analyze other files. If you find no vulnerabilities in this file, say 'No vulnerabilities found.' and nothing else.`;

    opts.onFileStart?.(fileRel, i, opts.files.length);

    try {
      const agentResult = await opts.invoke({
        file: fileAbs,
        fileRel,
        systemPrompt: filePrompt,
        cliSystemPrompt,
      });
      opts.onUsage?.(agentResult);
      aggregated.push(...agentResult.findings);
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      opts.onFileError?.(fileRel, e);
    }
  }
  return aggregated;
}

// ── npm dynamic-discovery stage (opt-in) ──

/** Env-toggle counterpart of the `npmDynamicDiscovery` opt-in (cloud config). */
function npmDynamicDiscoveryEnvEnabled(): boolean {
  const v = (process.env.PWNKIT_NPM_DYNAMIC_DISCOVERY ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/**
 * Gate: run the npm dynamic-discovery sweep only when it is (a) opted in — via
 * `--npm-dynamic` / `npmDynamicDiscovery: true` or the env toggle — AND (b) the
 * prepared target is an npm-ecosystem package (a package-source npm review or an
 * `npm-package` audit) with a resolved package name. Exported for tests.
 */
export function shouldRunNpmDynamicDiscovery(
  opts: Pick<PipelineOptions, "npmDynamicDiscovery">,
  prepared: Pick<PrepareResult, "packageEcosystem" | "resolvedType" | "packageName">,
): boolean {
  const enabled = opts.npmDynamicDiscovery === true || npmDynamicDiscoveryEnvEnabled();
  if (!enabled) return false;
  const isNpm = prepared.packageEcosystem === "npm" || prepared.resolvedType === "npm-package";
  return isNpm && !!prepared.packageName;
}

/**
 * Run the npm dynamic-discovery detector sweep over a single target package and
 * return the confirmed leads as canonical `Finding`s (so the pipeline can merge
 * them into `findings` before VERIFY). Isolation is the per-package sandbox
 * runner; a sandbox fault skips the package (never a fabricated finding).
 * Exported for tests. Never throws — a stage-level failure is returned as a
 * warning so it can't abort the surrounding scan.
 */
export async function runNpmDynamicDiscoveryStage(args: {
  packageName: string;
  packageVersion?: string;
  runner?: NpmPackageRunner;
  log?: (msg: string) => void;
}): Promise<{ findings: Finding[]; warnings: string[] }> {
  const runner = args.runner ?? createSandboxPackageRunner({ log: args.log });
  try {
    const result = await runNpmDynamicDiscovery({
      worklist: [{ name: args.packageName, version: args.packageVersion }],
      packageRunner: runner,
      log: args.log,
    });
    return { findings: result.findings, warnings: result.warnings };
  } catch (e) {
    return { findings: [], warnings: [`npm-dynamic-discovery: ${e instanceof Error ? e.message : String(e)}`] };
  }
}

// ── Main entry point ──

/**
 * Unified pipeline for all pwnkit scan types.
 *
 * Pipeline:
 *   Phase 1: PREPARE   — detect target type, install/clone/resolve
 *   Phase 2: ANALYZE   — static scanner + dependency audit
 *   Phase 3: RESEARCH  — single AI agent discovers, attacks, and writes PoCs
 *   Phase 4: VERIFY    — parallel blind agents independently verify each finding
 *
 * Reuses runAnalysisAgent() from agent-runner.ts which handles all runtimes
 * (Claude Code CLI, Codex, API with native tool_use, legacy fallback).
 */
export async function runPipeline(opts: PipelineOptions): Promise<PipelineReport> {
  const emit: ScanListener = (opts.onEvent as ScanListener) ?? (() => {});
  const startTime = Date.now();
  const warnings: Array<{ stage: string; message: string }> = [];
  let emittedScanCompleted = false;

  const emitPipelineScanCompleted = (
    exitReason: "completed" | "failed" | "cost_exceeded",
    payload: Record<string, unknown> = {},
  ): void => {
    if (!shouldEmitPipelineCloudEvents()) return;
    if (emittedScanCompleted) return;
    emittedScanCompleted = true;
    // Mirror the audit path's scan_completed field set (agentic-scanner.ts
    // emitScanCompleted) so the cloud can populate scan detail for
    // pipeline (review / package-audit) runs too: the engine-resolved model,
    // cross-session turns + tool-call totals, and the ledger's true
    // cross-session cost + per-model breakdown. cost_usd / cost_breakdown
    // are omitted when no metered runtime ran (never a fabricated $0);
    // model is omitted when nothing resolved one (never a guess).
    const cost = costLedger.costBreakdown();
    eventBus.emit("scan_completed", {
      exit_reason: exitReason,
      duration_ms: Date.now() - startTime,
      turns_used: usageTotals.turns,
      tool_calls_total: toolCallsTotal,
      ...(resolvedModel !== undefined ? { model: resolvedModel } : {}),
      ...(typeof payload.findings === "number"
        ? { findings_count: payload.findings }
        : {}),
      ...(cost !== null
        ? { cost_usd: cost.costUsd, cost_breakdown: cost.breakdown }
        : {}),
      ...payload,
    });
  };

  // ── Truthful server-side phase timeline ──
  // Each real top-level phase transition fires `phase_started` on the bus;
  // `startPhase` closes the previously-open phase with a `phase_completed`
  // carrying its wall-clock duration. Only phases that actually execute get
  // an event (a skipped analyze/research/verify leaves no gap), and `index`
  // is the 0-based execution order. Gated identically to `scan_completed` so
  // local CLI runs stay quiet.
  //
  // Per-phase token/turn totals ride on `phase_completed` too. Every LLM agent
  // run in this pipeline returns its own `{ usage, turns }`; `recordUsage`
  // folds those into a pipeline-wide monotonic accumulator as each phase runs
  // (return values, not events, so the concurrent verify wave sums exactly).
  // `startPhase` snapshots the accumulator; `finishPhase` emits the delta —
  // the real work THIS phase did. Phases that call no agent (prepare, analyze,
  // report) leave the accumulator untouched → a truthful 0. Runtime paths that
  // don't surface usage (CLI runtimes, legacy loop for tokens) contribute 0
  // rather than a fabricated estimate.
  const usageTotals = { inputTokens: 0, outputTokens: 0, turns: 0 };
  const recordUsage = (
    r?: { usage?: { inputTokens: number; outputTokens: number }; turns?: number } | null,
  ): void => {
    if (!r) return;
    usageTotals.inputTokens += r.usage?.inputTokens ?? 0;
    usageTotals.outputTokens += r.usage?.outputTokens ?? 0;
    usageTotals.turns += r.turns ?? 0;
  };

  // ── Per-scan metrics tracked off the bus ──
  // Mirror the audit path (agentic-scanner.ts): count tool_call_completed
  // events between scan start and completion so scan_completed's
  // tool_calls_total covers every agent session (research + verify wave),
  // never under-counting even on partial / errored exits.
  let toolCallsTotal = 0;
  const unsubscribeMetrics = eventBus.subscribe({
    emit(type) {
      if (type === "tool_call_completed") toolCallsTotal += 1;
    },
  });

  // ── Scan-wide cost budget ──
  // ONE ledger shared by every agent session this pipeline runs (research +
  // the concurrent blind-verify wave + per-file research). The native loop
  // folds each turn's usage into it and prices `opts.costCeilingUsd` against
  // the cross-session cumulative total — so the hard ceiling binds the SCAN,
  // not each session (previously every session got the full ceiling, so a
  // $3-capped 0review scan could really spend research($3) + N×verify($3);
  // prod review scans landed at $4.99 / $6.36).
  const costLedger = new ScanCostLedger();
  /** True once the shared ledger's cumulative cost has reached the ceiling. */
  const scanCostCeilingTripped = (): boolean =>
    opts.costCeilingUsd !== undefined &&
    opts.costCeilingUsd > 0 &&
    costLedger.costUsd(opts.model) >= opts.costCeilingUsd;

  // Engine-resolved model id, stamped on scan_completed. Assigned once the
  // API runtime is probed (below); stays undefined when nothing resolved a
  // model (e.g. a CLI runtime ran the scan with no --model pick).
  let resolvedModel: string | undefined;
  let phaseIndex = 0;
  let openPhase:
    | {
        name: string;
        index: number;
        startedAt: number;
        usageAtStart: { inputTokens: number; outputTokens: number; turns: number };
      }
    | null = null;
  const finishPhase = (): void => {
    if (!openPhase) return;
    if (shouldEmitPipelineCloudEvents()) {
      eventBus.emit("phase_completed", {
        name: openPhase.name,
        index: openPhase.index,
        duration_ms: Date.now() - openPhase.startedAt,
        input_tokens: usageTotals.inputTokens - openPhase.usageAtStart.inputTokens,
        output_tokens: usageTotals.outputTokens - openPhase.usageAtStart.outputTokens,
        turns: usageTotals.turns - openPhase.usageAtStart.turns,
      });
    }
    openPhase = null;
  };
  const startPhase = (name: string): void => {
    finishPhase();
    const index = phaseIndex++;
    openPhase = { name, index, startedAt: Date.now(), usageAtStart: { ...usageTotals } };
    if (shouldEmitPipelineCloudEvents()) {
      eventBus.emit("phase_started", { name, index });
    }
  };

  // Initialize DB (optional, best-effort)
  let db = await (async () => {
    try {
      const { pwnkitDB, repairPwnkitDatabase } = await import("@pwnkit/db");
      try {
        return new pwnkitDB(opts.dbPath);
      } catch (error) {
        if (!isRepairableDbError(error)) throw error;
        const repaired = repairPwnkitDatabase(opts.dbPath);
        warnings.push({
          stage: "prepare",
          message: repaired.backupPath
            ? `Recovered local scan database. Backup saved to ${repaired.backupPath}`
            : `Recovered local scan database at ${repaired.path}`,
        });
        return new pwnkitDB(opts.dbPath);
      }
    } catch {
      return null as any;
    }
  })() as any;

  const existingScan = opts.resumeScanId ? db?.getScan(opts.resumeScanId) : null;
  if (opts.resumeScanId && !existingScan) {
    throw new Error(`Scan ${opts.resumeScanId} not found`);
  }

  let persistedScanId = opts.resumeScanId ?? "";
  const logPipelineEvent = (
    stage: string,
    eventType: string,
    payload: Record<string, unknown> = {},
  ): void => {
    if (!persistedScanId) return;
    db?.logEvent({
      scanId: persistedScanId,
      stage,
      eventType,
      payload,
      timestamp: Date.now(),
    });
  };

  // ── PHASE 1: PREPARE ──
  startPhase("prepare");
  emit({ type: "stage:start", stage: "prepare", message: opts.resumeScanId ? "Re-preparing target for resume..." : "Preparing target..." });

  let prepared: PrepareResult;
  try {
    prepared = prepareTarget(opts, emit);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logPipelineEvent("prepare", "stage_error", { error: msg });
    throw new Error(`Prepare failed: ${msg}`);
  }

  emit({ type: "stage:end", stage: "prepare", message: `Target ready: ${prepared.resolvedType}` });

  // Honor `--subsystem` for non-kernel source reviews by narrowing the review
  // scope to the requested subtree (pwnkit). Without this the subsystem hint
  // was ignored outside the linux-kernel profile, so `--subsystem` on a large
  // monorepo (e.g. dotnet/runtime) left scopePath at the whole repo and the
  // oversized-review guard below rejected it every time.
  if (prepared.resolvedType === "source-code" && !opts.resumeScanId) {
    const narrowed = resolveSubsystemScope(
      prepared.scopePath,
      opts.subsystem,
      opts.reviewProfile,
    );
    if (narrowed) {
      prepared = { ...prepared, scopePath: narrowed };
      emit({ type: "stage:end", stage: "prepare", message: `Scoped to subsystem: ${opts.subsystem}` });
    } else if (opts.subsystem && parseSubsystems(opts.subsystem).length === 1) {
      emit({ type: "error", stage: "prepare", message: `subsystem path not found in repo, scanning whole target: ${opts.subsystem}` });
    }
  }

  // Oversized-review guard (pwnkit). A whole-repo `review` feeds the source
  // tree to a single agent session under a fixed time budget; on a target the
  // size of the Linux kernel (~80k source files) the session exhausts the
  // budget with 0 tokens + 0 findings and times out silently. Count the scope
  // files up front (short-circuiting once the cap is passed, so we don't walk
  // all 80k just to reject) and fail fast with an actionable error instead.
  // Source-code review only — package audits are already file-bounded.
  const reviewSubsystemPaths =
    opts.reviewProfile === "linux-kernel" && opts.subsystem
      ? parseSubsystems(opts.subsystem).map((s) => join(prepared.scopePath, s))
      : undefined;

  // Diff-aware review: scope to the changed files BEFORE the oversized-
  // review guard. The guard counts the WHOLE repo, so a 3-file PR on a
  // monorepo would otherwise be rejected for the repo's size — the review
  // only reads the changed set, so the cap must apply to that set, not the
  // repo. null = not a diff run or the diff failed (fall back to whole-repo).
  let diffChangedFiles: string[] | null = null;
  if (
    prepared.resolvedType === "source-code" &&
    opts.diffBase &&
    opts.changedOnly &&
    !opts.resumeScanId
  ) {
    try {
      diffChangedFiles = listChangedFiles(prepared.scopePath, opts.diffBase);
    } catch {
      diffChangedFiles = null;
    }
  }

  if (prepared.resolvedType === "source-code" && !opts.resumeScanId) {
    const cap = reviewMaxFiles();
    const fileCount = diffChangedFiles
      ? diffChangedFiles.length
      : (() => {
          let n = 0;
          for (const scopePath of reviewSubsystemPaths ?? [prepared.scopePath]) {
            n += countScopeFilesUpTo(scopePath, cap - n);
            if (n > cap) break;
          }
          return n;
        })();
    if (fileCount > cap) {
      const msg = diffChangedFiles
        ? `review diff too large: ${fileCount} changed files exceeds the ${cap} ` +
          `review cap — split the change or scope to a subsystem/path`
        : `review target too large: over ${cap} source files exceeds the ${cap} ` +
          `review cap — scope to a subsystem/path (e.g. a specific directory) or ` +
          `use a smaller target (override with PWNKIT_REVIEW_MAX_FILES)`;
      logPipelineEvent("prepare", "stage_error", { error: msg, fileCount, cap });
      emit({ type: "error", stage: "prepare", message: msg });
      throw new Error(msg);
    }
  }

  const scanConfig: ScanConfig = {
    target: prepared.resolvedTarget,
    depth: opts.depth,
    format: opts.format,
    runtime: opts.runtime ?? "api",
    mode: opts.mode ?? "deep",
    // Thread the resolved package identity through to the publishability /
    // novelty gate (issue #851). Without this the gate defaulted ecosystem to
    // npm and dropped the version, so it could only do package-level dedup. We
    // map the pipeline's `oci` to undefined (not an OSV ecosystem) so the gate
    // stays conservative on container images.
    ...(prepared.packageEcosystem && prepared.packageEcosystem !== "oci"
      ? { ecosystem: prepared.packageEcosystem }
      : {}),
    ...(prepared.packageVersion ? { version: prepared.packageVersion } : {}),
  };

  if (db) {
    try {
      if (opts.resumeScanId) {
        persistedScanId = opts.resumeScanId;
        db.reopenScan(persistedScanId);
        logPipelineEvent("prepare", "scan_resumed", {
          originalStatus: existingScan?.status ?? null,
          resumedAt: new Date().toISOString(),
        });
      } else {
        persistedScanId = db.createScan(scanConfig);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      warnings.push({
        stage: "prepare",
        message: `Local scan database unavailable; continuing without persistence: ${msg}`,
      });
      db = null as any;
    }
  }
  if (!persistedScanId) {
    persistedScanId = `pipeline-${randomUUID().slice(0, 8)}`;
  }
  logPipelineEvent("prepare", "stage_start", { resumed: !!opts.resumeScanId });
  logPipelineEvent("prepare", "stage_complete", { resolvedType: prepared.resolvedType, resolvedTarget: prepared.resolvedTarget });

  try {
    // ── PHASE 2: ANALYZE (static analysis) ──
    startPhase("analyze");
    emit({ type: "stage:start", stage: "analyze", message: "Running static analysis..." });
    logPipelineEvent("analyze", "stage_start");

    // Intercept inner events — convert to analyze sub-actions
    const analyzeEmit: ScanListener = (event) => {
      if (event.type === "stage:start") {
        emit({ type: "stage:start", stage: "analyze", message: event.message });
      }
    };

    let semgrepFindings: SemgrepFinding[] = [];
    let npmAuditFindings: NpmAuditFinding[] = [];
    // Seeded by the pre-guard diff scoping for changedOnly runs; empty when
    // not a diff run or the pre-guard diff failed (the analyze stage's own
    // diffBase block then recomputes / falls back to full review).
    let changedFiles: string[] = diffChangedFiles ?? [];
    const staticScanner = selectedStaticScanner();
    let staticScannerRan = false;
    let staticScannerFindings = 0;

    // External seeds (e.g. from `gemmaforge scan` via `--seed-findings`).
    // Prepended to semgrepFindings so the agent prompt lists them FIRST —
    // the agent treats top-of-list as highest priority. When `seedOnly` is
    // also set we skip the static scan entirely. Closes pwnkit#368.
    const externalSeedCount = opts.seedFindings?.length ?? 0;
    if (externalSeedCount > 0) {
      const seededAsSemgrep = seedFindingsToSemgrepShape(opts.seedFindings!);
      semgrepFindings.push(...seededAsSemgrep);
      const sources = new Set(opts.seedFindings!.map((s) => s.source));
      emit({
        type: "stage:start",
        stage: "analyze",
        message: `Seeded ${externalSeedCount} external lead(s) from ${[...sources].join(", ")}`,
      });
      logPipelineEvent("analyze", "seed_findings_loaded", {
        count: externalSeedCount,
        sources: [...sources],
        seedOnly: !!opts.seedOnly,
      });
    }
    const skipSemgrep = !!(opts.seedOnly && externalSeedCount > 0);

    if (
      prepared.resolvedType === "source-code" &&
      opts.diffBase &&
      changedFiles.length === 0
    ) {
      try {
        changedFiles = listChangedFiles(prepared.scopePath, opts.diffBase);
        if (changedFiles.length > 0) {
          emit({
            type: "stage:start",
            stage: "analyze",
            message: `Diff context loaded: ${changedFiles.length} changed files from ${opts.diffBase}`,
          });
          logPipelineEvent("analyze", "diff_context", {
            diffBase: opts.diffBase,
            changedFiles: changedFiles.slice(0, 200),
            changedOnly: !!opts.changedOnly,
          });
        } else {
          warnings.push({
            stage: "analyze",
            message: `No changed files found for diff base '${opts.diffBase}'. Falling back to full review.`,
          });
          logPipelineEvent("analyze", "warning", {
            message: `No changed files found for diff base '${opts.diffBase}'. Falling back to full review.`,
          });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({
          stage: "analyze",
          message: `Failed to compute changed files from '${opts.diffBase}': ${msg}`,
        });
        logPipelineEvent("analyze", "warning", {
          message: `Failed to compute changed files from '${opts.diffBase}': ${msg}`,
        });
      }
    }

    // Static source scan. Foxguard is the default; PWNKIT_STATIC=semgrep
    // routes source and package-source leads through Semgrep while leaving
    // dependency advisory checks intact.
    if (
      !skipSemgrep && (
      prepared.resolvedType === "source-code" ||
      prepared.resolvedType === "npm-package" ||
      prepared.resolvedType === "pypi-package" ||
      prepared.resolvedType === "cargo-package" ||
      prepared.resolvedType === "oci-image"
      )
    ) {
      const scannerName = staticScanner === "foxguard" ? "Foxguard" : "Semgrep";
      try {
        const changedOnlyPaths =
          opts.changedOnly && changedFiles.length > 0
            ? changedFiles.map((path) => join(prepared.scopePath, path))
            : undefined;
        const packageStaticTarget =
          prepared.resolvedType === "npm-package" ||
          prepared.resolvedType === "pypi-package" ||
          prepared.resolvedType === "cargo-package" ||
          prepared.resolvedType === "oci-image";

        // Subsystem-scoped static scanning (pwnkit#466). When --subsystem is
        // set for a linux-kernel review, scope the static scanner to only the
        // specified subdirectory/directories. The full tree is still available
        // for cross-reference reads, but scanning the whole 30M-line tree
        // wastes the scanner's time budget.
        // Push (not assign) so prepended external seedFindings survive.
        const scanResults = runSelectedStaticScan(
          prepared.scopePath,
          analyzeEmit,
          {
            ...(packageStaticTarget ? { noGitIgnore: true } : {}),
            ...(changedOnlyPaths ? { paths: changedOnlyPaths } : {}),
            ...(reviewSubsystemPaths ? { paths: reviewSubsystemPaths } : {}),
          },
        );
        staticScannerRan = true;
        staticScannerFindings = scanResults.length;
        semgrepFindings.push(...scanResults);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({ stage: "analyze", message: `${scannerName} scan failed: ${msg}` });
        logPipelineEvent("analyze", "warning", { message: `${scannerName} scan failed: ${msg}` });
      }
    }

    // Haskell fallback seed layer (pwnkit). Foxguard v0.10.0 emits built-in
    // Cardano Haskell leads; keep this regex pass only for Semgrep/fallback
    // runs or older scanner output so cardano-haskell reviews never start from
    // an empty scanner list.
    if (
      prepared.resolvedType === "source-code" &&
      opts.reviewProfile === "cardano-haskell"
    ) {
      try {
        const hasFoxguardHaskellLeads = semgrepFindings.some((finding) =>
          finding.ruleId.startsWith("semgrep/cardano-haskell/"),
        );
        const haskellSeeds = hasFoxguardHaskellLeads ? [] : generateHaskellSeeds(prepared.scopePath);
        if (haskellSeeds.length > 0) {
          semgrepFindings.push(...haskellSeeds);
          emit({
            type: "stage:start",
            stage: "analyze",
            message: `Haskell seed layer: ${haskellSeeds.length} regex fallback lead(s)`,
          });
          logPipelineEvent("analyze", "haskell_seeds", {
            count: haskellSeeds.length,
          });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({ stage: "analyze", message: `Haskell seed layer failed: ${msg}` });
        logPipelineEvent("analyze", "warning", { message: `Haskell seed layer failed: ${msg}` });
      }
    }

    // Solidity/EVM fallback seed layer (pwnkit "0contract"). Semgrep's
    // Solidity coverage is thin and Slither is not on PATH in the engine
    // image, so this regex pass gives the evm-onchain review concrete
    // candidate sinks (external calls, delegatecall, cross-chain handlers,
    // oracle reads) so it never starts from an empty scanner list.
    if (
      prepared.resolvedType === "source-code" &&
      opts.reviewProfile === "evm-onchain"
    ) {
      try {
        const hasScannerSolidityLeads = semgrepFindings.some((finding) =>
          finding.path.endsWith(".sol"),
        );
        const evmSeeds = hasScannerSolidityLeads ? [] : generateEvmSeeds(prepared.scopePath);
        if (evmSeeds.length > 0) {
          semgrepFindings.push(...evmSeeds);
          emit({
            type: "stage:start",
            stage: "analyze",
            message: `EVM seed layer: ${evmSeeds.length} regex fallback lead(s)`,
          });
          logPipelineEvent("analyze", "evm_seeds", {
            count: evmSeeds.length,
          });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({ stage: "analyze", message: `EVM seed layer failed: ${msg}` });
        logPipelineEvent("analyze", "warning", { message: `EVM seed layer failed: ${msg}` });
      }
    }

    // dependency audit (package targets only, need the temp project dir)
    if (
      (prepared.resolvedType === "npm-package" || prepared.resolvedType === "pypi-package" || prepared.resolvedType === "cargo-package" || prepared.resolvedType === "oci-image") &&
      prepared.tempDir &&
      prepared.packageEcosystem
    ) {
      try {
        npmAuditFindings = runDependencyAuditForEcosystem(
          prepared.packageEcosystem,
          prepared.tempDir,
          emit,
          prepared.packageName && prepared.packageVersion
            ? { name: prepared.packageName, version: prepared.packageVersion }
            : undefined,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({ stage: "analyze", message: `dependency audit failed: ${msg}` });
        logPipelineEvent("analyze", "warning", { message: `dependency audit failed: ${msg}` });
      }
    }

    emit({
      type: "stage:end",
      stage: "analyze",
      message: `Analysis complete: ${semgrepFindings.length} static scanner findings, ${npmAuditFindings.length} dependency advisories`,
    });
    logPipelineEvent("analyze", "stage_complete", {
      staticScanner,
      staticScannerRan,
      staticScannerFindings,
      semgrepFindings: semgrepFindings.length,
      npmAuditFindings: npmAuditFindings.length,
    });
    if (shouldEmitPipelineCloudEvents()) {
      eventBus.emit("analyze:stage_complete", {
        stage: "static-analysis",
        staticScanner,
        staticScannerRan,
        staticScannerFindings,
        semgrepFindings: semgrepFindings.length,
        npmAuditFindings: npmAuditFindings.length,
      });
    }

    const availableRuntimes = await detectAvailableRuntimes();
    const needsApiDiagnostics =
      opts.runtime === "api" ||
      opts.runtime === "auto" ||
      opts.runtime === undefined ||
      (opts.runtime === "codex" && !availableRuntimes.has("codex"));
    const apiRuntimeForDiagnostics = needsApiDiagnostics
      ? new LlmApiRuntime({
          type: "api",
          timeout: opts.timeout ?? 120_000,
          apiKey: opts.apiKey,
          model: opts.model,
        })
      : null;
    const apiDiagnostics = apiRuntimeForDiagnostics
      ? apiRuntimeForDiagnostics.getConfigurationDiagnostics()
      : {
          valid: false,
          provider: "openai",
          providerLabel: "OpenAI",
          reason: "missing_key",
        } satisfies ApiRuntimeDiagnostics;
    assertApiRuntimeSelection(opts.runtime, apiDiagnostics);
    // The model id this run actually drives: the operator's explicit pick
    // wins; otherwise the probed API runtime's resolved (provider-default)
    // model — but only when that runtime is really configured, so a scan
    // that ran on a CLI runtime never gets a guessed model stamped.
    resolvedModel =
      opts.model ??
      (apiDiagnostics.valid
        ? apiRuntimeForDiagnostics?.resolvedModel()
        : undefined);
    const hasApiKey = apiDiagnostics.valid;
    const hasCliRuntime = availableRuntimes.size > 0;
    const canUseAiRuntime = hasRequestedAnalysisRuntime(
      opts.runtime,
      hasApiKey,
      availableRuntimes,
      apiDiagnostics,
    );
    const verificationRuntime = selectVerificationRuntime(opts.runtime, hasApiKey, availableRuntimes, apiDiagnostics);

    // Log pipeline decisions to stderr for CI visibility
    if (process.env.CI || process.env.PWNKIT_DEBUG) {
      process.stderr.write(`[pwnkit] Research: apiKey=${hasApiKey}, apiReason=${apiDiagnostics.reason ?? "ok"}, runtimes=[${[...availableRuntimes].join(",")}], config=${opts.runtime ?? "auto"}\n`);
    }

    if (!canUseAiRuntime) {
      const skipMessage = opts.runtime === "api"
        ? "Explicit runtime 'api' requested without an API key. AI analysis skipped."
        : opts.runtime && opts.runtime !== "auto"
          ? `Requested runtime '${opts.runtime}' is not available. AI analysis skipped.`
          : "No API key or CLI runtime available. AI analysis skipped. Set OPENROUTER_API_KEY, ANTHROPIC_API_KEY, AZURE_OPENAI_API_KEY, OPENAI_API_KEY, or Z_AI_API_KEY.";
      warnings.push({ stage: "research", message: skipMessage });
      emit({ type: "stage:end", stage: "research", message: "Skipped — no compatible AI runtime" });
      emit({ type: "stage:end", stage: "verify", message: "Skipped" });
      logPipelineEvent("research", "stage_skipped", { reason: "no_runtime", requestedRuntime: opts.runtime ?? "auto" });
      logPipelineEvent("verify", "stage_skipped", { reason: "no_runtime", requestedRuntime: opts.runtime ?? "auto" });
      // Skip research + verify, go straight to report
    }

    let findings: Finding[] = [];

    if (canUseAiRuntime) {
    const existingResearchSession = opts.resumeScanId ? db?.getSession(persistedScanId, prepared.resolvedType === "source-code" ? "review" : "audit") : null;
    const existingPersistedFindings = opts.resumeScanId
      ? ((db?.getFindings(persistedScanId) ?? []) as RestorablePersistedFindingRow[]).map(restorePersistedFinding)
      : [];
    const existingVerifiedFindings = existingPersistedFindings.filter((finding) => finding.status === "verified" || finding.status === "false-positive");
    const canResumeResearchSession = existingResearchSession?.status === "paused";
    const canSkipResearch = existingPersistedFindings.length > 0 && !canResumeResearchSession;

    startPhase("research");
    emit({
      type: "stage:start",
      stage: "research",
      message: canResumeResearchSession
        ? "Resuming AI research session..."
        : canSkipResearch
          ? "Reusing persisted research findings..."
          : "Researching vulnerabilities...",
    });
    logPipelineEvent("research", "stage_start", {
      resumed: canResumeResearchSession,
      reusedFindings: canSkipResearch,
    });

    const researchEmit: ScanListener = (event) => {
      if (event.type === "stage:start") {
        emit({ type: "stage:start", stage: "research", message: event.message });
      } else if (event.type === "thinking") {
        emit({ type: "thinking", stage: "research", message: event.message, data: event.data });
      } else if (event.type === "usage") {
        emit({ type: "usage", stage: "research", message: event.message, data: event.data });
      } else if (event.type === "error") {
        emit({ type: "error", stage: "research", message: event.message, data: event.data });
      } else if (event.type === "finding") {
        emit(event);
      }
    };

    if (canSkipResearch) {
      findings = existingPersistedFindings;
    } else if (
      prepared.resolvedType === "npm-package" ||
      prepared.resolvedType === "pypi-package" ||
      prepared.resolvedType === "cargo-package" ||
      prepared.resolvedType === "oci-image" ||
      prepared.resolvedType === "source-code"
    ) {
      const targetLabel = prepared.resolvedType === "source-code"
        ? "repository"
        : `${prepared.packageEcosystem === "pypi" ? "PyPI" : prepared.packageEcosystem === "cargo" ? "crates.io" : prepared.packageEcosystem === "oci" ? "OCI image" : "npm"} package ${prepared.packageName}@${prepared.packageVersion}`;
      const advisoryLabel =
        prepared.packageEcosystem === "pypi"
          ? "OSV PyPI advisory lookup"
          : prepared.packageEcosystem === "cargo"
            ? "OSV crates.io advisory lookup"
            : prepared.packageEcosystem === "oci"
              ? "OCI image dependency audit"
            : "npm audit";

      const agentSystemPrompt = researchPrompt(
        prepared.scopePath,
        semgrepFindings.map(f => ({ ruleId: f.ruleId, message: f.message, path: f.path, startLine: f.startLine })),
        npmAuditFindings.map(f => ({ name: f.name, severity: f.severity, title: f.title })),
        targetLabel,
        advisoryLabel,
      );

      // Log operator hypothesis for post-hoc analysis (#467)
      if (opts.hypothesis && prepared.resolvedType === "source-code") {
        emit({ type: "stage:start", stage: "research", message: `Operator hypothesis seeded: ${opts.hypothesis.slice(0, 200)}` });
      }

      // Pre-scan attack surface enumeration for kernel reviews (pwnkit#471).
      let attackSurfaceCtx: string | undefined;
      if (opts.reviewProfile === "linux-kernel" && prepared.resolvedType === "source-code") {
        try {
          const enumResult = enumerateAttackSurfaces({
            tree: prepared.scopePath,
            subsystem: opts.subsystem,
          });
          attackSurfaceCtx = formatAttackSurfaceForPrompt(enumResult);
        } catch {
          // Non-fatal — agent runs without attack surface context.
        }
      }

      const effectiveSystemPrompt = prepared.resolvedType === "source-code"
        ? (opts.reviewProfile === "linux-kernel"
            ? kernelReviewAgentPrompt(prepared.scopePath, semgrepFindings, undefined, opts.subsystem, opts.hypothesis, attackSurfaceCtx)
            : opts.reviewProfile === "c-library"
            ? cppReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "cardano-onchain"
            ? cardanoOnchainReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "solana-onchain"
            ? solanaOnchainReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "evm-onchain"
            ? evmOnchainReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "cairo-onchain"
            ? cairoOnchainReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "move-onchain"
            ? moveOnchainReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "cardano-haskell"
            ? cardanoHaskellReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.hypothesis)
            : opts.reviewProfile === "xnu-kernel"
            ? xnuKernelReviewAgentPrompt(prepared.scopePath, semgrepFindings, undefined, opts.subsystem, opts.hypothesis)
            : opts.reviewProfile === "xnu-re"
            ? xnuReReviewAgentPrompt(prepared.scopePath, semgrepFindings, opts.subsystem, opts.hypothesis)
            : reviewAgentPrompt(prepared.scopePath, semgrepFindings, changedFiles, !!opts.changedOnly, opts.hypothesis))
        : agentSystemPrompt;

      // Per-file research loop (#285). When `perItemOrchestration` is on,
      // we run one agent session per source file with a focused per-file
      // prompt — this guarantees full coverage instead of relying on the
      // model to walk every file inside a single shared session (which
      // historically skipped, deduped, or condensed past ~30 files).
      //
      // Scoped to package-research targets (npm / pypi / cargo / oci); the
      // `source-code` review path uses profile-specific prompts (kernel,
      // c-library, default review) and is intentionally untouched here.
      const usePerFileLoop =
        agentFeatures.perItemOrchestration &&
        prepared.resolvedType !== "source-code";

      try {
        if (usePerFileLoop) {
          const sourceFiles = collectScopeFiles(prepared.scopePath);
          if (sourceFiles.length === 0) {
            // Nothing to walk — fall back to the single-shot session so we
            // still take a whole-package look (e.g. inspecting package.json
            // metadata, examining built artifacts).
            const agentResult = await runAnalysisAgent({
              role: "audit",
              scopePath: prepared.scopePath,
              target: prepared.resolvedTarget,
              scanId: persistedScanId,
              sessionId: canResumeResearchSession ? existingResearchSession.id : undefined,
              config: {
                runtime: opts.runtime,
                timeout: opts.timeout,
                depth: opts.depth,
                apiKey: opts.apiKey,
                model: opts.model,
                costCeilingUsd: opts.costCeilingUsd,
                costLedger,
              },
              db,
              emit: researchEmit,
              cliPrompt: buildCliPrompt(
                prepared.scopePath,
                semgrepFindings,
                npmAuditFindings,
                targetLabel,
                advisoryLabel,
                changedFiles,
                !!opts.changedOnly,
              ),
              agentSystemPrompt: effectiveSystemPrompt,
              cliSystemPrompt:
                "You are a security researcher performing an authorized source code audit. For EACH vulnerability you find, output it using the exact ---FINDING--- / ---END--- format specified in the prompt. Do NOT write prose analysis — only output structured finding blocks. If you find no vulnerabilities, say 'No vulnerabilities found.' and nothing else.",
            });
            recordUsage(agentResult);
            findings = agentResult.findings;
          } else {
            findings = await runPerFileResearch({
              scopePath: prepared.scopePath,
              target: prepared.resolvedTarget,
              scanId: persistedScanId,
              files: sourceFiles,
              semgrepFindings,
              npmAuditFindings,
              targetLabel,
              advisoryLabel,
              invoke: ({ systemPrompt, cliSystemPrompt }) =>
                runAnalysisAgent({
                  role: "audit",
                  scopePath: prepared.scopePath,
                  target: prepared.resolvedTarget,
                  scanId: persistedScanId,
                  // Don't reuse the resume sessionId across multiple per-file
                  // calls — the resumable session is a single-prompt shape and
                  // would be wrongly reattached to the second file's session.
                  config: {
                    runtime: opts.runtime,
                    timeout: opts.timeout,
                    depth: opts.depth,
                    apiKey: opts.apiKey,
                    model: opts.model,
                    costCeilingUsd: opts.costCeilingUsd,
                    costLedger,
                  },
                  db,
                  emit: researchEmit,
                  cliPrompt: buildCliPrompt(
                    prepared.scopePath,
                    semgrepFindings,
                    npmAuditFindings,
                    targetLabel,
                    advisoryLabel,
                    changedFiles,
                    !!opts.changedOnly,
                  ),
                  agentSystemPrompt: systemPrompt,
                  cliSystemPrompt,
                }),
              onUsage: recordUsage,
              onFileStart: (fileRel, i, total) => {
                emit({
                  type: "stage:start",
                  stage: "research",
                  message: `Researching file ${i + 1}/${total}: ${fileRel}`,
                });
              },
              onFileError: (fileRel, perFileErr) => {
                warnings.push({ stage: "research", message: `Per-file analysis failed (${fileRel}): ${perFileErr.message}` });
                logPipelineEvent("research", "warning", { message: `Per-file analysis failed (${fileRel}): ${perFileErr.message}` });
              },
            });
          }
        } else {
          const agentResult = await runAnalysisAgent({
            role: prepared.resolvedType === "source-code" ? "review" : "audit",
            scopePath: prepared.scopePath,
            target: prepared.resolvedTarget,
            scanId: persistedScanId,
            sessionId: canResumeResearchSession ? existingResearchSession.id : undefined,
            config: {
              runtime: opts.runtime,
              timeout: opts.timeout,
              depth: opts.depth,
              apiKey: opts.apiKey,
              model: opts.model,
              costCeilingUsd: opts.costCeilingUsd,
              costLedger,
            },
            db,
            emit: researchEmit,
            cliPrompt: buildCliPrompt(
              prepared.scopePath,
              semgrepFindings,
              npmAuditFindings,
              targetLabel,
              advisoryLabel,
              changedFiles,
              !!opts.changedOnly,
            ),
            agentSystemPrompt: effectiveSystemPrompt,
            cliSystemPrompt:
              "You are a security researcher performing an authorized source code audit. For EACH vulnerability you find, output it using the exact ---FINDING--- / ---END--- format specified in the prompt. Do NOT write prose analysis — only output structured finding blocks. If you find no vulnerabilities, say 'No vulnerabilities found.' and nothing else.",
          });
          recordUsage(agentResult);
          findings = agentResult.findings;
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({ stage: "research", message: `AI analysis failed: ${msg}` });
        logPipelineEvent("research", "warning", { message: `AI analysis failed: ${msg}` });
      }
    } else {
      // URL / web-app targets — not supported yet in unified pipeline
      warnings.push({
        stage: "research",
        message: `Target type "${prepared.resolvedType}" is not yet supported in the unified pipeline. Use 'pwnkit scan' for URL/web-app targets.`,
      });
      logPipelineEvent("research", "warning", {
        message: `Target type "${prepared.resolvedType}" is not yet supported in the unified pipeline.`,
      });
    }

    emit({
      type: "stage:end",
      stage: "research",
      message: `${findings.length} findings discovered`,
    });
    logPipelineEvent("research", "stage_complete", { findings: findings.length });

    // ── PHASE 3.5: npm DYNAMIC DISCOVERY (opt-in) ──
    // A first-class, selectable discovery stage that sweeps the target npm
    // package with the pluggable detector registry (SSPP fuzz / validation
    // read-stability / SSRF parser-diff) in a disposable sandbox. It runs
    // independently of the AI review (even when no LLM runtime is configured),
    // and its confirmed leads are appended to `findings` HERE — before VERIFY —
    // so they flow through the exact same blind-verify → disclosure path as the
    // agent's findings. Gated: off unless `--npm-dynamic` / the env toggle is
    // set AND the target is an npm-ecosystem package (cost/latency discipline).
    if (!opts.resumeScanId && shouldRunNpmDynamicDiscovery(opts, prepared)) {
      startPhase("npm-dynamic-discovery");
      emit({
        type: "stage:start",
        stage: "npm-dynamic-discovery",
        message: `Dynamic-discovery sweep of ${prepared.packageName}...`,
      });
      logPipelineEvent("npm-dynamic-discovery", "stage_start", {
        package: prepared.packageName,
        version: prepared.packageVersion,
      });
      const discovery = await runNpmDynamicDiscoveryStage({
        packageName: prepared.packageName!,
        packageVersion: prepared.packageVersion,
        runner: opts.npmDynamicRunner,
        log: (m) => logPipelineEvent("npm-dynamic-discovery", "progress", { message: m }),
      });
      for (const w of discovery.warnings) {
        warnings.push({ stage: "npm-dynamic-discovery", message: w });
      }
      if (discovery.findings.length > 0) {
        findings = findings.concat(discovery.findings);
      }
      emit({
        type: "stage:end",
        stage: "npm-dynamic-discovery",
        message: `${discovery.findings.length} confirmed dynamic lead(s)`,
      });
      logPipelineEvent("npm-dynamic-discovery", "stage_complete", {
        findings: discovery.findings.length,
        warnings: discovery.warnings.length,
      });
    }

    // ── PHASE 4: VERIFY (parallel blind agents) ──
    if (
      findings.length > 0 &&
      (prepared.resolvedType === "source-code" || prepared.resolvedType === "npm-package" || prepared.resolvedType === "pypi-package" || prepared.resolvedType === "cargo-package" || prepared.resolvedType === "oci-image")
    ) {
      // #416 Bug A: a resumed scan whose verify wave already completed has
      // every finding sitting in storage with status='verified' or
      // 'false-positive'. We can — and must — short-circuit before
      // consulting `verificationRuntime`. Otherwise the runtime fail-close
      // below (Bug B) clobbers those persisted verdicts.
      const canSkipVerify =
        existingVerifiedFindings.length === findings.length &&
        findings.length > 0;

      startPhase("verify");
      emit({
        type: "stage:start",
        stage: "verify",
        message: canSkipVerify
          ? `Reusing persisted verification results for ${findings.length} findings...`
          : `Blind-verifying ${findings.length} findings...`,
      });
      logPipelineEvent("verify", "stage_start", {
        reusedFindings: canSkipVerify,
        findingCount: findings.length,
      });

      if (canSkipVerify) {
        // #416 Bug B: this branch MUST run before the `!verificationRuntime`
        // check below. A resumed scan with no API key still has fully
        // verified findings on disk; force-flipping them to false-positive
        // here would silently destroy real verdicts on every resume.
        findings = existingVerifiedFindings;
        const confirmedCount = findings.filter((finding: Finding) => finding.status === "verified").length;
        const rejectedCount = findings.filter((finding: Finding) => finding.status === "false-positive").length;
        emit({
          type: "stage:end",
          stage: "verify",
          message: `Verification reused: ${confirmedCount} confirmed, ${rejectedCount} rejected`,
        });
        logPipelineEvent("verify", "stage_complete", {
          confirmed: confirmedCount,
          rejected: rejectedCount,
          reused: true,
        });
      } else if (!verificationRuntime) {
        warnings.push({
          stage: "verify",
          message: "Verification skipped because no verifier runtime is available. Findings were dropped rather than fail open.",
        });
        findings = findings.map((finding) => ({ ...finding, status: "false-positive" as Finding["status"] }));
        // #416 Bug A: persist the forced verdict so a subsequent resume —
        // possibly with an API key available — sees a consistent verify
        // state instead of re-running the whole phase.
        for (const f of findings) {
          try {
            db?.saveFinding(persistedScanId, f);
          } catch (persistErr) {
            const msg = persistErr instanceof Error ? persistErr.message : String(persistErr);
            warnings.push({ stage: "verify", message: `Failed to persist verify verdict for "${f.title}": ${msg}` });
          }
        }
        emit({
          type: "stage:end",
          stage: "verify",
          message: "Verification skipped — no verifier runtime available",
        });
        logPipelineEvent("verify", "stage_skipped", { reason: "no_runtime" });
      } else if (scanCostCeilingTripped()) {
        // Budget exhausted by the research phase. Launching the blind-verify
        // wave anyway would spend past the hard per-scan ceiling: the shared
        // ledger trips each verify session only AFTER its first turn's LLM
        // call, so N concurrent verifiers would still burn N turns of
        // over-ceiling spend. Skip the wave entirely and hold every finding
        // as unverified via the inconclusive route (isDisclosureWorthy keeps
        // non-rejected verdicts → publishability needs_verify) — nothing is
        // silently confirmed. The report below is stamped costCeilingExceeded,
        // so the run lands cost_exceeded rather than a clean pass.
        warnings.push({
          stage: "verify",
          message: `Verification skipped: scan cost ceiling of $${opts.costCeilingUsd} reached during research ($${costLedger.costUsd(opts.model).toFixed(4)} spent). Findings left unverified.`,
        });
        findings = findings.map((finding) => {
          const decision = isDisclosureWorthy(finding, "inconclusive");
          if (!decision.keep) {
            return { ...finding, status: "false-positive" as Finding["status"] };
          }
          return {
            ...finding,
            publishability: "needs_verify" as Finding["publishability"],
            triageNote: `blind-verify skipped (scan cost ceiling reached): ${decision.reason}`,
          };
        });
        // Persist the held/dropped verdicts so a resume doesn't re-run (or
        // wrongly skip) verify against an already-exhausted budget.
        for (const f of findings) {
          try {
            db?.saveFinding(persistedScanId, f);
          } catch {
            // best-effort: don't compound a budget skip with a persistence error
          }
        }
        emit({
          type: "stage:end",
          stage: "verify",
          message: "Verification skipped — scan cost ceiling reached",
        });
        logPipelineEvent("verify", "stage_skipped", { reason: "cost_ceiling" });
      } else {
      try {
        const verifyResults = await Promise.all(
          findings.map(async (finding) => {
            // Extract file path from evidence_request field
            const filePath = finding.evidence.request || "";
            // Extract PoC from evidence_response (the PoC code)
            const poc = finding.evidence.response || finding.evidence.analysis || "";
            const claimedSeverity = finding.severity;

            const verifySystemPrompt = blindVerifyPrompt(
              filePath,
              poc,
              claimedSeverity,
              prepared.scopePath,
            );

            // #416 Bug C: the inner verifyEmit previously re-fired
            // `verify:result` on every `finding` event from the verify
            // agent. The outer findings.map (below) is the single source
            // of truth for verify:result — it knows confirmed vs
            // rejected, fires exactly once per input finding, and
            // matches the `{ confirmed, title, reason }` shape SSE/TUI
            // consumers actually read. So forward inner agent events
            // *without* synthesizing extra verify:result frames here.
            const verifyEmit: ScanListener = () => {
              // intentionally silent: see comment above
            };

            try {
              const agentResult = await runAnalysisAgent({
                role: "review",
                purpose: "verify",
                scopePath: prepared.scopePath,
                target: prepared.resolvedTarget,
                scanId: `${persistedScanId}-verify`,
                config: {
                  runtime: verificationRuntime,
                  timeout: Math.min(opts.timeout ?? 120_000, 120_000),
                  depth: "quick",
                  apiKey: opts.apiKey,
                  model: opts.model,
                  costCeilingUsd: opts.costCeilingUsd,
                  costLedger,
                },
                db: null,
                emit: verifyEmit,
                cliPrompt: `Verify this vulnerability in ${filePath}:\n\nPoC:\n${poc}\n\nClaimed severity: ${claimedSeverity}\n\nRead the file, trace data flow, confirm or reject.`,
                agentSystemPrompt: verifySystemPrompt,
                cliSystemPrompt: "You are a blind verification agent. Read the file, trace the PoC, confirm or reject the vulnerability.",
              });
              // Attribute this verify agent's tokens/turns to the verify phase.
              // Safe under the concurrent findings.map: these are return-value
              // sums, so interleaving never double-counts or races.
              recordUsage(agentResult);
              const verifiedFindings = agentResult.findings;

              // Budget truncation ≠ rejection. When the shared per-scan ledger
              // tripped mid-wave, this verifier stopped on budget — possibly
              // before it could attempt a reproduction. Returning an empty
              // findings list here would read as "rejected" and drop the
              // finding as a false positive on a scan that lands
              // cost_exceeded; an honest `inconclusive` holds it for review
              // instead (isDisclosureWorthy keeps non-rejected verdicts),
              // matching the verifier-error path (#599).
              if (agentResult.costCeilingExceeded) {
                const verdict: VerifyVerdict = {
                  verdict: "inconclusive",
                  confidence: finding.confidence ?? 0,
                  reasoning: "Verification truncated: scan cost ceiling reached.",
                  signals: [{ name: "blind_verify", passed: false, reasoning: "cost ceiling reached mid-verify" }],
                  evidenceKind: evidenceKindForFinding(finding),
                };
                return { finding, verdict, verifiedFinding: null };
              }

              const confirmed = verifiedFindings.length > 0;
              // Evidence basis (#674): native emission of reproduced-poc vs
              // source-only, derived from the finding's PoC signals — kept
              // identical to the 0cloud derivation so they never diverge.
              const evidenceKind = evidenceKindForFinding(finding);
              // Emit the unified VerifyVerdict contract so the static/code path
              // converges on the same shape the agentic/web path emits.
              const verdict: VerifyVerdict = confirmed
                ? {
                    verdict: "confirmed",
                    confidence: verifiedFindings[0]?.confidence ?? finding.confidence ?? 0,
                    reasoning: "Blind verifier independently reproduced the finding.",
                    signals: [{ name: "blind_verify", passed: true }],
                    evidenceKind,
                  }
                : {
                    verdict: "rejected",
                    confidence: finding.confidence ?? 0,
                    reasoning: "Could not independently reproduce",
                    signals: [{ name: "blind_verify", passed: false, reasoning: "Could not independently reproduce" }],
                    evidenceKind,
                  };
              return { finding, verdict, verifiedFinding: verifiedFindings[0] ?? null };
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              warnings.push({ stage: "verify", message: `Verification failed for "${finding.title}": ${msg}` });
              // A verifier that threw did NOT decide the finding is a false
              // positive — it failed to decide. Emit `inconclusive` so the
              // finding is never auto-dropped on an error (#599 / #518).
              const verdict: VerifyVerdict = {
                verdict: "inconclusive",
                confidence: 0,
                reasoning: `Verifier error: ${msg}`,
                signals: [{ name: "blind_verify", passed: false, reasoning: `Verifier error: ${msg}` }],
                evidenceKind: evidenceKindForFinding(finding),
              };
              return { finding, verdict, verifiedFinding: null };
            }
          }),
        );

        // Emit results and filter
        let confirmedCount = 0;
        let rejectedCount = 0;
        let heldCount = 0;

        findings = verifyResults
          .map(({ finding, verdict, verifiedFinding }) => {
            if (verdict.verdict === "confirmed") {
              confirmedCount++;
              emit({ type: "verify:result", message: `Confirmed: ${finding.title}`, data: { confirmed: true, title: finding.title } });
              return {
                ...finding,
                status: "verified" as Finding["status"],
                confidence: verifiedFinding?.confidence ?? finding.confidence,
                severity: verifiedFinding?.severity ?? finding.severity,
              };
            }
            // Not confirmed (rejected or inconclusive). Route the drop through
            // the one disclosure predicate: a disclosure-grade finding is held
            // for human review (never silently dropped), and an inconclusive
            // verdict is always kept. Everything else drops as a false positive.
            const decision = isDisclosureWorthy(finding, verdict);
            if (!decision.keep) {
              rejectedCount++;
              emit({ type: "verify:result", message: `Rejected: ${finding.title}`, data: { confirmed: false, title: finding.title, reason: verdict.reasoning } });
              return { ...finding, status: "false-positive" as Finding["status"] };
            }
            heldCount++;
            emit({ type: "verify:result", message: `Held for review: ${finding.title}`, data: { confirmed: false, title: finding.title, reason: `${verdict.reasoning} — held (${decision.reason})` } });
            return {
              ...finding,
              publishability: "needs_verify" as Finding["publishability"],
              triageNote: `blind-verify ${verdict.verdict} but held for review (${decision.guard ?? "inconclusive"}): ${decision.reason}`,
            };
          });

        // #416 Bug A: persist the verify verdict for each finding so a
        // subsequent resume can short-circuit through the canSkipVerify
        // branch above. Without this round-trip the verify phase re-runs
        // on every resume even though storage already knows the answer.
        //
        // We re-save the full Finding (saveFinding does INSERT … ON
        // CONFLICT UPDATE), so verificationSpec / pocSteps / evidence
        // round-trip rather than getting nulled out. A focused partial
        // update would be safer if other code paths mutated the same row
        // concurrently, but the verify phase is the sole writer here.
        for (const f of findings) {
          try {
            db?.saveFinding(persistedScanId, f);
          } catch (persistErr) {
            const msg = persistErr instanceof Error ? persistErr.message : String(persistErr);
            warnings.push({ stage: "verify", message: `Failed to persist verify verdict for "${f.title}": ${msg}` });
          }
        }

        emit({
          type: "stage:end",
          stage: "verify",
          message: `Verification complete: ${confirmedCount} confirmed, ${rejectedCount} rejected${heldCount > 0 ? `, ${heldCount} held for review` : ""}`,
        });
        logPipelineEvent("verify", "stage_complete", {
          confirmed: confirmedCount,
          rejected: rejectedCount,
          heldForReview: heldCount,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push({ stage: "verify", message: `Verification failed: ${msg}` });
        findings = findings.map((finding) => ({ ...finding, status: "false-positive" as Finding["status"] }));
        // #416 Bug A: persist the catch-all forced verdict too — without
        // this, the next resume sees no verified findings and re-runs
        // verify against an already-broken runtime.
        for (const f of findings) {
          try {
            db?.saveFinding(persistedScanId, f);
          } catch {
            // best-effort: don't compound a verify error with a persistence error
          }
        }
        emit({ type: "stage:end", stage: "verify", message: `Verification failed: ${msg}` });
        logPipelineEvent("verify", "warning", { message: `Verification failed: ${msg}` });
      }
      }
    }

    } // end of hasApiKey || hasCliRuntime else block

    // ── PHASE 5: BUILD REPORT ──
    startPhase("report");
    const confirmedFindings = findings.filter((f) => f.status !== "false-positive");

    // Public-advisory novelty gate (issue #851) on the OSS-package scan path.
    // agenticScan only runs this for url/web-app targets (mostly private → the
    // gate no-ops there); the findings that actually need it are OSS package
    // findings (npm/pypi/cargo), which route through runPipeline and never hit
    // the gate. Resolve ONCE per scan — the package+version is identical for
    // every finding on this target — then stamp each confirmed finding.
    //
    // Guardrails mirror agentic-scanner.ts: gated on the publishabilityGate
    // feature flag, OSS ecosystems only (npm/pypi/cargo; `oci`/unset map to no
    // OSV ecosystem so resolveNovelty no-ops), and fail-soft — any error leaves
    // the verdict undefined and behavior unchanged (never drops a finding).
    if (
      agentFeatures.publishabilityGate &&
      confirmedFindings.length > 0 &&
      (prepared.packageEcosystem === "npm" ||
        prepared.packageEcosystem === "pypi" ||
        prepared.packageEcosystem === "cargo") &&
      prepared.packageName
    ) {
      try {
        const novelty = await resolveNovelty(
          prepared.packageName,
          prepared.packageEcosystem,
          prepared.packageVersion,
        );
        if (novelty) {
          // Stamp every confirmed finding. The verdict rides on the returned
          // Finding objects (report.findings); the cloud worker that invokes
          // runPipeline persists them via the orchestrator PATCH
          // /findings/:id/publishability path wired in the prior commit (the
          // local SQLite resume store has no novelty column, so there is
          // nothing extra to re-save here).
          for (const finding of confirmedFindings) {
            finding.noveltyVerdict = novelty.verdict;
            if (novelty.advisoryMatches.length > 0) {
              finding.advisoryMatches = novelty.advisoryMatches;
            }
          }
        }
      } catch {
        // novelty is advisory-only; a network blip must never fail the scan
      }
    }

    const durationMs = Date.now() - startTime;
    const summary = buildSummary(confirmedFindings, semgrepFindings.length + npmAuditFindings.length);

    // Scan-wide budget verdict: the shared ledger reached the hard ceiling
    // (research tripped it, or the verify wave was skipped / truncated on
    // budget). Stamped on the report so the CLI exits 4 and the cloud lands
    // the scan cost_exceeded — a budget-truncated run must never read as a
    // clean completion (0review merge policy; see the audit path's
    // cost-ceiling short-circuit in agentic-scanner.ts).
    const costCeilingExceeded = scanCostCeilingTripped();

    db?.completeScan(persistedScanId, summary);
    logPipelineEvent("report", "stage_complete", summary as unknown as Record<string, unknown>);

    const report: PipelineReport = {
      target: opts.target,
      targetType: prepared.resolvedType,
      startedAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs,
      summary,
      findings: confirmedFindings,
      warnings,
      // Backwards-compat extras
      ...(costCeilingExceeded
        ? { costCeilingExceeded: true, exitReason: "cost_ceiling_exceeded" as const }
        : {}),
      ...(prepared.resolvedType === "npm-package" || prepared.resolvedType === "pypi-package" || prepared.resolvedType === "cargo-package" || prepared.resolvedType === "oci-image"
        ? {
            package: prepared.packageName,
            version: prepared.packageVersion,
            npmAuditFindings,
            semgrepFindings: semgrepFindings.length,
          }
        : {}),
      ...(prepared.resolvedType === "source-code"
        ? {
            repo: opts.target,
            semgrepFindings: semgrepFindings.length,
          }
        : {}),
    };

    // Close the report phase before the terminal scan_completed so the
    // dashboard sees a fully-bracketed phase timeline.
    finishPhase();

    emitPipelineScanCompleted(costCeilingExceeded ? "cost_exceeded" : "completed", {
      findings: confirmedFindings.length,
      summary: `${confirmedFindings.length} finding(s), ${semgrepFindings.length + npmAuditFindings.length} automated lead(s)`,
    });

    return report;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    db?.failScan(persistedScanId, msg);
    logPipelineEvent("report", "stage_error", { error: msg });
    emitPipelineScanCompleted("failed", { summary: msg });
    throw err;
  } finally {
    unsubscribeMetrics();
    db?.close();
    // Clean up temporary directories
    if (prepared.needsCleanup && prepared.tempDir) {
      try {
        rmSync(prepared.tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
  }
}
