import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import chalk from "chalk";
import { VERSION } from "@0sec/shared";
import type { ScanDepth, OutputFormat, RuntimeMode, ScanMode, AuthConfig, ScanReport, SeedFinding } from "@0sec/shared";
import type { CostBreakdownEntry } from "@0sec/core";
import { formatAuditReport, formatReviewReport, formatReport, generatePdfReport } from "../formatters/index.js";
import { buildShareUrl, checkRuntimeAvailability, getRuntimeAvailability } from "../utils.js";
import { formatCrossValidatedLeads, type CrossValidatedLeadsSummary } from "./cross-validated-leads.js";
import { resolveOsecRunStorage, writeOsecRunReport } from "@0sec/db";
import { runDeepReview } from "./deep-review.js";

interface ScanCompletedCost {
  cost_usd: number;
  cost_breakdown?: CostBreakdownEntry[];
  cost_per_flag?: number;
}

type CoreModule = typeof import("@0sec/core");

let coreModulePromise: Promise<CoreModule> | null = null;

async function loadCoreModule(): Promise<CoreModule> {
  if (!coreModulePromise) {
    // Under Bun in a dev workspace checkout we can import the TypeScript
    // source directly, skipping the compile step. In the packaged tarball
    // that path doesn't exist, so fall back to the bundled module. The
    // presence-check keeps both Bun-dev and Bun-prod users happy.
    const srcUrl = new URL("../../../core/src/index.ts", import.meta.url);
    const srcExists = process.versions.bun && existsSync(fileURLToPath(srcUrl));
    coreModulePromise = srcExists
      ? import(srcUrl.href) as Promise<CoreModule>
      : import("@0sec/core");
  }
  return coreModulePromise;
}

export interface RunOptions {
  target: string;
  targetType?: "npm-package" | "pypi-package" | "cargo-package" | "oci-image" | "source-code" | "url" | "web-app";
  resumeScanId?: string;
  /** Fork from a specific journal entry within the resumed run (wires `branchJournal`). Requires `resumeScanId`. */
  branchFromEntry?: number;
  diffBase?: string;
  changedOnly?: boolean;
  /** Prior findings to use as untrusted variant-hunting context on a fresh review. */
  priorFindings?: Array<{
    id: string;
    title: string;
    category: string;
    description?: string;
    location?: string;
  }>;
  depth: ScanDepth;
  format: OutputFormat;
  runtime: RuntimeMode;
  mode?: ScanMode;
  /**
   * Source review execution strategy. The primary control plane uses
   * `lenses`, which is the validated self-evolving source-review path.
   */
  reviewStrategy?: "pipeline" | "lenses";
  timeout: number;
  verbose: boolean;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  packageVersion?: string;
  reportPath?: string;
  repoPath?: string;
  auth?: AuthConfig;
  apiSpecPath?: string;
  exportTarget?: string;
  race?: boolean;
  egats?: boolean;
  /** Hard per-scan USD cost ceiling. Aborts cleanly with partial findings if exceeded. */
  costCeilingUsd?: number;
  /** Per-host rate-limit spec (#214). Plain "5" or "host=rps,host2=rps:burst,default". */
  rateLimit?: string;
  /** Open the operator TUI after the run completes. */
  tui?: boolean;
  /** Path to a JSON scope file (0sec#215). Threaded into ScanConfig.scopeFile. */
  scopeFile?: string;
  /** Opt-out for the scanner-binary suppression gate (0sec#217). Threaded into ScanConfig.allowScanners. */
  allowScanners?: boolean;
  /** Repeatable `--attribution-header NAME=VALUE` (0sec#216). */
  attributionHeaders?: string[];
  /** `--attribution-ua <token>` (0sec#216). */
  attributionUaToken?: string;
  /**
   * `--engagement-profile <name>` — engagement hardening posture
   * (`standard` / `conservative`). Threaded into ScanConfig.engagementProfile.
   */
  engagementProfile?: string;
  /**
   * `--no-waf-evasion` → false. Standalone opt-out for the adaptive
   * WAF-evasion ladder, independent of the engagement profile.
   */
  wafEvasion?: boolean;
  /**
   * http_audit env-bridge config (FROZEN CONTRACT). Populated by the scan
   * command from 0SEC_TARGET_* env vars only when `mode === "http_audit"`;
   * undefined otherwise. The core (`agenticScan`) turns these into an
   * in-memory ScopePolicy (host allowlist), PathPolicy (path-prefix
   * allowlist), per-host RateLimiter, and a wall-clock kill switch, all
   * aggregated into the report's `enforcement_summary` block.
   */
  httpAuditAllowedHosts?: string[];
  httpAuditAllowedPaths?: string[];
  httpAuditRateLimitRps?: number;
  httpAuditKillAfterSec?: number;
  /**
   * Tool-call dispatch protocol (0sec#232) — `json`, `xml`, or `auto`.
   * Threaded into ScanConfig.dispatchMode and consulted only by the
   * legacy text-based agent loop.
   */
  dispatchMode?: "json" | "xml" | "auto";
  /**
   * Review profile (only applied when targetType === "source-code").
   * "c-library" tunes the prompt for C/C++ memory-safety + tier-1/2/3
   * harness construction. "linux-kernel" tunes for kernel-aware static
   * review (syscall/ioctl surface, copy_from_user, refcount races,
   * Dirty Frag class). "cardano-onchain" tunes for Aiken/Plutus EUTXO
   * validator logic bugs (double satisfaction, missing signer checks,
   * unconserved value, unauthorized mint). "solana-onchain" tunes for Solana
   * Anchor/native Rust account-model authorization bugs (missing signer/owner
   * checks, account substitution, missing PDA validation, arbitrary CPI,
   * missing has_one, AMM/lending overflow). "evm-onchain" tunes for Solidity /
   * Foundry / Hardhat DeFi/bridge value-logic bugs (reentrancy, missing
   * access control / init front-run, oracle & price manipulation,
   * first-depositor share inflation, signature/permit replay, cross-chain
   * message verification & replay, delegatecall/proxy storage collision,
   * unchecked external-call return). "cairo-onchain" tunes for Cairo/Starknet
   * DeFi value-logic bugs (caller/ownership auth gaps, fixed-point
   * share-conversion rounding, reentrancy via call_contract, storage
   * default-value trust, L1↔L2 message / l1_handler access control, oracle
   * staleness). "move-onchain" tunes for Sui/Aptos Move resource/capability
   * bugs (object/capability ownership & instance-binding gaps, shared-math
   * overflow/truncation, uninitialized reward-index accounting, capability
   * leakage, shared-object races, init/one-time-witness misuse, coin
   * conservation). "cardano-haskell" tunes for
   * first-party Cardano Haskell node-stack bugs (partial-function/decoder
   * crashes on untrusted input, FFI memory-safety, lazy-eval space leaks,
   * Plutus-VM budget/eval flaws, ledger STS rule gaps). "xnu-kernel" tunes
   * for Apple XNU (Mach trap/MIG, IOKit externalMethod, BSD copyin, Mach
   * port/VM). "xnu-re" reviews DECOMPILED Apple kext pseudo-C (closed kexts
   * from a kernelcache). Default: "default".
   */
  reviewProfile?: "default" | "c-library" | "linux-kernel" | "cardano-onchain" | "solana-onchain" | "evm-onchain" | "cairo-onchain" | "move-onchain" | "cardano-haskell" | "xnu-kernel" | "xnu-re";
  /**
   * Review the source of a published package: `target` is a package NAME and
   * the pipeline installs it (npm/pypi/cargo/oci) before reviewing its
   * extracted source. `packageVersion` pins the version. Only honored with
   * `targetType === "source-code"`. See unified-pipeline `reviewPackageEcosystem`.
   */
  reviewPackageEcosystem?: "npm" | "pypi" | "cargo" | "oci";
  /**
   * Restrict analysis to files under this subdirectory. Only meaningful when
   * `reviewProfile === "linux-kernel"`. The value is injected into the agent
   * prompt as a scope restriction (e.g. `crypto/`, `net/tcp/`).
   */
  subsystem?: string;
  /** Operator hypothesis for directed research. */
  hypothesis?: string;
  /** PR/MR discussion thread (untrusted) to review against. */
  conversation?: string;
  /**
   * Pre-computed candidate vulnerable spans, parsed from an external producer
   * (today: GemmaForge, schema `gemmaforge.leads/v1`). Only consumed when
   * `targetType === "source-code"`. See `0sec#368` for the broader plan to
   * inject these into the agent's worklist before static scanner prioritisation runs.
   */
  seedFindings?: SeedFinding[];
  /** Skip semgrep entirely and rely solely on `seedFindings`. */
  seedOnly?: boolean;
  /**
   * Opt-in: also run the npm dynamic-discovery detector sweep over the target
   * package (only effective for npm-ecosystem package reviews/audits). Confirmed
   * leads flow into the same verify → disclosure path as the review findings.
   */
  npmDynamicDiscovery?: boolean;
  /**
   * Emit target (0sec#377). Default unset → existing terminal/json/etc.
   * `pr` → turn each reproduced finding into a GitHub PR (repro + suggested
   * patch from the fix-template registry). Unverified findings roll up into
   * a single `hypotheses.md`.
   */
  emit?: "pr";
  /** Base branch for `--emit pr`. Default "main". */
  emitPrBase?: string;
  /**
   * Dry-run for `--emit pr`. When set, prints `git`/`gh` commands instead of
   * executing them. Automatically forced on when `gh auth status` fails.
   */
  emitPrDryRun?: boolean;
  /**
   * Output directory (used by `--emit pr` for `hypotheses.md`). Defaults to
   * the system temp dir when unset.
   */
  emitOutDir?: string;
  sessionUiFactory?: (options: {
    target: string;
    depth: string;
    mode: "scan" | "audit" | "review";
  }) => Promise<{
    onEvent: (event: any) => void;
    setReport: (report: any) => void;
    waitForExit: () => Promise<void>;
    getPendingUserMessages?: () => string[];
  }>;
}

interface ResultLinePayload {
  ok: boolean;
  exitCode: number;
  exit_reason: string;
  target: string;
  targetType?: string;
  runtime: RuntimeMode;
  format: OutputFormat;
  cost_usd?: number;
  token_input?: number;
  token_output?: number;
  finding_count?: number;
  estimatedCostUsd?: number;
  usage?: { inputTokens: number; outputTokens: number };
  summary?: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  error?: string;
}

function toScanReport(report: any): ScanReport {
  if (report.targetType === "npm-package" || report.targetType === "pypi-package" || report.targetType === "cargo-package" || report.targetType === "oci-image") {
    return {
      target: `${report.package}@${report.version}`,
      scanDepth: "deep",
      startedAt: report.startedAt,
      completedAt: report.completedAt,
      durationMs: report.durationMs,
      summary: report.summary,
      findings: report.findings,
      warnings: [],
    };
  }

  if (report.targetType === "source-code") {
    return {
      target: report.repo,
      scanDepth: "deep",
      startedAt: report.startedAt,
      completedAt: report.completedAt,
      durationMs: report.durationMs,
      summary: report.summary,
      findings: report.findings,
      warnings: report.warnings ?? [],
      executionSuccessful: report.researchFailed ? false : undefined,
    };
  }

  return report as ScanReport;
}

function getEstimatedCost(report: any): number | undefined {
  if (typeof report?.estimatedCostUsd === "number") return report.estimatedCostUsd;
  if (typeof report?.benchmarkMeta?.estimatedCostUsd === "number") return report.benchmarkMeta.estimatedCostUsd;
  return undefined;
}

function getUsage(report: any): { inputTokens: number; outputTokens: number } | undefined {
  return report?.usage;
}

function getTargetType(report: any, opts: RunOptions): string | undefined {
  return report?.targetType ?? opts.targetType;
}

function emitResultLine(payload: ResultLinePayload): void {  if (process.env["0SEC_EMIT_RESULT_LINE"] !== "1" && !process.env["0SEC_CLOUD_SINK"]) return;
  console.log(`0SEC_RESULT=${JSON.stringify(payload)}`);
}

function getCloudFinalSinkConfig(): { sinkUrl: string; scanId: string; token?: string } | null {
  if (process.env["0SEC_FEATURE_CLOUD_SINK"] === "0") return null;
  const sinkUrl = process.env["0SEC_CLOUD_SINK"]?.trim();
  const scanId = process.env["0SEC_CLOUD_SCAN_ID"]?.trim();
  if (!sinkUrl || !scanId) return null;
  const token = process.env["0SEC_CLOUD_TOKEN"]?.trim() || undefined;
  return { sinkUrl, scanId, token };
}

function isCostBreakdownEntry(value: unknown): value is CostBreakdownEntry {
  if (!value || typeof value !== "object") return false;
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.provider === "string" &&
    typeof entry.model === "string" &&
    typeof entry.cost_in === "number" &&
    typeof entry.cost_out === "number" &&
    (entry.cost_cache_read === undefined || typeof entry.cost_cache_read === "number")
  );
}

function readScanCompletedCost(payload: unknown): ScanCompletedCost | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.cost_usd !== "number") return null;

  const cost: ScanCompletedCost = { cost_usd: p.cost_usd };
  if (Array.isArray(p.cost_breakdown)) {
    const breakdown = p.cost_breakdown.filter(isCostBreakdownEntry);
    if (breakdown.length > 0) cost.cost_breakdown = breakdown;
  }
  if (typeof p.cost_per_flag === "number") {
    cost.cost_per_flag = p.cost_per_flag;
  }
  return cost;
}

function printCostSummary(cost: ScanCompletedCost): void {
  let costIn = 0;
  let costOut = 0;
  let costCacheRead: number | undefined;
  if (cost.cost_breakdown) {
    for (const entry of cost.cost_breakdown) {
      costIn += entry.cost_in;
      costOut += entry.cost_out;
      if (entry.cost_cache_read !== undefined) {
        costCacheRead = (costCacheRead ?? 0) + entry.cost_cache_read;
      }
    }
  }
  const parts = cost.cost_breakdown
    ? [`in: $${costIn.toFixed(2)}`, `out: $${costOut.toFixed(2)}`]
    : [];
  if (costCacheRead !== undefined) {
    parts.push(`cache: $${costCacheRead.toFixed(2)}`);
  }
  let line = `cost: $${cost.cost_usd.toFixed(2)}`;
  if (parts.length > 0) {
    line += ` (${parts.join(", ")})`;
  }
  if (cost.cost_per_flag !== undefined) {
    line += ` — $${cost.cost_per_flag.toFixed(2)}/flag`;
  }
  console.log(chalk.gray(line));
}

/** Severity → chalk styler, matching the palette used elsewhere in the CLI. */
function crossValidatedSeverityColor(severity: string): (text: string) => string {
  switch (severity) {
    case "critical":
      return chalk.red.bold;
    case "high":
      return chalk.redBright;
    case "medium":
      return chalk.yellow;
    case "low":
      return chalk.blue;
    case "info":
      return chalk.gray;
    default:
      return chalk.white;
  }
}

/**
 * Print the cross-validated-leads highlight block (0sec FoxGuard Phase 4).
 * Purely additive end-of-scan output: a scan with no agreeing leads never
 * reaches here, and this never touches exit codes or the result line.
 */
function printCrossValidatedLeads(summary: CrossValidatedLeadsSummary): void {
  console.log("");
  console.log(chalk.cyan.bold(summary.header));
  for (const line of summary.lines) {
    console.log(`  ${crossValidatedSeverityColor(line.severity)(line.text)}`);
  }
  if (summary.moreCount > 0) {
    console.log(chalk.gray(`  +${summary.moreCount} more`));
  }
}

async function postFinalResultToCloud(report: unknown): Promise<void> {
  const config = getCloudFinalSinkConfig();
  if (!config) return;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-0sec-Scan-Id": config.scanId,
  };
  if (config.token) headers.Authorization = `Bearer ${config.token}`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ report, final: true }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      process.stderr.write(
        `[0sec cloud-sink] report POST ${url} returned ${res.status}: ${text.slice(0, 200)}\n`,
      );
    }

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[0sec cloud-sink] report POST ${url} failed: ${msg}\n`);
  }
}
/**
 * A skipped lens review still needs a canonical terminal record so the unified
 * session, formatter, and persistence paths do not fork around a missing
 * report. Its nonzero runner exit code remains authoritative.
 */
function skippedLensReviewReport(target: string, message: string): ScanReport {
  const now = new Date().toISOString();
  return {
    target,
    scanDepth: "deep",
    startedAt: now,
    completedAt: now,
    durationMs: 0,
    summary: {
      totalAttacks: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    findings: [],
    warnings: [{ stage: "attack", message }],
  };
}

export async function runUnified(opts: RunOptions): Promise<void> {
  const { target, depth, format, runtime, timeout } = opts;
  const core = await loadCoreModule();

  // ── Journal-based resume (0sec#374) ───────────────────────────────
  let effectiveResumeScanId = opts.resumeScanId;

  // ── Journal branching (0sec#250) ─────────────────────────────────
  if (opts.branchFromEntry !== undefined) {
    if (!effectiveResumeScanId) {
      console.error(chalk.red("--branch-from requires --resume <run-id>"));
      process.exit(2);
    }
    const { branchJournal } = await import("@0sec/core");
    const result = branchJournal({
      runId: effectiveResumeScanId,
      fromEntry: opts.branchFromEntry,
    });
    console.error(
      chalk.cyan(
        `[branch] Created branch run ${result.newRunId} with ${result.entriesCopied} entries ` +
          `and ${result.artifactsCopied} sidecar artifacts from ${effectiveResumeScanId}`,
      ),
    );
    effectiveResumeScanId = result.newRunId;
  }

  // Replace the original resumeScanId with the (possibly branched) one
  // so the rest of the function threads the correct value.
  opts = { ...opts, resumeScanId: effectiveResumeScanId };

  // Capture the scanner's canonical scan_completed cost payload. Reports
  // do not carry the per-model in/out/cache split.
  let scanCompletedCost: ScanCompletedCost | null = null;
  // FoxGuard cross-validation (Phase 4): captured off the same subscription so
  // it's printed after the report / TUI exits, alongside the cost summary.
  // Parsing is fail-soft (formatCrossValidatedLeads never throws), and the
  // extra guard here keeps a malformed payload from ever aborting the scan.
  let crossValidatedLeads: CrossValidatedLeadsSummary | null = null;
  const unsubscribeCost = core.eventBus.subscribe({
    emit(type, payload) {
      if (type === "scan_completed") {
        scanCompletedCost = readScanCompletedCost(payload);
        return;
      }
      if (type === "cross_validated_leads") {
        try {
          crossValidatedLeads = formatCrossValidatedLeads(payload);
        } catch {
          crossValidatedLeads = null;
        }
        return;
      }
    },
  });

  const validRuntimes = ["api", "claude", "codex", "gemini", "ollama", "auto"];
  if (!validRuntimes.includes(runtime)) {
    console.error(chalk.red(`Unknown runtime '${runtime}'. Valid: ${validRuntimes.join(", ")}`));
    process.exit(2);
  }

  // Check non-auto runtime availability. Live `--runtime codex` uses the
  // direct ChatGPT Codex provider when subscription auth is configured, so it
  // must not require the Codex CLI binary. Both env vars are valid
  // activations — refresh token is the long-lived OAuth credential the
  // local CLI uses, while access token is what the cloud worker forwards
  // to sandboxes (see 0sec-cloud PR #324). detectProvider in
  // packages/core/src/runtime/llm-api.ts accepts either pair, so the
  // preflight gate must accept either pair too.
  const directCodexProviderConfigured =
    runtime === "codex" &&
    (!!process.env["0SEC_CHATGPT_ACCESS_TOKEN"]?.trim() ||
      !!process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]?.trim());
  if (runtime !== "api" && runtime !== "auto" && !directCodexProviderConfigured) {
    const rt = core.createRuntime({ type: runtime, timeout });
    const available = await rt.isAvailable();
    if (!available) {
      console.error(chalk.red(`Runtime '${runtime}' not available. Is ${runtime} installed?`));
      process.exit(2);
    }
  }

  if (format === "terminal") await checkRuntimeAvailability(runtime);

  // Ink TUI for terminal, silent for json/md
  let inkUI: { onEvent: (event: any) => void; setReport: (report: any) => void; waitForExit: () => Promise<void>; getPendingUserMessages?: () => string[] } | null = null;
  let eventHandler: (event: any) => void = () => {};
  let getPendingUserMessages: (() => string[]) | undefined;

  if (format === "terminal" && process.stdout.isTTY && process.stdin.isTTY) {
    const mode = opts.targetType === "npm-package" || opts.targetType === "pypi-package" || opts.targetType === "cargo-package" || opts.targetType === "oci-image" ? "audit"
      : opts.targetType === "source-code" ? "review"
      : "scan";
    if (opts.sessionUiFactory) {
      inkUI = await opts.sessionUiFactory({ target, depth, mode });
    } else {
      const { isBunRuntime } = await import("../tui/runtime.js");
      if (isBunRuntime()) {
        const { createOpenTuiSession } = await import("../tui/run.js");
        const availability = await getRuntimeAvailability();
        inkUI = await createOpenTuiSession({
          target,
          depth,
          mode,
          runtime,
          apiProviderLabel: availability.apiRuntime.providerLabel,
          apiConfigured: availability.apiRuntime.configured,
          apiConnected: availability.hasApiKey && availability.apiRuntime.valid,
          localRuntimes: availability.availableRuntimes,
          model: opts.model,
        });
      } else {
        // Node fallback: plain stdout streaming (one tagged line per scan
        // event). The full TUI is OpenTUI under the standalone binary, installed
        // with `curl -fsSL .../install.sh | bash`.
        const { renderScanStream } = await import("../ui/scan-stream.js");
        inkUI = renderScanStream({ version: VERSION, target, depth, mode });
      }
    }
    eventHandler = inkUI.onEvent;
    getPendingUserMessages = inkUI.getPendingUserMessages;
  }

  try {
    let runnerExitCode = 0;
    let report: unknown;

    if (opts.targetType === "source-code" && opts.reviewStrategy === "lenses") {
      eventHandler({
        type: "stage:start",
        stage: "source-analysis",
        message: "capturing the validated finder-lens snapshot",
      });
      const outcome = await runDeepReview({
        target,
        profile: opts.reviewProfile,
        subsystem: opts.subsystem,
        models: opts.model ? [opts.model] : undefined,
        runtime,
        timeoutMs: timeout,
        costCeilingUsd: opts.costCeilingUsd,
        log: (message) => eventHandler({
          type: "stage:start",
          stage: "attack",
          message,
        }),
      });
      runnerExitCode = outcome.exitCode;
      const lensReport = outcome.report ?? skippedLensReviewReport(
        target,
        typeof outcome.result === "object" && outcome.result !== null && "note" in outcome.result
          ? String(outcome.result.note)
          : `lens review ended with exit code ${outcome.exitCode}`,
      );
      report = lensReport;
      writeOsecRunReport(
        resolveOsecRunStorage({ ...(opts.dbPath ? { dbPath: opts.dbPath } : {}) }),
        lensReport,
      );
      eventHandler({
        type: "stage:end",
        stage: "attack",
        message: outcome.exitCode === 0
          ? "validated finder-lens review completed"
          : `validated finder-lens review ended with exit code ${outcome.exitCode}`,
      });
    } else if (opts.targetType === "url" || opts.targetType === "web-app") {
      report = await core.agenticScan({
        config: {
          target,
          depth,
          format,
          runtime,
          mode: opts.mode ?? "deep",
          timeout,
          verbose: opts.verbose,
          apiKey: opts.apiKey,
          model: opts.model,
          repoPath: opts.repoPath,
          auth: opts.auth,
          apiSpecPath: opts.apiSpecPath,
          race: opts.race,
          egats: opts.egats,
          costCeilingUsd: opts.costCeilingUsd,
          scopeFile: opts.scopeFile,
          rateLimit: opts.rateLimit,
          allowScanners: opts.allowScanners,
          attributionHeaders: opts.attributionHeaders,
          attributionUaToken: opts.attributionUaToken,
          engagementProfile: opts.engagementProfile,
          wafEvasion: opts.wafEvasion,
          dispatchMode: opts.dispatchMode,
          httpAuditAllowedHosts: opts.httpAuditAllowedHosts,
          httpAuditAllowedPaths: opts.httpAuditAllowedPaths,
          httpAuditRateLimitRps: opts.httpAuditRateLimitRps,
          httpAuditKillAfterSec: opts.httpAuditKillAfterSec,
        },
        dbPath: opts.dbPath,
        onEvent: eventHandler,
        getPendingUserMessages,
        resumeScanId: opts.resumeScanId,
      });
    } else {
      report = await core.runPipeline({
        target,
        targetType: opts.targetType,
        resumeScanId: opts.resumeScanId,
        diffBase: opts.diffBase,
        changedOnly: opts.changedOnly,
        priorFindings: opts.priorFindings,
        depth,
        format,
        runtime,
        onEvent: eventHandler,
        dbPath: opts.dbPath,
        apiKey: opts.apiKey,
        model: opts.model,
        timeout,
        packageVersion: opts.packageVersion,
        costCeilingUsd: opts.costCeilingUsd,
        reviewProfile: opts.reviewProfile,
        reviewPackageEcosystem: opts.reviewPackageEcosystem,
        subsystem: opts.subsystem,
        hypothesis: opts.hypothesis,
        conversation: opts.conversation,
        seedFindings: opts.seedFindings,
        seedOnly: opts.seedOnly,
        npmDynamicDiscovery: opts.npmDynamicDiscovery,
      });
    }

    const reportAny = report as any;
    const canonicalReport = toScanReport(report);

    if (opts.targetType !== "url" && opts.targetType !== "web-app") {
      await postFinalResultToCloud(reportAny);
    }

    if (inkUI) {
      inkUI.setReport(report as any);
      await inkUI.waitForExit();
    } else {
      if (format === "html" || format === "pdf") {
        const extension = format === "pdf" ? "pdf" : "html";
        const filePath = opts.reportPath
          ? resolve(opts.reportPath)
          : join(tmpdir(), `0sec-report-${Date.now()}.${extension}`);
        if (format === "pdf") {
          await generatePdfReport(toScanReport(reportAny), filePath);
        } else {
          const output = reportAny.targetType === "npm-package" || reportAny.targetType === "pypi-package" || reportAny.targetType === "cargo-package" || reportAny.targetType === "oci-image"
            ? formatAuditReport(reportAny, format)
            : reportAny.targetType === "source-code"
              ? formatReviewReport(reportAny, format)
              : formatReport(reportAny, format);
          await writeFile(filePath, output, "utf-8");
        }
        console.log(chalk.green(`Report saved to: ${filePath}`));
        const openCmd = process.platform === "darwin" ? "open" : "xdg-open";
        execFile(openCmd, [filePath], () => {});
      } else {
        const output = reportAny.targetType === "npm-package" || reportAny.targetType === "pypi-package" || reportAny.targetType === "cargo-package" || reportAny.targetType === "oci-image"
          ? formatAuditReport(reportAny, format)
          : reportAny.targetType === "source-code"
            ? formatReviewReport(reportAny, format)
            : formatReport(reportAny, format);
        console.log(output);
      }
    }

    if (opts.tui && process.stdout.isTTY && process.stdin.isTTY && !(globalThis as { Bun?: unknown }).Bun) {
      // The post-scan operator TUI was Ink-based; in v0.9.0 we shipped
      // binary-only and dropped Ink. Tell the user where to find the
      // OpenTUI replacement and continue (don't fail the scan).
      // Gated on `!Bun` because under Bun the OpenTUI replacement is
      // already available — printing this message there would be wrong.
      console.log("");
      console.log(chalk.gray("  --tui post-scan view is no longer bundled in the npm package."));
      console.log(chalk.gray("  Install the standalone binary for the full OpenTUI experience:"));
      console.log(chalk.gray("    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash"));
      console.log("");
    }

    if (crossValidatedLeads) {
      printCrossValidatedLeads(crossValidatedLeads);
    }
    if (scanCompletedCost) {
      printCostSummary(scanCompletedCost);
    }
    unsubscribeCost();

    let exitCode = runnerExitCode;
    const estimatedCostUsd = getEstimatedCost(reportAny);
    const usage = getUsage(reportAny);

    // ── Emit findings as PRs (0sec#377) ──
    if (opts.emit === "pr") {
      const findings = (report as any).findings ?? [];
      const core = await loadCoreModule();
      // PRs are opened against the repo we just reviewed when the target is
      // a local source path; for URL scans we fall back to cwd and let the
      // operator notice that the resulting branches need to be pushed
      // elsewhere. We can do better here once #377 ships and we learn the
      // first real usage shape.
      const repoRoot = opts.targetType === "source-code" && existsSync(target)
        ? resolve(target)
        : process.cwd();
      const outDir = opts.emitOutDir ?? join(tmpdir(), `0sec-emit-${Date.now()}`);
      console.log(chalk.blue(`[emit pr] ${findings.length} finding(s); repo=${repoRoot} base=${opts.emitPrBase ?? "main"}${opts.emitPrDryRun ? " (dry-run)" : ""}`));
      const emitReport = await core.emitFindingsAsPRs(findings, {
        repoRoot,
        baseBranch: opts.emitPrBase,
        dryRun: opts.emitPrDryRun,
        outDir,
      });
      const created = emitReport.results.filter((r) => r.outcome === "pr_created").length;
      const dry = emitReport.results.filter((r) => r.outcome === "pr_dry_run").length;
      const skipped = emitReport.results.filter((r) => r.outcome.startsWith("skipped")).length;
      console.log(
        chalk.green(
          `[emit pr] ${created} PR(s) created${dry ? `, ${dry} dry-run` : ""}${skipped ? `, ${skipped} skipped` : ""}${emitReport.hypothesesMdPath ? `; hypotheses → ${emitReport.hypothesesMdPath}` : ""}`,
        ),
      );
    }

    // ── Export findings to issue tracker if requested ──
    if (opts.exportTarget) {
      const match = opts.exportTarget.match(/^github:(.+\/.+)$/);
      if (!match) {
        console.error(
          chalk.red(`Invalid --export format: '${opts.exportTarget}'. Expected: github:owner/repo`),
        );
        process.exit(2);
      }
      const repo = match[1];
      const reportAny = report as any;
      const findings = reportAny.findings ?? [];
      if (findings.length === 0) {
        console.log(chalk.yellow("No findings to export."));
      } else {
        const { exportToGitHubIssues } = await import("../exporters/github-issues.js");
        console.log(chalk.blue(`Exporting ${findings.length} finding(s) to GitHub Issues on ${repo}...`));
        const result = await exportToGitHubIssues(findings, repo);
        console.log(
          chalk.green(`Export complete: ${result.created} created, ${result.skipped} skipped (duplicates).`),
        );
      }
    }

    const ceilingRaw = process.env["0SEC_COST_CEILING_USD"]?.trim();
    if (ceilingRaw) {
      const ceiling = Number(ceilingRaw);
      if (Number.isFinite(ceiling) && estimatedCostUsd !== undefined && estimatedCostUsd > ceiling) {
        console.error(chalk.red(`Cost ceiling exceeded: $${estimatedCostUsd.toFixed(4)} > $${ceiling.toFixed(4)}`));
        exitCode = 4;
      }
    }

    // Cost ceiling abort from the live scan path: exit code 4 so operators
    // (CI, schedulers, cloud watchers) can distinguish a clean budget abort
    // from a normal completion or failure.
    if (canonicalReport.costCeilingExceeded && exitCode === 0) {
      console.error(
        chalk.yellow(
          `Scan aborted: cost ceiling exceeded. ${canonicalReport.summary.totalFindings} partial finding(s) preserved.`,
        ),
      );
      exitCode = 4;
    }

    if (reportAny.researchFailed && exitCode === 0) {
      console.error(chalk.red("Review completed with partial static results because AI analysis failed."));
      exitCode = 2;
    }

    if (exitCode === 0 && (canonicalReport.summary.critical > 0 || canonicalReport.summary.high > 0)) {
      exitCode = 1;
    }

    emitResultLine({
      ok: exitCode === 0,
      exitCode,
      exit_reason:
        exitCode === 4
          ? "cost_ceiling_exceeded"
          : exitCode === 2
            ? "error"
            : exitCode === 1
              ? "findings"
              : "completed",
      target,
      targetType: getTargetType(reportAny, opts),
      runtime,
      format,
      cost_usd: estimatedCostUsd,
      token_input: usage?.inputTokens,
      token_output: usage?.outputTokens,
      finding_count: canonicalReport.summary.totalFindings,
      estimatedCostUsd,
      usage,
      summary: canonicalReport.summary,
    });

    if (exitCode !== 0 && !inkUI) process.exit(exitCode);
  } catch (err) {
    // Always release the cost-bus subscription so a long-lived
    // process (test runner, future REPL) doesn't leak sinks across
    // scans.
    unsubscribeCost();
    const message = err instanceof Error ? err.message : String(err);
    if (inkUI) {
      eventHandler({
        type: "error",
        stage: "report",
        message,
      });
      await inkUI.waitForExit();
      return;
    }
    console.error(chalk.red(message));
    emitResultLine({
      ok: false,
      exitCode: 2,
      exit_reason: "error",
      target,
      targetType: opts.targetType,
      runtime,
      format,
      error: message,
    });
    process.exit(2);
  }
}
