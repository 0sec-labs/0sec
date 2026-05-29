import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import chalk from "chalk";
import { VERSION } from "@pwnkit/shared";
import type { ScanDepth, OutputFormat, RuntimeMode, ScanMode, AuthConfig, ScanReport, SeedFinding } from "@pwnkit/shared";
import type { CostBreakdownEntry } from "@pwnkit/core";
import { formatAuditReport, formatReviewReport, formatReport, generatePdfReport } from "../formatters/index.js";
import { buildShareUrl, checkRuntimeAvailability, getRuntimeAvailability } from "../utils.js";

interface ScanCompletedCost {
  cost_usd: number;
  cost_breakdown?: CostBreakdownEntry[];
  cost_per_flag?: number;
}

type CoreModule = typeof import("@pwnkit/core");

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
      : import("@pwnkit/core");
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
  depth: ScanDepth;
  format: OutputFormat;
  runtime: RuntimeMode;
  mode?: ScanMode;
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
  /** Path to a JSON scope file (pwnkit#215). Threaded into ScanConfig.scopeFile. */
  scopeFile?: string;
  /** Opt-out for the scanner-binary suppression gate (pwnkit#217). Threaded into ScanConfig.allowScanners. */
  allowScanners?: boolean;
  /** Repeatable `--attribution-header NAME=VALUE` (pwnkit#216). */
  attributionHeaders?: string[];
  /** `--attribution-ua <token>` (pwnkit#216). */
  attributionUaToken?: string;
  /**
   * http_audit env-bridge config (FROZEN CONTRACT). Populated by the scan
   * command from PWNKIT_TARGET_* env vars only when `mode === "http_audit"`;
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
   * Tool-call dispatch protocol (pwnkit#232) — `json`, `xml`, or `auto`.
   * Threaded into ScanConfig.dispatchMode and consulted only by the
   * legacy text-based agent loop.
   */
  dispatchMode?: "json" | "xml" | "auto";
  /**
   * Review profile (only applied when targetType === "source-code").
   * "c-library" tunes the prompt for C/C++ memory-safety + tier-1/2/3
   * harness construction. "linux-kernel" tunes for kernel-aware static
   * review (syscall/ioctl surface, copy_from_user, refcount races,
   * Dirty Frag class). Default: "default".
   */
  reviewProfile?: "default" | "c-library" | "linux-kernel";
  /**
   * Restrict analysis to files under this subdirectory. Only meaningful when
   * `reviewProfile === "linux-kernel"`. The value is injected into the agent
   * prompt as a scope restriction (e.g. `crypto/`, `net/tcp/`).
   */
  subsystem?: string;
  /** Operator hypothesis for directed research. */
  hypothesis?: string;
  /**
   * Pre-computed candidate vulnerable spans, parsed from an external producer
   * (today: GemmaForge, schema `gemmaforge.leads/v1`). Only consumed when
   * `targetType === "source-code"`. See `pwnkit#368` for the broader plan to
   * inject these into the agent's worklist before static scanner prioritisation runs.
   */
  seedFindings?: SeedFinding[];
  /** Skip semgrep entirely and rely solely on `seedFindings`. */
  seedOnly?: boolean;
  /**
   * Emit target (pwnkit#377). Default unset → existing terminal/json/etc.
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
      warnings: [],
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

function emitResultLine(payload: ResultLinePayload): void {
  if (process.env.PWNKIT_EMIT_RESULT_LINE !== "1" && !process.env.PWNKIT_CLOUD_SINK) return;
  console.log(`PWNKIT_RESULT=${JSON.stringify(payload)}`);
}

function getCloudFinalSinkConfig(): { sinkUrl: string; scanId: string; token?: string } | null {
  if (process.env.PWNKIT_FEATURE_CLOUD_SINK === "0") return null;
  const sinkUrl = process.env.PWNKIT_CLOUD_SINK?.trim();
  const scanId = process.env.PWNKIT_CLOUD_SCAN_ID?.trim();
  if (!sinkUrl || !scanId) return null;
  const token = process.env.PWNKIT_CLOUD_TOKEN?.trim() || undefined;
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

async function postFinalResultToCloud(report: unknown): Promise<void> {
  const config = getCloudFinalSinkConfig();
  if (!config) return;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Pwnkit-Scan-Id": config.scanId,
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
        `[pwnkit cloud-sink] report POST ${url} returned ${res.status}: ${text.slice(0, 200)}\n`,
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[pwnkit cloud-sink] report POST ${url} failed: ${msg}\n`);
  }
}

export async function runUnified(opts: RunOptions): Promise<void> {
  const { target, depth, format, runtime, timeout } = opts;
  const core = await loadCoreModule();

  // ── Journal-based resume (pwnkit#374) ───────────────────────────────
  let effectiveResumeScanId = opts.resumeScanId;

  // ── Journal branching (pwnkit#250) ─────────────────────────────────
  if (opts.branchFromEntry !== undefined) {
    if (!effectiveResumeScanId) {
      console.error(chalk.red("--branch-from requires --resume <run-id>"));
      process.exit(2);
    }
    const { branchJournal } = await import("@pwnkit/core");
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
  const unsubscribeCost = core.eventBus.subscribe({
    emit(type, payload) {
      if (type !== "scan_completed") return;
      scanCompletedCost = readScanCompletedCost(payload);
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
  // to sandboxes (see pwnkit-cloud PR #324). detectProvider in
  // packages/core/src/runtime/llm-api.ts accepts either pair, so the
  // preflight gate must accept either pair too.
  const directCodexProviderConfigured =
    runtime === "codex" &&
    (!!process.env.PWNKIT_CHATGPT_ACCESS_TOKEN?.trim() ||
      !!process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN?.trim());
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
        // event). The full TUI is OpenTUI under Bun — install via
        // `curl -fsSL .../install.sh | bash` (standalone binary) or
        // `bun add -g pwnkit-cli` to get it.
        const { renderScanStream } = await import("../ui/scan-stream.js");
        inkUI = renderScanStream({ version: VERSION, target, depth, mode });
      }
    }
    eventHandler = inkUI.onEvent;
    getPendingUserMessages = inkUI.getPendingUserMessages;
  }

  try {
    const report = opts.targetType === "url" || opts.targetType === "web-app"
      ? await core.agenticScan({
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
        })
      : await core.runPipeline({
          target,
          targetType: opts.targetType,
          resumeScanId: opts.resumeScanId,
          diffBase: opts.diffBase,
          changedOnly: opts.changedOnly,
          depth,
          format,
          runtime,
          onEvent: eventHandler,
          dbPath: opts.dbPath,
          apiKey: opts.apiKey,
          model: opts.model,
          timeout,
          packageVersion: opts.packageVersion,
          reviewProfile: opts.reviewProfile,
          subsystem: opts.subsystem,
          hypothesis: opts.hypothesis,
          // External seeds (e.g. `gemmaforge scan` leads) — the pipeline
          // prepends them to the agent's worklist so they are surfaced
          // first in the prompt. `seedOnly` skips semgrep entirely when
          // the operator trusts the external producer enough to rely on
          // it alone. Companion producer: peaktwilight/gemmaforge#23.
          seedFindings: opts.seedFindings,
          seedOnly: opts.seedOnly,
        } as any);

    const reportAny = report as any;

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
          : join(tmpdir(), `pwnkit-report-${Date.now()}.${extension}`);
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
      console.log(chalk.gray("    curl -fsSL https://raw.githubusercontent.com/0sec-labs/pwnkit/main/install.sh | bash"));
      console.log("");
    }

    if (scanCompletedCost) {
      printCostSummary(scanCompletedCost);
    }
    unsubscribeCost();

    let exitCode = 0;
    const estimatedCostUsd = getEstimatedCost(reportAny);
    const usage = getUsage(reportAny);

    // ── Emit findings as PRs (pwnkit#377) ──
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
      const outDir = opts.emitOutDir ?? join(tmpdir(), `pwnkit-emit-${Date.now()}`);
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

    const ceilingRaw = process.env.PWNKIT_COST_CEILING_USD?.trim();
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
    if ((report as ScanReport).costCeilingExceeded && exitCode === 0) {
      console.error(
        chalk.yellow(
          `Scan aborted: cost ceiling exceeded. ${report.summary.totalFindings} partial finding(s) preserved.`,
        ),
      );
      exitCode = 4;
    }

    if (exitCode === 0 && (report.summary.critical > 0 || report.summary.high > 0)) {
      exitCode = 1;
    }

    emitResultLine({
      ok: exitCode === 0,
      exitCode,
      exit_reason:
        exitCode === 4
          ? "cost_ceiling_exceeded"
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
      finding_count: report.summary.totalFindings,
      estimatedCostUsd,
      usage,
      summary: report.summary,
    });

    if (exitCode !== 0) process.exit(exitCode);
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
