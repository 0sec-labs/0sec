import type {
  ScanConfig,
  ScanReport,
  Finding,
  LayerVerdict,
  LayerVerdictKind,
  PocStep,
  Severity,
  TriageLayerName,
} from "@pwnkit/shared";
import { loadTemplates } from "@pwnkit/templates";
import { createRuntime } from "./runtime/index.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import type { ApiRuntimeDiagnostics } from "./runtime/llm-api.js";
import { CliNativeRuntime } from "./runtime/cli-native.js";
import { detectAvailableRuntimes } from "./runtime/registry.js";
// DB lazy-loaded to avoid native module issues
import { runAgentLoop } from "./agent/loop.js";
import { runNativeAgentLoop } from "./agent/native-loop.js";
import { maybeStartCloudInboxPoller } from "./agent/cloud-inbox.js";
import { toolCallPreview } from "./agent/tool-preview.js";
import { getToolsForRole, TOOL_DEFINITIONS, parsePocStepsArg } from "./agent/tools.js";
import {
  discoveryPrompt,
  attackPrompt,
  verifyPrompt,
  verifyPromptSingleFinding,
  reportPrompt,
  webPentestDiscoveryPrompt,
  webPentestAttackPrompt,
  shellPentestPrompt,
  buildAccessControlPromptBlock,
} from "./agent/prompts.js";
import { resolveIdentities } from "@pwnkit/shared";
import type { RuntimeMode } from "@pwnkit/shared";
import { features } from "./agent/features.js";
import type { ScanEvent, ScanListener } from "./scanner.js";
import type { NativeRuntime, NativeMessage, NativeContentBlock } from "./runtime/types.js";
import { isMcpTarget } from "./http.js";
import { discoverMcpTarget, runMcpSecurityChecks } from "./mcp.js";
import { runLlmIpiAudit } from "./llm-ipi-audit.js";
import { z } from "zod";
import { layerVerdictArraySchema, formatZodError } from "./schemas.js";
import { createScanContext, finalize } from "./context.js";
import { generateRemediation } from "./remediation.js";
import { parseApiSpec } from "./api-spec.js";
import { raceWithDefaults } from "./racing.js";
import type { RaceResult } from "./racing.js";
import { runEGATSWithDefaults } from "./agent/egats.js";
import {
  isHoldingItWrong,
  extractFeatures,
  FEATURE_NAMES,
  verifyOracleByCategory,
  type OracleResult,
  checkMultiModalAgreement,
  fuseTriageSignals,
  checkReachability,
  analyzeInputControllability,
  controllabilityDowngradeTarget,
  canAutoSuppressDetailed,
  routeFinding,
  decideLayers,
  isDisclosureWorthy,
  evidenceKindForFinding,
  checkPublishability,
  buildPublishabilityInputs,
  resolveNovelty,
  resolveRepository,
  inferPackage,
  type LayerId,
  type RoutingDecision,
  type DedupEcosystem,
  type PublishabilityInputs,
} from "./triage/index.js";
import { verify, toVerifyVerdict } from "./triage/structured-verify.js";
import { generatePov, oracleForCategory, oastConfirmedPayload } from "./triage/pov-gate.js";
import {
  generateStaticPoc,
  applyStaticPocResult,
} from "./agent/static-poc-gen.js";
import { getCloudSinkConfig, postFinding, postFinalReport } from "./cloud-sink.js";
import { eventBus } from "./events/bus.js";
import type { CostBreakdownEntry } from "./events/bus.js";
import { modelProvider, splitCost } from "./agent/cost.js";
import { loadScope, ScopePolicy } from "./scope/scope.js";
import { RateLimiter, parseRateLimitFlag } from "./scope/rate-limit.js";
import { EnforcementTracker, PathPolicy } from "./scope/enforcement.js";
import {
  resolveAttribution,
  extractAttributionFromScopeJson,
} from "./scope/attribution.js";
import type { AttributionConfig } from "./scope/attribution.js";
import {
  resolveEngagementProfile,
  extractEngagementFromScopeJson,
  describeEngagementPosture,
  effectiveFallbackRps,
} from "./scope/engagement-profile.js";
import type { EngagementPosture } from "./scope/engagement-profile.js";
import {
  describeScopeGuards,
  scopeRequiredRefusal,
  SCOPE_GUARDS_INERT_EVENT,
} from "./scope/scope-guard.js";
import { resolveLocalTargetPath } from "./path-resolution.js";
import { runMemSafetyScan } from "./stages/memsafety-scan.js";
import type { MemSafetyScanOptions } from "./stages/memsafety-scan.js";
import type { MemSafetyTarget } from "./triage/memsafety-types.js";
import { runCraftScan } from "./stages/craft-scan.js";
import type { CraftTarget, CraftScanOptions } from "./stages/craft-scan.js";
import { runEnsembleCraft, resolveEnsembleModels } from "./stages/ensemble-craft.js";
import { runReportStage } from "./agentic/stages/report.js";
import { applyFindingPostProcess, loadPriorScanAnchors, type DedupeItem } from "./agentic/finding-postprocess.js";

/**
 * Per-scan rate-limiter cache (#214). The limiter is stateful — buckets
 * track per-host token availability and 429 cool-offs across the entire
 * scan — so we build one instance keyed on the ScanConfig object and
 * thread it into every agent loop and every stage that fetches.
 *
 * Default 5 rps when the operator did not pass `--rate-limit`. The
 * issue body is explicit on this: the primitive should default
 * conservative even without an explicit operator flag, so an
 * unconfigured `pwnkit scan` can't accidentally hammer a target.
 */
const RATE_LIMITER_CACHE = new WeakMap<ScanConfig, RateLimiter>();
function getOrCreateRateLimiter(config: ScanConfig): RateLimiter {
  let rl = RATE_LIMITER_CACHE.get(config);
  if (!rl) {
    // In http_audit mode the per-host rps comes from the env-bridge
    // (PWNKIT_TARGET_RATE_LIMIT_RPS, default 5) rather than the --rate-limit
    // flag; the flag form isn't part of the worker contract. Otherwise we
    // honour the parsed --rate-limit spec with the usual 5 rps default.
    const modeFallbackRps = config.mode === "http_audit"
      ? (config.httpAuditRateLimitRps ?? 5)
      : 5;
    // Engagement hardening: an active profile lowers the default rps and adds
    // full jitter so the request train stops being periodic. It can only ever
    // make the scan QUIETER — we take the min, never the profile's number when
    // the operator already configured something slower. An explicit
    // `--rate-limit` default still wins (parseRateLimitFlag only consumes the
    // fallback when the spec carries no default).
    const posture = resolveEngagementForConfig(config);
    const cfg = parseRateLimitFlag(
      config.rateLimit ?? "",
      effectiveFallbackRps(posture, modeFallbackRps),
    );
    if (posture.jitter) cfg.jitter = { baseMs: posture.jitter.baseMs };
    // Wire the throttle observer into the http_audit enforcement tracker so
    // every blocked acquire / 429 park bumps `rate_limited_count`. No-op for
    // every other mode (tracker is undefined).
    const enforcement = resolveEnforcementForConfig(config);
    rl = new RateLimiter(cfg, {
      onThrottle: enforcement ? () => enforcement.noteRateLimited() : undefined,
    });
    RATE_LIMITER_CACHE.set(config, rl);
  }
  return rl;
}

/**
 * Per-scan engagement-posture cache. The posture is pure config (no I/O beyond
 * the already-cached scope file) but it is read at several call sites — the
 * rate limiter, the web-recon pre-pass, every agent config, and the report —
 * so resolve it once per ScanConfig and hand the same object around.
 *
 * Returns the `standard` posture (unchanged engine behaviour) when nothing is
 * configured, so this is safe to call unconditionally.
 */
const ENGAGEMENT_CACHE = new WeakMap<ScanConfig, EngagementPosture>();
function resolveEngagementForConfig(config: ScanConfig): EngagementPosture {
  const cached = ENGAGEMENT_CACHE.get(config);
  if (cached) return cached;
  const scope = resolveScopeForConfig(config);
  const posture = resolveEngagementProfile({
    scopeFileBlock: scope ? extractEngagementFromScopeJson(scope.raw) : undefined,
    env: process.env,
    cliProfile: config.engagementProfile,
    cliWafEvasion: config.wafEvasion,
  });
  ENGAGEMENT_CACHE.set(config, posture);
  return posture;
}

/**
 * Attach the engagement-posture audit record to a report. Only present when a
 * hardening profile was actually applied, so default scans emit byte-for-byte
 * identical reports. Mutates `report` in place; called on every report return
 * path so the evidence is always there when it applies.
 */
function attachEngagementPosture(report: ScanReport, config: ScanConfig): void {
  const posture = resolveEngagementForConfig(config);
  if (!posture.active) return;
  report.engagementPosture = describeEngagementPosture(posture);
}

/**
 * Per-scan enforcement-tracker cache (http_audit only). Created lazily the
 * first time any helper needs it and reused for the whole scan so the
 * scope/rate counters and the kill-switch clock aggregate across discovery +
 * attack + verify stages. Returns undefined for every non-http_audit scan,
 * leaving the legacy behaviour untouched.
 *
 * The tracker owns the path-prefix allowlist (PathPolicy) and the auth mode;
 * the host allowlist is enforced separately via the ScopePolicy built in
 * `resolveScopeForConfig`.
 */
const ENFORCEMENT_CACHE = new WeakMap<ScanConfig, EnforcementTracker>();
function resolveEnforcementForConfig(config: ScanConfig): EnforcementTracker | undefined {
  if (config.mode !== "http_audit") return undefined;
  const cached = ENFORCEMENT_CACHE.get(config);
  if (cached) return cached;
  const tracker = new EnforcementTracker({
    pathPolicy: new PathPolicy(config.httpAuditAllowedPaths ?? []),
    auth: config.auth,
    killAfterSec: config.httpAuditKillAfterSec ?? 1800,
  });
  ENFORCEMENT_CACHE.set(config, tracker);
  return tracker;
}

/**
 * Attach the frozen `enforcement_summary` block to a report when the scan ran
 * in http_audit mode. No-op for every other mode (tracker is undefined), so
 * non-http_audit reports are byte-for-byte unchanged. Mutates `report` in
 * place; called on every http_audit report return path (happy, kill-switch,
 * cost-ceiling) so the block is always present.
 */
function attachEnforcementSummary(report: ScanReport, config: ScanConfig): void {
  const enforcement = resolveEnforcementForConfig(config);
  if (!enforcement) return;
  report.enforcementSummary = enforcement.summarize();
}

/**
 * Count distinct `FLAG{...}` matches across a finding set. Used by
 * `emitScanCompleted` to derive `cost_per_flag` for the
 * `scan_completed` event (pwnkit#231).
 *
 * Mirrors the regex in `agent/flag-validator.ts` (`FLAG_WRAPPER_RE`)
 * so anything the validator would accept counts here. Walks
 * `title` / `description` / evidence fields — the agent normally
 * commits a flag into one of these when `save_finding` fires after a
 * successful exploit. Dedupes by inner content so retries that save the
 * same flag twice don't double-count.
 *
 * Note: this does NOT validate flag shape — a decoy `FLAG{Im_a_Script_Kiddie}`
 * would still increment the counter. The triage pipeline already
 * downgrades decoy flags to `false-positive` / `info`; the cost-per-flag
 * metric is honest about cost-per-claimed-flag, not cost-per-real-flag.
 * Cleaner separation than guessing which findings are "real" here.
 */
const FLAG_PATTERN = /FLAG\{([^}]+)\}/gi;
function countFlagsInFindings(findings: Finding[]): number {
  if (!Array.isArray(findings) || findings.length === 0) return 0;
  const seen = new Set<string>();
  for (const f of findings) {
    if (!f) continue;
    const haystack = [
      typeof f.title === "string" ? f.title : "",
      typeof f.description === "string" ? f.description : "",
      typeof f.evidence?.request === "string" ? f.evidence.request : "",
      typeof f.evidence?.response === "string" ? f.evidence.response : "",
      typeof f.evidence?.analysis === "string" ? f.evidence.analysis : "",
    ].join("\n");
    const matches = haystack.matchAll(FLAG_PATTERN);
    for (const m of matches) {
      // Normalize on inner content so `FLAG{abc}` and `flag{abc}` collapse.
      const inner = (m[1] ?? "").trim().toLowerCase();
      if (inner) seen.add(inner);
    }
  }
  return seen.size;
}

export interface AgenticScanOptions {
  config: ScanConfig;
  dbPath?: string;
  onEvent?: ScanListener;
  /** Poll for user-injected messages from the TUI at turn boundaries. */
  getPendingUserMessages?: () => string[];
  /** Optional hint/description for benchmark challenges */
  challengeHint?: string;
  /** Resume from a previous scan (uses persisted sessions) */
  resumeScanId?: string;
  /**
   * Suppress this invocation's scan_completed event when it is a child of a
   * higher-level fan-out. The parent owns one aggregated terminal event.
   */
  emitTerminalEvent?: boolean;
  /**
   * Userspace / Rust memory-safety scan role ("Monty-mode", pwnkit#700). When
   * set, the scan dispatches to the focused `runMemSafetyScan` stage
   * (audit-playbook → closed fuzz loop → crash triage) and returns early,
   * BEFORE any of the live-target / DB / runtime machinery below runs. The
   * existing web/API/audit flows are byte-for-byte unaffected when this is
   * undefined. Optional knobs for the fuzz loop ride along in `memSafety`.
   */
  memSafetyTarget?: MemSafetyTarget;
  /** Optional fuzz-loop / logging knobs forwarded to `runMemSafetyScan`. */
  memSafety?: Omit<MemSafetyScanOptions, "target">;
  /**
   * Craft scan role — the agentic sibling of the memory-safety fuzz path. When
   * set, the agent reads the pre-patch source with read-only tools and crafts a
   * PoC input, testing each candidate against the injected `craft.evaluatePoc`
   * oracle (CyberGym differential for benchmarks; a local sanitizer runner for
   * real targets). Dispatches to `runCraftScan` and returns early, like the
   * memSafety path. Unaffected web/API/audit flows when undefined.
   */
  craftTarget?: CraftTarget;
  /** The PoC oracle + agent-loop knobs forwarded to `runCraftScan` (required when craftTarget is set). */
  craft?: Omit<CraftScanOptions, "target" | "runtime">;
}

/**
 * Append a triage-layer verdict to a finding's `layerVerdicts` log. The
 * array is created lazily so existing call sites that don't construct
 * findings via the scanner (tests, importers) keep working.
 *
 * Each entry is the per-layer telemetry that #112 was designed to surface
 * and that the dynamic-routing model in #113 trains on. Append-only,
 * ordered by execution.
 */
function pushLayerVerdict(
  finding: Finding,
  entry: {
    layer: TriageLayerName;
    verdict: LayerVerdictKind;
    confidence?: number;
    reason: string;
    startedAt: number;
    costUsd?: number;
    changedSeverity?: { from: Severity; to: Severity };
  },
): void {
  if (!finding.layerVerdicts) finding.layerVerdicts = [];
  const verdict: LayerVerdict = {
    layer: entry.layer,
    verdict: entry.verdict,
    reason: entry.reason,
    durationMs: Date.now() - entry.startedAt,
    costUsd: entry.costUsd ?? 0,
  };
  if (entry.confidence !== undefined) verdict.confidence = entry.confidence;
  if (entry.changedSeverity) verdict.changedSeverity = entry.changedSeverity;
  finding.layerVerdicts.push(verdict);
}

function assertApiRuntimeSelection(
  requestedRuntime: ScanConfig["runtime"] | undefined,
  diagnostics: ApiRuntimeDiagnostics,
): void {
  if (requestedRuntime === "api" && !diagnostics.valid) {
    throw new Error(diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is not available.`);
  }

  if ((requestedRuntime === "auto" || requestedRuntime === undefined) && diagnostics.reason === "invalid_config") {
    throw new Error(diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is misconfigured.`);
  }
}

function hasDirectChatGptCodexProvider(
  diagnostics: ApiRuntimeDiagnostics,
): boolean {
  return diagnostics.valid && diagnostics.provider === "chatgpt-codex";
}

/**
 * Auto-detect whether an HTTP target is a web app vs an AI/API endpoint.
 * If the target serves HTML and the user requested "deep" mode,
 * automatically switch to "web" mode for better coverage.
 */
async function normalizeScanConfig(config: ScanConfig): Promise<ScanConfig> {
  if (config.repoPath) {
    config = { ...config, repoPath: resolveLocalTargetPath(config.repoPath) };
  }

  // Normalize target URL first — if the user gave a bare hostname like
  // `doruk.ch`, every URL-using tool downstream (`crawl`, `http_request`,
  // playwright `goto`) blows up with "Invalid URL" on `new URL(input,
  // ctx.target)` because the base must be absolute. Auto-prefix `https://`
  // when no scheme is present so the rest of the pipeline gets a
  // well-formed URL. Skips package targets (npm/pypi/cargo names like
  // "lodash") — those don't have `.` or `://` in a way that triggers
  // this branch, and audit-mode targets aren't URLs anyway.
  if (
    config.target &&
    /\./.test(config.target) &&
    !/^[a-z][a-z0-9+.-]*:\/\//i.test(config.target)
  ) {
    config = { ...config, target: `https://${config.target.trim()}` };
  }

  // Only auto-route for default/deep mode on HTTP targets
  const requestedMode = config.mode ?? "deep";
  if (requestedMode !== "deep") return config;
  if (!config.target.startsWith("http://") && !config.target.startsWith("https://")) return config;

  try {
    // #214: rate-limit even the one-shot mode-auto-detect probe. The
    // limiter is built (and cached on `config`) here so subsequent
    // stages share the same per-host bucket state — a target that 429s
    // on the first probe stays parked across the whole scan.
    const limiter = getOrCreateRateLimiter(config);
    await limiter.acquire(config.target);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(config.timeout ?? 30_000, 8_000));
    try {
      const response = await fetch(config.target, {
        method: "GET",
        headers: {
          Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        },
        signal: controller.signal,
      });
      limiter.noteResponse(config.target, response);
      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      const body = await response.text();

      // Check if response is HTML (web app)
      const looksHtml =
        contentType.includes("text/html")
        || /^\s*<!doctype html/i.test(body)
        || /<html[\s>]/i.test(body);

      if (looksHtml) {
        return { ...config, mode: "web" };
      }

      // Check if response looks like an AI/LLM API endpoint
      // Common patterns: /v1/chat/completions, /v1/messages, /completions, /generate
      const url = new URL(config.target);
      const aiPathPatterns = [
        /\/v\d+\/chat/,
        /\/v\d+\/messages/,
        /\/completions/,
        /\/generate/,
        /\/inference/,
      ];
      const looksLikeAiEndpoint = aiPathPatterns.some((p) => p.test(url.pathname));

      // If it's a JSON API that doesn't match AI patterns, still use deep mode
      // but if it returned 405 on GET, it's likely a POST-only API
      if (response.status === 405 && !looksLikeAiEndpoint) {
        // POST-only endpoint that's not an AI API — likely a web API, keep deep mode
        return config;
      }

      // If JSON response with common AI indicators, keep deep mode (AI scanning)
      if (contentType.includes("application/json")) {
        try {
          const json = JSON.parse(body);
          const hasAiIndicators =
            json.model || json.choices || json.content || json.completion
            || json.object === "chat.completion" || json.object === "message";
          if (hasAiIndicators) return config; // Confirmed AI endpoint
        } catch {
          // Not valid JSON, proceed with default
        }
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // Keep the requested mode if preflight fails
  }

  return config;
}

/**
 * Run a full agentic scan with multi-turn agents, tool use, and persistent state.
 *
 * Pipeline:
 * - Discovery Agent: probes target, maps endpoints, builds profile
 * - Attack Agent: runs attacks with adaptation and multi-turn escalation
 * - Verification Agent: replays and confirms findings
 * - Report Agent: generates summary
 *
 * When ANTHROPIC_API_KEY is set, uses the native Claude Messages API with
 * structured tool_use for reliable tool execution. Otherwise, falls back to
 * the legacy text-based agent loop via subprocess runtimes.
 *
 * All findings persist to SQLite between stages and across scans.
 * Sessions are saved so interrupted scans can be resumed.
 */
/**
 * Memory-safety scan dispatch ("Monty-mode", pwnkit#700). Adapts the focused
 * `runMemSafetyScan` stage result into the unified `ScanReport` the rest of the
 * product consumes. Lives here only as the thin bridge between the scan entry
 * point and the stage module; all real orchestration is in
 * `stages/memsafety-scan.ts`. Does no DB / runtime / live-target work — the
 * fuzz loop owns its own (artifact-dir-scoped) side effects and degrades
 * honestly when tooling is absent.
 */
async function runMemSafetyScanStage(
  config: ScanConfig,
  target: MemSafetyTarget,
  memSafety: Omit<MemSafetyScanOptions, "target"> | undefined,
  emit: ScanListener,
): Promise<ScanReport> {
  const startedAt = Date.now();
  emit({
    type: "stage:start",
    stage: "attack",
    message: `Memory-safety scan: ${target.language} target at ${target.sourceRoot}`,
  });

  const result = await runMemSafetyScan({ ...memSafety, target });

  for (const finding of result.findings) {
    emit({ type: "finding", message: finding.title, data: finding });
  }

  const completedAt = Date.now();
  const findings = result.findings;
  const summary = {
    totalAttacks: result.loop.iterations,
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  emit({
    type: "stage:end",
    stage: "attack",
    message:
      result.toolingMissing.length > 0
        ? `Memory-safety scan could not run (missing: ${result.toolingMissing.join(", ")})`
        : `Memory-safety scan complete: ${findings.length} finding(s)`,
  });

  return {
    target: config.target || target.sourceRoot,
    scanDepth: config.depth,
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date(completedAt).toISOString(),
    durationMs: completedAt - startedAt,
    summary,
    findings,
    warnings: result.warnings.map((message) => ({
      stage: "attack" as const,
      message,
    })),
  };
}

/**
 * Craft scan dispatch — adapts `runCraftScan` into the unified `ScanReport`,
 * mirroring `runMemSafetyScanStage`. The PoC oracle lives in `craft.evaluatePoc`
 * (injected by the caller); this bridge does no I/O of its own.
 */
async function runCraftScanStage(
  config: ScanConfig,
  target: CraftTarget,
  craft: Omit<CraftScanOptions, "target" | "runtime">,
  emit: ScanListener,
): Promise<ScanReport> {
  const startedAt = Date.now();
  emit({
    type: "stage:start",
    stage: "attack",
    message: `Craft scan: ${target.language ?? "c"} target at ${target.sourceRoot}`,
  });

  const runtime = ((config as { runtime?: RuntimeMode }).runtime ?? "auto") as RuntimeMode;
  const model = craft.model ?? (config as { model?: string }).model;
  const log = (message: string) => emit({ type: "thinking", message });

  // Ensemble craft opt-in (OFF by default): when PWNKIT_ENSEMBLE_MODELS lists
  // more than one model, run N parallel craft trajectories across those models
  // and LLM-judge them down to one PoC. Unset / single model → the single-model
  // craft path below, byte-for-byte unchanged. `runEnsembleCraft` returns a
  // normal CraftScanResult, so the adaptation below is identical either way.
  const ensembleModels = resolveEnsembleModels();
  const result =
    ensembleModels.length > 1
      ? await runEnsembleCraft({
          target,
          runtime,
          n: ensembleModels.length,
          models: ensembleModels,
          // `model` is per-trajectory in the ensemble; strip the single-model knob.
          craft: (({ model: _drop, ...rest }) => rest)(craft),
          ...(model ? { judgeModel: model } : {}),
          log,
        })
      : await runCraftScan({
          ...craft,
          ...(model ? { model } : {}),
          target,
          runtime,
          log,
        });

  for (const finding of result.findings) {
    emit({ type: "finding", message: finding.title, data: finding });
  }

  const completedAt = Date.now();
  const findings = result.findings;
  const summary = {
    totalAttacks: result.submits,
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  emit({
    type: "stage:end",
    stage: "attack",
    message: result.passed
      ? `Craft scan: confirmed PoC in ${result.submits} submit(s)`
      : `Craft scan: no confirmed PoC (${result.warnings[result.warnings.length - 1] ?? "no candidate"})`,
  });

  return {
    target: config.target || target.sourceRoot,
    scanDepth: config.depth,
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date(completedAt).toISOString(),
    durationMs: completedAt - startedAt,
    summary,
    findings,
    warnings: result.warnings.map((message) => ({ stage: "attack" as const, message })),
    trace: [
      { type: "craft_attempts", attempts: result.attempts },
      ...(result.evidence && result.evidence.length > 0
        ? [{ type: "craft_evidence", records: result.evidence }]
        : []),
    ],
    benchmarkMeta: {
      attackTurns: result.steps,
      model: result.model,
      craftSubmits: result.submits,
      craftPassed: result.passed,
      craftFirstSubmitPassed: result.firstSubmitPassed,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      estimatedCostUsd: result.estimatedCostUsd,
    },
  };
}

/**
 * Parse a resolved package target of the shape `eco:name@version` (e.g.
 * `npm:lodash@4.17.4`, `pypi:requests@2.31.0`) that the unified pipeline emits
 * as `resolvedTarget`. Returns the OSS ecosystem / package name / version for
 * the #851 novelty gate, or undefined when the target is not a package
 * (URLs, bare hostnames, repo paths). Pure and conservative — a target it
 * cannot confidently parse yields undefined, so the gate stays a safe no-op.
 */
function parsePackageTarget(
  target: string,
): { ecosystem: string; name: string; version?: string } | undefined {
  const m = /^(npm|pypi|cargo|go|maven):(.+)$/.exec(target.trim());
  if (!m) return undefined;
  const ecosystem = m[1];
  const rest = m[2];
  // Split name@version, honoring npm scoped names (@scope/pkg@version): the
  // version `@` is the LAST one, and only when it follows a non-`/` char.
  const at = rest.lastIndexOf("@");
  if (at > 0) {
    return { ecosystem, name: rest.slice(0, at), version: rest.slice(at + 1) || undefined };
  }
  return { ecosystem, name: rest };
}

export async function agenticScan(opts: AgenticScanOptions): Promise<ScanReport> {
  const {
    dbPath,
    onEvent,
    getPendingUserMessages: optsGetPendingUserMessages,
    resumeScanId,
  } = opts;
  const emit = onEvent ?? (() => {});

  // #978 (ADR-060) — cloud control channel. The agent loop injects "pending
  // user messages" each turn via getPendingUserMessages (originally the local
  // TUI interrupt hook). In cloud mode there is no TUI; operator steers arrive
  // in the scan inbox (the dashboard's "Steer this scan"). Default the source
  // to a background inbox poller so a steer flips pending → consumed and lands
  // in the agent's context mid-run. Callers that pass their own callback (TUI)
  // keep it. The poller is unref'd, so the sandbox process still exits cleanly.
  const cloudInbox = optsGetPendingUserMessages
    ? null
    : maybeStartCloudInboxPoller();
  const getPendingUserMessages =
    optsGetPendingUserMessages ?? cloudInbox?.drain;

  // Memory-safety scan role ("Monty-mode", pwnkit#700). This is the minimal
  // dispatch seam for the userspace/Rust pipeline: when a `memSafetyTarget` is
  // supplied we delegate to the focused `runMemSafetyScan` stage and return,
  // before the DB / runtime / live-target machinery below. Keeping the actual
  // orchestration in `stages/memsafety-scan.ts` (not another branch in this
  // 3800-line module) is deliberate — see that module + CLAUDE.md.
  if (opts.memSafetyTarget) {
    return runMemSafetyScanStage(opts.config, opts.memSafetyTarget, opts.memSafety, emit);
  }

  // Craft scan role — agentic sibling of the fuzz path (see CraftScanOptions).
  // Dispatches to `runCraftScan` and returns, before the DB/runtime machinery.
  if (opts.craftTarget) {
    if (!opts.craft?.evaluatePoc) {
      throw new Error("agenticScan: craftTarget requires craft.evaluatePoc (the PoC oracle)");
    }
    return runCraftScanStage(opts.config, opts.craftTarget, opts.craft, emit);
  }

  const config = await normalizeScanConfig(opts.config);

  // Programmatic scope ingestion (pwnkit#215). Load once at the top and
  // pass the parsed `ScopePolicy` to every agent config below. The CLI
  // is responsible for catching ENOENT / parse errors before this point;
  // here we just propagate. Pre-validate the configured target so an
  // out-of-scope `--target` fails the scan loudly instead of being
  // refused silently by every tool call.
  let scope: ScopePolicy | undefined;
  if (config.scopeFile) {
    scope = loadScope(config.scopeFile);
    // Seed the per-scan cache so every downstream helper reuses this
    // exact policy instance instead of re-reading the JSON file. See
    // `resolveScopeForConfig` for the TOCTOU rationale (pwnkit#218
    // review).
    scopePolicyCache.set(config, scope);
    const verdict = scope.match(config.target);
    if (!verdict.allowed) {
      throw new Error(
        `--target ${config.target} is out of scope per ${config.scopeFile}: ${verdict.reason}`,
      );
    }
  }

  // Scope-guard visibility (pwnkit#133). `resolveScopeForConfig` — not the
  // `scope` local above — is the single authority for what every agent's
  // `ctx.scope` will be, because http_audit synthesises a host policy from
  // `httpAuditAllowedHosts` instead of reading a file. When it returns
  // undefined, the bash egress guards nested in `if (ctx.scope)` are inert for
  // the whole scan.
  //
  // Fail-CLOSED here only when explicitly opted in. Fail-closed by default
  // would break every scan mode we currently ship: the cloud dispatcher emits
  // no `--scope` for any mode except http_audit, and most of those modes
  // (source review, package audit, kernel review) have no live target to be
  // out of scope of. So the default is fail-LOUD — the warning below plus the
  // `scope_guards_inert` event — and `PWNKIT_REQUIRE_SCOPE=1`
  // (`pwnkit scan --require-scope`) is the switch for engagements that must
  // never run unscoped. Thrown before the DB opens so it costs nothing.
  const scopeGuards = describeScopeGuards(!!resolveScopeForConfig(config));
  if (!scopeGuards.active && scopeGuards.required) {
    throw new Error(scopeRequiredRefusal("scan"));
  }

  // Attribution-header config (pwnkit#216). Resolved by every per-stage
  // helper below via `buildAttributionForConfig(config)` — see that
  // function for the actual three-source merge. We pre-flight here so a
  // malformed `attribution` block in the scope file or a malformed
  // `PWNKIT_ATTRIBUTION_HEADERS` env var fails the scan loudly at boot
  // instead of crashing inside the discovery agent's first fetch.
  buildAttributionForConfig(config);

  // Engagement hardening profile. Resolved (and validated) once at boot for
  // the same reason as attribution: an unknown `--engagement-profile` name or
  // a malformed scope-file `engagement` block is a config error the operator
  // should see now, not after the loud default has already run. Resolving to
  // the `standard` posture is a no-op — nothing changes unless opted in.
  const enteredPosture = resolveEngagementForConfig(config);

  const db = await (async () => {
    try {
      const { pwnkitDB } = await import("@pwnkit/db");
      return new pwnkitDB(dbPath);
    } catch (err) {
      const cause = err instanceof Error ? err.message : String(err);
      throw new Error(
        `pwnkit: failed to initialize the local database (@pwnkit/db). ` +
        `Agentic scans require SQLite persistence. Underlying error: ${cause}`,
      );
    }
  })();

  // Resume or create new scan
  const scanId = resumeScanId ?? db.createScan(config);

  if (resumeScanId) {
    const existing = db.getScan(resumeScanId);
    if (!existing) throw new Error(`Scan ${resumeScanId} not found`);
    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "scan_resumed",
      payload: { originalScanId: resumeScanId },
      timestamp: Date.now(),
    });
    emit({ type: "stage:start", stage: "discovery", message: "Resuming scan..." });
  }

  // Record the inert-guard fact in the scan's OWN event log (pwnkit#133), not
  // just on stdout: cloud scans have no console to read, and the whole point
  // of the issue is that a reviewer must be able to answer "did the bash
  // egress guards run on this scan?" after the fact. Paired with the operator-
  // facing warning so a local run can't miss it either.
  if (!scopeGuards.active) {
    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: SCOPE_GUARDS_INERT_EVENT,
      payload: {
        mode: config.mode ?? "default",
        target: config.target,
        inert_guards: scopeGuards.inertGuards,
        remediation: "pass --scope <file>, or --require-scope to refuse unscoped runs",
      },
      timestamp: Date.now(),
    });
    emit({
      type: "stage:start",
      stage: "discovery",
      message: `Warning: ${scopeGuards.message}`,
    });
  }

  // Record the applied engagement posture in the scan's own event log, so the
  // "how did you run this against our estate?" answer is auditable from the DB
  // as well as from the report block. Only when a profile is actually active —
  // default scans log nothing new.
  if (enteredPosture.active) {
    const postureRecord = describeEngagementPosture(enteredPosture);
    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "engagement_posture_applied",
      payload: { ...postureRecord },
      timestamp: Date.now(),
    });
    emit({
      type: "stage:start",
      stage: "discovery",
      message:
        `Engagement profile '${postureRecord.profile}': ` +
        `reset-burst probe ${postureRecord.reset_endpoint_burst_probe}, ` +
        `WAF evasion ladder ${postureRecord.waf_evasion_ladder}, ` +
        `pre-pass ${postureRecord.web_recon_prepass}, ` +
        `${postureRecord.per_host_rps} rps/host with ${postureRecord.request_jitter}`,
    });
  }

  // Determine runtime mode
  const requestedRuntime = config.runtime ?? "api";

  // Native API runtime is only valid for explicit API mode, or for auto mode
  // when we intentionally choose the native API strategy.
  const nativeApiRuntime = new LlmApiRuntime({
    type: "api",
    timeout: config.timeout ?? 120_000,
    model: config.model,
    apiKey: config.apiKey,
  });
  const nativeApiDiagnostics = nativeApiRuntime.getConfigurationDiagnostics();
  assertApiRuntimeSelection(config.runtime, nativeApiDiagnostics);
  const nativeApiAvailable = nativeApiDiagnostics.valid;

  let selectedRuntimeType: "api" | "claude" | "codex" | "gemini" | "ollama" = "api";
  let useNative = false;
  // Subscription-CLI mode: when claude is selected without an API key,
  // we drive the native loop through the local CLI's session-resume
  // protocol (see CliNativeRuntime). This unlocks Claude Max users who
  // never set ANTHROPIC_API_KEY but have already run `claude login`.
  let cliNativeRuntime: CliNativeRuntime | undefined;

  if (requestedRuntime === "api") {
    selectedRuntimeType = "api";
    useNative = nativeApiAvailable;
  } else if (requestedRuntime === "auto") {
    if (nativeApiAvailable) {
      selectedRuntimeType = "api";
      useNative = true;
    } else {
      const availableCli = await detectAvailableRuntimes();
      // Claude is the supported local adapter for live target scanning.
      // Codex and Gemini are experimental and limited to source-analysis workflows.
      if (availableCli.has("claude")) {
        selectedRuntimeType = "claude";
        // No API key but Claude Code is installed — opt the native
        // loop in via the CLI subscription path instead of falling
        // back to the legacy text-based loop.
        cliNativeRuntime = new CliNativeRuntime({
          type: "claude",
          timeout: config.timeout ?? 600_000,
          model: config.model,
        });
        useNative = true;
        emit({
          type: "stage:start",
          stage: "discovery",
          message: "No API key found — running native agent loop through `claude` CLI (subscription mode).",
        });
      } else if (availableCli.has("codex")) {
        selectedRuntimeType = "codex";
        emit({
          type: "stage:start",
          stage: "discovery",
          message: "Warning: Codex CLI is source-analysis only for live targets. Configure ChatGPT Codex direct auth, use runtime=api, or install Claude Code CLI for full tool-loop support.",
        });
      } else if (availableCli.has("gemini")) {
        selectedRuntimeType = "gemini";
        emit({ type: "stage:start", stage: "discovery", message: "Warning: gemini is experimental for live targets. Prefer runtime=api or install Claude Code CLI for full tool-loop support." });
      } else {
        selectedRuntimeType = "api";
      }
    }
  } else if (requestedRuntime === "claude") {
    // Explicit `--runtime claude` always picks the CLI native loop,
    // regardless of whether ANTHROPIC_API_KEY is set. The flag is the
    // user's explicit opt-in to the subscription path; falling through
    // to the legacy text loop on the basis of an env var that happens
    // to be present would silently subvert that intent.
    selectedRuntimeType = "claude";
    cliNativeRuntime = new CliNativeRuntime({
      type: "claude",
      timeout: config.timeout ?? 600_000,
      model: config.model,
    });
    useNative = true;
    emit({
      type: "stage:start",
      stage: "discovery",
      message: nativeApiAvailable
        ? "Explicit --runtime claude: running native agent loop through `claude` CLI (subscription mode); ANTHROPIC_API_KEY ignored."
        : "Running native agent loop through `claude` CLI (subscription mode).",
    });
  } else if (requestedRuntime === "codex" && hasDirectChatGptCodexProvider(nativeApiDiagnostics)) {
    selectedRuntimeType = "api";
    useNative = true;
    emit({
      type: "stage:start",
      stage: "discovery",
      message: "Explicit --runtime codex: running native agent loop through ChatGPT Codex direct provider.",
    });
  } else {
    selectedRuntimeType = requestedRuntime;
    useNative = false;
  }

  // The native-loop entry points all take a NativeRuntime. When the
  // user is in subscription mode, swap the LLM-API runtime for the
  // CLI-backed one. Everywhere else, the API runtime is still in use.
  const nativeRuntime: NativeRuntime = cliNativeRuntime ?? nativeApiRuntime;

  const legacyRuntime = createRuntime({
    type: selectedRuntimeType,
    timeout: config.timeout ?? 60_000,
    model: config.model,
    apiKey: config.apiKey,
    // Route tool calls through the event system so they don't write
    // directly to stderr (which disrupts the Ink TUI)
    onToolCall: (name, detail) => {
      emit({ type: "stage:start", stage: "discovery", message: `${name}${detail ? `: ${detail}` : ""}` });
    },
  });

  const templates = loadTemplates(config.depth);
  const categories = [...new Set(templates.map((t) => t.category))];

  let allFindings: Finding[] = [];

  // Parse API spec if provided
  let apiSpecPromptText = "";
  if (config.apiSpecPath) {
    try {
      const specSummary = await parseApiSpec(config.apiSpecPath);
      apiSpecPromptText = specSummary.promptText;
      emit({ type: "stage:start", stage: "discovery", message: `Loaded API spec: ${specSummary.title} (${specSummary.endpoints.length} endpoints)` });
    } catch (err) {
      emit({ type: "stage:start", stage: "discovery", message: `Warning: failed to parse API spec: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  db.ensureCaseWorkPlan?.(scanId);

  // Log scan start
  db.logEvent({
    scanId,
    stage: "discovery",
    eventType: "scan_start",
    payload: {
      target: config.target,
      depth: config.depth,
      mode: config.mode ?? "probe",
      requestedRuntime,
      selectedRuntime: selectedRuntimeType,
      useNative,
      templateCount: templates.length,
      categoryCount: categories.length,
    },
    timestamp: Date.now(),
  });

  // Event-bus instrumentation: `agenticScan` has multiple exit paths (MCP
  // short-circuit, cost-ceiling partial report, normal report return, and the
  // catch re-throw). Each must emit a single `scan_completed` event so the
  // cloud worker-controller / dashboard tracer can transition the scan to a
  // terminal state. `scan()` in scanner.ts does NOT call agenticScan(), so
  // there is no double-emit risk from nesting — but we still guard against
  // double-fire from sloppy refactors via the `emittedScanCompleted` latch.
  let emittedScanCompleted = false;
  const scanStartedAt = Date.now();

  // ── Per-scan metrics tracked off the bus ─────────────────────────
  // `tool_calls_total` and `summary` (the agent's final narrative) get
  // surfaced on the cloud scan card / detail page so a no-findings scan
  // still tells the operator how much work happened. Tracked here in
  // the scanner (the producer) so the cloud doesn't re-derive these
  // from raw scan_events on every page load — see
  // pwnkit-cloud/services/dashboard/src/routes/_authed/$orgSlug/scans/index.tsx.
  let toolCallsTotal = 0;
  let lastDoneSummary = "";
  const unsubscribeMetrics = eventBus.subscribe({
    emit(type, payload) {
      if (type === "tool_call_completed") {
        toolCallsTotal += 1;
        return;
      }
      if (type === "tool_call_started") {
        // Capture the `done` tool's args_preview verbatim — it's the
        // model's final 1-2 sentence narrative ("Audited lodash, no
        // exploitable sinks found"). Last write wins so a `done` call
        // in a retry loop overwrites the first-attempt summary.
        const tool = payload.tool;
        const argsPreview = payload.args_preview;
        if (
          tool === "done" &&
          typeof argsPreview === "string"
        ) {
          const stripped = argsPreview
            .replace(/^done\s*:\s*/i, "")
            .trim();
          if (stripped) lastDoneSummary = stripped;
        }
      }
    },
  });

  const emitScanCompleted = (
    exit_reason: "completed" | "failed" | "cost_exceeded" | "max_turns" | "early_stop",
    findings_count: number,
    metrics?: {
      turnsUsed?: number;
      summary?: string;
      /**
       * Per-stage usage tally so the bus payload can carry a
       * `cost_breakdown` aggregated by (provider, model). Caller passes
       * one entry per agent loop that ran (discovery, attack, retry,
       * EGATS branch). Empty / undefined → omit `cost_usd` /
       * `cost_breakdown` rather than surface a misleading $0.
       */
      stages?: Array<{
        usage: {
          inputTokens: number;
          outputTokens: number;
          cachedInputTokens?: number;
        };
        model?: string;
      }>;
      /**
       * Optional override for the flag count used in `cost_per_flag`.
       * When absent, falls back to scanning every saved Finding's
       * title / summary / evidence text for `FLAG{...}` matches.
       * Surfaces flagsExtracted == 0 → omit `cost_per_flag`.
       */
      flagsExtracted?: number;
      /** Findings to scan for `FLAG{...}` patterns when `flagsExtracted` is unset. */
      findingsForFlagCount?: Finding[];
    },
  ): void => {
    if (opts.emitTerminalEvent === false || emittedScanCompleted) return;
    emittedScanCompleted = true;
    try {
      // Caller-provided summary (from the loop's `state.summary` field)
      // wins over the bus-derived `lastDoneSummary` because the loop's
      // version may aggregate retries; fall back to the bus capture for
      // exit paths that don't surface a state object (e.g. early-fail).
      const summary =
        (metrics?.summary && metrics.summary.trim()) ||
        lastDoneSummary ||
        undefined;

      // ── Cost surfacing (pwnkit#231) ──
      // Aggregate per-(provider, model) so a multi-model run (Haiku
      // discovery + Opus attack) emits one entry per model with split
      // input/output/cache costs. The cloud relay / consolidator can
      // sum across entries for a single dollar total without losing
      // the per-model breakdown.
      let cost_usd: number | undefined;
      let cost_breakdown: CostBreakdownEntry[] | undefined;
      if (metrics?.stages && metrics.stages.length > 0) {
        const acc = new Map<string, CostBreakdownEntry>();
        for (const stage of metrics.stages) {
          if (!stage.usage) continue;
          // Skip stages that ran but recorded zero usage (e.g. legacy
          // CLI runtimes that don't track tokens). Keeps the breakdown
          // honest — empty entries would mislead consumers into
          // thinking we're double-counting.
          if (
            stage.usage.inputTokens === 0 &&
            stage.usage.outputTokens === 0 &&
            !stage.usage.cachedInputTokens
          ) {
            continue;
          }
          const provider = modelProvider(stage.model);
          const model = stage.model ?? "unknown";
          const key = `${provider}\x1f${model}`;
          const split = splitCost(stage.usage, stage.model);
          const existing = acc.get(key);
          if (existing) {
            existing.cost_in += split.cost_in;
            existing.cost_out += split.cost_out;
            if (split.cost_cache_read !== undefined) {
              existing.cost_cache_read =
                (existing.cost_cache_read ?? 0) + split.cost_cache_read;
            }
          } else {
            acc.set(key, {
              provider,
              model,
              cost_in: split.cost_in,
              cost_out: split.cost_out,
              ...(split.cost_cache_read !== undefined
                ? { cost_cache_read: split.cost_cache_read }
                : {}),
            });
          }
        }
        if (acc.size > 0) {
          cost_breakdown = Array.from(acc.values());
          cost_usd = cost_breakdown.reduce(
            (sum, e) => sum + e.cost_in + e.cost_out + (e.cost_cache_read ?? 0),
            0,
          );
        }
      }

      // ── Flag count for cost_per_flag ──
      // Prefer caller-supplied `flagsExtracted` when present (currently
      // unused — left as an opt-in for future stages that count flags
      // structurally). Otherwise scan saved findings for `FLAG{...}`.
      let cost_per_flag: number | undefined;
      const flagsExtracted =
        metrics?.flagsExtracted !== undefined
          ? metrics.flagsExtracted
          : countFlagsInFindings(metrics?.findingsForFlagCount ?? []);
      if (cost_usd !== undefined && flagsExtracted > 0) {
        cost_per_flag = cost_usd / flagsExtracted;
      }

      eventBus.emit("scan_completed", {
        exit_reason,
        findings: findings_count,
        findings_count,
        duration_ms: Date.now() - scanStartedAt,
        turns_used: metrics?.turnsUsed,
        tool_calls_total: toolCallsTotal,
        summary,
        ...(cost_usd !== undefined ? { cost_usd } : {}),
        ...(cost_breakdown !== undefined ? { cost_breakdown } : {}),
        ...(cost_per_flag !== undefined ? { cost_per_flag } : {}),
      });
    } catch {
      /* bus is fail-soft, but be defensive */
    } finally {
      unsubscribeMetrics();
    }
  };

  try {
    // ── MCP fast-path: use deterministic MCP security checks ──
    // The agentic agent loops are designed for LLM API targets. For MCP targets,
    // LLM indirect-prompt-injection audit fast-path. Mirrors the MCP
    // short-circuit: a self-contained specialized audit, not a web pentest.
    if (config.mode === "llm-ipi") {
      emit({ type: "stage:start", stage: "discovery", message: "LLM IPI audit starting..." });
      const ipiCtx = createScanContext(config);
      ipiCtx.scanId = scanId;
      ipiCtx.target = { url: config.target, type: "chatbot", model: config.model };
      emit({ type: "stage:end", stage: "discovery", message: "LLM endpoint registered" });

      emit({ type: "stage:start", stage: "attack", message: "Running IPI campaign..." });
      const { findings } = await runLlmIpiAudit({
        baseUrl: config.target,
        apiKey: config.apiKey ?? process.env.PWNKIT_LLM_TARGET_KEY ?? "",
        models: config.model ? [config.model] : ["default"],
        maxAttempts: config.depth === "deep" ? 50 : 20,
      });
      for (const finding of findings) {
        finding.remediation = generateRemediation(finding);
        ipiCtx.findings.push(finding);
      }
      allFindings = [...findings];
      emit({ type: "stage:end", stage: "attack", message: `IPI audit complete: ${findings.length} findings` });

      if (db) {
        db.upsertTarget(ipiCtx.target);
        for (const finding of findings) db.saveFinding(scanId, finding);
      }
      finalize(ipiCtx);

      const summary = {
        totalAttacks: 0,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      };
      db.completeScan(scanId, summary);

      const report: ScanReport = {
        target: config.target,
        scanDepth: config.depth,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        summary,
        findings: allFindings,
        warnings: [],
      };
      const dbScan = db.getScan(scanId);
      if (dbScan) {
        report.startedAt = dbScan.startedAt;
        report.completedAt = dbScan.completedAt ?? report.completedAt;
        report.durationMs = dbScan.durationMs ?? 0;
      }
      emit({ type: "stage:end", stage: "report", message: `Report: ${summary.totalFindings} findings` });
      await postFinalReport(report);
      emitScanCompleted("completed", allFindings.length, { findingsForFlagCount: allFindings });
      return report;
    }

    // delegate to the structured MCP discovery + security checks which directly
    // speak JSON-RPC to the MCP server.
    if (config.mode === "mcp" || isMcpTarget(config.target)) {
      emit({ type: "stage:start", stage: "discovery", message: "MCP discovery starting..." });
      const mcpCtx = createScanContext(config);
      mcpCtx.scanId = scanId;

      try {
        const targetInfo = await discoverMcpTarget(config.target, config.timeout);
        mcpCtx.target = targetInfo;
      } catch (err) {
        mcpCtx.target = { url: config.target, type: "mcp" };
      }
      emit({ type: "stage:end", stage: "discovery", message: `MCP target discovered: ${mcpCtx.target.type}` });

      emit({ type: "stage:start", stage: "attack", message: "Running MCP security checks..." });
      const { results, findings } = await runMcpSecurityChecks(mcpCtx);
      mcpCtx.attacks.push(...results);
      for (const finding of findings) {
        mcpCtx.findings.push(finding);
      }
      allFindings = [...findings];

      // Attach remediation guidance to MCP findings
      for (const finding of allFindings) {
        finding.remediation = generateRemediation(finding);
      }

      emit({ type: "stage:end", stage: "attack", message: `MCP checks complete: ${findings.length} findings` });

      // Persist findings
      if (db) {
        db.upsertTarget(mcpCtx.target);
        for (const finding of findings) {
          db.saveFinding(scanId, finding);
        }
        for (const result of results) {
          db.saveAttackResult(scanId, result);
        }
      }

      finalize(mcpCtx);

      const summary = {
        totalAttacks: results.length,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      };

      db.completeScan(scanId, summary);

      const report: ScanReport = {
        target: config.target,
        scanDepth: config.depth,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        summary,
        findings: allFindings,
        warnings: [],
      };

      const dbScan = db.getScan(scanId);
      if (dbScan) {
        report.startedAt = dbScan.startedAt;
        report.completedAt = dbScan.completedAt ?? report.completedAt;
        report.durationMs = dbScan.durationMs ?? 0;
      }

      emit({ type: "stage:end", stage: "report", message: `Report: ${summary.totalFindings} findings` });
      // Stream final report to the opt-in webhook sink (no-op when unset).
      await postFinalReport(report);
      // MCP fast-path doesn't invoke a metered LLM runtime — `cost_usd`
      // is intentionally omitted (no `stages`). Still surface flag count
      // so `cost_per_flag` is null, not bogus.
      emitScanCompleted("completed", allFindings.length, {
        findingsForFlagCount: allFindings,
      });
      return report;
    }

    if (!useNative && selectedRuntimeType === "codex") {
      throw new Error(
        "Codex CLI live target scanning is not supported. " +
        "The MCP-backed Codex wrapper was removed because it adds a target-interaction bottleneck. " +
        "For live target scans with Codex, run `codex login`, set " +
        "PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN from ~/.codex/auth.json, and retry `pwnkit scan --runtime codex`; " +
        "otherwise use runtime=api or runtime=claude.",
      );
    }

    // ── Stage 1: Discovery Agent ──
    emit({ type: "stage:start", stage: "discovery", message: "Discovery agent starting..." });
    db.transitionCaseWorkItem?.(scanId, "surface_map", "in_progress", {
      owner: "attack-surface-agent",
      summary: "Discovery agent is mapping the target surface and initial context.",
    });
    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "stage_start",
      agentRole: "discovery",
      payload: {},
      timestamp: Date.now(),
    });

    // Deterministic web-recon pre-pass — runs ONCE here on the common path so it
    // applies to BOTH native and legacy discovery. The cloud worker invokes pwnkit
    // with `--runtime codex`, which resolves to the legacy discovery loop; a hook
    // wired only into runNativeDiscovery never fires there (the reason the pre-pass
    // produced nothing in cloud scans). Never breaks the scan; emits findings
    // directly and folds its leads into apiSpecPromptText, which both discovery
    // paths already inject into the agent system prompt.
    let reconFindings: Finding[] = [];
    const isWebPrepass = config.mode === "web" || config.mode === "http_audit";
    if (isWebPrepass && features.webRecon) {
      try {
        const { runWebReconPrePass } = await import("./stages/web-recon-prepass.js");
        // Engagement hardening: when a profile is active the pre-pass runs
        // through the shared per-host token bucket (it uses raw `fetch`
        // otherwise) and its password-reset burst probe is suppressed.
        const prepassPosture = resolveEngagementForConfig(config);
        const { findings: rf, promptBlock } = await runWebReconPrePass(config, {
          posture: prepassPosture,
          rateLimiter:
            prepassPosture.webReconPrepass === "rate-limited"
              ? getOrCreateRateLimiter(config)
              : undefined,
        });
        reconFindings = rf;
        if (promptBlock) {
          apiSpecPromptText = apiSpecPromptText
            ? apiSpecPromptText + "\n\n" + promptBlock
            : promptBlock;
        }
        emit({
          type: "stage:end",
          stage: "discovery",
          message: `Web recon pre-pass: ${reconFindings.length} finding${reconFindings.length === 1 ? "" : "s"} emitted`,
        });
      } catch (err) {
        // Pre-pass must never break the scan.
        console.error(
          `[web-recon-prepass] failed: ${err instanceof Error ? err.message : err}`,
        );
      }
    }

    const discoveryState = useNative
      ? await runNativeDiscovery(nativeRuntime, db, config, scanId, emit, apiSpecPromptText, getPendingUserMessages)
      : await runLegacyDiscovery(legacyRuntime, db, config, scanId, emit, dbPath, apiSpecPromptText);

    // Merge the deterministic pre-pass findings into discovery output (once).
    if (reconFindings.length) {
      discoveryState.findings = [...reconFindings, ...discoveryState.findings];
      // In cloud mode, findings reach the orchestrator DB only via postFinding —
      // which is otherwise fired solely by the agent's `save_finding` tool calls.
      // The pre-pass findings never go through that tool, so post them explicitly
      // here, or they'd be silently dropped in cloud scans (present in the local
      // report but absent from the 0cloud DB). postFinding no-ops when there is
      // no cloud sink config (local CLI), so this is a safe cloud-only emission.
      const sinkCfg = getCloudSinkConfig();
      if (sinkCfg) {
        for (const f of reconFindings) void postFinding(f, sinkCfg);
      }
    }

    // Persist target profile
    if (discoveryState.targetInfo.type) {
      db.upsertTarget({
        url: config.target,
        type: discoveryState.targetInfo.type ?? "unknown",
        model: discoveryState.targetInfo.model,
        systemPrompt: discoveryState.targetInfo.systemPrompt,
        endpoints: discoveryState.targetInfo.endpoints,
        detectedFeatures: discoveryState.targetInfo.detectedFeatures,
      });
    }

    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "stage_complete",
      agentRole: "discovery",
      payload: { summary: discoveryState.summary.slice(0, 500) },
      timestamp: Date.now(),
    });
    db.transitionCaseWorkItem?.(scanId, "surface_map", "done", {
      owner: "attack-surface-agent",
      summary: discoveryState.summary.slice(0, 500) || "Discovery completed.",
    });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "todo", {
      owner: "research-agent",
      summary: "Surface mapping completed. Exploit hypothesis is ready to start.",
    });
    emit({
      type: "stage:end",
      stage: "discovery",
      message: `Discovery complete: ${discoveryState.summary}`,
    });

    // ── Stage 2: Attack Agent ──
    const maxAttackTurns = config.depth === "deep" ? 100 : config.depth === "default" ? 40 : 20;

    emit({
      type: "stage:start",
      stage: "attack",
      message: `Attack agent starting (${categories.length} categories)...`,
    });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "in_progress", {
      owner: "research-agent",
      summary: "Attack agent is developing the exploit hypothesis and artifact path.",
    });
    db.transitionCaseWorkItem?.(scanId, "poc_build", "in_progress", {
      owner: "research-agent",
      summary: "Attack agent is building exploit requests, responses, and reproduction artifacts.",
    });
    db.logEvent({
      scanId,
      stage: "attack",
      eventType: "stage_start",
      agentRole: "attack",
      payload: { categories, maxTurns: maxAttackTurns },
      timestamp: Date.now(),
    });

    // ── Best-of-N Racing (--race flag) ──
    // When enabled, run multiple attack strategies in parallel and take the first success.
    let attackState: AgentOutput;

    if (config.egats && useNative) {
      emit({
        type: "stage:start",
        stage: "attack",
        message: "Running EGATS (Evidence-Gated Attack Tree Search)...",
      });

      const egatsResult = await runEGATSWithDefaults(
        config.target,
        scanId,
        nativeRuntime,
        db,
        {
          repoPath: config.repoPath,
          challengeHint: opts.challengeHint,
          onEvent: (eventType, payload) => {
            emit({
              type: "stage:start",
              stage: "attack",
              message: `[egats] ${eventType}`,
              data: payload,
            });
          },
        },
      );

      attackState = {
        findings: egatsResult.findings,
        targetInfo: discoveryState.targetInfo,
        summary: `[egats:${egatsResult.terminationReason}] explored ${egatsResult.allNodes.length} nodes, ${egatsResult.findings.length} findings`,
        turnCount: egatsResult.totalTurns,
        estimatedCostUsd: egatsResult.totalCostUsd,
      };
    } else if (config.race && useNative) {
      emit({
        type: "stage:start",
        stage: "attack",
        message: "Racing 5 strategies in parallel (best-of-N)...",
      });

      const raceResult = await raceWithDefaults(
        config.target,
        scanId,
        nativeRuntime,
        db,
        {
          maxConcurrency: config.maxConcurrency ?? 3,
          repoPath: config.repoPath,
          challengeHint: opts.challengeHint,
        },
      );

      // Convert RaceResult to AgentOutput
      if (raceResult.winner) {
        attackState = {
          findings: raceResult.winner.findings,
          targetInfo: discoveryState.targetInfo,
          summary: `[race:${raceResult.winner.strategyName}] ${raceResult.winner.summary}`,
          turnCount: raceResult.totalTurns,
          estimatedCostUsd: raceResult.totalCostUsd,
        };
      } else {
        // All strategies failed — combine findings from all attempts
        const combinedFindings = raceResult.allResults.flatMap((r) => r.findings);
        const summaryParts = raceResult.allResults.map(
          (r) => `${r.strategyName}: ${r.succeeded ? "success" : "failed"} (${r.turnCount} turns)`,
        );
        attackState = {
          findings: combinedFindings,
          targetInfo: discoveryState.targetInfo,
          summary: `All ${raceResult.allResults.length} strategies failed. ${summaryParts.join("; ")}`,
          turnCount: raceResult.totalTurns,
          estimatedCostUsd: raceResult.totalCostUsd,
        };
      }
    } else {
      attackState = useNative
        ? await runNativeAttack(nativeRuntime, db, config, scanId, discoveryState.targetInfo, categories, maxAttackTurns, emit, opts.challengeHint, apiSpecPromptText, getPendingUserMessages)
        : await runLegacyAttack(legacyRuntime, db, config, scanId, discoveryState.targetInfo, categories, maxAttackTurns, emit, dbPath, apiSpecPromptText);
    }

    allFindings = [...attackState.findings];

    db.logEvent({
      scanId,
      stage: "attack",
      eventType: "stage_complete",
      agentRole: "attack",
      payload: { findingCount: allFindings.length, summary: attackState.summary.slice(0, 500) },
      timestamp: Date.now(),
    });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "done", {
      owner: "research-agent",
      summary: attackState.summary.slice(0, 500) || "Exploit hypothesis completed.",
    });
    db.transitionCaseWorkItem?.(scanId, "poc_build", allFindings.length > 0 ? "done" : "blocked", {
      owner: "research-agent",
      summary: allFindings.length > 0
        ? `PoC build completed with ${allFindings.length} finding${allFindings.length > 1 ? "s" : ""}.`
        : "Attack stage finished without actionable exploit artifacts.",
    });
    if (allFindings.length > 0) {
      db.transitionCaseWorkItem?.(scanId, "blind_verify", "todo", {
        owner: "verify-agent",
        summary: "Exploit artifacts are ready for an independent verification pass.",
      });
    }
    emit({
      type: "stage:end",
      stage: "attack",
      message: `Attack complete: ${attackState.findings.length} findings, ${attackState.summary}`,
    });

    // ── Cost ceiling short-circuit ──
    // If the attack stage was aborted because the per-scan cost ceiling was
    // exceeded, skip triage/verify/remediation and emit a partial report
    // immediately. Findings collected so far are preserved in the DB and
    // returned on the report. Callers (CLI) can detect this via the
    // `costCeilingExceeded` flag on the returned report.
    if (attackState.costCeilingExceeded) {
      // Persist any findings collected so far so they're not lost.
      for (const f of allFindings) {
        try { db.saveFinding(scanId, f); } catch { /* may already be persisted */ }
      }

      const summary = {
        totalAttacks: attackState.turnCount,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      };
      try { db.completeScan(scanId, summary); } catch { /* best effort */ }

      const partialTraceMessages = [
        ...(discoveryState.messages ?? []),
        ...(attackState.messages ?? []),
      ];
      const partialReport: ScanReport = {
        target: config.target,
        scanDepth: config.depth,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        summary,
        findings: allFindings,
        warnings: [
          {
            stage: "attack",
            message: `Scan aborted: cost ceiling of $${(config.costCeilingUsd ?? 0).toFixed(4)} exceeded after ${attackState.turnCount} turns. Partial findings preserved.`,
          },
        ],
        benchmarkMeta: {
          attackTurns: attackState.turnCount,
          estimatedCostUsd: attackState.estimatedCostUsd,
          inputTokens: attackState.totalUsage?.inputTokens,
          outputTokens: attackState.totalUsage?.outputTokens,
          totalTokens:
            attackState.totalUsage
              ? attackState.totalUsage.inputTokens + attackState.totalUsage.outputTokens
              : undefined,
          model: config.model,
        },
        exitReason: "cost_ceiling_exceeded",
        costCeilingExceeded: true,
        ...(partialTraceMessages.length > 0 ? { trace: partialTraceMessages } : {}),
      };
      attachEnforcementSummary(partialReport, config);
      attachEngagementPosture(partialReport, config);

      const dbScan = db.getScan(scanId);
      if (dbScan) {
        partialReport.startedAt = dbScan.startedAt;
        partialReport.completedAt = dbScan.completedAt ?? partialReport.completedAt;
        partialReport.durationMs = dbScan.durationMs ?? 0;
      }

      emit({
        type: "stage:end",
        stage: "report",
        message: `cost_ceiling_exceeded: aborted with ${allFindings.length} partial finding(s)`,
      });

      db.logEvent({
        scanId,
        stage: "report",
        eventType: "scan_aborted",
        payload: { reason: "cost_ceiling_exceeded", ...summary },
        timestamp: Date.now(),
      });

      emitScanCompleted("cost_exceeded", allFindings.length, {
        turnsUsed:
          (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
        summary: attackState?.summary ?? discoveryState?.summary,
        stages: [
          ...(discoveryState
            ? [{ usage: discoveryState.totalUsage ?? { inputTokens: 0, outputTokens: 0 }, model: config.model }]
            : []),
          ...(attackState
            ? [{ usage: attackState.totalUsage ?? { inputTokens: 0, outputTokens: 0 }, model: config.model }]
            : []),
        ],
        findingsForFlagCount: allFindings,
      });
      return partialReport;
    }

    // ── http_audit kill-switch short-circuit ──
    // If the wall-clock budget expired during discovery or attack, the native
    // loop already broke cleanly at a turn boundary (partial findings flushed
    // to the DB and carried on `allFindings`). Skip triage/verify/remediation
    // — those would re-enter the loop only to break again immediately — and
    // emit a partial report straight away, exactly mirroring the cost-ceiling
    // path. Never process.exit: we flow through normal report assembly so the
    // enforcement_summary and partial findings reach the caller.
    const killEnforcement = resolveEnforcementForConfig(config);
    if (killEnforcement?.triggered) {
      for (const f of allFindings) {
        try { db.saveFinding(scanId, f); } catch { /* may already be persisted */ }
      }
      const killSummary = {
        totalAttacks: attackState.turnCount,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      };
      try { db.completeScan(scanId, killSummary); } catch { /* best effort */ }

      const killTrace = [
        ...(discoveryState.messages ?? []),
        ...(attackState.messages ?? []),
      ];
      const killReport: ScanReport = {
        target: config.target,
        scanDepth: config.depth,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        summary: killSummary,
        findings: allFindings,
        warnings: [
          {
            stage: "attack",
            message: `Scan aborted: http_audit kill switch fired after ${killEnforcement.wallClockSec().toFixed(1)}s. ${allFindings.length} partial finding(s) preserved.`,
          },
        ],
        benchmarkMeta: {
          attackTurns: attackState.turnCount,
          estimatedCostUsd: attackState.estimatedCostUsd,
          inputTokens: attackState.totalUsage?.inputTokens,
          outputTokens: attackState.totalUsage?.outputTokens,
          totalTokens: attackState.totalUsage
            ? attackState.totalUsage.inputTokens + attackState.totalUsage.outputTokens
            : undefined,
          model: config.model,
        },
        ...(killTrace.length > 0 ? { trace: killTrace } : {}),
      };
      attachEnforcementSummary(killReport, config);
      attachEngagementPosture(killReport, config);

      const dbScan = db.getScan(scanId);
      if (dbScan) {
        killReport.startedAt = dbScan.startedAt;
        killReport.completedAt = dbScan.completedAt ?? killReport.completedAt;
        killReport.durationMs = dbScan.durationMs ?? 0;
      }

      db.logEvent({
        scanId,
        stage: "report",
        eventType: "scan_aborted",
        payload: { reason: "kill_switch_triggered", ...killSummary },
        timestamp: Date.now(),
      });
      emit({
        type: "stage:end",
        stage: "report",
        message: `kill_switch_triggered: aborted with ${allFindings.length} partial finding(s)`,
      });
      await postFinalReport(killReport);
      emitScanCompleted("completed", allFindings.length, {
        turnsUsed: (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
        summary: attackState?.summary ?? discoveryState?.summary,
        stages: [
          ...(discoveryState
            ? [{ usage: discoveryState.totalUsage ?? { inputTokens: 0, outputTokens: 0 }, model: config.model }]
            : []),
          ...(attackState
            ? [{ usage: attackState.totalUsage ?? { inputTokens: 0, outputTokens: 0 }, model: config.model }]
            : []),
        ],
        findingsForFlagCount: allFindings,
      });
      return killReport;
    }

    // ── Stage 2.5: Triage (holding-it-wrong + feature extraction) ──
    // For every finding saved by the attack agent:
    //   1. Run `isHoldingItWrong` — if true, downgrade severity to `info`,
    //      mark triage_status=rejected, and skip further verification.
    //   2. Extract the 45-element feature vector and log it (the trained
    //      triage model is not yet wired in; we log for future training).
    //   3. Only findings that pass holding-it-wrong AND have
    //      evidence_completeness > 0.5 get sent to the blind verify agent.
    const verifyCandidates: Finding[] = [];
    const evidenceCompletenessIdx = FEATURE_NAMES.indexOf("cross_evidence_completeness");

    // ── Publishability dedup inputs (issue #537 / #539) ──
    // Built once per scan (the package/repo is constant across findings) and
    // only when the gate is enabled — `buildPublishabilityInputs` wires the four
    // live dedup sources (published GHSA/OSV/CVE, our own prior submissions incl.
    // declined, the repo's own security issues/PRs, and SECURITY.md). All are
    // behind injectable seams. The source repository ("owner/repo") lights up
    // the repo-issue + SECURITY.md sources; we take it from config when set,
    // else best-effort resolve it from npm metadata. If it stays unresolved,
    // those two sources no-op (conservative — never a guessed-repo false dup).
    const pkgNameForScan = inferPackage(config.target);
    const dedupEcosystem = (config.ecosystem ?? "npm") as DedupEcosystem;
    // For the novelty gate (issue #851) we resolve the package identity from
    // the config first, falling back to the resolved `eco:name@version` target
    // shape (e.g. "npm:lodash@4.17.4") that the unified pipeline produces. We
    // must NOT default the ecosystem to npm — defaulting would query the public
    // advisory DB for a private/SaaS target; resolveNovelty returns undefined
    // for any non-OSS / unset ecosystem, so leaving it unset is the safe no-op.
    const parsedTarget = parsePackageTarget(config.target);
    const noveltyEcosystem = config.ecosystem ?? parsedTarget?.ecosystem;
    const noveltyVersion = config.version ?? parsedTarget?.version;
    const noveltyPackage = parsedTarget?.name ?? pkgNameForScan;
    let publishabilityInputs: PublishabilityInputs | undefined;
    if (features.publishabilityGate) {
      const repository =
        config.repository ??
        (await resolveRepository(pkgNameForScan, { ecosystem: dedupEcosystem }));
      publishabilityInputs = buildPublishabilityInputs({
        ecosystem: dedupEcosystem,
        ...(repository ? { repository } : {}),
      });
    }
    // ── Dynamic per-finding triage routing (pwnkit#113) ──
    // When `PWNKIT_FEATURE_DYNAMIC_TRIAGE=1`, a per-finding decision says
    // which layers to skip. The decision is recorded in this map so we
    // can (a) gate layer execution below and (b) emit `routing-trace.jsonl`
    // at scan teardown for offline learned-router training.
    const routingDecisions = new Map<string, RoutingDecision>();
    for (const finding of allFindings) {
      // Always run isHoldingItWrong + extractFeatures for telemetry, but
      // only enforce the rejection when the feature flags are enabled.
      // Both default ON to preserve existing v0.6.0 behavior; setting
      // PWNKIT_FEATURE_HOLDING_IT_WRONG=0 / PWNKIT_FEATURE_EVIDENCE_GATE=0
      // turns the gates off so we can A/B test what they actually cost.
      const hiwStartedAt = Date.now();
      const hiw = isHoldingItWrong(finding);
      const featureVector = extractFeatures(finding);
      const evidenceCompleteness =
        evidenceCompletenessIdx >= 0 ? featureVector[evidenceCompletenessIdx] ?? 0 : 0;

      // Layer telemetry: holding-it-wrong always runs (just may not enforce).
      // pwnkit#112 — feeds the dynamic routing model in #113.
      //
      // The blocklist drop is a heuristic, so it routes through the one
      // disclosure predicate: a disclosure-grade finding is held for
      // verification instead of being dropped on a pattern match alone (#518).
      const hiwEnforces = hiw.isHoldingItWrong && features.holdingItWrong;
      const hiwDecision = hiwEnforces ? isDisclosureWorthy(finding, "rejected") : null;
      if (hiwEnforces && hiwDecision!.keep) {
        pushLayerVerdict(finding, {
          layer: "holding_it_wrong",
          verdict: "downgrade",
          reason: `matched holding-it-wrong (${hiw.reason}) but protected (${hiwDecision!.guard ?? "guard"}): held for verification`,
          startedAt: hiwStartedAt,
        });
      } else if (hiwEnforces) {
        pushLayerVerdict(finding, {
          layer: "holding_it_wrong",
          verdict: "reject",
          reason: hiw.reason ?? "matched holding-it-wrong blocklist",
          startedAt: hiwStartedAt,
          changedSeverity: { from: finding.severity, to: "info" },
        });
      } else {
        pushLayerVerdict(finding, {
          layer: "holding_it_wrong",
          verdict: hiw.isHoldingItWrong ? "skip" : "pass",
          reason: hiw.isHoldingItWrong
            ? `would have rejected (${hiw.reason}) but PWNKIT_FEATURE_HOLDING_IT_WRONG=0`
            : "no holding-it-wrong pattern matched",
          startedAt: hiwStartedAt,
        });
      }

      // Log the feature vector for future training
      db.logEvent?.({
        scanId,
        stage: "verify",
        eventType: "triage_features",
        agentRole: "triage",
        payload: {
          findingId: finding.id,
          featureVector,
          featureNames: FEATURE_NAMES,
          evidenceCompleteness,
          holdingItWrong: hiw.isHoldingItWrong,
          holdingItWrongReason: hiw.reason,
        },
        timestamp: Date.now(),
      });

      if (hiwEnforces && !hiwDecision!.keep) {
        // Suppressible: downgrade severity to info and mark rejected. Skip further verify.
        finding.severity = "info";
        finding.triageStatus = "suppressed";
        finding.triageNote = `rejected: holding-it-wrong — ${hiw.reason}`;
        db.updateFindingStatus?.(finding.id, "false-positive");
        finding.status = "false-positive";
        db.saveFinding?.(scanId, finding);
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage rejected ${finding.id}: ${hiw.reason}`,
        });
        continue;
      }
      if (hiwEnforces && hiwDecision!.keep) {
        // Protected class/severity — hold for verification, never a silent
        // drop on the blocklist. The finding falls through the pipeline.
        finding.triageNote = `holding-it-wrong matched but protected (${hiwDecision!.guard ?? "guard"}): held for verification — ${hiw.reason}`;
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "auto_suppress_guard",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            path: "holding_it_wrong",
            guard: hiwDecision!.guard,
            reason: hiwDecision!.reason,
            severity: finding.severity,
            category: finding.category,
          },
          timestamp: Date.now(),
        });
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage held ${finding.id} for verification (holding-it-wrong, protected): ${hiwDecision!.reason}`,
        });
        // fall through to the remaining triage layers + verify
      }

      const evidenceGateStartedAt = Date.now();
      const evidenceGateRejects = evidenceCompleteness <= 0.5;
      // Guardrail (#518): a low completeness *score* alone must never auto-drop
      // a high-severity / high-impact finding. When the guard fires we do NOT
      // short-circuit — the finding falls through to the rest of the triage
      // pipeline (reachability / multi-modal / verify), which is exactly the
      // "route to verification instead of suppress" behavior we want.
      const evidenceGuard = isDisclosureWorthy(finding, "rejected");
      if (evidenceGateRejects && features.evidenceGate && !evidenceGuard.keep) {
        pushLayerVerdict(finding, {
          layer: "evidence_gate",
          verdict: "reject",
          confidence: 1 - evidenceCompleteness,
          reason: `evidence_completeness=${evidenceCompleteness.toFixed(2)} <= 0.5`,
          startedAt: evidenceGateStartedAt,
        });
        finding.triageStatus = "suppressed";
        finding.triageNote = `rejected: evidence_completeness=${evidenceCompleteness.toFixed(2)} <= 0.5`;
        db.updateFindingStatus?.(finding.id, "false-positive");
        finding.status = "false-positive";
        db.saveFinding?.(scanId, finding);
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage rejected ${finding.id}: insufficient evidence (completeness=${evidenceCompleteness.toFixed(2)})`,
        });
        continue;
      }
      if (evidenceGateRejects && features.evidenceGate && evidenceGuard.keep) {
        // Guard bailed the auto-drop. Record it and let the finding proceed.
        pushLayerVerdict(finding, {
          layer: "evidence_gate",
          verdict: "skip",
          confidence: 1 - evidenceCompleteness,
          reason: `would have rejected (completeness=${evidenceCompleteness.toFixed(2)} <= 0.5) but auto-suppress guard fired: ${evidenceGuard.reason}`,
          startedAt: evidenceGateStartedAt,
        });
        finding.triageNote = `evidence_gate guard: kept for verification despite completeness=${evidenceCompleteness.toFixed(2)} <= 0.5 — ${evidenceGuard.reason}`;
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "auto_suppress_guard",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            path: "evidence_gate",
            guard: evidenceGuard.guard,
            reason: evidenceGuard.reason,
            severity: finding.severity,
            category: finding.category,
          },
          timestamp: Date.now(),
        });
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Evidence gate held ${finding.id} for verification: ${evidenceGuard.reason}`,
        });
        // fall through to remaining triage layers + verify
      }
      pushLayerVerdict(finding, {
        layer: "evidence_gate",
        verdict: evidenceGateRejects ? "skip" : "pass",
        confidence: evidenceCompleteness,
        reason: evidenceGateRejects
          ? `would have rejected (completeness=${evidenceCompleteness.toFixed(2)}) but PWNKIT_FEATURE_EVIDENCE_GATE=0`
          : `evidence_completeness=${evidenceCompleteness.toFixed(2)} > 0.5`,
        startedAt: evidenceGateStartedAt,
      });

      // ── Learned router (pwnkit#113) ──
      // When enabled, the XGBoost model decides per-finding whether to
      // auto-accept, auto-reject, or run a subset of layers. This runs
      // AFTER the two free always-on filters (holding-it-wrong +
      // evidence_gate) and BEFORE any expensive layer. The model loads
      // once from triage-router-v1.json and evaluates in sub-millisecond.
      if (features.learnedRouter) {
        const routerResult = routeFinding(finding);
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "learned_router",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            decision: routerResult.decision,
            tpProbability: routerResult.tpProbability,
            reason: routerResult.reason,
            layersToRun: routerResult.layersToRun,
            layersToSkip: routerResult.layersToSkip,
          },
          timestamp: Date.now(),
        });

        if (routerResult.decision === "auto_accept") {
          finding.confidence = Math.max(finding.confidence ?? 0, routerResult.tpProbability);
          finding.triageStatus = "accepted";
          finding.triageNote = `router_auto_accept: ${routerResult.reason}`;
          db.saveFinding?.(scanId, finding);
          verifyCandidates.push(finding);
          continue;
        }

        if (routerResult.decision === "auto_reject") {
          // Guardrail (#518): the XGBoost router's auto_reject is a *score*
          // (p<=0.25). It may never auto-drop a high-severity / high-impact
          // finding — those get at least one verification pass. When the guard
          // fires we record it and fall through to the remaining layers + verify.
          const routerGuard = isDisclosureWorthy(finding, "rejected");
          if (!routerGuard.keep) {
            finding.triageStatus = "suppressed";
            finding.triageNote = `router_auto_reject: ${routerResult.reason}`;
            db.updateFindingStatus?.(finding.id, "false-positive");
            finding.status = "false-positive";
            db.saveFinding?.(scanId, finding);
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Router rejected ${finding.id}: ${routerResult.reason}`,
            });
            continue;
          }
          finding.triageNote = `router guard: kept for verification despite auto_reject (${routerResult.reason}) — ${routerGuard.reason}`;
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "auto_suppress_guard",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              path: "learned_router",
              guard: routerGuard.guard,
              reason: routerGuard.reason,
              severity: finding.severity,
              category: finding.category,
              tpProbability: routerResult.tpProbability,
            },
            timestamp: Date.now(),
          });
          emit({
            type: "stage:end",
            stage: "attack",
            message: `Router held ${finding.id} for verification: ${routerGuard.reason}`,
          });
          // fall through to the dynamic router + remaining layers + verify
        }

        // decision === "run_layers" — continue to the layers below,
        // but the router's layersToSkip list is available for future
        // per-layer gating (not wired yet — the static feature flags
        // still control which layers run for now).
      }

      // ── Dynamic per-finding triage routing (pwnkit#113) ──
      // Gated behind PWNKIT_FEATURE_DYNAMIC_TRIAGE (default OFF). When
      // enabled, the router decides per-finding which subset of the
      // 11 triage layers to invoke. Layers NOT in `layers_to_invoke`
      // are short-circuited in the per-layer branches below. The
      // decision is recorded for emission to `routing-trace.jsonl` at
      // scan teardown for the joint paper's dataset.
      if (features.dynamicTriageRouting) {
        const decision = decideLayers(finding);
        routingDecisions.set(finding.id, decision);
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "dynamic_triage_routing",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            layersToInvoke: decision.layers_to_invoke,
            matchedRule: decision.matchedRule,
            routerConfidence: decision.confidence,
            reasoning: decision.reasoning,
          },
          timestamp: Date.now(),
        });
        // Rule 3 (FP-pattern auto-reject) and any other rule that
        // returns an empty layer set short-circuits the entire
        // downstream triage stage for this finding.
        if (decision.layers_to_invoke.length === 0) {
          // Guardrail (#518): an empty-layer-set (FP-pattern heuristic) may
          // never auto-drop a high-severity / high-impact finding. When the
          // guard fires we record it and fall through; the finding still
          // reaches the agentic verify agent (Stage 3) — a real verification
          // pass — instead of being marked false-positive on a pattern alone.
          const dynamicGuard = isDisclosureWorthy(finding, "rejected");
          if (!dynamicGuard.keep) {
            finding.triageStatus = "suppressed";
            finding.triageNote = `dynamic_router_auto_reject: ${decision.reasoning ?? decision.matchedRule ?? "empty layer set"}`;
            db.updateFindingStatus?.(finding.id, "false-positive");
            finding.status = "false-positive";
            db.saveFinding?.(scanId, finding);
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Dynamic router rejected ${finding.id}: ${decision.matchedRule ?? "empty layer set"}`,
            });
            continue;
          }
          finding.triageNote = `dynamic_router guard: kept for verification despite empty layer set (${decision.matchedRule ?? "FP-pattern"}) — ${dynamicGuard.reason}`;
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "auto_suppress_guard",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              path: "dynamic_triage",
              guard: dynamicGuard.guard,
              reason: dynamicGuard.reason,
              severity: finding.severity,
              category: finding.category,
              matchedRule: decision.matchedRule,
            },
            timestamp: Date.now(),
          });
          emit({
            type: "stage:end",
            stage: "attack",
            message: `Dynamic router held ${finding.id} for verification: ${dynamicGuard.reason}`,
          });
          // fall through; the empty layer set still routes to the verify agent
        }
      }

      // Helper closure: when dynamic routing is on, skip a layer the
      // router didn't include in its `layers_to_invoke` set. When the
      // flag is off, every layer runs as before.
      const routerAllowsLayer = (layer: LayerId): boolean => {
        if (!features.dynamicTriageRouting) return true;
        const decision = routingDecisions.get(finding.id);
        if (!decision) return true;
        return decision.layers_to_invoke.includes(layer);
      };

      // ── Reachability gate ("Endor Labs moat") ──
      // Opt-in via PWNKIT_FEATURE_REACHABILITY_GATE. Only runs in white-box
      // mode when we have source code. For each finding, check whether the
      // vulnerable sink is actually reachable from an application entry
      // point (HTTP handler, CLI main, route file). Dead code and test-only
      // paths are suppressed before we spend any LLM tokens on verify.
      if (features.reachabilityGate && config.repoPath && routerAllowsLayer("reachability")) {
        const reachStartedAt = Date.now();
        try {
          const reach = await checkReachability(finding, config.repoPath);
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "reachability_check",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              reachable: reach.reachable,
              confidence: reach.confidence,
              entryPoints: reach.entryPoints,
              callPath: reach.callPath,
              reason: reach.reason,
            },
            timestamp: Date.now(),
          });
          if (!reach.reachable && reach.confidence >= 0.7) {
            // Unreachable is a confident verdict, but a disclosure-grade
            // finding still routes through the one disclosure predicate so it
            // is never dropped on the reachability heuristic alone (#518).
            const reachDecision = isDisclosureWorthy(finding, "rejected");
            if (!reachDecision.keep) {
              pushLayerVerdict(finding, {
                layer: "reachability",
                verdict: "reject",
                confidence: reach.confidence,
                reason: `unreachable: ${reach.reason}`,
                startedAt: reachStartedAt,
              });
              finding.triageStatus = "suppressed";
              finding.triageNote = `unreachable: ${reach.reason}`;
              db.updateFindingStatus?.(finding.id, "false-positive");
              finding.status = "false-positive";
              db.saveFinding?.(scanId, finding);
              emit({
                type: "stage:end",
                stage: "attack",
                message: `Reachability gate rejected ${finding.id}: ${reach.reason}`,
              });
              continue;
            }
            // Protected — hold for verification, never a silent drop.
            pushLayerVerdict(finding, {
              layer: "reachability",
              verdict: "downgrade",
              confidence: reach.confidence,
              reason: `unreachable (${reach.reason}) but protected (${reachDecision.guard ?? "guard"}): held for verification`,
              startedAt: reachStartedAt,
            });
            finding.triageNote = `unreachable but protected (${reachDecision.guard ?? "guard"}): held for verification — ${reach.reason}`;
            db.logEvent?.({
              scanId,
              stage: "verify",
              eventType: "auto_suppress_guard",
              agentRole: "triage",
              payload: {
                findingId: finding.id,
                path: "reachability",
                guard: reachDecision.guard,
                reason: reachDecision.reason,
                severity: finding.severity,
                category: finding.category,
              },
              timestamp: Date.now(),
            });
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Reachability gate held ${finding.id} for verification (protected): ${reachDecision.reason}`,
            });
            // fall through to the remaining triage layers + verify
          } else {
            pushLayerVerdict(finding, {
              layer: "reachability",
              verdict: "pass",
              confidence: reach.confidence,
              reason: reach.reachable
                ? `reachable from ${reach.entryPoints.length} entry point(s): ${reach.reason}`
                : `low-confidence unreachable verdict (${reach.confidence.toFixed(2)} < 0.7), kept`,
              startedAt: reachStartedAt,
            });

            // ── Reachability v2: input-controllability (issue #658) ──
            // File-reachability says the sink is in live code, but for
            // injection classes the *injected value* can still be a developer-
            // supplied identifier (ORM table/column/constraint name) rather
            // than attacker input. These ORM-internal identifier-injection
            // findings flood triage with non-exploitable noise. We DOWNGRADE +
            // annotate — never drop: sql-injection is a #518-protected class, so
            // `canAutoSuppress` refuses to suppress it; this only lowers the
            // severity/priority so it stops over-promoting into disclosure while
            // staying visible for human review.
            const ctrl = analyzeInputControllability(finding, config.repoPath);
            if (
              ctrl.controllability === "internal-identifier" &&
              ctrl.confidence >= 0.75
            ) {
              const guard = canAutoSuppressDetailed(finding);
              const fromSev = finding.severity;
              const toSev = controllabilityDowngradeTarget(fromSev, ctrl.confidence);
              if (toSev && toSev !== fromSev) {
                finding.severity = toSev;
                finding.triageNote = `internal-identifier (not attacker-controllable): ${ctrl.reason}`;
                pushLayerVerdict(finding, {
                  layer: "reachability",
                  verdict: "downgrade",
                  confidence: ctrl.confidence,
                  reason: `internal-identifier injection (${ctrl.taintedParam ?? "object name"}); downgraded ${fromSev}→${toSev}, kept for review — ${ctrl.reason}`,
                  startedAt: reachStartedAt,
                  changedSeverity: { from: fromSev, to: toSev },
                });
              } else {
                // Already low-priority, or below the per-tier confidence bar:
                // annotate only, never change severity, never drop.
                finding.triageNote = `internal-identifier (not attacker-controllable), severity unchanged: ${ctrl.reason}`;
                pushLayerVerdict(finding, {
                  layer: "reachability",
                  verdict: "downgrade",
                  confidence: ctrl.confidence,
                  reason: `internal-identifier injection (${ctrl.taintedParam ?? "object name"}); flagged, severity unchanged — ${ctrl.reason}`,
                  startedAt: reachStartedAt,
                });
              }
              db.logEvent?.({
                scanId,
                stage: "verify",
                eventType: "controllability_check",
                agentRole: "triage",
                payload: {
                  findingId: finding.id,
                  controllability: ctrl.controllability,
                  confidence: ctrl.confidence,
                  taintedParam: ctrl.taintedParam,
                  ormInternal: ctrl.ormInternal,
                  evidence: ctrl.evidence,
                  fromSeverity: fromSev,
                  toSeverity: finding.severity,
                  guard: guard.guard ?? null,
                  canSuppress: guard.canSuppress,
                  reason: ctrl.reason,
                },
                timestamp: Date.now(),
              });
            }
          }
        } catch (err) {
          // Reachability check errors must not drop findings silently —
          // let the rest of the pipeline continue.
          pushLayerVerdict(finding, {
            layer: "reachability",
            verdict: "error",
            reason: `reachability check threw: ${(err as Error).message}`,
            startedAt: reachStartedAt,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "reachability_check_error",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              error: (err as Error).message,
            },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "reachability",
          verdict: "skip",
          reason: features.reachabilityGate
            ? "no repoPath available (black-box mode)"
            : "PWNKIT_FEATURE_REACHABILITY_GATE=0",
          startedAt: Date.now(),
        });
      }

      // ── Multi-modal agreement (foxguard cross-validation) ──
      // Opt-in via PWNKIT_FEATURE_MULTIMODAL. Only runs when we have source
      // code (white-box mode). Cross-checks every finding against the
      // foxguard Rust pattern scanner — if both agents agree, the finding is
      // almost certainly real; if foxguard disagrees and the evidence is
      // thin, we auto-reject.
      if (features.multiModalAgreement && config.repoPath && routerAllowsLayer("multi_modal")) {
        const mmStartedAt = Date.now();
        try {
          const mm = await checkMultiModalAgreement(finding, config.repoPath);
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "multi_modal_agreement",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              agreement: mm.agreement,
              confidence: mm.confidence,
              foxguardMatches: mm.foxguardFindings.length,
              reasoning: mm.reasoning,
            },
            timestamp: Date.now(),
          });

          const fused = fuseTriageSignals({
            multiModal: mm,
            holdingItWrong: false,
            evidenceCompleteness,
          });

          if (fused.decision === "auto_accept") {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "pass",
              confidence: fused.confidence,
              reason: `auto_accept: ${fused.reasoning}`,
              startedAt: mmStartedAt,
            });
            finding.confidence = Math.max(finding.confidence ?? 0, fused.confidence);
            finding.triageStatus = "accepted";
            finding.triageNote = `multi_modal_accept: ${fused.reasoning}`;
          } else if (fused.decision === "auto_reject") {
            // Multi-modal disagreement is a fused signal, not a verification
            // pass — so a disclosure-grade finding routes through the one
            // disclosure predicate and is held for verification rather than
            // dropped on the fused score alone (#518).
            const mmDecision = isDisclosureWorthy(finding, "rejected");
            if (!mmDecision.keep) {
              pushLayerVerdict(finding, {
                layer: "multi_modal",
                verdict: "reject",
                confidence: fused.confidence,
                reason: `auto_reject: ${fused.reasoning}`,
                startedAt: mmStartedAt,
                changedSeverity: { from: finding.severity, to: "info" },
              });
              finding.severity = "info";
              finding.triageStatus = "suppressed";
              finding.triageNote = `multi_modal_reject: ${fused.reasoning}`;
              db.updateFindingStatus?.(finding.id, "false-positive");
              finding.status = "false-positive";
              db.saveFinding?.(scanId, finding);
              emit({
                type: "stage:end",
                stage: "attack",
                message: `Multi-modal rejected ${finding.id}: ${fused.reasoning}`,
              });
              continue;
            }
            // Protected — hold for verification, never a silent drop.
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "downgrade",
              confidence: fused.confidence,
              reason: `auto_reject (${fused.reasoning}) but protected (${mmDecision.guard ?? "guard"}): held for verification`,
              startedAt: mmStartedAt,
            });
            finding.triageNote = `multi_modal_reject but protected (${mmDecision.guard ?? "guard"}): held for verification — ${fused.reasoning}`;
            db.logEvent?.({
              scanId,
              stage: "verify",
              eventType: "auto_suppress_guard",
              agentRole: "triage",
              payload: {
                findingId: finding.id,
                path: "multi_modal",
                guard: mmDecision.guard,
                reason: mmDecision.reason,
                severity: finding.severity,
                category: finding.category,
              },
              timestamp: Date.now(),
            });
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Multi-modal held ${finding.id} for verification (protected): ${mmDecision.reason}`,
            });
            // fall through to the remaining triage layers + verify
          } else if (fused.decision === "verify_priority") {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "pass",
              confidence: mm.confidence,
              reason: `verify_priority: ${mm.reasoning}`,
              startedAt: mmStartedAt,
            });
            finding.confidence = Math.max(finding.confidence ?? 0, mm.confidence);
            finding.triageNote = `multi_modal_agree: ${mm.reasoning}`;
          } else {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "pass",
              confidence: mm.confidence,
              reason: `verify (${fused.decision}): ${fused.reasoning}`,
              startedAt: mmStartedAt,
            });
          }
        } catch (err) {
          pushLayerVerdict(finding, {
            layer: "multi_modal",
            verdict: "error",
            reason: `multi-modal threw: ${(err as Error).message}`,
            startedAt: mmStartedAt,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "multi_modal_error",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              error: (err as Error).message,
            },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "multi_modal",
          verdict: "skip",
          reason: features.multiModalAgreement
            ? "no repoPath available (black-box mode)"
            : "PWNKIT_FEATURE_MULTIMODAL=0",
          startedAt: Date.now(),
        });
      }

      // ── Publishability / in-scope gate (issue #537 / #539) ──
      // Opt-in via PWNKIT_FEATURE_PUBLISHABILITY_GATE (default OFF). Decides
      // disclosure-worthiness so we stop filing by-design / duplicate /
      // dead-code / already-fixed findings. The layer itself only *computes* a
      // verdict; any SUPPRESSION decision (by_design / duplicate / fixed /
      // unreachable) is routed through `isDisclosureWorthy` so a
      // high-severity / high-impact finding is NEVER silently dropped — it is
      // downgraded to `needs_verify` + human review instead. `in_scope` and
      // `fix_bypass` are the green-to-file verdicts and are kept.
      //
      // Network checks live behind injectable seams on `publishabilityInputs`,
      // wired by `buildPublishabilityInputs` to the four live dedup sources:
      // published GHSA/OSV/CVE, our own prior submissions (incl. declined), the
      // target repo's open+closed security issues/PRs, and SECURITY.md. Each
      // seam is fail-soft (network error → that source returns nothing), so a
      // blip degrades dedup coverage but never drops or mis-suppresses a
      // finding. When the gate is off, `publishabilityInputs` is undefined and
      // the layer runs with no seams → `in_scope` (safe no-op).
      if (features.publishabilityGate && routerAllowsLayer("publishability")) {
        const pubStartedAt = Date.now();
        try {
          const result = await checkPublishability(
            finding,
            pkgNameForScan,
            "",
            publishabilityInputs ?? {},
          );
          finding.publishability = result.decision;
          if (result.dedupRefs && result.dedupRefs.length > 0) {
            finding.dedupRefs = result.dedupRefs;
          }
          // Public-advisory novelty gate (issue #851). Live OSV / GitHub
          // Advisory DB lookup, OSS ecosystems only, version-scoped when known.
          // Default-safe: absent/non-OSS ecosystem → resolveNovelty returns
          // undefined and the finding's verdict stays unset (behavior
          // unchanged). Fail-soft: any error must never drop a finding, so we
          // swallow and leave the verdict undefined.
          try {
            const novelty = await resolveNovelty(
              noveltyPackage,
              noveltyEcosystem,
              noveltyVersion,
            );
            if (novelty) {
              finding.noveltyVerdict = novelty.verdict;
              if (novelty.advisoryMatches.length > 0) {
                finding.advisoryMatches = novelty.advisoryMatches;
              }
            }
          } catch {
            // novelty is advisory-only; never let it disturb the finding
          }
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "publishability_check",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              decision: result.decision,
              confidence: result.confidence,
              reason: result.reason,
              threatModelExclusion: result.threatModelExclusion,
              dedupRefs: result.dedupRefs,
              latestVersionFixed: result.latestVersionFixed,
              publicApiReachable: result.publicApiReachable,
            },
            timestamp: Date.now(),
          });

          // Green verdicts — keep the finding, record a pass.
          if (result.decision === "in_scope" || result.decision === "fix_bypass") {
            pushLayerVerdict(finding, {
              layer: "publishability",
              verdict: "pass",
              confidence: result.confidence,
              reason: `${result.decision}: ${result.reason}`,
              startedAt: pubStartedAt,
            });
          } else {
            // A suppression verdict (by_design / duplicate / fixed /
            // unreachable). Route through the auto-suppress guard: a
            // disclosure-grade finding may NOT be dropped on a heuristic.
            const guard = isDisclosureWorthy(finding, "rejected");
            if (!guard.keep) {
              pushLayerVerdict(finding, {
                layer: "publishability",
                verdict: "reject",
                confidence: result.confidence,
                reason: `${result.decision}: ${result.reason}`,
                startedAt: pubStartedAt,
              });
              finding.triageStatus = "suppressed";
              finding.triageNote = `publishability_${result.decision}: ${result.reason}`;
              db.updateFindingStatus?.(finding.id, "false-positive");
              finding.status = "false-positive";
              db.saveFinding?.(scanId, finding);
              emit({
                type: "stage:end",
                stage: "attack",
                message: `Publishability gate suppressed ${finding.id} (${result.decision}): ${result.reason}`,
              });
              continue;
            }
            // Protected class/severity — downgrade to needs_verify + human
            // review, NEVER a silent drop. The finding stays in the pipeline.
            finding.publishability = "needs_verify";
            finding.triageNote = `publishability_${result.decision} held for review (${guard.reason}): ${result.reason}`;
            pushLayerVerdict(finding, {
              layer: "publishability",
              verdict: "downgrade",
              confidence: result.confidence,
              reason: `${result.decision} but protected (${guard.guard ?? "guard"}): held as needs_verify for human review — ${result.reason}`,
              startedAt: pubStartedAt,
            });
            db.saveFinding?.(scanId, finding);
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Publishability gate held ${finding.id} for review (${result.decision} → needs_verify): ${guard.reason}`,
            });
          }
        } catch (err) {
          // Publishability errors must never drop a finding — log and keep.
          pushLayerVerdict(finding, {
            layer: "publishability",
            verdict: "error",
            reason: `publishability check threw: ${(err as Error).message}`,
            startedAt: pubStartedAt,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "publishability_check_error",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              error: (err as Error).message,
            },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "publishability",
          verdict: "skip",
          reason: features.publishabilityGate
            ? "skipped by dynamic_router"
            : "PWNKIT_FEATURE_PUBLISHABILITY_GATE=0",
          startedAt: Date.now(),
        });
      }

      // ── Per-class verification oracle ──
      // "No exploit, no report" — attempt a deterministic exploit check for
      // each category we have an oracle for. If the oracle verifies, boost
      // confidence and mark the finding accepted. If it fails and we have an
      // oracle for the category, downgrade severity to low and annotate.
      // Categories without oracles fall through to the LLM-verify stage.
      const oracleStartedAt = Date.now();
      const oracleAllowed = routerAllowsLayer("oracle");
      // Captured so the PoV gate can reuse a deterministic oracle run instead
      // of firing the browser / collector a second time. Only set when the
      // oracle actually executed (not router-skipped, not thrown).
      let oracleOutcomeForPov: OracleResult | undefined;
      try {
        // Inline-validation reuse (#554): when the in-loop onFindingSaved hook
        // already CONFIRMED this finding with the same deterministic oracle,
        // do NOT re-run the probe / browser / collector here — that would
        // double-spend. Reuse the inline verdict as a verified OracleResult.
        // It flows through the `oracle.verified` branch below (accept the
        // finding), which also makes the PoV gate skip via
        // triageStatus === "accepted" — exactly the "don't double-spend"
        // requirement.
        const inlineConfirmed = finding.inlineValidation?.confirmed === true;
        const oracle: OracleResult = inlineConfirmed
          ? {
              verified: true,
              confidence: finding.inlineValidation?.confidence ?? 1,
              evidence:
                `inline-confirmed: ` +
                `${finding.inlineValidation?.evidence ?? finding.inlineValidation?.reason ?? ""}`.trim(),
              reason: "",
            }
          : oracleAllowed
            ? await verifyOracleByCategory(finding, config.target)
            : { verified: false, confidence: 0, evidence: "", reason: "skipped by dynamic_router" };
        // Reuse for the PoV gate whenever the oracle actually produced a
        // verdict here — either it ran, or we reused an inline confirmation.
        if (oracleAllowed || inlineConfirmed) oracleOutcomeForPov = oracle;
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "oracle_result",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            category: finding.category,
            verified: oracle.verified,
            confidence: oracle.confidence,
            evidence: oracle.evidence,
            reason: oracle.reason,
          },
          timestamp: Date.now(),
        });

        if (oracle.verified) {
          pushLayerVerdict(finding, {
            layer: "oracle",
            verdict: "pass",
            confidence: oracle.confidence,
            reason: `verified: ${oracle.evidence}`,
            startedAt: oracleStartedAt,
          });
          finding.confidence = 1.0;
          finding.triageStatus = "accepted";
          finding.triageNote = `oracle_verified: ${oracle.evidence}`;
          // pwnkit#659 / 0cloud#1278 — when this deterministic pass came from the
          // OAST-callback oracle (SSRF / OOB-RCE / OOB-SQLi), emit an ALWAYS-ON
          // `oast_confirmed` bus event so cloudEventSink relays it to
          // scan_events. Unlike `pov_oracle` (below, gated behind the default-off
          // FP-moat pov_gate), the `oracle` layer is always-on — so this is the
          // reliable cloud-side signal the blind-vuln→verify loop reads to
          // promote. Additive: `oastConfirmedPayload` returns null (no emit) on
          // any non-OAST oracle. See that helper for the exact gate.
          const oastEvent = oastConfirmedPayload(finding, oracle);
          if (oastEvent) eventBus.emit("oast_confirmed", oastEvent);
        } else if (
          oracle.reason &&
          !oracle.reason.startsWith("no oracle for category")
        ) {
          // An oracle exists for this category but the exploit didn't
          // reproduce. Downgrade severity and annotate so downstream agents
          // don't over-promote the finding.
          const fromSev = finding.severity;
          finding.severity = "low";
          finding.triageNote = `oracle_failed: ${oracle.reason}`;
          pushLayerVerdict(finding, {
            layer: "oracle",
            verdict: "downgrade",
            confidence: oracle.confidence,
            reason: `failed to reproduce: ${oracle.reason}`,
            startedAt: oracleStartedAt,
            changedSeverity: { from: fromSev, to: "low" },
          });
        } else {
          pushLayerVerdict(finding, {
            layer: "oracle",
            verdict: "skip",
            reason: `no oracle for category=${finding.category}`,
            startedAt: oracleStartedAt,
          });
        }
      } catch (err) {
        pushLayerVerdict(finding, {
          layer: "oracle",
          verdict: "error",
          reason: `oracle threw: ${(err as Error).message}`,
          startedAt: oracleStartedAt,
        });
        // Never let oracle errors kill the scan — log and move on.
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "oracle_error",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            error: (err as Error).message,
          },
          timestamp: Date.now(),
        });
      }

      // ── PoV generation gate ──
      // Empirical ground truth from arXiv:2509.07225: if the agent cannot
      // build a working PoC in N turns, the finding is likely a false
      // positive. Run AFTER the oracle (so we skip oracle-verified findings)
      // and BEFORE the blind verify agent. Only runs when the feature flag
      // is enabled and we have a native runtime.
      if (
        features.povGate
        && (nativeApiAvailable || cliNativeRuntime)
        && finding.triageStatus !== "accepted"
        && routerAllowsLayer("pov_gate")
      ) {
        const povStart = Date.now();
        try {
          // Reuse the deterministic oracle already run above when this category
          // delegates to one (XSS → headless browser, SSRF / blind RCE / blind
          // injection → OAST callback), so the PoV gate doesn't re-fire the
          // browser / collector.
          const povOracleKind = oracleForCategory(finding.category);
          const pov = await generatePov(finding, config.target, nativeRuntime, 5, {
            precomputedOracle:
              povOracleKind !== "regex-fallback"
                ? oracleOutcomeForPov
                : undefined,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "pov_gate_result",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              category: finding.category,
              hasPov: pov.hasPov,
              artifactType: pov.artifactType,
              confidence: pov.confidence,
              turnsUsed: pov.turnsUsed,
              reason: pov.reason,
              durationMs: Date.now() - povStart,
            },
            timestamp: Date.now(),
          });
          // Dashboard trace: which oracle decided the PoV verdict.
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "pov_oracle",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              category: finding.category,
              oracle: pov.oracle,
              hasPov: pov.hasPov,
              inconclusive: pov.inconclusive ?? false,
              reason: pov.reason,
            },
            timestamp: Date.now(),
          });
          // Mirror onto the typed EventBus (#570). `db.logEvent` only writes
          // pwnkit's LOCAL sqlite, which the cloud worker never relays — so
          // without this the per-finding "deterministic vs heuristic" badge
          // never reaches the dashboard. cloudEventSink serializes this to a
          // `PWNKIT_EVENT_POV_ORACLE` line → worker → orchestrator
          // `scan_events`, keyed by findingId, exactly like
          // untrusted_input_sanitized (#558).
          eventBus.emit("pov_oracle", {
            findingId: finding.id,
            category: finding.category,
            oracle: pov.oracle,
            hasPov: pov.hasPov,
            inconclusive: pov.inconclusive ?? false,
            reason: pov.reason,
          });
          if (pov.hasPov) {
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "pass",
              confidence: pov.confidence,
              reason: `pov_verified(${pov.artifactType}): ${pov.reason}`,
              startedAt: povStart,
            });
            // Boost confidence and attach the working PoC as evidence.
            finding.confidence = Math.max(finding.confidence ?? 0, pov.confidence);
            finding.triageStatus = "accepted";
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") +
              `pov_verified(${pov.artifactType}): ${pov.reason}`;
            const existing = finding.evidence.analysis ?? "";
            finding.evidence.analysis =
              `${existing}${existing ? "\n\n" : ""}` +
              `## PoV Artifact (${pov.artifactType})\n${pov.povArtifact ?? ""}\n\n` +
              `## Execution Evidence\n${pov.executionEvidence}`;
          } else if (pov.inconclusive) {
            // The deterministic oracle could not run to a conclusion (browser /
            // collector errored). "Inconclusive on error, not a false pass":
            // never downgrade on this signal — the verify agent gets a second
            // shot.
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") +
              `pov_inconclusive(${pov.oracle}): ${pov.reason}`;
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "pass",
              confidence: pov.confidence,
              reason: `inconclusive (${pov.oracle}): ${pov.reason}`,
              startedAt: povStart,
            });
          } else if (
            pov.oracle !== "regex-fallback" ||
            pov.turnsUsed >= 5 ||
            pov.reason.startsWith("max turns")
          ) {
            const fromSev = finding.severity;
            // Hard gate: either a deterministic oracle ran and the exploit did
            // NOT reproduce (e.g. XSS reflected as text but never fired), or no
            // working PoC was produced within the turn budget → downgrade to
            // info.
            finding.severity = "info";
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") + "no_pov";
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "downgrade",
              confidence: pov.confidence,
              reason: `no_pov (${pov.oracle}): ${pov.reason}`,
              startedAt: povStart,
              changedSeverity: { from: fromSev, to: "info" },
            });
          } else {
            // Regex-fallback category, agent gave up / runtime error — annotate
            // but don't downgrade (the verify agent gets a second shot).
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") +
              `pov_failed: ${pov.reason}`;
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "pass",
              confidence: pov.confidence,
              reason: `inconclusive: ${pov.reason}`,
              startedAt: povStart,
            });
          }
        } catch (err) {
          pushLayerVerdict(finding, {
            layer: "pov_gate",
            verdict: "error",
            reason: `pov gate threw: ${(err as Error).message}`,
            startedAt: povStart,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "pov_gate_error",
            agentRole: "triage",
            payload: { findingId: finding.id, error: (err as Error).message },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "pov_gate",
          verdict: "skip",
          reason: !features.povGate
            ? "PWNKIT_FEATURE_POV_GATE=0"
            : !(nativeApiAvailable || cliNativeRuntime)
              ? "no native runtime available"
              : "already accepted by upstream layer",
          startedAt: Date.now(),
        });
      }

      // ── Static-finding PoC generation gate (#666 / EPIC #674 Part A) ──
      // Findings that reach here with NO executable PoC (`pocSteps` empty —
      // the static / code-analysis path) are exactly the ones the cloud
      // verify fan-out silently `skipped` (poc_steps IS NULL → never promoted
      // to verify). Run an agentic PoC-gen pass: build + run a minimal PoC in
      // the scan substrate (reuses the PoV mini-loop's bash / http / oracle
      // execution path — no new infra). On reproduce, synthesize runnable
      // pocSteps so the verify runner picks it up; on no-repro, flag
      // `poc:none` so 0cloud routes it to manual / inconclusive — never a
      // silent skip. Default OFF (PWNKIT_FEATURE_POC_GEN_STATIC), A/B-able via
      // the #656 harness.
      if (
        features.pocGenStatic
        && (nativeApiAvailable || cliNativeRuntime)
        && !(finding.pocSteps && finding.pocSteps.length > 0)
        && finding.severity !== "info"
        && routerAllowsLayer("poc_gen")
      ) {
        const pocGenStart = Date.now();
        try {
          const pocResult = await generateStaticPoc(
            finding,
            config.target,
            nativeRuntime,
          );
          applyStaticPocResult(finding, pocResult, pocGenStart);
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "poc_gen_result",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              category: finding.category,
              reproduced: pocResult.reproduced,
              artifactType: pocResult.pov.artifactType,
              oracle: pocResult.pov.oracle,
              turnsUsed: pocResult.pov.turnsUsed,
              pocStepCount: pocResult.pocSteps?.length ?? 0,
              marker: pocResult.marker,
              durationMs: Date.now() - pocGenStart,
            },
            timestamp: Date.now(),
          });
        } catch (err) {
          pushLayerVerdict(finding, {
            layer: "poc_gen",
            verdict: "error",
            reason: `poc_gen threw: ${(err as Error).message}`,
            startedAt: pocGenStart,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "poc_gen_error",
            agentRole: "triage",
            payload: { findingId: finding.id, error: (err as Error).message },
            timestamp: Date.now(),
          });
        }
      } else if (features.pocGenStatic) {
        // Flag is on but this finding wasn't eligible — record why.
        pushLayerVerdict(finding, {
          layer: "poc_gen",
          verdict: "skip",
          reason: !(nativeApiAvailable || cliNativeRuntime)
            ? "no native runtime available"
            : finding.pocSteps && finding.pocSteps.length > 0
              ? "finding already has executable pocSteps"
              : finding.severity === "info"
                ? "severity=info (downgraded by upstream gate)"
                : "router excluded poc_gen",
          startedAt: Date.now(),
        });
      }

      db.saveFinding?.(scanId, finding);
      verifyCandidates.push(finding);
    }

    // ── Stage 3: Verification Agent ──
    if (verifyCandidates.length > 0) {
      emit({
        type: "stage:start",
        stage: "verify",
        message: `Verifying ${verifyCandidates.length} findings (${allFindings.length - verifyCandidates.length} rejected by triage)...`,
      });
      db.transitionCaseWorkItem?.(scanId, "blind_verify", "in_progress", {
        owner: "verify-agent",
        summary: `Verification agent is reproducing ${verifyCandidates.length} finding${verifyCandidates.length > 1 ? "s" : ""}.`,
      });
      db.logEvent({
        scanId,
        stage: "verify",
        eventType: "stage_start",
        agentRole: "verify",
        payload: {
          findingCount: verifyCandidates.length,
          triageRejected: allFindings.length - verifyCandidates.length,
        },
        timestamp: Date.now(),
      });

      // ── Self-consistency voting (feature-gated) ──
      // Before the agentic verify agent touches anything, optionally run the
      // structured verify pipeline N=3 times per candidate and take a
      // majority vote. Findings rejected by consensus are dropped from the
      // verify queue and marked as false positives — this is the cheapest
      // remaining FP-reduction knob in the pipeline (~15% in research).
      let consensusFiltered = verifyCandidates;
      if (features.selfConsistencyVerify && (nativeApiAvailable || cliNativeRuntime)) {
        const survivors: Finding[] = [];
        for (const finding of verifyCandidates) {
          try {
            const consensus = await verify(
              finding,
              config.target,
              nativeRuntime,
              { votes: 3, temperature: 0.7, earlyStopThreshold: 0.8 },
            );
            const consensusVerdict = toVerifyVerdict(consensus);
            // Stamp the evidence basis natively (#674) so the disclosure gate
            // and 0cloud read one canonical value instead of re-deriving it.
            consensusVerdict.evidenceKind = evidenceKindForFinding(finding);
            db.logEvent?.({
              scanId,
              stage: "verify",
              eventType: "consensus_verify",
              agentRole: "verify",
              payload: {
                findingId: finding.id,
                verdict: consensus.verdict,
                confidence: consensus.confidence,
                agreement: consensus.agreement,
                runCount: consensus.runs.length,
                runVerdicts: consensus.runs.map((r) => r.verdict),
              },
              timestamp: Date.now(),
            });
            emit({
              type: "stage:end",
              stage: "verify",
              message: `Consensus ${consensus.verdict} for ${finding.id} (${Math.round(consensus.confidence * 100)}% agreement across ${consensus.runs.length} runs)`,
            });
            // Route the consensus verdict through the one disclosure predicate.
            // A `rejected` vote drops only when the finding is auto-suppressible;
            // a disclosure-grade finding (high/critical or high-impact class) is
            // held and still handed to the agentic verify agent (a real pass),
            // never silently buried on a vote alone (#518).
            const consensusDecision = isDisclosureWorthy(finding, consensusVerdict);
            if (consensus.verdict === "rejected" && !consensusDecision.keep) {
              finding.triageStatus = "suppressed";
              finding.triageNote = `rejected by self-consistency vote (${Math.round(consensus.confidence * 100)}% agreement, ${consensus.runs.length} runs)`;
              db.updateFindingStatus?.(finding.id, "false-positive");
              finding.status = "false-positive";
              db.saveFinding?.(scanId, finding);
              continue;
            }
            if (consensus.verdict === "rejected") {
              finding.triageNote = `self-consistency vote rejected but protected (${consensusDecision.guard ?? "guard"}): held for agentic verify — ${consensusDecision.reason}`;
              db.logEvent?.({
                scanId,
                stage: "verify",
                eventType: "auto_suppress_guard",
                agentRole: "verify",
                payload: {
                  findingId: finding.id,
                  path: "self_consistency",
                  guard: consensusDecision.guard,
                  reason: consensusDecision.reason,
                  severity: finding.severity,
                  category: finding.category,
                },
                timestamp: Date.now(),
              });
            }
            survivors.push(finding);
          } catch (err) {
            // If consensus verification itself errors, fall through to the
            // agentic verify agent rather than silently dropping the finding.
            db.logEvent?.({
              scanId,
              stage: "verify",
              eventType: "consensus_verify_error",
              agentRole: "verify",
              payload: {
                findingId: finding.id,
                error: err instanceof Error ? err.message : String(err),
              },
              timestamp: Date.now(),
            });
            survivors.push(finding);
          }
        }
        consensusFiltered = survivors;
      }

      if (consensusFiltered.length === 0) {
        emit({
          type: "stage:end",
          stage: "verify",
          message: "All candidates rejected by consensus — skipping agentic verify.",
        });
      } else if (useNative) {
        await runNativeVerify(nativeRuntime, db, config, scanId, consensusFiltered, emit);
      } else {
        await runLegacyVerify(legacyRuntime, db, config, scanId, consensusFiltered, emit, dbPath);
      }

      // Merge verification results — DB is source of truth
      const dbFindings = db.getFindings(scanId);
      allFindings = dbFindings.map(dbFindingToFinding);

      // Attach remediation guidance to confirmed/verified findings
      for (const finding of allFindings) {
        if (finding.status !== "false-positive") {
          finding.remediation = generateRemediation(finding);
        }
      }

      db.logEvent({
        scanId,
        stage: "verify",
        eventType: "stage_complete",
        agentRole: "verify",
        payload: {
          verified: allFindings.filter((f) => f.status === "verified").length,
          falsePositive: allFindings.filter((f) => f.status === "false-positive").length,
        },
        timestamp: Date.now(),
      });
      const verifiedCount = allFindings.filter((f) => f.status === "verified").length;
      const falsePositiveCount = allFindings.filter((f) => f.status === "false-positive").length;
      db.transitionCaseWorkItem?.(scanId, "blind_verify", "done", {
        owner: "verify-agent",
        summary: `Verification finished with ${verifiedCount} verified and ${falsePositiveCount} false-positive findings.`,
      });
      db.transitionCaseWorkItem?.(scanId, "consensus", "done", {
        owner: "consensus-agent",
        summary: "Verification evidence has been consolidated into the next decision state.",
      });
      db.transitionCaseWorkItem?.(scanId, "human_review", "todo", {
        owner: "operator",
        summary: "Autonomous verification completed. Operator review is now required.",
      });
      emit({
        type: "stage:end",
        stage: "verify",
        message: `Verification complete: ${allFindings.filter((f) => f.status !== "false-positive").length} confirmed`,
      });
    }

    // ── Remediation: ensure all non-false-positive findings have guidance ──
    for (const finding of allFindings) {
      if (!finding.remediation && finding.status !== "false-positive") {
        finding.remediation = generateRemediation(finding);
      }
    }

    // ── Stage 4: Report ──
    // Extracted to `agentic/stages/report.ts` (pwnkit#1285) — the terminal
    // stage assembles the report, persists completion, emits the routing
    // trace + webhook, and fires `scan_completed`. `emitScanCompleted` and
    // `attachEnforcementSummary` stay owned here (they close over the bus /
    // enforcement cache) and are handed in via ctx.
    // ── Post-scan post-process (flag-gated, default OFF) ──
    // Intra-scan semantic dedupe + incremental ranking over the final finding
    // set, right before the report stage. Mutates findings in place with
    // additive optional fields; fail-soft — a post-process error never fails
    // the scan (the pass itself is also fail-soft per batch).
    if (features.semanticDedupe || features.incrementalRank) {
      try {
        // Load prior-scan anchors for cross-scan dedupe when semanticDedupe
        // is active and a local DB is available. Anchor-load failure must
        // never fail the scan — proceed with no anchors on error.
        let anchors: DedupeItem[] | undefined;
        if (features.semanticDedupe) {
          try {
            anchors = await loadPriorScanAnchors(db, config.target, { excludeScanId: scanId });
          } catch {
            // Anchor load failure is non-fatal
          }
        }

        const collapsed = await applyFindingPostProcess(allFindings, nativeRuntime, {
          semanticDedupe: features.semanticDedupe,
          incrementalRank: features.incrementalRank,
          scanId,
          anchors,
        });
        emit({
          type: "stage:end",
          stage: "report",
          message: `Post-process: ${collapsed} duplicate(s) collapsed across ${allFindings.length} findings`,
        });
      } catch (err) {
        emit({
          type: "thinking",
          message: `Post-scan post-process skipped: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }

    return await runReportStage(
      { allFindings, attackState, discoveryState, config, scanId, routingDecisions },
      { db, emit, emitScanCompleted, attachEnforcementSummary, attachEngagementPosture },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const blockedSummary = msg.slice(0, 500);
    db.transitionCaseWorkItem?.(scanId, "surface_map", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "poc_build", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "blind_verify", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "consensus", "blocked", { summary: blockedSummary });
    db.failScan(scanId, msg);
    db.logEvent({
      scanId,
      stage: "report",
      eventType: "scan_error",
      payload: { error: msg },
      timestamp: Date.now(),
    });
    // Surface whatever cost we'd accrued before the throw — the catch
    // block sees `discoveryState` / `attackState` only when they were
    // hoisted to function scope. They aren't, so we settle for the
    // partial-findings flag count and skip cost.
    emitScanCompleted("failed", allFindings.length, {
      findingsForFlagCount: allFindings,
    });
    throw err;
  } finally {
    // Safety net: if none of the normal exit paths fired (e.g. a synchronous
    // exception bypassed the catch above, or a future refactor adds a new
    // return site), ensure the cloud relay still sees a terminal event.
    if (!emittedScanCompleted) {
      emitScanCompleted("failed", allFindings.length, {
        findingsForFlagCount: allFindings,
      });
    }
    db.close();
  }
}

// ── Shared state type for agent outputs ──

export interface AgentOutput {
  findings: Finding[];
  targetInfo: Partial<import("@pwnkit/shared").TargetInfo>;
  summary: string;
  turnCount: number;
  estimatedCostUsd: number;
  /**
   * Raw token-usage tally from the loop state. Surfaced separately
   * from `estimatedCostUsd` so the `scan_completed` event payload
   * can build per-(provider, model) cost splits via `splitCost()`
   * (pwnkit#231) instead of just emitting a fused dollar total.
   * Optional for back-compat with legacy CLI runtimes that don't
   * report tokens.
   */
  totalUsage?: {
    inputTokens: number;
    outputTokens: number;
    cachedInputTokens?: number;
  };
  /** True when this stage terminated because the cost ceiling was hit. */
  costCeilingExceeded?: boolean;
  /**
   * Set when the agent loop bailed because the planner LLM returned an
   * error (or empty response). Propagated up from `NativeAgentState.errorExit`
   * so the top-level scan can flip `exit_reason` from "completed" to "failed"
   * — the legacy `summary` field still carries the raw "Error: ..." marker
   * for back-compat with older readers.
   */
  errorExit?: { error: string; turn: number };
  /** Full conversation trace (messages) from the agent loop. */
  messages?: NativeMessage[];
}

// ── Native (Claude API) stage runners ──

/**
 * Per-scan cache of parsed scope policies (pwnkit#218 review). The first
 * helper that needs a policy parses the JSON file once; every subsequent
 * helper for the same `ScanConfig` reuses the same `ScopePolicy`
 * instance.
 *
 * Why a WeakMap instead of a plain `Map` keyed by path: callers can
 * construct multiple `ScanConfig`s pointing at the same scope file, and
 * we want each top-level `agenticScan()` call to see a consistent
 * snapshot — but we also don't want to leak parsed policies for the
 * lifetime of the process. Tying lifetime to the `ScanConfig` object
 * itself fixes both.
 *
 * Why this matters: without it, every stage helper called
 * `loadScope(config.scopeFile)` again, which is a TOCTOU window. If the
 * file changed mid-scan, later tool calls would run under a different
 * policy than the one that admitted `--target` at scan start.
 */
const scopePolicyCache = new WeakMap<ScanConfig, ScopePolicy>();

function resolveScopeForConfig(config: ScanConfig): ScopePolicy | undefined {
  const cached = scopePolicyCache.get(config);
  if (cached) return cached;
  // http_audit mode synthesises an in-memory host-allowlist ScopePolicy from
  // the env-bridge `httpAuditAllowedHosts` rather than reading a scope file.
  // This is the host half of the enforcement; the path half lives on the
  // EnforcementTracker's PathPolicy.
  if (config.mode === "http_audit") {
    const hosts = config.httpAuditAllowedHosts ?? [];
    const policy = ScopePolicy.fromJson({ in_scope: hosts });
    scopePolicyCache.set(config, policy);
    return policy;
  }
  if (!config.scopeFile) return undefined;
  const policy = loadScope(config.scopeFile);
  scopePolicyCache.set(config, policy);
  return policy;
}

/**
 * Resolve the attribution config (pwnkit#216) from a ScanConfig. Called
 * inline at every helper-function call site that constructs an
 * `AgentConfig`/`NativeAgentConfig`. Reuses the cached `ScopePolicy`
 * via `resolveScopeForConfig` so the scope file isn't reparsed.
 * Returns `undefined` when no source contributed anything.
 */
function buildAttributionForConfig(config: ScanConfig): AttributionConfig | undefined {
  const scope = resolveScopeForConfig(config);
  return resolveAttribution({
    scopeFileBlock: scope ? extractAttributionFromScopeJson(scope.raw) : undefined,
    env: process.env,
    cliHeaders: config.attributionHeaders,
    cliUaToken: config.attributionUaToken,
  });
}

async function runNativeDiscovery(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  emit: ScanListener,
  apiSpecPromptText?: string,
  getPendingUserMessages?: () => string[],
): Promise<AgentOutput> {
  // http_audit reuses the web-pentest prompts + tools wholesale; the only
  // additions are the env-driven scope/path/rate/kill enforcement layered on
  // via the EnforcementTracker. So it is "web" for every prompt/tool decision.
  const isWeb = config.mode === "web" || config.mode === "http_audit";
  // Multi-identity access-control testing (pwnkit#564): reconcile legacy
  // `auth` with `identities` and surface the access_control_probe guidance.
  const identities = resolveIdentities(config);
  const basePrompt = isWeb
    ? webPentestDiscoveryPrompt(config.target, config.auth) + buildAccessControlPromptBlock(identities)
    : discoveryPrompt(config.target, config.auth) + buildAccessControlPromptBlock(identities);
  let systemPrompt = apiSpecPromptText
    ? basePrompt + "\n\n" + apiSpecPromptText
    : basePrompt;
  const tools = isWeb
    ? getToolsForRole("discovery", { webMode: true, allowScanners: config.allowScanners })
    : getToolsForRole("discovery", { allowScanners: config.allowScanners });

  // NOTE: the deterministic web-recon pre-pass runs once on the COMMON discovery
  // path in agenticScan (so it covers both native and legacy/codex runtimes) —
  // not here. Its leads arrive via apiSpecPromptText, injected into systemPrompt above.

  const state = await runNativeAgentLoop({
    config: {
      role: "discovery",
      systemPrompt,
      tools,
      maxTurns: isWeb ? 12 : 8,
      target: config.target,
      scanId,
      sessionId: db.getSession(scanId, "discovery")?.id,
      authConfig: config.auth,
      identities,
      scope: resolveScopeForConfig(config),
      rateLimiter: getOrCreateRateLimiter(config),
      enforcement: resolveEnforcementForConfig(config),
      allowScanners: config.allowScanners,
      attribution: buildAttributionForConfig(config),
      engagement: resolveEngagementForConfig(config),
      costCeilingUsd: config.costCeilingUsd,
      costModel: config.model,
    },
    runtime,
    db,
    getPendingUserMessages,
    onEvent: (eventType, payload) => {
      if (eventType === "user:injected") {
        emit({ type: "user:injected", stage: "discovery", message: String(payload.text ?? ""), data: payload });
      }
    },
    onTurn: (turn, toolCalls) => {
      // One sub-action per tool call with a real preview of what the tool
      // was invoked with — e.g. `turn 3: bash: curl -sI https://t/admin`
      // instead of a useless `turn 3: bash`. Uses `stage:start` (not
      // `stage:end`) because the stage is still running; `stage:end` would
      // prematurely mark Discover as ✓ done every turn, which was the exact
      // bug we carried pre-0.7.7.
      if (toolCalls.length === 0) {
        emit({ type: "stage:start", stage: "discovery", message: `turn ${turn}: thinking` });
      } else {
        for (const call of toolCalls) {
          emit({
            type: "stage:start",
            stage: "discovery",
            message: `turn ${turn}: ${toolCallPreview(call)}`,
          });
        }
      }
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: state.estimatedCostUsd,
    totalUsage: state.totalUsage,
    errorExit: state.errorExit,
    messages: state.messages,
  };
}

async function runNativeAttack(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  targetInfo: Partial<import("@pwnkit/shared").TargetInfo>,
  categories: string[],
  maxTurns: number,
  emit: ScanListener,
  challengeHint?: string,
  apiSpecPromptText?: string,
  getPendingUserMessages?: () => string[],
): Promise<AgentOutput> {
  // http_audit reuses the web-pentest prompts + tools wholesale; the only
  // additions are the env-driven scope/path/rate/kill enforcement layered on
  // via the EnforcementTracker. So it is "web" for every prompt/tool decision.
  const isWeb = config.mode === "web" || config.mode === "http_audit";

  // Detect playwright availability for browser tool
  let hasBrowser = false;
  // @ts-ignore — playwright is an optional dependency
  try { await import("playwright"); hasBrowser = true; } catch { /* playwright not installed */ }

  // Shell-first for web targets: minimal tool set (bash + save_finding + done)
  // White-box mode: add read_file + run_command when source code path is provided
  const hasSource = !!config.repoPath;
  const identities = resolveIdentities(config);
  let basePrompt = isWeb
    ? shellPentestPrompt(config.target, config.repoPath, { hasBrowser, auth: config.auth })
    : attackPrompt(config.target, targetInfo, categories, config.auth);
  basePrompt += buildAccessControlPromptBlock(identities);
  // Inject API spec knowledge if available
  if (apiSpecPromptText) basePrompt += "\n\n" + apiSpecPromptText;

  // Pre-recon CVE check (white-box mode only). Walk the source tree,
  // run `npm audit` / `pip-audit` against any detected manifests, and
  // surface high/critical advisories as priority leads in the system
  // prompt. Defends against expensive thrash on CVE-tagged challenges
  // like XBEN-030 / XBEN-034 where the agent had source access but no
  // concrete leads and burned $6+ producing 0 findings.
  // Gated behind PWNKIT_FEATURE_PRE_RECON_CVE (default ON in white-box).
  let preReconBlock = "";
  if (hasSource && config.repoPath && features.preReconCve) {
    try {
      const { runPreReconCveCheck, formatPreReconForPrompt } = await import(
        "./pre-recon-cve.js"
      );
      const report = runPreReconCveCheck(config.repoPath);
      const formatted = formatPreReconForPrompt(report);
      if (formatted) {
        preReconBlock = "\n\n" + formatted;
        emit({
          type: "stage:end",
          stage: "discovery",
          message: `Pre-recon CVE check: ${report.advisories.length} high/critical advisor${report.advisories.length === 1 ? "y" : "ies"} across ${report.manifestsScanned.length} manifest${report.manifestsScanned.length === 1 ? "" : "s"} (${report.durationMs}ms)`,
        });
      }
    } catch (err) {
      // Pre-recon must never break the scan
      console.error(
        `[pre-recon-cve] failed: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // Phase-4 WordPress pre-recon. Runs three cheap probes against the
  // target; if WP is detected, invokes runWpFingerprint directly (not
  // via the agent loop) and folds the structured CVE leads into the
  // system prompt alongside the source-tree CVE block above. Gated by
  // the `wpFingerprint` feature flag so it stays off in runs where
  // network egress is not wanted. See GitHub issue #83.
  if (isWeb && features.wpFingerprint) {
    try {
      const { runPreReconWordPress, formatPreReconWordPressForPrompt } =
        await import("./pre-recon-cve.js");
      const wpReport = await runPreReconWordPress({
        target: config.target,
      });
      if (wpReport.isWordPress && wpReport.fingerprint) {
        const formatted = formatPreReconWordPressForPrompt(wpReport);
        if (formatted) {
          preReconBlock += "\n\n" + formatted;
          const pluginCount = wpReport.fingerprint.plugins.length;
          const cveCount = wpReport.fingerprint.findings.reduce(
            (sum, f) => sum + f.cves.length,
            0,
          );
          emit({
            type: "stage:end",
            stage: "discovery",
            message: `Pre-recon WordPress: ${pluginCount} plugin${pluginCount === 1 ? "" : "s"} enumerated, ${cveCount} CVE hit${cveCount === 1 ? "" : "s"} (${wpReport.durationMs}ms)`,
          });
        }
      }
    } catch (err) {
      console.error(
        `[pre-recon-wp] failed: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // Append challenge hint if provided (standard practice for XBOW benchmarks)
  const systemPrompt =
    (challengeHint ? basePrompt + "\n" + challengeHint : basePrompt) + preReconBlock;

  const shellToolNames = hasSource
    ? [
        "bash",
        ...(hasBrowser ? ["browser"] : []),
        "payload_lookup",
        ...(features.wpFingerprint ? ["wp_fingerprint"] : []),
        ...(features.mongoObjectIdForge ? ["mongo_objectid"] : []),
        ...(features.jitSkills ? ["list_skills", "load_skill"] : []),
        "read_file",
        "run_command",
        "spawn_agent",
        "save_finding",
        "done",
      ]
    : [
        "bash",
        ...(hasBrowser ? ["browser"] : []),
        "payload_lookup",
        ...(features.wpFingerprint ? ["wp_fingerprint"] : []),
        ...(features.mongoObjectIdForge ? ["mongo_objectid"] : []),
        ...(features.jitSkills ? ["list_skills", "load_skill"] : []),
        "spawn_agent",
        "save_finding",
        "done",
      ];
  const shellTools: import("./agent/types.js").ToolDefinition[] = shellToolNames
    .map((n) => TOOL_DEFINITIONS[n])
    .filter((t): t is import("./agent/types.js").ToolDefinition => t !== undefined);

  const tools = isWeb ? shellTools : getToolsForRole("attack", { hasBrowser, allowScanners: config.allowScanners });

  const effectiveMaxTurns = isWeb ? Math.max(maxTurns, 15) : maxTurns;

  const cloudSinkCfg = getCloudSinkConfig();
  const onTurnHandler = (turn: number, toolCalls: import("./agent/types.js").ToolCall[]) => {
    // One sub-action per tool call with a full preview (tool + first-order
    // argument) so the verbose TUI can show what the attack agent is
    // actually running on each turn — e.g. `turn 7: bash: nmap -sV t.com`
    // instead of `turn 7: bash`. Compact view still clips to last 3.
    if (toolCalls.length === 0) {
      emit({ type: "stage:start", stage: "attack", message: `turn ${turn}: thinking` });
    } else {
      for (const call of toolCalls) {
        emit({
          type: "stage:start",
          stage: "attack",
          message: `turn ${turn}: ${toolCallPreview(call)}`,
        });
      }
    }

    for (const call of toolCalls) {
      if (call.name === "save_finding") {
        emit({
          type: "finding",
          message: `[${call.arguments.severity}] ${call.arguments.title}`,
          data: call.arguments,
        });
        // Fire-and-forget: stream finding to opt-in webhook sink.
        // Failures are logged in postFinding and never abort the scan.
        void postFinding(call.arguments, cloudSinkCfg);
      }
    }
  };

  // First attempt: give the full budget. The loop's early-stop logic will
  // bail at 50% if no save_finding has been called (retryCount=0 enables this).
  const state = await runNativeAgentLoop({
    config: {
      role: "attack",
      systemPrompt,
      tools,
      maxTurns: effectiveMaxTurns,
      target: config.target,
      scanId,
      scopePath: config.repoPath,
      sessionId: db.getSession(scanId, "attack")?.id,
      retryCount: 0,
      authConfig: config.auth,
      identities,
      scope: resolveScopeForConfig(config),
      rateLimiter: getOrCreateRateLimiter(config),
      enforcement: resolveEnforcementForConfig(config),
      allowScanners: config.allowScanners,
      attribution: buildAttributionForConfig(config),
      engagement: resolveEngagementForConfig(config),
      costCeilingUsd: config.costCeilingUsd,
      costModel: config.model,
    },
    runtime,
    db,
    getPendingUserMessages,
    onEvent: (eventType, payload) => {
      if (eventType === "user:injected") {
        emit({ type: "user:injected", stage: "attack", message: String(payload.text ?? ""), data: payload });
      }
    },
    onTurn: onTurnHandler,
  });

  // ── Early-stop retry: if no findings by halfway, retry with a different strategy ──
  if (features.earlyStopRetry && state.earlyStopNoProgress) {
    const remainingBudget = effectiveMaxTurns - state.turnCount;

    emit({
      type: "stage:start",
      stage: "attack",
      message: `No findings after ${state.turnCount} turns — retrying with different strategy (${remainingBudget} turns remaining)...`,
    });

    db.logEvent?.({
      scanId,
      stage: "attack",
      eventType: "early_stop_retry",
      agentRole: "attack",
      payload: {
        firstAttemptTurns: state.turnCount,
        remainingBudget,
        attemptSummary: state.attemptSummary,
      },
      timestamp: Date.now(),
    });

    // Build structured progress handoff: prefer LLM-generated summary from
    // the agent loop (richer context, captures reasoning), fall back to regex
    // extraction if the LLM summary wasn't generated.
    let progressSection = "";
    if (features.progressHandoff) {
      if (state.progressSummary) {
        progressSection = `## Previous Attempt — Structured Progress\n\n${state.progressSummary}`;
      } else {
        progressSection = formatProgressHandoff(extractProgressFromAttempt(state.messages));
      }
    }

    const retrySystemPrompt = systemPrompt + `\n\n## RETRY — Previous Attempt Failed\n\nA previous attack attempt used ${state.turnCount} turns and found NOTHING.\n${state.attemptSummary}\n${progressSection}\nYou MUST try a COMPLETELY DIFFERENT approach:\n- Different entry points and endpoints\n- Different vulnerability classes (if SQLi failed, try SSTI/command injection/SSRF/path traversal)\n- Different tools and techniques (if curl failed, try Python scripts; if GET failed, try POST)\n- Different encoding and bypass techniques\n- Look for indirect/second-order vulnerabilities\n\nDo NOT repeat the same strategies. Be creative and aggressive.`;

    const retryState = await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: retrySystemPrompt,
        tools,
        maxTurns: remainingBudget,
        target: config.target,
        scanId,
        scopePath: config.repoPath,
        retryCount: 1,
        authConfig: config.auth,
        identities,
        scope: resolveScopeForConfig(config),
        rateLimiter: getOrCreateRateLimiter(config),
        enforcement: resolveEnforcementForConfig(config),
      allowScanners: config.allowScanners,
      attribution: buildAttributionForConfig(config),
      engagement: resolveEngagementForConfig(config),
        costCeilingUsd: config.costCeilingUsd,
        costModel: config.model,
      },
      runtime,
      db,
      getPendingUserMessages,
      onEvent: (eventType, payload) => {
        if (eventType === "user:injected") {
          emit({ type: "user:injected", stage: "attack", message: String(payload.text ?? ""), data: payload });
        }
      },
      onTurn: onTurnHandler,
    });

    // Merge results from both attempts
    const combinedFindings = [...state.findings, ...retryState.findings];
    const totalTurns = state.turnCount + retryState.turnCount;
    const combinedSummary = retryState.findings.length > 0
      ? retryState.summary
      : `First attempt (${state.turnCount} turns): no findings. Retry (${retryState.turnCount} turns): ${retryState.summary}`;

    return {
      findings: combinedFindings,
      targetInfo: { ...state.targetInfo, ...retryState.targetInfo },
      summary: combinedSummary,
      turnCount: totalTurns,
      estimatedCostUsd: state.estimatedCostUsd + retryState.estimatedCostUsd,
      // The native-loop's state.totalUsage today only carries
      // input/output (no cachedInputTokens). When the runtime starts
      // tracking cache reads (likely via a separate runtime-level
      // hook), this merge will need to fold that field in too.
      totalUsage: {
        inputTokens:
          (state.totalUsage?.inputTokens ?? 0) +
          (retryState.totalUsage?.inputTokens ?? 0),
        outputTokens:
          (state.totalUsage?.outputTokens ?? 0) +
          (retryState.totalUsage?.outputTokens ?? 0),
      },
      costCeilingExceeded: state.costCeilingExceeded || retryState.costCeilingExceeded,
      // If either attempt bailed on a planner error, surface the latest
      // one (retry takes precedence — it ran most recently).
      errorExit: retryState.errorExit ?? state.errorExit,
      messages: [...state.messages, ...retryState.messages],
    };
  }

  // First attempt completed normally (found something, or exhausted turns).
  // No retry needed.
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: state.estimatedCostUsd,
    totalUsage: state.totalUsage,
    costCeilingExceeded: state.costCeilingExceeded,
    errorExit: state.errorExit,
    messages: state.messages,
  };
}

// ── Progress Handoff: extract structured findings from a failed attempt's conversation ──

interface AttemptProgress {
  endpoints: string[];
  credentials: string[];
  technologies: string[];
  attacksTried: string[];
}

/**
 * Regex-extract structured progress from the first attempt's messages.
 * No LLM call — pure pattern matching on tool results.
 */
function extractProgressFromAttempt(messages: NativeMessage[]): AttemptProgress {
  const endpoints = new Set<string>();
  const credentials = new Set<string>();
  const technologies = new Set<string>();
  const attacksTried = new Set<string>();

  // Patterns
  const urlPattern = /https?:\/\/[^\s"'<>)\]}{,]+/g;
  const credPatterns = [
    /(?:login|username|user|email)[\s:="']+([^\s"'<>,;}{)(\]]{2,60})/gi,
    /(?:password|passwd|pass|pwd)[\s:="']+([^\s"'<>,;}{)(\]]{2,60})/gi,
    /(?:token|cookie|session[_-]?id|api[_-]?key|bearer|jwt|authorization)[\s:="']+([^\s"'<>,;}{)(\]]{2,80})/gi,
  ];
  const techPatterns = [
    /(?:server|x-powered-by|x-framework):\s*([^\r\n]+)/gi,
    /(?:express|flask|django|rails|spring|laravel|next\.?js|fastapi|gin|fiber|sinatra|koa)/gi,
    /(?:mysql|postgres(?:ql)?|sqlite|mongodb|redis|mariadb)/gi,
    /(?:php|python|ruby|node(?:\.?js)?|java|golang|go|rust|\.net)/gi,
  ];
  const curlPattern = /curl\s+[^\n]{10,}/g;

  for (const msg of messages) {
    for (const block of msg.content) {
      let text = "";
      if (block.type === "tool_result") {
        text = block.content;
      } else if (block.type === "text") {
        text = block.text;
      } else if (block.type === "tool_use") {
        // Extract curl commands from shell_exec / run_command arguments
        const input = block.input as Record<string, unknown>;
        const cmd = (input.command ?? input.cmd ?? "") as string;
        if (cmd) text = cmd;
        // Also capture the URL from http_request tool
        const url = (input.url ?? "") as string;
        if (url) endpoints.add(url);
      }

      if (!text) continue;

      // Extract URLs/endpoints
      for (const match of text.matchAll(urlPattern)) {
        const u = match[0].replace(/[.,;:!?)}\]]+$/, ""); // strip trailing punctuation
        if (u.length < 200) endpoints.add(u);
      }

      // Extract credentials
      for (const pattern of credPatterns) {
        for (const match of text.matchAll(pattern)) {
          const full = match[0].trim();
          if (full.length < 200) credentials.add(full);
        }
      }

      // Extract technologies
      for (const pattern of techPatterns) {
        for (const match of text.matchAll(pattern)) {
          const tech = (match[1] ?? match[0]).trim();
          if (tech.length < 100) technologies.add(tech);
        }
      }

      // Extract curl commands (as attacks tried)
      for (const match of text.matchAll(curlPattern)) {
        const cmd = match[0].trim();
        if (cmd.length < 300) attacksTried.add(cmd);
      }
    }
  }

  return {
    endpoints: [...endpoints].slice(0, 30),
    credentials: [...credentials].slice(0, 20),
    technologies: [...technologies].slice(0, 15),
    attacksTried: [...attacksTried].slice(0, 25),
  };
}

/** Format extracted progress into a section for the retry system prompt. */
function formatProgressHandoff(progress: AttemptProgress): string {
  const sections: string[] = ["## Previous Attempt Summary", ""];

  if (progress.endpoints.length > 0) {
    sections.push("### URLs/Endpoints Discovered");
    for (const ep of progress.endpoints) sections.push(`- ${ep}`);
    sections.push("");
  }

  if (progress.credentials.length > 0) {
    sections.push("### Credentials / Tokens Found");
    for (const c of progress.credentials) sections.push(`- ${c}`);
    sections.push("");
  }

  if (progress.technologies.length > 0) {
    sections.push("### Technologies Identified");
    for (const t of progress.technologies) sections.push(`- ${t}`);
    sections.push("");
  }

  if (progress.attacksTried.length > 0) {
    sections.push("### Attacks Already Tried (do NOT repeat these)");
    for (const a of progress.attacksTried) sections.push(`- \`${a}\``);
    sections.push("");
  }

  // Only return if we actually extracted something useful
  const hasContent = progress.endpoints.length > 0
    || progress.credentials.length > 0
    || progress.technologies.length > 0
    || progress.attacksTried.length > 0;

  return hasContent ? sections.join("\n") : "";
}

/** Format targetInfo from the discovery stage into a human-readable summary for the web attack prompt. */
function formatWebDiscoveryInfo(targetInfo: Partial<import("@pwnkit/shared").TargetInfo>): string {
  const parts: string[] = [];
  if (targetInfo.type) parts.push(`Type: ${targetInfo.type}`);
  if (targetInfo.model) parts.push(`Server/Framework: ${targetInfo.model}`);
  if (targetInfo.endpoints?.length) {
    parts.push(`Discovered endpoints:\n${targetInfo.endpoints.map((e) => `  - ${e}`).join("\n")}`);
  }
  if (targetInfo.detectedFeatures?.length) {
    parts.push(`Features: ${targetInfo.detectedFeatures.join(", ")}`);
  }
  if (targetInfo.systemPrompt) {
    parts.push(`Additional info: ${targetInfo.systemPrompt.slice(0, 1000)}`);
  }
  return parts.length > 0 ? parts.join("\n") : "No prior discovery information available. Start by crawling the target.";
}

/**
 * Per-finding verify budget. Reference: `pov-gate.ts:367 buildPovSystemPrompt`
 * runs one-finding-per-agent-session with a tight 5-turn cap; mirroring that
 * here ensures one runaway finding can't burn the whole verify pass.
 *
 * Background (from #285 — control-flow audit H2): the previous implementation
 * passed every finding into a single `runNativeAgentLoop` with
 * `maxTurns: Math.min(findings.length * 3, 15)`. With ≥6 findings the model
 * silently skipped, deduped, or condensed, producing under-coverage that's
 * invisible in benchmarks.
 */
const VERIFY_TURNS_PER_FINDING = 5;

export async function runNativeVerify(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  findings: Finding[],
  emit: ScanListener,
): Promise<void> {
  // Per-finding verify loop (#285). One agent session per finding so each
  // gets its own turn budget — N findings → N runtime calls, never a shared
  // pool the model can starve from.
  for (const finding of findings) {
    await runNativeAgentLoop({
      config: {
        role: "verify",
        systemPrompt: verifyPromptSingleFinding(config.target, finding, config.auth),
        tools: getToolsForRole("verify", { hasScope: !!config.repoPath, allowScanners: config.allowScanners }),
        maxTurns: VERIFY_TURNS_PER_FINDING,
        target: config.target,
        scanId,
        sessionId: db?.getSession?.(scanId, "verify")?.id,
        authConfig: config.auth,
        identities: resolveIdentities(config),
        scope: resolveScopeForConfig(config),
        rateLimiter: getOrCreateRateLimiter(config),
        enforcement: resolveEnforcementForConfig(config),
        allowScanners: config.allowScanners,
        attribution: buildAttributionForConfig(config),
        engagement: resolveEngagementForConfig(config),
        costCeilingUsd: config.costCeilingUsd,
        costModel: config.model,
      },
      runtime,
      db,
      onTurn: (turn, toolCalls) => {
        // One sub-action per tool call with a full preview, matching the
        // discovery and attack handlers. Without this the verify stage is
        // completely silent in the TUI, even under verbose mode.
        if (toolCalls.length === 0) {
          emit({
            type: "stage:start",
            stage: "verify",
            message: `[${finding.id}] turn ${turn}: thinking`,
          });
        } else {
          for (const call of toolCalls) {
            emit({
              type: "stage:start",
              stage: "verify",
              message: `[${finding.id}] turn ${turn}: ${toolCallPreview(call)}`,
            });
          }
        }
      },
    });
  }
}

// ── Legacy (text-based) stage runners ──

async function runLegacyDiscovery(
  runtime: import("./runtime/types.js").Runtime,
  db: any,
  config: ScanConfig,
  scanId: string,
  emit: ScanListener,
  dbPath?: string,
  apiSpecPromptText?: string,
): Promise<AgentOutput> {
  // http_audit reuses the web-pentest prompts + tools wholesale; the only
  // additions are the env-driven scope/path/rate/kill enforcement layered on
  // via the EnforcementTracker. So it is "web" for every prompt/tool decision.
  const isWeb = config.mode === "web" || config.mode === "http_audit";
  const identities = resolveIdentities(config);
  const basePrompt =
    (isWeb
      ? webPentestDiscoveryPrompt(config.target, config.auth)
      : discoveryPrompt(config.target, config.auth)) + buildAccessControlPromptBlock(identities);
  const systemPrompt = apiSpecPromptText
    ? basePrompt + "\n\n" + apiSpecPromptText
    : basePrompt;
  const tools = isWeb
    ? getToolsForRole("discovery", { webMode: true, allowScanners: config.allowScanners })
    : getToolsForRole("discovery", { allowScanners: config.allowScanners });

  const state = await runAgentLoop({
    config: {
      role: "discovery",
      systemPrompt,
      tools,
      maxTurns: isWeb ? 12 : 8,
      target: config.target,
      scanId,
      sessionId: db?.getSession(scanId, "discovery")?.id,
      attachTargetToolsMcp: true,
      dbPath,
      authConfig: config.auth,
      identities,
      scope: resolveScopeForConfig(config),
      rateLimiter: getOrCreateRateLimiter(config),
      enforcement: resolveEnforcementForConfig(config),
      allowScanners: config.allowScanners,
      attribution: buildAttributionForConfig(config),
      engagement: resolveEngagementForConfig(config),
      dispatchMode: config.dispatchMode,
      modelHint: config.model,
    },
    runtime,
    db,
    onTurn: (turn, msg) => {
      // Sub-action while the stage is still running — must be `stage:start`,
      // not `stage:end`, or the UI marks Discover as ✓ done every turn.
      const preview = msg.content.replace(/\s+/g, " ").trim().slice(0, 100);
      emit({
        type: "stage:start",
        stage: "discovery",
        message: `turn ${turn}: ${preview}`,
      });
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: 0, // Legacy runtime does not track token usage
  };
}

async function runLegacyAttack(
  runtime: import("./runtime/types.js").Runtime,
  db: any,
  config: ScanConfig,
  scanId: string,
  targetInfo: Partial<import("@pwnkit/shared").TargetInfo>,
  categories: string[],
  maxTurns: number,
  emit: ScanListener,
  dbPath?: string,
  apiSpecPromptText?: string,
): Promise<AgentOutput> {
  // http_audit reuses the web-pentest prompts + tools wholesale; the only
  // additions are the env-driven scope/path/rate/kill enforcement layered on
  // via the EnforcementTracker. So it is "web" for every prompt/tool decision.
  const isWeb = config.mode === "web" || config.mode === "http_audit";

  // Detect playwright availability for browser tool (mirrors native path)
  let hasBrowser = false;
  // @ts-ignore — playwright is an optional dependency
  try { await import("playwright"); hasBrowser = true; } catch { /* playwright not installed */ }

  const identities = resolveIdentities(config);
  let baseAttackPrompt = isWeb
    ? webPentestAttackPrompt(config.target, formatWebDiscoveryInfo(targetInfo), config.auth)
    : attackPrompt(config.target, targetInfo, categories, config.auth);
  baseAttackPrompt += buildAccessControlPromptBlock(identities);
  if (apiSpecPromptText) baseAttackPrompt += "\n\n" + apiSpecPromptText;
  const systemPrompt = baseAttackPrompt;
  const tools = isWeb
    ? getToolsForRole("attack", { webMode: true, hasBrowser, allowScanners: config.allowScanners })
    : getToolsForRole("attack", { hasBrowser, allowScanners: config.allowScanners });

  const state = await runAgentLoop({
    config: {
      role: "attack",
      systemPrompt,
      tools,
      maxTurns: isWeb ? Math.max(maxTurns, 25) : maxTurns,
      target: config.target,
      scanId,
      sessionId: db?.getSession(scanId, "attack")?.id,
      attachTargetToolsMcp: true,
      dbPath,
      identities,
      authConfig: config.auth,
      scope: resolveScopeForConfig(config),
      rateLimiter: getOrCreateRateLimiter(config),
      enforcement: resolveEnforcementForConfig(config),
      allowScanners: config.allowScanners,
      attribution: buildAttributionForConfig(config),
      engagement: resolveEngagementForConfig(config),
      dispatchMode: config.dispatchMode,
      modelHint: config.model,
    },
    runtime,
    db,
    onTurn: (turn, msg) => {
      const calls = msg.toolCalls ?? [];
      // One sub-action per tool call with a full preview (tool + first-
      // order argument), same as the native-API path. Previously this
      // handler only emitted finding events; the verbose TUI showed an
      // empty actions list between finding discoveries.
      if (calls.length === 0) {
        emit({ type: "stage:start", stage: "attack", message: `turn ${turn}: thinking` });
      } else {
        for (const call of calls) {
          emit({
            type: "stage:start",
            stage: "attack",
            message: `turn ${turn}: ${toolCallPreview(call)}`,
          });
        }
      }

      const cloudSinkCfg = getCloudSinkConfig();
      for (const call of calls) {
        if (call.name === "save_finding") {
          emit({
            type: "finding",
            message: `[${call.arguments.severity}] ${call.arguments.title}`,
            data: call.arguments,
          });
          void postFinding(call.arguments, cloudSinkCfg);
        }
      }
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: 0, // Legacy runtime does not track token usage
  };
}

async function runLegacyVerify(
  runtime: import("./runtime/types.js").Runtime,
  db: any,
  config: ScanConfig,
  scanId: string,
  findings: Finding[],
  _emit: ScanListener,
  dbPath?: string,
): Promise<void> {
  await runAgentLoop({
    config: {
      role: "verify",
      systemPrompt: verifyPrompt(config.target, findings, config.auth),
      tools: getToolsForRole("verify", { hasScope: !!config.repoPath, allowScanners: config.allowScanners }),
      maxTurns: Math.min(findings.length * 3, 15),
      target: config.target,
      scanId,
      sessionId: db?.getSession(scanId, "verify")?.id,
      attachTargetToolsMcp: true,
      dbPath,
      authConfig: config.auth,
      identities: resolveIdentities(config),
      scope: resolveScopeForConfig(config),
      rateLimiter: getOrCreateRateLimiter(config),
      enforcement: resolveEnforcementForConfig(config),
      allowScanners: config.allowScanners,
      attribution: buildAttributionForConfig(config),
      engagement: resolveEngagementForConfig(config),
      dispatchMode: config.dispatchMode,
      modelHint: config.model,
    },
    runtime,
    db,
  });
}

// ── Helper: convert DB finding row to Finding type ──

function dbFindingToFinding(dbf: {
  id: string;
  templateId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  confidence: number | null;
  cvssVector: string | null;
  cvssScore: number | null;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis: string | null;
  pocSteps?: string | null;
  layerVerdicts?: string | null;
  timestamp: number;
}): Finding {
  let layerVerdicts: LayerVerdict[] | undefined;
  if (dbf.layerVerdicts) {
    try {
      // Validated parse: zod enforces the LayerVerdict shape so a corrupt or
      // legacy DB row can't silently leak a malformed verdict into the
      // hydrated Finding (which would surface as a deep TypeError when the
      // dashboard / dynamic-routing model touches verdict.changedSeverity
      // or verdict.confidence). Schema `.passthrough()`s unknown fields so
      // newer telemetry columns keep round-tripping.
      const parsed: unknown = JSON.parse(dbf.layerVerdicts);
      const validated = layerVerdictArraySchema.parse(parsed);
      if (validated.length > 0) layerVerdicts = validated as LayerVerdict[];
    } catch (err) {
      // Corrupt or legacy row — drop the field rather than crashing the
      // hydration. The triage stage will repopulate on the next scan.
      if (err instanceof z.ZodError) {
        console.warn(
          `[agentic-scanner] dropping layerVerdicts for finding ${dbf.id}: ${formatZodError(err, "layerVerdicts")}`,
        );
      } else if (err instanceof SyntaxError) {
        console.warn(
          `[agentic-scanner] dropping layerVerdicts for finding ${dbf.id}: invalid JSON (${err.message})`,
        );
      }
    }
  }
  let pocSteps: PocStep[] | undefined;
  if (dbf.pocSteps) {
    try {
      const parsed = JSON.parse(dbf.pocSteps) as unknown;
      // Validate each element via the same predicate the agent tool path uses,
      // so a half-corrupt array degrades to "drop bad steps" rather than
      // letting malformed rows escape into Finding.pocSteps.
      const valid = parsePocStepsArg(parsed);
      if (valid && valid.length > 0) {
        pocSteps = valid;
      }
    } catch {
      // Corrupt or legacy row — drop the field rather than crashing
      // hydration. The agent loop is free to repopulate on a future scan.
    }
  }
  return {
    id: dbf.id,
    templateId: dbf.templateId,
    title: dbf.title,
    description: dbf.description,
    severity: dbf.severity as Finding["severity"],
    category: dbf.category as Finding["category"],
    status: dbf.status as Finding["status"],
    confidence: dbf.confidence ?? undefined,
    cvssVector: dbf.cvssVector ?? undefined,
    cvssScore: dbf.cvssScore ?? undefined,
    evidence: {
      request: dbf.evidenceRequest,
      response: dbf.evidenceResponse,
      analysis: dbf.evidenceAnalysis ?? undefined,
    },
    ...(pocSteps ? { pocSteps } : {}),
    ...(layerVerdicts ? { layerVerdicts } : {}),
    ...(pocSteps ? { pocSteps } : {}),
    timestamp: dbf.timestamp,
  };
}
