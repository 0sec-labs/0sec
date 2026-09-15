/**
 * Self-securing software lifecycle: prepare → investigate → repair → deliver.
 *
 * Orchestrates a full managed lifecycle for a software project:
 * 1. **Prepare** — clone/pin source to a clean checkout outside the user's repo
 * 2. **Investigate** — discover actual findings via the existing analysis pipeline
 * 3. **Repair** — for each finding, delegate to `runBehavioralRepair` bounded by
 *    maxFindings / maxAttempts / maxTurns / timeout and a cooperative cost ceiling
 * 4. **Deliver** — retain patch/evidence artifacts; optionally publish VERIFIED
 *    repair patches as GitHub PRs via deterministic branches
 *
 * State is persisted atomically in `stateDir`, supporting resume with revision and
 * config identity checks.  An exclusive file lock prevents competing runs.
 *
 * ## Cost ceiling
 *
 * When `costCeilingUsd` is set it is passed to the investigation pipeline for
 * its own internal cooperative ceiling.  Repair-phase cost accounting depends
 * on the runtime surfacing token usage in `NativeRuntimeResult.usage`.  If a
 * runtime does not surface usage the ceiling is a no-op for the repair phase.
 * No fabricated cost estimates are produced.
 *
 * ## Runtime support
 *
 * Supports `api` (LlmApiRuntime) and `auto` (detect available runtimes).
 * Other modes (`claude`, `codex`, `gemini`, `ollama`) are not yet wired
 * through the secure lifecycle integration path — they require per-mode
 * NativeRuntime construction and validation.
 *
 * ## Resume rules
 *
 * - `resume=true` with no saved state → error (blocked).
 * - `resume=true` with completed or cancelled state → error (blocked); a
 *   cancelled run is never silently continued — start a fresh run.
 * - `resume=true` with mismatched config identity or revision → error (blocked).
 *   The identity is recomputed from the CURRENT options and compared against
 *   the identity persisted by the original run.
 * - `resume=true` on a run that ENDED blocked/failed → the repair phase is
 *   retried for the selected findings (previously blocked ones included);
 *   findings omitted by maxFindings stay blocked.
 * - `resume` unset with existing state → fresh run (lock prevents concurrent use).
 *
 * ## Cancellation
 *
 * The workflow deadline and the operator's signal abort the REPAIR phase
 * cooperatively (in-flight probes/tests are interrupted, state is persisted,
 * final status is `cancelled`). KNOWN LIMITATION: the investigation pipeline
 * (`runPipeline`) does not accept an AbortSignal — a SIGINT/deadline during
 * investigation only takes effect once the pipeline returns; it is bounded
 * solely by `timeoutMs` forwarded as the pipeline timeout.
 */

import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import type { Finding, ScanDepth, TokenUsageForPricing } from "@0sec/shared";
import type { PipelineOptions } from "../unified-pipeline.js";
import { runPipeline } from "../unified-pipeline.js";
import { cloneGitRepo, parseRepoRef } from "../repo-clone.js";
import { ScanCostLedger } from "../agent/cost-ledger.js";
import type { NativeRuntime, NativeRuntimeResult, NativeMessage, NativeToolDef, NativeStreamCallbacks, RuntimeType } from "../runtime/types.js";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import { detectAvailableRuntimes } from "../runtime/registry.js";
import type {
  SecureProjectOptions,
  SecureProjectResult,
  SecurePhase,
  SecureEvent,
  BehavioralRepairOptions,
  BehavioralRepairResult,
} from "./types.js";
import { runBehavioralRepair } from "./behavioral-repair.js";
import { ProjectLock, LockHeldError } from "./project-lock.js";
import {
  type SecureProjectState,
  type IdentityFields,
  createInitialState,
  computeConfigIdentity,
  readState,
  writeState,
  advanceState,
  addError,
  checkResumeCompatibility,
  resolveRepoRevision,
  resumePhase,
} from "./project-state.js";

// ── Defaults ────────────────────────────────────────────────────────────────

const MAX_FINDINGS_DEFAULT = 10;
const MAX_ATTEMPTS_DEFAULT = 3;
const MAX_TURNS_DEFAULT = 25;
const TIMEOUT_MS_DEFAULT = 600_000; // 10 min total workflow

// ── Managed-checkout directory ──────────────────────────────────────────────

function managedCheckoutDir(stateDir: string): string {
  return join(stateDir, "checkout");
}

// ── Sanitize finding id for file paths ──────────────────────────────────────

function safeFindingDir(findingId: string): string {
  return createHash("sha256").update(findingId).digest("hex").slice(0, 16);
}

// ── Cost-tracking runtime wrapper ──────────────────────────────────────────

/**
 * Wraps a NativeRuntime to intercept `executeNative` results and feed token
 * usage into a ScanCostLedger.  All other methods delegate directly.
 * Usage is only recorded when the result carries a `usage` object (runtimes
 * that don't surface usage leave the ledger untouched).
 */
class CostTrackingRuntime implements NativeRuntime {
  readonly type: RuntimeType;

  constructor(
    private readonly inner: NativeRuntime,
    private readonly ledger: ScanCostLedger,
  ) {
    this.type = inner.type;
  }

  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
    callbacks?: NativeStreamCallbacks,
    signal?: AbortSignal,
  ): Promise<NativeRuntimeResult> {
    const result = await this.inner.executeNative(system, messages, tools, callbacks, signal);
    if (result.usage) {
      this.ledger.add(result.usage as TokenUsageForPricing, this.inner.resolvedModel?.());
    }
    return result;
  }

  isAvailable(): Promise<boolean> { return this.inner.isAvailable(); }
  forkForSubagent?(timeoutMs: number, selection?: Parameters<Exclude<NativeRuntime["forkForSubagent"], undefined>>[1]): Promise<NativeRuntime> {
    return this.inner.forkForSubagent!(timeoutMs, selection);
  }
  accessibleModels?(): string[] { return this.inner.accessibleModels?.() ?? []; }
  reconfigure?(sel: Parameters<Exclude<NativeRuntime["reconfigure"], undefined>>[0]): void {
    this.inner.reconfigure?.(sel);
  }
  resolvedModel?(): string { return this.inner.resolvedModel?.() ?? "unknown"; }
}

// ── Runtime resolution ──────────────────────────────────────────────────────

/**
 * Resolve the given RuntimeMode to a NativeRuntime instance.
 *
 * Only `api` and `auto` are supported for the secure lifecycle.  For `api`
 * the caller MUST provide an API key (via options, env, or cloud injection).
 * Returns `{ runtime, blockedReason }` — when the mode is unsupported,
 * `runtime` is null and `blockedReason` explains why.
 */
async function resolveNativeRuntime(
  mode: "api" | "auto" | undefined,
  timeoutMs: number,
  apiKey?: string,
  model?: string,
): Promise<{ runtime: NativeRuntime | null; blockedReason?: string }> {
  const rt = mode ?? "auto";

  if (rt === "api") {
    const key = apiKey ??
      process.env["ANTHROPIC_API_KEY"] ??
      process.env["OPENAI_API_KEY"] ??
      process.env["0SEC_API_KEY"];
    return {
      runtime: new LlmApiRuntime({
        type: "api",
        timeout: timeoutMs,
        apiKey: key,
        model,
      }),
    };
  }

  if (rt === "auto") {
    const available = await detectAvailableRuntimes();
    if (available.has("api")) {
      const key = apiKey ??
        process.env["ANTHROPIC_API_KEY"] ??
        process.env["OPENAI_API_KEY"] ??
        process.env["0SEC_API_KEY"];
      return {
        runtime: new LlmApiRuntime({
          type: "api",
          timeout: timeoutMs,
          apiKey: key,
          model,
        }),
      };
    }
    return {
      runtime: null,
      blockedReason:
        "No API credentials available (set ANTHROPIC_API_KEY, OPENAI_API_KEY, or 0SEC_API_KEY). " +
        "CLI-native runtimes (claude/codex/gemini/ollama) are not yet wired through the secure lifecycle path.",
    };
  }

  return {
    runtime: null,
    blockedReason: `Unsupported runtime mode: ${rt}. Only "api" and "auto" are supported for the secure lifecycle.`,
  };
}

// ── Source resolution ───────────────────────────────────────────────────────

interface ResolvedSource {
  checkoutPath: string;
  revision: string;
}

function prepareSource(source: string, stateDir: string): ResolvedSource {
  const checkout = managedCheckoutDir(stateDir);

  if (/^https?:\/\//.test(source) || /^git@/.test(source)) {
    mkdirSync(stateDir, { recursive: true });
    cloneGitRepo(source, checkout);
    const { ref } = parseRepoRef(source);
    if (ref) {
      execFileSync("git", ["checkout", ref], {
        cwd: checkout,
        timeout: 30_000,
        stdio: "pipe",
      });
    }
    return { checkoutPath: checkout, revision: resolveRepoRevision(checkout) };
  }

  // Local path.
  const sourcePath = isAbsolute(source) ? source : resolve(process.cwd(), source);
  if (!existsSync(sourcePath)) {
    throw new Error(`Source path does not exist: ${sourcePath}`);
  }
  execFileSync("git", ["rev-parse", "--git-dir"], {
    cwd: sourcePath,
    timeout: 10_000,
    stdio: "pipe",
  });
  mkdirSync(stateDir, { recursive: true });
  execFileSync("git", ["clone", "--depth", "1", `file://${sourcePath}`, checkout], {
    timeout: 120_000,
    stdio: "pipe",
  });
  return { checkoutPath: checkout, revision: resolveRepoRevision(checkout) };
}

// ── Investigation via pipeline ──────────────────────────────────────────────

interface InvestigationResult {
  findings: Finding[];
  costCeilingExceeded: boolean;
  researchFailed: boolean;
  error: string | null;
}

async function investigateSource(
  checkoutPath: string,
  depth: ScanDepth | undefined,
  costCeilingUsd: number | undefined,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<InvestigationResult> {
  const opts: PipelineOptions = {
    target: checkoutPath,
    targetType: "source-code",
    depth: depth ?? "default",
    format: "json",
    timeout: timeoutMs,
  };

  // Forward cost ceiling so the pipeline can self-limit during investigation.
  if (costCeilingUsd != null && costCeilingUsd > 0) {
    opts.costCeilingUsd = costCeilingUsd;
  }

  let report;
  try {
    report = await runPipeline(opts);
  } catch (err) {
    return {
      findings: [],
      costCeilingExceeded: false,
      researchFailed: true,
      error: `Investigation pipeline error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (signal?.aborted) {
    return {
      findings: report.findings ?? [],
      costCeilingExceeded: false,
      researchFailed: true,
      error: "Investigation cancelled by signal.",
    };
  }

  return {
    findings: report.findings ?? [],
    costCeilingExceeded: report.costCeilingExceeded === true,
    researchFailed: report.researchFailed === true,
    error: report.researchFailed ? "Pipeline research failed — findings may be partial." : null,
  };
}

// ── PR publication ──────────────────────────────────────────────────────────

interface PublishedPullRequest {
  findingId: string;
  branch: string;
  url: string;
}

async function publishRepairPatches(
  checkoutPath: string,
  repairs: Record<string, BehavioralRepairResult>,
  findings: Finding[],
  revision: string,
  signal?: AbortSignal,
): Promise<{ prs: PublishedPullRequest[]; errors: string[] }> {
  const result: PublishedPullRequest[] = [];
  const errors: string[] = [];

  try {
    execFileSync("gh", ["auth", "status"], { timeout: 10_000, stdio: "pipe" });
  } catch {
    errors.push("gh CLI not available or not authenticated — skipping PR publication.");
    return { prs: result, errors };
  }

  let remoteUrl: string;
  try {
    remoteUrl = execFileSync("git", ["remote", "get-url", "origin"], {
      cwd: checkoutPath,
      timeout: 10_000,
      stdio: "pipe",
      encoding: "utf-8",
    }).trim();
  } catch {
    errors.push("No git remote 'origin' configured — cannot publish PRs.");
    return { prs: result, errors };
  }

  const repoSlash = remoteUrl
    .replace(/^git@[^:]+:/, "")
    .replace(/^https?:\/\/[^/]+\//, "")
    .replace(/\.git$/, "");

  for (const finding of findings) {
    if (signal?.aborted) break;

    const repair = repairs[finding.id];
    if (!repair || repair.status !== "verified") continue;

    const patchPath = repair.patchPath;
    if (!patchPath || !existsSync(patchPath)) {
      errors.push(`Finding ${finding.id}: no patch file at ${patchPath}, skipping PR.`);
      continue;
    }

    if (repair.patchSha256) {
      const actual = createHash("sha256").update(readFileSync(patchPath)).digest("hex");
      if (actual !== repair.patchSha256) {
        errors.push(
          `Finding ${finding.id}: patch SHA256 mismatch (expected ${repair.patchSha256}, got ${actual}), skipping PR.`,
        );
        continue;
      }
    }

    const branch = `0sec/repair/${safeFindingDir(finding.id)}`;

    // Dedup: check for existing open PR with this head branch.
    try {
      const existingPrs = execFileSync(
        "gh",
        ["pr", "list", "--head", branch, "--state", "open", "--json", "url"],
        { cwd: checkoutPath, timeout: 15_000, stdio: "pipe", encoding: "utf-8" },
      );
      const parsed = JSON.parse(existingPrs);
      if (Array.isArray(parsed) && parsed.length > 0) {
        result.push({ findingId: finding.id, branch, url: parsed[0].url });
        continue;
      }
    } catch {
      // gh failed — try creating.
    }

    try {
      execFileSync("git", ["checkout", revision], {
        cwd: checkoutPath, timeout: 15_000, stdio: "pipe",
      });
      execFileSync("git", ["checkout", "-b", branch], {
        cwd: checkoutPath, timeout: 10_000, stdio: "pipe",
      });
      execFileSync("git", ["apply", patchPath], {
        cwd: checkoutPath, timeout: 15_000, stdio: "pipe",
      });
      execFileSync("git", ["add", "-A"], {
        cwd: checkoutPath, timeout: 10_000, stdio: "pipe",
      });
      execFileSync(
        "git",
        [
          "commit", "-m",
          `fix: ${finding.title}\n\nAutomated repair by 0sec secure lifecycle.`,
          "--no-verify",
        ],
        { cwd: checkoutPath, timeout: 15_000, stdio: "pipe" },
      );
      execFileSync("git", ["push", "origin", branch], {
        cwd: checkoutPath, timeout: 30_000, stdio: "pipe",
      });

      const prOutput = execFileSync(
        "gh",
        [
          "pr", "create",
          "--base", "main",
          "--head", branch,
          "--title", `fix: ${finding.title}`,
          "--body",
          [
            "Automated security repair by 0sec secure lifecycle.",
            "",
            `Finding: ${finding.id}`,
            `Severity: ${finding.severity}`,
            "",
            `**Verification**: ${repair.verification?.detail ?? "Verified via behavioral probe."}`,
            "",
            "This PR was automatically generated. Review before merging.",
          ].join("\n"),
          "--repo", repoSlash,
        ],
        { cwd: checkoutPath, timeout: 30_000, stdio: "pipe", encoding: "utf-8" },
      );

      result.push({ findingId: finding.id, branch, url: prOutput.trim() });

      // Restore checkout to clean state.
      execFileSync("git", ["checkout", revision], {
        cwd: checkoutPath, timeout: 10_000, stdio: "pipe",
      });
      execFileSync("git", ["branch", "-D", branch], {
        cwd: checkoutPath, timeout: 10_000, stdio: "pipe",
      });
    } catch (err) {
      errors.push(
        `Finding ${finding.id}: PR publication failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      try {
        execFileSync("git", ["checkout", revision], {
          cwd: checkoutPath, timeout: 10_000, stdio: "pipe",
        });
      } catch { /* best-effort recovery */ }
    }
  }

  return { prs: result, errors };
}

// ── Event helper ────────────────────────────────────────────────────────────

function makeEvent(
  phase: SecurePhase,
  message: string,
  findingId?: string,
): SecureEvent {
  return {
    type: "secure:phase",
    phase,
    message,
    ...(findingId ? { findingId } : {}),
  };
}

// ── Finding sort ────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function severityRank(a: Finding, b: Finding): number {
  return (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
}

// ── Main entry point ────────────────────────────────────────────────────────

/**
 * Run the complete secure project lifecycle.
 *
 * Orchestrates prepare → investigate → repair (reproduce/repair/test/verify) →
 * deliver.  State is persisted atomically to `stateDir` after each phase,
 * supporting resume with revision/config identity checks.
 */
export async function runSecureProject(
  options: SecureProjectOptions,
): Promise<SecureProjectResult> {
  const {
    repoRoot,
    stateDir,
    testCommand,
    setupCommand,
    model,
    apiKey,
    runtime: runtimeMode,
    depth,
    maxFindings: maxFindingsOpt,
    maxAttempts: maxAttemptsOpt,
    maxTurns: maxTurnsOpt,
    timeoutMs: timeoutMsOpt,
    costCeilingUsd,
    resume,
    publish,
    signal,
    onEvent,
  } = options;

  const runId = randomUUID();

  // Only "api" and "auto" are wired through the secure lifecycle; reject any
  // other RuntimeMode up front (also narrows the type for resolveNativeRuntime).
  if (runtimeMode !== undefined && runtimeMode !== "api" && runtimeMode !== "auto") {
    return resultFromPhase(runId, repoRoot, "prepare", "blocked", [
      `Unsupported runtime mode: ${runtimeMode}. Only "api" and "auto" are supported for the secure lifecycle.`,
    ]);
  }
  const maxFindings = maxFindingsOpt ?? MAX_FINDINGS_DEFAULT;
  const maxAttempts = maxAttemptsOpt ?? MAX_ATTEMPTS_DEFAULT;
  const maxTurns = maxTurnsOpt ?? MAX_TURNS_DEFAULT;
  const workflowTimeoutMs = timeoutMsOpt ?? TIMEOUT_MS_DEFAULT;
  const perFindingTimeout = Math.max(
    30_000,
    Math.floor(workflowTimeoutMs / Math.max(maxFindings, 1) / 2),
  );

  function emit(event: SecureEvent): void {
    onEvent?.(event);
  }

  // ── Workflow deadline ─────────────────────────────────────────────────
  // A single AbortController that fires when the entire lifecycle must stop.
  // Linked to the caller's signal so either triggers abort.
  const deadlineController = new AbortController();
  const deadlineTimer = setTimeout(() => deadlineController.abort(new Error("Workflow deadline exceeded")), workflowTimeoutMs);
  const combinedSignal = signal
    ? combineAbortSignals(signal, deadlineController.signal)
    : deadlineController.signal;

  // Clean up deadline timer when the workflow finishes (in finally block).
  let finished = false;

  // ── Lock & state dir ──────────────────────────────────────────────────

  mkdirSync(stateDir, { recursive: true });
  const lock = new ProjectLock(stateDir);

  try {
    // Acquire lock. Both fresh and resume runs refuse to clobber a lock held
    // by a LIVE process; clearStale only removes locks whose holder is dead.
    if (lock.isHeld()) {
      return resultFromPhase(
        runId, repoRoot, "prepare", "blocked",
        [
          resume
            ? "Another secure lifecycle process is still running. Cannot resume while locked."
            : "Another secure lifecycle process is still running. Wait for it or clear the lock after confirming the holder is dead.",
        ],
      );
    }
    lock.clearStale();
    lock.acquire();

    // ── State initialization / resume ───────────────────────────────────

    let state: SecureProjectState;
    let skipRepairIds: string[] = [];
    let skipBlockedIds: string[] = [];

    if (resume) {
      const saved = readState(stateDir);
      if (!saved) {
        throw new BlockedError("No saved state to resume. Start a fresh run without --resume.");
      }
      if (saved.status === "completed") {
        throw new BlockedError(
          `Run ${saved.runId} already completed at ${saved.completedAt}. Start a fresh run to re-run.`,
        );
      }

      // Resolve current revision for identity check.
      let currentRevision = "";
      try {
        currentRevision = existsSync(managedCheckoutDir(stateDir))
          ? resolveRepoRevision(managedCheckoutDir(stateDir))
          : resolveRepoRevision(repoRoot);
      } catch {
        throw new BlockedError("Cannot resolve current git revision for resume identity check.");
      }

      // Recompute the config identity from the CURRENT options and compare
      // against the identity persisted by the original run. The previous
      // implementation read config fields off the saved state — fields the
      // state never stored — so every value fell back to the current options
      // and the mismatch check was vacuous.
      const configFields: IdentityFields = {
        source: repoRoot,
        testCommand,
        setupCommand,
        runtime: runtimeMode,
        maxFindings,
        maxAttempts,
        maxTurns,
        depth: depth ?? "default",
      };
      const configIdentity = computeConfigIdentity(configFields);

      const incompatibility = checkResumeCompatibility(saved, configIdentity, currentRevision);
      if (incompatibility) {
        throw new BlockedError(incompatibility);
      }

      state = saved;
      const resumed = resumePhase(state);

      // A run that ENDED blocked/failed retries its selected findings: the
      // blocked markers for findings in the selected set are cleared so the
      // repair loop attempts them again. Findings omitted by maxFindings are
      // not in the selected set and stay blocked.
      if (
        resumed.phase === "reproduce" &&
        saved.phase === "complete" &&
        (saved.status === "blocked" || saved.status === "failed")
      ) {
        const selectedIds = new Set(state.findings.map((f) => f.id));
        state.blockedFindingIds = state.blockedFindingIds.filter((id) => !selectedIds.has(id));
      }

      state = advanceState(state, resumed.phase);
      writeState(stateDir, state);

      skipRepairIds = resumed.skipRepairIds;
      skipBlockedIds = resumed.skipBlockedIds;

      emit(makeEvent("prepare", `Resuming from phase: ${state.phase}`));
    } else {
      // Fresh run: capture identity fields from current options.
      let revision = "";
      try {
        revision = existsSync(managedCheckoutDir(stateDir))
          ? resolveRepoRevision(managedCheckoutDir(stateDir))
          : resolveRepoRevision(repoRoot);
      } catch { /* will resolve during prepare */ }

      const configFields: IdentityFields = {
        source: repoRoot,
        testCommand,
        setupCommand,
        runtime: runtimeMode,
        maxFindings,
        maxAttempts,
        maxTurns,
        depth: depth ?? "default",
      };
      state = createInitialState(runId, repoRoot, revision, configFields);
      writeState(stateDir, state);
    }

    // ── Phase: Prepare ──────────────────────────────────────────────────

    let checkoutPath = repoRoot;
    let revision: string;

    if (state.phase === "prepare") {
      emit(makeEvent("prepare", "Preparing source checkout"));

      try {
        const prepared = prepareSource(repoRoot, stateDir);
        checkoutPath = prepared.checkoutPath;
        revision = prepared.revision;
        state.revision = revision;
        state = advanceState(state, "investigate");
        writeState(stateDir, state);
        emit(makeEvent("prepare", `Source prepared at ${checkoutPath}, revision ${revision.slice(0, 12)}`));
      } catch (err) {
        const msg = `Prepare failed: ${err instanceof Error ? err.message : String(err)}`;
        addError(state, msg);
        state = advanceState(state, "investigate", "failed");
        writeState(stateDir, state);
        emit(makeEvent("prepare", msg));
        return buildResult(state);
      }
    } else {
      checkoutPath = managedCheckoutDir(stateDir);
      if (!existsSync(checkoutPath)) {
        try {
          const prepared = prepareSource(repoRoot, stateDir);
          checkoutPath = prepared.checkoutPath;
          revision = prepared.revision;
          state.revision = revision;
          writeState(stateDir, state);
        } catch (err) {
          const msg = `Re-prepare on resume failed: ${err instanceof Error ? err.message : String(err)}`;
          addError(state, msg);
          state = advanceState(state, "investigate", "failed");
          writeState(stateDir, state);
          return buildResult(state);
        }
      } else {
        try {
          revision = resolveRepoRevision(checkoutPath);
        } catch {
          revision = state.revision;
        }
      }
    }

    // ── Phase: Investigate ──────────────────────────────────────────────

    if (state.phase === "investigate") {
      emit(makeEvent("investigate", "Running source investigation pipeline"));

      const investigation = await investigateSource(
        checkoutPath, depth, costCeilingUsd, workflowTimeoutMs, combinedSignal,
      );

      if (investigation.error) {
        emit(makeEvent("investigate", investigation.error));
      }

      if (investigation.researchFailed) {
        addError(state, investigation.error ?? "Pipeline research failed.");
        state = advanceState(state, "deliver", "failed");
        writeState(stateDir, state);
        return buildResult(state);
      }

      state.findings = investigation.findings;
      if (investigation.costCeilingExceeded) {
        addError(state,
          "Investigation pipeline hit its cost ceiling; findings may be partial. " +
          "Any findings discovered are included, but the investigation is incomplete.",
        );
      }

      state.findings.sort(severityRank);

      const allFindings = [...state.findings];
      state.findings = state.findings.slice(0, maxFindings);

      const omitted = allFindings.slice(maxFindings);
      for (const f of omitted) {
        state.blockedFindingIds.push(f.id);
      }

      const nextPhase = state.findings.length > 0 ? "reproduce" : "deliver";
      state = advanceState(state, nextPhase);
      writeState(stateDir, state);
      emit(makeEvent("investigate",
        `Investigation complete: ${state.findings.length} finding(s) selected` +
        (omitted.length ? `, ${omitted.length} omitted (maxFindings=${maxFindings})` : ""),
      ));
    }

    // ── Phase: Reproduce/Repair/Test/Verify ─────────────────────────────

    if (state.phase === "reproduce" || state.phase === "repair") {
      emit(makeEvent("reproduce", `Starting repair phase for ${state.findings.length} finding(s)`));

      const nativeResult = await resolveNativeRuntime(
        runtimeMode, perFindingTimeout, apiKey, model,
      );

      if (!nativeResult.runtime) {
        const msg = nativeResult.blockedReason ?? "No native runtime available for repair.";
        addError(state, msg);
        state = advanceState(state, "deliver", "blocked");
        writeState(stateDir, state);
        emit(makeEvent("reproduce", msg));
        return buildResult(state);
      }

      // Wrap the runtime with cost tracking.
      const costLedger = new ScanCostLedger();
      const costTrackingRuntime = new CostTrackingRuntime(nativeResult.runtime, costLedger);

      for (const finding of state.findings) {
        if (combinedSignal.aborted) break;

        // Skip already-repaired findings (resume).
        if (skipRepairIds.includes(finding.id)) {
          emit(makeEvent("reproduce", `Skipping already-repaired finding ${finding.id}`, finding.id));
          continue;
        }
        // Skip explicitly blocked findings.
        if (skipBlockedIds.includes(finding.id) || state.blockedFindingIds.includes(finding.id)) {
          continue;
        }

        // ── Cost ceiling check ─────────────────────────────────────────
        if (costCeilingUsd != null && costCeilingUsd > 0) {
          const spentSoFar = costLedger.totalCostUsd();
          if (spentSoFar >= costCeilingUsd) {
            const remaining = state.findings
              .slice(state.findings.indexOf(finding))
              .map((f) => f.id);
            state.blockedFindingIds.push(...remaining);
            addError(state,
              `Cost ceiling reached ($${spentSoFar.toFixed(4)} >= $${costCeilingUsd.toFixed(2)}) ` +
              `before processing finding ${finding.id}. ${remaining.length} remaining finding(s) blocked.`,
            );
            emit(makeEvent("reproduce",
              `Cost ceiling reached — ${remaining.length} finding(s) blocked.`,
            ));
            break;
          }
        }

        emit(makeEvent("reproduce", `Processing finding ${finding.id}: ${finding.title}`, finding.id));

        const artifactDir = join(stateDir, "artifacts", safeFindingDir(finding.id));
        mkdirSync(artifactDir, { recursive: true });

        const findingTimeout = AbortSignal.timeout(perFindingTimeout);
        const findingSignal = combineAbortSignals(combinedSignal, findingTimeout);

        const repairOptions: BehavioralRepairOptions = {
          repoRoot: checkoutPath,
          finding,
          artifactDir,
          runtime: costTrackingRuntime,
          setupCommand,
          testCommand,
          maxAttempts,
          maxTurns,
          timeoutMs: perFindingTimeout,
          signal: findingSignal,
          onEvent: (event) => { emit(event); },
        };

        let repairResult: BehavioralRepairResult;
        try {
          repairResult = await runBehavioralRepair(repairOptions);
        } catch (err) {
          repairResult = {
            findingId: finding.id,
            status: "error",
            attempts: 0,
            reason: `Behavioral repair threw: ${err instanceof Error ? err.message : String(err)}`,
            artifactDir,
          };
        }

        state.repairs[finding.id] = repairResult;

        // Persist the REAL metered cost so far. The ledger only contains
        // usage the runtime actually reported; when no usage is surfaced the
        // total stays 0 — no fabricated estimates.
        state.costUsd = costLedger.totalCostUsd();

        // Only add to repairedFindingIds when the outcome is verified.
        if (repairResult.status === "verified") {
          state.repairedFindingIds.push(finding.id);
        }
        // All other statuses leave the finding unrepaired (blocked implicitly).

        writeState(stateDir, state);
        emit({
          type: "secure:repair",
          phase: "reproduce",
          message: `Finding ${finding.id}: ${repairResult.status} (${repairResult.attempts} attempts)`,
          findingId: finding.id,
          data: repairResult,
        });

        if (repairResult.status === "error") {
          addError(state, `Finding ${finding.id} repair error: ${repairResult.reason}`);
        }
      }

      state = advanceState(state, "deliver");
      writeState(stateDir, state);
      emit(makeEvent("deliver", "Repair phase complete"));
    }

    // ── Phase: Deliver ──────────────────────────────────────────────────

    if (state.phase === "deliver") {
      emit(makeEvent("deliver", "Delivering results"));

      if (publish === true) {
        const { prs, errors: pubErrors } = await publishRepairPatches(
          checkoutPath, state.repairs, state.findings, revision, combinedSignal,
        );
        state.pullRequests = prs.map((pr) => pr.url);
        for (const err of pubErrors) {
          addError(state, err);
        }

        if (combinedSignal.aborted) {
          state = advanceState(state, "complete", "cancelled");
          writeState(stateDir, state);
          emit(makeEvent("deliver", "Cancelled during delivery — state preserved"));
        }
      } else {
        emit(makeEvent("deliver",
          `Artifacts retained in ${stateDir} (publish=false, no PRs created)`,
        ));
      }

      // ── Determine final status ────────────────────────────────────────
      const hasUnrepairedSelectedFindings = state.findings.some(
        (f) => !state.repairedFindingIds.includes(f.id) && !state.blockedFindingIds.includes(f.id),
      );

      let finalStatus: SecureProjectResult["status"];
      if (combinedSignal.aborted) {
        finalStatus = "cancelled";
      } else if (state.errors.length > 0 && state.repairedFindingIds.length === 0) {
        finalStatus = "failed";
      } else if (state.repairedFindingIds.length > 0 && !hasUnrepairedSelectedFindings) {
        // All selected findings either verified-repaired or explicitly blocked.
        finalStatus = "completed";
      } else if (state.blockedFindingIds.length > 0 || hasUnrepairedSelectedFindings) {
        // Mark any truly unrepaired (not blocked) findings as blocked.
        for (const f of state.findings) {
          if (!state.repairedFindingIds.includes(f.id) && !state.blockedFindingIds.includes(f.id)) {
            state.blockedFindingIds.push(f.id);
          }
        }
        finalStatus = state.repairedFindingIds.length > 0 ? "blocked" : "failed";
      } else {
        finalStatus = "completed";
      }

      state = advanceState(state, "complete", finalStatus);
      writeState(stateDir, state);
      emit({ type: "secure:complete", phase: "complete", message: `Lifecycle ${finalStatus}` });
    }

    finished = true;
    return buildResult(state);

  } catch (err) {
    if (err instanceof BlockedError) {
      return resultFromPhase(runId, repoRoot, "prepare", "blocked", [err.message]);
    }
    if (err instanceof LockHeldError) {
      // Lost the acquire race against a concurrent run (TOCTOU between the
      // liveness check and the atomic mkdir).
      return resultFromPhase(runId, repoRoot, "prepare", "blocked", [err.message]);
    }
    return resultFromPhase(runId, repoRoot, "prepare", "failed", [
      `Unexpected error: ${err instanceof Error ? err.message : String(err)}`,
    ]);
  } finally {
    lock.release();
    clearTimeout(deadlineTimer);
    if (!finished) {
      deadlineController.abort(new Error("Workflow terminated"));
    }
  }
}

// ── Result builders ─────────────────────────────────────────────────────────

function buildResult(state: SecureProjectState): SecureProjectResult {
  const allRepairs = Object.values(state.repairs);
  return {
    version: 1,
    runId: state.runId,
    status: state.status as SecureProjectResult["status"],
    phase: state.phase,
    repoRoot: state.source,
    revision: state.revision,
    startedAt: state.startedAt,
    completedAt: state.completedAt,
    findings: state.findings,
    repairs: allRepairs,
    errors: state.errors,
    pullRequests: state.pullRequests,
  };
}

function resultFromPhase(
  runId: string,
  repoRoot: string,
  phase: SecurePhase,
  status: SecureProjectResult["status"],
  errors: string[],
): SecureProjectResult {
  return {
    version: 1,
    runId,
    status,
    phase,
    repoRoot,
    revision: "",
    startedAt: new Date().toISOString(),
    findings: [],
    repairs: [],
    errors,
    pullRequests: [],
  };
}

// ── Error types ─────────────────────────────────────────────────────────────

class BlockedError extends Error {
  override readonly name = "BlockedError";
}

// ── Abort signal combiner ───────────────────────────────────────────────────

function combineAbortSignals(...signals: AbortSignal[]): AbortSignal {
  const controller = new AbortController();
  for (const sig of signals) {
    if (sig.aborted) {
      controller.abort(sig.reason);
      return controller.signal;
    }
    sig.addEventListener("abort", () => controller.abort(sig.reason), { once: true });
  }
  return controller.signal;
}