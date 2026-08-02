import type { Finding } from "@pwnkit/shared";
import type { ScanListener } from "./scanner.js";
import { createRuntime } from "./runtime/index.js";
import type { RuntimeType } from "./runtime/index.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import { createEphemeralCodexHome, isEphemeralScope } from "./runtime/codex-home.js";
import { detectAvailableRuntimes, pickRuntimeForStage } from "./runtime/registry.js";
import { runAgentLoop } from "./agent/loop.js";
import { runNativeAgentLoop } from "./agent/native-loop.js";
import { maybeStartCloudInboxPoller } from "./agent/cloud-inbox.js";
import { toolCallPreview } from "./agent/tool-preview.js";
import { getToolsForRole } from "./agent/tools.js";
import type { NativeRuntime } from "./runtime/types.js";
import { CLI_RUNTIME_TYPES } from "./shared-analysis.js";
import { parseFindingsFromCliOutput } from "./findings-parser.js";
import { estimateCost } from "./agent/cost.js";
import { getCloudSinkConfig, postFinding } from "./cloud-sink.js";

// ── Types ──

export interface AnalysisAgentOptions {
  role: "audit" | "review";
  scopePath: string;
  target: string;
  scanId: string;
  sessionId?: string;
  config: { runtime?: string; timeout?: number; depth?: string; apiKey?: string; model?: string; costCeilingUsd?: number; costLedger?: import("./agent/cost-ledger.js").ScanCostLedger };
  db: any;
  emit: ScanListener;
  /** Prompt sent to CLI runtimes (compact, includes ---FINDING--- format instructions) */
  cliPrompt: string;
  /** System prompt for the native agentic loop (full methodology prompt) */
  agentSystemPrompt: string;
  /** System prompt for CLI runtimes (short role description) */
  cliSystemPrompt: string;
  /** Optional: direct API prompt with embedded source code for single-shot fallback */
  directApiPrompt?: string;
  /**
   * Why the agent is being invoked. `research` (default) uses the full
   * depth-derived turn budget. `verify` reproves a single specific finding
   * and is capped much tighter — late turns in a long verify call cost as
   * much as in a long research call (each one re-sends the entire growing
   * conversation), and a single finding shouldn't need 15 turns to reproduce.
   */
  purpose?: "research" | "verify";
}

/**
 * Re-export of the canonical TokenUsage shape from @pwnkit/shared so
 * call sites that imported AnalysisTokenUsage from this module continue
 * to work without churn.
 */
export type AnalysisTokenUsage = import("@pwnkit/shared").TokenUsage;

export interface AnalysisAgentResult {
  findings: Finding[];
  usage?: AnalysisTokenUsage;
  estimatedCostUsd?: number;
  /**
   * Number of agent-loop turns this run consumed. Populated by the loop
   * branches that track it (native + legacy); the CLI-runtime and single-shot
   * paths don't expose a multi-turn count, so it's left undefined there. Used
   * by the pipeline to attribute per-phase turn totals.
   */
  turns?: number;
  /**
   * True when the agent loop terminated on the hard cost ceiling (native
   * branch only; undefined elsewhere). The pipeline distinguishes a
   * budget-truncated verifier from a genuine "could not reproduce" so the
   * finding is held as inconclusive rather than rejected.
   */
  costCeilingExceeded?: boolean;
}

// ── Depth → maxTurns mapping ──

/**
 * Read a positive-integer turn budget from the environment. Invalid, zero, and
 * negative values are ignored rather than clamped — a typo'd sweep parameter
 * should fall back to the tuned default, not silently pin the agent to one turn.
 */
function envTurns(key: string): number | undefined {
  const raw = process.env[key];
  if (raw === undefined || raw.trim() === "") return undefined;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) return undefined;
  return parsed;
}

/**
 * Resolve the maximum number of agent-loop turns for a run.
 *
 * ── Why these numbers changed (prompt caching) ──
 *
 * The previous budgets — verify capped at 8 turns, audit at 30 — were set
 * against PR #198 heartbeat data showing per-turn LLM latency growing with
 * conversation history: 5s at turn 1, 60s at turn 14. That growth was never
 * about the model thinking harder; it was the engine re-prefilling the entire
 * transcript on every stateless request. Trimming turns treated the symptom by
 * capping how long the agent was allowed to think.
 *
 * Prompt caching (`runtime/prompt-cache.ts`, default ON) addresses the cause:
 * the system prompt, tool schemas, and settled conversation are now marked with
 * `cache_control` breakpoints and re-read from cache instead of re-billed and
 * re-prefilled each turn. The late-turn tax that justified the tight caps is
 * substantially paid down, so the budgets are re-derived from what the WORK
 * needs rather than from what the latency curve could tolerate.
 *
 * For scale: a competitive system on the same class of task (Crystalline,
 * 89.6% on CyberGym) runs a mean of ~169 turns/task. Everything below still
 * sits at or under that, deliberately.
 *
 * ── The real cost guard ──
 *
 * Turns are a crude proxy for spend. The actual ceiling is `costCeilingUsd` /
 * `ScanCostLedger`, which cuts a run on dollars regardless of turn count — so
 * raising turns raises the CEILING on work, not the floor on spend. A run that
 * finishes in 6 turns still costs 6 turns. That asymmetry is what makes these
 * increases safe: they only bind on runs that were being truncated mid-work.
 *
 * ── Legacy branch deliberately unchanged ──
 *
 * The legacy branch goes through `execute()` (prompt-in/text-out), not
 * `executeNative()`, and prompt caching is implemented only on the native
 * path. The latency/cost argument above therefore does not apply to it, so its
 * budgets stay exactly as they were. Only `verify` gets a small legacy bump,
 * on task-shape grounds rather than caching (see below).
 *
 * ── Env overrides ──
 *
 * All budgets are overridable without a rebuild so they can be swept:
 *   PWNKIT_MAX_TURNS         — every role and purpose
 *   PWNKIT_MAX_TURNS_VERIFY  — verify runs only
 *   PWNKIT_MAX_TURNS_AUDIT   — audit research runs
 *   PWNKIT_MAX_TURNS_REVIEW  — review research runs
 * The specific variable wins over the global one when both are set.
 */
export function getMaxTurns(
  role: "audit" | "review",
  depth: string | undefined,
  branch: "native" | "legacy",
  purpose: "research" | "verify" = "research",
): number {
  const globalOverride = envTurns("PWNKIT_MAX_TURNS");

  if (purpose === "verify") {
    const override = envTurns("PWNKIT_MAX_TURNS_VERIFY") ?? globalOverride;
    if (override !== undefined) return override;
    // Verify reproves ONE specific finding, so it genuinely doesn't need a
    // research-scale budget. But 8 turns was below the floor for the task:
    // reproducing a finding costs roughly read target → write PoC → run it →
    // read the failure → fix → re-run, which is 6 turns with zero slack for a
    // single wrong assumption. Runs were hitting the cap mid-debug and getting
    // scored as "could not reproduce" — a false negative manufactured by the
    // budget rather than by the evidence. 20 affords two full debug cycles and
    // still lands at ~12% of the Crystalline reference.
    return branch === "native" ? 20 : 12;
  }
  if (role === "audit") {
    const override = envTurns("PWNKIT_MAX_TURNS_AUDIT") ?? globalOverride;
    if (override !== undefined) return override;
    if (branch === "native") {
      // Doubled across the board. Audit walks a dependency/source tree, and
      // depth is the operator's explicit statement of how much of it to walk;
      // 30 turns for "deep" was under-serving that request on any non-trivial
      // package. `quick` moves 10 → 15 only, since its whole contract is to
      // stay cheap.
      return depth === "deep" ? 60 : depth === "default" ? 40 : 15;
    }
    // legacy — unchanged, no caching on this path
    return depth === "deep" ? 50 : depth === "default" ? 50 : 15;
  }
  // review
  const override = envTurns("PWNKIT_MAX_TURNS_REVIEW") ?? globalOverride;
  if (override !== undefined) return override;
  if (branch === "native") {
    // `deep` 100 → 150 brings the one budget meant for exhaustive work in line
    // with the ~169-turn competitive reference. `default` 40 → 60 and `quick`
    // 15 → 20 are scaled more conservatively: they are the common path, so a
    // bad increase there is paid on every scan rather than on opt-in runs.
    return depth === "deep" ? 150 : depth === "default" ? 60 : 20;
  }
  // legacy — unchanged, no caching on this path
  return depth === "deep" ? 100 : depth === "default" ? 50 : 15;
}

// ── Main entry point ──

/**
 * Unified agent runner for both audit and review roles.
 *
 * Contains the 3-branch runtime selection logic:
 * 1. CLI runtime fast path (ProcessRuntime) — claude/codex/gemini/
 * 2. API runtime with native tool_use (runNativeAgentLoop)
 * 3. Legacy fallback (runAgentLoop)
 */
export async function runAnalysisAgent(opts: AnalysisAgentOptions): Promise<AnalysisAgentResult> {
  const { role, scopePath, target, scanId, sessionId, config, db, emit, cliPrompt, agentSystemPrompt, cliSystemPrompt, directApiPrompt, purpose = "research" } = opts;

  const templatePrefix = `cli-${role}`;
  const requestedRuntime = config.runtime as RuntimeType | "auto" | undefined;
  const allowApiFallback = requestedRuntime === undefined || requestedRuntime === "auto" || requestedRuntime === "api";

  emit({
    type: "stage:start",
    stage: "attack",
    message: role === "audit"
      ? "AI agent analyzing source code..."
      : "AI agent performing deep code review...",
  });

  // Detect available CLI runtimes
  const available = await detectAvailableRuntimes();

  // `--runtime codex` is dual-mode: it can resolve through either the
  // local `codex` CLI binary or the direct ChatGPT Codex provider when
  // PWNKIT_CHATGPT_ACCESS_TOKEN / PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN is
  // set. Probe the API runtime configuration once up front so we can
  // route codex requests through the API native loop when the CLI
  // binary is absent but the operator has subscription auth configured.
  // This matches the routing already in `agentic-scanner.ts` for the
  // web-target path (closes #402: previously, kernel reviews + npm/pypi/
  // cargo audits with `--runtime codex` failed on machines without the
  // codex CLI binary, even when the subscription provider was working).
  const codexApiProbe =
    requestedRuntime === "codex" && !available.has("codex")
      ? new LlmApiRuntime({
          type: "api",
          timeout: config.timeout ?? 120_000,
          apiKey: config.apiKey,
          model: config.model,
        }).getConfigurationDiagnostics()
      : null;
  const useDirectChatGptCodex =
    requestedRuntime === "codex" &&
    !available.has("codex") &&
    codexApiProbe?.valid === true &&
    codexApiProbe.provider === "chatgpt-codex";

  // Determine runtime: prefer CLI runtimes, fall back to API agent loop
  let runtimeType: RuntimeType;
  if (config.runtime === "auto") {
    runtimeType = available.size > 0
      ? pickRuntimeForStage("source-analysis", available)
      : "api";
  } else if (useDirectChatGptCodex) {
    // Codex was requested, the CLI binary is missing, but the
    // subscription provider is configured. Route through the API
    // runtime (native tool_use loop). agent-runner Branch 2 handles
    // the LlmApiRuntime → executeNative dispatch.
    runtimeType = "api";
  } else {
    runtimeType = (config.runtime ?? "api") as RuntimeType;
  }

  if (process.env.CI || process.env.PWNKIT_DEBUG) {
    process.stderr.write(`[pwnkit] agent-runner: type=${runtimeType}, available=[${[...available].join(",")}], directCodex=${useDirectChatGptCodex}\n`);
  }

  // ── Branch 1: CLI runtime fast path (claude/codex/etc.) ──
  if (CLI_RUNTIME_TYPES.has(runtimeType) && available.has(runtimeType)) {
    emit({
      type: "stage:start",
      stage: "attack",
      message: `Using ${runtimeType} CLI for deep AI analysis...`,
    });

    // Schema for structured findings output
    const findingsSchema = {
      type: "object",
      additionalProperties: false,
      properties: {
        findings: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            properties: {
              title: { type: "string", description: "Clear vulnerability title" },
              severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
              category: { type: "string" },
              file: { type: "string", description: "File path and line number" },
              suggested_replacement: {
                type: "string",
                description: "Optional exact replacement for the cited source line or range",
              },
              description: { type: "string", description: "Detailed vulnerability description" },
              poc: { type: "string", description: "Proof-of-concept code or command" },
            },
            required: ["title", "severity", "category", "file", "description", "poc"],
          },
        },
        summary: { type: "string", description: "Brief summary of the audit" },
      },
      required: ["findings", "summary"],
    };

    const { ProcessRuntime } = await import("./runtime/process.js");
    // Run-scoped CODEX_HOME when the working directory is code we just
    // downloaded (a package-audit temp tree). The Codex CLI records a trust
    // decision for whatever directory it runs in, into the OPERATOR's
    // ~/.codex/config.toml — and trust gates project-local config, hooks, exec
    // policies and MCP servers, so a hostile package's `.codex/config.toml`
    // becomes execution on a host with no OS sandbox. See runtime/codex-home.ts.
    // A real checkout is left alone: trusting your own repo is the point.
    const codexHome =
      runtimeType === "codex" && isEphemeralScope(scopePath)
        ? createEphemeralCodexHome()
        : undefined;
    const cliRuntime = new ProcessRuntime({
      type: runtimeType,
      timeout: config.timeout ?? 600_000,
      cwd: scopePath,
      ...(codexHome ? { env: { CODEX_HOME: codexHome.path } } : {}),
      outputSchema: findingsSchema,
      onToolCall: (name, detail) => {
        emit({
          type: "stage:start",
          stage: "attack",
          message: `${name}${detail ? ": " + detail : ""}`,
        });
      },
      onThinking: (text) => {
        emit({
          type: "thinking" as any,
          stage: "attack",
          message: text.slice(0, 100),
        });
      },
    });

    let result;
    try {
      result = await cliRuntime.execute(cliPrompt, {
        systemPrompt: cliSystemPrompt,
        // scanId is required for ProcessRuntime's codex stream-event
        // relay to fire (see process.ts:emitScanEvents gate). Without it
        // audit-mode CLI scans through codex run silently on the
        // cloud-side dashboard — the codex agent does the work, but no
        // turn/tool-call/cost events surface for the live trace. Same
        // scanId we already pass through the rest of the agent runner.
        scanId,
      });
    } finally {
      // Discards any trust entry, project-local config or hook the run
      // picked up; syncs back only a rotated credential.
      codexHome?.dispose();
    }

    if (result.error && !result.output) {
      emit({
        type: "stage:end",
        stage: "attack",
        message: `CLI agent error: ${result.error}`,
      });
      if (!allowApiFallback) {
        emit({
          type: "error",
          stage: "attack",
          message: `Explicit runtime '${runtimeType}' failed; API fallback disabled.`,
        });
        return { findings: [], usage: undefined, estimatedCostUsd: undefined };
      }
      // Fall through to API / legacy branches below only for auto/api modes.
    } else {
      const findings = parseFindingsFromCliOutput(result.output, { templatePrefix, scopePath });

      for (const f of findings) {
        emit({
          type: "finding",
          message: `[${f.severity}] ${f.title}`,
          data: f,
        });
      }

      emit({
        type: "stage:end",
        stage: "attack",
        message: `CLI agent complete: ${findings.length} findings (${result.durationMs}ms)`,
      });

      return { findings };
    }
  }

  // ── Branch 2: API runtime with native tool_use ──
  if (runtimeType === "api" || !available.has(runtimeType)) {
    if (!allowApiFallback && runtimeType !== "api") {
      emit({
        type: "error",
        stage: "attack",
        message: `Runtime '${runtimeType}' is unavailable and API fallback is disabled for explicit runtime selection.`,
      });
      return { findings: [], usage: undefined, estimatedCostUsd: undefined };
    }

    emit({
      type: "stage:start",
      stage: "attack",
      message: `Running agentic source code ${role === "audit" ? "analysis" : "review"} via API...`,
    });

    const apiRuntime = new LlmApiRuntime({
      type: "api" as RuntimeType,
      timeout: config.timeout ?? 120_000,
      apiKey: config.apiKey,
      model: config.model,
    });
    const apiDiagnostics = apiRuntime.getConfigurationDiagnostics();
    if (!apiDiagnostics.valid) {
      throw new Error(apiDiagnostics.fatalError ?? `${apiDiagnostics.providerLabel} runtime is not available.`);
    }

    // Check if runtime supports native tool_use (multi-turn agentic loop)
    const supportsNative = typeof (apiRuntime as NativeRuntime).executeNative === "function";
    if (process.env.CI || process.env.PWNKIT_DEBUG) {
      process.stderr.write(`[pwnkit] API runtime: native=${supportsNative}, model=${config.model ?? "default"}\n`);
    }

    if (supportsNative) {
      const maxTurns = getMaxTurns(role, config.depth, "native", purpose);

      // #978 (ADR-060) — cloud control channel. unified-pipeline.ts (the
      // package/source audit + review path) runs the agent here, NOT through
      // agenticScan, so the inbox drain must be wired in BOTH entries. In
      // cloud mode, default getPendingUserMessages to the scan-inbox poller so
      // operator steers ("Steer this scan") reach the agent mid-run. null in
      // local mode (no cloud sink). unref'd, so the process still exits clean.
      const cloudInbox = maybeStartCloudInboxPoller();

      const agentState = await runNativeAgentLoop({
        config: {
          role,
          systemPrompt: agentSystemPrompt,
          tools: getToolsForRole(role, { hasScope: !!scopePath }),
          maxTurns,
          target,
          scanId,
          scopePath,
          sessionId,
          costCeilingUsd: config.costCeilingUsd,
          costModel: config.model,
          costLedger: config.costLedger,
        },
        runtime: apiRuntime as NativeRuntime,
        db,
        getPendingUserMessages: cloudInbox?.drain,
        onTurn: (turn, toolCalls, _results) => {
          const cloudSinkCfg = getCloudSinkConfig();
          if (toolCalls.length === 0) {
            emit({
              type: "stage:start",
              stage: "attack",
              message: `turn ${turn}: thinking`,
            });
          }
          for (const call of toolCalls) {
            if (call.name === "save_finding") {
              emit({
                type: "finding",
                message: `[${call.arguments.severity}] ${call.arguments.title}`,
                data: call.arguments,
              });
              void postFinding(call.arguments, cloudSinkCfg);
            }
            emit({
              type: "stage:start",
              stage: "attack",
              message: `turn ${turn}: ${toolCallPreview(call)}`,
            });
          }
        },
        onEvent: (eventType, payload) => {
          if (eventType === "thinking") {
            const data = payload as { text?: string; turn?: number };
            if (data.text) {
              emit({ type: "thinking", stage: "attack", message: data.text, data });
            }
            return;
          }
          if (eventType === "usage") {
            emit({ type: "usage", stage: "attack", message: "usage", data: payload });
          }
        },
      });

      // Surface agent errors
      if (agentState.summary.startsWith("Error:")) {
        emit({
          type: "error",
          stage: "attack",
          message: agentState.summary,
        });
      }

      // Honor the loop's structured hard-exit (errorExit): an auth-class or
      // exhausted-retry failure is NOT "0 findings" — propagate so the
      // caller's error path (per-file onFileError + circuit breaker, or the
      // pipeline's "AI analysis failed" warning) records it. Without this a
      // dead provider reads as a clean "no vulnerabilities" report (measured
      // 2026-07-17: codex 401 → 0-finding clean report, warnings[] empty).
      if (agentState.errorExit) {
        throw new Error(agentState.errorExit.error);
      }

      emit({
        type: "stage:end",
        stage: "attack",
        message: `${role === "audit" ? "Agent" : "Review"} complete: ${agentState.findings.length} findings in ${agentState.turnCount} turns (${agentState.totalUsage.inputTokens + agentState.totalUsage.outputTokens} tokens)`,
      });

      return {
        findings: agentState.findings,
        usage: agentState.totalUsage,
        estimatedCostUsd: agentState.estimatedCostUsd,
        turns: agentState.turnCount,
        costCeilingExceeded: agentState.costCeilingExceeded,
      };
    }

    // ── Single-shot fallback for API runtimes without native tool_use ──
    if (directApiPrompt) {
      const result = await apiRuntime.execute(directApiPrompt, {
        systemPrompt: cliSystemPrompt,
      });

      if (result.error && !result.output) {
        emit({
          type: "stage:end",
          stage: "attack",
          message: `API analysis error: ${result.error}`,
        });
        return { findings: [], usage: undefined, estimatedCostUsd: undefined };
      }

      const findings = parseFindingsFromCliOutput(result.output, { templatePrefix, scopePath });

      for (const f of findings) {
        emit({
          type: "finding",
          message: `[${f.severity}] ${f.title}`,
          data: f,
        });
      }

      emit({
        type: "stage:end",
        stage: "attack",
        message: `API analysis complete: ${findings.length} findings (${result.durationMs}ms)`,
      });

      return {
        findings,
        usage: result.usage,
        estimatedCostUsd: result.usage
          ? estimateCost(result.usage, config.model)
          : undefined,
        // Single-shot fallback = exactly one model round-trip.
        turns: 1,
      };
    }
  }

  // ── Branch 3: Legacy fallback — text-based agent loop ──
  const maxTurns = getMaxTurns(role, config.depth, "legacy", purpose);

  const runtimeConfig = {
    type: runtimeType as RuntimeType,
    timeout: config.timeout ?? 120_000,
    apiKey: config.apiKey,
    model: config.model,
  };
  const runtime =
    runtimeType === "api" || !available.has(runtimeType)
      ? new LlmApiRuntime(runtimeConfig)
      : createRuntime(runtimeConfig);

  const agentState = await runAgentLoop({
    config: {
      role,
      systemPrompt: agentSystemPrompt,
      tools: getToolsForRole(role, { hasScope: !!scopePath }),
      maxTurns,
      target,
      scanId,
      scopePath,
    },
    runtime,
    db,
    onTurn: (_turn, msg) => {
      const calls = msg.toolCalls ?? [];
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

  emit({
    type: "stage:end",
    stage: "attack",
    message: `${role === "audit" ? "Agent" : "Review"} complete: ${agentState.findings.length} findings${agentState.summary ? `, ${agentState.summary}` : ""}`,
  });

  // Legacy loop doesn't track token usage / cost — those are populated
  // only by the native API loop branch above. It does count turns, so those
  // are still attributable per-phase.
  return { findings: agentState.findings, usage: undefined, estimatedCostUsd: undefined, turns: agentState.turnCount };
}
