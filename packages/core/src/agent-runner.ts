import type { Finding } from "@pwnkit/shared";
import type { ScanListener } from "./scanner.js";
import { createRuntime } from "./runtime/index.js";
import type { RuntimeType } from "./runtime/index.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
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

function getMaxTurns(
  role: "audit" | "review",
  depth: string | undefined,
  branch: "native" | "legacy",
  purpose: "research" | "verify" = "research",
): number {
  // Verify reproves one specific finding and should never need more than
  // a handful of turns; cap it tight regardless of depth so verify-wave
  // wall-clock stays bounded. (See PR #198 heartbeat data: per-turn LLM
  // call duration grows with conversation history — 5s at turn 1, 60s at
  // turn 14 — so trimming late verify turns is the highest-leverage cut.)
  if (purpose === "verify") {
    return branch === "native" ? 8 : 10;
  }
  if (role === "audit") {
    if (branch === "native") {
      return depth === "deep" ? 30 : depth === "default" ? 20 : 10;
    }
    // legacy
    return depth === "deep" ? 50 : depth === "default" ? 50 : 15;
  }
  // review
  if (branch === "native") {
    return depth === "deep" ? 100 : depth === "default" ? 40 : 15;
  }
  // legacy
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
    const cliRuntime = new ProcessRuntime({
      type: runtimeType,
      timeout: config.timeout ?? 600_000,
      cwd: scopePath,
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

    const result = await cliRuntime.execute(cliPrompt, {
      systemPrompt: cliSystemPrompt,
      // scanId is required for ProcessRuntime's codex stream-event
      // relay to fire (see process.ts:emitScanEvents gate). Without it
      // audit-mode CLI scans through codex run silently on the
      // cloud-side dashboard — the codex agent does the work, but no
      // turn/tool-call/cost events surface for the live trace. Same
      // scanId we already pass through the rest of the agent runner.
      scanId,
    });

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
