import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { writeFileSync } from "node:fs";
import type { Runtime, RuntimeConfig, RuntimeContext, RuntimeResult, RuntimeType } from "./types.js";
import { eventBus, isCloudEventSinkActive } from "../events/bus.js";

// Dim the subprocess output so it's visually distinct from pwnkit's own output
const dim = (text: string) => `\x1b[2m${text}\x1b[0m`;

function formatToolDetail(input: unknown): string {
  const inp = input as Record<string, unknown> | undefined;
  if (inp?.file_path) return String(inp.file_path).split("/").slice(-2).join("/");
  if (inp?.command) return String(inp.command).slice(0, 60);
  if (inp?.pattern) return String(inp.pattern).slice(0, 40);
  if (inp?.path) return String(inp.path).slice(0, 60);
  if (inp?.content) return "(writing file)";
  return "";
}

/** Map raw MCP tool names to human-friendly labels. */
function friendlyToolName(name: string): string {
  const stripped = name.replace(/^mcp__\w+__/, "");
  return stripped
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function showToolCall(
  onToolCall: ((name: string, detail: string) => void) | undefined,
  name: string | undefined,
  input: unknown,
): void {
  const rawName = name || "tool";
  // Skip internal/framework tool calls that aren't meaningful to the user
  if (/^(ToolSearch|Read|Glob|Grep|Write|Edit|Bash|LSP|Agent)$/i.test(rawName)) return;
  const toolName = friendlyToolName(rawName);
  const detail = formatToolDetail(input);

  if (onToolCall) {
    onToolCall(toolName, detail);
  }

  // Fallback: write to stderr for raw terminal display (only when no TUI)
  if (process.stderr.isTTY && !onToolCall) {
    process.stderr.write(dim(`    ${toolName}${detail ? ": " + detail : ""}\n`));
  }
}

const RUNTIME_COMMANDS: Record<string, string> = {
  claude: "claude",
  codex: "codex",
  gemini: "gemini",
};

function resolveCliEntrypoint(): string {
  return resolve(process.argv[1] ?? join(process.cwd(), "dist", "index.js"));
}

function buildPwnkitMcpCommandArgs(context: RuntimeContext): string[] {
  const cliEntrypoint = resolveCliEntrypoint();
  const args = [
    cliEntrypoint,
    "mcp-server",
    "--target",
    context.target ?? "",
    "--scan-id",
    context.scanId ?? "no-scan-id",
  ];

  if (context.mcp?.dbPath) {
    args.push("--db-path", context.mcp.dbPath);
  }
  if (context.mcp?.scopeFile) {
    args.push("--scope", context.mcp.scopeFile);
  }
  if (context.mcp?.rateLimit) {
    args.push("--rate-limit", context.mcp.rateLimit);
  }
  if (context.mcp?.allowScanners) {
    args.push("--allow-scanners");
  }

  return args;
}

/** Read a number-valued field from a codex usage object, tolerating string-encoded ints. */
function numericField(obj: Record<string, unknown>, key: string): number | undefined {
  const v = obj[key];
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

/** JSON.stringify but never throws — falls back to a stable placeholder on cycles / BigInt. */
function safeJsonStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return "(unserialisable)";
  }
}

function buildClaudeMcpConfig(context: RuntimeContext): string {
  return JSON.stringify({
    mcpServers: {
      pwnkit: {
        command: process.execPath,
        args: buildPwnkitMcpCommandArgs(context),
      },
    },
  });
}

export class ProcessRuntime implements Runtime {
  readonly type: RuntimeType;
  private config: RuntimeConfig;
  private command: string;

  constructor(config: RuntimeConfig) {
    this.type = config.type as RuntimeType;
    this.config = config;
    this.command = RUNTIME_COMMANDS[config.type] ?? config.type;
  }

  async execute(prompt: string, context?: RuntimeContext): Promise<RuntimeResult> {
    const start = Date.now();
    const args = this.buildArgs(prompt, context);
    const env = this.buildEnv(context);

    const onToolCall = this.config.onToolCall;
    // Per-execution observability state for the Codex CLI JSON stream. Tracks
    // the 1-indexed turn number we emit `agent_turn_*` events under, plus the
    // tool-call indices we emit `tool_call_*` events under. Codex's `--json`
    // stream uses its own `sequence_number` for stream ordering — pwnkit's
    // event types use a simpler turn-and-tool-call counter that matches what
    // the api-runtime path emits, so the dashboard's live-trace renderer
    // doesn't need to special-case codex events.
    const scanId = context?.scanId;
    // Fire the cloud stream-event relay whenever (a) we're driving a
    // codex subprocess AND (b) something is listening — that is, the
    // cloud sink has been subscribed via PWNKIT_CLOUD_EVENTS=1. The
    // earlier `Boolean(scanId)` guard skipped audit-mode CLI runs
    // because `runAnalysisAgent` didn't pass scanId in its execute
    // context; the runner still subscribes events via the cloud sink,
    // and the worker-controller's per-relay scanId injection happens
    // upstream of the bus anyway, so requiring scanId here was over-
    // tightening the gate. The bus is fail-soft and no-ops when the
    // sink isn't subscribed, so we use the same `isCloudEventSinkActive`
    // predicate the native-loop's hot-path delta forwarder uses.
    const emitScanEvents = this.type === "codex" && isCloudEventSinkActive();
    // Codex's per-scan max-turn budget isn't exposed on its --json stream,
    // so we surface the runtime-config timeout-derived turn cap (rendered
    // as a UI hint) — falls back to a sensible 40 to match the api-runtime
    // attack-stage default. The dashboard treats this as best-effort.
    const maxTurnsHint = 40;
    let turnNumber = 0;
    let toolCallSeq = 0;
    let deltaSeq = 0;
    let turnStartedAt = 0;
    // Per-tool-call start timestamps so item.completed can synthesise the
    // duration_ms field on the cloud event (codex emits a `sequence_number`
    // but no wall-clock timestamps).
    const toolCallStartedAt = new Map<number, number>();
    // Stream-level dedup. Codex's `exec --json` empirically emits its
    // `thread.started` + `turn.started` + `turn.completed` events twice
    // per logical turn — observed via end-to-end test 2026-05-13 with
    // two `agent_turn_started` rows ~250ms apart and two `cost_update`
    // rows with distinct token counts. We strongly suspect this comes
    // from codex internally running both a planner and a synthesis
    // model and surfacing completion events for both; the exact cause
    // is opaque from our side. Either way, the dashboard renders
    // double events as confusing duplicate turns. Drop the second
    // event of each (type, sequence_number) pair within a turn.
    const seenSequenceNumbers = new Set<string>();
    const isSeenSequence = (event: Record<string, unknown>): boolean => {
      const seq = event.sequence_number;
      if (typeof seq !== "number" && typeof seq !== "string") return false;
      const key = `${event.type ?? "?"}|${seq}`;
      if (seenSequenceNumbers.has(key)) return true;
      seenSequenceNumbers.add(key);
      return false;
    };

    // Closure over the per-execution counters above. Each codex JSON event
    // becomes 0..N pwnkit cloud-bus events. See the comment above the call
    // site in the stdout handler for what this exists for.
    const emitCodexCloudEvents = (event: Record<string, unknown>): void => {
      // Stream dedup — see seenSequenceNumbers definition above.
      if (isSeenSequence(event)) return;
      const eventType = typeof event.type === "string" ? event.type : "";
      switch (eventType) {
        case "thread.started": {
          // Map to llm_planner_invoked at turn 0 so the dashboard's
          // first-event timestamp matches when the agent loop actually
          // started, not when worker-controller dispatched.
          eventBus.emit("llm_planner_invoked", {
            turn: 0,
            model: this.config.model,
            role: "attack",
          });
          return;
        }
        case "turn.started": {
          turnNumber += 1;
          turnStartedAt = Date.now();
          deltaSeq = 0;
          eventBus.emit("agent_turn_started", {
            turn: turnNumber,
            max_turns: maxTurnsHint,
            role: "attack",
          });
          eventBus.emit("llm_planner_invoked", {
            turn: turnNumber,
            model: this.config.model,
            role: "attack",
          });
          return;
        }
        case "turn.completed": {
          const usage = (event.usage ?? {}) as Record<string, unknown>;
          const inputTokens = numericField(usage, "input_tokens");
          const cachedInputTokens = numericField(usage, "cached_input_tokens");
          const outputTokens = numericField(usage, "output_tokens");
          const reasoningTokens = numericField(usage, "reasoning_output_tokens");
          const durationMs = turnStartedAt > 0 ? Date.now() - turnStartedAt : 0;
          eventBus.emit("agent_turn_completed", {
            turn: turnNumber,
            duration_ms: durationMs,
            reason: "continue",
            role: "attack",
          });
          // Subscription-auth scans have no $ cost, but surfacing token
          // counts still helps operators reason about scan size + retry
          // budgets — emit cost_update with cost=0 so the dashboard's
          // token meter populates.
          eventBus.emit("cost_update", {
            turn: turnNumber,
            cost_usd: 0,
            input_tokens: inputTokens,
            output_tokens: outputTokens,
            cached_input_tokens: cachedInputTokens,
            reasoning_output_tokens: reasoningTokens,
          });
          return;
        }
        case "item.started": {
          const item = (event.item ?? {}) as Record<string, unknown>;
          const itemType = typeof item.type === "string" ? item.type : "";
          if (itemType === "command_execution" && typeof item.command === "string") {
            toolCallSeq += 1;
            toolCallStartedAt.set(toolCallSeq, Date.now());
            eventBus.emit("tool_call_started", {
              tool: "shell",
              turn: turnNumber,
              args_preview: item.command.slice(0, 200),
            });
          } else if (itemType === "mcp_tool_call") {
            // Codex emits item.started for MCP tool calls with the call's
            // args + status=in_progress, then item.completed with the
            // result + status=success|error. Pair them via toolCallSeq so
            // we can synthesise duration_ms on completion. The fully-
            // qualified name we surface to the dashboard is
            // `<server>__<tool>` (e.g. `pwnkit__http_request`) so the
            // live-trace UI can show which MCP server backed the call.
            toolCallSeq += 1;
            toolCallStartedAt.set(toolCallSeq, Date.now());
            const server = typeof item.server === "string" ? item.server : "?";
            const tool = typeof item.tool === "string" ? item.tool : "?";
            const argsRaw = item.arguments ?? {};
            const argsPreview = typeof argsRaw === "string"
              ? argsRaw
              : safeJsonStringify(argsRaw);
            eventBus.emit("tool_call_started", {
              tool: `${server}__${tool}`,
              turn: turnNumber,
              args_preview: argsPreview.slice(0, 200),
            });
          }
          return;
        }
        case "item.completed": {
          const item = (event.item ?? {}) as Record<string, unknown>;
          const itemType = typeof item.type === "string" ? item.type : "";
          if (itemType === "command_execution") {
            // Pair with the item.started above using the seq counter; the
            // dashboard renders order by emit timestamp, so this just needs
            // to be the *same tool* in the same turn.
            const startedAt = toolCallStartedAt.get(toolCallSeq);
            const durationMs = startedAt != null ? Date.now() - startedAt : 0;
            toolCallStartedAt.delete(toolCallSeq);
            eventBus.emit("tool_call_completed", {
              tool: "shell",
              turn: turnNumber,
              duration_ms: durationMs,
              status: "ok",
            });
          } else if (itemType === "mcp_tool_call") {
            // Pair with the corresponding item.started above. Codex sets
            // item.status to "success" / "failed" / "cancelled" depending
            // on outcome; map success → "ok", anything else → "error" so
            // the dashboard's red/green tool-call badge reflects truth.
            const startedAt = toolCallStartedAt.get(toolCallSeq);
            const durationMs = startedAt != null ? Date.now() - startedAt : 0;
            toolCallStartedAt.delete(toolCallSeq);
            const server = typeof item.server === "string" ? item.server : "?";
            const tool = typeof item.tool === "string" ? item.tool : "?";
            const status: "ok" | "error" =
              item.status === "success" || item.status === "completed"
                ? "ok"
                : "error";
            const errorMsg =
              status === "error"
                ? (typeof item.error === "string"
                    ? item.error
                    : safeJsonStringify(item.error ?? null))
                : undefined;
            eventBus.emit("tool_call_completed", {
              tool: `${server}__${tool}`,
              turn: turnNumber,
              duration_ms: durationMs,
              status,
              ...(errorMsg ? { error: errorMsg.slice(0, 400) } : {}),
            });
          } else if (itemType === "function_call" || itemType === "tool_call") {
            // Legacy / non-MCP function-call shape — kept for forward-
            // compatibility against future codex CLI versions that might
            // surface tool calls under a different item.type name. The
            // current 0.130.x stream uses `mcp_tool_call` for the MCP
            // path (handled above), but we emit a (started+completed)
            // pair here in case other call shapes appear.
            toolCallSeq += 1;
            const toolName =
              (typeof item.tool_name === "string" && item.tool_name) ||
              (typeof item.name === "string" && item.name) ||
              "mcp_tool";
            const argsField = item.arguments ?? item.input ?? "";
            const detail = typeof argsField === "string" ? argsField : safeJsonStringify(argsField);
            eventBus.emit("tool_call_started", {
              tool: toolName,
              turn: turnNumber,
              args_preview: detail.slice(0, 200),
            });
            eventBus.emit("tool_call_completed", {
              tool: toolName,
              turn: turnNumber,
              duration_ms: 0,
              status: "ok",
            });
          } else if (itemType === "reasoning") {
            const reasoningText =
              (typeof item.text === "string" && item.text) ||
              (typeof item.summary === "string" && item.summary) ||
              "";
            if (reasoningText.length > 0) {
              eventBus.emit("reasoning_summary", {
                turn: turnNumber,
                summary: reasoningText.slice(0, 2000),
              });
            }
          } else if (itemType === "agent_message") {
            const messageText = typeof item.text === "string" ? item.text : "";
            if (messageText.length > 0) {
              deltaSeq += 1;
              eventBus.emit("delta", {
                turn: turnNumber,
                scope: "assistant_response",
                text: messageText.slice(0, 2000),
                seq: deltaSeq,
                role: "attack",
              });
            }
          }
          return;
        }
        // thread.completed / response.* / unknown events: deliberately
        // unmapped. Adding them later is a one-line case extension.
      }
    };

    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let resultText = "";
      let timedOut = false;
      const isJsonStream = args.includes("stream-json") || args.includes("--json");

      const proc = spawn(this.command, args, {
        cwd: this.config.cwd ?? process.cwd(),
        env: { ...process.env, ...env },
        stdio: ["ignore", "pipe", "pipe"],
      });

      proc.stdout.on("data", (chunk: Buffer) => {
        const text = chunk.toString();
        stdout += text;

        if (isJsonStream) {
          for (const line of text.split("\n")) {
            if (!line.trim()) continue;
            try {
              const event = JSON.parse(line);

              // Claude stream-json format
              if (event.type === "assistant" && event.message?.content) {
                for (const block of event.message.content) {
                  if (block.type === "text") {
                    resultText += block.text;
                    this.config.onThinking?.(block.text);
                  } else if (block.type === "tool_use") {
                    showToolCall(onToolCall, block.name, block.input);
                  }
                }
              } else if (event.type === "result") {
                resultText = event.result || resultText;
              }

              // Codex JSONL format
              if (event.type === "item.started" && event.item?.type === "command_execution") {
                showToolCall(onToolCall, "shell", { command: event.item.command });
              }
              if (event.type === "item.completed" && event.item) {
                if (event.item.type === "agent_message" && event.item.text) {
                  resultText += event.item.text;
                  this.config.onThinking?.(event.item.text);
                } else if (event.item.type === "command_execution" && event.item.command) {
                  // Already shown on item.started
                }
              }

              // ── Pwnkit cloud-trace bridge (codex only) ──
              // Codex emits structured turn/tool/reasoning events on its
              // `--json` stream which we'd otherwise discard — translating
              // each one into a `PWNKIT_EVENT_*` line on our stdout fills
              // the dashboard's live-trace UI for the duration of Codex
              // source-analysis workflows.
              //
              // Guarded on `emitScanEvents` so non-codex runtimes and
              // non-cloud codex usage (e.g. local CLI `pwnkit scan
              // --runtime codex`) don't pay the bus serialisation cost.
              // `eventBus.emit` is a no-op when the cloud sink is not
              // subscribed (`PWNKIT_CLOUD_EVENTS` unset) so this is safe
              // to call unconditionally inside the guard.
              if (emitScanEvents) emitCodexCloudEvents(event);
            } catch {
              // Not valid JSON line, skip
            }
          }
        }
      });

      proc.stderr.on("data", (chunk: Buffer) => {
        const text = chunk.toString();
        stderr += text;

        // Detect MCP permission loop: if the subprocess keeps asking for
        // tool approval, kill it with a helpful error instead of looping
        if (/permission|approve|allow.*tool/i.test(stderr) && stderr.length > 500) {
          proc.kill("SIGTERM");
          stderr += "\n[pwnkit] Subprocess killed: MCP tools require interactive approval. Use --runtime api instead.";
        }
      });

      const timer = setTimeout(() => {
        timedOut = true;
        proc.kill("SIGTERM");
        setTimeout(() => proc.kill("SIGKILL"), 5_000);
      }, this.config.timeout);

      proc.on("close", (code) => {
        clearTimeout(timer);
        // For stream-json, use the parsed result text; otherwise raw stdout
        const output = isJsonStream ? (resultText || stdout).trim() : stdout.trim();
        resolve({
          output,
          exitCode: code,
          timedOut,
          durationMs: Date.now() - start,
          error: code !== 0 ? stderr.trim() || undefined : undefined,
        });
      });

      proc.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          output: "",
          exitCode: 1,
          timedOut: false,
          durationMs: Date.now() - start,
          error: err.message,
        });
      });
    });
  }

  async isAvailable(): Promise<boolean> {
    // Probe `<runtime> --version` with a single retry to absorb cold-start
    // variance. The fast happy path is unchanged (~ms on a warm host) but
    // the previous 5s single-shot deadline failed false-negative on
    // E2B-style ephemeral sandboxes: a freshly-booted container has cold
    // OS page-cache on /usr/local/bin/<runtime>, so the first exec pays
    // for the binary load + dynamic linker + the runtime's own startup,
    // which can exceed 5s for an ~80 MB Rust binary. Empirically observed
    // (2026-05-13 pwnkit-cloud rollout): same lodash audit dispatched
    // back-to-back where one sandbox succeeded and the next failed with
    // "Runtime 'codex' not available. Is codex installed?", correlating
    // with sandbox cold/warm state, not codex install state. After this
    // change the failure window is gone — total cap is ~20s, well under
    // any reasonable orchestrator-level dispatch timeout.
    const attempt = (timeoutMs: number): Promise<boolean> =>
      new Promise((resolve) => {
        const proc = spawn(this.command, ["--version"], {
          stdio: ["pipe", "pipe", "pipe"],
        });
        let settled = false;
        const finish = (ok: boolean) => {
          if (settled) return;
          settled = true;
          resolve(ok);
        };
        proc.on("close", (code) => finish(code === 0));
        proc.on("error", () => finish(false));
        setTimeout(() => {
          proc.kill();
          finish(false);
        }, timeoutMs).unref?.();
      });
    // First attempt: warm-path budget. If a runtime is installed and the
    // file cache is hot this returns true in well under a second.
    if (await attempt(5_000)) return true;
    // Retry with a generous deadline before declaring unavailable.
    // Catches cold-disk first-exec cost.
    return attempt(15_000);
  }

  private buildArgs(prompt: string, context?: RuntimeContext): string[] {
    switch (this.type) {
      case "claude": {
        const args = ["-p", prompt, "--verbose", "--output-format", "stream-json"];
        if (context?.mcp?.enableTargetTools && context.target && context.scanId) {
          // --dangerously-skip-permissions auto-approves MCP tool calls
          // without this, the subprocess hangs waiting for interactive approval
          args.push("--mcp-config", buildClaudeMcpConfig(context), "--dangerously-skip-permissions");
        }
        if (context?.systemPrompt) {
          args.push("--system-prompt", context.systemPrompt);
        }
        // Structured output schema for findings
        if (this.config.outputSchema) {
          args.push("--json-schema", JSON.stringify(this.config.outputSchema));
        }
        return args;
      }
      case "codex": {
        const args = [
          "exec",
          "--skip-git-repo-check",
          "--json",
        ];
        if (this.config.model) {
          args.push("--model", this.config.model);
        }
        if (context?.mcp?.enableTargetTools && context.target && context.scanId) {
          throw new Error(
            "Codex CLI MCP target tools are not supported. Use the direct ChatGPT Codex provider for live target scans.",
          );
        }
        if (this.config.outputSchema) {
          // Codex needs schema as a file — write to temp
          const schemaPath = join(tmpdir(), `pwnkit-schema-${Date.now()}.json`);
          writeFileSync(schemaPath, JSON.stringify(this.config.outputSchema));
          args.push("--output-schema", schemaPath);
        }
        args.push(prompt);
        return args;
      }
      case "gemini": {
        const args = ["-p", prompt, "--output-format", "stream-json"];
        return args;
      }
      default:
        return ["-p", prompt];
    }
  }

  private buildEnv(context?: RuntimeContext): Record<string, string> {
    const env: Record<string, string> = {
      ...this.config.env,
    };

    if (context?.target) {
      env.PWNKIT_TARGET = context.target;
    }
    if (context?.findings) {
      env.PWNKIT_FINDINGS = context.findings;
    }
    if (context?.templateId) {
      env.PWNKIT_TEMPLATE_ID = context.templateId;
    }
    if (context?.mcp?.auth) {
      env.PWNKIT_MCP_AUTH_JSON = JSON.stringify(context.mcp.auth);
    }
    if (context?.mcp?.attributionHeaders) {
      env.PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON = JSON.stringify(context.mcp.attributionHeaders);
    }
    if (context?.mcp?.attributionUaToken) {
      env.PWNKIT_MCP_ATTRIBUTION_UA_TOKEN = context.mcp.attributionUaToken;
    }

    return env;
  }
}
