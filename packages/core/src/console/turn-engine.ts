import { randomUUID } from "node:crypto";
import { realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, resolve, sep } from "node:path";

import { LlmApiRuntime } from "../runtime/llm-api.js";
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
  NativeStreamCallbacks,
  NativeToolDef,
  RuntimeConfig,
} from "../runtime/types.js";
import { ToolExecutor, getToolsForRole } from "../agent/tools.js";
import { TOOL_DISPATCH } from "../agent/tools/dispatch.js";
import {
  evaluateGuards,
  guardApprovalUnavailable,
  guardNetworkRequiresScope,
  guardUnresolvedCapabilities,
  type GuardContext,
  type ToolGuard,
} from "../plugins/guards.js";
import type { AgentRole, ScopedAuditEscalationRequest, ToolCall, ToolContext, ToolDefinition, ToolResult } from "../agent/types.js";
import type { ScopePolicy } from "../scope/scope.js";

/**
 * Unified interactive chat console — engine-side turn driver.
 *
 * This is the conversational front-end for the 0sec engine described in the
 * 0sec "operator cockpit" direction: one surface where an operator talks to the
 * engine and it can invoke every tool in the registry (recon, web pentest,
 * source-scan, variant-hunt, verify, patch-gen) in one place.
 *
 * It deliberately REUSES the engine's real components rather than re-building
 * them:
 *   - the real tool registry + dispatcher (`getToolsForRole` + `ToolExecutor`
 *     from `agent/tools.ts`),
 *   - the real LLM runtime (`LlmApiRuntime.executeNative` from
 *     `runtime/llm-api.ts`, the same native tool_use client the autonomous
 *     `runNativeAgentLoop` drives).
 *
 * What it adds is the thin turn-orchestration glue that `runNativeAgentLoop`
 * intentionally does NOT expose: a chat turn that runs the model + its tool
 * calls to a natural stop and then HANDS CONTROL BACK to the operator, keeping
 * the conversation history across operator turns. `runNativeAgentLoop` is a
 * one-shot autonomous scan (it terminates the whole run when the model calls
 * `done`), so its terminal semantics don't fit a "respond, then wait for me"
 * console. The inner turn cycle here mirrors that loop's cycle (executeNative →
 * dispatch tool_use via ToolExecutor → append tool_result → repeat) so the two
 * stay behaviourally aligned. See `console/repl.ts` for the CLI consumer.
 *
 * The session now supports in-memory, operator-approved scope expansion and
 * per-tool approval for the interactive surface. It never writes a scope file;
 * normal autonomous scan enforcement remains outside this console-specific
 * layer.
 */

/** Streaming + activity callbacks a renderer (CLI REPL, product UI) hooks into. */
export interface ConsoleRenderCallbacks {
  /** Incremental visible assistant text (SSE delta fragments, not cumulative). */
  onAssistantDelta?: (text: string) => void;
  /** Incremental hidden reasoning-summary text. */
  onReasoningDelta?: (text: string) => void;
  /** Fired just before a tool call is dispatched to the executor. */
  onToolStart?: (call: ToolCall) => void;
  /** Fired after a tool call resolves, with its result. */
  onToolResult?: (call: ToolCall, result: ToolResult) => void;
  /**
   * Live token accounting, fired ONCE PER MODEL CALL inside a turn (not only at
   * the end of the turn), so a renderer can show consumption ticking up against
   * the per-turn budget while the model is still working. See
   * {@link ConsoleUsageReport}.
   */
  onUsage?: (usage: ConsoleUsageReport) => void;
  /** Non-fatal operational notice (e.g. the turn ran out of token budget). */
  onNotice?: (message: string) => void;
}

/**
 * One live usage sample, emitted after every model call within a turn.
 *
 * `inputTokens`/`outputTokens` are the DELTA billed by the model call that just
 * completed (0 when the runtime reported no usage at all); the `turn*` fields
 * are the running totals for the whole turn measured against the budget in
 * force. Keeping the two delta fields first and required preserves structural
 * compatibility with the previous `{ inputTokens, outputTokens }` payload, so
 * an existing handler typed against the old shape still type-checks.
 */
export interface ConsoleUsageReport {
  /** Input tokens billed by the model call that just completed. */
  inputTokens: number;
  /** Output tokens billed by the model call that just completed. */
  outputTokens: number;
  /** Turn-cumulative input + output tokens, including this call. */
  turnTokensUsed: number;
  /** The per-turn token budget in force (`maxTurnTokens`). */
  turnTokenBudget: number;
  /** Tool-call rounds COMPLETED so far in this turn (0 on the first call). */
  iterations: number;
  /** The runaway iteration backstop in force (`maxToolIterations`). */
  maxToolIterations: number;
}

// ── Console autonomy / scope resolution (0sec console) ──

/**
 * Operator engagement mode for the console.
 * - `"standard"` (default): automatic tool execution inside known scope;
 *   scope-on-demand may request a narrow session-only extension when a
 *   network-capable tool references URLs outside the current scope. No
 *   per-tool approval prompts.
 * - `"copilot"`: same scope-on-demand as standard, plus requires per-tool
 *   approval for every non-read-only operation via `approveTool`.
 * - `"yolo"`: prompt-free execution only inside an explicit, nonempty
 *   preconfigured scope. It MUST NOT invoke scope approval or silently
 *   extend scope. Any missing or out-of-scope target is a hard denial.
 */
export type ConsoleAutonomyMode = "standard" | "copilot" | "yolo";

/**
 * Request payload passed to `ConsoleSessionConfig.requestScope` when a
 * network-capable tool call references URLs outside the current scope.
 * The callback may return a resolution (new target + scope) or null to deny.
 */
export interface ConsoleScopeRequest {
  /** The pending tool call that triggered this request. */
  call: ToolCall;
  /** URLs extracted from the tool call's arguments. */
  requestedUrls: string[];
  /**
   * Descriptions of network-reaching shell constructs whose destination could
   * NOT be resolved to a URL (`curl "$H"`, `… | sh`, `eval …`). Present only
   * for shell-payload tools. When this is non-empty the operator is being asked
   * to approve a call whose destination is UNKNOWN — the request carries the
   * full `call`, so the surface should show the actual command, not just
   * `requestedUrls` (which may be empty). Approving such a call means "I read
   * the command and I accept it", not "the scope covers it": nothing here can
   * be checked against `ScopePolicy`.
   */
  unresolvedTargets?: string[];
  /** Current session target (may be empty). */
  target: string;
  /** Current scope policy, if any. */
  currentScope?: ScopePolicy;
}

/**
 * Operator approval of an expanded scope.
 * Returned by `requestScope` to authorise the tool call.
 */
export interface ConsoleScopeResolution {
  /** Updated target (may be the same as the current one). */
  target: string;
  /** Scope policy covering the requested URLs. Never undefined on approval. */
  scope: ScopePolicy;
}

/**
 * Request payload passed to `ConsoleSessionConfig.requestLocalScope` when a
 * filesystem-scoped tool call (read_file/list_files/search_files/…) is issued
 * with no local scope covering the path it wants to touch. The local-scope
 * analogue of {@link ConsoleScopeRequest}: the operator approves an in-memory,
 * session-only directory subtree, or the callback returns null to deny.
 */
export interface ConsoleLocalScopeRequest {
  /** The pending tool call that triggered this request. */
  call: ToolCall;
  /**
   * The concrete filesystem path the tool asked to touch, already resolved to
   * an ABSOLUTE, symlink-resolved real path. This is exactly the path the
   * approval decision is made against — what the operator sees is what the
   * engine authorizes.
   */
  requestedPath: string;
  /** Current in-memory local scope directory, if any (absolute real path). */
  currentScopePath?: string;
}

/**
 * Operator approval of a local filesystem scope.
 * Returned by `requestLocalScope` to authorise the tool call. The approved
 * directory authorises that directory SUBTREE only; it is applied to the
 * session's in-memory tool context and NEVER written to disk.
 */
export interface ConsoleLocalScopeResolution {
  /** Absolute directory path the operator authorized (its subtree becomes readable). */
  scopePath: string;
}

/**
 * Why a single operator turn stopped.
 *
 * - `end_turn` — the model finished and handed control back (the normal path).
 * - `max_turn_tokens` — the turn's TOKEN BUDGET is exhausted. This is the
 *   primary cost guard and is NOT an error: the conversation is intact and the
 *   operator can simply send another message to continue (see
 *   {@link ConsoleTurnOutcome.budget} for the numbers to show them).
 * - `max_tool_iterations` — the runaway backstop tripped: the model kept asking
 *   for tools past a round count no legitimate investigation should reach.
 *   Distinct from `max_turn_tokens` on purpose, so a surface can say "something
 *   is looping" rather than "you ran out of budget".
 * - `error` — the LLM runtime failed.
 */
export type ConsoleStopReason =
  | "end_turn"
  | "max_tool_iterations"
  | "max_turn_tokens"
  | "error";

/**
 * What a turn consumed, against the limits that were in force for it. Carried
 * on every {@link ConsoleTurnOutcome} — including successful ones — so a
 * surface can render "used 780,000 of 2,000,000 tokens over 30 rounds" instead
 * of a bare stop message, and so a budget stop is a reportable, resumable state
 * rather than a dead end.
 */
export interface ConsoleTurnBudget {
  /** Total tokens (input + output) this turn consumed. */
  tokensUsed: number;
  /** The per-turn token budget that was in force (`maxTurnTokens`). */
  tokenBudget: number;
  /** Tool-call rounds completed in this turn. */
  iterations: number;
  /** The runaway iteration backstop that was in force (`maxToolIterations`). */
  maxToolIterations: number;
}

/** Outcome of one operator message (the model's reply + every tool it ran). */
export interface ConsoleTurnOutcome {
  assistantText: string;
  toolCalls: Array<{ call: ToolCall; result: ToolResult }>;
  usage: { inputTokens: number; outputTokens: number };
  /**
   * Consumption vs. the limits in force. Always present, whatever the stop
   * reason — the operator needs the numbers to decide whether to continue.
   */
  budget: ConsoleTurnBudget;
  stopReason: ConsoleStopReason;
  error?: string;
}

export interface ConsoleSessionConfig {
  /**
   * LLM client. Any `NativeRuntime` works (tests inject a stub); production
   * passes an `LlmApiRuntime`. Build one with {@link createConsoleRuntime}.
   */
  runtime: NativeRuntime;
  /**
   * Prior conversation to seed the session with. When provided, the session's
   * history starts as a DEFENSIVE COPY of these native messages instead of
   * empty, so a session can be rebuilt around a different runtime without
   * losing the engagement context. This is what makes an in-place `/model`
   * switch possible: the CLI tears down the old session and constructs a fresh
   * one over the new LLM client, replaying the existing `messages` so the model
   * change is invisible to the ongoing conversation. The copy means later
   * `send()` calls never mutate the array the caller passed in. When absent,
   * the session starts with empty history (unchanged behaviour).
   */
  initialMessages?: NativeMessage[];
  /**
   * Engagement target the tools operate against (same-origin checks, tool
   * context). Optional — a bare console can start target-less and the operator
   * can name targets in-conversation; target-scoped tools then return a
   * graceful error until a target is set.
   */
  target?: string;
  /**
   * Role whose tool set the console exposes. Defaults to `"audit"`, which maps
   * to the full "everything" registry (recon, web, source, patch, run_command,
   * …) — the cockpit wants every tool in one place.
   */
  role?: AgentRole;
  /** Explicit tool override; defaults to `getToolsForRole(role, …)`. */
  tools?: ToolDefinition[];
  /** Stable id for this console session (telemetry / future persistence). */
  scanId?: string;
  /**
   * RUNAWAY BACKSTOP on tool-call rounds within a single operator turn.
   * Defaults to {@link DEFAULT_MAX_TOOL_ITERATIONS}. This is deliberately no
   * longer the primary guard — {@link maxTurnTokens} is, because a round that
   * reads ten lines and one that reads a 5 MB file cost wildly different
   * amounts yet count identically here. Keep this only high enough to terminate
   * a pathological loop that somehow costs nothing (e.g. a runtime that reports
   * no usage, or tools that fail instantly). An explicitly supplied value is
   * honoured exactly and never overridden.
   */
  maxToolIterations?: number;
  /**
   * PRIMARY COST GUARD: the token budget (input + output, summed across every
   * model call) a single operator turn may consume. Defaults to
   * {@link DEFAULT_MAX_TURN_TOKENS}. Because every tool iteration resends the
   * whole conversation, turn cost grows superlinearly with tool count, so the
   * meaningful unit is tokens, not rounds.
   *
   * The turn stops when the accumulated usage has reached the budget, or when
   * the next model call would push it past — the last call's input tokens are a
   * conservative lower bound on the next call's, since the conversation only
   * grows. Independent of {@link maxToolIterations}: either guard can trip
   * first, and each is separately configurable.
   */
  maxTurnTokens?: number;
  /** Opt in to generic-scanner tool wrappers (sqlmap/nikto/…). Default off. */
  allowScanners?: boolean;
  /** System-prompt override. Defaults to {@link buildConsoleSystemPrompt}. */
  systemPrompt?: string;
  /**
   * Engagement mode: `"standard"` (default) automatically executes tools
   * inside known scope but uses scope-on-demand for out-of-scope network-
   * capable calls; `"copilot"` adds per-tool approval for non-read-only
   * operations; `"yolo"` requires a nonempty preconfigured scope and hard-
   * denies anything outside it without calling scope approval.
   */
  autonomyMode?: ConsoleAutonomyMode;
  /**
   * Pre-loaded scope policy. When absent, the session starts scopeless and
   * `requestScope` is invoked before the first network-capable tool call.
   * NEVER written to disk — in-memory only.
   */
  scope?: ScopePolicy;
  /**
   * Callback invoked when a network-capable tool call references URLs outside
   * the current scope (or scope is absent). Return a
   * {@link ConsoleScopeResolution} to approve with an updated target + scope,
   * or return null to deny the call. The resolution updates the session's
   * in-memory scope only — never rewrites a scope file.
   * When absent, the legacy readline console keeps its historical behavior.
   * The Bun/OpenTUI entrypoint always supplies this callback, so engagement
   * egress there remains scope-on-demand.
   */
  requestScope?: (req: ConsoleScopeRequest) => Promise<ConsoleScopeResolution | null>;
  /**
   * Callback invoked when a filesystem-scoped tool
   * (read_file/list_files/search_files/apply_patch/run_command/analyze_binary)
   * is issued and no in-memory local scope covers the path it wants to touch.
   * The local-filesystem analogue of {@link requestScope}: return a
   * {@link ConsoleLocalScopeResolution} to approve an in-memory directory
   * subtree, or return null to deny the call. The approved directory updates
   * the session's tool context only — it is NEVER written to a scope file.
   * When absent, behaviour is unchanged from the legacy readline console: the
   * tool simply returns its "requires a scoped local directory" error.
   */
  requestLocalScope?: (req: ConsoleLocalScopeRequest) => Promise<ConsoleLocalScopeResolution | null>;
  /**
   * Callback invoked before every non-read-only tool call in `"copilot"` mode.
   * Return true to allow the call, false to block with a "denied" result.
   * Ignored in `"yolo"` mode. When absent, non-read-only tools proceed without
   * confirmation (equivalent to `"yolo"` for the approval gate).
   */
  approveTool?: (call: ToolCall) => Promise<boolean>;
  /**
   * Invoked when a tool is blocked purely by the scoped-source-audit
   * allow-list (role `audit`/`review` with a local scope). Return true to
   * let it run for the rest of the session, false to deny and remember.
   *
   * This lifts ONE restriction; it is not a master key. Network scope,
   * local-filesystem scope and the co-pilot gate all still apply, and in
   * yolo mode the allow-list is lifted without prompting. When absent,
   * blocked tools hard-deny exactly as they always have.
   */
  escalateScopedAudit?: (req: ScopedAuditEscalationRequest) => Promise<boolean>;
}

/** A live console session: persistent history + a `send()` per operator line. */
export interface ConsoleSession {
  readonly scanId: string;
  readonly systemPrompt: string;
  readonly tools: ToolDefinition[];
  /** Full conversation so far (native content blocks). Grows with each turn. */
  readonly messages: NativeMessage[];
  /** Current autonomy mode (configurable at creation time). */
  readonly autonomyMode: ConsoleAutonomyMode;
  /** Current engagement target (may be updated by scope resolution). */
  readonly target: string;
  /** Current in-memory scope policy (never persisted to disk). */
  readonly scope: ScopePolicy | undefined;
  /**
   * Current in-memory local filesystem scope directory (absolute real path), or
   * undefined when none has been approved. Never persisted to disk.
   */
  readonly localScopePath: string | undefined;
  /** Switch autonomy without discarding the conversation or in-memory scope. */
  setAutonomyMode(mode: ConsoleAutonomyMode): void;
  /**
   * Clear all conversation messages while preserving session identity, target,
   * scope, autonomy mode, system prompt, tools, and executor resources.
   * The next call to {@link send} starts from an empty history.
   */
  clearConversation(): void;
  /** Run one operator message to a natural stop, streaming via `callbacks`. */
  send(userText: string, callbacks?: ConsoleRenderCallbacks): Promise<ConsoleTurnOutcome>;
  /** Release tool resources (browser/PTY) held by the executor. */
  cleanup(): Promise<void>;
}

/**
 * Runaway backstop for tool-call rounds in one turn.
 *
 * Raised from the original 20 because 20 was doing the job of a COST guard and
 * doing it badly: a real repo audit was cut off mid-investigation at 20 rounds
 * even though the model was making genuine progress. With
 * {@link DEFAULT_MAX_TURN_TOKENS} now holding the cost line, this number only
 * has to stop a loop that is somehow free — one where the runtime reports no
 * usage, or every tool fails instantly — so it is set well above any plausible
 * legitimate investigation depth (the observed real audit ran 30 rounds) while
 * still terminating a pathological loop in bounded time. In any realistic turn
 * the token budget trips long before this does.
 */
const DEFAULT_MAX_TOOL_ITERATIONS = 100;

/**
 * Default per-turn token budget (input + output across every model call).
 *
 * Calibrated against a real observed session: a repo audit that had run 30 tool
 * calls reported 779,532 input tokens in a single turn — and was still not
 * finished when the old 20-round cap dead-ended it. Because each iteration
 * resends the whole conversation, cumulative turn cost grows roughly with the
 * SQUARE of the round count, so 2,000,000 tokens (~2.5x the observed spend)
 * buys roughly sqrt(2.5) ~= 1.6x more rounds — around 45-50 — which is ample
 * headroom for that audit to reach a natural stop, while still bounding a
 * single turn to a knowable worst case (a few dollars at frontier input
 * pricing) instead of an open-ended one. It is a ceiling, not a target: a
 * normal conversational turn spends a tiny fraction of it.
 */
const DEFAULT_MAX_TURN_TOKENS = 2_000_000;

/**
 * Build the console persona system prompt. Distinct from the scan-role prompts
 * (`discoveryPrompt`/`attackPrompt`/…): this frames an interactive operator
 * cockpit rather than an autonomous hunt, and tells the model to answer the
 * operator directly and stop for input instead of driving to a `done` verdict.
 */
export function buildConsoleSystemPrompt(opts: {
  target?: string;
  scanId: string;
  autonomyMode?: ConsoleAutonomyMode;
}): string {
  const autonomyInstruction = opts.autonomyMode === "yolo"
    ? "YOLO mode: execute required in-scope tool calls without per-tool approval. Only targets within the explicit preconfigured scope are authorized; do not request scope extensions — out-of-scope targets are denied."
    : opts.autonomyMode === "copilot"
    ? "Co-pilot mode: explain each non-read-only action and wait for the operator approval gate before it runs."
    : "Standard mode: execute tools automatically within the current scope. When a target is not authorized, request a narrow scope extension and wait for the operator's decision.";
  return [
    "You are the 0sec operator console — an interactive security assistant with",
    "direct access to the full 0sec tool registry (reconnaissance, web pentest,",
    "source and package scanning, variant hunting, exploit verification, and",
    "patch generation).",
    "",
    "You are talking to a trusted operator on an authorized engagement. Work",
    "conversationally: use tools to investigate, report what you find in clear",
    "prose, and then STOP and wait for the operator's next instruction. Do not",
    "narrate a long autonomous plan — take the next concrete step, show the",
    "result, and hand control back.",
    "",
    "Call tools whenever they help; prefer real tool output over speculation.",
    autonomyInstruction,
    "",
    opts.target ? `Current target: ${opts.target}` : "No target is set yet; ask the operator for one when a tool needs it.",
    `Session id: ${opts.scanId}`,
  ].join("\n");
}

/**
 * Construct the production LLM client for the console and fail fast on a
 * misconfigured provider (missing API key, etc). Mirrors the pre-flight
 * `getConfigurationDiagnostics()` check `agent-runner.ts` runs before the
 * native loop.
 */
export function createConsoleRuntime(config?: Partial<RuntimeConfig>): LlmApiRuntime {
  const runtime = new LlmApiRuntime({
    type: "api",
    timeout: config?.timeout ?? 120_000,
    apiKey: config?.apiKey,
    model: config?.model,
    ...config,
  });
  const diagnostics = runtime.getConfigurationDiagnostics();
  if (!diagnostics.valid) {
    throw new Error(
      diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is not configured (no API key found).`,
    );
  }
  return runtime;
}

/** Convert a registry `ToolDefinition` to the runtime's native tool schema. */
function toNativeToolDef(tool: ToolDefinition): NativeToolDef {
  const properties: Record<string, unknown> = {};
  for (const [key, param] of Object.entries(tool.parameters)) {
    const prop: Record<string, unknown> = { type: param.type, description: param.description };
    if (param.enum) prop.enum = param.enum;
    properties[key] = prop;
  }
  return {
    name: tool.name,
    description: tool.description,
    input_schema: { type: "object", properties, required: tool.required ?? [] },
  };
}

/** Serialize a tool result into the string content of a `tool_result` block. */
function stringifyToolResult(result: ToolResult): string {
  if (!result.success) return result.error ?? "tool execution failed";
  return typeof result.output === "string" ? result.output : JSON.stringify(result.output);
}

// ── Console autonomy helpers ──

/** Tools that can perform engagement egress — scope resolution is required when configured. */
const NETWORK_CAPABLE_TOOLS: Record<string, true> = {
  http_request: true,
  send_prompt: true,
  crawl: true,
  submit_form: true,
  access_control_probe: true,
  browser: true,
  wp_fingerprint: true,
  discover_api_surface: true,
  surface_sweep: true,
  js_recon: true,
  bash: true,
  run_command: true,
  pty_session: true,
  python_exec: true,
  spawn_agent: true,
  spawn_agents: true,
  run_sqlmap: true,
  run_nmap: true,
  run_ffuf: true,
  run_nuclei: true,
  structural_sqli_probe: true,
  prompt_layer_probe: true,
  auth_boundary_probe: true,
  cloud_s3_probe: true,
  cloud_validate_credentials: true,
  start_scan: true,
  oast_register: true,
  oast_poll: true,
};

/** Tools that only read local state — exempt from copilot approval prompts. */
const READ_ONLY_TOOLS: Record<string, true> = {
  read_file: true,
  search_files: true,
  list_files: true,
  query_findings: true,
  list_skills: true,
  load_skill: true,
  intel_search_advisories: true,
  intel_lookup_cve: true,
  intel_search_similar: true,
  intel_build_dossier: true,
  payload_lookup: true,
  done: true,
};

/**
 * Tools whose handlers hard-require a scoped local directory (`ctx.scopePath`)
 * and fail without one. Derived from the tool registry, not guessed: these are
 * exactly the handlers in `agent/tools.ts` that early-return a
 * "requires a scoped local directory"-class error when `this.ctx.scopePath` is
 * unset —
 *   - read_file       (tools.ts readFile)
 *   - list_files      (tools.ts listFiles)
 *   - search_files    (tools.ts searchFiles)
 *   - apply_patch     (tools.ts applyPatch)
 *   - run_command     (tools.ts runCommand; also NETWORK_CAPABLE — both gates
 *                      compose, network first then local)
 *   - analyze_binary  (tools.ts analyzeBinary; "requires a local scoped source
 *                      root", feature-gated behind 0verse)
 * These are the same names the `SCOPED_SOURCE_AUDIT_TOOLS` registry marks as
 * the filesystem read surface (read_file/list_files/search_files/analyze_binary)
 * plus the two scoped write/exec tools (apply_patch/run_command). When one of
 * these is called with no covering local scope, the console asks the operator
 * for a directory instead of dead-ending — the local-filesystem mirror of the
 * NETWORK_CAPABLE_TOOLS scope-on-demand flow above.
 */
const LOCAL_SCOPE_TOOLS: Record<string, true> = {
  read_file: true,
  list_files: true,
  search_files: true,
  apply_patch: true,
  run_command: true,
  analyze_binary: true,
};

/**
 * Canonicalize an operator-facing or tool-requested path to an ABSOLUTE,
 * symlink-resolved real path. The deepest existing ancestor is passed through
 * `realpathSync` (resolving every symlink in the prefix — so a symlink can't be
 * used to make the operator approve one directory while the tool touches
 * another), then any not-yet-existing trailing segments are appended. Relative
 * inputs resolve against the process cwd ONLY to compute a concrete path to
 * SHOW the operator; nothing is authorized without explicit approval, so this
 * is not an implicit grant of the cwd. Throws when no ancestor exists.
 */
function canonicalizeRealPath(input: string): string {
  const abs = isAbsolute(input) ? resolve(input) : resolve(process.cwd(), input);
  const missing: string[] = [];
  let existing = abs;
  for (;;) {
    try {
      existing = realpathSync(existing);
      break;
    } catch {
      const parent = dirname(existing);
      if (parent === existing) {
        throw new Error(`Path has no existing ancestor: ${input}`);
      }
      missing.unshift(basename(existing));
      existing = parent;
    }
  }
  return missing.length > 0 ? resolve(existing, ...missing) : existing;
}

/**
 * Whether `child` lies within the `parent` directory subtree (or IS it). Both
 * must already be canonicalized absolute real paths. The `parent + sep` guard
 * defeats the sibling-prefix trap: `/a/bc` is NOT within `/a/b`.
 */
function isWithinDir(child: string, parent: string): boolean {
  return child === parent || child.startsWith(parent + sep);
}

/**
 * Whether `dir` (a canonicalized real path) is a root too dangerous to ever
 * offer as a scan scope: the filesystem root itself (or any drive/mount root,
 * detected as a path that is its own parent) and the user's home directory
 * itself. Subdirectories of home (e.g. `~/code/proj`) are fine — only the bare
 * home root is refused, so a stray `.` / `~` approval can't hand the tools the
 * operator's entire home tree.
 */
function isDangerousLocalRoot(dir: string): boolean {
  if (dirname(dir) === dir) return true;
  try {
    if (dir === realpathSync(homedir())) return true;
  } catch {
    // homedir unresolvable — fall through; the root check above still applies.
  }
  return false;
}

/**
 * The concrete path a filesystem-scoped tool wants to touch, pulled from its
 * arguments. read_file/list_files/search_files use `path`; run_command uses
 * `cwd`; apply_patch carries its targets inside the patch envelope and
 * analyze_binary uses `binary_path`. When nothing path-like is present we fall
 * back to "." so the operator is still asked about a concrete directory.
 */
function extractLocalPath(call: ToolCall): string {
  const args = (call.arguments ?? {}) as Record<string, unknown>;
  for (const key of ["path", "cwd", "binary_path"]) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return ".";
}

/**
 * Parse a URL's hostname as a normalized lowercase string for scope-decision
 * memory. Returns null when the URL cannot be parsed — callers MUST fail safe
 * on null (never record it in, nor match it against, the denied set) so an
 * unparseable URL can neither poison the denied set nor be mistaken for a
 * previously-declined host.
 */
function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// ── Target extraction from tool arguments ──
//
// HONEST LIMIT — READ THIS BEFORE TRUSTING ANYTHING BELOW.
//
// A regex (or a hand-rolled tokenizer) over a shell command CANNOT be a
// security boundary, and this code does not pretend to be one. A shell command
// is a program in a Turing-complete language whose destination is decided at
// RUNTIME, not at parse time. Every one of these defeats the extractor below,
// trivially and by design of the shell, not by a bug here:
//
//   H=evil.example; curl "$H"          — variable indirection
//   curl $(cat /tmp/h)                 — command substitution
//   echo Y3VybCBldmls | base64 -d | sh — encoded payload piped to a shell
//   python3 -c 'import socket; ...'    — any interpreter with a socket API
//   curl -K /tmp/cfg                   — destination read from a config file
//   ./fetch.sh                         — a script whose contents we never see
//   printf '\\x63url evil.example' | sh — escaped/obfuscated program name
//
// So the extractor is DEFENCE IN DEPTH, not ENFORCEMENT. Its job is to raise
// the cost of an accidental or lazily-constructed out-of-scope call and to give
// the operator something concrete to approve. The ACTUAL enforcement decision
// lives in `maybeResolveScope`: when a network-capable tool carries a shell
// payload whose destination we could NOT resolve, the call is escalated to the
// operator (standard/copilot) or denied (yolo) instead of being approved by
// default. "We did not find a URL" must never again mean "there is no URL".
//
// Real enforcement, if it is ever wanted, has to happen where the syscalls
// happen: a network namespace, a filtering proxy the tools are forced through,
// or a seccomp/LSM policy. None of that is in this file.

/**
 * Tools whose arguments are (or contain) a shell command line — the payload
 * class the schemeless extraction below understands, and the ONLY class the
 * unresolved-target escalation in `maybeResolveScope` applies to. Structured
 * tools (`http_request`, `crawl`, `read_file`, …) keep their previous
 * behaviour exactly: explicit `http(s)://` extraction plus the session-target
 * fallback.
 *
 * `python_exec` is deliberately NOT here: its payload is Python, not shell, so
 * the shell tokenizer would produce noise rather than signal. That is a known
 * residual hole (see the honesty note above) — it is covered only by the
 * yolo-requires-scope floor, not by target extraction.
 */
const SHELL_PAYLOAD_TOOLS: Record<string, true> = {
  bash: true,
  run_command: true,
  pty_session: true,
};

/**
 * Programs that speak to the network with a destination in argv. A bare
 * `host`, `host:port` or `host/path` argument to one of these is treated as an
 * engagement target even without a scheme. Restricting schemeless host
 * detection to these argument windows is the central FALSE-POSITIVE control:
 * scanning every shell token for "something with a dot in it" would classify
 * `package.json`, `app.ts` and `README.md` as hosts.
 */
const NETWORK_CLIENTS: Record<string, true> = {
  curl: true,
  wget: true,
  wget2: true,
  nc: true,
  ncat: true,
  netcat: true,
  socat: true,
  ssh: true,
  scp: true,
  sftp: true,
  rsync: true,
  ftp: true,
  telnet: true,
  dig: true,
  nslookup: true,
  host: true,
  ping: true,
  ping6: true,
  openssl: true,
};

/**
 * Clients whose remote operand is a `[user@]host:path` / `host::module` spec.
 * For these, a token is only read as a host when it carries `@` or `:` — the
 * syntax that actually makes it remote. Without this, `scp report.txt srv:/tmp`
 * would report `report.txt` as a target host.
 */
const REMOTE_SPEC_CLIENTS: Record<string, true> = { scp: true, sftp: true, rsync: true };

/** Clients that take a bare positional port after the host (`nc host 443`). */
const PORT_POSITIONAL_CLIENTS: Record<string, true> = {
  nc: true,
  ncat: true,
  netcat: true,
  telnet: true,
};

/** Command prefixes that wrap another command; the real program follows. */
const COMMAND_WRAPPERS: Record<string, true> = {
  sudo: true,
  doas: true,
  env: true,
  time: true,
  timeout: true,
  nohup: true,
  nice: true,
  ionice: true,
  stdbuf: true,
  command: true,
  builtin: true,
  exec: true,
  xargs: true,
  then: true,
  do: true,
  else: true,
};

/** Interpreters that execute whatever text is piped into them. */
const SHELL_INTERPRETERS: Record<string, true> = {
  sh: true,
  bash: true,
  zsh: true,
  dash: true,
  ksh: true,
  python: true,
  python3: true,
  perl: true,
  ruby: true,
  node: true,
};

/**
 * Flags whose NEXT token is a value, not a destination. Skipping them stops
 * `curl -d @payload.json host` from reporting `payload.json` as a host. The set
 * is a union across clients on purpose: over-skipping can only LOSE a host,
 * which downgrades the call to "unresolved" and still gates it, whereas
 * under-skipping invents targets the operator then has to reject.
 */
const VALUE_FLAGS: Record<string, true> = {
  "-H": true, "--header": true,
  "-d": true, "--data": true, "--data-raw": true, "--data-binary": true, "--data-urlencode": true,
  "--post-data": true, "--post-file": true,
  "-o": true, "--output": true, "-O": true, "--output-document": true,
  "-u": true, "--user": true, "--proxy-user": true,
  "-X": true, "--request": true,
  "-A": true, "--user-agent": true, "-U": true,
  "-b": true, "--cookie": true, "-c": true, "--cookie-jar": true,
  "-e": true, "--referer": true,
  "-F": true, "--form": true,
  "-T": true, "--upload-file": true, "--timeout": true,
  "-x": true, "--proxy": true,
  "-m": true, "--max-time": true, "--connect-timeout": true, "--retry": true,
  "-w": true, "--write-out": true,
  "-K": true, "--config": true,
  "--cacert": true, "--cert": true, "--key": true,
  "-p": true, "-l": true, "-P": true,
};

/** Flags whose next token IS the destination. */
const TARGET_VALUE_FLAGS: Record<string, true> = {
  "--url": true,
  "-connect": true,
  "--connect": true,
  "--connect-to": true,
};

/** `>/dev/tcp/host/port` — bash's built-in socket, no external binary needed. */
const DEV_SOCKET_RE = /\/dev\/(?:tcp|udp)\/([^\s/'"`;|&()<>]+)\/(\d{1,5})/gi;

/** A bare IPv4 literal (optionally `:port` and `/path`), not part of a longer word. */
const BARE_IPV4_RE =
  /(?<![\w.-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?::(\d{1,5}))?((?:\/[^\s'"`<>|;&)]*)?)(?![\w.-])/g;

/** A bracketed IPv6 literal (`[::1]`, `[2001:db8::1]:8443`). */
const BRACKET_IPV6_RE = /\[([0-9a-f:]{2,}(?:%[0-9a-z]+)?)\](?::(\d{1,5}))?/gi;

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[0-9a-z]+)?$/i;
const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)+$/i;

/** A destination recovered from a shell token. */
interface ParsedHost {
  host: string;
  ipv6: boolean;
  port?: number;
  path?: string;
}

/** Bound a payload fragment before it is embedded in an operator-facing reason. */
function truncateForReason(text: string, max = 80): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`;
}

/** The program name of a command token (`/usr/bin/curl` → `curl`). */
function programName(token: string): string {
  const cleaned = token.replace(/^\.\//, "");
  const slash = cleaned.lastIndexOf("/");
  return (slash >= 0 ? cleaned.slice(slash + 1) : cleaned).toLowerCase();
}

/**
 * Interpret one shell token as a network destination, or return null when it is
 * not host-shaped. Accepts `host`, `host:port`, `host/path`, `user@host`,
 * `user@host:/path`, `[v6]:port` and bare IPv4/IPv6 literals. A single-label
 * name is rejected (it is far more likely a file or a subcommand) with the sole
 * exception of `localhost`.
 */
function parseHostToken(rawToken: string): ParsedHost | null {
  let token = rawToken.trim();
  if (!token || token.startsWith("-")) return null;
  // A token that still carries a scheme is handled by the URL regex; report it
  // as "resolved" to the caller without duplicating it.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) return null;
  // Strip userinfo (`user:pass@host`).
  const at = token.lastIndexOf("@");
  if (at >= 0) token = token.slice(at + 1);
  if (!token) return null;

  // Bracketed IPv6 first — its colons are not a port separator.
  const bracket = token.match(/^\[([^\]]+)\](?::(\d{1,5}))?(\/.*)?$/);
  if (bracket) {
    const inner = bracket[1];
    if (!IPV6_RE.test(inner)) return null;
    return { host: inner.toLowerCase(), ipv6: true, port: clampPort(bracket[2]), path: bracket[3] };
  }

  // Bare IPv6 (two or more colons and nothing but hex/colon characters).
  const beforeSlashV6 = token.split("/")[0];
  if ((beforeSlashV6.match(/:/g) ?? []).length >= 2 && IPV6_RE.test(beforeSlashV6)) {
    return { host: beforeSlashV6.toLowerCase(), ipv6: true };
  }

  // Split off a path, then a `:port` or an rsync `::module` / scp `:path`.
  const slash = token.indexOf("/");
  let authority = slash >= 0 ? token.slice(0, slash) : token;
  const path = slash >= 0 ? token.slice(slash) : undefined;
  let port: number | undefined;
  const colon = authority.indexOf(":");
  if (colon >= 0) {
    const tail = authority.slice(colon + 1);
    authority = authority.slice(0, colon);
    if (/^\d{1,5}$/.test(tail)) port = clampPort(tail);
  }
  const host = authority.toLowerCase();
  if (!host) return null;
  if (IPV4_RE.test(host)) return { host, ipv6: false, port, path };
  if (host === "localhost") return { host, ipv6: false, port, path };
  if (!HOSTNAME_RE.test(host)) return null;
  // Require an alphabetic, >=2 char final label so `1.2.3` / `v1.0` are not hosts.
  const last = host.slice(host.lastIndexOf(".") + 1);
  if (!/^[a-z]{2,}$/.test(last)) return null;
  return { host, ipv6: false, port, path };
}

function clampPort(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : undefined;
}

/**
 * Normalize a recovered destination into a URL `ScopePolicy.match` can parse.
 * The scheme is cosmetic — the policy only ever reads the hostname — but it has
 * to be present and the host has to be bracketed when it is IPv6, or `new URL`
 * throws and the policy fails closed on a target we actually did resolve.
 */
function hostToUrl(parsed: ParsedHost): string {
  const authority = parsed.ipv6 ? `[${parsed.host}]` : parsed.host;
  const scheme = parsed.port === 80 || parsed.port === 8080 ? "http" : "https";
  const port = parsed.port !== undefined ? `:${parsed.port}` : "";
  const path = parsed.path ?? "";
  const url = `${scheme}://${authority}${port}${path}`;
  try {
    // Round-trip so an unparseable synthesis never reaches the policy.
    new URL(url);
    return url;
  } catch {
    return `${scheme}://${authority}`;
  }
}

/** Shell separators the tokenizer emits as standalone tokens. */
function isSeparator(token: string): boolean {
  return token === "|" || token === "||" || token === "&" || token === "&&" ||
    token === ";" || token === ";;" || token === "\n";
}

/**
 * Split a shell payload into tokens, honouring single/double quotes and
 * emitting `| || & && ; \n` as separators. A quoted run that contains spaces is
 * preserved as ONE token, which is what lets the scanner recurse into
 * `bash -c '…'` bodies.
 */
function shellTokens(payload: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let started = false;
  let quote: '"' | "'" | null = null;
  const flush = () => {
    if (started) {
      tokens.push(current);
      current = "";
      started = false;
    }
  };
  for (let i = 0; i < payload.length; i++) {
    const ch = payload[i];
    if (quote) {
      if (ch === quote) { quote = null; continue; }
      if (quote === '"' && ch === "\\" && i + 1 < payload.length) { current += payload[++i]; started = true; continue; }
      current += ch;
      started = true;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; started = true; continue; }
    if (ch === "\n") { flush(); tokens.push("\n"); continue; }
    if (ch === " " || ch === "\t" || ch === "\r") { flush(); continue; }
    if (ch === "|" || ch === "&" || ch === ";") {
      flush();
      let op = ch;
      while (i + 1 < payload.length && payload[i + 1] === ch) { op += payload[++i]; }
      tokens.push(op);
      continue;
    }
    current += ch;
    started = true;
  }
  flush();
  return tokens;
}

/** Accumulator threaded through the shell scan. */
interface ShellScanSink {
  urls: Set<string>;
  unresolved: Set<string>;
}

/**
 * Read one network client's argument window (up to the next separator) and add
 * every destination it names. When the window names none — `curl "$H"`,
 * `wget -i list.txt`, a destination hidden behind a substitution — the client is
 * recorded as UNRESOLVED so the caller escalates instead of approving.
 */
function scanClientWindow(program: string, window: string[], sink: ShellScanSink): void {
  if (program === "openssl" && !window.some((t) => t === "s_client" || t === "s_time")) {
    // `openssl rand`, `openssl x509`, … are not network clients.
    return;
  }
  const remoteSpecOnly = REMOTE_SPEC_CLIENTS[program] === true;
  let found = 0;
  for (let i = 0; i < window.length; i++) {
    const token = window[i];
    const eq = token.match(/^(--[a-z][a-z0-9-]*)=(.*)$/i);
    if (eq && TARGET_VALUE_FLAGS[eq[1].toLowerCase()]) {
      const parsed = parseHostToken(eq[2]);
      if (parsed) { sink.urls.add(hostToUrl(parsed)); found += 1; }
      else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(eq[2])) found += 1;
      continue;
    }
    if (TARGET_VALUE_FLAGS[token.toLowerCase()]) {
      const value = window[++i];
      if (value !== undefined) {
        const parsed = parseHostToken(value);
        if (parsed) { sink.urls.add(hostToUrl(parsed)); found += 1; }
        else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) found += 1;
      }
      continue;
    }
    if (token.startsWith("-")) {
      if (VALUE_FLAGS[token]) i += 1;
      continue;
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue;
    if (/^\d+$/.test(token)) continue;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) { found += 1; continue; }
    if (remoteSpecOnly && !token.includes("@") && !token.includes(":")) continue;
    const parsed = parseHostToken(token);
    if (!parsed) continue;
    // `nc host 443` / `telnet host 23`: a bare number right after the host is
    // the port, not another argument.
    if (
      parsed.port === undefined &&
      PORT_POSITIONAL_CLIENTS[program] &&
      i + 1 < window.length &&
      /^\d{1,5}$/.test(window[i + 1])
    ) {
      parsed.port = clampPort(window[i + 1]);
      i += 1;
    }
    sink.urls.add(hostToUrl(parsed));
    found += 1;
  }
  if (found === 0) {
    sink.unresolved.add(
      `"${program}" is invoked with no destination this gate can read (${truncateForReason([program, ...window].join(" "))})`,
    );
  }
}

/**
 * Scan a shell payload for engagement destinations and for constructs that hide
 * one. Recurses into quoted sub-commands (`bash -c '…'`) up to a small depth.
 *
 * This is best-effort pattern recognition, NOT parsing and NOT enforcement —
 * see the honesty note at the top of this section.
 */
function scanShellPayload(payload: string, sink: ShellScanSink, depth = 0): void {
  if (depth > 3 || !payload) return;

  // bash's built-in socket: `exec 3<>/dev/tcp/host/port`.
  for (const match of payload.matchAll(DEV_SOCKET_RE)) {
    const parsed = parseHostToken(`${match[1]}:${match[2]}`);
    if (parsed) sink.urls.add(hostToUrl(parsed));
    else sink.unresolved.add(`a /dev/tcp socket to an unreadable host (${truncateForReason(match[0])})`);
  }

  // Bare IP literals anywhere in the payload — high signal, and not confusable
  // with a filename the way a bare hostname is.
  for (const match of payload.matchAll(BARE_IPV4_RE)) {
    sink.urls.add(hostToUrl({ host: match[1], ipv6: false, port: clampPort(match[2]), path: match[3] || undefined }));
  }
  for (const match of payload.matchAll(BRACKET_IPV6_RE)) {
    if (!IPV6_RE.test(match[1])) continue;
    sink.urls.add(hostToUrl({ host: match[1].toLowerCase(), ipv6: true, port: clampPort(match[2]) }));
  }

  const tokens = shellTokens(payload);
  let commandPosition = true;
  let afterPipe = false;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (isSeparator(token)) {
      afterPipe = token === "|" || token === "||";
      commandPosition = true;
      continue;
    }
    if (commandPosition) {
      if (token.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue;
      if (/\s/.test(token)) {
        // A whole quoted command sat in command position (`sh -c` with the
        // body quoted as one word, `xargs "curl host"`, …).
        commandPosition = false;
        afterPipe = false;
        scanShellPayload(token, sink, depth + 1);
        continue;
      }
      const program = programName(token);
      if (COMMAND_WRAPPERS[program]) continue;
      commandPosition = false;
      const window: string[] = [];
      for (let j = i + 1; j < tokens.length && !isSeparator(tokens[j]); j++) window.push(tokens[j]);

      if (afterPipe && SHELL_INTERPRETERS[program]) {
        sink.unresolved.add(`output is piped into "${program}", which executes text this gate never sees`);
      }
      if (program === "eval") {
        sink.unresolved.add(`"eval" executes a string this gate cannot resolve (${truncateForReason(window.join(" "))})`);
      }
      if (program === "base64" && window.some((t) => t === "-d" || t === "-D" || t === "--decode")) {
        sink.unresolved.add(`"base64 --decode" hides the payload from this gate`);
      }
      if (NETWORK_CLIENTS[program]) scanClientWindow(program, window, sink);
      afterPipe = false;
      continue;
    }
    // A quoted sub-command (`sh -c 'curl evil.example'`) survives tokenization
    // as one token containing whitespace; scan it as a payload in its own right.
    if (/\s/.test(token)) scanShellPayload(token, sink, depth + 1);
  }
}

/** What the scope gate learned about a pending tool call. */
interface ToolTargets {
  /** Destinations normalized to URLs, ready for `ScopePolicy.match`. */
  urls: string[];
  /**
   * Human-readable descriptions of shell constructs that reach the network (or
   * execute opaque text) WITHOUT naming a destination this gate could read.
   * Non-empty means "we do not know where this goes" — which is precisely the
   * case that must not be silently approved.
   */
  unresolved: string[];
  /** The raw shell payloads seen, used as the key for declined-payload memory. */
  shellPayloads: string[];
}

/**
 * Extract candidate targets from nested tool arguments.
 *
 * Structured (non-shell) tools behave exactly as before: explicit `http(s)://`
 * URLs, plus the session target as a fallback when nothing was found — correct
 * for `crawl`/`surface_sweep`/… which really do operate on the session target.
 *
 * Shell-payload tools additionally get schemeless extraction, and deliberately
 * DROP the session-target fallback: substituting the session target for a shell
 * command validated a host the command was never going to contact, which made
 * the gate look like it had done its job when it had not.
 */
function extractToolTargets(call: ToolCall, target: string): ToolTargets {
  const urls = new Set<string>();
  const unresolved = new Set<string>();
  const shellPayloads: string[] = [];
  const shellShaped = SHELL_PAYLOAD_TOOLS[call.name] === true;

  const visit = (value: unknown) => {
    if (typeof value === "string") {
      if (/^https?:\/\//i.test(value)) urls.add(value);
      for (const embedded of value.match(/https?:\/\/[^\s'"`<>|]+/gi) ?? []) urls.add(embedded);
      if (shellShaped && value.trim()) {
        shellPayloads.push(value);
        scanShellPayload(value, { urls, unresolved });
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (value && typeof value === "object") {
      for (const item of Object.values(value as Record<string, unknown>)) visit(item);
    }
  };
  visit(call.arguments);

  if (
    !shellShaped &&
    urls.size === 0 &&
    unresolved.size === 0 &&
    target.trim() &&
    NETWORK_CAPABLE_TOOLS[call.name]
  ) {
    urls.add(target);
  }
  return { urls: [...urls], unresolved: [...unresolved], shellPayloads };
}

/**
 * Create an interactive console session over the real tool registry + runtime.
 *
 * The returned session holds conversation history in memory; each `send()`
 * runs the model and its tool calls to a natural stop and returns control.
 */
export function createConsoleSession(config: ConsoleSessionConfig): ConsoleSession {
  const scanId = config.scanId ?? `console-${randomUUID()}`;
  const role: AgentRole = config.role ?? "audit";
  let autonomyMode: ConsoleAutonomyMode = config.autonomyMode ?? "standard";

  // In-memory mutable scope state — updated by requestScope, NEVER written
  // to disk.
  let sessionTarget = config.target ?? "";
  let sessionScope: ScopePolicy | undefined = config.scope;

  // Session-scoped memory of hosts the operator explicitly DECLINED via
  // requestScope. In-memory only, per session — NEVER persisted to a scope
  // file. Once a host is recorded here, further tool calls that touch it are
  // denied outright without re-prompting, so a single rejection can't turn
  // into an unbounded re-prompt loop when the model retries the same target.
  const deniedHosts = new Set<string>();

  // Session-scoped memory of SHELL PAYLOADS the operator declined when this
  // gate could not resolve their destination. An unresolved destination has no
  // hostname, so `deniedHosts` cannot hold it; keying on the exact command text
  // is what stops a retried `curl "$H"` from re-prompting on every round.
  // In-memory only, per session — never persisted.
  const deniedShellPayloads = new Set<string>();

  // In-memory, session-only local filesystem scope — the directory subtree the
  // operator authorized via requestLocalScope. Starts unset (the console never
  // grants a scope implicitly); NEVER written to disk.
  let sessionScopePath: string | undefined;

  // Session-scoped memory of local paths the operator explicitly DECLINED via
  // requestLocalScope. In-memory only, per session. Once a path is recorded
  // here, a later tool call whose requested path falls inside that declined
  // directory is denied outright without re-prompting — the filesystem mirror
  // of `deniedHosts`, guarding against the same re-prompt loop when the model
  // retries the same (or a covered) path.
  const deniedLocalPaths = new Set<string>();

  const toolContext: ToolContext = {
    target: sessionTarget,
    scanId,
    role,
    findings: [],
    attackResults: [],
    targetInfo: {},
    allowScanners: config.allowScanners,
    scope: sessionScope,
    // The executor re-reads these per call, so a mid-session /mode switch
    // changes what is dispatchable without rebuilding anything. Escalation
    // lifts ONLY the scoped-source-audit allow-list — the network, local
    // filesystem and co-pilot gates in this file still run first.
    autonomyMode,
    escalateScopedAudit: config.escalateScopedAudit,
  };

  // The real dispatcher over the real registry. `db = null` → no persistence
  // this pass (findings live in `toolContext.findings` for the session).
  const executor = new ToolExecutor(toolContext);

  const tools =
    config.tools ?? getToolsForRole(role, { allowScanners: config.allowScanners });
  const nativeTools = tools.map(toNativeToolDef);

  const customSystemPrompt = config.systemPrompt;
  let systemPrompt = customSystemPrompt ??
    buildConsoleSystemPrompt({ target: sessionTarget, scanId, autonomyMode });
  // Both guards are resolved with `??` only: an explicitly supplied value —
  // including a deliberately tiny one — is honoured EXACTLY and never clamped
  // or overridden. They are independent; whichever is reached first stops the
  // turn.
  const maxToolIterations = config.maxToolIterations ?? DEFAULT_MAX_TOOL_ITERATIONS;
  const maxTurnTokens = config.maxTurnTokens ?? DEFAULT_MAX_TURN_TOKENS;

  // Seed conversation history. A caller rebuilding the session (e.g. an
  // in-place `/model` switch) passes the prior `messages` here; we take a
  // defensive deep copy so the session owns its own history and later `send()`
  // mutations never leak back into the array the caller still holds. Absent
  // seed → empty history, identical to the original behaviour. The seeded
  // turns are treated as ordinary prior conversation — never re-validated or
  // filtered beyond whatever `send()` already does.
  const messages: NativeMessage[] = config.initialMessages
    ? structuredClone(config.initialMessages)
    : [];

  // Resolve scope for a network-capable tool call, or return a "denied"
  // ToolResult. In yolo mode, missing/uncovered scope is a hard denial
  // without invoking requestScope. When requestScope is absent, fall
  // through — the existing validateTargetUrl inside ToolExecutor governs
  // (no scope → same-origin OK).
  async function maybeResolveScope(
    call: ToolCall,
  ): Promise<"approved" | ToolResult> {
    if (!NETWORK_CAPABLE_TOOLS[call.name]) return "approved";

    const { urls, unresolved, shellPayloads } = extractToolTargets(call, sessionTarget);

    // Nothing to decide about: no destination was named AND nothing in the call
    // reaches the network in a way this gate could not read. This is the branch
    // that keeps `bash echo hello`, `read_file`, and every other ordinary local
    // call prompt-free — the escalation below is driven by evidence of network
    // reach, never by mere membership in NETWORK_CAPABLE_TOOLS.
    if (urls.length === 0 && unresolved.length === 0) return "approved";

    // Check if every extracted URL is already covered by the current scope. An
    // unresolved destination can NEVER be "covered": there is nothing to match
    // a policy against, so scope coverage cannot discharge it.
    const allCovered = urls.every((url) => sessionScope?.match(url).allowed);
    if (allCovered && unresolved.length === 0) return "approved";

    // In yolo mode, missing or out-of-scope targets are a hard denial
    // without invoking requestScope — enforced even when no requestScope
    // callback is configured. An unreadable destination is denied on the same
    // principle: yolo means "no prompts INSIDE an authorized scope", and a
    // destination nobody can name is not inside anything.
    if (autonomyMode === "yolo") {
      const reason = !sessionScope
        ? `YOLO mode: no scope configured — tool "${call.name}" cannot run without an explicit preconfigured scope.`
        : allCovered
        ? `YOLO mode: tool "${call.name}" reaches the network with a destination this gate cannot resolve (${unresolved.join("; ")}) — denied.`
        : `YOLO mode: target ${urls.join(", ")} is outside the configured scope — tool "${call.name}" denied.`;
      return {
        success: false,
        output: null,
        error: reason,
      };
    }

    // For standard/copilot modes: if no requestScope callback is configured,
    // fall through to the executor's own validateTargetUrl (no scope →
    // same-origin OK).
    const requestScope = config.requestScope;
    if (!requestScope) return "approved";

    // A shell payload the operator already refused must not re-prompt — the
    // same unbounded-re-prompt guard `deniedHosts` provides for named hosts.
    // Keyed on the exact payload text because an unresolved destination has no
    // host to key on.
    if (unresolved.length > 0) {
      const refused = shellPayloads.find((payload) => deniedShellPayloads.has(payload));
      if (refused !== undefined) {
        return {
          success: false,
          output: null,
          error: `Scope request for tool "${call.name}" denied — this command was already declined by the operator this session; not prompting again.`,
        };
      }
    }

    // Hosts the operator already declined this session must not trigger a fresh
    // prompt — that re-prompt loop is exactly the bug this guards against. Only
    // URLs not already covered by the current scope are candidates for a new
    // request; of those, if ANY host was previously declined we deny the whole
    // call without prompting rather than silently dropping the declined host
    // from a call the model explicitly asked for. Unparseable URLs yield a null
    // host and are ignored here so they can't be mistaken for a declined one.
    const uncoveredUrls = urls.filter((url) => !sessionScope?.match(url).allowed);
    const previouslyDenied = uncoveredUrls.filter((url) => {
      const host = hostOf(url);
      return host !== null && deniedHosts.has(host);
    });
    if (previouslyDenied.length > 0) {
      return {
        success: false,
        output: null,
        error: `Scope request for tool "${call.name}" denied — ${previouslyDenied.join(", ")} was already declined by the operator this session; not prompting again.`,
      };
    }

    // URLs are not covered — ask the operator for approval.
    const resolution = await requestScope({
      call,
      requestedUrls: urls,
      ...(unresolved.length > 0 ? { unresolvedTargets: unresolved } : {}),
      target: sessionTarget,
      currentScope: sessionScope,
    });

    if (!resolution) {
      // Remember every requested host so a retry of the same (or an
      // overlapping) target is denied outright above instead of re-prompting.
      // Unparseable URLs contribute no host (fail safe — see hostOf).
      for (const url of urls) {
        const host = hostOf(url);
        if (host !== null) deniedHosts.add(host);
      }
      // An unreadable destination contributes no host, so remember the payload
      // itself; otherwise a retried `curl "$H"` would re-prompt forever.
      if (unresolved.length > 0) {
        for (const payload of shellPayloads) deniedShellPayloads.add(payload);
      }
      return {
        success: false,
        output: null,
        error: `Scope request denied for tool "${call.name}" — operator declined to expand scope.`,
      };
    }
    if (!resolution.target.trim()) {
      return {
        success: false,
        output: null,
        error: `Scope request for tool "${call.name}" returned an empty target.`,
      };
    }

    const uncovered = urls.filter((url) => !resolution.scope.match(url).allowed);
    if (uncovered.length > 0) {
      return {
        success: false,
        output: null,
        error: `Scope approval for tool "${call.name}" does not cover ${uncovered.join(", ")}.`,
      };
    }

    // Apply the resolution: update in-memory target + scope (never persist).
    sessionTarget = resolution.target;
    sessionScope = resolution.scope;
    toolContext.target = resolution.target;
    toolContext.scope = resolution.scope;
    // An approved host must never remain a denied one: clear from the denied
    // set every host the newly approved scope now authorizes, so an earlier
    // denial can't shadow a later approval of the same target (whether that
    // host was the one just requested or is simply covered by the broadened
    // scope).
    for (const host of [...deniedHosts]) {
      if (resolution.scope.match(`https://${host}`).allowed) deniedHosts.delete(host);
    }
    if (!customSystemPrompt) {
      systemPrompt = buildConsoleSystemPrompt({ target: sessionTarget, scanId, autonomyMode });
    }
    return "approved";
  }

  // Resolve LOCAL filesystem scope for a filesystem-scoped tool call, or return
  // a "denied" ToolResult. Mirrors maybeResolveScope (the network flow) as
  // closely as possible so the two behave consistently:
  //   - tools not in LOCAL_SCOPE_TOOLS pass straight through;
  //   - a requested path already inside the approved subtree passes through;
  //   - with no requestLocalScope callback configured, fall through unchanged so
  //     the executor returns its own "requires a scoped local directory" error
  //     (legacy readline console / test behaviour is identical to today);
  //   - a previously-declined path is denied without re-prompting;
  //   - dangerous roots are refused without ever prompting;
  //   - on approval, the operator-approved directory is applied to the in-memory
  //     tool context (never persisted) after re-canonicalizing and confirming it
  //     still covers the requested path.
  async function maybeResolveLocalScope(
    call: ToolCall,
  ): Promise<"approved" | ToolResult> {
    if (!LOCAL_SCOPE_TOOLS[call.name]) return "approved";

    // Resolve the concrete path the tool wants to touch to an absolute,
    // symlink-resolved real path — the exact value the approval is made against.
    let requestedPath: string;
    try {
      requestedPath = canonicalizeRealPath(extractLocalPath(call));
    } catch {
      // The path resolves to nothing real (no existing ancestor). There is
      // nothing concrete to authorize; defer to today's behaviour and let the
      // executor produce its own error.
      return "approved";
    }

    // Already inside an approved local scope subtree → run it.
    if (sessionScopePath && isWithinDir(requestedPath, sessionScopePath)) {
      return "approved";
    }

    // No callback wired (legacy readline console / tests): behave exactly as
    // today — fall through so the executor returns its own scope error.
    const requestLocalScope = config.requestLocalScope;
    if (!requestLocalScope) return "approved";

    // Refuse obviously dangerous roots outright — never even offer approval.
    if (isDangerousLocalRoot(requestedPath)) {
      return {
        success: false,
        output: null,
        error: `Local scope request for tool "${call.name}" refused — ${requestedPath} is a protected root (filesystem root or home directory) and cannot be authorized as a scan scope.`,
      };
    }

    // A path already covered by an earlier denial must not trigger a fresh
    // prompt — that re-prompt loop is exactly the bug this guards against.
    for (const denied of deniedLocalPaths) {
      if (isWithinDir(requestedPath, denied)) {
        return {
          success: false,
          output: null,
          error: `Local scope request for tool "${call.name}" denied — ${denied} was already declined by the operator this session; not prompting again.`,
        };
      }
    }

    const resolution = await requestLocalScope({
      call,
      requestedPath,
      currentScopePath: sessionScopePath,
    });

    if (!resolution) {
      // Remember the declined path so a retry of the same (or a covered) path is
      // denied outright above instead of re-prompting.
      deniedLocalPaths.add(requestedPath);
      return {
        success: false,
        output: null,
        error: `Local scope request denied for tool "${call.name}" — operator declined to grant local filesystem scope.`,
      };
    }

    if (!resolution.scopePath.trim()) {
      return {
        success: false,
        output: null,
        error: `Local scope approval for tool "${call.name}" returned an empty directory path.`,
      };
    }

    // Re-canonicalize the APPROVED directory to what will actually be
    // authorized, so a symlink swapped between prompt and apply cannot widen it.
    let approvedDir: string;
    try {
      approvedDir = canonicalizeRealPath(resolution.scopePath);
    } catch {
      return {
        success: false,
        output: null,
        error: `Local scope approval for tool "${call.name}" points to a path that does not exist: ${resolution.scopePath}.`,
      };
    }

    // Re-apply the dangerous-root guard to the approved directory.
    if (isDangerousLocalRoot(approvedDir)) {
      return {
        success: false,
        output: null,
        error: `Local scope approval for tool "${call.name}" refused — ${approvedDir} is a protected root (filesystem root or home directory) and cannot be authorized as a scan scope.`,
      };
    }

    // The approved scope must be a real directory.
    try {
      if (!statSync(approvedDir).isDirectory()) {
        return {
          success: false,
          output: null,
          error: `Local scope approval for tool "${call.name}" is not a directory: ${approvedDir}.`,
        };
      }
    } catch {
      return {
        success: false,
        output: null,
        error: `Local scope approval for tool "${call.name}" points to a path that does not exist: ${approvedDir}.`,
      };
    }

    // What the operator saw must cover what the tool asked for — a requested
    // path that escapes the approved directory subtree is rejected.
    if (!isWithinDir(requestedPath, approvedDir)) {
      return {
        success: false,
        output: null,
        error: `Local scope approval for tool "${call.name}" does not cover ${requestedPath} (outside the approved directory ${approvedDir}).`,
      };
    }

    // Apply the resolution: set the in-memory local scope on the shared tool
    // context so the tool now works (never persisted to disk).
    sessionScopePath = approvedDir;
    toolContext.scopePath = approvedDir;
    return "approved";
  }

  // In copilot mode, prompt the operator before non-read-only tool dispatch.
  // In standard and yolo modes, skip this per-tool gate. When approveTool is
  // absent, always allow.
  /**
   * The guards actually wired into dispatch — equivalent to `BUILTIN_GUARDS`,
   * listed explicitly so the wiring states its own policy rather than
   * inheriting whatever a shared default happens to contain.
   *
   * `guardNetworkRequiresScope` is the load-bearing addition, and it IS a
   * deliberate product decision rather than a wiring detail: yolo mode means
   * "no prompts INSIDE an authorized scope", not "unrestricted". A yolo session
   * with no scope object has no authorized scope, so there is nothing for the
   * absence of prompts to be safe relative to. The TUI already refuses
   * `/mode yolo` without a configured scope; wiring the guard makes that
   * invariant hold in the ENGINE, so a session constructed directly against
   * `createConsoleSession` (a script, a test harness, an embedder) cannot end
   * up in the state the UI forbids.
   *
   * The cost is real and is accepted knowingly: `bash echo hello` in yolo with
   * no scope is now denied, because `bash` is network-capable and this layer
   * cannot prove a shell command is local. The remedy is one step — configure a
   * scope, or use standard mode — and the failure is a clear message rather
   * than an unbounded egress.
   *
   * Guards remain a deny-only floor: adding one can only ever narrow access,
   * and it runs last, after every gate above has already approved.
   */
  const WIRED_GUARDS: readonly ToolGuard[] = [
    guardUnresolvedCapabilities,
    guardNetworkRequiresScope,
    guardApprovalUnavailable,
  ];

  /**
   * Project one call into the guard layer's input.
   *
   * `capabilitiesResolved` is the load-bearing field: it is true ONLY for a
   * tool this build actually knows (one with a dispatch entry). An unrecognized
   * name — a typo, a stale model memory, or a future plugin-contributed tool
   * that has not been through the manifest's capability translation — resolves
   * to false and is denied by `guardUnresolvedCapabilities` rather than
   * inheriting the least-dangerous class by omission. The three capability
   * flags read the SAME maps the gates read, so the guard floor can never
   * disagree with the gate above it about what a tool is.
   */
  function guardContextFor(call: ToolCall): GuardContext {
    return {
      toolName: call.name,
      networkCapable: NETWORK_CAPABLE_TOOLS[call.name] === true,
      localScope: LOCAL_SCOPE_TOOLS[call.name] === true,
      readOnly: READ_ONLY_TOOLS[call.name] === true,
      autonomyMode,
      hasScope: sessionScope !== undefined,
      approvalAvailable: config.approveTool !== undefined,
      capabilitiesResolved: Object.prototype.hasOwnProperty.call(TOOL_DISPATCH, call.name),
    };
  }

  async function maybeApproveTool(call: ToolCall): Promise<"approved" | ToolResult> {
    if (autonomyMode !== "copilot") return "approved";
    const approveTool = config.approveTool;
    if (!approveTool) return "approved";
    if (READ_ONLY_TOOLS[call.name]) return "approved";

    const ok = await approveTool(call);
    if (!ok) {
      return {
        success: false,
        output: null,
        error: `Tool "${call.name}" was not approved by the operator in copilot mode.`,
      };
    }
    return "approved";
  }

  async function send(userText: string, callbacks?: ConsoleRenderCallbacks): Promise<ConsoleTurnOutcome> {
    messages.push({ role: "user", content: [{ type: "text", text: userText }] });

    const runCalls: Array<{ call: ToolCall; result: ToolResult }> = [];
    const usage = { inputTokens: 0, outputTokens: 0 };
    let assistantText = "";
    let iterations = 0;
    // Input tokens billed by the most recent model call. The next call resends
    // the entire conversation plus everything this iteration appended, so this
    // is a conservative LOWER BOUND on what one more iteration would cost — it
    // is what lets the budget check ask "would this exceed?" instead of only
    // "did this exceed?".
    let lastCallInputTokens = 0;

    const budgetSnapshot = (): ConsoleTurnBudget => ({
      tokensUsed: usage.inputTokens + usage.outputTokens,
      tokenBudget: maxTurnTokens,
      iterations,
      maxToolIterations,
    });

    // Usage the runtime surfaced through its stream callbacks for the CURRENT
    // model call. Some provider wires report usage only on the return value and
    // some only through this callback, so we capture both and prefer
    // `result.usage`; taking exactly one of the two is what keeps the turn
    // total accurate without ever double-counting a call.
    let streamedUsage: { inputTokens: number; outputTokens: number } | undefined;

    const streamCallbacks: NativeStreamCallbacks = {
      onDelta: (scope, text) => {
        if (scope === "assistant_response") callbacks?.onAssistantDelta?.(text);
        else callbacks?.onReasoningDelta?.(text);
      },
      // Captured, not forwarded: the engine re-emits a single authoritative
      // `onUsage` per model call below, carrying the turn totals and the budget
      // alongside this delta. Forwarding here as well would fire the same
      // callback twice per iteration with two different meanings.
      onUsage: (u) => {
        streamedUsage = u;
      },
    };

    // Turn cycle: plan → run tools → feed results back → repeat until the model
    // stops requesting tools (end_turn), the turn's token budget is spent, or
    // the runaway iteration backstop trips.
    for (;;) {
      streamedUsage = undefined;
      const result = await config.runtime.executeNative(systemPrompt, messages, nativeTools, streamCallbacks);

      if (result.stopReason === "error") {
        return {
          assistantText,
          toolCalls: runCalls,
          usage,
          budget: budgetSnapshot(),
          stopReason: "error",
          error: result.error ?? "LLM runtime error",
        };
      }

      const callUsage = result.usage ?? streamedUsage;
      if (callUsage) {
        usage.inputTokens += callUsage.inputTokens;
        usage.outputTokens += callUsage.outputTokens;
        lastCallInputTokens = callUsage.inputTokens;
      }
      // Live progress against the budget, once per model call rather than only
      // at the end of the turn, so a UI can show consumption climbing while a
      // long multi-tool turn is still running.
      callbacks?.onUsage?.({
        inputTokens: callUsage?.inputTokens ?? 0,
        outputTokens: callUsage?.outputTokens ?? 0,
        turnTokensUsed: usage.inputTokens + usage.outputTokens,
        turnTokenBudget: maxTurnTokens,
        iterations,
        maxToolIterations,
      });

      messages.push({ role: "assistant", content: result.content });

      // Surface any visible text the runtime didn't stream token-by-token.
      const turnText = result.content
        .filter((b): b is Extract<NativeContentBlock, { type: "text" }> => b.type === "text")
        .map((b) => b.text)
        .join("");
      if (turnText) assistantText += turnText;

      const toolUseBlocks = result.content.filter(
        (b): b is Extract<NativeContentBlock, { type: "tool_use" }> => b.type === "tool_use",
      );
      if (toolUseBlocks.length === 0) {
        return { assistantText, toolCalls: runCalls, usage, budget: budgetSnapshot(), stopReason: "end_turn" };
      }

      const toolResultBlocks: NativeContentBlock[] = [];
      for (const block of toolUseBlocks) {
        const call: ToolCall = { name: block.name, arguments: block.input };

        // ── Scope resolution gate (network-capable tools) ──
        const scopeVerdict = await maybeResolveScope(call);
        if (scopeVerdict !== "approved") {
          callbacks?.onToolStart?.(call);
          callbacks?.onToolResult?.(call, scopeVerdict);
          runCalls.push({ call, result: scopeVerdict });
          toolResultBlocks.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: stringifyToolResult(scopeVerdict),
            is_error: true,
          });
          continue;
        }

        // ── Local filesystem scope-on-demand gate (filesystem-scoped tools) ──
        const localScopeVerdict = await maybeResolveLocalScope(call);
        if (localScopeVerdict !== "approved") {
          callbacks?.onToolStart?.(call);
          callbacks?.onToolResult?.(call, localScopeVerdict);
          runCalls.push({ call, result: localScopeVerdict });
          toolResultBlocks.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: stringifyToolResult(localScopeVerdict),
            is_error: true,
          });
          continue;
        }

        // ── Copilot approval gate (non-read-only tools) ──
        const approvalVerdict = await maybeApproveTool(call);
        if (approvalVerdict !== "approved") {
          callbacks?.onToolStart?.(call);
          callbacks?.onToolResult?.(call, approvalVerdict);
          runCalls.push({ call, result: approvalVerdict });
          toolResultBlocks.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: stringifyToolResult(approvalVerdict),
            is_error: true,
          });
          continue;
        }

        // ── Monotonic guard floor (deny-only) ──
        // The three gates above are keyed on tool-NAME membership in static
        // maps, which means a tool absent from all of them lands in the
        // least-dangerous class by omission. The guards are the backstop for
        // that: each may only return a denial reason or abstain, so adding one
        // can never widen access, and an unknown tool is refused rather than
        // silently trusted. This runs last, after every gate has approved, so
        // it is the single point every dispatched call passes through.
        const guardVerdict = evaluateGuards(WIRED_GUARDS, guardContextFor(call));
        if (!guardVerdict.allowed) {
          const denial: ToolResult = {
            success: false,
            output: null,
            error: `Tool "${call.name}" denied: ${guardVerdict.reasons.join("; ")}`,
          };
          callbacks?.onToolStart?.(call);
          callbacks?.onToolResult?.(call, denial);
          runCalls.push({ call, result: denial });
          toolResultBlocks.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: stringifyToolResult(denial),
            is_error: true,
          });
          continue;
        }

        callbacks?.onToolStart?.(call);
        const toolResult = await executor.execute(call);
        callbacks?.onToolResult?.(call, toolResult);
        runCalls.push({ call, result: toolResult });
        toolResultBlocks.push({
          type: "tool_result",
          tool_use_id: block.id,
          content: stringifyToolResult(toolResult),
          is_error: !toolResult.success,
        });
      }
      messages.push({ role: "user", content: toolResultBlocks });

      iterations += 1;

      // Both guards are evaluated HERE — after every tool_use block in this
      // round has a matching tool_result appended — and never between the
      // assistant's tool_use and its results. That ordering is what makes a
      // stop resumable: the conversation is always left well-formed, so the
      // operator's next `send()` continues from the existing history (the model
      // sees every prior tool result and does not re-run anything). Nothing
      // auto-continues; the decision is the operator's.
      const tokensUsed = usage.inputTokens + usage.outputTokens;

      // PRIMARY GUARD: token budget. Checked before the iteration backstop
      // because it is the guard that reflects real cost; the outcome carries
      // the iteration count too, so nothing is hidden when both are at their
      // limits. Stops either when the budget is already spent, or when one more
      // model call would demonstrably overrun it.
      if (tokensUsed >= maxTurnTokens || tokensUsed + lastCallInputTokens > maxTurnTokens) {
        callbacks?.onNotice?.(
          `Token budget for this turn is spent — used ${tokensUsed} of ${maxTurnTokens} tokens over ${iterations} tool round(s). Pausing for operator input; send another message to continue from here.`,
        );
        return { assistantText, toolCalls: runCalls, usage, budget: budgetSnapshot(), stopReason: "max_turn_tokens" };
      }

      // BACKSTOP: runaway rounds. Only reachable when the turn is burning
      // rounds without burning budget.
      if (iterations >= maxToolIterations) {
        callbacks?.onNotice?.(
          `Reached the ${maxToolIterations}-tool-call runaway cap for this turn (${tokensUsed} of ${maxTurnTokens} tokens used); pausing for operator input.`,
        );
        return { assistantText, toolCalls: runCalls, usage, budget: budgetSnapshot(), stopReason: "max_tool_iterations" };
      }
    }
  }

  return {
    scanId,
    get systemPrompt(): string { return systemPrompt; },
    tools,
    messages,
    get autonomyMode(): ConsoleAutonomyMode { return autonomyMode; },
    get target(): string { return sessionTarget; },
    get scope(): ScopePolicy | undefined { return sessionScope; },
    get localScopePath(): string | undefined { return sessionScopePath; },
    setAutonomyMode: (mode) => {
      autonomyMode = mode;
      // The executor shares this mutable context object, so updating it here
      // is what makes `/mode yolo` take effect without a restart.
      toolContext.autonomyMode = mode;
      if (!customSystemPrompt) {
        systemPrompt = buildConsoleSystemPrompt({ target: sessionTarget, scanId, autonomyMode });
      }
    },
    clearConversation: () => {
      messages.length = 0;
    },
    send,
    cleanup: () => executor.cleanup(),
  };
}
