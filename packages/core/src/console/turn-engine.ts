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
  guardUnresolvedCapabilities,
  type GuardContext,
  type ToolGuard,
} from "../plugins/guards.js";
import type { AgentRole, OperatorQuestionAnswer, OperatorQuestionRequest, ScopedAuditEscalationRequest, ToolCall, ToolContext, ToolDefinition, ToolResult } from "../agent/types.js";
import { ScopePolicy } from "../scope/scope.js";
import { eventBus } from "../events/bus.js";
import { createSessionObjectiveService } from "./session-objective.js";

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
 * Operator engagement mode for the console. This is a FRICTION model, not an
 * authorization-removal model: the launch TARGET is the authorization anchor in
 * every mode, and the executor's own target/scope boundary plus the absolute
 * SSRF/private-network rail run underneath all three regardless of mode.
 *
 * - `"standard"` (default): the MOST-PROMPTING mode. Every effectful
 *   (non-read-only) action is put to the operator via `approveTool` before it
 *   runs and is dispatched only on an explicit yes — approval is never assumed.
 *   Out-of-scope network targets still go through scope-on-demand
 *   (`requestScope`), and uncovered local paths through `requestLocalScope`.
 * - `"copilot"`: full autonomy WITHIN the engagement. No per-action prompts.
 *   Scope-on-demand is AUTO-APPROVED for newly-discovered targets that belong
 *   to the engagement (the launch target's host / its sub-domains, or paths
 *   adjacent to an established local scope) — the scope grows without asking,
 *   and the expansion is recorded. A target OUTSIDE the established engagement
 *   is not auto-authorized: it defers to the operator (`requestScope`) or, with
 *   no approval channel, is refused. Copilot only ever operates against the
 *   target/scope the operator established.
 * - `"yolo"`: no prompts of any kind, and NO preconfigured scope required. It
 *   proceeds on the operator's launch TARGET and hosts that belong to it,
 *   auto-expanding scope to them without asking, and auto-grants local scope for
 *   the paths it touches. yolo drops only the interactive prompting and the
 *   "configure a scope first" requirement — it does NOT drop the target anchor:
 *   a host that is neither the launch target nor reachable-from-it, and any
 *   network destination this gate cannot even resolve, is still refused. The
 *   dangerous-local-root refusal, the denied-decision memory, the executor's
 *   target/scope boundary and the absolute SSRF rail all still apply.
 * - `"recon"`: passive, in-scope reconnaissance — the MOST capability-restricted
 *   mode. For AUTHORIZATION it behaves like standard: it operates strictly
 *   within the configured scope / target anchor and NEVER auto-expands scope
 *   (out-of-anchor targets are prompted via `requestScope`, or fall through to
 *   the executor's same-origin validation — never silently widened). For
 *   CAPABILITY it is stricter than any other mode: only non-exploitative work is
 *   permitted — read-only tools plus a conservative set of passive network-recon
 *   tools (see {@link RECON_PASSIVE_NETWORK_TOOLS}). Every effectful / mutating /
 *   exploitation tool (apply_patch, run_command, browser, exploit-class
 *   scanners, spawn_agent, raw http_request, …) is REFUSED with a clear reason —
 *   never prompted, never auto-lifted. Because it never runs effectful tools,
 *   recon does not use the per-action approval prompt at all. The target anchor
 *   and the absolute SSRF rail still bound the passive tools it does allow.
 */
export type ConsoleAutonomyMode = "standard" | "copilot" | "yolo" | "recon";

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
 * - `cancelled` — the operator interrupted the turn via an {@link AbortSignal}
 *   (see {@link ConsoleSendOptions.signal}). Like the budget stops, this is NOT
 *   an error: the conversation is left intact and resumable — every dispatched
 *   `tool_use` still has a matching `tool_result` — so the operator can send
 *   another message to continue. What it does and does NOT interrupt is spelled
 *   out on {@link ConsoleSendOptions.signal}.
 * - `error` — the LLM runtime failed.
 */
export type ConsoleStopReason =
  | "end_turn"
  | "max_tool_iterations"
  | "max_turn_tokens"
  | "cancelled"
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

/**
 * Per-call options for {@link ConsoleSession.send}. A dedicated options bag —
 * NOT a field on {@link ConsoleRenderCallbacks} — because cancellation is a
 * different concern from rendering: `callbacks` are output hooks a *renderer*
 * owns (deltas, tool start/result, usage), whereas an `AbortSignal` is turn
 * *control* a *controller* owns. A headless caller with no renderer must still
 * be able to cancel, and a renderer must not have to become a cancellation
 * authority to draw output. Keeping them separate also matches the platform
 * `{ signal }` convention (fetch, addEventListener, node streams). The whole
 * bag is optional and every field within it is optional, so every existing
 * `send(text)` / `send(text, callbacks)` caller compiles and behaves
 * identically.
 */
export interface ConsoleSendOptions {
  /**
   * Operator interrupt for this turn. When it fires (or is already aborted on
   * entry), the turn stops at the next checkpoint and returns a
   * {@link ConsoleTurnOutcome} with `stopReason: "cancelled"`, still carrying
   * the {@link ConsoleTurnOutcome.budget} spent so far.
   *
   * WHAT IT INTERRUPTS — and only these, checked at the points where a check
   * can actually take effect:
   *   - before the FIRST model call (already-aborted signal ⇒ immediate return,
   *     no model call, no history mutation);
   *   - between rounds / before issuing the NEXT model call;
   *   - before dispatching each tool in a round.
   *
   * WHAT IT CANNOT INTERRUPT — stated plainly so no one is misled:
   *   - a tool already executing. Same-process JavaScript cannot be hard-
   *     killed; a tool in `executor.execute(...)` runs to completion and the
   *     signal takes effect only at the NEXT checkpoint (the next tool, or the
   *     next round).
   *   - an OAuth token refresh already in flight. `executeNative` now takes
   *     the signal and aborts an in-flight model call, but a ChatGPT/Codex
   *     token refresh issued inside `ensureFreshHeaders` takes no signal, so
   *     an abort during that one refresh waits it out — the model fetch then
   *     aborts immediately and the pre-attempt guard stops any retry.
   *
   * An in-flight MODEL call IS interruptible: the runtime composes the
   * operator signal with its own timeout and idle watchdog, and reports the
   * result structurally via `cancelled` so a cancellation is never mistaken
   * for a transport failure. A cancelled call is also never retried and never
   * fails over to another provider — retrying a request the operator just
   * cancelled would defeat the cancellation.
   *
   * CONVERSATION INTEGRITY is preserved regardless of when the signal fires:
   * if it fires mid-round after tool calls were already dispatched, every
   * outstanding `tool_use` still receives a matching `tool_result` (a synthetic
   * "cancelled by operator" result) before the turn returns, so history is
   * never left with an unmatched `tool_use` and the next `send()` resumes
   * cleanly. Cancelling a turn NEVER clears or bypasses authorization state —
   * denied-host / denied-path memory and granted scope are untouched.
   */
  signal?: AbortSignal;
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
   * Engagement mode (see {@link ConsoleAutonomyMode}): `"standard"` (default)
   * prompts the operator to approve EACH effectful action before it runs and
   * uses scope-on-demand for out-of-scope network calls; `"copilot"` runs
   * without per-action prompts and AUTO-EXPANDS scope to in-engagement targets
   * without asking; `"yolo"` runs prompt-free with no preconfigured scope
   * required, anchored to the launch target and what belongs to it.
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
   * Per-action approval callback for `"standard"` mode — the most-prompting
   * mode. Invoked before every non-read-only tool call; return true to allow,
   * false to block with a "denied" result. Ignored in `"copilot"` and `"yolo"`
   * (neither prompts per action). When absent, the gate falls through (the
   * engine cannot invent an operator to ask), mirroring every other gate's
   * "no callback → defer to the layers beneath" contract.
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
  /**
   * Operator question channel for the `ask_operator` tool. Invoked when the
   * model pauses to ask the operator a STRUCTURED question; render the
   * question(s), collect the answer, and resolve with an
   * {@link OperatorQuestionAnswer} — or `null` if the operator dismissed the ask
   * without answering.
   *
   * This is INFORMATION-GATHERING ONLY and distinct from `approveTool` /
   * `requestScope` / `escalateScopedAudit`: it authorizes NOTHING. When absent,
   * `ask_operator` returns a graceful "not available" result rather than
   * blocking, mirroring every other gate's "no callback → defer" contract.
   */
  askOperator?: (req: OperatorQuestionRequest) => Promise<OperatorQuestionAnswer | null>;
  /**
   * Agent-to-agent messaging identity and policy for this session's agent.
   *
   * Propagates to every subagent, which is how a child learns its parent's
   * id and — when the operator channel is enabled — the operator console's
   * id, a value a child cannot compute for itself. Absent means messaging
   * is unavailable and the child tools say so.
   *
   * Typed `unknown` because the concrete shape lives in
   * `agent/agent-messaging.ts`; importing it here would invert the layering.
   */
  agentMessaging?: unknown;
  /**
   * Whether to run the ONE-shot model refinement of the session objective (the
   * OMP-style "what am I working on" pill). Default `true`. The instant
   * heuristic is always emitted regardless; this only governs whether the
   * runtime is asked to rewrite it into a crisper label. Fully fail-soft and
   * off the turn's critical path — see `console/session-objective.ts`. Set
   * `false` to keep the heuristic only (e.g. to avoid any extra model spend).
   */
  refineObjective?: boolean;
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
  /**
   * Run one operator message to a natural stop, streaming via `callbacks`.
   * Pass `opts.signal` to make the turn cancellable — see
   * {@link ConsoleSendOptions.signal} for exactly what an abort can and cannot
   * interrupt. Both trailing parameters are optional; omitting them is today's
   * behaviour exactly.
   */
  send(
    userText: string,
    callbacks?: ConsoleRenderCallbacks,
    opts?: ConsoleSendOptions,
  ): Promise<ConsoleTurnOutcome>;
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
    ? "YOLO mode: run without any approval prompts and without a preconfigured scope. You are anchored to the launch target — the target and hosts that belong to it (its sub-domains) are reached automatically; a host unrelated to the target, and any network destination whose address cannot be determined, is refused. Do not attempt to pivot to unrelated hosts."
    : opts.autonomyMode === "copilot"
    ? "Co-pilot mode: act with full autonomy within the engagement — no per-action approval prompts. Scope expands automatically to newly-discovered targets that belong to the engagement; a target outside the established engagement still needs the operator's decision."
    : opts.autonomyMode === "recon"
    ? "Recon mode: passive, in-scope reconnaissance ONLY. Operate strictly within the authorized target/scope and use only read-only and passive network-recon tools (crawling, fingerprinting, surface/API discovery, JS recon, intel lookups, source reading). Do NOT attempt any effectful, mutating, or exploitation action — those tools are refused in this mode. Gather and report what you observe, then hand control back. Scope is not auto-expanded; an out-of-scope target needs the operator's decision."
    : "Standard mode: the operator approves each action before it runs. Take one concrete step, wait for approval, and when a target is not authorized request a narrow scope extension and wait for the operator's decision.";
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
  // Reads only this agent's own inbox and grants no authority, so it is
  // exempt from the copilot gate. Its counterpart `send_message` is
  // deliberately absent from all three maps: it changes state, so copilot
  // gates it like any other action, but it reaches neither the target
  // network nor the operator-approved project scope.
  check_messages: true,
  // Puts a structured question to the operator and blocks for an answer. It is
  // an INFORMATION-GATHERING tool: it authorizes nothing — no scope, no
  // approval, no capability — so, like check_messages, it grants no authority
  // and is exempt from the copilot/standard approval gate.
  ask_operator: true,
  // update_todos/write_todos mutate only the run's plan (TodoWrite-style
  // full-state write) — no scope, no capability, grants nothing — so, like
  // ask_operator, they are exempt from the copilot/standard approval gate.
  update_todos: true,
  write_todos: true,
  done: true,
};

/**
 * Passive network-recon tools permitted in `"recon"` mode ON TOP OF every
 * {@link READ_ONLY_TOOLS} entry. This is a deliberately CONSERVATIVE allow-list
 * ("prefer passive; when unsure, deny"): a network tool earns a place here only
 * when its entire job is passive information gathering about the engagement
 * surface — spidering/crawling, fingerprinting, surface/API discovery, and
 * client-side JS reconnaissance. None of these mutate target state or exercise
 * an exploit.
 *
 * Deliberately EXCLUDED (and therefore refused in recon): everything that can
 * mutate, submit input, or exploit — `http_request` (carries any method/body),
 * `submit_form`, `browser` (drives clicks/forms), `send_prompt`,
 * `access_control_probe`, all `structural_sqli_probe`/`prompt_layer_probe`/
 * `auth_boundary_probe`/`cloud_*` probes, every `run_*` scanner
 * (sqlmap/nmap/ffuf/nuclei — active/intrusive), `oast_*`, `start_scan`, the
 * shell/interpreter tools (`bash`/`run_command`/`pty_session`/`python_exec`),
 * `apply_patch`, and agent-spawning (`spawn_agent`/`spawn_agents`). Recon is the
 * most capability-restricted mode by design.
 */
const RECON_PASSIVE_NETWORK_TOOLS: Record<string, true> = {
  crawl: true,
  wp_fingerprint: true,
  discover_api_surface: true,
  surface_sweep: true,
  js_recon: true,
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

/**
 * The host of the engagement anchor (the launch/session target), lowercased, or
 * null when no usable target is set. Accepts both a full URL and a bare
 * `host[:port]`, so a target configured either way yields the same anchor host.
 */
function anchorHostFromTarget(target: string): string | null {
  const trimmed = target.trim();
  if (!trimmed) return null;
  return hostOf(trimmed) ?? hostOf(`https://${trimmed}`);
}

/**
 * Whether `host` belongs to the current engagement — the conservative predicate
 * that decides what copilot may AUTO-EXPAND to, and what stays inside the yolo
 * TARGET ANCHOR. A host belongs when it is:
 *   - already authorized by the established scope, OR
 *   - the anchor host itself, OR
 *   - a sub-domain of the anchor host (matched on the dot boundary, so
 *     `notexample.com` is NOT a sub-domain of `example.com`, and
 *     `example.com.evil.com` is not one either).
 * Deliberately narrow: a host related only by some looser measure is treated as
 * foreign so it can NEVER be auto-authorized — the operator (standard/copilot
 * prompt) or a hard denial (yolo) decides instead. This is the friction-model
 * guarantee that neither copilot nor yolo silently reaches an unrelated host.
 */
function hostBelongsToEngagement(
  host: string | null,
  anchorHost: string | null,
  scope: ScopePolicy | undefined,
): boolean {
  if (!host) return false;
  if (scope?.match(`https://${host}`).allowed) return true;
  if (!anchorHost) return false;
  if (host === anchorHost) return true;
  return anchorHost.includes(".") && host.endsWith(`.${anchorHost}`);
}

/**
 * The nearest existing directory at or above `p` (an absolute real path). Used
 * to ground an AUTO-GRANTED local scope on a directory that actually exists,
 * even when the tool asked for a not-yet-created file. Walks up to a mount/drive
 * root at worst.
 */
function nearestExistingDir(p: string): string {
  let current = p;
  for (;;) {
    try {
      if (statSync(current).isDirectory()) return current;
    } catch {
      // does not exist / not stat-able — climb.
    }
    const parent = dirname(current);
    if (parent === current) return current;
    current = parent;
  }
}

/**
 * The directory subtree to auto-grant so a filesystem-scoped tool call can touch
 * `requestedPath` (an absolute real path): the path itself when it is a
 * directory, otherwise its containing directory — grounded on the nearest
 * directory that exists so the grant is always a real subtree covering the
 * request.
 */
function directoryToGrantFor(requestedPath: string): string {
  try {
    if (statSync(requestedPath).isDirectory()) return requestedPath;
  } catch {
    // Missing (e.g. a file to be created) — grant its parent instead.
  }
  return nearestExistingDir(dirname(requestedPath));
}

/**
 * Whether `requestedPath` belongs to the engagement whose established local
 * scope is `scopePath`: it lies within the PARENT of the established scope
 * (a sibling/descendant subtree of the same project root), provided that parent
 * is not a dangerous root. Returns false when no local scope is established yet
 * (the first local root is an operator decision, never auto-expanded) or when
 * broadening to the parent would reach the filesystem/home root.
 */
function pathBelongsToEngagement(requestedPath: string, scopePath: string | undefined): boolean {
  if (!scopePath) return false;
  const parent = dirname(scopePath);
  if (isDangerousLocalRoot(parent)) return false;
  return isWithinDir(requestedPath, parent);
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
    // Information-gathering only — grants no authority (see ConsoleSessionConfig).
    askOperator: config.askOperator,
    agentMessaging: config.agentMessaging,
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

  // Session objective ("what am I working on" pill). DISPLAY-ONLY: it never
  // enters model-facing context. The heuristic is emitted synchronously on the
  // first operator message; the optional one-shot refinement (default on)
  // reuses this session's runtime and is deferred off the turn's critical path.
  // Published on the SAME event bus the TUI already watches for todos/subagents,
  // keyed by scanId so a renderer can filter to its own session.
  const objectiveService = createSessionObjectiveService({
    runtime: config.runtime,
    refine: config.refineObjective,
    emit: (objective, refined) => {
      eventBus.emit("session_objective", { scanId, objective, refined });
    },
  });

  // AUTO-EXPAND the in-memory engagement scope to cover `uncoveredUrls`, used by
  // copilot (in-engagement targets) and yolo (target-anchored hosts) to grow
  // scope WITHOUT prompting. Adds each host as an EXACT-host rule (never a
  // wildcard — no silent broadening) on top of whatever scope already exists.
  // The out_of_scope deny-list is preserved and still WINS: a host the operator
  // explicitly excluded is refused even here, so auto-expansion can only ever
  // add hosts the anchor already vouches for, never override a deny. Never
  // written to disk; the expansion is announced via `notify` so it is auditable.
  function autoExpandScope(
    uncoveredUrls: string[],
    notify: ((message: string) => void) | undefined,
    modeLabel: string,
  ): "approved" | ToolResult {
    const hosts = [
      ...new Set(
        uncoveredUrls.map((url) => hostOf(url)).filter((h): h is string => h !== null),
      ),
    ];
    const base = sessionScope?.raw ?? {};
    const expanded = ScopePolicy.fromJson({
      ...base,
      in_scope: [...(base.in_scope ?? []), ...hosts],
    });
    // Deny-wins floor: an explicitly out-of-scope host is never authorized by
    // auto-expansion, and an unparseable pseudo-URL never becomes "covered".
    const stillUncovered = uncoveredUrls.filter((url) => !expanded.match(url).allowed);
    if (stillUncovered.length > 0) {
      return {
        success: false,
        output: null,
        error: `${modeLabel} mode: ${stillUncovered.join(", ")} is explicitly out of scope and was not auto-expanded.`,
      };
    }
    sessionScope = expanded;
    toolContext.scope = expanded;
    if (!customSystemPrompt) {
      systemPrompt = buildConsoleSystemPrompt({ target: sessionTarget, scanId, autonomyMode });
    }
    notify?.(
      `${modeLabel} mode: auto-expanded engagement scope to ${hosts.join(", ")} without prompting (in-engagement target).`,
    );
    return "approved";
  }

  // Resolve scope for a network-capable tool call, or return a "denied"
  // ToolResult. Per-mode friction (see ConsoleAutonomyMode):
  //   - standard: prompt the operator (requestScope) for anything uncovered.
  //   - copilot: auto-expand for in-engagement targets; defer the rest to the
  //     operator (or refuse when no prompt channel exists).
  //   - yolo: no prompts and no preconfigured-scope requirement — auto-expand
  //     to target-anchored hosts and REFUSE anything outside the anchor (an
  //     unrelated host, or a destination this gate cannot even resolve).
  // In EVERY mode the executor's own validateTargetUrl (target/scope boundary +
  // the absolute SSRF rail) still runs underneath, and the denied-decision
  // memory below is never cleared or skipped by a mode.
  async function maybeResolveScope(
    call: ToolCall,
    notify?: (message: string) => void,
  ): Promise<"approved" | ToolResult> {
    if (!NETWORK_CAPABLE_TOOLS[call.name]) return "approved";

    const { urls, unresolved, shellPayloads } = extractToolTargets(call, sessionTarget);

    // Nothing to decide about: no destination was named AND nothing in the call
    // reaches the network in a way this gate could not read. This is the branch
    // that keeps `bash echo hello`, `read_file`, and every other ordinary local
    // call prompt-free — the escalation below is driven by evidence of network
    // reach, never by mere membership in NETWORK_CAPABLE_TOOLS. It is also what
    // lets yolo run a local shell command with NO scope configured.
    if (urls.length === 0 && unresolved.length === 0) return "approved";

    // Check if every extracted URL is already covered by the current scope. An
    // unresolved destination can NEVER be "covered": there is nothing to match
    // a policy against, so scope coverage cannot discharge it.
    const allCovered = urls.every((url) => sessionScope?.match(url).allowed);
    if (allCovered && unresolved.length === 0) return "approved";

    // ── Denied-decision memory (ALL modes; never cleared or skipped by a mode) ──
    // A previously-declined opaque payload or host is denied outright — without a
    // fresh prompt and without auto-expansion — in standard, copilot AND yolo.
    // Keyed on the exact payload text for unresolved destinations (no host to
    // key on) and on the hostname for named ones.
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
    // Only URLs not already covered by the current scope are candidates; of
    // those, if ANY host was previously declined we deny the whole call rather
    // than silently dropping the declined host from a call the model asked for.
    // Unparseable URLs yield a null host and are ignored (fail safe).
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

    // Partition the uncovered destinations by the TARGET ANCHOR: those that
    // belong to the engagement (target host / its sub-domains / already scoped)
    // versus foreign ones. This split drives copilot's auto-expand and yolo's
    // anchor enforcement.
    const anchorHost = anchorHostFromTarget(sessionTarget);
    const foreign = uncoveredUrls.filter(
      (url) => !hostBelongsToEngagement(hostOf(url), anchorHost, sessionScope),
    );

    // ── yolo: no prompts, no preconfigured-scope requirement, TARGET-anchored ──
    // yolo drops the interactive prompt and the "configure a scope first" gate,
    // but the launch TARGET stays the authorization anchor: reach the target and
    // hosts that belong to it, and REFUSE everything else. A destination this
    // gate cannot resolve cannot be proven in-anchor, so it is refused too. The
    // executor's SSRF rail and target/scope boundary still run underneath.
    if (autonomyMode === "yolo") {
      // A command this gate cannot fully READ — a piped interpreter, base64 -d,
      // a $VAR URL, a local file op like `ls ~/.ssh` — is NOT proof of a foreign
      // target. YOLO is the operator's explicit full-autonomy opt-in on their
      // own machine; refusing every unreadable command just blocks legitimate
      // local work (the operator kept hitting this). Allow unnameable
      // destinations — the executor's SSRF rail (private/internal-network block)
      // still runs beneath every call. Only a FOREIGN NAMED host outside the
      // launch-target anchor stays refused: yolo is target-anchored, not
      // "attack anything, anywhere".
      if (foreign.length > 0) {
        return {
          success: false,
          output: null,
          error: `YOLO mode: ${foreign.join(", ")} is not the launch target and is not reachable from it — outside the yolo authorization anchor; refused.`,
        };
      }
      return autoExpandScope(uncoveredUrls, notify, "YOLO");
    }

    // ── copilot: full autonomy WITHIN the engagement ──
    // When the WHOLE call stays in-engagement, expand scope automatically with
    // no prompt. Anything foreign or unreadable is an engagement-boundary
    // decision, so it falls through to the operator prompt below (or a hard
    // refusal when no prompt channel exists) — copilot never silently authorizes
    // a target outside the established engagement.
    if (autonomyMode === "copilot" && foreign.length === 0 && unresolved.length === 0) {
      return autoExpandScope(uncoveredUrls, notify, "Co-pilot");
    }

    // ── standard (and copilot's foreign/unreadable remainder): ask the operator ──
    const requestScope = config.requestScope;
    if (!requestScope) {
      if (autonomyMode === "copilot") {
        // Copilot must not fall open on a foreign/unreadable target with no
        // operator channel — refuse rather than defer to same-origin luck.
        return {
          success: false,
          output: null,
          error: `Co-pilot mode: tool "${call.name}" targets ${foreign.join(", ") || "an unresolved destination"} outside the current engagement and no scope-approval channel is available; refused.`,
        };
      }
      // standard, no callback → the executor's own validateTargetUrl governs
      // (no scope → same-origin only). Unchanged from the legacy console.
      return "approved";
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

  // AUTO-GRANT a local filesystem scope covering `requestedPath` WITHOUT
  // prompting, used by yolo (any non-dangerous path) and copilot (paths that
  // belong to the engagement). Grants the requested path's directory subtree
  // (grounded on a directory that exists), re-checks the dangerous-root floor on
  // the directory actually granted, and applies it to the in-memory tool context
  // (never persisted). The expansion is announced via `notify` for auditability.
  function autoGrantLocalScope(
    call: ToolCall,
    requestedPath: string,
    notify: ((message: string) => void) | undefined,
    modeLabel: string,
  ): "approved" | ToolResult {
    const grantDir = directoryToGrantFor(requestedPath);
    if (isDangerousLocalRoot(grantDir)) {
      return {
        success: false,
        output: null,
        error: `Local scope for tool "${call.name}" refused — granting ${grantDir} would expose a protected root (filesystem root or home directory).`,
      };
    }
    if (!isWithinDir(requestedPath, grantDir)) {
      return {
        success: false,
        output: null,
        error: `Local scope for tool "${call.name}" could not be auto-granted for ${requestedPath}.`,
      };
    }
    sessionScopePath = grantDir;
    toolContext.scopePath = grantDir;
    notify?.(
      `${modeLabel} mode: auto-granted local scope ${grantDir} for ${requestedPath} without prompting.`,
    );
    return "approved";
  }

  // Resolve LOCAL filesystem scope for a filesystem-scoped tool call, or return
  // a "denied" ToolResult. Per-mode friction:
  //   - standard: prompt the operator (requestLocalScope) for uncovered paths.
  //   - copilot: auto-grant paths that belong to the engagement (adjacent to an
  //     established local scope); defer the rest to the operator prompt.
  //   - yolo: auto-grant any path (no prompt), subject only to the floors below.
  // Floors that hold in ALL modes: tools not in LOCAL_SCOPE_TOOLS pass straight
  // through; a path already inside the approved subtree passes through; dangerous
  // roots (filesystem/home root) are refused without ever prompting or granting;
  // a previously-declined path is denied without re-prompting. On the operator
  // prompt path, the approved directory is re-canonicalized and confirmed to
  // cover the requested path before it is applied (never persisted).
  async function maybeResolveLocalScope(
    call: ToolCall,
    notify?: (message: string) => void,
  ): Promise<"approved" | ToolResult> {
    if (!LOCAL_SCOPE_TOOLS[call.name]) return "approved";

    // Resolve the concrete path the tool wants to touch to an absolute,
    // symlink-resolved real path — the exact value the decision is made against.
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

    // ── Floors that apply in EVERY mode, before any prompt or auto-grant ──
    // Refuse obviously dangerous roots outright — never prompt, never grant.
    if (isDangerousLocalRoot(requestedPath)) {
      return {
        success: false,
        output: null,
        error: `Local scope request for tool "${call.name}" refused — ${requestedPath} is a protected root (filesystem root or home directory) and cannot be authorized as a scan scope.`,
      };
    }
    // A path covered by an earlier denial must not trigger a fresh prompt or a
    // silent grant — the denied-decision memory is honoured in every mode.
    for (const denied of deniedLocalPaths) {
      if (isWithinDir(requestedPath, denied)) {
        return {
          success: false,
          output: null,
          error: `Local scope request for tool "${call.name}" denied — ${denied} was already declined by the operator this session; not prompting again.`,
        };
      }
    }

    // ── yolo: auto-grant the path's subtree, no prompt (floors above still ran) ──
    if (autonomyMode === "yolo") {
      return autoGrantLocalScope(call, requestedPath, notify, "YOLO");
    }

    // ── copilot: auto-grant when the path belongs to the engagement ──
    // (adjacent to an established local scope); otherwise defer to the operator.
    if (autonomyMode === "copilot" && pathBelongsToEngagement(requestedPath, sessionScopePath)) {
      return autoGrantLocalScope(call, requestedPath, notify, "Co-pilot");
    }

    // ── standard (and copilot's out-of-engagement remainder): ask the operator ──
    // No callback wired (legacy readline console / tests): behave exactly as
    // today — fall through so the executor returns its own scope error.
    const requestLocalScope = config.requestLocalScope;
    if (!requestLocalScope) return "approved";

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
    // A local scope is a DIRECTORY subtree. If the approved path is a FILE
    // (e.g. the exact read_file/search_files target the operator confirmed),
    // grant its containing directory instead of erroring — mirrors the
    // auto-grant path (directoryToGrantFor) so standard mode behaves the same.
    approvedDir = directoryToGrantFor(approvedDir);

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

  /**
   * The guards actually wired into dispatch — the deny-only monotonic floor that
   * runs LAST, after every per-mode gate above has already approved. Listed
   * explicitly so the wiring states its own policy rather than inheriting a
   * shared default.
   *
   * TWO guards are wired, both mode-correct under the CURRENT autonomy model:
   *   - `guardUnresolvedCapabilities` (mode-agnostic): refuses any tool whose
   *     capability flags could not be resolved from a known source (the
   *     danger-by-omission class), always correct regardless of autonomy mode.
   *   - `guardApprovalUnavailable` (standard-mode): standard is now the mode
   *     that requires per-action approval, so this guard closes that gate's
   *     fail-OPEN corner — in standard mode a non-read-only tool with no
   *     approval mechanism is denied rather than run unapproved. It is inert in
   *     copilot/yolo (prompt-free by design) and in recon (whose capability gate
   *     refuses effectful tools before this floor is ever reached).
   * The deny-only pattern is preserved intact — "allow" remains inexpressible,
   * and adding guards can only narrow access.
   *
   * The THIRD built-in, `guardNetworkRequiresScope`, is DELIBERATELY NOT wired:
   * it is retired. It denied a network-capable tool in yolo when no scope was
   * configured, but the new yolo intentionally drops the
   * require-preconfigured-scope gate — it is anchored to the launch target, not
   * to a scope object. That anchor is enforced precisely by `maybeResolveScope`
   * (target-relatedness) plus the executor's own same-origin/scope boundary and
   * the absolute SSRF rail — a stronger, mode-correct check than a blanket
   * "needs a scope", and no OTHER mode requires a preconfigured scope either
   * (standard/recon prompt or same-origin-validate, copilot auto-expands).
   * Wiring it would wrongly re-deny scopeless yolo (even `bash echo hello`). The
   * function still exists and is exported from `plugins/guards.ts` for its own
   * unit tests and any other consumer; only the wired sets omit it.
   */
  const WIRED_GUARDS: readonly ToolGuard[] = [
    guardUnresolvedCapabilities,
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

  // Per-action operator approval — the STANDARD-mode friction. Standard is the
  // most-prompting mode: every effectful (non-read-only) action is put to the
  // operator via `approveTool` and dispatched ONLY on an explicit yes; approval
  // is never assumed. Copilot and yolo skip this gate entirely (copilot
  // auto-proceeds within the engagement; yolo runs prompt-free). READ_ONLY_TOOLS
  // (reads, findings queries, the `done` control signal) grant no authority and
  // change nothing, so they are exempt in every mode. When no `approveTool`
  // channel is wired (headless/legacy embedder) the gate falls through — the
  // engine cannot invent an operator to ask, and this mirrors every other gate's
  // "no callback → defer to the layers beneath" contract.
  async function maybeApproveTool(call: ToolCall): Promise<"approved" | ToolResult> {
    if (autonomyMode !== "standard") return "approved";
    const approveTool = config.approveTool;
    if (!approveTool) return "approved";
    if (READ_ONLY_TOOLS[call.name]) return "approved";

    const ok = await approveTool(call);
    if (!ok) {
      return {
        success: false,
        output: null,
        error: `Tool "${call.name}" was not approved by the operator in standard mode.`,
      };
    }
    return "approved";
  }

  // Recon capability gate — the RECON-mode friction, and the strictest one.
  // Recon permits only non-exploitative, passive/read work: every
  // READ_ONLY_TOOLS entry plus the conservative RECON_PASSIVE_NETWORK_TOOLS
  // set. Any effectful / mutating / exploitation tool is REFUSED with a clear
  // reason — never prompted (recon does not use the per-action approval flow)
  // and never auto-lifted. This is a hard capability floor, so it runs FIRST in
  // the dispatch loop: a denied tool never reaches the scope, local-scope,
  // approval, or plugin-guard gates, so it can never trigger a scope/approval
  // prompt. Recon still authorizes the passive tools it DOES allow exactly like
  // standard (target anchor + scope-on-demand, no auto-expansion), and the
  // executor's SSRF rail and target/scope boundary run underneath. In every
  // other mode this gate is a no-op.
  function maybeAllowReconCapability(call: ToolCall): "approved" | ToolResult {
    if (autonomyMode !== "recon") return "approved";
    if (READ_ONLY_TOOLS[call.name] || RECON_PASSIVE_NETWORK_TOOLS[call.name]) {
      return "approved";
    }
    return {
      success: false,
      output: null,
      error: `Recon mode: tool "${call.name}" is not permitted — recon allows only passive, read-only reconnaissance (read-only tools and passive network recon), never effectful, mutating, or exploitation tools. Switch to standard, copilot, or yolo to run it.`,
    };
  }

  async function send(
    userText: string,
    callbacks?: ConsoleRenderCallbacks,
    opts?: ConsoleSendOptions,
  ): Promise<ConsoleTurnOutcome> {
    const signal = opts?.signal;

    // Checkpoint — already aborted before any work. Return immediately with the
    // cancel reason and, crucially, WITHOUT mutating history or issuing a model
    // call: the user message is not even appended, so a session cancelled here
    // is byte-for-byte where it was before the call. The budget snapshot reads
    // zero because nothing was spent.
    if (signal?.aborted) {
      return {
        assistantText: "",
        toolCalls: [],
        usage: { inputTokens: 0, outputTokens: 0 },
        budget: {
          tokensUsed: 0,
          tokenBudget: maxTurnTokens,
          iterations: 0,
          maxToolIterations,
        },
        stopReason: "cancelled",
      };
    }

    messages.push({ role: "user", content: [{ type: "text", text: userText }] });

    // Derive/emit the session objective from the first message (no-op on later
    // turns once seeded). Synchronous + cheap for the heuristic; the optional
    // refinement is deferred and fire-and-forget, so this never blocks the turn.
    objectiveService.noteUserMessage(userText);

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
    //
    // Mark the turn active (synchronously, before any await) so the objective
    // refinement's deferred model call never runs concurrently with this turn.
    objectiveService.turnStarted();
    try {
    for (;;) {
      // Checkpoint — between rounds / before issuing the next model call. On the
      // first iteration this is redundant with the pre-abort check above and
      // harmless; on later iterations it is what stops the loop AFTER a round
      // has been fully closed out (every tool_use matched by a tool_result and
      // the tool_result message pushed), so history is well-formed and the next
      // send() resumes from it. We cannot abort an executeNative call that is
      // already in flight — the runtime takes no AbortSignal (see the honest
      // note where executeNative is called), so the signal is honoured here,
      // before the request is issued, not during it.
      if (signal?.aborted) {
        callbacks?.onNotice?.(
          `Turn cancelled by operator after ${iterations} tool round(s) — used ${usage.inputTokens + usage.outputTokens} of ${maxTurnTokens} tokens. Conversation is intact; send another message to continue.`,
        );
        return { assistantText, toolCalls: runCalls, usage, budget: budgetSnapshot(), stopReason: "cancelled" };
      }

      streamedUsage = undefined;
      // HONEST LIMIT: this call cannot be interrupted once issued. NativeRuntime
      // .executeNative takes no AbortSignal, so an abort that fires while the
      // model request is in flight only takes effect at the next checkpoint
      // (the top of this loop, or before the next tool dispatch). Aborting the
      const result = await config.runtime.executeNative(systemPrompt, messages, nativeTools, streamCallbacks, signal);

      if (result.stopReason === "error") {
        // The runtime reports an operator abort structurally via `cancelled`
        // rather than by message text, so an interrupted call is reported as
        // a cancellation and not as a failure the operator has to interpret.
        if (result.cancelled) {
          return {
            assistantText,
            toolCalls: runCalls,
            usage,
            budget: budgetSnapshot(),
            stopReason: "cancelled",
          };
        }
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
      // Set once the abort fires partway through this round. We do NOT break out
      // of the loop: CONVERSATION INTEGRITY requires that every tool_use block
      // the assistant emitted (already pushed to history above) gets a matching
      // tool_result, or the next model call rejects the history as malformed.
      // So once cancelled we keep iterating, but instead of dispatching we
      // append a synthetic "cancelled" tool_result for each outstanding block.
      let cancelledMidRound = false;
      for (const block of toolUseBlocks) {
        const call: ToolCall = { name: block.name, arguments: block.input };

        // Checkpoint — before dispatching this tool. A tool already running in a
        // PRIOR iteration of this loop cannot be interrupted (same-process JS is
        // not hard-killable); the abort takes effect here, before the NEXT tool
        // is dispatched. Every remaining block still gets a matching tool_result
        // so history stays well-formed. This runs BEFORE the scope / local-scope
        // / copilot / guard gates so a cancel never consults, mutates, or
        // bypasses any authorization state — denial memory and granted scope are
        // left exactly as they were.
        if (cancelledMidRound || signal?.aborted) {
          cancelledMidRound = true;
          const cancelResult: ToolResult = {
            success: false,
            output: null,
            error: "Tool call cancelled by operator before dispatch.",
          };
          callbacks?.onToolStart?.(call);
          callbacks?.onToolResult?.(call, cancelResult);
          runCalls.push({ call, result: cancelResult });
          toolResultBlocks.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: stringifyToolResult(cancelResult),
            is_error: true,
          });
          continue;
        }

        // ── Recon capability gate (recon mode only; runs first) ──
        // A hard, passive-only capability floor: an effectful/exploit tool is
        // refused here before any scope or approval prompt can fire.
        const reconVerdict = maybeAllowReconCapability(call);
        if (reconVerdict !== "approved") {
          callbacks?.onToolStart?.(call);
          callbacks?.onToolResult?.(call, reconVerdict);
          runCalls.push({ call, result: reconVerdict });
          toolResultBlocks.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: stringifyToolResult(reconVerdict),
            is_error: true,
          });
          continue;
        }

        // ── Scope resolution gate (network-capable tools) ──
        const scopeVerdict = await maybeResolveScope(call, callbacks?.onNotice);
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
        const localScopeVerdict = await maybeResolveLocalScope(call, callbacks?.onNotice);
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

        // ── Standard per-action approval gate (non-read-only tools) ──
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

      // A mid-round abort stops here — AFTER the tool_result message for this
      // round is pushed, so every tool_use in it is matched and the history is
      // resumable. Reported as `cancelled`, carrying the budget spent so far.
      if (cancelledMidRound) {
        callbacks?.onNotice?.(
          `Turn cancelled by operator mid-round — used ${usage.inputTokens + usage.outputTokens} of ${maxTurnTokens} tokens over ${iterations} tool round(s). Outstanding tool calls were closed out; send another message to continue.`,
        );
        return { assistantText, toolCalls: runCalls, usage, budget: budgetSnapshot(), stopReason: "cancelled" };
      }

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
    } finally {
      // Turn over. Once no turn is active this lets the one-shot objective
      // refinement fire — deferred and rescheduled while any turn runs, so its
      // model call never races the turn's own. Fire-and-forget, fully fail-soft.
      objectiveService.turnEnded();
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
    cleanup: () => {
      objectiveService.dispose();
      return executor.cleanup();
    },
  };
}
