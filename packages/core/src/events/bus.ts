/**
 * Pluggable event bus for scanner / agent-loop telemetry.
 *
 * The legacy `ScanListener` API (see `../scanner.ts`) only carried coarse
 * stage:start / stage:end / finding events. The cloud worker-controller and
 * future tracing sinks need richer signal — per-turn agent state, tool calls,
 * planner invocations, finding ingests — so this module introduces a
 * fan-out `EventBus` that the rest of the core can `emit()` typed events
 * into, and that any number of `EventSink` consumers can subscribe to.
 *
 * Design goals:
 *
 *   1. Pluggable. Any module that can take an `EventSink` (cloud relay,
 *      in-memory spy for tests, OpenTelemetry exporter, etc.) can subscribe
 *      at process start without the scanner knowing about it.
 *   2. Backwards-compatible. The existing `ScanListener` public API is
 *      preserved via `scanListenerSink()` — an adapter that maps the new
 *      richer event vocabulary back onto the three legacy `ScanEvent`
 *      shapes so external consumers keep receiving familiar signals.
 *   3. Fail-soft. One buggy sink must never be able to abort a scan;
 *      exceptions thrown by a sink are caught and logged to stderr.
 *   4. Opt-in cloud relay. The `CloudEventSink` is OFF by default so
 *      local CLI runs are not spammed with `0SEC_EVENT_*` lines;
 *      enable via `0SEC_CLOUD_EVENTS=1` (checked at subscribe time).
 *
 * Cloud wire format (matches the cloud worker-controller's
 * `parseEventLines` in `0sec-cloud/services/worker-controller/src/poller.ts`):
 *
 *     0SEC_EVENT_<TYPE_UPPER> {"…json payload…"}
 *
 * e.g. `0SEC_EVENT_STEP_STARTED {"step":"recon","n":1}`.
 */
import type { ScanEvent, ScanListener } from "../scanner.js";
import type { ToolCall, ToolResult } from "../agent/types.js";
import {
  createPresentationEvent,
  type PresentationEvent,
  type PresentationSource,
} from "@0sec/shared";

// ── Event taxonomy ──────────────────────────────────────────────────────────
//
// The discriminated union below is the single source of truth for what
// events the core emits. New event types MUST be added here (and in the
// `EventType` alias) before they can be emitted — TypeScript will then
// enforce payload shapes at every call site.
//
// Canonical event types the cloud already understands (schema comment in
// `0sec-cloud/services/dashboard/src/db/schema.ts:680`):
//
//   step_started, step_completed, finding_ingested, cost_update,
//   scan_completed
//
// M5 (agent-trace) additions — cloud will learn to render these:
//
//   agent_turn_started, agent_turn_completed,
//   tool_call_started, tool_call_completed,
//   llm_planner_invoked, reasoning_summary

export interface StepStartedPayload {
  step: string;
  n?: number;
}

export interface StepCompletedPayload {
  step: string;
  duration_ms?: number;
  n?: number;
  [k: string]: unknown;
}

export interface FindingIngestedPayload {
  finding_id?: string;
  severity?: string;
  title?: string;
  description?: string;
  category?: string;
  /**
   * Agent-assessed confidence in [0,1]. Optional — sourced from the hybrid
   * helper in `agent/finding-confidence.ts` (LLM self-report clamped UP to
   * a PoC-status floor). Older OSS releases that don't compute this leave
   * it absent; the cloud parser must accept absent as NULL.
   */
  confidence?: number;
  /** Rich fields for cloud-side reconciliation so a pending finding
   * carries evidence, not just a bare title (deep-review postmortem).
   * All optional — additive and backward-compatible. */
  evidence_request?: string;
  evidence_response?: string;
  evidence_analysis?: string;
  source_path?: string;
  source_start_line?: number;
  source_end_line?: number;
  poc_steps?: string;
  verification_spec?: string;
  [k: string]: unknown;
}

export interface CostUpdatePayload {
  cost_usd?: number;
  /** Engine-canonical running-total token counts (per agent session). */
  input_tokens?: number;
  output_tokens?: number;
  /**
   * Dual-spelling mirrors of input_tokens / output_tokens. The 0cloud
   * orchestrator's scan_jobs segment-sum (updateScanCostFromEvent) keys on
   * `token_input` / `token_output`, while engine-side consumers
   * (live-agent-state, dashboard live trace) read input_tokens /
   * output_tokens — producers emit BOTH so neither reader sees NULL.
   */
  token_input?: number;
  token_output?: number;
  /**
   * Cached-input (cache-read) tokens, when the runtime tracks them
   * (currently the codex CLI process runtime). Matches the key the
   * orchestrator's cache-read segment-sum reads.
   */
  cached_input_tokens?: number;
  turn?: number;
  [k: string]: unknown;
}

/**
 * Per-(provider, model) cost breakdown entry. One scan may invoke multiple
 * stages with different models (discovery on `claude-haiku-4-5`, attack on
 * `claude-opus-4-7`); the cloud renderer / `consolidate-xbow` aggregator
 * groups by `model` and sums.
 *
 * `cost_in` is uncached input dollars, `cost_out` is output dollars,
 * `cost_cache_read` is the discounted cached-input dollars (only present
 * when the runtime tracks cache reads — currently only `claude-*` via the
 * native API; OpenAI / Gemini / DeepSeek runtimes leave it absent).
 */
export interface CostBreakdownEntry {
  provider: string;
  model: string;
  cost_in: number;
  cost_out: number;
  cost_cache_read?: number;
}

export interface ScanCompletedPayload {
  exit_reason?: string;
  findings?: number;
  duration_ms?: number;
  /**
   * How many agent turns the scan consumed before terminating. Sourced
   * from the loop state's `turnCount`. Cloud dashboard renders this in
   * the per-scan card meta line so a no-findings scan still tells the
   * operator how much work was done.
   */
  turns_used?: number;
  /**
   * Total tool calls across all turns. Tracked by counting
   * `tool_call_completed` bus events between `scan_started` and this
   * one, so we never under-count even on partial / errored exits.
   */
  tool_calls_total?: number;
  /**
   * Short narrative the agent produced in its final `done` tool call,
   * e.g. "Audited lodash, no exploitable sinks found in template.js".
   * Empty when the scan didn't reach a `done` call (cost-exceeded,
   * max-turns, etc.). Cloud uses this verbatim as the human-readable
   * summary on the scan card and detail header.
   */
  summary?: string;
  /**
   * Total dollar cost of this scan run across all stages and models.
   * Sourced from `agent/cost.ts:estimateCost()` summed over discovery +
   * attack (+ retry / EGATS branches when active). Absent when the run
   * never invoked a metered runtime (legacy CLI, MCP fast-path,
   * source-code review under codex).
   */
  cost_usd?: number;
  /**
   * Per-(provider, model) cost split. When the scan used a single model
   * the array has one entry; multi-model runs (e.g. discovery on Haiku,
   * attack on Opus) emit one entry per model with `cost_in` / `cost_out`
   * already separated. Order matches stage order — discovery first.
   *
   * Why surface this on the event vs. let the cloud re-derive: the
   * scanner is the only process that knows the cached-input rate that
   * actually applied (rates change; the model's pricing-table snapshot
   * at scan time is authoritative). Cloud-side derivation would drift.
   */
  cost_breakdown?: CostBreakdownEntry[];
  /**
   * `cost_usd / flagsExtracted`. Omitted when no flags were extracted
   * (avoids divide-by-zero and prevents the cloud from rendering "$N/0"
   * on no-findings scans). Flags are counted by scanning every saved
   * finding's title / summary / evidence text for the `FLAG{...}`
   * wrapper pattern — the same pattern `agent/flag-validator.ts` uses
   * to triage decoys.
   */
  cost_per_flag?: number;
  [k: string]: unknown;
}

export interface AnalyzeStageCompletePayload {
  stage: "static-analysis";
  staticScanner: string;
  staticScannerRan: boolean;
  staticScannerFindings: number;
  semgrepFindings: number;
  npmAuditFindings: number;
  [k: string]: unknown;
}

export interface AgentTurnStartedPayload {
  turn: number;
  max_turns: number;
  role?: string;
}

export interface AgentTurnCompletedPayload {
  turn: number;
  duration_ms: number;
  reason: "continue" | "finished" | "max_turns" | "error" | "cost_ceiling" | "early_stop";
  role?: string;
}

export interface ToolCallStartedPayload {
  tool: string;
  turn: number;
  args_preview: string;
  /**
   * Absolute wall clock (epoch ms) at which the invocation started. The bus
   * itself carries no clock, so without this a consumer can only recover
   * relative ordering — not the "at 14:32:07.412 UTC we sent X" timeline a SOC
   * cross-reference needs.
   */
  ts: number;
}

export interface ToolCallCompletedPayload {
  tool: string;
  turn: number;
  duration_ms: number;
  status: "ok" | "error";
  error?: string;
  /** Absolute wall clock (epoch ms) at which the invocation completed. */
  ts: number;
}

export interface LlmPlannerInvokedPayload {
  turn: number;
  model?: string;
  tokens_est?: number;
  role?: string;
}

export interface ReasoningSummaryPayload {
  turn: number;
  summary: string;
}

// ── Skill events (0sec#458 — JIT skill A/B tracking) ────────────────────

export interface SkillLoadedPayload {
  skill_id: string;
  name: string;
  estimated_tokens: number;
  turn?: number;
  role?: string;
}

export interface SkillListedPayload {
  total: number;
  suggested_count: number;
  tag?: string;
  turn?: number;
  role?: string;
}

// ── Inbound prompt-injection defense (#558) ───────────────────────────────

/**
 * Fired when `sanitizeUntrustedToolResult` neutralizes one or more injection
 * markers in untrusted tool output (HTTP body, crawled HTML, file content,
 * MCP result) BEFORE that content re-enters model context. This is the
 * self-defense analogue of the `mcp-indirect-prompt-injection` probe: the
 * probe records a finding when the *target* is vulnerable; this event records
 * that OUR harness defanged an attempted indirect injection against itself.
 */
export interface UntrustedInputSanitizedPayload {
  /** The untrusted-source tool whose result was sanitized. */
  tool: string;
  /** Agent turn the sanitization happened on. */
  turn?: number;
  role?: string;
  /** Distinct marker labels neutralized (e.g. "instruction-override"). */
  markers: string[];
  [k: string]: unknown;
}

/**
 * Inline validation / validate-on-save verdict (#554). Emitted by the native
 * attack loop's onFindingSaved hook when a high/critical finding's PoC is
 * re-run inline by the deterministic category oracle.
 */
export interface InlineValidationPayload {
  /** Agent turn the finding was saved on. */
  turn?: number;
  /** Id of the saved finding that was validated. */
  findingId: string;
  category?: string;
  severity?: string;
  /** The oracle reproduced the exploit out-of-band. */
  confirmed: boolean;
  /** Oracle could not run to a conclusion (never a refutation). */
  inconclusive: boolean;
  /** Short reason for the verdict. */
  reason?: string;
  /** Wall-clock cost of the inline check. */
  durationMs?: number;
  [k: string]: unknown;
}

/**
 * Per-finding proof-of-vulnerability oracle verdict (#570). Emitted by the
 * batch PoV gate in `agentic-scanner.ts` immediately after `generatePov`
 * decides which deterministic oracle (or the regex fallback) adjudicated a
 * finding — mirroring the existing `db.logEvent("pov_oracle")` trace.
 *
 * Why both: `db.logEvent` only writes 0sec's LOCAL sqlite `pipeline_events`,
 * which the cloud worker never relays. Putting the same signal on the typed
 * bus lets `cloudEventSink` serialize it (→ worker → orchestrator
 * `scan_events`), so the dashboard can join it to the finding by `findingId`
 * and render the "deterministically verified vs heuristic" badge that is the
 * core low-false-positive story. Mirrors `untrusted_input_sanitized` (#558).
 */
export interface PovOraclePayload {
  /** Id of the finding the oracle adjudicated. */
  findingId: string;
  category?: string;
  /**
   * Which oracle decided the verdict:
   *  - `headless-browser` / `oast-callback` → deterministic proof.
   *  - `regex-fallback` → heuristic / pattern match (no deterministic oracle
   *    exists for the category).
   */
  oracle: "headless-browser" | "oast-callback" | "regex-fallback";
  /** A working PoV artifact reproduced the exploit. */
  hasPov: boolean;
  /**
   * Deterministic oracle could not run to a conclusion (browser / collector
   * errored). Never a refutation — "inconclusive on error, not a false pass".
   */
  inconclusive: boolean;
  /** Short reason for the verdict. */
  reason?: string;
  [k: string]: unknown;
}

/**
 * Confirmed OAST out-of-band callback (0sec#659 / 0cloud#1278). Emitted by the
 * deterministic per-category `oracle` triage layer in `agentic-scanner.ts` when
 * the OAST-callback oracle (SSRF / OOB-RCE / OOB-SQLi …) reproduces a
 * token-matched callback.
 *
 * WHY A DEDICATED EVENT (not `pov_oracle`): the `pov_oracle` event only fires
 * inside the FP-moat `pov_gate` layer, which is `0SEC_FEATURE_POV_GATE`-gated
 * and default-OFF — so in the cloud it never reaches `scan_events` and the
 * blind-vuln→verify loop can't promote. The `oracle` layer is `(always on)`
 * (FREE_LAYER_SET), so this event fires on every scan that confirms an OAST
 * callback, independent of `features.povGate`. Same {findingId, oracle, hasPov}
 * shape as `PovOraclePayload` so the 0cloud consumer (verify-claim EXISTS +
 * the #570 dashboard badge) reads either uniformly.
 *
 * `findingId` is the SAME engine finding id the `CloudSinkFinding` carries, so
 * the cloud correlates it to the finding row's `engine_finding_id`.
 */
export interface OastConfirmedPayload {
  /** Engine finding id — matches CloudSinkFinding.id → findings.engine_finding_id. */
  findingId: string;
  category?: string;
  /** Always `oast-callback`: this event is only emitted for the OAST oracle. */
  oracle: "oast-callback";
  /** Always true: emitted only when a token-matched callback reproduced. */
  hasPov: true;
  /** Callback channel (`http` / `dns` / …) when the oracle surfaced one. */
  protocol?: string;
  /** Short human-readable evidence for the audit trail. */
  reason?: string;
  [k: string]: unknown;
}

/**
 * Token-level streaming delta. Emitted by the agent loop while the runtime
 * is still streaming the assistant's text or reasoning channel — each emit
 * carries a *coalesced* run of characters (NOT per-token; see the batcher in
 * `agent/native-loop.ts` for the size/time bounds).
 *
 * Two orthogonal axes:
 *
 *   - `turn` — agent turn the chunks belong to. Cloud renderers key on this
 *     so that switching from turn N to turn N+1 retires the previous
 *     buffer's typing cursor.
 *   - `scope` — which channel the text came from. `"assistant_response"`
 *     is the visible text the model is producing; `"reasoning"` is the
 *     hidden chain-of-thought / reasoning-summary channel (only some
 *     models emit this, and only when reasoning is enabled).
 *
 * `seq` is monotonically increasing per (turn, scope) starting at 0 so
 * consumers can reorder out-of-order arrivals (e.g. across HTTP retries
 * on the cloud relay) and detect gaps. It MUST be unique within a
 * (turn, scope) pair but can repeat across distinct pairs.
 */
export interface DeltaPayload {
  turn: number;
  role?: string;
  scope: "assistant_response" | "reasoning";
  text: string;
  seq: number;
}

// ── Pipeline phase events (server-side truthful phase timeline) ───────────
//
// The unified pipeline (`unified-pipeline.ts`) runs a fixed sequence of
// top-level phases — prepare → analyze → research → verify → report — and
// emits one `phase_started` at each REAL transition (skipped phases never
// fire), plus a matching `phase_completed` carrying the wall-clock duration.
//
// Before this event existed the dashboard GUESSED phase boundaries client-
// side by watching when a turn's `max_turns` changed (see live-trace.tsx
// `TurnGroup.phaseStart` / `PhaseDivider`). That heuristic can be replaced by
// reading `phase_started.payload.name` / `.index` directly. Rides the same
// cloudEventSink → worker → orchestrator `scan_events` → SSE path as every
// other bus event; the orchestrator accepts the free-form `event_type` and
// the worker relay has no allow-list, so no cloud redeploy is required.

export interface PhaseStartedPayload {
  /** Canonical phase name: `prepare` | `analyze` | `research` | `verify` | `report`. */
  name: string;
  /** 0-based execution order of this phase within the scan (skipped phases leave no gap). */
  index: number;
  [k: string]: unknown;
}

export interface PhaseCompletedPayload {
  name: string;
  index: number;
  /** Wall-clock duration of the phase in milliseconds. */
  duration_ms: number;
  /**
   * LLM input tokens attributed to THIS phase (delta of the pipeline-wide
   * cumulative usage between the phase's start and completion). 0 for phases
   * that do no LLM work (prepare/analyze/report) and for runtime paths that
   * don't surface token usage (CLI runtimes, legacy loop) — truthful, never
   * synthesized.
   */
  input_tokens: number;
  /** LLM output tokens attributed to this phase (same delta semantics). */
  output_tokens: number;
  /** Agent-loop turns attributed to this phase (same delta semantics). */
  turns: number;
  [k: string]: unknown;
}

// ── Subagent lifecycle events (live TUI agent cards) ────────────────────

/**
 * A sub-agent emits queued → running → completed|failed after runtime setup,
 * or queued → failed when startup itself fails. The event has no graph, DAG,
 * cost, or cancellation fields.
 *
 * Consumers (CLI TUI, cloud trace) filter by `parent_scan_id` and
 * unsubscribe on unmount. `agent_id` uniquely identifies the sub-agent
 * instance across the parent scan's lifetime.
 */
export interface SubagentLifecyclePayload {
  /** Opaque instance id for this sub-agent, unique within the parent scan. */
  agent_id: string;
  /** Scan id of the parent that called spawn_agent. */
  parent_scan_id: string;
  status: "queued" | "running" | "completed" | "failed";
  /** The task description passed to spawn_agent. */
  task: string;
  /** Effective max turns for the sub-agent (clamped to ≤25). */
  max_turns: number;
  /** Actual turns consumed — present on completed|failed. */
  turns?: number;
  /** Number of findings the sub-agent saved — present on completed|failed. */
  findings?: number;
  /** Sub-agent's final summary — present on completed. */
  summary?: string;
  /** Error message on failure (truncated to 500 chars). */
  error?: string;
  /** Scope rules inherited from the parent — only when scope is active. */
  scope_rules?: string[];
  [k: string]: unknown;
}

/**
 * Fine-grained progress for ONE running sub-agent, keyed by the SAME
 * `agent_id` as {@link SubagentLifecyclePayload}. A UI joins these to the
 * lifecycle record by `agent_id` and renders "turn N of M" plus the tool the
 * child is working, so an operator watching a `spawn_agents` fan-out sees what
 * each child is doing instead of a bare wall-clock counter.
 *
 * GRANULARITY — turn boundaries, NOT tokens. This event is emitted once per
 * COMPLETED child turn (from the parent's per-child `onTurn` hook). It is
 * deliberately NOT emitted per token or per streaming `delta`: a child's
 * streaming text is high-volume and the parent UI does not need it — turn
 * boundaries and the tool that ran are the right granularity for a
 * "what is this child doing" indicator. See the `delta` event for the
 * (cloud-only, opt-in) high-volume token channel that this is NOT.
 *
 * PRIVACY / SIZE — this payload carries the tool NAME and small counters ONLY.
 * It never carries tool ARGUMENTS or tool OUTPUT, and it does NOT re-send the
 * child's task text (that rides once on the `queued` lifecycle event). Keeping
 * it this small is what lets it fire every turn for every concurrent child
 * without flooding the bus.
 *
 * ADDITIVE — this is a SIBLING event, not a change to `subagent_lifecycle`.
 * The existing queued/running/completed/failed transitions and their payload
 * fields are untouched, so `packages/cli/src/tui/subagent-card.ts` (which only
 * subscribes to `subagent_lifecycle`) keeps working unchanged. A sibling event
 * was chosen over a new lifecycle `status` precisely because the card's reducer
 * upserts any non-terminal lifecycle event into its active-set record; a fifth
 * status would have overwritten the stored `running` payload each turn.
 */
export interface SubagentProgressPayload {
  /** Same opaque id as this child's `subagent_lifecycle` events. */
  agent_id: string;
  /** Scan id of the parent that called spawn_agent(s). */
  parent_scan_id: string;
  /**
   * 1-based turn the child just completed. Increases monotonically per
   * `agent_id` (one emit per child turn), so a UI can drive a progress bar.
   */
  turn: number;
  /** The child's effective turn budget M, so a UI can render "turn N of M". */
  max_turns: number;
  /**
   * NAME of the most recent tool the child ran this turn — no arguments, no
   * output. Absent on a turn where the child ran no tool (or ran only the
   * meta `report_status` channel). Never a path or a payload.
   */
  tool?: string;
  /**
   * Optional short, single-line, control-character-stripped status the child
   * authored via the child-only `report_status` tool (see agent/tools.ts).
   * Bounded length — it renders into one terminal line. Absent when the child
   * did not report a status this turn.
   */
  note?: string;
  [k: string]: unknown;
}

/** One tool the child ran this turn, carried so a UI can format it with the
 * SAME `formatToolArgs`/`formatToolResult` the main transcript uses — giving a
 * focused child's tool cards byte-identical rendering. `result.output` is
 * bounded at emit time (see agent/tools.ts) so a many-child fleet's retained
 * transcripts stay light. */
export interface SubagentToolMessage {
  call: ToolCall;
  result: ToolResult;
}

/**
 * A child subagent's per-turn MESSAGES — the assistant prose it wrote plus the
 * tools it ran — so a UI can render a focused child's transcript IDENTICALLY to
 * the main agent's (fed through the same `planTranscript`/`renderEntry`).
 *
 * Fires ONCE per completed child turn: turn-granular, so full messages appear
 * per turn rather than token-by-token. This is deliberate — it keeps the
 * child's content OFF the high-volume per-delta channel (which the parent UI
 * still does not subscribe to), while giving the operator the real transcript
 * instead of the coarse `subagent_progress` tool-name ping.
 *
 * ADDITIVE sibling of `subagent_progress` / `subagent_lifecycle`: existing
 * subscribers are untouched. Content is bounded at emit time so neither the bus
 * nor the UI's retained-transcript memory can be flooded by a large fleet.
 */
export interface SubagentMessagePayload {
  /** Same opaque id as this child's `subagent_lifecycle`/`subagent_progress`. */
  agent_id: string;
  /** Scan id of the parent that called spawn_agent(s). */
  parent_scan_id: string;
  /** 1-based turn the child just completed (monotonic per `agent_id`). */
  turn: number;
  /** Epoch ms of the emit, for the transcript entry's relative timestamp. */
  ts: number;
  /** The child's assistant prose this turn, bounded. Absent when empty. */
  assistant?: string;
  /** Tools the child ran this turn (bounded results). Absent when none. */
  tools?: SubagentToolMessage[];
  [k: string]: unknown;
}

/**
 * A single tool-health event (a tool failed or was skipped, and why).
 * Emitted by the ToolExecutor's {@link ToolHealthTracker} sink so a UI /
 * diagnostics consumer can surface "N tool issues" without polling the
 * executor. Mirrors the `ToolHealthEvent` shape in agent/tool-health.ts;
 * declared structurally here to avoid an events→agent import cycle.
 */
export interface ToolHealthPayload {
  /** Tool / command name the issue is attributed to. */
  tool: string;
  /** Coarse taxonomy: missing-binary | buffer-limit | wrong-lockfile | policy-denied | scope-denied | error. */
  category: string;
  /** Operator-facing description of what happened. */
  message: string;
  /** Optional actionable remedy hint. */
  remedy?: string;
  /** Dedup count for this (tool, category, message) triple at emit time. */
  count: number;
  [k: string]: unknown;
}

/**
 * A full-state plan snapshot from the `update_todos` tool (TodoWrite shape).
 * Emitted once per CHANGE (not on idempotent re-writes) so the TUI can repaint
 * its live task tree. `line` is the "Todos · done/total" header.
 */
export interface TodosPayload {
  /** The complete plan at this revision, in declared order. */
  todos: Array<{ id: string; content: string; status: string; group?: string }>;
  /** Overall completed count. */
  done: number;
  /** Overall task count. */
  total: number;
  /** One-line header, e.g. "Todos · 1/3" ("" when the plan is empty). */
  line: string;
  /** Monotonic revision; bumps only when the plan actually changed. */
  revision: number;
  [k: string]: unknown;
}

/**
 * The current "what am I working on" objective for a console session — a short,
 * Title-Case label the TUI renders in a pill on the bottom bar (OMP-style). It
 * is DISPLAY-ONLY: it never enters model-facing context (like {@link TodosPayload}
 * it is a UI signal, not a tool result), and it updates IN PLACE — the instant
 * heuristic arrives first (`refined: false`), and the optional model-refined
 * rewrite replaces it later if it succeeds (`refined: true`).
 *
 * `scanId` matches {@link ConsoleSession.scanId}, so a renderer with more than
 * one session on the bus can filter to its own (mirroring the subagent events).
 * An empty `objective` means "no objective" and the TUI hides the pill.
 */
export interface SessionObjectivePayload {
  /** Console session id this objective belongs to (ConsoleSession.scanId). */
  scanId: string;
  /**
   * The short objective title (<= ~48 chars, ~3-6 words, Title Case). Empty
   * string ⇒ the renderer hides the pill.
   */
  objective: string;
  /**
   * `false` for the instant heuristic derived from the operator's first
   * message; `true` once the optional one-shot model refinement has replaced it.
   * A renderer can use this to know the pill may still change once more.
   */
  refined: boolean;
  [k: string]: unknown;
}

/**
 * Aggregate multi-modal cross-validation summary (0sec FoxGuard cross-validation,
 * Phase 3). Emitted ONCE per scan, after the per-finding triage loop, when the
 * multi-modal agreement layer ran (`0SEC_FEATURE_MULTIMODAL=1` + white-box) and
 * at least one finding reached `both_fire` agreement — i.e. both the 0sec agent
 * AND the foxguard pattern scanner fired on the same file. Lets the console / TUI
 * / cloud show "both scanners agree on N findings" without re-deriving it from
 * per-finding `multi_modal_agreement` DB events.
 *
 * PURELY OBSERVATIONAL — this is a summary of decisions already made by
 * `fuseTriageSignals`; emitting it does NOT change any triage decision, verdict,
 * or the multi-modal default gate.
 */
export interface CrossValidatedLeadEntry {
  /** Engine finding id — matches CloudSinkFinding.id → findings.engine_finding_id. */
  findingId: string;
  title: string;
  severity: string;
  category?: string;
  /** foxguard × 0sec agreement confidence in [0,1] from the multi-modal check. */
  confidence: number;
  /** Number of foxguard SARIF findings that matched this finding's file. */
  foxguardMatches: number;
}

export interface CrossValidatedLeadsPayload {
  /** Number of findings both scanners agreed on (multi-modal agreement === both_fire). */
  count: number;
  /** The agreeing findings, in triage order. */
  leads: CrossValidatedLeadEntry[];
  [k: string]: unknown;
}

/** Discriminated union of all events flowing through the bus. */
export type osecEvent =
  | { type: "step_started"; payload: StepStartedPayload }
  | { type: "step_completed"; payload: StepCompletedPayload }
  | { type: "finding_ingested"; payload: FindingIngestedPayload }
  | { type: "cost_update"; payload: CostUpdatePayload }
  | { type: "scan_completed"; payload: ScanCompletedPayload }
  | { type: "analyze:stage_complete"; payload: AnalyzeStageCompletePayload }
  | { type: "agent_turn_started"; payload: AgentTurnStartedPayload }
  | { type: "agent_turn_completed"; payload: AgentTurnCompletedPayload }
  | { type: "tool_call_started"; payload: ToolCallStartedPayload }
  | { type: "tool_call_completed"; payload: ToolCallCompletedPayload }
  | { type: "llm_planner_invoked"; payload: LlmPlannerInvokedPayload }
  | { type: "reasoning_summary"; payload: ReasoningSummaryPayload }
  | { type: "delta"; payload: DeltaPayload }
  | { type: "skill_loaded"; payload: SkillLoadedPayload }
  | { type: "skill_listed"; payload: SkillListedPayload }
  | { type: "untrusted_input_sanitized"; payload: UntrustedInputSanitizedPayload }
  | { type: "inline_validation"; payload: InlineValidationPayload }
  | { type: "pov_oracle"; payload: PovOraclePayload }
  | { type: "oast_confirmed"; payload: OastConfirmedPayload }
  | { type: "phase_started"; payload: PhaseStartedPayload }
  | { type: "phase_completed"; payload: PhaseCompletedPayload }
  | { type: "subagent_lifecycle"; payload: SubagentLifecyclePayload }
  | { type: "subagent_progress"; payload: SubagentProgressPayload }
  | { type: "subagent_message"; payload: SubagentMessagePayload }
  | { type: "tool_health"; payload: ToolHealthPayload }
  | { type: "todos"; payload: TodosPayload }
  | { type: "session_objective"; payload: SessionObjectivePayload }
  | { type: "cross_validated_leads"; payload: CrossValidatedLeadsPayload };

/** Narrow the event type string to the known vocabulary. */
export type EventType = osecEvent["type"];

/** Payload for a given event type. */
export type EventPayloadFor<T extends EventType> = Extract<
  osecEvent,
  { type: T }
>["payload"];

// ── Sink interface ──────────────────────────────────────────────────────────

export interface EventSink {
  /**
   * Called once per emitted event. Exceptions are caught by the bus; a sink
   * SHOULD still try to avoid throwing — the diagnostic write happens on
   * stderr which may itself be captured.
   */
  emit(type: EventType, payload: Record<string, unknown>): void;
}

/** Consumer of the renderer-neutral event envelope. */
export interface PresentationEventSink {
  emit(event: PresentationEvent): void;
}

export interface PresentationEventSinkOptions {
  /** Producer identity carried by the canonical record. Defaults to core. */
  source?: PresentationSource;
  /** Injected for deterministic tests; defaults to the current UTC instant. */
  now?: () => string;
}

/**
 * Adapt the typed core bus to the versioned presentation stream without
 * changing legacy cloud or ScanListener wire contracts.
 */
export function presentationEventSink(
  sink: PresentationEventSink,
  options: PresentationEventSinkOptions = {},
): EventSink {
  let sequence = 0;
  const source = options.source ?? "core";
  const now = options.now ?? (() => new Date().toISOString());

  return {
    emit(type, payload) {
      const scanId = typeof payload["scan_id"] === "string"
        ? payload["scan_id"]
        : typeof payload["scanId"] === "string"
          ? payload["scanId"]
          : undefined;
      const sessionId = typeof payload["session_id"] === "string"
        ? payload["session_id"]
        : typeof payload["sessionId"] === "string"
          ? payload["sessionId"]
          : undefined;
      sink.emit(createPresentationEvent({
        source,
        sequence: ++sequence,
        at: now(),
        eventType: type,
        payload,
        ...(scanId ? { scanId } : {}),
        ...(sessionId ? { sessionId } : {}),
      }));
    },
  };
}

// ── EventBus ────────────────────────────────────────────────────────────────

class EventBus {
  private sinks: EventSink[] = [];

  /** Subscribe a sink. Returns an unsubscribe function. */
  subscribe(sink: EventSink): () => void {
    this.sinks.push(sink);
    return () => {
      const idx = this.sinks.indexOf(sink);
      if (idx >= 0) this.sinks.splice(idx, 1);
    };
  }

  /** Remove every subscriber — primarily useful in tests. */
  clear(): void {
    this.sinks = [];
  }

  /** Returns a read-only snapshot of the current sinks (for tests). */
  get size(): number {
    return this.sinks.length;
  }

  /**
   * Fan out a single event to every subscribed sink. Exceptions thrown by
   * any sink are swallowed — one misbehaving consumer must never abort a
   * scan. Diagnostic is written to stderr so the failure is visible.
   */
  emit<T extends EventType>(type: T, payload: EventPayloadFor<T>): void {
    // Snapshot so unsubscribes mid-iteration don't skip sinks.
    const snapshot = this.sinks.slice();
    for (const sink of snapshot) {
      try {
        sink.emit(type, payload as Record<string, unknown>);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        try {
          process.stderr.write(`[0sec event-bus] sink threw on ${type}: ${msg}\n`);
        } catch {
          /* stderr gone — nothing more we can do */
        }
      }
    }
  }
}

/** Singleton bus. Modules `import { eventBus } from "../events/bus.js"`. */
export const eventBus = new EventBus();

// ── ScanListenerSink: legacy adapter ────────────────────────────────────────

/**
 * Translate the new richer event vocabulary back onto the legacy
 * `ScanListener` / `ScanEvent` shape so external consumers keep seeing the
 * familiar `stage:start` / `stage:end` / `finding` / `usage` events.
 *
 * Events that have no legacy equivalent (agent_turn_*, tool_call_*,
 * llm_planner_invoked, reasoning_summary) are intentionally dropped by this
 * adapter — callers who want those should subscribe a richer sink directly.
 */
export function scanListenerSink(listener: ScanListener): EventSink {
  return {
    emit(type, payload) {
      const scanEvent = mapToScanEvent(type, payload);
      if (scanEvent !== null) listener(scanEvent);
    },
  };
}

function mapToScanEvent(
  type: EventType,
  payload: Record<string, unknown>,
): ScanEvent | null {
  switch (type) {
    case "step_started": {
      const step = String(payload.step ?? "");
      return {
        type: "stage:start",
        stage: step,
        message: typeof payload.message === "string"
          ? payload.message
          : `Stage ${step} started`,
        data: payload,
      };
    }
    case "step_completed": {
      const step = String(payload.step ?? "");
      return {
        type: "stage:end",
        stage: step,
        message: typeof payload.message === "string"
          ? payload.message
          : `Stage ${step} completed`,
        data: payload,
      };
    }
    case "finding_ingested": {
      const severity = typeof payload.severity === "string"
        ? payload.severity.toUpperCase()
        : "INFO";
      const title = typeof payload.title === "string" ? payload.title : "Finding";
      return {
        type: "finding",
        message: `[${severity}] ${title}`,
        data: payload,
      };
    }
    case "cost_update":
      return {
        type: "usage",
        message: "usage",
        data: payload,
      };
    case "scan_completed":
      // The OSS ScanListener has no "done" event — swallow.
      return null;
    default:
      return null;
  }
}

// ── CloudEventSink ──────────────────────────────────────────────────────────

/**
 * Emits one line per event to stdout in the format the cloud
 * worker-controller expects:
 *
 *     0SEC_EVENT_<TYPE_UPPER> {"…json payload…"}
 *
 * Default OFF. Opt-in by setting `0SEC_CLOUD_EVENTS=1` (or, equivalently,
 * by calling `subscribeCloudEventSink()` explicitly from the CLI entry
 * point when worker mode is selected). Local interactive runs keep a clean
 * stdout.
 */
export const cloudEventSink: EventSink = {
  emit(type, payload) {
    const prefix = `0SEC_EVENT_${type.toUpperCase()}`;
    let line: string;
    try {
      line = `${prefix} ${JSON.stringify(payload)}`;
    } catch {
      // Unserializable payload — degrade gracefully rather than throwing.
      line = `${prefix} {"_unserializable":true}`;
    }
    // Use process.stdout.write directly so we bypass any console.log
    // formatting / buffering surprises. One 0SEC_EVENT_ line per call.
    process.stdout.write(line + "\n");
  },
};

/**
 * Idempotent helper for the CLI entry point: subscribe the cloud sink iff
 * the opt-in env var is truthy AND we haven't already subscribed. Safe to
 * call multiple times.
 */
let cloudSinkSubscribed = false;
export function maybeSubscribeCloudEventSink(): void {
  if (cloudSinkSubscribed) return;
  const flag = process.env["0SEC_CLOUD_EVENTS"];
  if (flag && flag !== "0" && flag.toLowerCase() !== "false") {
    eventBus.subscribe(cloudEventSink);
    cloudSinkSubscribed = true;
  }
}

/**
 * Returns `true` iff the cloud relay sink is currently subscribed. Used by
 * hot-path callers (token-delta forwarding in the agent loop) to skip
 * non-trivial work entirely when nobody's listening — keeps local CLI
 * runs free of per-token overhead.
 *
 * Note: this is a *liveness* probe, not a feature flag — `0SEC_CLOUD_EVENTS`
 * still gates whether the sink subscribes at all, but once subscribed the
 * agent loop consults this predicate so adding/removing sinks at runtime
 * (tests, future SDK consumers) Just Works without touching the env var.
 */
export function isCloudEventSinkActive(): boolean {
  return cloudSinkSubscribed;
}

/** Test-only: reset the idempotency flag. */
export function _resetCloudSinkSubscriptionForTests(): void {
  cloudSinkSubscribed = false;
}
