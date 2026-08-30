import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
  NativeToolDef,
  NativeRuntimeResult,
} from "../runtime/types.js";
import type { AuthConfig } from "@0sec/shared";
import { resolveIdentities } from "@0sec/shared";
import type { ToolDefinition, ToolCall, ToolResult, ToolContext, AgentRole } from "./types.js";
import { toNativeToolDef, toNativeExtensionToolDef } from "./native-tooldef.js";
import { SessionEngine } from "./session.js";
import type { ScopePolicy } from "../scope/scope.js";
import type { AttributionConfig } from "../scope/attribution.js";
import type { EngagementPosture } from "../scope/engagement-profile.js";
import type { EnforcementTracker } from "../scope/enforcement.js";
import { WafDetector } from "../scope/waf-detect.js";
import { ToolExecutor, getToolsForRole, TOOL_DEFINITIONS, SELF_EXTENSION_RESERVED_TOOL_NAMES } from "./tools.js";
import { SelfExtensionRegistry } from "../plugins/self-extension.js";
import type {
  RegisteredExtensionTool,
  SelfExtensionEvent,
} from "../plugins/self-extension.js";
import { BUILTIN_GUARDS } from "../plugins/guards.js";
import { ToolHealthTracker } from "./tool-health.js";
import type { ToolHealthSummary } from "./tool-health.js";
import { TodoTracker, buildTodosPayload } from "./todos.js";
import type { TodoSnapshot } from "./todos.js";
import { features } from "./features.js";
import { LootLedger } from "./loot.js";
import { TaskLedger } from "./task-ledger.js";
import { DriftMonitor } from "./drift.js";
import { createCollaborator } from "../oast/index.js";
import {
  maybeCreateTrustGraphSession,
  type TrustGraphConfig,
} from "./trust-graph-runtime.js";
import { createShadowJournal, type ShadowJournal } from "./journal/shadow.js";
import { loadJournal, rehydrateContext, renderSeedMessages } from "./journal/index.js";
import { detectPlaybooks, buildPlaybookInjection } from "./playbooks.js";
import { detectDoomLoop, doomLoopNudge, toolCallSignature } from "./doom-loop.js";
import { formatJitSkillsInstruction, getSkillById } from "./skills/index.js";
import { estimateCost } from "./cost.js";
import type { ScanCostLedger } from "./cost-ledger.js";
import { eventBus, isCloudEventSinkActive } from "../events/bus.js";
import { diag } from "../diagnostics/channel.js";
import {
  reduceCoordinatorState,
  superviseCoordinator,
  formatFindingTailLine,
  type CoordinatorState,
  type CoordinatorIntervention,
} from "./coordinator-rails.js";
import {
  sendOperatorMessage,
  type MessagingRuntime,
} from "./agent-messaging.js";
import {
  HuntMemoryStore,
  type HuntSeverity,
} from "../memory/index.js";
import {
  isUntrustedSourceTool,
  sanitizeUntrustedToolResult,
} from "../untrusted-sanitizer.js";
import { DeltaBatcherSet } from "./delta-batcher.js";
import { toolCallPreview } from "./tool-preview.js";
import {
  newCorrelationId,
  buildToolCallLogEntry,
  buildToolCallsPayload,
  type ToolCallLogEntry,
} from "./action-log.js";
import { registerSignalCleanup } from "./signal-cleanup.js";
import {
  validateFindingInline,
  buildInlineValidationNote,
  shouldValidateInline,
  type InlineOracle,
  type InlineValidationOutcome,
} from "./inline-validation.js";
import type { osecDB } from "@0sec/db";
import type { Finding, AttackResult, TargetInfo } from "@0sec/shared";

// ── External Memory ──
// The agent can persist working state (creds, endpoints, attack plans) to this
// file via bash. At reflection checkpoints the contents are injected back into
// the conversation so the agent doesn't lose track of discoveries.
function externalMemoryPath(scanId?: string): string {
  return `/tmp/0sec-state-${scanId ?? randomUUID()}.json`;
}

// ── Loot harvesting (0sec#567) ──
// Tools whose result text reflects target data worth mining for footholds.
// `isUntrustedSourceTool` already covers http_request / crawl / read_file /
// send_prompt / submit_form / browser; bash + run_command are added because
// they routinely shell out to curl / cat and surface the same kind of
// credentials, tokens, and paths. Our own trusted bookkeeping tools
// (save_finding / query_findings / use_loot / done) are deliberately excluded
// — save_finding harvests via its own evidence path in the executor.
function shouldHarvestLoot(toolName: string): boolean {
  return (
    isUntrustedSourceTool(toolName) ||
    toolName === "bash" ||
    toolName === "run_command"
  );
}

// ── Reasoning summary heuristic ──
// The agent-trace dashboard renders a short preview of what the model was
// thinking on each turn. We derive a 1-line summary from the streamed
// thinking text using a cheap, deterministic heuristic:
//
//   1. If any line begins with `Thought:` / `Reasoning:` / `Plan:`
//      (case-insensitive, with optional surrounding whitespace/markdown),
//      take the first sentence of the remainder of that line.
//   2. Otherwise, take the first sentence of the whole thinking text.
//   3. Collapse whitespace and truncate to ~140 chars.
//   4. Return "" for empty/unusable input — callers skip emit on empty.
//
// Exported for unit tests.
const REASONING_PREFIX_RE =
  /^\s*(?:[*_>#-]\s*)*(?:thought|reasoning|plan)\s*:\s*/i;
const SENTENCE_SPLIT_RE = /(?<=[.!?])\s+/;
const REASONING_MAX_LEN = 140;

export function summarizeReasoning(thinkingText: string | undefined | null): string {
  if (!thinkingText) return "";

  // Normalize whitespace FIRST — newlines / tabs / repeat spaces all collapse
  // to single spaces. This lets the prefix regex work regardless of how the
  // runtime wrapped the thinking text, and gives the sentence splitter clean
  // input.
  const normalized = String(thinkingText).replace(/\s+/g, " ").trim();
  if (!normalized) return "";

  // Strip the prefix if one is present — work on the content after it.
  const candidate = normalized.replace(REASONING_PREFIX_RE, "").trim();
  if (!candidate) return "";

  // First sentence only (split on `.` / `!` / `?` followed by whitespace).
  const firstSentence = candidate.split(SENTENCE_SPLIT_RE)[0] ?? candidate;
  const trimmed = firstSentence.trim();
  if (!trimmed) return "";

  if (trimmed.length <= REASONING_MAX_LEN) return trimmed;
  // Truncate with an ellipsis so downstream renderers see clean boundaries.
  return trimmed.slice(0, REASONING_MAX_LEN - 1).trimEnd() + "…";
}

const EXTERNAL_MEMORY_MAX_CHARS = 2000;

/**
 * Transient provider error classifier: overload / rate-limit / 5xx / held
 * stream — failures where retrying the SAME turn after a backoff is right
 * (bounded by MAX_TRANSIENT_RETRIES, then the run exits loudly via errorExit).
 * `stall` covers the SSE idle-watchdog's error (a server that accepted the
 * request then held the stream silently; see llm-api.ts
 * consumeResponsesStream). Exported for tests.
 */
export function isTransientLlmError(errorMsg: string): boolean {
  return /\b(429|529|502|503|504)\b|overloaded|rate.?limit|temporarily|too many requests|ETIMEDOUT|ECONNRESET|throttl|stall/i.test(errorMsg);
}

/**
 * Provider context-window rejection classifier. This is intentionally narrower
 * than transient transport errors: pruning history changes the next request,
 * so it must never fire for a rate limit or a generic 5xx.
 */
export function isContextWindowError(errorMsg: string): boolean {
  return /context.{0,40}(?:window|length|limit)|(?:maximum|max).{0,20}context|too many tokens|prompt.{0,30}(?:too long|too large)|input.{0,30}(?:too long|too large)/i.test(
    errorMsg,
  );
}

// ── Native Agent Loop Config ──

export interface NativeAgentConfig {
  /**
   * Agent-to-agent messaging identity and policy, propagated to the tool
   * context so the child messaging tools know who they are and whom they
   * may address. Absent means messaging is unavailable.
   */
  agentMessaging?: unknown;
  role: AgentRole;
  systemPrompt: string;
  tools: ToolDefinition[];
  maxTurns: number;
  target: string;
  scanId: string;
  scopePath?: string;
  sessionId?: string; // Resume from existing session
  /** Which retry attempt this is (0 = first attempt). Used by early-stop logic. */
  retryCount?: number;
  /** Authentication credentials to inject into tool context */
  authConfig?: AuthConfig;
  /**
   * Resolved named identities for access-control testing (0sec#564). When
   * present, the loop builds a stateful per-identity `SessionEngine` and
   * threads it onto the ToolContext so cookies persist and access_control_probe
   * can replay as each principal. Reconciled from the legacy `authConfig` when
   * omitted.
   */
  identities?: import("@0sec/shared").NamedIdentity[];
  /**
   * Pre-built session engine (0sec#564). Normally left unset — the loop
   * constructs one from `identities`/`authConfig`. Provided only when a caller
   * wants cookie state to persist across multiple loop invocations.
   */
  session?: import("./session.js").SessionEngine;
  /**
   * Per-host token-bucket rate limiter (#214). Threaded into the
   * ToolContext so every fetch chokepoint paces against it.
   */
  rateLimiter?: import("../scope/rate-limit.js").RateLimiter;
  /**
   * Hard cost ceiling in USD. When set, the loop checks the running
   * estimated cost after every tool-call turn and aborts cleanly when
   * the ceiling is exceeded. Partial findings collected so far are
   * preserved on the returned state.
   *
   * By default the running cost is THIS session's `totalUsage` alone.
   * When {@link NativeAgentConfig.costLedger} is present the check prices
   * the ledger's cross-session cumulative total instead, so the ceiling
   * binds the whole scan rather than each agent session individually.
   */
  costCeilingUsd?: number;
  /** Optional model id used to price token usage against the ceiling. */
  costModel?: string;
  /**
   * Shared per-scan cost ledger (see agent/cost-ledger.ts). When present,
   * every turn's token usage is folded into the ledger AND the cost-ceiling
   * check above prices the ledger total — so a scan running multiple agent
   * sessions (research + the concurrent verify wave) enforces ONE ceiling
   * across all of them instead of granting each session the full ceiling
   * independently. Omit to keep the legacy per-session accounting.
   */
  costLedger?: ScanCostLedger;
  /**
   * Programmatic engagement scope (0sec#215). When set, every URL the
   * agent touches is checked against this policy and out-of-scope URLs
   * return as `ToolResult.error`. Same-origin checks remain enforced ON
   * TOP of this; scope is additive, never substitutive.
   */
  scope?: ScopePolicy;
  /**
   * http_audit enforcement tracker (path allowlist + counters + kill
   * switch). When set, the main loop polls `enforcement.isKillExpired()`
   * at each turn boundary and aborts cleanly (preserving partial findings)
   * once the wall-clock budget is exhausted. Also threaded onto the
   * ToolContext so fetch chokepoints enforce the path allowlist and tally
   * counters. Undefined for non-http_audit scans.
   */
  enforcement?: EnforcementTracker;
  /**
   * WAF detection + adaptive evasion aggregator (0sec#568). When omitted
   * but the scan carries an engagement scope (`scope`/`enforcement` set), one
   * is created automatically so authorized engagements get WAF fingerprinting
   * and adaptive evasion by default. Pass `null` to disable explicitly.
   */
  wafDetector?: WafDetector | null;
  /**
   * Generic-scanner-traffic suppression opt-out (0sec#217). Defaults
   * to false. Only consulted when `scope` is set.
   */
  allowScanners?: boolean;
  /**
   * Resolved attribution-header config (0sec#216). Same propagation
   * shape as `scope` — set once at agentic-scanner top-level and passed
   * through to every fetch site so in-scope traffic is identifiable
   * without leaking attribution to out-of-scope hosts.
   */
  attribution?: AttributionConfig;
  /**
   * Resolved engagement hardening posture (`scope/engagement-profile.ts`).
   * Same propagation shape as `attribution`: resolved once in the scanner and
   * threaded onto the ToolContext, where the WAF chokepoint consults it before
   * escalating a block into the adaptive evasion ladder.
   */
  engagement?: EngagementPosture;
  /**
   * Methodology skill IDs to auto-load into context before the loop starts
   * (#557). Used by EGATS specialist routing so a class branch begins with the
   * matching playbook already in its system prompt. Each skill's content is
   * appended to the system prompt and the ID is recorded in the loop's
   * `loadedSkills` set, so a later `load_skill` call on the same ID is a no-op
   * (`already_loaded`) — the preload is idempotent. Unknown IDs and skills not
   * applicable to `role` are skipped silently. Independent of the `jitSkills`
   * flag: the preload reads the registry directly, so the playbook lands even
   * when the `list_skills` / `load_skill` tools are not exposed.
   */
  preloadedSkillIds?: string[];
  /**
   * Durable cross-scan credential store wiring (0sec#771, connects #786 +
   * #780). OPT-IN and OFF BY DEFAULT: when omitted, the loop behaves exactly as
   * today — no durable store is constructed, no prior footholds are loaded, the
   * ledger is never persisted, and no `credential_shared` journal entry is
   * emitted (zero new I/O, byte-identical behaviour; asserted by test).
   *
   * When set, the loop (a) injects this target's prior-scan footholds at start,
   * (b) persists the in-scan ledger (hash + redacted preview only — never
   * plaintext) on harvest growth and at completion, and (c) emits a
   * `credential_shared` journal entry when a prior-scan credential from a
   * different source target is re-found against this target. See
   * `trust-graph-runtime.ts` for the full contract.
   */
  trustGraph?: TrustGraphConfig;
  /**
   * Model self-extension (the "it builds itself" capability). OFF BY DEFAULT and
   * load-bearing: only an explicit `true` constructs an ENABLED
   * `SelfExtensionRegistry` for the session and injects the `self_extend` tool
   * into the model-facing tool set. When false/omitted the registry is inert,
   * `self_extend` is absent from the tool set, and any call to it refuses. The
   * registry is session-scoped (in-memory, never persisted) and additive-only;
   * it enforces every limit in plugins/self-extension.ts. Mirrors the operator
   * setting `allowModelSelfExtension` (SELF_EXTENSION_SETTING_DEF).
   */
  allowModelSelfExtension?: boolean;
}

export interface NativeAgentLoopOptions {
  config: NativeAgentConfig;
  runtime: NativeRuntime;
  db: osecDB | null;
  onTurn?: (
    turn: number,
    toolCalls: ToolCall[],
    results: ToolResult[],
    assistantText: string,
  ) => void;
  /** Called only after a new finding has passed save_finding validation. */
  onFindingSaved?: (finding: Finding) => void | Promise<void>;
  onEvent?: (eventType: string, payload: Record<string, unknown>) => void;
  /** Poll for user-injected messages at turn boundaries. */
  getPendingUserMessages?: () => string[];
  /**
   * Inline-validation oracle override (#554). Defaults to the shared
   * `verifyOracleByCategory` from triage/oracles. Tests inject a deterministic
   * stub here so the onFindingSaved hook never touches the network. Only
   * consulted when `features.inlineValidation` is on.
   */
  inlineValidationOracle?: InlineOracle;
  /**
   * Cross-scan hunt-memory store override. Normally left unset — the loop lazily
   * constructs a single {@link HuntMemoryStore} (defaulting to
   * ~/.0sec/hunt-memory) for the run. Tests inject a deterministic store here so
   * the memory path never touches the real per-user state dir. Ignored when the
   * memory integration is disabled via `0SEC_DISABLE_HUNT_MEMORY`.
   */
  huntMemoryStore?: HuntMemoryStore;
}

export interface NativeAgentState {
  sessionId: string;
  messages: NativeMessage[];
  turnCount: number;
  findings: Finding[];
  attackResults: AttackResult[];
  targetInfo: Partial<TargetInfo>;
  done: boolean;
  summary: string;
  /**
   * `inputTokens` is total prompt tokens (cached spans included), so the
   * compaction trigger below keeps measuring real context growth regardless of
   * cache hit rate. `cachedInputTokens` is tracked alongside it purely so
   * `estimateCost` can price those tokens at the cached-input rate instead of
   * full price — without it, a well-cached run would report roughly 10x its
   * actual input spend.
   */
  totalUsage: { inputTokens: number; outputTokens: number; cachedInputTokens: number };
  /** Set to true when the loop stopped early because no save_finding was called by the halfway point. */
  earlyStopNoProgress: boolean;
  /** Brief description of tools/approaches used before the early stop (for retry context). */
  attemptSummary: string;
  /** LLM-generated structured progress summary for retry handoff. */
  progressSummary: string;
  /** Path to exported progress JSON (set when progressHandoff writes to disk). */
  progressPath?: string;
  /** Approximate USD cost based on token usage and model pricing. */
  estimatedCostUsd: number;
  /**
   * Set to true when the loop terminated because the running cost
   * exceeded the configured `costCeilingUsd`. Partial findings on
   * `state.findings` are preserved.
   */
  costCeilingExceeded: boolean;
  /**
   * Set to true when the http_audit wall-clock kill switch fired and the
   * loop aborted cleanly. Partial findings on `state.findings` are
   * preserved and flow through the normal report-assembly path. Always
   * false for non-http_audit scans (no kill switch configured).
   */
  killSwitchTriggered: boolean;
  /**
   * Set when the loop terminated because the planner LLM call returned an
   * error (or empty response). The legacy `state.summary = "Error: ..."`
   * marker is preserved for back-compat with downstream readers, but this
   * structured signal is what callers should branch on to surface a
   * `failed` exit_reason to the cloud / CLI rather than the default
   * `completed` path. Carries the raw error message and the turn at which
   * the loop bailed out.
   */
  errorExit?: { error: string; turn: number };
  /**
   * Inline-validation outcomes (#554), one per high/critical finding that the
   * onFindingSaved hook validated. Empty when `features.inlineValidation` is
   * off or no high/critical finding was saved. Carries the verdict for
   * telemetry / test assertions; the per-finding verdict is also stamped on
   * `finding.inlineValidation` so EGATS and the batch triage can read it.
   */
  inlineValidations: InlineValidationOutcome[];
  /**
   * Tool-health roll-up for this run (0sec#tool-reliability): the deduped set
   * of tool skips / failures (missing binary, buffer limit, wrong lockfile,
   * policy/scope denial) with a concise `line` the CLI can surface as
   * "N tool issues (missing: semgrep; …)". `total: 0` when nothing degraded.
   */
  toolHealth?: ToolHealthSummary;
  /**
   * Final structured full-state plan for this run (TodoWrite shape): the last
   * plan the model declared via `update_todos`, with per-phase groups and
   * overall done/total counts. Empty (`progress.total: 0`) when the model never
   * declared a plan. Live updates fan out on the event bus as `todos`; this is
   * the end-of-run snapshot attached to the returned state.
   */
  todos?: TodoSnapshot;
}

/**
 * Run a multi-turn agent loop using Claude's native Messages API with tool_use.
 *
 * Unlike the legacy loop that serializes conversation to text and parses
 * TOOL_CALL: patterns, this loop:
 * - Uses structured NativeMessage objects with typed content blocks
 * - Leverages Claude's native tool_use stop reason and tool_result flow
 * - Persists session state to SQLite for resumability
 * - Logs pipeline events for audit trail
 * - Tracks token usage
 */
export async function runNativeAgentLoop(
  opts: NativeAgentLoopOptions,
): Promise<NativeAgentState> {
  const {
    config,
    runtime,
    db,
    onTurn,
    onFindingSaved,
    onEvent,
    getPendingUserMessages,
    inlineValidationOracle,
  } = opts;

  const memoryPath = externalMemoryPath(config.scanId);

  // Substitute external memory placeholder in system prompt
  if (config.systemPrompt.includes("{{EXTERNAL_MEMORY_PATH}}")) {
    config.systemPrompt = config.systemPrompt.replaceAll("{{EXTERNAL_MEMORY_PATH}}", memoryPath);
  }

  // 0sec#567 — loot / foothold ledger. Created only when the feature is on;
  // threaded through ToolContext so save_finding harvests into it and use_loot
  // reads from it. The loop below also harvests from evidence-bearing tool
  // results and re-injects a compact "known footholds" block each turn.
  const loot = features.lootLedger ? new LootLedger() : undefined;

  // Typed TODO / plan ledger. Threaded through ToolContext so the `plan` tool
  // reads and mutates it; the loop below re-injects a compact plan block
  // re-rendered from the structured state (which is what makes the plan
  // survive compaction) and feeds its open tasks to the drift monitor.
  const plan = features.agentPlan ? new TaskLedger() : undefined;

  // Task-drift monitor. Deterministic, no LLM call — see agent/drift.ts.
  //
  // The objective anchor is a BOUNDED PREFIX of the system prompt, not the
  // whole thing, and that bound is load-bearing rather than a micro-
  // optimisation. The attack system prompts run to thousands of words and
  // enumerate every vulnerability class the engine knows (`SQLI_SECTION`,
  // `XSS_SECTION`, …); feeding all of it in would put essentially every
  // security term into the anchor set, anchor contact would then be true on
  // every conceivable turn, and the detector would be silent forever. The
  // opening lines carry the actual mission statement, so that is what anchors.
  // In practice the OPEN PLAN is the dominant anchor source, which is the
  // intended design: drift is measured against what the agent said it would do.
  const OBJECTIVE_PREFIX_CHARS = 600;
  const driftMonitor = features.driftDetection
    ? new DriftMonitor({
        objective: config.systemPrompt.slice(0, OBJECTIVE_PREFIX_CHARS),
        target: config.target,
      })
    : undefined;

  // 0sec#659 — hosted OAST interaction collaborator. Built only when the
  // feature is on AND a collaborator server is configured (0SEC_OAST_URL);
  // `createCollaborator` returns undefined otherwise, in which case the
  // oast_register / oast_poll tools return a graceful "not deployed" result.
  const oast = features.oastCollaborator ? createCollaborator() : undefined;

  // 0sec#771 (extends #687, connects #786 + #780) — durable cross-scan
  // credential store wiring. OPT-IN: `config.trustGraph` is undefined by default,
  // in which case `maybeCreateTrustGraphSession` returns undefined and every
  // `trustGraph?.` call site below is a no-op — the loop is byte-identical to the
  // single-scan path. When present, the session (constructed once the shadow
  // journal exists, below) loads this target's prior footholds, persists the
  // in-scan ledger (hash + preview only, never plaintext), and emits a
  // `credential_shared` journal entry on cross-target credential reuse. The full
  // contract lives in `trust-graph-runtime.ts`. `trustGraph` is declared here so
  // it is in scope for the loop; it is assigned after `shadowJournal` is created
  // (the default journal sink for credential_shared entries).
  let trustGraph: ReturnType<typeof maybeCreateTrustGraphSession>;

  // Stateful access-control session (0sec#564). Reconcile the legacy singular
  // `authConfig` with the multi-identity `identities` list, then build (or
  // reuse) a SessionEngine so HTTP tools persist cookies across turns and the
  // access_control_probe can replay as each principal. No identities → no
  // session → stateless behaviour unchanged.
  const identities = config.identities ?? resolveIdentities({ auth: config.authConfig });
  const session =
    config.session ?? (identities.length > 0 ? new SessionEngine(identities) : undefined);

  // ── Model self-extension (session-scoped, additive-only) ──
  // OFF by default: only an explicit `allowModelSelfExtension === true` builds an
  // ENABLED registry. The registry is constructed with the deny-only built-in
  // guard floor and the built-in tool names as reserved (so a model-registered
  // tool can never shadow a built-in), and enforces every per-session limit
  // itself. It lives only in this closure — session-scoped, never persisted, and
  // discarded when the loop returns. Every registration attempt (success OR
  // rejection) is surfaced via `onEvent` so the TUI/journal can show what the
  // model registered.
  const selfExtensionEnabled = config.allowModelSelfExtension === true;
  const selfExtension = new SelfExtensionRegistry({
    enabled: selfExtensionEnabled,
    baseGuards: BUILTIN_GUARDS,
    reservedToolNames: SELF_EXTENSION_RESERVED_TOOL_NAMES,
    onEvent: (event: SelfExtensionEvent) => {
      onEvent?.("self_extension", {
        kind: event.kind,
        at: event.at,
        registrationId: event.registrationId,
        origin: event.origin,
        pluginId: event.pluginId,
        pluginName: event.pluginName,
        version: event.version,
        tools: event.tools.map((t) => ({
          name: t.name,
          capabilities: [...t.capabilities],
          gateFlags: { ...t.gateFlags },
        })),
        guardCount: event.guardCount,
        manifestBytes: event.manifestBytes,
        ...(event.errors ? { errors: [...event.errors] } : {}),
        role: config.role,
      });
    },
  });

  const toolCtx: ToolContext = {
    target: config.target,
    scanId: config.scanId,
    role: config.role,
    findings: [],
    attackResults: [],
    targetInfo: {},
    scopePath: config.scopePath,
    persistFindings: db !== null,
    authConfig: config.authConfig,
    identities,
    session,
    scope: config.scope,
    rateLimiter: config.rateLimiter,
    enforcement: config.enforcement,
    agentMessaging: config.agentMessaging,
    // WAF detection + adaptive evasion (0sec#568). Auto-enabled for
    // authorized engagements (scope/enforcement configured) unless the caller
    // passed `wafDetector: null` to opt out.
    wafDetector:
      config.wafDetector === null
        ? undefined
        : (config.wafDetector ??
          (config.scope || config.enforcement ? new WafDetector() : undefined)),
    allowScanners: config.allowScanners,
    attribution: config.attribution,
    engagement: config.engagement,
    loot,
    plan,
    oast,
    // Thread the shared cost ledger + ceiling onto the tool context so the
    // spawn_agent / spawn_agents handlers can charge spawned subagents against
    // the SAME scan-wide ledger and ceiling as this session (closing the
    // off-ledger gap where subagent spend escaped the ceiling entirely).
    costLedger: config.costLedger,
    costCeilingUsd: config.costCeilingUsd,
    costModel: config.costModel,
    // Tool-health aggregator (0sec#tool-reliability). Shared across the scan so
    // the end-of-run summary sees every tool skip/failure; each NEW distinct
    // event also fans out on the bus as `tool_health`.
    toolHealth: new ToolHealthTracker({
      emit: (event) => {
        eventBus.emit("tool_health", {
          tool: event.tool,
          category: event.category,
          message: event.message,
          ...(event.remedy ? { remedy: event.remedy } : {}),
          count: event.count,
        });
      },
    }),
    // Structured full-state plan tracker (TodoWrite shape). One per run, shared
    // across the scan so the end-of-run snapshot reflects the final plan; every
    // plan CHANGE fans out on the bus as `todos` so the TUI repaints its live
    // task tree. Additive and authority-free — records only the declared plan.
    todos: new TodoTracker({
      emit: (snap) => {
        eventBus.emit("todos", buildTodosPayload(snap));
      },
    }),
  };

  // Attach the self-extension registry to the tool context (via the same cast
  // pattern the messaging runtime uses) so the `self_extend` handler and the
  // model-registered-tool dispatcher both resolve THIS session's registry.
  (toolCtx as ToolContext & { selfExtension?: SelfExtensionRegistry }).selfExtension =
    selfExtension;

  const executor = new ToolExecutor(toolCtx, db);
  const baseTools = config.tools.length > 0 ? config.tools : getToolsForRole(config.role, { hasScope: !!config.scopePath, allowScanners: config.allowScanners });

  // `self_extend` is never advertised by getToolsForRole; inject it into the
  // model-facing set ONLY when enabled, and strip it out otherwise (defence in
  // depth against a caller passing it in `config.tools`). Default OFF ⇒ absent.
  const selfExtendDef = TOOL_DEFINITIONS.self_extend;
  const tools: ToolDefinition[] = selfExtensionEnabled
    ? baseTools.some((t) => t.name === "self_extend") || !selfExtendDef
      ? baseTools
      : [...baseTools, selfExtendDef]
    : baseTools.filter((t) => t.name !== "self_extend");

  // Convert ToolDefinitions to native API format. `nativeTools` is a `let` and
  // the base (built-in) portion is captured separately: after a successful
  // `self_extend` the model-registered tools are unioned back in each turn so
  // they become callable on subsequent turns (see `syncExtensionTools`).
  const baseNativeTools: NativeToolDef[] = tools.map(toNativeToolDef);
  let nativeTools: NativeToolDef[] = baseNativeTools;

  /**
   * Rebuild the model-facing tool set as base tools ∪ the registry's currently
   * live model-registered tools. Idempotent and session-scoped: it only ever
   * reflects what the model registered THIS session, and a disabled registry
   * contributes nothing.
   */
  const syncExtensionTools = (): void => {
    if (!selfExtensionEnabled) return;
    const extTools = selfExtension.tools().map(toNativeExtensionToolDef);
    nativeTools = extTools.length > 0 ? [...baseNativeTools, ...extTools] : baseNativeTools;
  };

  // Initialize or restore state
  const sessionId = config.sessionId ?? randomUUID();
  let messages: NativeMessage[] = [];
  let turnCount = 0;

  // ── Execution-journal shadow mode (#494, flag-gated, default OFF) ──
  // When 0SEC_FEATURE_EXECUTION_JOURNAL is on, mirror this run's steps into
  // an append-only journal at ~/.0sec/runs/<scanId>/journal.jsonl. This is
  // strictly additive: the loop still drives off its own conversation window,
  // the journal is write-only here, and createShadowJournal returns a no-op
  // (no I/O) when the flag is off. The run id is the scanId — the same
  // convention the agentic-scanner already uses for resolveJournalPaths.
  const shadowJournal: ShadowJournal = createShadowJournal({ runId: config.scanId });
  if (shadowJournal.enabled) {
    shadowJournal.append({
      kind: "dispatch",
      targetAgent: config.role,
      objective: `${config.role} agent on ${config.target}`,
      context: { scanId: config.scanId, maxTurns: config.maxTurns, sessionId },
    });
  }

  // 0sec#771 — construct the trust-graph session iff opted in (above). The
  // shadow journal is the default sink for `credential_shared` entries. Loading
  // prior footholds is the ONLY store read here; it happens once. Best-effort:
  // a store failure here must never abort the loop, so it falls back to no
  // session (identical to the opted-out path).
  if (config.trustGraph) {
    try {
      trustGraph = maybeCreateTrustGraphSession(config.trustGraph, {
        target: config.target,
        defaultJournalSink: shadowJournal,
      });
    } catch {
      trustGraph = undefined;
    }
  }

  // ── Execution-journal context routing (#494, slice 2, flag-gated, OFF) ──
  // When 0SEC_FEATURE_JOURNAL_REHYDRATE is on, seed the loop's context off
  // the durable on-disk journal (rehydrateContext + renderSeedMessages)
  // instead of the truncated 40-message DB session blob. This is the slice
  // that routes the loop OFF the journal. Independent of the shadow-WRITE flag
  // (executionJournal): rehydrate is a READER, so it only fires when a journal
  // was actually written for this run. A fresh run rehydrates to empty, which
  // falls through to the identical fresh-start prompt below — so the flag only
  // changes behaviour on RESUME of an already-journaled run. Missing / empty /
  // corrupt journals fall back to the DB-blob path and never crash the loop.
  let rehydratedFromJournal = false;
  if (features.journalRehydrate) {
    const seed = seedFromJournal(config.scanId, (reason, detail) => {
      onEvent?.("journal_rehydrate_fallback", {
        sessionId,
        scanId: config.scanId,
        reason,
        detail: detail instanceof Error ? detail.message : detail,
      });
    });
    if (seed.seeded) {
      messages = seed.messages;
      turnCount = seed.turnCount;
      toolCtx.findings = seed.findings;
      rehydratedFromJournal = true;
      onEvent?.("journal_rehydrated", {
        sessionId,
        scanId: config.scanId,
        turnCount,
        messageCount: messages.length,
        findingCount: seed.findings.length,
      });
    }
  }

  // Try to restore from existing session (skipped when the journal already
  // seeded the context above — the journal is the source of truth then).
  if (!rehydratedFromJournal && config.sessionId && db) {
    const existing = db.getSessionById(config.sessionId);
    if (existing && existing.status === "paused") {
      messages = JSON.parse(existing.messages) as NativeMessage[];
      turnCount = existing.turnCount;
      const ctx = JSON.parse(existing.toolContext) as ToolContext;
      toolCtx.findings = ctx.findings ?? [];
      toolCtx.attackResults = ctx.attackResults ?? [];
      toolCtx.targetInfo = ctx.targetInfo ?? {};

      onEvent?.("session_resumed", { sessionId, turnCount, messageCount: messages.length });
    }
  }

  // If fresh start, add the initial user message
  if (messages.length === 0) {
    messages.push({
      role: "user",
      content: [{ type: "text", text: buildInitialPrompt(config) }],
    });

    // 0sec#771 — on a fresh start, inject this target's prior-scan footholds
    // (hash + redacted preview only) alongside the normal in-scan loot render.
    // Gated on the opt-in `trustGraph` session: when absent this whole block is
    // skipped, so the fresh-start prompt is byte-identical to today. "" render
    // (no prior footholds) is also skipped — no empty message is pushed.
    if (trustGraph) {
      try {
        const priorText = trustGraph.renderPriorFootholds(config.target);
        if (priorText) {
          messages.push({
            role: "user",
            content: [{ type: "text", text: priorText }],
          });
          onEvent?.("prior_footholds_injected", {
            scanId: config.scanId,
            count: trustGraph.priorCount,
          });
        }
      } catch {
        /* prior-footholds injection is best-effort */
      }
    }

    // Clean up external memory file at the start of a new scan (not between retries)
    if (features.externalMemory && (config.retryCount ?? 0) === 0) {
      try { fs.unlinkSync(memoryPath); } catch { /* file may not exist */ }
    }
  }

  const state: NativeAgentState = {
    sessionId,
    messages,
    turnCount,
    findings: toolCtx.findings,
    attackResults: toolCtx.attackResults,
    targetInfo: toolCtx.targetInfo,
    done: false,
    summary: "",
    totalUsage: { inputTokens: 0, outputTokens: 0, cachedInputTokens: 0 },
    earlyStopNoProgress: false,
    attemptSummary: "",
    progressSummary: "",
    estimatedCostUsd: 0,
    costCeilingExceeded: false,
    killSwitchTriggered: false,
    inlineValidations: [],
  };

  // Early-stop tracking: has the agent called save_finding at least once?
  let saveFindingCalled = false;
  // Collect tool names used for the attempt summary (deduped)
  const toolsUsedSet = new Set<string>();

  // CI heartbeat: one stderr line per turn so a CI log of a hung scan
  // tells us at which turn / on which tool we stopped making progress.
  // Gated on CI / explicit opt-in so local TUI runs stay quiet.
  const heartbeatEnabled = !!(process.env.CI || process.env["0SEC_HEARTBEAT"] || process.env["0SEC_DEBUG"]);
  const loopStartedAt = Date.now();
  let lastToolName: string | null = null;

  // Context window compaction — allow re-compaction as context regrows
  let compactionCount = 0;
  let tokensAtLastCompaction = 0;
  // Last-resort context-window recovery. Compaction normally runs before this
  // is needed; a provider rejection is the only trigger for destructive
  // drop-oldest pruning, and the retry cap prevents an endless shrink loop.
  let contextOverflowRecoveries = 0;

  // Dynamic playbook injection. `playbookInjected` now only records that the
  // FIRST injection has happened (for event labelling); the structured
  // `injectedPlaybookTypes` list is what the block is re-rendered from, so the
  // methodology can be restored after a compaction erases the message.
  let playbookInjected = false;
  let injectedPlaybookTypes: string[] = [];
  const recentToolResultTexts: string[] = [];

  // 0sec#567 — loot-injection cadence. Re-surface the "known footholds"
  // block when the ledger grew since the last injection, or at least every
  // LOOT_REINJECT_INTERVAL turns so a foothold captured early stays in the
  // recent context window even after the original tool result scrolls/compacts
  // away. -1 sentinels force a first injection as soon as loot exists.
  let lastInjectedLootRevision = -1;
  let lastLootInjectionTurn = -1;

  // Plan-injection cadence, same sentinels and same contract as the loot pair
  // above: -1 forces a first injection as soon as the agent records any task.
  let lastInjectedPlanRevision = -1;
  let lastPlanInjectionTurn = -1;

  // JIT skill tracking (#458): share the recentToolResultTexts buffer and
  // a persistent loadedSkills set with the ToolContext so skill tools can
  // access them. The buffer is the SAME array — pushes from the playbook
  // detection block below are visible to the skill trigger matcher, and
  // vice versa.
  toolCtx.recentToolResultTexts = recentToolResultTexts;
  if (!toolCtx.loadedSkills) {
    toolCtx.loadedSkills = new Set<string>();
  }

  // ── Specialist skill pre-loading (#557) ──
  // EGATS specialist routing passes the vuln-class methodology skill(s) so the
  // branch agent starts with the right playbook already in its system prompt.
  // Idempotent: a skill already in loadedSkills (or listed twice) is appended
  // only once, and a later load_skill on the same ID returns already_loaded.
  // Reads the registry directly so it works regardless of the jitSkills flag.
  if (config.preloadedSkillIds && config.preloadedSkillIds.length > 0) {
    for (const skillId of config.preloadedSkillIds) {
      if (toolCtx.loadedSkills.has(skillId)) continue;
      const skill = getSkillById(skillId);
      if (!skill) continue;
      if (!skill.applicable_roles.includes(config.role as "attack" | "audit" | "review")) {
        continue;
      }
      config.systemPrompt += `\n\n## Loaded Skill: ${skill.name}\n\n${skill.content}`;
      toolCtx.loadedSkills.add(skill.id);
      onEvent?.("skill_preloaded", {
        skillId: skill.id,
        name: skill.name,
        role: config.role,
      });
    }
  }

  // Loop / oscillation detection (BoxPwnr-inspired)
  const loopDetector = new LoopDetector();

  // Two-stage budget warnings (Strix-inspired, 0sec#408). Each warning
  // fires at most once per run. Thresholds are precomputed so the test
  // suite can assert the exact turn numbers.
  const budgetThresholds = computeBudgetWarningTurns(config.maxTurns);
  const budgetWarningsFired: { soft: boolean; hard: boolean } = {
    soft: false,
    hard: false,
  };

  // Log session start
  if (db) {
    db.logEvent({
      scanId: config.scanId,
      stage: config.role,
      eventType: "agent_start",
      agentRole: config.role,
      payload: { sessionId, maxTurns: config.maxTurns, toolCount: nativeTools.length },
      timestamp: Date.now(),
    });
  }

  // ── Graceful cleanup on signals ──
  const signalCleanup = () => {
    executor.cleanup();
  };
  const unregisterSignalCleanup = registerSignalCleanup(signalCleanup);

  // ── Coordinator rails (multi-agent supervisor) ──
  // Additive, feature-flagged (0SEC_FEATURE_COORDINATOR_RAILS, default OFF /
  // opt-IN). Set the env var to "1"/"true" to enable. Default off so the
  // supervisor's nudge/intervention events never surface as transcript noise
  // unless the operator opts in. When on, this loop's
  // spawned sub-agents (spawn_agent/spawn_agents) are observed via the eventBus
  // and the pure rails in `coordinator-rails.ts` (stall watchdog on
  // idle-since-last-output, kill-vs-escalate policy, anti-solo-takeover gate,
  // and loop/repetition detection) run BETWEEN iterations. The supervisor NEVER
  // touches `toolCtx.findings` (a reaped/stalled child's saved findings are
  // preserved) and LOGS every intervention AND enforcement action through the
  // diagnostics channel + `onEvent` — never raw stdout. Its enforcement is
  // conservative and non-destructive: a spin / warn-or-escalate stall is
  // NUDGED (a guidance message to the affected running child via
  // `sendOperatorMessage` when a messaging runtime is wired, otherwise an
  // `onEvent` the surface can show); an anti-takeover trip surfaces a
  // checkpoint/yield signal; and a provably-dead 'kill' is DOWNGRADED to
  // escalate-to-operator because no per-agent cancellation path is wired to a
  // spawned subagent (see `actOnIntervention`). When the flag is opted out
  // nothing subscribes and the supervise step is skipped, so behavior is
  // byte-identical to the legacy path.
  const coordinatorRailsEnabled =
    process.env["0SEC_FEATURE_COORDINATOR_RAILS"] === "1" ||
    process.env["0SEC_FEATURE_COORDINATOR_RAILS"] === "true";
  let coordinatorState: CoordinatorState = {};
  // Log each (agent, kind, action) transition once so a persistent condition
  // does not spam the diagnostics channel every turn.
  const loggedInterventions = new Set<string>();
  const unsubscribeCoordinator = coordinatorRailsEnabled
    ? eventBus.subscribe({
        emit: (type, payload) => {
          if (type === "subagent_lifecycle" || type === "subagent_progress") {
            coordinatorState = reduceCoordinatorState(
              coordinatorState,
              { type, payload },
              Date.now(),
            );
          }
        },
      })
    : () => {};

  function runCoordinatorSupervisor(): void {
    if (!coordinatorRailsEnabled) return;
    let interventions: CoordinatorIntervention[];
    try {
      // Bind the takeover gate to this loop's own turn budget so a single
      // child can never eat the whole allocation.
      interventions = superviseCoordinator(coordinatorState, {
        now: Date.now(),
        totalBudget: config.maxTurns,
      });
    } catch {
      // The supervisor is best-effort telemetry — it must never break the loop.
      return;
    }
    for (const iv of interventions) {
      const key = `${iv.agentId}:${iv.kind}:${iv.action}`;
      if (loggedInterventions.has(key)) continue;
      loggedInterventions.add(key);
      diag.warn("coordinator_rails_intervention", iv.reason, {
        scanId: config.scanId,
        agentId: iv.agentId,
        kind: iv.kind,
        action: iv.action,
        turn: state.turnCount,
        ...(iv.idleMs !== undefined ? { idleMs: iv.idleMs } : {}),
        ...(iv.share !== undefined ? { share: iv.share } : {}),
        ...(iv.repeatCount !== undefined ? { repeatCount: iv.repeatCount } : {}),
      });
      onEvent?.("coordinator_intervention", {
        turn: state.turnCount,
        agentId: iv.agentId,
        kind: iv.kind,
        action: iv.action,
        reason: iv.reason,
      });
      // ── Enforcement: ACT on the intervention (conservative, non-destructive,
      // never touches findings). Wrapped so an action can never break the loop.
      try {
        actOnIntervention(iv);
      } catch {
        /* enforcement is best-effort — it must never break the loop */
      }
    }
  }

  // Narrow the loop's (deliberately untyped) `agentMessaging` handle to a
  // MessagingRuntime we can address a running child through. Returns undefined
  // when messaging is not wired for this session, in which case a nudge falls
  // back to a surfaced `onEvent`.
  function nudgeMessagingRuntime(): MessagingRuntime | undefined {
    const m = config.agentMessaging as Partial<MessagingRuntime> | undefined;
    if (
      m &&
      typeof m === "object" &&
      typeof m.selfId === "string" &&
      typeof m.selfRole === "string" &&
      typeof m.projectPath === "string"
    ) {
      return m as MessagingRuntime;
    }
    return undefined;
  }

  // Log (once, via diagnostics — never stdout) AND surface the concrete
  // ENFORCEMENT action the supervisor took for an intervention. Dedup is the
  // caller's `loggedInterventions` key, so this fires at most once per
  // (agent, kind, action). Never touches `toolCtx.findings`.
  function emitCoordinatorAction(
    iv: CoordinatorIntervention,
    enforcement: string,
    detail: string,
  ): void {
    diag.warn("coordinator_rails_action", detail, {
      scanId: config.scanId,
      agentId: iv.agentId,
      kind: iv.kind,
      intervention: iv.action,
      enforcement,
      turn: state.turnCount,
    });
    onEvent?.("coordinator_action", {
      turn: state.turnCount,
      agentId: iv.agentId,
      kind: iv.kind,
      intervention: iv.action,
      enforcement,
      reason: detail,
    });
  }

  // Map one supervisor intervention to a concrete, conservative enforcement:
  //   • loop-detection nudge/force-pivot, or stall warn/escalate → NUDGE the
  //     affected running child (guidance message via `sendOperatorMessage` when
  //     a messaging runtime is wired; else a surfaced `onEvent`).
  //   • anti-takeover checkpoint → surface a checkpoint/yield signal (NO kill).
  //   • kill-escalate 'kill' (provably dead) → DOWNGRADED to escalate-to-operator
  //     because no per-agent cancellation path is wired to a spawned subagent
  //     (runOneSubagent awaits runNativeAgentLoop with no AbortController/signal),
  //     so inventing a kill here could drop a child's in-flight work. Other
  //     kill-escalate actions (escalate-to-operator / restart) surface as an
  //     operator escalation. Findings are never touched by any branch.
  function actOnIntervention(iv: CoordinatorIntervention): void {
    const isNudge =
      (iv.kind === "loop-detection" &&
        (iv.action === "nudge" || iv.action === "force-pivot")) ||
      (iv.kind === "stall-watchdog" &&
        (iv.action === "warn" || iv.action === "escalate"));

    if (isNudge) {
      const body =
        `[coordinator] ${iv.reason}. Change approach: try a different tool, ` +
        `endpoint, parameter, or technique instead of repeating the last action.`;
      const runtime = nudgeMessagingRuntime();
      if (runtime) {
        try {
          const res = sendOperatorMessage(runtime, iv.agentId, body, Date.now());
          if (res.ok) {
            emitCoordinatorAction(
              iv,
              "nudge-message",
              `nudged agent ${iv.agentId} via operator message`,
            );
            return;
          }
        } catch {
          /* delivery failed — fall back to the event surface below */
        }
      }
      emitCoordinatorAction(
        iv,
        "nudge-event",
        `nudge surfaced via event for ${iv.agentId} (no messaging runtime wired)`,
      );
      return;
    }

    if (iv.kind === "anti-takeover" && iv.action === "checkpoint") {
      emitCoordinatorAction(
        iv,
        "checkpoint",
        `checkpoint/yield signal surfaced for ${iv.agentId} (no hard-kill)`,
      );
      return;
    }

    if (iv.kind === "kill-escalate") {
      if (iv.action === "kill") {
        emitCoordinatorAction(
          iv,
          "escalate-downgraded-from-kill",
          `provably-dead ${iv.agentId}: no per-agent cancellation path wired — ` +
            `escalating to operator instead of killing (in-flight work preserved)`,
        );
      } else {
        // escalate-to-operator / restart both surface as an operator escalation:
        // there is no restart-capable dispatch here either, so we hand off.
        emitCoordinatorAction(iv, "escalate-to-operator", iv.reason);
      }
      return;
    }
  }

  // ── Hunt memory (cross-scan pattern DB) ──
  // Default ON, opt out with 0SEC_DISABLE_HUNT_MEMORY=1. On each saved finding
  // we append a REDACTED HuntRecord (the store redacts every persisted string;
  // `evidenceRef` is a POINTER, never raw evidence), and once at loop start we
  // surface a concise "prior findings for similar targets" count via `onEvent`
  // (never injected into the model prompt). Best-effort throughout: every store
  // call is wrapped and a failure is logged via the diagnostics channel only —
  // it never blocks or fails the scan.
  const huntMemoryEnabled =
    process.env["0SEC_DISABLE_HUNT_MEMORY"] !== "1" &&
    process.env["0SEC_DISABLE_HUNT_MEMORY"] !== "true";
  // Single store instance for the run. When a store is injected (tests) it is
  // used as-is; otherwise it is lazily constructed on first use so a scan that
  // never saves a finding pays no store-open cost.
  let huntMemory: HuntMemoryStore | undefined = huntMemoryEnabled
    ? opts.huntMemoryStore
    : undefined;
  function getHuntMemory(): HuntMemoryStore | undefined {
    if (!huntMemoryEnabled) return undefined;
    if (!huntMemory) {
      try {
        huntMemory = new HuntMemoryStore({});
      } catch (err) {
        diag.warn(
          "hunt_memory_unavailable",
          "could not open hunt-memory store; continuing without it",
          {
            scanId: config.scanId,
            error: err instanceof Error ? err.message : String(err),
          },
        );
        // Disable further attempts this run so we don't log on every finding.
        huntMemory = undefined;
      }
    }
    return huntMemory;
  }

  // Append one saved finding to hunt memory as a redacted HuntRecord. Never
  // throws into the scan; a store error is logged via diagnostics only.
  function recordFindingToMemory(finding: Finding): void {
    const store = getHuntMemory();
    if (!store) return;
    try {
      store.append({
        kind: "finding",
        target: config.target,
        // Vuln class is mapped from the finding's category (an AttackCategory);
        // the store lowercases/normalizes it.
        vulnClass: String(finding.category ?? "other"),
        title: finding.title ?? "(untitled finding)",
        summary: finding.description ?? "",
        // POINTER to where the evidence lives — never the raw evidence itself.
        evidenceRef: finding.fingerprint
          ? `fp:${finding.fingerprint}`
          : `finding:${finding.id}`,
        // Severity shares the exact value set with HuntSeverity.
        severity: finding.severity as HuntSeverity,
        tags: [
          String(finding.category ?? "other"),
          String(finding.severity ?? "info"),
        ],
        source: `scan:${config.scanId}`,
        createdAt: Date.now(),
      });
    } catch (err) {
      diag.warn(
        "hunt_memory_append_failed",
        "failed to record finding to hunt memory; continuing",
        {
          scanId: config.scanId,
          error: err instanceof Error ? err.message : String(err),
        },
      );
    }
  }

  // Surface a concise cross-target context line ONCE at loop start: how many
  // prior findings exist for this exact target and for OTHER (similar) targets,
  // plus the top vuln classes. Redacted-by-construction (the store only holds
  // redacted data) and emitted via `onEvent` only — nothing is injected into
  // the model prompt uninvited. Cheap and best-effort.
  if (huntMemoryEnabled) {
    try {
      const store = getHuntMemory();
      if (store) {
        const priorForTarget = store.query({
          target: config.target,
          kind: "finding",
          limit: 200,
        }).length;
        const cross = store.crossTarget({
          excludeTarget: config.target,
          kind: "finding",
          limit: 500,
        });
        if (priorForTarget > 0 || cross.length > 0) {
          const classCounts = new Map<string, number>();
          for (const r of cross) {
            classCounts.set(r.vulnClass, (classCounts.get(r.vulnClass) ?? 0) + 1);
          }
          const topClasses = [...classCounts.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3)
            .map(([cls]) => cls);
          onEvent?.("hunt_memory_context", {
            scanId: config.scanId,
            target: config.target,
            priorForTarget,
            crossTargetFindings: cross.length,
            topClasses,
            note:
              `prior findings for similar targets: ${cross.length}` +
              (topClasses.length ? ` (top: ${topClasses.join(", ")})` : "") +
              (priorForTarget ? `; ${priorForTarget} on this target` : ""),
          });
        }
      }
    } catch (err) {
      diag.warn(
        "hunt_memory_query_failed",
        "failed to query hunt-memory context; continuing",
        {
          scanId: config.scanId,
          error: err instanceof Error ? err.message : String(err),
        },
      );
    }
  }

  // ── Main loop ──

  // Transient-error backoff budget. A provider that returns 429/529/5xx
  // ("overloaded", "try again later") is temporarily unavailable, not broken —
  // without this a single transient blip ends the whole agent run (observed:
  // z-ai 529 zeroed an entire 20-finder hunt fleet). Capped so a hard outage
  // still terminates.
  let transientRetries = 0;
  const MAX_TRANSIENT_RETRIES = 6;

  // Rolling window of recent tool-call signatures for doom-loop detection — the
  // agent running the SAME tool with the SAME args over and over (a stuck probe)
  // burns budget for nothing. Bounded; reset after a nudge fires so it warns
  // once per stuck streak, not every turn.
  const toolCallLog: string[] = [];

  try {
  while (!state.done && state.turnCount < config.maxTurns) {
    // ── Coordinator rails: supervise sub-agents BETWEEN iterations ──
    // No-op unless the feature flag is on. Read-only observation + logging.
    runCoordinatorSupervisor();

    // ── http_audit wall-clock kill switch ──
    // Checked at the turn boundary BEFORE spending another LLM call so an
    // expired budget can't trigger one more (expensive) round-trip. Breaks
    // out cleanly: partial findings already live on toolCtx.findings and
    // are synced to state.findings post-loop, then assembled into the
    // report by agentic-scanner. We deliberately do NOT process.exit here.
    if (config.enforcement && config.enforcement.isKillExpired()) {
      state.killSwitchTriggered = true;
      config.enforcement.markKilled();
      state.summary =
        `http_audit kill switch fired at turn ${state.turnCount} ` +
        `(${config.enforcement.wallClockSec().toFixed(1)}s elapsed). ` +
        `Aborting cleanly with ${toolCtx.findings.length} partial finding(s).`;
      onEvent?.("kill_switch_triggered", {
        turn: state.turnCount,
        wallClockSec: config.enforcement.wallClockSec(),
        findingCount: toolCtx.findings.length,
      });
      if (db) {
        db.logEvent({
          scanId: config.scanId,
          stage: config.role,
          eventType: "kill_switch_triggered",
          agentRole: config.role,
          payload: {
            turn: state.turnCount,
            wallClockSec: config.enforcement.wallClockSec(),
            findingCount: toolCtx.findings.length,
          },
          timestamp: Date.now(),
        });
      }
      break;
    }

    state.turnCount++;
    // Keep the tool context's turn stamp fresh so tools that record state can
    // date it (the plan ledger stamps createdTurn / updatedTurn, which is what
    // makes a task that has sat untouched for 20 turns visible as stale).
    toolCtx.currentTurn = state.turnCount;
    const turnStartedAt = Date.now();
    // Mutable inside the try-block; read in the finally to stamp
    // agent_turn_completed with the right exit reason. Reassigned by
    // the break paths below (error, cost_ceiling, early_stop, finished).
    let turnExitReason: "continue" | "finished" | "max_turns" | "error" | "cost_ceiling" | "early_stop" = "continue";

    // Bus event: agent turn boundary start. Rich sinks (cloud relay,
    // dashboard tracer) use this to render per-turn UI; the legacy
    // ScanListener adapter drops it on the floor.
    eventBus.emit("agent_turn_started", {
      turn: state.turnCount,
      max_turns: config.maxTurns,
      role: config.role,
    });

    if (heartbeatEnabled) {
      const elapsed = ((Date.now() - loopStartedAt) / 1000).toFixed(1);
      const inTok = state.totalUsage.inputTokens;
      const outTok = state.totalUsage.outputTokens;
      const cost = state.estimatedCostUsd.toFixed(4);
      process.stderr.write(
        `[0sec:hb] t=${elapsed}s role=${config.role} turn=${state.turnCount}/${config.maxTurns} tokens=${inTok}/${outTok} cost=$${cost} last_tool=${lastToolName ?? "-"}\n`,
      );
    }

    try {

    // ── Inject user messages queued from the TUI ──
    if (getPendingUserMessages) {
      const pending = getPendingUserMessages();
      for (const text of pending) {
        state.messages.push({
          role: "user",
          content: [{ type: "text", text: `[User interrupt]: ${text}` }],
        });
        onEvent?.("user:injected", { turn: state.turnCount, text });
      }
    }

    // ── Two-stage budget warnings (#408, Strix-inspired) ──
    // Fire before the LLM call on the turn the threshold is reached so
    // the model sees the warning in the SAME planner invocation it
    // would otherwise blow the budget on. Soft fires first when the
    // two thresholds collide (small maxTurns) — see BUDGET_WARNING_*
    // for the soft-then-hard rationale.
    if (features.budgetWarnings) {
      if (!budgetWarningsFired.soft && state.turnCount >= budgetThresholds.soft) {
        budgetWarningsFired.soft = true;
        state.messages.push({
          role: "user",
          content: [{ type: "text", text: BUDGET_WARNING_SOFT }],
        });
        onEvent?.("budget_warning", {
          turn: state.turnCount,
          stage: "soft",
          maxTurns: config.maxTurns,
        });
      }
      if (!budgetWarningsFired.hard && state.turnCount >= budgetThresholds.hard) {
        budgetWarningsFired.hard = true;
        state.messages.push({
          role: "user",
          content: [{ type: "text", text: BUDGET_WARNING_HARD }],
        });
        onEvent?.("budget_warning", {
          turn: state.turnCount,
          stage: "hard",
          maxTurns: config.maxTurns,
        });
      }
    }

    let streamedThinkingText = "";
    let streamedUsageInputTokens: number | undefined;
    let streamedUsageOutputTokens: number | undefined;

    // ── Token-level delta forwarding (cloud Live Trace) ──
    // Only wire the per-token callback when a cloud sink is actually
    // listening. For local CLI invocations `isCloudEventSinkActive()`
    // returns false and we leave `onDelta` undefined — the runtime then
    // skips the delta-forwarding branch entirely, so non-cloud runs pay
    // zero per-token overhead beyond the existing thinking-throttle path.
    //
    // `deltaSeq` is keyed by scope so assistant_response and reasoning
    // each get their own monotonic counter. Resets every turn — the
    // (turn, scope) tuple is what the dashboard renderer keys on.
    const cloudActive = isCloudEventSinkActive();
    const deltaSeq: Record<"assistant_response" | "reasoning", number> = {
      assistant_response: 0,
      reasoning: 0,
    };
    const deltaBatchers = cloudActive
      ? new DeltaBatcherSet(({ scope, text }) => {
          const seq = deltaSeq[scope]++;
          eventBus.emit("delta", {
            turn: state.turnCount,
            role: config.role,
            scope,
            text,
            seq,
          });
        })
      : null;

    // Bus event: planner invocation. `tokens_est` is cumulative input
    // tokens going INTO this call — the actual response usage lands on
    // `cost_update` below once the runtime returns.
    eventBus.emit("llm_planner_invoked", {
      turn: state.turnCount,
      model: config.costModel,
      tokens_est: state.totalUsage.inputTokens,
      role: config.role,
    });

    // Call Claude API with native messages + tools
    const result = await runtime.executeNative(
      config.systemPrompt,
      state.messages,
      nativeTools,
      {
        onThinking: (text) => {
          streamedThinkingText = text;
          if (text.trim()) {
            onEvent?.("thinking", {
              turn: state.turnCount,
              text,
            });
          }
        },
        onUsage: (usage) => {
          streamedUsageInputTokens = usage.inputTokens;
          streamedUsageOutputTokens = usage.outputTokens;
          const cumulativeUsage = {
            inputTokens: state.totalUsage.inputTokens + usage.inputTokens,
            outputTokens: state.totalUsage.outputTokens + usage.outputTokens,
          };
          onEvent?.("usage", {
            turn: state.turnCount,
            inputTokens: cumulativeUsage.inputTokens,
            outputTokens: cumulativeUsage.outputTokens,
            estimatedCostUsd: estimateCost(cumulativeUsage, config.costModel),
          });
        },
        ...(deltaBatchers
          ? {
              onDelta: (scope: "assistant_response" | "reasoning", text: string) => {
                deltaBatchers.push(scope, text);
              },
            }
          : {}),
      },
    );

    // Drain any trailing delta buffer before the turn-completed event so
    // the cloud sees the full streamed text BEFORE it sees the next
    // turn's `agent_turn_started` and retires the typing cursor.
    deltaBatchers?.flushAll();

    // `reasoning_summary` is emitted further down once we've also seen the
    // assistant's pre-tool-call text — that lets us fall back to summarising
    // the visible narration when the runtime doesn't stream a separate
    // thinking channel (most non-reasoning models). Without that fallback,
    // every turn from a plain GPT-style model produces zero reasoning_summary
    // events and the dashboard live trace stays cold.

    // Track usage
    if (result.usage) {
      state.totalUsage.inputTokens += result.usage.inputTokens;
      state.totalUsage.outputTokens += result.usage.outputTokens;
      state.totalUsage.cachedInputTokens += result.usage.cachedInputTokens ?? 0;
      // Fold this turn into the shared per-scan ledger (when threaded) so
      // sibling agent sessions see this spend in their own ceiling checks.
      // The session's pricing model keys the ledger's per-model buckets,
      // which the scan_completed cost_breakdown is derived from.
      config.costLedger?.add(result.usage, config.costModel);
      state.estimatedCostUsd = estimateCost(state.totalUsage, config.costModel);
      if (
        streamedUsageInputTokens !== result.usage.inputTokens
        || streamedUsageOutputTokens !== result.usage.outputTokens
      ) {
        onEvent?.("usage", {
          turn: state.turnCount,
          inputTokens: state.totalUsage.inputTokens,
          outputTokens: state.totalUsage.outputTokens,
          estimatedCostUsd: state.estimatedCostUsd,
        });
      }
      // Bus event: cumulative cost snapshot for the cloud relay / dashboard.
      // Token counts ride under BOTH spellings: input_tokens/output_tokens
      // is the engine-canonical pair (bus.ts CostUpdatePayload, consumed by
      // live-agent-state + the dashboard live trace); token_input/
      // token_output is what the orchestrator's scan_jobs segment-sum
      // (updateScanCostFromEvent) keys on. The dual write is additive —
      // without it the cloud's token columns stayed NULL even though the
      // events carried usage (prod review scans: cost_usd 6/6, tokens 0/6).
      eventBus.emit("cost_update", {
        cost_usd: state.estimatedCostUsd,
        input_tokens: state.totalUsage.inputTokens,
        output_tokens: state.totalUsage.outputTokens,
        token_input: state.totalUsage.inputTokens,
        token_output: state.totalUsage.outputTokens,
        turn: state.turnCount,
      });
    }

    // ── Context window compaction (BoxPwnr-inspired) ──
    // Trigger at 60% of context window (~77k tokens for 128k models).
    // Allow multiple compactions as context regrows — don't re-compact until
    // tokens have grown by at least 30k since last compaction.
    //
    // PROMPT-CACHE INTERACTION: this REWRITES history (middle turns collapse
    // into a summary message), which changes the cached prefix and therefore
    // invalidates every message-level cache entry. That is unavoidable — any
    // rewrite of a prefix-matched cache voids it by definition — and it is
    // still the right trade: compaction only fires once the transcript is large
    // enough that carrying it is worse than re-establishing it. Recovery is
    // automatic and needs no bookkeeping here: `llm-api.ts` re-plans breakpoints
    // from the CURRENT message array on every request, so the next call writes a
    // fresh set over the rewritten transcript and the turn after that reads it
    // back. The system prompt + tool schemas keep hitting throughout — compaction
    // never touches them, and they carry their own breakpoint.
    //
    // The threshold itself is measured against total prompt tokens (cache reads
    // included), so a high cache hit rate does not silently defer compaction
    // past the real context limit. See `readCacheUsage` in runtime/prompt-cache.ts.
    const COMPACTION_THRESHOLD = 77_000;
    const COMPACTION_REGROW = 30_000;
    if (
      features.contextCompaction
      && state.totalUsage.inputTokens > COMPACTION_THRESHOLD
      && state.totalUsage.inputTokens - tokensAtLastCompaction > COMPACTION_REGROW
      && state.messages.length > 15
    ) {
      const beforeCount = state.messages.length;

      // Use LLM-based compaction if we have the runtime, otherwise regex
      state.messages = await compactMessagesWithLLM(state.messages, runtime, config.systemPrompt);

      compactionCount++;
      tokensAtLastCompaction = state.totalUsage.inputTokens;

      const afterCount = state.messages.length;
      onEvent?.("context_compacted", {
        turn: state.turnCount,
        inputTokens: state.totalUsage.inputTokens,
        messagesBefore: beforeCount,
        messagesAfter: afterCount,
        compactionNumber: compactionCount,
      });
      if (db) {
        db.logEvent({
          scanId: config.scanId,
          stage: config.role,
          eventType: "context_compacted",
          agentRole: config.role,
          payload: {
            turn: state.turnCount,
            inputTokens: state.totalUsage.inputTokens,
            messagesBefore: beforeCount,
            messagesAfter: afterCount,
            compactionNumber: compactionCount,
          },
          timestamp: Date.now(),
        });
      }
    }

    // Handle error or empty response
    if (result.error || (result.content.length === 0 && (!result.usage || result.usage.outputTokens === 0))) {
      const errorMsg = result.error || "API returned empty response (0 tokens) — model may be rate-limited or unavailable";
      if (
        result.error
        && isContextWindowError(errorMsg)
        && contextOverflowRecoveries < 2
      ) {
        const beforeCount = state.messages.length;
        const preserveTailCount = Math.max(2, 10 - contextOverflowRecoveries * 4);
        const pruned = dropOldestMessages(state.messages, preserveTailCount);
        if (pruned.length < beforeCount) {
          contextOverflowRecoveries++;
          state.messages = pruned;
          tokensAtLastCompaction = state.totalUsage.inputTokens;
          process.stderr.write(
            `[0sec] context overflow: pruned ${beforeCount - pruned.length} old messages `
            + `(recovery ${contextOverflowRecoveries}/2)\n`,
          );
          onEvent?.("context_overflow_recovered", {
            turn: state.turnCount,
            messagesBefore: beforeCount,
            messagesAfter: pruned.length,
            recovery: contextOverflowRecoveries,
          });
          if (state.turnCount > 0) state.turnCount--;
          continue;
        }
      }
      // Transient provider overload / rate-limit / 5xx → back off and retry the
      // SAME turn rather than killing the run. Doesn't consume a turn (the LLM
      // call failed before any tool ran), capped by MAX_TRANSIENT_RETRIES.
      const transient = isTransientLlmError(errorMsg);
      if (transient && transientRetries < MAX_TRANSIENT_RETRIES) {
        transientRetries++;
        const backoffMs = Math.min(20_000, 500 * 2 ** transientRetries);
        process.stderr.write(`[0sec] transient LLM error (retry ${transientRetries}/${MAX_TRANSIENT_RETRIES}, backoff ${backoffMs}): ${errorMsg.slice(0, 120)}\n`);
        onEvent?.("agent_error", { turn: state.turnCount, error: `transient (retry ${transientRetries}): ${errorMsg.slice(0, 200)}` });
        if (state.turnCount > 0) state.turnCount--; // a failed transient turn must not burn budget
        await delay(backoffMs);
        continue;
      }
      process.stderr.write(`[0sec] Agent loop error on turn ${state.turnCount}: ${errorMsg}\n`);
      onEvent?.("agent_error", { turn: state.turnCount, error: errorMsg });
      // Preserve the legacy summary marker — downstream readers (cloud
      // relay legacy paths, CLI TUI) still key on the "Error: " prefix
      // for back-compat. The `errorExit` field below is the structured
      // signal modern callers should branch on to distinguish a planner
      // bailout from a clean completion.
      state.summary = `Error: ${errorMsg}`;
      state.errorExit = { error: errorMsg, turn: state.turnCount };
      if (db) {
        db.logEvent({
          scanId: config.scanId,
          stage: config.role,
          eventType: "agent_error",
          agentRole: config.role,
          payload: { turn: state.turnCount, error: errorMsg },
          timestamp: Date.now(),
        });
      }
      break;
    }

    // Append assistant response. `providerRaw` rides along so the next request
    // can replay this turn's reasoning items verbatim instead of dropping them
    // (see ProviderRawOutput); the runtime only replays it back to the same
    // provider+model+wireApi that produced it.
    state.messages.push({
      role: "assistant",
      content: result.content,
      ...(result.providerRaw ? { providerRaw: result.providerRaw } : {}),
    });

    // Extract tool_use blocks
    const textBlocks = result.content.filter(
      (b): b is Extract<NativeContentBlock, { type: "text" }> => b.type === "text",
    );
    const textContent = textBlocks.map((b) => b.text).join("\n");
    if (textContent.trim() && textContent.trim() !== streamedThinkingText.trim()) {
      onEvent?.("thinking", {
        turn: state.turnCount,
        text: textContent,
      });
    }

    // Bus event: reasoning_summary — a 1-line distillation of the model's
    // thinking for the dashboard agent-trace UI. Source order:
    //   1. `streamedThinkingText` from a runtime that exposes a separate
    //      thinking/reasoning channel (Claude w/ extended thinking, GPT-o
    //      family, etc.).
    //   2. `textContent` — the model's pre-tool-call narration ("I'll
    //      now inspect /admin for stale session cookies"). Most non-
    //      reasoning models produce this; the heuristic picks the first
    //      sentence so it reads as a "thinking out loud" snippet.
    // Wrapped in try/catch so a bad summary never kills the scan; emitted
    // at most once per turn and only when the result is non-empty.
    try {
      const reasoningSource = streamedThinkingText.trim()
        ? streamedThinkingText
        : textContent;
      const summary = summarizeReasoning(reasoningSource);
      if (summary) {
        eventBus.emit("reasoning_summary", {
          turn: state.turnCount,
          summary,
        });
      }
    } catch {
      /* heuristic failure must never abort the scan */
    }

    const toolUseBlocks = result.content.filter(
      (b): b is Extract<NativeContentBlock, { type: "tool_use" }> =>
        b.type === "tool_use",
    );

    if (toolUseBlocks.length > 0) {
      lastToolName = toolUseBlocks[toolUseBlocks.length - 1].name;
    }

    // If no tool calls, the model responded with text only
    if (toolUseBlocks.length === 0) {
      // Only allow early exit if the agent has done meaningful work:
      // - At least 4 turns (read files, ran commands, analyzed code)
      // - OR explicitly called the done tool (handled below in tool execution)
      // `textContent.trim()` is load-bearing: an empty-text end_turn is not a
      // conclusion. It used to be impossible to hit on the Responses path
      // because the reasoning summary was flattened into `content`, so the
      // model's *thinking* became the scan's reported summary. That paraphrase
      // no longer enters `content` (llm-api.ts), which leaves a genuinely
      // silent turn silent — and marking it `done` with an empty summary would
      // report `status: "success"` alongside the "reached max turns" fallback
      // string from the tail of this function. Nudge the agent instead.
      const minTurns = Math.min(4, config.maxTurns);
      if (state.turnCount >= minTurns && result.stopReason === "end_turn" && textContent.trim()) {
        state.summary = textContent;
        state.done = true;
        break;
      }

      // Push the agent to keep working — but only if the last message
      // in the conversation is from the user (avoid invalid sequences
      // where two user messages follow each other on the Responses API)
      const lastMsg = state.messages[state.messages.length - 1];
      if (lastMsg?.role !== "user") {
        state.messages.push({
          role: "user",
          content: [
            {
              type: "text",
              text: buildContinuePrompt(config, state.turnCount, memoryPath),
            },
          ],
        });
      }
      continue;
    }

    // Execute each tool call and collect results
    const toolCalls: ToolCall[] = [];
    const toolResults: ToolResult[] = [];
    const toolResultBlocks: NativeContentBlock[] = [];
    // Action-level durable log for this turn (one entry per tool invocation,
    // each with its own wall clock + the correlation id that joins it to the
    // `tool_artifact` row). Persisted below as the `tool_calls` payload.
    const actionLog: ToolCallLogEntry[] = [];
    // Inline-validation context notes accumulated this turn (#554). Appended as
    // text blocks to the tool-results user message below so the agent sees the
    // confirmed/unconfirmed verdict on its NEXT turn.
    const inlineValidationNotes: string[] = [];

    for (const block of toolUseBlocks) {
      const call: ToolCall = { name: block.name, arguments: block.input };
      toolCalls.push(call);
      // Track the call signature for doom-loop detection (see after the loop).
      toolCallLog.push(toolCallSignature(call.name, call.arguments));
      if (toolCallLog.length > 12) toolCallLog.shift();

      // Correlation id for this single invocation — threaded into the executor
      // so any `tool_artifact` it persists carries the same key, and recorded
      // on the action-log entry below.
      const correlationId = newCorrelationId();
      const toolStartedAt = Date.now();

      // Bus event: tool_call_started. `args_preview` is a short, safe
      // rendering of the tool invocation suitable for dashboard UI.
      let argsPreview: string;
      try {
        argsPreview = toolCallPreview(call).slice(0, 200);
      } catch {
        argsPreview = block.name;
      }
      eventBus.emit("tool_call_started", {
        tool: block.name,
        turn: state.turnCount,
        args_preview: argsPreview,
        ts: toolStartedAt,
      });

      // Shadow journal: record the tool call (#494). `block.id` is the native
      // tool_use id; reuse it as the callId so the matching tool_result entry
      // joins to this call during rehydration.
      shadowJournal.append({
        kind: "tool_call",
        tool: block.name,
        arguments: block.input as Record<string, unknown>,
        turn: state.turnCount,
        callId: block.id,
      });

      const toolResult = await executor.execute(call, { correlationId });
      const toolEndedAt = Date.now();
      toolResults.push(toolResult);
      actionLog.push(
        buildToolCallLogEntry({
          call,
          correlationId,
          startedAt: toolStartedAt,
          endedAt: toolEndedAt,
          result: { success: toolResult.success, error: toolResult.error },
        }),
      );

      // Shadow journal: record the tool result (#494). Large outputs are
      // sidecarred by the writer; here we only attach the raw output and let
      // the writer's threshold logic decide. Errors are recorded too.
      shadowJournal.append({
        kind: "tool_result",
        tool: block.name,
        ok: toolResult.success,
        ...(toolResult.success ? { output: toolResult.output } : { error: toolResult.error }),
        turn: state.turnCount,
        callId: block.id,
      });

      // Bus event: tool_call_completed.
      eventBus.emit("tool_call_completed", {
        tool: block.name,
        turn: state.turnCount,
        duration_ms: toolEndedAt - toolStartedAt,
        status: toolResult.success ? "ok" : "error",
        ...(toolResult.success ? {} : { error: toolResult.error ?? "unknown" }),
        ts: toolEndedAt,
      });

      // Bus event: finding_ingested — fires whenever the agent successfully
      // saves a finding so downstream sinks (cloud relay, dashboard) see the
      // finding at creation time rather than waiting for the final report.
      // `input.confidence` is the hybrid value the `save_finding` tool
      // stamped back onto the call args (LLM self-report clamped UP to a
      // PoC-status floor — see agent/finding-confidence.ts), not the raw
      // LLM-reported number.
      if (block.name === "save_finding" && toolResult.success) {
        const f = toolResult.output as Record<string, unknown> | undefined;
        const input = block.input as Record<string, unknown>;
        const confidence =
          typeof input.confidence === "number" && Number.isFinite(input.confidence)
            ? input.confidence
            : undefined;
        eventBus.emit("finding_ingested", {
          finding_id: typeof f?.id === "string" ? f.id : typeof f?.findingId === "string" ? f.findingId : undefined,
          severity: typeof input.severity === "string" ? input.severity : undefined,
          title: typeof input.title === "string" ? input.title : undefined,
          description: typeof input.description === "string" ? input.description : undefined,
          category: typeof input.category === "string" ? input.category : undefined,
          confidence,
          evidence_request:
            typeof input.evidence_request === "string" && input.evidence_request.trim()
              ? input.evidence_request
              : undefined,
          evidence_response:
            typeof input.evidence_response === "string" && input.evidence_response.trim()
              ? input.evidence_response
              : undefined,
          evidence_analysis:
            typeof input.evidence_analysis === "string" && input.evidence_analysis.trim()
              ? input.evidence_analysis
              : undefined,
          source_path:
            typeof input.source_path === "string" && input.source_path.trim()
              ? input.source_path
              : undefined,
          source_start_line:
            typeof input.source_start_line === "number" && Number.isInteger(input.source_start_line)
              ? input.source_start_line
              : undefined,
          source_end_line:
            typeof input.source_end_line === "number" && Number.isInteger(input.source_end_line)
              ? input.source_end_line
              : undefined,
          poc_steps:
            typeof input.poc_steps === "string" && input.poc_steps.trim()
              ? input.poc_steps
              : undefined,
          verification_spec:
            typeof input.verification_spec === "string" && input.verification_spec.trim()
              ? input.verification_spec
              : undefined,
        });
        // Shadow journal: record the finding (#494) as a first-class entry so
        // a rehydrated context sees confirmed findings without replaying the
        // whole tool stream.
        shadowJournal.append({
          kind: "finding",
          finding: { ...(f ?? {}), ...input },
        });

        // 0sec#771/#773 — cross-target `credential_shared` emit is now wired
        // (opt-in) at the loot-harvest site: when `config.trustGraph` is set, a
        // newly-harvested value whose hash matches a prior scan's credential
        // from a DIFFERENT source target emits a `credential_shared` entry via
        // `trustGraph.noteHarvest` (see the harvest block below). It hangs off
        // the durable store rather than save_finding because the reuse signal is
        // the recovered VALUE, not the finding shape. No-op when trustGraph is
        // not opted in, so this single-target finding path is unchanged.

        // ── Accepted finding callback + inline validation (#554) ──
        // First expose the actual persisted finding (not the agent's proposed
        // tool arguments) to optional sinks. Then, for high/critical findings,
        // run the cheap deterministic oracle and feed the verdict back so the
        // agent stops piling on a confirmed lead — or knows not to assume
        // success on an unconfirmed one. The callback fires only for a new
        // saved record; a dedup merge is skipped. Inline errors remain
        // inconclusive, never false-positive.
        const saveMsg = typeof f?.message === "string" ? f.message : "";
        const findingId = typeof f?.findingId === "string" ? f.findingId : undefined;
        const saved =
          saveMsg === "Finding saved" && findingId
            ? toolCtx.findings.find((x) => x.id === findingId)
            : undefined;
        if (saved) {
          try {
            await onFindingSaved?.(saved);
          } catch {
            // External sinks must not make a successfully-saved local finding fail.
          }
          // Hunt memory: persist a redacted record of this finding so future
          // hunts on this / similar targets can learn from it. Self-contained
          // and best-effort — swallows its own errors, never blocks the save.
          recordFindingToMemory(saved);
          // Live findings tail (data path for a `tail -f findings.md`-style
          // view). Additive + non-blocking: gated on the coordinator-rails flag,
          // emits one sanitized single-line summary through `onEvent` as each
          // finding lands. Best-effort — a formatter error never fails the save.
          if (coordinatorRailsEnabled) {
            try {
              const tailLine = formatFindingTailLine(saved);
              if (tailLine) {
                onEvent?.("findings_tail", {
                  turn: state.turnCount,
                  findingId: saved.id,
                  line: tailLine,
                });
              }
            } catch {
              /* findings tail is best-effort, never blocks the loop */
            }
          }
        }
        if (
          features.inlineValidation &&
          saved &&
          shouldValidateInline(saved)
        ) {
          const inlineStartedAt = Date.now();
          const outcome = await validateFindingInline(saved, config.target, {
            oracle: inlineValidationOracle,
          });
          // Stamp the verdict on the finding so EGATS scoreEvidence and the
          // batch oracle/PoV gate can read it (skip the redundant re-run).
          saved.inlineValidation = {
            confirmed: outcome.confirmed,
            inconclusive: outcome.inconclusive,
            reason: outcome.reason,
            evidence: outcome.evidence || undefined,
            confidence: outcome.confidence,
          };
          state.inlineValidations.push(outcome);
          inlineValidationNotes.push(buildInlineValidationNote(outcome));

          const inlinePayload = {
            turn: state.turnCount,
            findingId: outcome.findingId,
            category: outcome.category,
            severity: outcome.severity,
            confirmed: outcome.confirmed,
            inconclusive: outcome.inconclusive,
            reason: outcome.reason,
            durationMs: Date.now() - inlineStartedAt,
          };
          onEvent?.("inline_validation", inlinePayload);
          eventBus.emit("inline_validation", inlinePayload);
          if (db) {
            db.logEvent({
              scanId: config.scanId,
              stage: config.role,
              eventType: "inline_validation",
              agentRole: config.role,
              payload: inlinePayload,
              timestamp: Date.now(),
            });
          }
        }
      }

      // Check if agent called done
      if (block.name === "done" && toolResult.success) {
        state.done = true;
        state.summary = (toolResult.output as { summary: string }).summary;
      }

      // Build tool_result block.
      //
      // Inbound prompt-injection defense (#558): output from untrusted-source
      // tools (http_request / crawl / read_file / send_prompt / submit_form /
      // browser / MCP) is attacker-influenced. Before it re-enters model
      // context — and before it feeds the recentToolResultTexts buffer used by
      // dynamic playbooks + JIT skills below — we wrap it in DATA-not-
      // instructions delimiters and NEUTRALIZE (escape + annotate, never drop)
      // common injection markers. Our own structured outputs (save_finding,
      // query_findings, done, …) are trusted and pass through untouched.
      // Deterministic / pattern-based only; no LLM-guards-LLM.
      let resultContent = toolResult.success
        ? JSON.stringify(toolResult.output)
        : `Error: ${toolResult.error}`;
      // 0sec#567 — harvest reusable footholds from evidence-bearing tool
      // results into the loot ledger. Done on the RAW output (before the
      // injection-marker sanitizer rewrites it) and only for tools whose
      // output reflects target data — never our own trusted bookkeeping
      // results (save_finding / query_findings / use_loot / done). Best-effort:
      // a harvest failure must never abort the agent loop.
      if (loot && toolResult.success && shouldHarvestLoot(block.name)) {
        try {
          const harvested = loot.harvest(resultContent, block.name, state.turnCount);
          // 0sec#771 — if any newly-harvested value matches a credential a
          // PRIOR scan recovered from a DIFFERENT source target, that's a
          // cross-target reuse → emit a `credential_shared` journal entry. No-op
          // when trustGraph is not opted in. Best-effort: never abort the loop.
          if (trustGraph && harvested.length > 0) {
            try {
              trustGraph.noteHarvest(harvested, state.turnCount);
            } catch {
              /* credential_shared emit is best-effort */
            }
          }
        } catch {
          /* harvesting is best-effort */
        }
      }
      if (toolResult.success && isUntrustedSourceTool(block.name)) {
        const sanitized = sanitizeUntrustedToolResult(resultContent);
        resultContent = sanitized.content;
        if (sanitized.neutralized) {
          eventBus.emit("untrusted_input_sanitized", {
            tool: block.name,
            turn: state.turnCount,
            role: config.role,
            markers: sanitized.markers,
          });
        }
      }
      toolResultBlocks.push({
        type: "tool_result",
        tool_use_id: block.id,
        content: resultContent,
        is_error: !toolResult.success,
      });
    }

    // Inline-validation notes (#554): append as text blocks to the SAME
    // tool-results user message so the verdict reaches the agent next turn
    // without creating an invalid two-user-messages-in-a-row sequence.
    for (const note of inlineValidationNotes) {
      toolResultBlocks.push({ type: "text", text: note });
    }

    // Doom-loop guard: if the last several tool calls are byte-identical the
    // agent is stuck re-running the same thing (a failing probe, a command that
    // never changes). Inject a one-line nudge into the SAME tool-results message
    // so it lands next turn, then reset the window so it warns once per streak.
    const doom = detectDoomLoop(toolCallLog);
    if (doom.looping && doom.signature) {
      toolResultBlocks.push({ type: "text", text: `[0sec] ${doomLoopNudge(doom.signature, doom.count ?? 0)}` });
      onEvent?.("doom_loop", { turn: state.turnCount, signature: doom.signature, count: doom.count ?? 0 });
      if (db) {
        db.logEvent({
          scanId: config.scanId,
          stage: config.role,
          eventType: "doom_loop",
          agentRole: config.role,
          payload: { turn: state.turnCount, count: doom.count ?? 0 },
          timestamp: Date.now(),
        });
      }
      toolCallLog.length = 0;
    }

    // Append tool results as user message
    state.messages.push({ role: "user", content: toolResultBlocks });

    // If the model registered new tools this turn via `self_extend`, union them
    // into the model-facing tool set so they are callable on the NEXT turn.
    // Idempotent: a no-op unless self-extension is enabled and something new was
    // registered.
    syncExtensionTools();

    // ── Collect tool result text for playbook detection + skill triggers ──
    // Feed the shared recentToolResultTexts buffer whenever dynamic
    // playbooks need them (pre-injection) OR JIT skills are enabled
    // (skill trigger matching needs the full history). The buffer is the
    // same array reference threaded into toolCtx (#458).
    // The playbook half of this condition used to stop filling the buffer once
    // the one-shot injection had fired. Now that the injection can be re-
    // evaluated (below), the buffer has to keep flowing so a class detected
    // only after deeper recon can still be picked up.
    if (features.dynamicPlaybooks || features.jitSkills) {
      for (const block of toolResultBlocks) {
        if (block.type === "tool_result") {
          recentToolResultTexts.push(block.content);
          if (recentToolResultTexts.length > 20) recentToolResultTexts.shift();
        }
      }
    }

    // ── Dynamic playbook injection at ~30% budget ──
    // After initial reconnaissance, pattern-match tool results to detect
    // vulnerability types and inject targeted methodology playbooks.
    //
    // This block used to be strictly one-shot: a `playbookInjected` latch fired
    // once and the methodology then lived ONLY in the transcript. That made it
    // the one piece of injected guidance that did not survive compaction — a
    // `compactMessagesWithLLM` pass at turn ~25 could silently erase the
    // playbook injected at turn 12, so the feature aimed at long runs lost its
    // content precisely on long runs. Worse for evaluation: whether the
    // methodology was present at the end of a run depended on whether a
    // compaction happened to land after the injection turn, which means an A/B
    // of this flag would partly be measuring compaction timing rather than the
    // feature.
    //
    // Fix follows the loot / plan pattern — re-render from structured state
    // (the detected type list) rather than trusting the message to survive —
    // with one refinement. Loot and plan re-inject on a fixed turn interval and
    // accept duplicate blocks; a playbook block is up to ~3.6k tokens, so
    // periodic duplication would be a real context cost. Instead we re-inject
    // only when the block is ABSENT from the live message window, which is a
    // cheap deterministic check over a bounded array and re-injects exactly
    // when compaction ate it — zero duplicates in the steady state. The default
    // for `dynamicPlaybooks` is deliberately unchanged (still OFF); this makes
    // the mechanism sound so a future A/B measures the feature itself.
    const playbookPct = state.turnCount / config.maxTurns;
    if (
      features.dynamicPlaybooks
      && playbookPct >= 0.3
      && recentToolResultTexts.length > 0
    ) {
      const detectedTypes = detectPlaybooks(recentToolResultTexts);
      // Re-inject when the class set changed (deeper recon revealed another
      // vuln class) or when the block is no longer present in the window.
      const typesChanged =
        detectedTypes.join("|") !== injectedPlaybookTypes.join("|");
      const needsReinject =
        detectedTypes.length > 0
        && (typesChanged || !messagesContainText(state.messages, PLAYBOOK_MARKER));
      if (needsReinject) {
        const playbookText = buildPlaybookInjection(detectedTypes);
        if (playbookText) {
          state.messages.push({
            role: "user",
            content: [{ type: "text", text: playbookText }],
          });
          const isFirstInjection = !playbookInjected;
          playbookInjected = true;
          injectedPlaybookTypes = detectedTypes;
          onEvent?.("playbook_injected", {
            turn: state.turnCount,
            types: detectedTypes,
            // Distinguishes the initial injection from a post-compaction
            // restore so the two are separable in run analysis.
            reason: isFirstInjection ? "initial" : typesChanged ? "types_changed" : "restored",
          });
          if (db) {
            db.logEvent({
              scanId: config.scanId,
              stage: config.role,
              eventType: "playbook_injected",
              agentRole: config.role,
              payload: { turn: state.turnCount, types: detectedTypes },
              timestamp: Date.now(),
            });
          }
        }
      }
    }

    // ── Known-footholds (loot) injection (0sec#567) ──
    // Re-surface captured footholds so the agent reuses them to chain to
    // higher impact. The block is re-rendered from the structured ledger (not
    // the original tool result), so it survives context compaction. Throttled:
    // inject when the ledger grew since the last injection, OR at least every
    // LOOT_REINJECT_INTERVAL turns — that keeps an early credential in the
    // recent window without re-pushing identical text every single turn.
    const LOOT_REINJECT_INTERVAL = 3;
    if (
      loot
      && loot.size > 0
      && (loot.revision !== lastInjectedLootRevision
        || state.turnCount - lastLootInjectionTurn >= LOOT_REINJECT_INTERVAL)
    ) {
      const lootText = loot.render({ limit: 12 });
      if (lootText) {
        state.messages.push({
          role: "user",
          content: [{ type: "text", text: lootText }],
        });
        lastInjectedLootRevision = loot.revision;
        lastLootInjectionTurn = state.turnCount;
        onEvent?.("loot_injected", {
          turn: state.turnCount,
          count: loot.size,
          revision: loot.revision,
        });
        if (db) {
          db.logEvent({
            scanId: config.scanId,
            stage: config.role,
            eventType: "loot_injected",
            agentRole: config.role,
            payload: { turn: state.turnCount, count: loot.size, revision: loot.revision },
            timestamp: Date.now(),
          });
        }
      }
    }

    // ── Plan (TODO ledger) injection ──
    // Same mechanism and the same reason as the loot block above: the plan is
    // re-rendered from STRUCTURED STATE, so `compactMessagesWithLLM` summarizing
    // away or dropping the message that carried it costs nothing — the next
    // injection reproduces it exactly. A plan that lived only in the transcript
    // would not survive, which is precisely the failure the external-memory
    // scratchpad has today.
    //
    // Throttled on the same revision-or-interval rule, but with a longer
    // interval: unlike loot (where a credential captured at turn 12 must stay
    // in the recent window), an unchanged plan re-pushed every third turn is
    // pure repetition. Revision changes still inject immediately, so a plan the
    // agent is actively maintaining is always current in context.
    const PLAN_REINJECT_INTERVAL = 6;
    if (
      plan
      && plan.size > 0
      && (plan.revision !== lastInjectedPlanRevision
        || state.turnCount - lastPlanInjectionTurn >= PLAN_REINJECT_INTERVAL)
    ) {
      const planText = plan.render();
      if (planText) {
        state.messages.push({
          role: "user",
          content: [{ type: "text", text: planText }],
        });
        lastInjectedPlanRevision = plan.revision;
        lastPlanInjectionTurn = state.turnCount;
        onEvent?.("plan_injected", {
          turn: state.turnCount,
          open: plan.open().length,
          total: plan.size,
          revision: plan.revision,
        });
      }
    }

    // ── Task-drift detection ──
    // Deliberately placed alongside loop detection because the two are
    // complementary halves of "the agent has stopped making progress":
    // `loopDetector` catches repetition (same call over and over), this catches
    // divergence (novel activity every turn, none of it on-task). Neither sees
    // the other's failure mode. Deterministic and free — see agent/drift.ts for
    // the signal and, importantly, for what it cannot see.
    if (driftMonitor) {
      driftMonitor.record(toolCalls, plan?.openText() ?? "");
      const driftWarning = driftMonitor.detect();
      if (driftWarning) {
        state.messages.push({
          role: "user",
          content: [{ type: "text", text: driftWarning }],
        });
        const driftState = driftMonitor.state;
        onEvent?.("drift_detected", {
          turn: state.turnCount,
          streak: driftState.streak,
          anchorSize: driftState.anchorSize,
          warningsIssued: driftState.warningsIssued,
        });
        if (db) {
          db.logEvent({
            scanId: config.scanId,
            stage: config.role,
            eventType: "drift_detected",
            agentRole: config.role,
            payload: {
              turn: state.turnCount,
              streak: driftState.streak,
              anchorSize: driftState.anchorSize,
            },
            timestamp: Date.now(),
          });
        }
      }
    }

    // ── Loop / oscillation detection ──
    if (features.loopDetection) loopDetector.record(toolCalls);
    const loopWarning = features.loopDetection ? loopDetector.detect() : null;
    if (loopWarning) {
      // Inject warning into the conversation so the model sees it next turn
      state.messages.push({
        role: "user",
        content: [{ type: "text", text: loopWarning }],
      });
      onEvent?.("loop_detected", { turn: state.turnCount });
    }

    // Track tool usage for early-stop logic
    for (const call of toolCalls) {
      toolsUsedSet.add(call.name);
      if (call.name === "save_finding") {
        saveFindingCalled = true;
      }
    }

    // ── Early-stop check at 50% budget ──
    // If the agent is at the halfway point, hasn't found anything, and this
    // is the first attempt (retryCount === 0), bail out so the caller can
    // retry with a different strategy. Only applies to attack role with a
    // meaningful budget (>= 10 turns — below that, early-stop overhead isn't
    // worth it).
    const retryCount = config.retryCount ?? 0;
    const halfwayTurn = Math.floor(config.maxTurns / 2);
    if (
      features.earlyStopRetry
      && config.role === "attack"
      && retryCount === 0
      && config.maxTurns >= 10
      && state.turnCount >= halfwayTurn
      && !saveFindingCalled
      && !state.done
    ) {
      state.earlyStopNoProgress = true;
      state.attemptSummary = `Used tools: ${[...toolsUsedSet].join(", ")}. Ran ${state.turnCount} turns without calling save_finding.`;
      state.summary = `Early stop at turn ${state.turnCount}/${config.maxTurns}: no findings — retry recommended.`;

      // Generate LLM-based structured progress summary for the retry
      if (features.progressHandoff) {
        try {
          state.progressSummary = await generateProgressSummary(state.messages, runtime);
          // Optionally export to disk for cross-session handoff
          const progressDir = `/tmp/0sec-progress-${config.scanId}`;
          try {
            fs.mkdirSync(progressDir, { recursive: true });
            const progressFile = `${progressDir}/progress.json`;
            fs.writeFileSync(progressFile, JSON.stringify({
              scanId: config.scanId,
              target: config.target,
              turnCount: state.turnCount,
              maxTurns: config.maxTurns,
              toolsUsed: [...toolsUsedSet],
              progressSummary: state.progressSummary,
              timestamp: Date.now(),
            }, null, 2));
            state.progressPath = progressFile;
          } catch { /* non-fatal — disk export is best-effort */ }
        } catch {
          // LLM summary failed — fall back to the shallow attemptSummary
          state.progressSummary = "";
        }
      }

      onEvent?.("early_stop_no_progress", {
        turn: state.turnCount,
        maxTurns: config.maxTurns,
        toolsUsed: [...toolsUsedSet],
        hasProgressSummary: state.progressSummary.length > 0,
      });
      break;
    }

    // Notify callback
    onTurn?.(state.turnCount, toolCalls, toolResults, textContent);

    // Log tool calls
    if (db) {
      db.logEvent({
        scanId: config.scanId,
        stage: config.role,
        eventType: "tool_calls",
        agentRole: config.role,
        // Action-level: one entry per invocation with its own startedAt /
        // durationMs / redacted args / correlationId. `tools` + `results` are
        // still emitted for readers that predate the upgrade.
        payload: buildToolCallsPayload(state.turnCount, actionLog),
        timestamp: Date.now(),
      });
    }

    // Persist session state periodically
    if (db && state.turnCount % 2 === 0) {
      persistSession(db, state, config, "running");
    }

    // ── Cost ceiling check ──
    // After every tool-call turn, recompute the running cost estimate from
    // the cumulative token usage. If the user configured a hard ceiling and
    // we've exceeded it, break out of the loop. Findings collected so far
    // are preserved on `state.findings`.
    //
    // When a shared per-scan ledger is threaded, price the LEDGER's
    // cross-session cumulative total: a scan running multiple agent sessions
    // (research + the verify wave) must trip the ceiling on their combined
    // spend, not grant each session the full ceiling independently.
    if (config.costCeilingUsd !== undefined && config.costCeilingUsd > 0) {
      const runningCost = config.costLedger
        ? config.costLedger.totalCostUsd()
        : estimateCost(state.totalUsage, config.costModel);
      if (runningCost >= config.costCeilingUsd) {
        state.costCeilingExceeded = true;
        state.estimatedCostUsd = runningCost;
        state.summary = `Cost ceiling exceeded at turn ${state.turnCount}: $${runningCost.toFixed(4)} >= $${config.costCeilingUsd.toFixed(4)} ceiling. Aborting with ${toolCtx.findings.length} partial finding(s).`;
        onEvent?.("cost_ceiling_exceeded", {
          turn: state.turnCount,
          runningCostUsd: runningCost,
          ceilingUsd: config.costCeilingUsd,
          findingCount: toolCtx.findings.length,
        });
        if (db) {
          db.logEvent({
            scanId: config.scanId,
            stage: config.role,
            eventType: "cost_ceiling_exceeded",
            agentRole: config.role,
            payload: {
              turn: state.turnCount,
              runningCostUsd: runningCost,
              ceilingUsd: config.costCeilingUsd,
              findingCount: toolCtx.findings.length,
            },
            timestamp: Date.now(),
          });
        }
        break;
      }
    }
    } finally {
      // Bus event: agent turn boundary end. Exit reason is inferred from
      // state flags set by the various break paths inside the body. If the
      // loop will iterate again (done=false and no early/error flag),
      // that's the "continue" case.
      if (state.done) {
        turnExitReason = "finished";
      } else if (state.costCeilingExceeded) {
        turnExitReason = "cost_ceiling";
      } else if (state.earlyStopNoProgress) {
        turnExitReason = "early_stop";
      } else if (state.summary.startsWith("Error:")) {
        turnExitReason = "error";
      } else if (state.turnCount >= config.maxTurns) {
        turnExitReason = "max_turns";
      }
      eventBus.emit("agent_turn_completed", {
        turn: state.turnCount,
        duration_ms: Date.now() - turnStartedAt,
        reason: turnExitReason,
        role: config.role,
      });
    }
  }

  // Sync final state
  state.findings = toolCtx.findings;
  state.attackResults = toolCtx.attackResults;
  state.targetInfo = toolCtx.targetInfo;

  // 0sec#771 — on loop completion, persist this scan's in-memory loot ledger
  // to the durable store (hash + redacted preview only; the plaintext never
  // leaves the in-memory ledger). No-op when trustGraph is not opted in or the
  // ledger is empty. Best-effort: a persist failure must never break the return
  // path or the final session save below.
  if (trustGraph && loot && loot.size > 0) {
    try {
      const persisted = trustGraph.persist(loot, {
        target: config.target,
        scanId: config.scanId,
      });
      onEvent?.("credentials_persisted", {
        scanId: config.scanId,
        count: persisted,
      });
    } catch {
      /* durable persist is best-effort */
    }
  }

  // Keep the final return value on the same model-specific rate used for every
  // turn and cost-ceiling check; dropping costModel here reprices Azure runs at
  // the generic fallback after the loop completes.
  state.estimatedCostUsd = estimateCost(state.totalUsage, config.costModel);

  // If none of the break paths set a summary, the loop exited naturally by
  // completing all maxTurns iterations. Only in that case do we stamp the
  // generic "reached max turns" message. Previously this branch also fired
  // whenever any break path did not flip one of the three termination flags
  // — notably the API-error bail at ~line 263 sets state.summary to an
  // "Error: ..." string but does NOT set done/earlyStopNoProgress/
  // costCeilingExceeded, and the post-loop code would silently overwrite
  // the real error message with "reached max turns (N)". That produced
  // internally inconsistent stage summaries in the scan TUI like:
  //   "Retry (5 turns): Agent reached max turns (10) without completing"
  // where the real cause was a transient Azure API timeout on turn 5.
  if (!state.summary) {
    state.summary = `Agent reached max turns (${config.maxTurns}) without completing.`;
  }

  // Shadow journal: terminal entry (#494). Mirrors the loop's own
  // done/timeout/error verdict so a replayed journal knows the run is closed.
  if (shadowJournal.enabled) {
    shadowJournal.append({
      kind: "done",
      status: state.done ? "success" : state.summary.startsWith("Error:") ? "failed" : "cancelled",
      summary: state.summary.slice(0, 2000),
    });
  }

  // Final session save
  if (db) {
    persistSession(db, state, config, state.done ? "completed" : "paused");
    db.logEvent({
      scanId: config.scanId,
      stage: config.role,
      eventType: "agent_complete",
      agentRole: config.role,
      payload: {
        sessionId: state.sessionId,
        turnCount: state.turnCount,
        findingCount: state.findings.length,
        done: state.done,
        usage: state.totalUsage,
        estimatedCostUsd: state.estimatedCostUsd,
        summary: state.summary.slice(0, 500),
      },
      timestamp: Date.now(),
    });
  }

  // Tool-health roll-up (0sec#tool-reliability): attach the deduped summary to
  // the returned state and log a concise "N tool issues" line so the operator
  // sees WHY a tool didn't run. Non-blocking / fail-soft.
  try {
    const toolHealth = executor.toolHealthSummary();
    state.toolHealth = toolHealth;
    if (toolHealth.total > 0 && db) {
      db.logEvent({
        scanId: config.scanId,
        stage: "attack",
        eventType: "tool_health_summary",
        payload: {
          total: toolHealth.total,
          occurrences: toolHealth.occurrences,
          byCategory: toolHealth.byCategory,
          missing: toolHealth.missing,
          line: toolHealth.line,
        },
        timestamp: Date.now(),
      });
    }
  } catch {
    // Reporting is best-effort; never fail a completed run over it.
  }

  // Structured full-state plan (TodoWrite shape): attach the final snapshot to
  // the returned state and log it once so the plan the model ended on is part
  // of the run record. Non-blocking / fail-soft — a plan is working state, and
  // never worth failing a completed run over.
  try {
    const todos = executor.todosSnapshot();
    state.todos = todos;
    if (todos.progress.total > 0 && db) {
      db.logEvent({
        scanId: config.scanId,
        stage: "attack",
        eventType: "todos_summary",
        payload: {
          done: todos.progress.done,
          total: todos.progress.total,
          line: todos.summaryLine,
          revision: todos.revision,
          groups: todos.groups.map((g) => ({
            group: g.group,
            done: g.done,
            total: g.total,
          })),
        },
        timestamp: Date.now(),
      });
    }
  } catch {
    // Reporting is best-effort; never fail a completed run over it.
  }

  // Clean up per-scan external memory file
  try { fs.unlinkSync(memoryPath); } catch { /* file may not exist */ }

  return state;
  } finally {
    executor.cleanup();
    unregisterSignalCleanup();
    unsubscribeCoordinator();
  }
}

// ── Context Window Compaction (BoxPwnr-style) ──
// When the conversation grows too large, replace middle messages with a summary
// while preserving critical ones (credentials, flags, findings) and the tail.

/** Patterns that indicate a message contains critical information worth preserving verbatim. */
const CRITICAL_PATTERNS = [
  /flag/i, /password/i, /credentials?/i, /cookie/i, /token/i,
  /session/i, /admin/i, /root/i, /\/etc\/passwd/i, /save_finding/i,
  /secret/i, /api[_-]?key/i, /bearer/i, /jwt/i,
];

/**
 * Critical-message regex used by `compactMessagesWithLLM` to decide which
 * middle messages to preserve verbatim alongside the LLM summary, gated
 * behind `features.preserveCriticalMessages` (0sec#229, BoxPwnr-inspired).
 *
 * Tuned to high-signal tokens that survive paraphrasing poorly — the
 * literal credential string is what matters, not the model's recap of it.
 */
export const CRITICAL_MESSAGE_PATTERNS =
  /\b(password|credential|root|shell|access gained|vulnerability|exploit successful|key found|login|authenticated)\b/i;

/** Patterns for extracting noteworthy lines from tool results for the summary. */
const SUMMARY_EXTRACT_PATTERNS = [
  /flag\{[^}]*\}/i, /password[\s:="]+\S+/i, /token[\s:="]+\S+/i,
  /cookie[\s:="]+\S+/i, /secret[\s:="]+\S+/i, /api[_-]?key[\s:="]+\S+/i,
  /HTTP\/\d\.\d\s+\d{3}/i, /status[\s:]+\d{3}/i,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/,
  /\/[\w/.-]{3,}/, // file paths / URL paths
  /error|denied|forbidden|unauthorized|success|found|vulnerable/i,
  /save_finding/i,
  /admin|root|sudo/i,
];

function serializeMessageToText(msg: NativeMessage): string {
  const parts: string[] = [];
  for (const block of msg.content) {
    if (block.type === "text") parts.push(block.text);
    else if (block.type === "tool_use") parts.push(`${block.name}(${JSON.stringify(block.input)})`);
    else if (block.type === "tool_result") parts.push(block.content);
  }
  return parts.join("\n");
}

function isCriticalMessage(msg: NativeMessage): boolean {
  const text = serializeMessageToText(msg);
  return CRITICAL_PATTERNS.some((p) => p.test(text));
}

function extractKeyFindings(messages: NativeMessage[]): string {
  const findings: string[] = [];
  const seen = new Set<string>();

  for (const msg of messages) {
    for (const block of msg.content) {
      // Extract from tool results (where most useful info lives)
      const text = block.type === "tool_result"
        ? block.content
        : block.type === "text"
          ? block.text
          : block.type === "tool_use"
            ? `${block.name}: ${JSON.stringify(block.input)}`
            : "";

      if (!text) continue;

      // For save_finding calls, capture the whole thing
      if (block.type === "tool_use" && block.name === "save_finding") {
        const entry = `FINDING: ${JSON.stringify(block.input)}`;
        if (!seen.has(entry)) {
          seen.add(entry);
          findings.push(entry);
        }
        continue;
      }

      // Extract matching lines from tool output
      const lines = text.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.length > 500) continue;
        if (SUMMARY_EXTRACT_PATTERNS.some((p) => p.test(trimmed))) {
          if (!seen.has(trimmed)) {
            seen.add(trimmed);
            findings.push(trimmed);
          }
        }
      }
    }
  }

  // Cap the summary so it doesn't bloat the context
  return findings.slice(0, 80).join("\n");
}

/**
 * Compact the conversation using LLM-based summarization.
 *
 * Approach (BoxPwnr-inspired):
 * 1. Serialize all middle messages (between first prompt and last 10 turns) to text
 * 2. Ask the LLM to produce a concise technical summary (preserving creds, endpoints, findings)
 * 3. Rebuild conversation: [system + initial prompt] → [assistant ack] → [user: summary] → [tail]
 *
 * Falls back to regex-based extraction if LLM summarization fails.
 */
export async function compactMessagesWithLLM(
  messages: NativeMessage[],
  runtime: NativeRuntime,
  systemPrompt: string,
): Promise<NativeMessage[]> {
  const preserveTailCount = 10;

  if (messages.length <= preserveTailCount + 2) {
    return messages; // not enough messages to compact
  }

  const firstMessage = messages[0]!;
  const tailStart = messages.length - preserveTailCount;
  const tail = messages.slice(tailStart);
  const middle = messages.slice(1, tailStart);

  // Serialize middle messages for summarization
  const conversationText = middle
    .map((m) => {
      const prefix = m.role === "assistant" ? "[Assistant]" : "[Tool Output]";
      return `${prefix}\n${serializeMessageToText(m)}`;
    })
    .join("\n\n")
    .slice(0, 50_000); // Cap to avoid overwhelming the summary call

  // Also extract regex findings as fallback / supplement
  const regexFindings = extractKeyFindings(middle);

  // Try LLM summarization
  let summaryText: string;
  try {
    const summaryResult = await runtime.executeNative(
      "You are a concise technical summarizer for a security testing conversation.",
      [
        {
          role: "user",
          content: [{
            type: "text",
            text: `Summarize this security testing conversation. Preserve ALL:\n- URLs and endpoints discovered\n- Credentials, tokens, cookies, API keys found\n- Technologies and frameworks identified\n- Vulnerabilities found or suspected\n- Attack attempts and their results (success/failure)\n- Any flags or partial flags seen\n\nBe concise but complete. Use bullet points.\n\nCONVERSATION:\n${conversationText}`,
          }],
        },
      ],
      [], // no tools for summary
    );

    // Extract text from result
    const textBlocks = summaryResult.content.filter(
      (b): b is NativeContentBlock & { type: "text" } => b.type === "text",
    );
    summaryText = textBlocks.map((b) => b.text).join("\n");

    if (!summaryText || summaryText.length < 50) {
      throw new Error("LLM summary too short or empty");
    }
  } catch {
    // Fallback to regex extraction
    summaryText = [
      "## Scan Progress Summary (compacted)",
      "",
      `Compacted ${middle.length} messages.`,
      "",
      "### Key findings, credentials, endpoints:",
      regexFindings || "(no findings extracted)",
    ].join("\n");
  }

  // Append regex findings that may have been missed by LLM
  if (regexFindings) {
    summaryText += `\n\n### Additional extracted context:\n${regexFindings}`;
  }

  // 0sec#229: append credential / exploit-bearing middle messages verbatim,
  // because LLM paraphrasing routinely drops the literal string
  // ("Found admin password: hunter2" → "discovered admin credentials"), which
  // breaks long-tail challenges where the agent recovers a credential early
  // and needs to type it back exactly later. BoxPwnr-inspired (see
  // single_loop_compactation.py in 0ca/BoxPwnr).
  if (features.preserveCriticalMessages) {
    const preserved: string[] = [];
    for (const msg of middle) {
      const text = serializeMessageToText(msg);
      if (CRITICAL_MESSAGE_PATTERNS.test(text)) {
        const prefix = msg.role === "assistant" ? "[Assistant]" : "[Tool Output]";
        preserved.push(`${prefix}\n${text}`);
      }
    }
    if (preserved.length > 0) {
      summaryText += `\n\n### Preserved verbatim (credential / exploit-bearing turns):\n${preserved.join("\n\n")}`;
    }
  }

  // Rebuild with correct role alternation
  const compacted: NativeMessage[] = [firstMessage];

  compacted.push({
    role: "assistant",
    content: [{ type: "text", text: "I have been working on this scan. Here is my progress so far." }],
  });

  compacted.push({
    role: "user",
    content: [{ type: "text", text: `[COMPACTED CONVERSATION SUMMARY]\n\n${summaryText}\n\nPlease continue from where we left off. What should we try next?` }],
  });

  // Append the tail, ensuring correct role alternation
  let tailIdx = 0;
  while (tailIdx < tail.length && tail[tailIdx]!.role !== "assistant") {
    tailIdx++;
  }

  let lastRole: "user" | "assistant" = "user";
  for (let i = tailIdx; i < tail.length; i++) {
    const msg = tail[i]!;
    if (msg.role === lastRole) {
      // MERGE the same-role run, never drop it. The loop injects extra user
      // messages routinely — loot, playbooks, loop warnings, budget warnings —
      // so consecutive user messages are normal, and the one being dropped was
      // often the `tool_result`-bearing message, i.e. the answer to the tool
      // call the assistant just made. Dropping it also orphans that call.
      compacted[compacted.length - 1] = mergeSameRole(compacted[compacted.length - 1]!, msg);
      continue;
    }
    compacted.push(msg);
    lastRole = msg.role;
  }

  return compacted;
}

/**
 * Concatenate two same-role messages into one.
 *
 * `providerRaw` (the opaque reasoning sidecar) survives only when both sides
 * carry one from the same provider+model+wireApi — concatenating the two raw
 * arrays keeps each one's internal ordering, so every reasoning item is still
 * immediately followed by the item it produced. When only one side has it the
 * sidecar is DROPPED: replaying it verbatim would skip the other message's
 * content entirely, and falling back to reconstruction is the safe direction.
 */
function mergeSameRole(a: NativeMessage, b: NativeMessage): NativeMessage {
  const merged: NativeMessage = { role: a.role, content: [...a.content, ...b.content] };
  const rawA = a.providerRaw;
  const rawB = b.providerRaw;
  if (
    rawA && rawB
    && rawA.provider === rawB.provider
    && rawA.model === rawB.model
    && rawA.wireApi === rawB.wireApi
  ) {
    merged.providerRaw = { ...rawA, output: [...rawA.output, ...rawB.output] };
  }
  return merged;
}

/**
 * Last-resort overflow recovery: preserve the opening task and recent tail,
 * explicitly mark the removed middle, and normalize tail role alternation.
 *
 * This intentionally runs only after a provider rejects the request for its
 * context window. Normal growth uses `compactMessagesWithLLM`, which preserves
 * more evidence through a summary; this path trades detail for a bounded retry.
 */
export function dropOldestMessages(
  messages: NativeMessage[],
  preserveTailCount = 10,
): NativeMessage[] {
  if (messages.length <= preserveTailCount + 3) return messages;

  const first = messages[0]!;
  const tail = messages.slice(Math.max(1, messages.length - preserveTailCount));
  const compacted: NativeMessage[] = [
    first,
    {
      role: "assistant",
      content: [{
        type: "text",
        text: "Earlier conversation context was pruned after a provider context-window rejection.",
      }],
    },
    {
      role: "user",
      content: [{
        type: "text",
        text: `[CONTEXT OVERFLOW RECOVERY] Dropped ${messages.length - tail.length - 1} older messages. Continue from the preserved recent context.`,
      }],
    },
  ];

  let tailIndex = 0;
  while (tailIndex < tail.length && tail[tailIndex]!.role !== "assistant") {
    tailIndex++;
  }

  let lastRole: "user" | "assistant" = "user";
  for (let index = tailIndex; index < tail.length; index++) {
    const message = tail[index]!;
    if (message.role === lastRole) {
      compacted[compacted.length - 1] = mergeSameRole(
        compacted[compacted.length - 1]!,
        message,
      );
      continue;
    }
    compacted.push(message);
    lastRole = message.role;
  }
  return compacted;
}

// ── Progress Summary Generation ──
// When early-stop triggers, ask the LLM to produce a structured summary of what
// was tried and discovered so the retry attempt can skip dead ends. Similar to
// BoxPwnr's --generate-progress / --resume-from pattern.

async function generateProgressSummary(
  messages: NativeMessage[],
  runtime: NativeRuntime,
): Promise<string> {
  // Serialize all messages into a conversation transcript for the summarizer
  const conversationText = messages
    .map((m) => {
      const prefix = m.role === "assistant" ? "[Assistant]" : "[Tool Output]";
      return `${prefix}\n${serializeMessageToText(m)}`;
    })
    .join("\n\n")
    .slice(0, 60_000); // Cap input to avoid token limits on the summary call

  const summaryResult = await runtime.executeNative(
    "You are a concise technical summarizer for a security penetration testing session.",
    [
      {
        role: "user",
        content: [{
          type: "text",
          text: `A penetration testing agent ran out of its turn budget without finding any vulnerabilities. Summarize its progress into a structured handoff document so a DIFFERENT agent can continue without repeating the same work.

Your summary MUST include these sections (use exactly these headings). If a section has no items, write "None found." under it.

### Endpoints/URLs Discovered
List every URL, path, and API endpoint the agent interacted with, along with HTTP status codes and notable response characteristics.

### Vulnerabilities Tested & Results
For each vulnerability class tested (SQLi, XSS, SSTI, IDOR, path traversal, command injection, etc.), list:
- What specific payloads/techniques were tried
- What the result was (blocked, reflected, error, no effect)
- Any partial progress or promising leads

### Credentials/Tokens/Cookies Found
Any authentication material discovered (usernames, passwords, tokens, session cookies, API keys, JWTs).

### Failed Approaches & Why
What strategies were tried and definitively ruled out? Why did they fail? (e.g., "WAF blocks all <script> tags", "CSRF tokens rotate per-request")

### Remaining Untried Approaches
Based on what was discovered, what attack vectors have NOT been attempted yet? What looks most promising?

CONVERSATION:
${conversationText}`,
        }],
      },
    ],
    [], // no tools for summary
  );

  const textBlocks = summaryResult.content.filter(
    (b): b is NativeContentBlock & { type: "text" } => b.type === "text",
  );
  const summary = textBlocks.map((b) => b.text).join("\n");

  if (!summary || summary.length < 50) {
    throw new Error("Progress summary too short or empty");
  }

  return summary;
}

// ── Loop / Oscillation Detection ──
// Inspired by BoxPwnr (97.1% on XBOW): when the agent gets stuck repeating the
// same commands, inject a warning to break the cycle.

interface ToolCallFingerprint {
  name: string;
  argPrefix: string; // first 100 chars of JSON-stringified arguments
}

class LoopDetector {
  private history: ToolCallFingerprint[] = [];
  private readonly windowSize = 6;
  /** Track which pattern signatures already fired so we don't spam. */
  private firedPatterns = new Set<string>();

  /** Record one or more tool calls from a single turn. */
  record(calls: Array<{ name: string; arguments: unknown }>): void {
    for (const c of calls) {
      const argStr = typeof c.arguments === "string"
        ? c.arguments
        : JSON.stringify(c.arguments ?? "");
      this.history.push({
        name: c.name,
        argPrefix: argStr.slice(0, 100),
      });
    }
    // Keep bounded
    if (this.history.length > this.windowSize * 2) {
      this.history = this.history.slice(-this.windowSize * 2);
    }
  }

  /** Returns a warning string if a loop is detected, or null otherwise. */
  detect(): string | null {
    const h = this.history;
    if (h.length < 3) return null;

    const fp = (e: ToolCallFingerprint) => `${e.name}:${e.argPrefix}`;

    // Pattern 1: Same exact command repeated 3+ times in a row
    if (h.length >= 3) {
      const last = fp(h[h.length - 1]!);
      const prev1 = fp(h[h.length - 2]!);
      const prev2 = fp(h[h.length - 3]!);
      if (last === prev1 && last === prev2) {
        const sig = `repeat:${last}`;
        if (!this.firedPatterns.has(sig)) {
          this.firedPatterns.add(sig);
          return LOOP_WARNING;
        }
      }
    }

    // Pattern 2: A-B-A-B alternating pattern (2+ full cycles = 4 entries)
    if (h.length >= 4) {
      const a1 = fp(h[h.length - 4]!);
      const b1 = fp(h[h.length - 3]!);
      const a2 = fp(h[h.length - 2]!);
      const b2 = fp(h[h.length - 1]!);
      if (a1 !== b1 && a1 === a2 && b1 === b2) {
        const sig = `alt:${a1}|${b1}`;
        if (!this.firedPatterns.has(sig)) {
          this.firedPatterns.add(sig);
          return LOOP_WARNING;
        }
      }
    }

    return null;
  }
}

/**
 * Header of the dynamic-playbook block, used as a presence marker so the loop
 * can tell whether the methodology is still in the live message window or was
 * removed by a compaction pass. Must stay in sync with the header emitted by
 * `buildPlaybookInjection` (agent/playbooks.ts) — `sop-flags.test.ts` asserts
 * that they match, so a rename there fails loudly here rather than silently
 * disabling the restore.
 */
export const PLAYBOOK_MARKER = "## Dynamic Playbook Injection";

/**
 * Whether any message in the window contains `needle`.
 *
 * Bounded and cheap: the window is the loop's own conversation array (kept
 * small by compaction) and the scan short-circuits on the first hit. Deliberately
 * a substring test on serialized text rather than structural matching, because
 * the block can come back in two shapes — as the original standalone user
 * message, or folded into a compaction summary by
 * `features.preserveCriticalMessages` (playbook text is full of "password" /
 * "admin" / "token", so it frequently trips the critical-message regex). Either
 * shape means the methodology is still in front of the model, and neither
 * warrants re-injecting it.
 */
function messagesContainText(messages: NativeMessage[], needle: string): boolean {
  for (const msg of messages) {
    for (const block of msg.content) {
      if (block.type === "text" && block.text.includes(needle)) return true;
      if (block.type === "tool_result" && block.content.includes(needle)) return true;
    }
  }
  return false;
}

const LOOP_WARNING =
  "⚠ You appear stuck in a loop repeating the same commands. " +
  "Try a COMPLETELY DIFFERENT approach — different tool, different endpoint, different payload.";

// ── Two-stage budget warnings (Strix-inspired, 0sec#408) ──
//
// Distinct from the existing `buildContinuePrompt` checkpoints (which only
// fire when the model emits zero tool calls and the loop has to nudge it):
// these warnings fire on a normal tool-call turn — once at ~85% of the
// turn budget so the model has time to pivot to a clean handoff, and once
// at `maxTurns − 3` as a final shove. Each one fires at most once per run;
// the flag pair `budgetWarningsFired` lives on the loop's closure.
//
// 85% uses Math.ceil so a 20-turn budget warns on turn 17, matching the
// issue spec (PR #406 §11 Strix comparison). For small budgets where the
// two thresholds coincide (e.g. maxTurns=20 → soft=17, hard=17), we fire
// BOTH messages in order — the soft warning first, then the hard one. The
// alternative (suppress the soft when they collide) would silently change
// the at-most-once invariant on a per-warning basis, and the test bar in
// #408 explicitly asserts two distinct warning strings appear.

/** Soft warning injected at ~85% of the turn budget. */
export const BUDGET_WARNING_SOFT =
  "[0sec budget] You have used ~85% of your turn budget. If you have a credible finding, call `save_finding` now and then `done`. Otherwise prepare a clean handoff — summarize what you tried and what looks most promising for a follow-up agent. Do NOT start a new exploration thread.";

/** Hard warning injected at `maxTurns − 3`. */
export const BUDGET_WARNING_HARD =
  "[0sec budget] Only 3 turns remaining. Submit your best finding now or call `done`. Further exploration won't fit — wrap up cleanly.";

/**
 * Compute the two budget-warning turn thresholds for a given `maxTurns`.
 *
 * - `soft`: `ceil(maxTurns * 0.85)` — fired the first turn where
 *   `turnCount >= soft`.
 * - `hard`: `max(1, maxTurns - 3)` — fired the first turn where
 *   `turnCount >= hard`.
 *
 * Both clamp to at least 1 so degenerate `maxTurns <= 3` runs still get
 * a hard warning on turn 1 instead of `-2`. Exported so the legacy loop
 * (`loop.ts`) and unit tests share the same math.
 */
export function computeBudgetWarningTurns(maxTurns: number): { soft: number; hard: number } {
  const soft = Math.max(1, Math.ceil(maxTurns * 0.85));
  const hard = Math.max(1, maxTurns - 3);
  return { soft, hard };
}

// ── Helpers ──

/**
 * Read the agent's external working memory file. Returns a formatted suffix
 * to append to the reflection checkpoint prompt, or an empty string if the
 * file doesn't exist or the feature is off.
 */
function readExternalMemory(path: string): string {
  try {
    const raw = fs.readFileSync(path, "utf-8");
    fs.chmodSync(path, 0o600);
    if (!raw.trim()) return "";
    const capped = raw.length > EXTERNAL_MEMORY_MAX_CHARS
      ? raw.slice(0, EXTERNAL_MEMORY_MAX_CHARS) + "\n...(truncated)"
      : raw;
    return `\n\n## Your Saved State\n\`\`\`json\n${capped}\n\`\`\`\nUpdate this file as you discover new information.`;
  } catch {
    return "";
  }
}

/**
 * Result of attempting to seed the loop's context off the execution journal
 * (#494, slice 2). `messages` is the rendered conversation window (empty when
 * there is no journaled progress yet — a fresh run); `findings` are the
 * findings recovered from `finding` entries so the in-loop tool context starts
 * with what the prior run already confirmed. `seeded` is true only when we
 * actually rehydrated non-empty progress from the journal.
 */
interface JournalSeed {
  messages: NativeMessage[];
  findings: Finding[];
  /** Highest tool-step turn observed in the journal (0 when unknown). */
  turnCount: number;
  seeded: boolean;
}

/**
 * Load the run's execution journal and render it into a fresh conversation
 * seed. Guard-railed: a missing/empty/corrupt journal yields an empty,
 * un-seeded result (the caller falls back to DB-blob / fresh-prompt seeding)
 * and NEVER throws — rehydration must not be more fragile than the journal it
 * reads. The reason for any non-fatal degradation is reported via `onWarn` so
 * the fallback is observable.
 */
function seedFromJournal(
  scanId: string,
  onWarn: (reason: string, detail?: unknown) => void,
): JournalSeed {
  const empty: JournalSeed = { messages: [], findings: [], turnCount: 0, seeded: false };

  let entries;
  try {
    entries = loadJournal({ runId: scanId });
  } catch (err) {
    // loadJournal throws on a complete malformed line (corrupt journal).
    onWarn("journal_load_failed", err);
    return empty;
  }

  if (!Array.isArray(entries) || entries.length === 0) {
    // Missing or empty journal — nothing to rehydrate. Not an error: this is
    // the fresh-run case, which must behave exactly as today.
    return empty;
  }

  let messages: NativeMessage[];
  let findings: Finding[];
  let turnCount: number;
  try {
    const state = rehydrateContext(entries);
    messages = renderSeedMessages(state);
    // `finding` journal entries are written from real `save_finding` payloads
    // (native-loop shadow write), but the journal types them loosely as
    // `Record<string, unknown>`. Cast through `unknown` to recover the shape
    // the in-loop tool context carries.
    findings = state.findings as unknown as Finding[];
    // Continue numbering from the last turn the prior run reached so budget /
    // loop-detection math stays consistent. Falls back to 0 when no tool step
    // carried a turn (older journals).
    turnCount = state.toolSteps.reduce(
      (max, step) => (typeof step.turn === "number" && step.turn > max ? step.turn : max),
      0,
    );
  } catch (err) {
    // rehydrateContext is total by contract, but render or an unexpected edge
    // must still degrade rather than abort the loop.
    onWarn("journal_rehydrate_failed", err);
    return empty;
  }

  if (messages.length === 0) {
    // Journal had entries but no conversation-bearing progress — treat as a
    // fresh start so we stay byte-equivalent to today's initial prompt.
    return empty;
  }

  return { messages, findings, turnCount, seeded: true };
}

function buildInitialPrompt(config: NativeAgentConfig): string {
  const hasJitSkillTools =
    features.jitSkills &&
    config.tools.some((tool) => tool.name === "list_skills") &&
    config.tools.some((tool) => tool.name === "load_skill");

  return [
    `You are a ${config.role} agent for 0sec, an AI red-teaming toolkit.`,
    `Target: ${config.target}`,
    `Scan ID: ${config.scanId}`,
    "",
    "Use your tools to accomplish your task. When done, call the done tool with a summary.",
    hasJitSkillTools ? `\n## Just-in-Time Skills\n${formatJitSkillsInstruction()}` : "",
  ].join("\n");
}

function buildContinuePrompt(config: NativeAgentConfig, turnCount: number, memoryPath: string): string {
  const pct = turnCount / config.maxTurns;
  const remaining = config.maxTurns - turnCount;

  // Read external memory at reflection checkpoints (30%/50%/70%/85%)
  const memorySuffix = (pct >= 0.3 && features.externalMemory)
    ? readExternalMemory(memoryPath)
    : "";

  // Multi-checkpoint budget awareness (inspired by Cyber-AutoAgent)
  if (pct >= 0.85) {
    return `FINAL PUSH: ${remaining} turns left. Go for the highest-confidence exploit path ONLY. No more exploration — exploit what you found. Use your tools.${memorySuffix}`;
  }
  if (pct >= 0.7) {
    return `URGENCY: ${remaining} turns left. If current approach is not working, SWITCH NOW to a completely different technique. Use your tools.${memorySuffix}`;
  }
  if (pct >= 0.5) {
    return `HALFWAY: ${remaining} turns left. List every approach tried and its result. What is the MOST PROMISING untested vector? Focus there. Use your tools.${memorySuffix}`;
  }
  if (pct >= 0.3) {
    return `STATUS: ${remaining} turns left. Summarize what you have learned. What is your top hypothesis? Use your tools to test it.${memorySuffix}`;
  }

  const scopedSourceAudit =
    typeof config.scopePath === "string" && config.scopePath.trim().length > 0;

  switch (config.role) {
    case "discovery":
    case "attack":
    case "verify":
      return turnCount < 2
        ? "You must use your target interaction tools. Start by sending prompts or HTTP requests to the configured target. Do not just describe what you would do."
        : "Continue testing. Use your tools — do not just describe what you would do.";
    case "audit":
    case "review":
    default:
      return turnCount < 2
        ? scopedSourceAudit
          ? "You must use your scoped source tools to analyze the target. Start by listing files and reading source. Do not just describe what you would do — actually do it."
          : "You must use your tools to analyze the target. Start by reading files and running commands. Do not just describe what you would do — actually do it."
        : scopedSourceAudit
          ? "Continue your analysis. Use list_files to map source, search_files with literal identifiers to trace patterns, read_file for full context, and save_finding for vulnerabilities. Call done only when you have thoroughly analyzed the code."
          : "Continue your analysis. Use read_file to examine source code, run_command to search for patterns, and save_finding for any vulnerabilities. Call the done tool only when you have thoroughly analyzed the code.";
  }
}

function persistSession(
  db: osecDB,
  state: NativeAgentState,
  config: NativeAgentConfig,
  status: string,
): void {
  // Trim messages for storage — keep last N to stay under size limits
  const maxStoredMessages = 40;
  const messagesToStore =
    state.messages.length > maxStoredMessages
      ? state.messages.slice(-maxStoredMessages)
      : state.messages;

  db.saveSession({
    id: state.sessionId,
    scanId: config.scanId,
    agentRole: config.role,
    turnCount: state.turnCount,
    messages: messagesToStore,
    toolContext: {
      findings: state.findings,
      attackResults: state.attackResults,
      targetInfo: state.targetInfo,
    },
    status,
  });
}
