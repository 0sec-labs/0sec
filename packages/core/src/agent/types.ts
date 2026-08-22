import type { Finding, AttackResult, TargetInfo, AuthConfig, NamedIdentity } from "@0sec/shared";
import type { ScopePolicy } from "../scope/scope.js";
import type { RateLimiter } from "../scope/rate-limit.js";
import type { AttributionConfig } from "../scope/attribution.js";
import type { EngagementPosture } from "../scope/engagement-profile.js";
import type { EnforcementTracker } from "../scope/enforcement.js";
import type { LootLedger } from "./loot.js";
import type { TaskLedger } from "./task-ledger.js";
import type { OastCollaborator } from "../oast/types.js";
import type { SessionEngine } from "./session.js";
import type { WafDetector } from "../scope/waf-detect.js";
import type { ScanCostLedger } from "./cost-ledger.js";

// ── Agent Roles ──

export type AgentRole = "discovery" | "attack" | "verify" | "report" | "audit" | "review";

// ── Tool Definitions ──

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, ToolParam>;
  required?: string[];
}

export interface ToolParam {
  type: "string" | "number" | "boolean" | "object" | "array";
  description: string;
  enum?: string[];
  /**
   * JSON-schema `items` for `type: "array"` params (e.g. `spawn_agents`'
   * `tasks` list). Passed through verbatim into the tool's `input_schema` so
   * the model receives a properly typed array-of-objects. Omit for scalar
   * params.
   */
  items?: Record<string, unknown>;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolResult {
  success: boolean;
  output: unknown;
  error?: string;
}

// ── Console autonomy (scoped source-audit gate) ──

/**
 * Operator engagement mode, as seen by the tool executor. This union is a
 * copy of the console's `ConsoleAutonomyMode` (`console/turn-engine.ts`) kept
 * here to avoid a layering inversion — `agent/` is a lower layer than
 * `console/` and must not import from it. Keep the two unions in sync.
 *
 * Only the scoped-source-audit allow-list gate in `ToolExecutor.execute`
 * consults this. It is OPTIONAL: when absent (every non-console caller,
 * including the scan pipeline), that gate behaves exactly as it did before the
 * field existed — a hard denial of any non-allow-listed tool.
 *
 * `"recon"` is the passive, capability-restricted mode: for the scoped-audit
 * gate it behaves like `standard`/`copilot`'s prompting path (it is NOT
 * auto-lifted like `yolo`/`copilot`), because the console's own recon
 * capability gate already refuses effectful tools before dispatch.
 */
export type ToolAutonomyMode = "standard" | "copilot" | "yolo" | "recon";

/**
 * Payload handed to {@link ToolContext.escalateScopedAudit} when a scoped
 * source audit hits a tool outside the `SCOPED_SOURCE_AUDIT_TOOLS` allow-list
 * in `standard` / `copilot` mode. The console renders this to the operator and
 * resolves to `true` (allow the call, once, and remember it) or `false` (deny,
 * and remember the denial so a retry does not re-prompt). Mirrors the shape of
 * the console's existing scope-request callbacks.
 */
export interface ScopedAuditEscalationRequest {
  /** The blocked tool call. */
  call: ToolCall;
  /** Human-readable reason the call was blocked (for the operator prompt). */
  reason: string;
}

// ── Agent Messages (multi-turn) ──

export type MessageRole = "system" | "user" | "assistant" | "tool";

export interface AgentMessage {
  role: MessageRole;
  content: string;
  toolCalls?: ToolCall[];
  toolResults?: Array<{ name: string; result: ToolResult }>;
}

// ── Agent Configuration ──

export interface AgentConfig {
  role: AgentRole;
  systemPrompt: string;
  tools: ToolDefinition[];
  maxTurns: number;
  target: string;
  scanId: string;
  scopePath?: string;
  sessionId?: string;
  attachTargetToolsMcp?: boolean;
  dbPath?: string;
  authConfig?: AuthConfig;
  /**
   * Resolved named identities for access-control testing (0sec#564).
   * Passed through to the `ToolContext` so the prompt + `access_control_probe`
   * can enumerate principals. The active identity's `auth` is mirrored into
   * `authConfig` for back-compat with the env-var / fallback paths.
   */
  identities?: NamedIdentity[];
  /**
   * Stateful per-identity HTTP session engine (0sec#564). Built once per
   * scan and shared across discovery/attack/verify phases so cookies persist.
   * Passed straight through to the `ToolContext`.
   */
  session?: SessionEngine;
  /**
   * Programmatic engagement scope (0sec#215). When set, every URL the
   * agent touches — http_request, submit_form, browser navigate, crawl,
   * shellExec URL extraction, wp_fingerprint, web_search inputs — is
   * checked against this policy and out-of-scope URLs return as
   * `ToolResult.error`. Same-origin checks remain enforced ON TOP of
   * this; scope is additive, never substitutive.
   */
  scope?: ScopePolicy;
  /**
   * Per-host rate limiter for outbound HTTP. When set, every fetch
   * chokepoint (`http_request`, `crawl`, `submit_form`, `web_search`,
   * `wp_fingerprint`) acquires a token before the network call and
   * pipes the response back via `noteResponse` so 429 honours.
   * See `scope/rate-limit.ts` (#214).
   */
  rateLimiter?: RateLimiter;
  /**
   * http_audit enforcement tracker (path allowlist + counters + kill
   * switch). Present ONLY in `mode: "http_audit"` scans; undefined for
   * every other mode, leaving behaviour identical to the pre-http_audit
   * path. When set, the path-prefix allowlist is enforced alongside the
   * host scope at every fetch chokepoint and the scope/rate counters are
   * tallied into the report's `enforcement_summary` block.
   */
  enforcement?: EnforcementTracker;
  /**
   * WAF detection + adaptive evasion aggregator (0sec#568). When omitted
   * but an engagement scope (`scope`/`enforcement`) is configured, one is
   * created automatically so authorized engagements get WAF fingerprinting +
   * adaptive evasion. Pass `null` to disable explicitly.
   */
  wafDetector?: WafDetector | null;
  /**
   * Generic-scanner-traffic suppression opt-out (0sec#217). When
   * scope is loaded the agent refuses to spawn `sqlmap`, `wpscan`,
   * `nikto`, `gobuster`, `dirb`, `wfuzz`, `ffuf`, and the noisy `nmap -sV` /
   * `nmap -A` modes — those binaries fingerprint themselves on the
   * wire and most coordinated-disclosure programs forbid them. Setting
   * this to `true` disables that gate (use only when the engagement
   * explicitly permits generic-scanner traffic).
   */
  allowScanners?: boolean;
  /**
   * Resolved attribution-header config (0sec#216). When set, every
   * fetch site merges these headers + applies the User-Agent override on
   * IN-SCOPE requests. Out-of-scope hosts are never tagged. When `scope`
   * is also undefined, attribution behaves as opt-in: present here means
   * the operator explicitly configured it (env or CLI) and wants it on.
   */
  attribution?: AttributionConfig;
  /**
   * Resolved engagement hardening posture (`scope/engagement-profile.ts`).
   * Read at the WAF chokepoint to decide whether a blocked response escalates
   * into the adaptive evasion ladder. When undefined the tool falls back to
   * resolving the standalone `0SEC_WAF_EVASION` env opt-out, so the default
   * (ladder enabled) is unchanged.
   */
  engagement?: EngagementPosture;
  /**
   * Tool-call dispatch protocol (0sec#232). When unset or `"json"`, the
   * legacy `TOOL_CALL: <name> {...}` line format is used. When `"xml"`,
   * the loop drives the model with the `<command>` / `<flag>` /
   * `<finding>` / `<note>` XML protocol from `xml-dispatch.ts`. `"auto"`
   * picks XML for cheap providers (gemini / deepseek / openrouter /
   * qwen / mistral / llama) and JSON otherwise. Consulted only by the
   * legacy text-based `runAgentLoop` — `runNativeAgentLoop` always uses
   * provider-native tool_use blocks.
   */
  dispatchMode?: DispatchMode;
  /**
   * Optional model identifier used by `dispatchMode: "auto"` substring
   * matching. When omitted, `resolveDispatchMode` falls back to JSON.
   */
  modelHint?: string;
}

// ── Agent State ──

export interface AgentState {
  messages: AgentMessage[];
  turnCount: number;
  findings: Finding[];
  attackResults: AttackResult[];
  targetInfo: Partial<TargetInfo>;
  done: boolean;
  summary: string;
}

// ── Tool Execution Context ──

export interface ToolContext {
  target: string;
  scanId: string;
  findings: Finding[];
  attackResults: AttackResult[];
  targetInfo: Partial<TargetInfo>;
  /**
   * Agent role this executor is serving. Used by the `done`-tool coverage
   * gate (#audit-laziness) to enforce minimum source inspection before a
   * sub-agent of role `audit`/`review` can declare itself complete. Other
   * roles short-circuit the gate. Optional for back-compat with the many
   * test fixtures that construct `ToolContext` literals directly.
   */
  role?: AgentRole;
  scopePath?: string;
  /**
   * Current console autonomy mode, re-read by the scoped-source-audit gate on
   * every `execute()` so switching mode mid-session takes effect immediately
   * (no executor rebuild). Absent for every non-console caller — the scan
   * pipeline never sets it — in which case the gate behaves byte-identically
   * to the pre-autonomy hard denial. See {@link ToolAutonomyMode}.
   */
  autonomyMode?: ToolAutonomyMode;
  /**
   * Escalation callback for the scoped-source-audit allow-list gate. When a
   * scoped source audit (role audit/review + a non-empty {@link scopePath})
   * hits a tool outside `SCOPED_SOURCE_AUDIT_TOOLS` in `standard`/`copilot`
   * mode, the executor invokes this instead of dead-ending: `true` runs the
   * tool (and the grant is remembered per-tool for the session), `false`
   * returns the existing denial (and is remembered so a retry does not
   * re-prompt). When ABSENT — every existing non-console caller — the gate
   * falls back to today's hard denial, so no existing behaviour changes.
   *
   * This callback ONLY lifts the scoped-source-audit allow-list. It is not a
   * master key: the console's network scope-on-demand, local-filesystem scope,
   * and co-pilot per-tool approval gates all still apply on top.
   */
  escalateScopedAudit?: (req: ScopedAuditEscalationRequest) => Promise<boolean>;
  /**
   * Agent-to-agent messaging identity and policy for this executor.
   *
   * Absent means messaging is unavailable — the child tools report that
   * rather than failing obscurely. Typed as `unknown` here because the
   * concrete shape lives in `agent-messaging.ts`, which imports from this
   * module; importing it back would be a cycle. `tools.ts` narrows it.
   */
  agentMessaging?: unknown;
  persistFindings?: boolean;
  authConfig?: AuthConfig;
  /**
   * Resolved named identities for access-control testing (0sec#564).
   * Present when the scan configured ≥1 identity (via `identities` or the
   * legacy `auth` shim). Used by the prompt builder and `access_control_probe`
   * to enumerate the principals it can replay requests as.
   */
  identities?: NamedIdentity[];
  /**
   * Stateful per-identity HTTP session engine (0sec#564). When present, the
   * HTTP tools (`http_request`/`crawl`/`submit_form`) act as `session.activeLabel`,
   * persist captured `Set-Cookie` across turns, and re-auth on 401/403. When
   * absent, tools fall back to the stateless `buildAuthHeaders(authConfig)`
   * path — behaviour identical to pre-#564 single-credential scans.
   */
  session?: SessionEngine;
  /**
   * See `AgentConfig.scope`. When present, every URL-touching tool
   * runs `policy.match()` before egress and refuses out-of-scope URLs
   * with `ToolResult.error`.
   */
  scope?: ScopePolicy;
  /** Per-host rate limiter; see AgentConfig.rateLimiter. */
  rateLimiter?: RateLimiter;
  /**
   * See `AgentConfig.enforcement`. http_audit-only path allowlist +
   * scope/rate counters + kill switch. Every URL-touching tool consults
   * `enforcement.pathPolicy` (when set) in addition to host scope, and
   * increments the in-scope / out-of-scope counters at the verdict sites.
   */
  enforcement?: EnforcementTracker;
  /**
   * WAF detection + adaptive evasion aggregator (0sec#568). When set, the
   * `http_request` chokepoint fingerprints each response for known WAF
   * vendors; on a detected block it runs a bounded adaptive-evasion campaign
   * (re-encoding / casing / jitter) through the same rate-limited fetch path
   * and records every attempt as evidence. Created for authorized engagements
   * (when `scope` or `enforcement` is configured); undefined otherwise so the
   * default scan path is unchanged.
   */
  wafDetector?: WafDetector;
  /**
   * See `AgentConfig.allowScanners`. Opt-out for the scanner-binary
   * suppression gate (0sec#217). Only consulted when `scope` is set.
   */
  allowScanners?: boolean;
  /** See `AgentConfig.engagement`. */
  engagement?: EngagementPosture;
  /** See `AgentConfig.attribution` (0sec#216). */
  attribution?: AttributionConfig;
  /**
   * Recent tool result texts for JIT skill trigger matching (#457).
   * Populated by the agent loop with the last N tool result strings so
   * `list_skills` can compute `suggested` flags via `matchTriggers()`.
   */
  recentToolResultTexts?: string[];
  /**
   * Set of skill IDs already loaded in this session (#457). Prevents
   * double-loading the same skill and lets `load_skill` return a
   * "Skill already loaded" message instead of burning tokens.
   */
  loadedSkills?: Set<string>;
  /**
   * Typed loot / foothold ledger (0sec#567). When set, `save_finding`
   * harvests reusable artifacts (credentials, tokens, cookies, hashes,
   * endpoints, paths) from the finding's evidence into it, and the `use_loot`
   * tool reads from it so the agent can replay a captured artifact in a
   * follow-up request to chain to higher impact. The agent loop also harvests
   * from evidence-bearing tool results and re-injects a compact "known
   * footholds" block each turn. Created only when `features.lootLedger` is on;
   * undefined otherwise so the default scan path is unchanged.
   */
  loot?: LootLedger;
  /**
   * Typed TODO / plan ledger. When set, the `plan` tool reads and mutates it,
   * and the agent loop re-injects a compact plan block re-rendered from this
   * structured state each turn (so the plan survives context compaction). The
   * ledger's open tasks are also the anchor set for task-drift detection
   * (`agent/drift.ts`). Created only when `features.agentPlan` is on;
   * undefined otherwise, in which case `plan` returns a graceful
   * "not enabled" result rather than an error.
   */
  plan?: TaskLedger;
  /**
   * The agent turn currently executing. Kept fresh by the loop so tools can
   * stamp turn numbers on state they create (the plan ledger records the turn
   * a task was added and last touched, which is what makes a stale task
   * visible). Undefined outside the native loop, in which case turn stamps
   * fall back to 0.
   */
  currentTurn?: number;
  /**
   * Hosted OAST interaction collaborator (0sec#659). When set, the
   * `oast_register` / `oast_poll` tools mint unique interaction handles and
   * poll for DNS/HTTP/LDAP callbacks to confirm blind/out-of-band classes
   * (blind SSRF/XSS, OOB RCE/SQLi, XXE-OOB, JNDI) via correlation-token
   * matching. A verified handle can then be supplied to `save_finding`, which
   * persists the callback as a verified finding. Created only when
   * `features.oastCollaborator` is on AND a collaborator server is configured
   * (0SEC_OAST_URL); undefined otherwise, in which case the OAST tools return
   * a graceful "not deployed" result.
   */
  oast?: OastCollaborator;
  /**
   * Shared per-scan cost ledger (see agent/cost-ledger.ts). Threaded onto the
   * ToolContext so the `spawn_agent` / `spawn_agents` handlers can pass it into
   * the child `runNativeAgentLoop` config — otherwise every subagent session
   * charges only its own session-local usage and escapes the scan-wide ceiling
   * (the off-ledger gap the ledger exists to close). Mirrors
   * `NativeAgentConfig.costLedger`. Undefined outside a native loop.
   */
  costLedger?: ScanCostLedger;
  /**
   * Hard per-scan cost ceiling in USD, mirrored from
   * `NativeAgentConfig.costCeilingUsd` onto the ToolContext so spawned
   * subagents inherit and enforce the SAME ceiling as the parent, priced
   * against the shared {@link costLedger}.
   */
  costCeilingUsd?: number;
  /**
   * Model id used to price token usage against the ceiling, mirrored from
   * `NativeAgentConfig.costModel`. Passed through to spawned subagents so
   * their ledger contributions price identically to the parent.
   */
  costModel?: string;
}

// ── Dispatch Mode (0sec#232) ──

/**
 * How tool calls flow between the model and the harness in `runAgentLoop`.
 *
 * - `"json"` (default): the legacy `TOOL_CALL: <name> {...}` line format.
 *   Models that emit JSON correctly should keep using this.
 * - `"xml"`: an XML-tag protocol (`<command>`, `<flag>`, `<finding>`,
 *   `<note>`) parsed by regex. Cheap models (DeepSeek, Gemini-flash,
 *   Qwen, etc.) emit malformed JSON under load; XML survives that. See
 *   `agent/xml-dispatch.ts` and 0sec#232.
 * - `"auto"`: pick by model substring (gemini / deepseek / openrouter /
 *   qwen / mistral / llama → xml; otherwise json). Resolved by
 *   `resolveDispatchMode()` in `xml-dispatch.ts`.
 */
export type DispatchMode = "json" | "xml" | "auto";
