import type { Finding, AttackResult, TargetInfo, AuthConfig, NamedIdentity } from "@pwnkit/shared";
import type { ScopePolicy } from "../scope/scope.js";
import type { RateLimiter } from "../scope/rate-limit.js";
import type { AttributionConfig } from "../scope/attribution.js";
import type { EngagementPosture } from "../scope/engagement-profile.js";
import type { EnforcementTracker } from "../scope/enforcement.js";
import type { LootLedger } from "./loot.js";
import type { OastCollaborator } from "../oast/types.js";
import type { SessionEngine } from "./session.js";
import type { WafDetector } from "../scope/waf-detect.js";

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
  type: "string" | "number" | "boolean" | "object";
  description: string;
  enum?: string[];
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
   * Resolved named identities for access-control testing (pwnkit#564).
   * Passed through to the `ToolContext` so the prompt + `access_control_probe`
   * can enumerate principals. The active identity's `auth` is mirrored into
   * `authConfig` for back-compat with the env-var / fallback paths.
   */
  identities?: NamedIdentity[];
  /**
   * Stateful per-identity HTTP session engine (pwnkit#564). Built once per
   * scan and shared across discovery/attack/verify phases so cookies persist.
   * Passed straight through to the `ToolContext`.
   */
  session?: SessionEngine;
  /**
   * Programmatic engagement scope (pwnkit#215). When set, every URL the
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
   * WAF detection + adaptive evasion aggregator (pwnkit#568). When omitted
   * but an engagement scope (`scope`/`enforcement`) is configured, one is
   * created automatically so authorized engagements get WAF fingerprinting +
   * adaptive evasion. Pass `null` to disable explicitly.
   */
  wafDetector?: WafDetector | null;
  /**
   * Generic-scanner-traffic suppression opt-out (pwnkit#217). When
   * scope is loaded the agent refuses to spawn `sqlmap`, `wpscan`,
   * `nikto`, `gobuster`, `dirb`, `wfuzz`, `ffuf`, and the noisy `nmap -sV` /
   * `nmap -A` modes — those binaries fingerprint themselves on the
   * wire and most coordinated-disclosure programs forbid them. Setting
   * this to `true` disables that gate (use only when the engagement
   * explicitly permits generic-scanner traffic).
   */
  allowScanners?: boolean;
  /**
   * Resolved attribution-header config (pwnkit#216). When set, every
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
   * resolving the standalone `PWNKIT_WAF_EVASION` env opt-out, so the default
   * (ladder enabled) is unchanged.
   */
  engagement?: EngagementPosture;
  /**
   * Tool-call dispatch protocol (pwnkit#232). When unset or `"json"`, the
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
  persistFindings?: boolean;
  authConfig?: AuthConfig;
  /**
   * Resolved named identities for access-control testing (pwnkit#564).
   * Present when the scan configured ≥1 identity (via `identities` or the
   * legacy `auth` shim). Used by the prompt builder and `access_control_probe`
   * to enumerate the principals it can replay requests as.
   */
  identities?: NamedIdentity[];
  /**
   * Stateful per-identity HTTP session engine (pwnkit#564). When present, the
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
   * WAF detection + adaptive evasion aggregator (pwnkit#568). When set, the
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
   * suppression gate (pwnkit#217). Only consulted when `scope` is set.
   */
  allowScanners?: boolean;
  /** See `AgentConfig.engagement`. */
  engagement?: EngagementPosture;
  /** See `AgentConfig.attribution` (pwnkit#216). */
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
   * Typed loot / foothold ledger (pwnkit#567). When set, `save_finding`
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
   * Hosted OAST interaction collaborator (pwnkit#659). When set, the
   * `oast_register` / `oast_poll` tools mint unique interaction handles and
   * poll for DNS/HTTP/LDAP callbacks to confirm blind/out-of-band classes
   * (blind SSRF/XSS, OOB RCE/SQLi, XXE-OOB, JNDI) via correlation-token
   * matching. Created only when `features.oastCollaborator` is on AND a
   * collaborator server is configured (PWNKIT_OAST_URL); undefined otherwise,
   * in which case the OAST tools return a graceful "not deployed" result.
   */
  oast?: OastCollaborator;
}

// ── Dispatch Mode (pwnkit#232) ──

/**
 * How tool calls flow between the model and the harness in `runAgentLoop`.
 *
 * - `"json"` (default): the legacy `TOOL_CALL: <name> {...}` line format.
 *   Models that emit JSON correctly should keep using this.
 * - `"xml"`: an XML-tag protocol (`<command>`, `<flag>`, `<finding>`,
 *   `<note>`) parsed by regex. Cheap models (DeepSeek, Gemini-flash,
 *   Qwen, etc.) emit malformed JSON under load; XML survives that. See
 *   `agent/xml-dispatch.ts` and pwnkit#232.
 * - `"auto"`: pick by model substring (gemini / deepseek / openrouter /
 *   qwen / mistral / llama → xml; otherwise json). Resolved by
 *   `resolveDispatchMode()` in `xml-dispatch.ts`.
 */
export type DispatchMode = "json" | "xml" | "auto";
