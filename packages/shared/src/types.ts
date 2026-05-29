import type { VerificationResult } from "./verification.js";

// ── Scan Configuration ──

export type ScanDepth = "quick" | "default" | "deep";
export type OutputFormat = "terminal" | "json" | "markdown" | "html" | "sarif" | "pdf";
export type RuntimeMode = "api" | "claude" | "codex" | "gemini" | "ollama" | "auto";
export type ScanMode = "probe" | "deep" | "mcp" | "web" | "http_audit";
export type PackageEcosystem = "npm" | "pypi" | "cargo" | "oci";

// ── Authentication ──

export type AuthType = "bearer" | "cookie" | "basic" | "header";

export interface AuthConfigBearer {
  type: "bearer";
  token: string;
}

export interface AuthConfigCookie {
  type: "cookie";
  value: string;
}

export interface AuthConfigBasic {
  type: "basic";
  username: string;
  password: string;
}

export interface AuthConfigHeader {
  type: "header";
  name: string;
  value: string;
}

export type AuthConfig = AuthConfigBearer | AuthConfigCookie | AuthConfigBasic | AuthConfigHeader;

// ── Multi-identity access-control testing (pwnkit#564) ──

/**
 * Privilege tier of a named identity, used for vertical-privilege-escalation
 * reasoning (a `user`/`anonymous` identity reaching an `admin`-only endpoint
 * is a BFLA / vertical privesc). Free-form strings are accepted so engagements
 * can model bespoke role names, but the three canonical tiers carry meaning in
 * the access-control probe's verdict logic.
 */
export type IdentityRole = "admin" | "user" | "anonymous" | (string & {});

/**
 * One named identity for broken-access-control testing (BOLA/IDOR/BFLA,
 * pwnkit#564). Holds a human label, an optional privilege role, and the
 * credential the engine acts with when this identity is active. An identity
 * with no `auth` is treated as unauthenticated (anonymous) — exactly what you
 * want as the negative-control principal in an authz diff.
 */
export interface NamedIdentity {
  /**
   * Stable, human-readable label (e.g. `"alice"`, `"admin"`, `"anon"`). Used
   * verbatim in probe evidence and finding text, so keep it short + distinct.
   */
  label: string;
  /**
   * Privilege tier. Optional; defaults to `"anonymous"` when `auth` is unset
   * and `"user"` otherwise. Drives vertical-privesc verdicts.
   */
  role?: IdentityRole;
  /**
   * Credential this identity authenticates with. Omit for an unauthenticated
   * identity (the negative control in an A-vs-B authz diff).
   */
  auth?: AuthConfig;
}

export interface ScanConfig {
  target: string;
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  mode?: ScanMode;
  repoPath?: string;
  /**
   * Package ecosystem of the target (npm / pypi / cargo / …). Optional; when
   * unset the publishability dedup gate (issue #537 / #539) defaults to npm.
   * Used to resolve the advisory DB and the source repository.
   */
  ecosystem?: string;
  /**
   * Source repository as "owner/repo", for the publishability dedup gate's
   * repo-issue + SECURITY.md sources. Optional; when unset the scanner
   * best-effort resolves it from package metadata (npm only today) and leaves
   * it undefined if it cannot resolve cleanly — those two sources then no-op
   * rather than risk a false duplicate against a guessed repo.
   */
  repository?: string;
  apiKey?: string;
  model?: string;
  templateFilter?: string[];
  maxConcurrency?: number;
  timeout?: number;
  /** Whole-scan wallclock timeout for single-process runners. */
  scanTimeout?: number;
  verbose?: boolean;
  /**
   * Single credential the agent authenticates with. Legacy singular field,
   * retained for back-compat: when `identities` is unset this is the only
   * credential, and the engine internally wraps it into a one-entry identity
   * list (see `resolveIdentities`). Prefer `identities` for any scan that
   * needs broken-access-control testing.
   */
  auth?: AuthConfig;
  /**
   * Named identities for multi-principal access-control testing (BOLA/IDOR/
   * BFLA + horizontal/vertical privesc, pwnkit#564). When ≥2 entries are
   * present the engine can act as identity A, capture an authorized response,
   * replay the same request as identity B / unauthenticated, and diff
   * status + body to flag broken object-/function-level authorization.
   *
   * Back-compat: `auth` and `identities` are reconciled by `resolveIdentities`
   * — if only `auth` is set it becomes a single identity; if both are set
   * `identities` wins and `auth` is ignored.
   */
  identities?: NamedIdentity[];
  /** Path to an OpenAPI 3.x / Swagger 2.0 spec file for pre-loaded endpoint knowledge */
  apiSpecPath?: string;
  /** Enable best-of-N strategy racing: run multiple attack strategies in parallel, take the first that succeeds */
  race?: boolean;
  /** Enable EGATS (Evidence-Gated Attack Tree Search): beam-search over hypothesis tree */
  egats?: boolean;
  /**
   * Hard per-scan cost ceiling in USD. When set, the cumulative estimated
   * cost is checked after every tool call and the scan aborts cleanly
   * (exit code 4, partial findings preserved) once exceeded. Default
   * undefined → no ceiling, behavior unchanged.
   */
  costCeilingUsd?: number;
  /**
   * Path to a JSON scope file (pwnkit#215). Format: `{ "in_scope": [...],
   * "out_of_scope": [...] }` with rules of the form `host`, `*.domain`,
   * or `cidr/prefix`. When set, every URL the agent touches is checked
   * against this policy and out-of-scope URLs return as
   * `ToolResult.error`. The CLI pre-validates `--target` is in scope
   * before the agent boots; out-of-scope target = hard exit.
   */
  scopeFile?: string;
  /**
   * Per-host token-bucket rate-limit specification (#214). Accepts a
   * plain rps (`"5"` / `"10:25"` for rps:burst) or a comma-separated
   * mixture of per-host overrides plus a default
   * (`"api.example.com=5,*.example.com=3:6,2"`). When unset, scan
   * applies a conservative 5 rps default; set to disable
   * (semantically: `"0"` is rejected as invalid — a missing flag is
   * the way to disable, when we add an opt-out).
   */
  rateLimit?: string;
  /**
   * Generic-scanner-traffic suppression opt-out (pwnkit#217). Default
   * `false`. When scope is loaded the agent refuses to spawn `sqlmap`,
   * `nikto`, `gobuster`, `dirb`, `wfuzz`, `ffuf`, and `nmap -sV` /
   * `nmap -A`. Setting this to `true` disables that gate (use only
   * when the engagement explicitly permits generic-scanner traffic).
   * Has no effect unless `scopeFile` is also set.
   */
  allowScanners?: boolean;
  /**
   * Attribution headers from CLI (pwnkit#216). Each entry is `NAME=VALUE`.
   * Lower precedence than env vars and the scope file's `attribution`
   * block. Headers are injected ONLY on in-scope outbound traffic so
   * attribution doesn't leak to non-engagement targets.
   */
  attributionHeaders?: string[];
  /**
   * Attribution User-Agent token from CLI (pwnkit#216). When set (and not
   * overridden by env/scope file), the agent's User-Agent on in-scope
   * traffic becomes `pwnkit/<ver> (engagement: <token>)`.
   */
  attributionUaToken?: string;
  /**
   * Tool-call dispatch protocol for the legacy text-based agent loop
   * (pwnkit#232). `"json"` (default) keeps the `TOOL_CALL: <name> {...}`
   * format. `"xml"` switches to the `<command>` / `<flag>` / `<finding>` /
   * `<note>` protocol from `agent/xml-dispatch.ts` — survives malformed-
   * JSON output from cheap OpenRouter / Gemini / DeepSeek models. `"auto"`
   * picks XML when the model name matches the cheap-provider list, JSON
   * otherwise. Has no effect on the native API loop, which always uses
   * provider-native tool_use blocks.
   */
  dispatchMode?: "json" | "xml" | "auto";
  /**
   * http_audit mode (FROZEN CONTRACT). Set only when `mode === "http_audit"`.
   * The CLI parses these from the PWNKIT_TARGET_* env vars; the core builds
   * an in-memory ScopePolicy (host allowlist), path-prefix allowlist,
   * per-host RateLimiter, and a wall-clock kill switch from them, threaded
   * down through an EnforcementTracker into every fetch chokepoint and
   * aggregated into the report's `enforcement_summary` block.
   *
   * - `httpAuditAllowedHosts`: hosts the scan may touch (default = base host).
   * - `httpAuditAllowedPaths`: path PREFIXES the scan may touch (empty = all).
   * - `httpAuditRateLimitRps`: per-host requests-per-second cap (default 5).
   * - `httpAuditKillAfterSec`: wall-clock budget in seconds (default 1800).
   */
  httpAuditAllowedHosts?: string[];
  httpAuditAllowedPaths?: string[];
  httpAuditRateLimitRps?: number;
  httpAuditKillAfterSec?: number;
}

// ── Attack Templates ──

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AttackCategory =
  | "prompt-injection"
  | "jailbreak"
  | "system-prompt-extraction"
  | "data-exfiltration"
  | "tool-misuse"
  | "output-manipulation"
  | "encoding-bypass"
  | "multi-turn"
  // Source-code audit categories (pwnkit audit)
  | "prototype-pollution"
  | "path-traversal"
  | "command-injection"
  | "code-injection"
  | "regex-dos"
  | "unsafe-deserialization"
  | "information-disclosure"
  | "ssrf"
  | "sql-injection"
  | "xss"
  | "cors"
  | "security-misconfiguration"
  | "missing-validation"
  // Memory corruption / binary categories (kernel crash validation)
  | "heap-overflow"
  | "out-of-bounds-read"
  | "out-of-bounds-write"
  | "use-after-free"
  | "stack-buffer-overflow"
  | "null-pointer-deref"
  | "null-deref"
  | "integer-overflow"
  | "integer-truncation"
  | "race-condition"
  | "toctou"
  | "type-confusion"
  | "double-free"
  | "format-string"
  | "uninitialized-memory"
  // Supply-chain / package categories (audit + malicious-detector)
  | "known-vulnerable-package"
  | "supply-chain"
  | "other";

export interface AttackTemplate {
  id: string;
  name: string;
  category: AttackCategory;
  description: string;
  severity: Severity;
  owaspLlmTop10?: string;
  depth: ScanDepth[];
  payloads: AttackPayload[];
  detection: DetectionRules;
  metadata?: Record<string, unknown>;
}

export interface AttackPayload {
  id: string;
  prompt: string;
  systemContext?: string;
  multiTurn?: string[];
  description?: string;
}

export interface DetectionRules {
  vulnerablePatterns: string[];
  safePatterns?: string[];
  customCheck?: string;
}

// ── Scan Context (shared agent memory) ──

export interface ScanContext {
  config: ScanConfig;
  scanId?: string;
  target: TargetInfo;
  findings: Finding[];
  attacks: AttackResult[];
  warnings: ScanWarning[];
  startedAt: number;
  completedAt?: number;
}

export interface TargetInfo {
  url: string;
  type: "api" | "chatbot" | "agent" | "mcp" | "web-app" | "unknown";
  endpoints?: string[];
  systemPrompt?: string;
  model?: string;
  detectedFeatures?: string[];
}

// ── Findings ──

export type FindingStatus = "discovered" | "verified" | "confirmed" | "scored" | "reported" | "false-positive";
export type FindingTriageStatus = "new" | "accepted" | "suppressed";
export type FindingWorkflowStatus =
  | "backlog"
  | "todo"
  | "agent_review"
  | "in_progress"
  | "human_review"
  | "blocked"
  | "done"
  | "cancelled";

export type CaseTargetType = "ai-app" | "package" | "repository" | "web-app" | "unknown";
export type WorkItemKind =
  | "surface_map"
  | "hypothesis"
  | "poc_build"
  | "blind_verify"
  | "consensus"
  | "human_review";
export type WorkItemStatus = "backlog" | "todo" | "in_progress" | "blocked" | "done" | "cancelled";
export type ArtifactKind = "request" | "response" | "analysis" | "verdicts" | "sessions" | "events";
export type WorkerStatus = "idle" | "claiming" | "running" | "sleeping" | "stopped" | "error";

export interface FindingRemediation {
  summary: string;
  steps: string[];
  codeExample?: { before: string; after: string; language: string };
  references: string[];
}

/**
 * Per-layer triage telemetry. Each entry records what happened when one
 * triage layer (holding-it-wrong, evidence_gate, oracle, …) evaluated a
 * finding: did it pass, reject, downgrade, or skip; what was its confidence;
 * what reason did it give; how long did it take; what did it cost.
 *
 * The array is append-only and ordered by execution. A downstream router
 * model trains on it: given the layerVerdicts a finding accumulates, can a
 * cheaper subset of layers reach the same final verdict?
 *
 * See pwnkit#112 for the design and pwnkit#113 for the dynamic-routing
 * model that consumes this telemetry.
 */
export type TriageLayerName =
  | "holding_it_wrong"
  | "evidence_gate"
  | "reachability"
  | "multi_modal"
  | "oracle"
  | "pov_gate"
  | "structured_verify"
  | "consensus"
  | "kernel_oracle"
  | "publishability";

/**
 * Disclosure-worthiness verdict for a finding (issue #537 / #539).
 *
 * "Reproduces" ≠ "in scope." A finding can be a real, reproducible behaviour
 * and still not be worth filing — because the maintainer's threat model
 * disclaims it (`by_design`), an advisory already covers it (`duplicate`), the
 * latest version patched it (`fixed`), or the sink is only reachable from dead
 * / unexported code (`unreachable`). The valuable exception is `fix_bypass`: an
 * advisory exists, but our PoC still reproduces on the latest published version
 * — those ARE worth disclosing and must never be dropped as duplicates.
 *
 * `needs_verify` is the conservative fallback: the gate wanted to suppress but
 * the finding is severity/class-protected (see `canAutoSuppress`), so it is
 * routed to human review instead of being silently dropped.
 */
export type PublishabilityDecision =
  | "in_scope"
  | "by_design"
  | "duplicate"
  | "fixed"
  | "unreachable"
  | "fix_bypass"
  | "needs_verify";

export type LayerVerdictKind =
  | "pass"      // layer ran and approved the finding
  | "reject"    // layer ran and rejected (suppressed) the finding
  | "downgrade" // layer ran and downgraded severity but kept the finding
  | "skip"      // layer was disabled or didn't run for this finding
  | "error";    // layer threw, finding kept (conservative default)

export interface LayerVerdict {
  layer: TriageLayerName;
  verdict: LayerVerdictKind;
  /** 0.0–1.0 confidence in the verdict, where applicable. */
  confidence?: number;
  /** Short human-readable reason. Stable across runs for the same input. */
  reason: string;
  /** Wall-clock duration of this layer, in milliseconds. */
  durationMs: number;
  /** USD cost of this layer (LLM tokens etc). 0 for regex/grep layers. */
  costUsd: number;
  /** Severity transition if the layer changed it. */
  changedSeverity?: { from: Severity; to: Severity };
}

/**
 * Supply-chain dependency attribution (issue #565). Optional and additive —
 * stamped onto a Finding by the malicious-package oracles so a reviewer can
 * tell whether a supply-chain finding originates from the audited root package
 * itself (`direct`) or from a transitive dependency pulled in beneath it
 * (`transitive`). Real-world supply-chain attacks ride transitive deps
 * (event-stream was transitive), so attribution is the difference between
 * "this package is malicious" and "something three levels down is malicious".
 */
export interface SupplyChainAttribution {
  /** Whether the finding is about the audited root or a transitive dependency. */
  relation: "direct" | "transitive";
  /** The package the finding is actually about, formatted `name@version`. */
  package: string;
  /**
   * Depth in the resolved dependency tree. 0 = the audited root package,
   * 1 = a direct dependency of the root, 2+ = deeper transitive deps.
   */
  depth?: number;
  /**
   * Best-effort resolved path of package names from the audited root down to
   * the package this finding is about, e.g. `["my-app", "a", "evil-pkg"]`.
   */
  dependencyPath?: string[];
}

export interface Finding {
  id: string;
  templateId: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  status: FindingStatus;
  evidence: Evidence;
  fingerprint?: string;
  triageStatus?: FindingTriageStatus;
  triageNote?: string;
  /**
   * Append-only list of triage layer verdicts, ordered by execution.
   * Empty until the triage stage runs. See {@link LayerVerdict} for details.
   */
  layerVerdicts?: LayerVerdict[];
  workflowStatus?: FindingWorkflowStatus;
  workflowAssignee?: string | null;
  /**
   * ISO-8601 timestamp of the last workflow-state transition (pwnkit#414).
   * Optional and additive — set by the DB writer on every save and threaded
   * back through the restore mapper so resume paths preserve audit ordering.
   */
  workflowUpdatedAt?: string | null;
  /**
   * CVSS-like 0–100 score, populated during the "scored" stage (pwnkit#414).
   * Optional and additive. The shared `Finding` keeps it loosely typed
   * (numeric only) so it can be threaded through the persistence round-trip
   * without coupling shared to the scoring engine.
   */
  score?: number | null;
  confidence?: number; // 0.0–1.0 agent-assessed confidence
  cvssVector?: string; // CVSS vector string
  cvssScore?: number; // CVSS numeric score (0–10)
  remediation?: FindingRemediation;
  /**
   * Ordered proof-of-concept step graph (pwnkit#170). Optional and additive —
   * findings produced before this field existed leave it undefined, and every
   * renderer/exporter/sink must continue to work in that case. When populated,
   * downstream consumers (screenshot renderer, behavioural re-verify, advisory
   * markdown) prefer this structured form over the prose `evidence.*` strings.
   */
  pocSteps?: PocStep[];
  /**
   * Machine-executable verification contract (pwnkit#193 / pwnkit-cloud#111).
   * Optional and additive. When populated, cloud's canary watcher (and any
   * OSS caller) can re-evaluate whether the finding is still real against
   * a fresh checkout of the target repo. See {@link VerificationSpec}.
   */
  verificationSpec?: VerificationSpec;
  /**
   * Prior PoC execution report (pwnkit#171 / pwnkit#414). Optional and
   * additive. Typed as `unknown` here because the concrete
   * `PocExecutionReport` shape lives in `@pwnkit/core/disclose` and shared
   * must not import from core. Consumers that need the full shape
   * narrow it at the call site.
   */
  pocExecution?: unknown;
  /**
   * Last deterministic-replay verification result attached to this finding
   * (pwnkit#193). Optional and additive — populated by the replay runner
   * (or by cloud after re-running the verifier) and consumed by the
   * disclosure / promotion gates. The shape is validated by
   * `VerificationResultSchema` in this same module; we type it as the
   * inferred TS type here to keep import-cycle risk down (no zod runtime
   * dep needed for callers that only *read* the field).
   */
  verification_result?: VerificationResult;
  /**
   * Optional parent finding link for derived findings. Kernel crash ingest
   * uses this when a crash-triggered subsystem review finds sibling bugs.
   */
  relatedFindingId?: string;
  /**
   * Disclosure-worthiness verdict from the publishability triage layer
   * (issue #537 / #539). Optional and additive — undefined until the
   * `publishability` layer runs (flag-gated, default OFF). When populated it
   * is the single in-product signal of whether a reproducible finding is
   * actually worth filing; the pre-file gate consumes it. See
   * {@link PublishabilityDecision}.
   */
  publishability?: PublishabilityDecision;
  /**
   * Advisory references the dedup check matched against this finding (GHSA /
   * CVE / OSV ids, issue #537 / #539). Optional and additive. Populated by the
   * publishability layer's dedup step; carries the evidence behind a
   * `duplicate` / `fix_bypass` decision so a reviewer can see what was matched.
   */
  dedupRefs?: string[];
  /**
   * Inline (in-loop) validation verdict (issue #554). Optional and additive.
   * Set by the native attack loop's onFindingSaved hook when
   * PWNKIT_FEATURE_INLINE_VALIDATION is on and a high/critical finding is saved:
   * a fast deterministic oracle re-runs the PoC inline so the attack agent gets
   * a real-time ground-truth signal instead of burning turns on an unprovable
   * lead. `confirmed` means the oracle reproduced the exploit — downstream
   * triage reuses this to skip the redundant batch oracle / PoV gate (no
   * double-spend), and EGATS `scoreEvidence` lets a confirmed finding dominate
   * the regex signals. `inconclusive` (the oracle errored or could not run to a
   * conclusion) NEVER marks a finding false-positive. See
   * {@link InlineValidationVerdict}.
   */
  inlineValidation?: InlineValidationVerdict;
  /**
   * Supply-chain dependency attribution (issue #565). Optional and additive —
   * populated by the transitive malicious-package scan and the
   * dependency-confusion check. When absent, the finding predates the
   * attribution work or is not a supply-chain finding. See
   * {@link SupplyChainAttribution}.
   */
  supplyChain?: SupplyChainAttribution;
  timestamp: number;
}

/**
 * Verdict from the in-loop ("validate-on-save") deterministic check (#554).
 * Attached to {@link Finding.inlineValidation}. Lives in shared so both the
 * core attack loop (which writes it) and downstream consumers (EGATS scorer,
 * triage oracle layer) can read it without an import cycle.
 */
export interface InlineValidationVerdict {
  /** The deterministic oracle reproduced the exploit out-of-band. */
  confirmed: boolean;
  /**
   * The oracle could not run to a conclusion (harness/infra error, or the
   * inline check itself threw). Inconclusive is NEVER a refutation — the full
   * verification batch re-checks the finding later.
   */
  inconclusive: boolean;
  /** Short human-readable reason for the verdict. */
  reason: string;
  /** Concrete artifact the oracle reproduced (when confirmed). */
  evidence?: string;
  /** Oracle confidence (0–1) when confirmed. */
  confidence?: number;
}

// ── Agent Verdicts (multi-agent consensus) ──

export type VerdictType = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "UNSURE";

export interface AgentVerdict {
  id: string;
  findingId: string;
  agentRole: string;
  model: string;
  verdict: VerdictType;
  confidence: number; // 0.0–1.0
  reasoning: string;
  timestamp: number;
}

// ── Case / Work Graph ──

export interface CaseRecord {
  id: string;
  target: string;
  targetType: CaseTargetType;
  latestScanId?: string | null;
  status: "open" | "in_progress" | "human_review" | "done" | "cancelled";
  createdAt: string;
  updatedAt: string;
}

export interface WorkItemRecord {
  id: string;
  caseId: string;
  findingFingerprint?: string | null;
  kind: WorkItemKind;
  title: string;
  owner?: string | null;
  status: WorkItemStatus;
  summary?: string | null;
  dependsOn?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ArtifactRecord {
  id: string;
  caseId: string;
  findingFingerprint?: string | null;
  workItemId?: string | null;
  kind: ArtifactKind;
  label: string;
  content?: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export interface WorkerRecord {
  id: string;
  role: "orchestrator";
  status: WorkerStatus;
  label: string;
  currentCaseId?: string | null;
  currentWorkItemId?: string | null;
  currentScanId?: string | null;
  pid?: number | null;
  host?: string | null;
  lastError?: string | null;
  heartbeatAt: string;
  startedAt: string;
  updatedAt: string;
}

// ── Pipeline Events (audit trail) ──

export interface PipelineEvent {
  id: string;
  scanId: string;
  stage: string; // PipelineStage or agent role
  eventType: string;
  findingId?: string;
  agentRole?: string;
  payload: Record<string, unknown>;
  timestamp: number;
}

// ── Agent Sessions (resumable state) ──

export interface AgentSessionState {
  id: string;
  scanId: string;
  agentRole: string;
  turnCount: number;
  messages: unknown[]; // serialized conversation
  toolContext: Record<string, unknown>;
  status: "running" | "paused" | "completed" | "failed";
  createdAt: string;
  updatedAt: string;
}

export interface Evidence {
  request: string;
  response: string;
  analysis?: string;
}

// ── PoC Step Graph (pwnkit#170) ──────────────────────────────────────────────
//
// Today, `Finding.evidence` is three free-text strings. Everything downstream
// that wants to *act* on the PoC — multi-frame screenshot rendering, behavioural
// re-verification (pwnkit#171), advisory rendering, machine-checkable
// verification specs — has to re-parse that prose.
//
// `pocSteps` formalises the proof-of-concept as an ordered list of named
// steps. Each step has a `kind` (setup / auth / prerequisite / exploit /
// verify), a one-line `summary` that captions the step in screenshots and
// advisories, an `action` (shell / http / docker / note), and an optional
// `expect` predicate that downstream executors check to decide pass/fail.
//
// The field is OPTIONAL and ADDITIVE. Existing findings produced before this
// type existed have `pocSteps === undefined` and continue to round-trip
// unchanged through every renderer, exporter, the DB, and the cloud sink.

/** Stage of a PoC step in the discover → exploit → verify lifecycle. */
export type PocStepKind = "setup" | "auth" | "prerequisite" | "exploit" | "verify";

/**
 * Action of a PoC step. Discriminated union keyed on `type`. Exactly one
 * variant is set; downstream executors switch on `type` to dispatch.
 *
 * - `shell` — a command to run in a shell. `cwd` is optional and defaults to
 *   the executor's working directory.
 * - `http` — a single HTTP request. `headers`/`body` optional.
 * - `docker` — a docker run with image + args, used when the PoC needs a
 *   side-container (e.g. attacker-controlled HTTP listener).
 * - `note` — operator-narrated, non-executable step. Renders into screenshots
 *   and advisories but is skipped by the behavioural re-verify executor.
 */
export type PocStepAction =
  | { type: "shell"; cmd: string; cwd?: string }
  | {
      type: "http";
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: string;
    }
  | { type: "docker"; image: string; args: string[] }
  | { type: "note"; text: string };

/**
 * Predicate the behavioural re-verify executor checks after running an action.
 * If `expect` is undefined the step is treated as informational and any
 * non-throwing execution counts as pass.
 *
 * - `exit-zero` — process exited 0 (only meaningful for shell/docker).
 * - `http-status` — HTTP status equals the given code or is a member of the
 *   given set.
 * - `body-contains` — response body contains the given substring (HTTP) or
 *   stdout contains it (shell/docker).
 * - `body-matches` — response body matches the given regex pattern.
 * - `file-exists` — the named path exists after the step ran.
 */
export type PocStepExpect =
  | { type: "exit-zero" }
  | { type: "http-status"; status: number | number[] }
  | { type: "body-contains"; text: string }
  | { type: "body-matches"; pattern: string }
  | { type: "file-exists"; path: string };

export interface PocStep {
  /** Stable identifier — used by the screenshot renderer to name its output. */
  id: string;
  /** Lifecycle stage of this step. */
  kind: PocStepKind;
  /** One-line description shown as caption in screenshots and the advisory. */
  summary: string;
  /** How to execute this step. Exactly one variant set. */
  action: PocStepAction;
  /**
   * Optional predicate the re-verify executor checks. When present, the step
   * counts as pass only if the predicate is satisfied; otherwise the step is
   * informational.
   */
  expect?: PocStepExpect;
}

// ── Verification Spec (pwnkit#193 / pwnkit-cloud#111) ───────────────────────
//
// A `VerificationSpec` is a *machine-executable* contract attached to a
// finding. It answers a single question: "is this finding still real?".
//
// The engine emits the spec when it produces a finding. Cloud (and OSS
// callers) can later evaluate it against a fresh checkout of the target
// repo to decide if the underlying vulnerability has been patched, partially
// fixed, or is still exploitable — without re-running the full LLM agent.
//
// The spec is split into two layers:
//
// 1. `code[]` — pure code-level predicates. Cheap, deterministic, no target
//    provisioning required. All predicates must pass for the finding to
//    still count as vulnerable. If any fails, surface as `partial-fix`.
//
// 2. `behavior` — optional behavioural predicate. Requires a provisioned
//    target. If present and its exploit predicate fails, the finding is
//    `fixed` regardless of what `code[]` says.
//
// The field is OPTIONAL and ADDITIVE on `Finding`. Existing findings produced
// before this type existed leave it undefined and continue to round-trip
// unchanged through every renderer, exporter, the DB, and the cloud sink.

/**
 * Code-level predicate. Each variant is a discriminated union keyed on
 * `kind`. All paths are repo-relative (resolved against the repoRoot the
 * verifier is given). Patterns are JS regex source strings (so they can
 * be persisted as JSON and re-hydrated cleanly).
 *
 * - `file-contains` — file exists AND its contents match `pattern` (with
 *   optional regex `flags`). The vulnerable shape should still be present.
 * - `file-missing-pattern` — file exists AND its contents do NOT match
 *   `pattern`. Used to assert that a fix-marker (e.g. an `assertAdmin`
 *   call) is still absent.
 * - `file-exists` — file simply exists. Cheapest predicate; useful when
 *   the vulnerable file has a stable name but the shape is hard to pin
 *   with a single regex.
 * - `ast-shape` — tree-sitter query against the file's parsed AST.
 *   Stronger than regex but costs a tree-sitter dependency. Marked as
 *   not-yet-implemented in the OSS verifier; treated as "skipped" when
 *   evaluated, which is conservative (an unimplemented predicate cannot
 *   prove the finding is fixed).
 */
export type VerificationCodePredicate =
  | { kind: "file-contains"; file: string; pattern: string; flags?: string }
  | { kind: "file-missing-pattern"; file: string; pattern: string; flags?: string }
  | { kind: "file-exists"; file: string }
  | { kind: "ast-shape"; file: string; query: string };

/**
 * Behavioural predicate — a single HTTP step the verifier should replay
 * against a provisioned target. `expect` is one of:
 *
 * - `"success"` — any 2xx is fine.
 * - `"forbidden"` — the request is expected to be rejected (4xx, typically
 *   401/403). When the finding is "still vulnerable" the actual response
 *   is a `success`, so a `forbidden` here is the *fix marker*: if the
 *   target is forbidden, the exploit no longer works.
 * - `{ status: number }` — exact status code match.
 *
 * The runtime executor that consumes this is OUT OF SCOPE for the OSS
 * verifier in pwnkit#193 — code predicates only. The shape is recorded
 * here so cloud's canary watcher can dispatch it later.
 */
export interface VerificationBehaviorStep {
  method: string;
  path: string;
  body?: unknown;
  expect: "success" | "forbidden" | { status: number };
}

export interface VerificationBehavior {
  steps: VerificationBehaviorStep[];
}

export interface VerificationSpec {
  /**
   * Code-level predicates that must all be true for the finding to remain
   * vulnerable. Empty array is permitted (means "no code-level signal";
   * verifier returns inconclusive when there is also no `behavior`).
   */
  code: VerificationCodePredicate[];
  /** Optional behavioural predicate. Requires target provisioning. */
  behavior?: VerificationBehavior;
}

// ── Kernel Crash Reports ──

export type CrashType =
  | "kasan-oob"          // KASAN: heap out-of-bounds
  | "kasan-stack-oob"    // KASAN: stack-out-of-bounds
  | "kasan-uaf"          // KASAN: use-after-free
  | "kasan-double-free"  // KASAN: double-free
  | "kasan-invalid-free" // KASAN: invalid-free (freeing non-allocated memory)
  | "kasan-null"         // KASAN: null-ptr-deref
  | "kasan-wild"         // KASAN: wild-memory-access
  | "ubsan"              // UBSAN: undefined behavior (unrecognized subtype)
  | "ubsan-shift"        // UBSAN: shift-out-of-range
  | "ubsan-overflow"     // UBSAN: signed/unsigned integer overflow
  | "ubsan-bounds"       // UBSAN: array-index-out-of-bounds
  | "ubsan-alignment"    // UBSAN: misaligned access
  | "kernel-bug"         // BUG()/BUG_ON()
  | "kernel-oops"        // Kernel oops
  | "kernel-panic"       // Kernel panic
  | "general-protection" // general protection fault
  | "rcu-stall"          // RCU stall
  | "lockdep"            // Lock dependency violation
  | "unknown";

export interface CrashReport {
  rawText: string;
  crashType: CrashType;
  faultingFunction: string;
  callStack: string[];
  subsystem: string;
  accessType?: "read" | "write";
  accessSize?: number;
  accessAddress?: string;
  allocSite?: string;
  freeSite?: string;
  reproducer?: string;
  reproducerLanguage?: "c" | "syz" | "bash";
  kernelVersion?: string;
  commitHash?: string;
  configFragment?: string;
}

export interface IngestConfig {
  inputPath: string;
  format?: "auto" | "kasan" | "ubsan" | "oops" | "syzkaller" | "generic";
  outputFormat: OutputFormat;
  verbose?: boolean;
}

// ── Attack Results ──

export type AttackOutcome = "vulnerable" | "safe" | "error" | "inconclusive";

export interface AttackResult {
  templateId: string;
  payloadId: string;
  outcome: AttackOutcome;
  request: string;
  response: string;
  latencyMs: number;
  timestamp: number;
  error?: string;
}

// ── Pipeline Stages ──

export type PipelineStage = "discovery" | "source-analysis" | "attack" | "verify" | "report";

export interface StageResult<T = unknown> {
  stage: PipelineStage;
  success: boolean;
  data: T;
  durationMs: number;
  error?: string;
}

// ── Report ──

export interface ScanWarning {
  stage: PipelineStage;
  message: string;
}

/**
 * Reason a scan terminated. Undefined / "completed" means the scan finished
 * normally. "cost_ceiling_exceeded" means the per-scan cost ceiling
 * (`PWNKIT_COST_CEILING_USD` / `--cost-ceiling`) was hit and the scan
 * aborted with partial findings preserved.
 */
export type ScanExitReason = "completed" | "cost_ceiling_exceeded";

export interface ScanReport {
  target: string;
  scanDepth: ScanDepth;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  summary: ReportSummary;
  findings: Finding[];
  warnings: ScanWarning[];
  benchmarkMeta?: {
    attackTurns?: number;
    estimatedCostUsd?: number;
    inputTokens?: number;
    outputTokens?: number;
    totalTokens?: number;
    model?: string;
  };
  /**
   * Reason the scan terminated. Undefined for normal completion. Set to
   * "cost_ceiling_exceeded" when the scan was aborted by the cost ceiling.
   */
  exitReason?: ScanExitReason;
  /** True when the scan was aborted by the per-scan cost ceiling. */
  costCeilingExceeded?: boolean;
  /**
   * Full conversation trace from the agent loop (discovery + attack messages).
   * Populated only when the caller opts in (e.g. benchmark runs). Not included
   * in normal scan output to avoid bloating JSON reports.
   */
  trace?: unknown[];
  /**
   * http_audit enforcement summary (frozen worker contract). Present ONLY
   * when the scan ran in `mode: "http_audit"`; undefined for every other
   * mode. Emitted verbatim as the `enforcement_summary` block in the report
   * JSON so the cloud worker can audit scope adherence, rate-limit pacing,
   * and the kill-switch outcome of an authed HTTP scan.
   */
  enforcementSummary?: EnforcementSummary;
}

/**
 * Frozen `enforcement_summary` block emitted in http_audit reports. Mirrors
 * `EnforcementSummary` in `@pwnkit/core` (scope/enforcement.ts); duplicated
 * here (rather than imported) so `@pwnkit/shared` stays dependency-free of
 * core. snake_case keys are part of the contract — do not rename.
 */
export interface EnforcementSummary {
  auth_mode_used: "bearer" | "header" | "cookie" | "basic" | "none";
  requests_in_scope: number;
  requests_out_of_scope_blocked: number;
  peak_rps: number;
  rate_limited_count: number;
  kill_switch_triggered: boolean;
  wall_clock_sec: number;
}

export interface ReportSummary {
  totalAttacks: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ── Package Audit (pwnkit audit) ──

export interface AuditConfig {
  package: string;
  version?: string;
  ecosystem?: PackageEcosystem;
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  timeout?: number;
  verbose?: boolean;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  /** Hard cost ceiling in USD; aborts the audit when exceeded. Default: no ceiling. */
  costCeilingUsd?: number;
  /**
   * Transitive-dependency source-audit budget (issue #565). Maximum number of
   * distinct (name@version) transitive packages whose source is scanned by the
   * deterministic malicious-package oracles. Default 200.
   * Set to 0 to disable the transitive walk entirely (root-only behaviour).
   */
  transitiveAuditBudget?: number;
  /**
   * Internal/private npm scopes the org owns, e.g. `["@acme", "@internal"]`
   * (issue #565). A dependency whose name lives in one of these scopes but
   * which ALSO resolves on the public registry is flagged as a
   * dependency-confusion risk. Empty/undefined disables the check.
   */
  internalScopes?: string[];
  /**
   * Exact internal/private npm package names (unscoped) the org publishes
   * privately (issue #565). Same dependency-confusion semantics as
   * {@link internalScopes} but for names without an `@scope/` prefix.
   */
  internalPackages?: string[];
}

export interface SemgrepFinding {
  ruleId: string;
  message: string;
  severity: string;
  path: string;
  startLine: number;
  endLine: number;
  snippet: string;
  metadata?: Record<string, unknown>;
}

export interface NpmAuditFinding {
  name: string;
  severity: Severity;
  title: string;
  range?: string;
  source?: number | string;
  url?: string;
  via: string[];
  fixAvailable: boolean | string;
}

/**
 * Token usage from an LLM-driven scan / audit / review. Optional because
 * non-LLM runtimes (semgrep-only, deterministic-only) won't populate it.
 */
export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
}

export interface AuditReport {
  package: string;
  version: string;
  ecosystem?: PackageEcosystem;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  semgrepFindings: number;
  npmAuditFindings: NpmAuditFinding[];
  summary: ReportSummary;
  findings: Finding[];
  /** LLM token usage (input + output). Undefined when no LLM agent ran. */
  usage?: TokenUsage;
  /** Estimated USD cost from token usage at the configured model rates. */
  estimatedCostUsd?: number;
}

// ── Source Code Review (pwnkit review) ──

/**
 * Review profile selects the prompt + harness strategy.
 *
 * - `default`: application-layer review (web, JS/TS/Python/Go business logic).
 * - `c-library`: foundational C/C++ libraries — memory safety, integer
 *   bugs, allocation paths. Pairs with the tier-1/2/3 harness scaffolder.
 * - `linux-kernel`: Linux kernel source review — syscall/ioctl/netlink
 *   surface, copy_from_user discipline, refcount races, skb cow/share
 *   violations (Dirty Frag class), TOCTOU on inode fields. Static-only;
 *   verification phase is pwnkit#271 (kernel oracle) and pwnkit#272
 *   (syzkaller harness scaffold).
 */
export type ReviewProfile = "default" | "c-library" | "linux-kernel";

export interface ReviewConfig {
  repo: string;
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  timeout?: number;
  verbose?: boolean;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  /** Hard cost ceiling in USD; aborts the review when exceeded. Default: no ceiling. */
  costCeilingUsd?: number;
  /** Review profile. Default: `"default"`. */
  profile?: ReviewProfile;
  /**
   * Restrict the review agent to files under this subdirectory (e.g. `crypto/`,
   * `net/tcp/`). Only meaningful when `profile === "linux-kernel"`. The value is
   * injected into the agent prompt as a hard scope restriction.
   */
  subsystem?: string;
  /** Operator hypothesis to seed the agent with a specific research direction.
   *  Inspired by Xint Code's operator prompt that found CVE-2026-31431. */
  hypothesis?: string;
  /**
   * External candidate vulnerable spans to seed the agent's worklist before
   * static scanner prioritisation runs. Today the only first-class producer is
   * GemmaForge (`gemmaforge scan`, schema `gemmaforge.leads/v1`). The parser
   * lives in `@pwnkit/core` (`seed-findings.ts`); it normalises any compliant
   * ND-JSON into this shape. Empty array = no external seeds; the selected
   * static scanner remains the lead source.
   */
  seedFindings?: SeedFinding[];
  /**
   * Skip static scanning entirely and rely solely on `seedFindings`. Only meaningful
   * when `seedFindings` is non-empty. Useful when the operator trusts the
   * external probe enough to skip the static-analysis pass.
   */
  seedOnly?: boolean;
}

/**
 * A vulnerability lead supplied externally (e.g. by GemmaForge) for the
 * review agent to investigate before its own lead-discovery passes run.
 *
 * The shape is intentionally narrow — just enough for the agent to know
 * *where* to look and *what kind* of issue to expect. The originating
 * confidence + free-form metadata are preserved so triage / reporting can
 * cite provenance (see issue #368).
 */
export interface SeedFinding {
  /** Repo-relative POSIX path to the file containing the candidate. */
  file: string;
  /** 1-indexed inclusive line span. */
  startLine: number;
  endLine: number;
  /** Verbatim source text of the span — carried inline so the agent doesn't need to re-read the file. */
  snippet: string;
  /** CWE identifier the producer assigns to the candidate, if any (`CWE-89` etc.). */
  cwe?: string;
  /** Producer-supplied confidence in [0, 1]. */
  confidence?: number;
  /** Free-text claim from the producer. Renderer may surface this as the seed's title. */
  claim?: string;
  /** Tag identifying the producer (`gemmaforge`, etc.). Required: provenance must survive into final findings. */
  source: string;
  /** Producer-specific provenance keys (e.g. `gemmaforge_layer`, `gemmaforge_confidence`). */
  metadata?: Record<string, unknown>;
}

export interface ReviewReport {
  repo: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  semgrepFindings: number;
  summary: ReportSummary;
  findings: Finding[];
  /** LLM token usage (input + output). Undefined when no LLM agent ran. */
  usage?: TokenUsage;
  /** Estimated USD cost from token usage at the configured model rates. */
  estimatedCostUsd?: number;
}
