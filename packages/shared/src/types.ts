import type { VerificationResult } from "./verification.js";
import type { ResearchEvidenceEnvelope } from "./research-evidence.js";

// ── Scan Configuration ──

export type ScanDepth = "quick" | "default" | "deep";
export type OutputFormat = "terminal" | "json" | "markdown" | "html" | "sarif" | "pdf";
export type RuntimeMode = "api" | "claude" | "codex" | "gemini" | "ollama" | "auto";
export type ScanMode = "probe" | "deep" | "mcp" | "web" | "http_audit" | "llm-ipi";
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

// ── Multi-identity access-control testing (0sec#564) ──

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
 * 0sec#564). Holds a human label, an optional privilege role, and the
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
   * Resolved package version of the target (e.g. "4.17.4"). Optional; when set
   * the publishability novelty gate (issue #851) scopes its OSV / GitHub
   * Advisory lookup to advisories that actually affect THIS version, instead of
   * matching any historical advisory for the package. Unset → the gate falls
   * back to a package-level lookup (less precise → `possibly-known` on a hit).
   */
  version?: string;
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
  /**
   * Explicit attack-agent turn ceiling. When omitted the engine derives its
   * normal budget from `depth`; benchmark adapters set this to make the
   * declared per-attempt budget enforceable.
   */
  maxAttackTurns?: number;
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
   * BFLA + horizontal/vertical privesc, 0sec#564). When ≥2 entries are
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
   * Path to a JSON scope file (0sec#215). Format: `{ "in_scope": [...],
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
   * Generic-scanner-traffic suppression opt-out (0sec#217). Default
   * `false`. When scope is loaded the agent refuses to spawn `sqlmap`,
   * `nikto`, `gobuster`, `dirb`, `wfuzz`, `ffuf`, and `nmap -sV` /
   * `nmap -A`. Setting this to `true` disables that gate (use only
   * when the engagement explicitly permits generic-scanner traffic).
   * Has no effect unless `scopeFile` is also set.
   */
  allowScanners?: boolean;
  /**
   * Attribution headers from CLI (0sec#216). Each entry is `NAME=VALUE`.
   * Lower precedence than env vars and the scope file's `attribution`
   * block. Headers are injected ONLY on in-scope outbound traffic so
   * attribution doesn't leak to non-engagement targets.
   */
  attributionHeaders?: string[];
  /**
   * Attribution User-Agent token from CLI (0sec#216). When set (and not
   * overridden by env/scope file), the agent's User-Agent on in-scope
   * traffic becomes `0sec/<ver> (engagement: <token>)`.
   */
  attributionUaToken?: string;
  /**
   * Tool-call dispatch protocol for the legacy text-based agent loop
   * (0sec#232). `"json"` (default) keeps the `TOOL_CALL: <name> {...}`
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
   * The CLI parses these from the 0SEC_TARGET_* env vars; the core builds
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
  /**
   * Engagement hardening profile (`--engagement-profile <name>`). `"standard"`
   * (or unset) is the historical, unchanged behaviour. `"conservative"` applies
   * a single quiet posture for authorized enterprise engagements: no
   * password-reset burst probe, the web-recon pre-pass routed through the
   * per-host rate limiter, no WAF-evasion ladder, full jitter on the token
   * bucket, and a reduced default per-host rps. Lower precedence than the scope
   * file's `engagement` block and `0SEC_ENGAGEMENT_PROFILE`. See
   * `scope/engagement-profile.ts` in `@0sec/core`.
   */
  engagementProfile?: string;
  /**
   * Standalone opt-out for the adaptive WAF-evasion ladder, independent of the
   * engagement profile (`--no-waf-evasion` → `false`). Unset = enabled, which
   * is the historical default. Lower precedence than the scope file's
   * `engagement.waf_evasion` and `0SEC_WAF_EVASION`.
   */
  wafEvasion?: boolean;
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
  // Source-code audit categories (0sec audit)
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
  // Cryptographic misuse (static source audit — weak hash, hardcoded keys/IV,
  // ECB mode, JWT alg-confusion, predictable RNG for secrets)
  | "crypto-misuse"
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
  // Availability-only kernel findings (soft lockups, hangs — no corruption)
  | "denial-of-service"
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

export type FindingStatus = "discovered" | "verified" | "confirmed" | "scored" | "reported" | "fixed" | "false-positive";
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
 * See 0sec#112 for the design and 0sec#113 for the dynamic-routing
 * model that consumes this telemetry.
 */
export type TriageLayerName =
  | "holding_it_wrong"
  | "evidence_gate"
  | "reachability"
  | "multi_modal"
  | "oracle"
  | "pov_gate"
  | "poc_gen"
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

/**
 * Business-impact scoring for a finding (issue #1103). Qualifies raw
 * `severity` + `exploitability` with the decision-relevant question a triager
 * actually asks: how much does this bug matter, and how hard is it to reach?
 *
 * The engine self-prioritizes on these so a nominally "critical" bug gated
 * behind root+host-migration (an FS-image UAF that needs a mounted attacker
 * image = noise) sorts BELOW a "high" bug that hits every device on the network
 * (a remote-unauth NFC crash = headline). Optional/additive — populated by the
 * impact-assessment triage layer; undefined on findings that predate it.
 */

/**
 * How the attacker has to be positioned to reach the sink — the gate that
 * turns raw severity into real risk. Ordered most→least dangerous.
 *   - `remote-unauth`         — reachable over the network with no auth.
 *   - `proximity-rf`          — needs RF/physical proximity (NFC, BLE, Wi-Fi).
 *   - `local-unpriv`          — needs an unprivileged local account.
 *   - `local-priv`            — needs an already-privileged local account
 *     (root/admin) — a low-value LPE target: the attacker is already there.
 *   - `needs-hardware`        — needs specific/attacker-supplied hardware.
 *   - `needs-host-migration`  — needs the victim to mount/import/migrate an
 *     attacker-supplied artifact (FS image, VM, container) first.
 */
export type ReachabilityTier =
  | "remote-unauth"
  | "proximity-rf"
  | "local-unpriv"
  | "local-priv"
  | "needs-hardware"
  | "needs-host-migration";

/**
 * What the attacker gets once they trigger the bug. Ordered least→most severe.
 *   - `dos-crash`   — denial of service / crash only.
 *   - `info-leak`   — reads memory / secrets they shouldn't.
 *   - `lpe-to-root` — local privilege escalation to root/admin.
 *   - `rce`         — arbitrary remote code execution.
 */
export type Weaponizability = "dos-crash" | "info-leak" | "lpe-to-root" | "rce";

/**
 * Deployment context of a finding's exploit path — where the vulnerable code
 * actually runs. Bounty programs reject dev/test/build-only findings outright,
 * and the engine auto-downgrades them. Set by the mechanical path heuristic at
 * lead→finding conversion; the model lens may refine it, but the mechanical
 * tag wins on conflict (it is the deterministic floor).
 *
 * - `prod_reachable`: the vulnerable code is deployed to production or could
 *   reach a production runtime via a trust-boundary crossing.
 * - `dev_only`: dev-only surface (seeds, .dev.vars, dev servers).
 * - `test_only`: files in test directories or matching test patterns.
 * - `build_only`: build/config tooling, CI, scaffolding, generated code.
 */
export type DeploymentContext = "prod_reachable" | "dev_only" | "test_only" | "build_only";

/**
 * The coarse, ranking-facing tier. This is the single knob the engine sorts on:
 * `noise` gets deprioritized, `headline` gets escalated. Ordered.
 */
export type BusinessImpact = "headline" | "notable" | "modest" | "noise";

/**
 * Structured impact assessment attached to a {@link Finding} by the
 * impact-assessment triage layer. Optional/additive.
 */
export interface ImpactAssessment {
  /** How the attacker has to be positioned to reach the sink. */
  reachability_tier: ReachabilityTier;
  /** Free-text scope of who/what is affected (e.g. "every device with NFC"). */
  blast_radius: string;
  /** What the attacker gains once the bug fires. */
  weaponizability: Weaponizability;
  /** The coarse tier the engine ranks on. */
  business_impact: BusinessImpact;
  /** Short human-readable justification, stable for the same input. */
  rationale: string;
}

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
   * ISO-8601 timestamp of the last workflow-state transition (0sec#414).
   * Optional and additive — set by the DB writer on every save and threaded
   * back through the restore mapper so resume paths preserve audit ordering.
   */
  workflowUpdatedAt?: string | null;
  /**
   * CVSS-like 0–100 score, populated during the "scored" stage (0sec#414).
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
   * Structured source location for CI review annotations. Populated only when
   * the agent cites an exact workspace-contained path and line range at
   * save_finding time. Consumers must still intersect this with the provider's
   * changed-line map before posting an inline comment.
   */
  reviewAnnotation?: {
    path: string;
    startLine: number;
    endLine?: number;
    /** Replacement text for a provider-native suggestion block. */
    suggestion?: string;
    /**
     * Exact cited source lines contain a maintainer-awareness marker
     * (TODO/FIXME/XXX/HACK or a known-limitation note). The cloud holds
     * automatic disclosure promotion; this never drops the finding.
     */
    knownMarker?: boolean;
  };
  /**
   * Ordered proof-of-concept step graph (0sec#170). Optional and additive —
   * findings produced before this field existed leave it undefined, and every
   * renderer/exporter/sink must continue to work in that case. When populated,
   * downstream consumers (screenshot renderer, behavioural re-verify, advisory
   * markdown) prefer this structured form over the prose `evidence.*` strings.
   */
  pocSteps?: PocStep[];
  /**
   * Machine-executable verification contract (0sec#193 / 0sec-cloud#111).
   * Optional and additive. When populated, cloud's canary watcher (and any
   * OSS caller) can re-evaluate whether the finding is still real against
   * a fresh checkout of the target repo. See {@link VerificationSpec}.
   */
  verificationSpec?: VerificationSpec;
  /**
   * Prior PoC execution report (0sec#171 / 0sec#414). Optional and
   * additive. Typed as `unknown` here because the concrete
   * `PocExecutionReport` shape lives in `@0sec/core/disclose` and shared
   * must not import from core. Consumers that need the full shape
   * narrow it at the call site.
   */
  pocExecution?: unknown;
  /**
   * Last deterministic-replay verification result attached to this finding
   * (0sec#193). Optional and additive — populated by the replay runner
   * (or by cloud after re-running the verifier) and consumed by the
   * disclosure / promotion gates. The shape is validated by
   * `VerificationResultSchema` in this same module; we type it as the
   * inferred TS type here to keep import-cycle risk down (no zod runtime
   * dep needed for callers that only *read* the field).
   */
  verification_result?: VerificationResult;
  /** Target-neutral research receipts attached by the shared adapter plane. */
  researchEvidence?: ResearchEvidenceEnvelope[];
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
   * Intra-scan semantic dedupe mapping (anchored incremental LLM clustering,
   * `triage/semantic-dedupe.ts`, flag-gated `0SEC_FEATURE_SEMANTIC_DEDUPE`,
   * default OFF). Optional and additive — undefined unless the post-pass ran.
   * Canonical findings carry `isCanonical: true` and map to themselves;
   * duplicates carry the canonical's id, a stable `clusterId` (`scanId:canonicalId`),
   * and the clustering reason so downstream consumers can collapse or display
   * the duplicate set without re-deriving it.
   */
  semanticDedupe?: {
    /** Id of the canonical finding this finding maps to. */
    canonicalId: string;
    /** Whether this finding IS the canonical for its cluster. */
    isCanonical: boolean;
    /** Stable cluster identifier: `${scanId}:${canonicalId}`. */
    clusterId: string;
    /** Human-readable reason for the clustering decision. */
    reason: string;
  };
  /**
   * Incremental rank assigned by the ranking post-pass
   * (`triage/incremental-rank.ts`, flag-gated
   * `0SEC_FEATURE_INCREMENTAL_RANK`, default OFF). 1 = highest comparative
   * promise for a security researcher. Optional and additive — undefined
   * unless the post-pass ran; ranks are per-scan, not global.
   */
  findingRank?: number;
  /**
   * Public-advisory novelty verdict (issue #851). Optional and additive —
   * undefined until the publishability layer's novelty step runs (flag-gated
   * via `0SEC_FEATURE_PUBLISHABILITY_GATE`, OSS ecosystems only). The
   * structured counterpart to the old text-over-notes heuristic the disclosure
   * cockpit used: `matches-CVE-…` / `matches-GHSA-…` mean a live OSV / GitHub
   * Advisory DB lookup found a published advisory covering this package+version
   * (downgrade send → courtesy), `novel` means the lookup ran and found nothing
   * (keep in the send lane), and `possibly-known` means the lookup was
   * inconclusive or skipped (private/SaaS target, no version, etc.). The
   * evidence behind a `matches-*` verdict lives in {@link advisoryMatches}.
   */
  noveltyVerdict?:
    | "novel"
    | "possibly-known"
    | `matches-GHSA-${string}`
    | `matches-CVE-${string}`;
  /**
   * Advisory links backing a `matches-*` {@link noveltyVerdict} (issue #851).
   * Optional and additive — each entry is a published advisory (OSV / GHSA /
   * CVE) covering this finding's package+version, with the advisory id and a
   * link a reviewer can open. Empty/undefined when the verdict is `novel` /
   * `possibly-known`.
   */
  advisoryMatches?: Array<{
    source: "OSV" | "GHSA" | "CVE";
    id: string;
    url?: string;
    version?: string;
  }>;
  /**
   * Inline (in-loop) validation verdict (issue #554). Optional and additive.
   * Set by the native attack loop's onFindingSaved hook when
   * 0SEC_FEATURE_INLINE_VALIDATION is on and a high/critical finding is saved:
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
  /**
   * Structured kernel-exploit state carried forward between weaponization
   * stages (kernel-autonomy Phase 1). Optional and additive — undefined for
   * non-kernel findings and for kernel findings that never reached
   * weaponization. The canonical typed shape (`KernelExploitContext`) lives in
   * `@0sec/core/kernel/exploit`; shared must not import from core (the
   * dependency only runs core → shared), so we mirror it here with a
   * structurally-identical lightweight interface. Core consumers can assign a
   * `KernelExploitContext` into this field and read it back without a cast
   * because the shapes match field-for-field. See {@link KernelExploitState}.
   */
  kernelExploit?: KernelExploitState;
  /**
   * Business-impact assessment (issue #1103). Optional and additive —
   * populated by the impact-assessment triage layer, undefined on findings
   * that predate it. Qualifies `severity` with reachability + weaponizability
   * so the engine can self-prioritize (deprioritize `noise`, escalate
   * `headline`). Round-trips into the `findings.impact_assessment` jsonb
   * column. See {@link ImpactAssessment}.
   */
  impactAssessment?: ImpactAssessment;
  /**
   * Deployment context classification (issue #1215). Set by the mechanical path
   * heuristic at lead→finding conversion in {@link leadToCandidateFinding}.
   * `prod_reachable` (default) means the heuristic found no dev/test/build
   * evidence; it does NOT guarantee prod reachability. Optional and additive -
   * findings produced before this field existed leave it undefined, and every
   * downstream consumer must work in that case.
   */
  deploymentContext?: DeploymentContext;
  timestamp: number;
}

/**
 * Lightweight, dependency-free mirror of `@0sec/core`'s `KernelExploitContext`
 * so the shared `Finding` can carry kernel-exploit state without importing from
 * core (which would invert the workspace dependency direction). Kept
 * structurally identical to the core type — when one changes, change both.
 */
export interface KernelExploitState {
  /** Derived shape of the controlled write primitive. */
  writeProfile?: KernelWritePrimitiveProfile;
  /** Candidate heap-spray reclaim plans. */
  sprayPlans?: KernelSprayPlan[];
  /** The targeted root-tail finisher plan. */
  rootTailPlan?: KernelRootTailPlan;
  /** Highest escalation rung any run has actually reached (monotone). */
  highestRung?: KernelEscalationRung;
  /** Whether a controlled reclaim was observed to land. */
  reclaimLanded?: boolean;
  /** Whether local privilege escalation (root) was deterministically achieved. */
  lpeAchieved?: boolean;
  /** Reference (path / id) to a proof artifact for the achieved capability. */
  proofArtifactRef?: string;
}

/** Mirror of core's `EscalationRung` (weakest → strongest). */
export type KernelEscalationRung =
  | "none"
  | "attempted"
  | "triggered"
  | "reclaim"
  | "arb-read"
  | "arb-write"
  | "root";

/** Mirror of core's `WritePrimitiveProfile`. */
export interface KernelWritePrimitiveProfile {
  dstOffset?: number;
  lenOffset?: number;
  srcOffset?: number;
  writeWidth?: "controlled" | "fixed";
  controllable?: boolean;
  /** Offset of the callable fn-ptr (timer_list.function) for a `call` primitive. */
  funcPtrOffset?: number;
  conclusion?: string;
}

/** Mirror of core's `SprayPlan`. */
export interface KernelSprayPlan {
  primitive: string;
  bucketMatch?: boolean;
  contentControlled?: boolean;
  unprivileged?: boolean;
  sameCpuPinnable?: boolean;
  persistence?: "transient" | "persistent";
  viabilityReason?: string;
}

/** Mirror of core's `RootTailPlan`. */
export interface KernelRootTailPlan {
  tail: "modprobe_path" | "core_pattern" | "cred" | "fake-cred" | "workqueue-www";
  targetSymbol?: string;
  /** Resolved target symbol address as a `0x…` hex string (unslid under KASLR). */
  targetAddr?: string;
  /** Unslid kernel base (`_text`) as a `0x…` hex string, for slide computation. */
  unslidBase?: string;
  /** Whether KASLR (`RANDOMIZE_BASE`) is on for the target kernel. */
  kaslrOn?: boolean;
  /** Whether the chain has an established kernel-address leak. */
  hasLeak?: boolean;
  pathString?: string;
  byteFidelityOk?: boolean;
  dropUidTrigger?: boolean;
  /** `fake-cred` honesty flag: KASLR on + no kernel-text leak ⇒ text leak required. */
  hardenedNeedsTextLeak?: boolean;
  reason?: string;
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
  /** Producer provenance survives DB persistence for presentation adapters. */
  source?: string;
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

// ── PoC Step Graph (0sec#170) ──────────────────────────────────────────────
//
// Today, `Finding.evidence` is three free-text strings. Everything downstream
// that wants to *act* on the PoC — multi-frame screenshot rendering, behavioural
// re-verification (0sec#171), advisory rendering, machine-checkable
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

// ── Verification Spec (0sec#193 / 0sec-cloud#111) ───────────────────────
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
 * `kind`. File-based variants use repo-relative paths (resolved against the
 * repoRoot the verifier is given). Patterns are JS regex source strings (so
 * they can be persisted as JSON and re-hydrated cleanly).
 *
 * - `file-contains` — file exists AND its contents match `pattern` (with
 *   optional regex `flags`). The vulnerable shape should still be present.
 * - `file-missing-pattern` — file exists AND its contents do NOT match
 *   `pattern`. Used to assert that a fix-marker (e.g. an `assertAdmin`
 *   call) is still absent.
 * - `file-exists` — file simply exists. Cheapest predicate; useful when the
 *   vulnerable file has a stable name but the shape is hard to pin
 *   with a single regex.
 * - `ast-shape` — tree-sitter query against the file's parsed AST.
 *   Stronger than regex but costs a tree-sitter dependency. Marked as
 *   not-yet-implemented in the OSS verifier; treated as "skipped" when
 *   evaluated, which is conservative (an unimplemented predicate cannot
 *   prove the finding is fixed).
 * - `git-diff-applies` — an evidence diff generated at `baseCommit` still
 *   applies cleanly to the repository HEAD. This proves source compatibility
 *   of the artifact, not runtime exploitability.
 */
export type VerificationCodePredicate =
  | { kind: "file-contains"; file: string; pattern: string; flags?: string }
  | { kind: "file-missing-pattern"; file: string; pattern: string; flags?: string }
  | { kind: "file-exists"; file: string }
  | { kind: "ast-shape"; file: string; query: string }
  | { kind: "git-diff-applies"; baseCommit: string; diff: string };

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
 * verifier in 0sec#193 — code predicates only. The shape is recorded
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
   * vulnerable. `git-diff-applies` is an artifact-compatibility receipt, not
   * a vulnerability signal, so it must accompany at least one other code or
   * behavioural predicate before a verifier can report a positive verdict.
   * Empty array is permitted (means "no code-level signal"; verifier returns
   * inconclusive when there is also no `behavior`).
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
  | "soft-lockup"        // watchdog: BUG: soft lockup - CPU#N stuck
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
  /**
   * Faulting program counter as `symbol+0xoffset/0xsize` (e.g.
   * `snd_rawmidi_kernel_write1+0x1ba/0x210`), parsed from the `in <sym>` token
   * on the `BUG: KASAN:` line. Optional and additive — undefined when the
   * splat has no such token. Distinct from `faultingFunction` (symbol only).
   */
  faultingPc?: string;
  /**
   * Slab cache the faulting object lives in (e.g. `kmalloc-192`), parsed from
   * the KASAN `cache kmalloc-NNN` / `Allocated by task … kmalloc-NNN` token.
   * Optional and additive — drives spray-bucket matching in later phases.
   */
  slabCache?: string;
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
 * (`0SEC_COST_CEILING_USD` / `--cost-ceiling`) was hit and the scan
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
    craftSubmits?: number;
    craftPassed?: boolean;
    craftFirstSubmitPassed?: boolean;
  };
  /**
   * Reason the scan terminated. Undefined for normal completion. Set to
   * "cost_ceiling_exceeded" when the scan was aborted by the cost ceiling.
   */
  exitReason?: ScanExitReason;
  /** True when the scan was aborted by the per-scan cost ceiling. */
  costCeilingExceeded?: boolean;
  /**
   * False only when an analysis stage failed after the scan had already
   * produced a partial report. Consumers must not render that as a clean run.
   */
  executionSuccessful?: boolean;
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
  /**
   * Engagement-posture audit record. Present ONLY when an engagement hardening
   * profile was actually applied (`--engagement-profile conservative` or an
   * equivalent env / scope-file setting); undefined for default scans, so
   * ordinary reports are byte-for-byte unchanged. It states which loud
   * behaviours were suppressed and which configuration source decided each
   * one — the evidence handed to a client alongside the findings.
   */
  engagementPosture?: EngagementPostureRecord;
}

/**
 * Auditable record of the engagement hardening posture a scan ran under.
 * Built by `describeEngagementPosture` in `@0sec/core`
 * (`scope/engagement-profile.ts`). snake_case keys match the
 * `enforcement_summary` contract; the values are the posture as APPLIED, not
 * as requested.
 */
export interface EngagementPostureRecord {
  /** Resolved profile name (`standard` / `conservative`). */
  profile: string;
  /** ISO timestamp the posture was rendered. */
  applied_at: string;
  /** Whether the bounded password-reset burst probe was allowed to fire. */
  reset_endpoint_burst_probe: "enabled" | "disabled";
  /** How the deterministic web-recon pre-pass issued HTTP. */
  web_recon_prepass: "direct-fetch" | "rate-limited";
  /** Whether a blocked response escalated into the adaptive evasion ladder. */
  waf_evasion_ladder: "enabled" | "disabled";
  /** Token-bucket pacing shape. */
  request_jitter: "full-jitter" | "none";
  /** Upper bound of the per-request random delay, ms (0 when no jitter). */
  jitter_base_ms: number;
  /** Default per-host requests-per-second applied to the token buckets. */
  per_host_rps: number;
  /** Which configuration source decided each field (scope-file / env / cli / default). */
  sources: Record<string, string>;
}

/**
 * Frozen `enforcement_summary` block emitted in http_audit reports. Mirrors
 * `EnforcementSummary` in `@0sec/core` (scope/enforcement.ts); duplicated
 * here (rather than imported) so `@0sec/shared` stays dependency-free of
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

// ── Package Audit (0sec audit) ──

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
  /** Bounded operator hypothesis appended to audit prompts for controlled A/B research. */
  hypothesis?: string;
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

/**
 * Provenance of the exact package source an audit ran against — registry,
 * tarball, and integrity of the artifact installed. Captured so a benchmark
 * result is reproducible (you can re-fetch the identical bytes that were
 * audited). Optional: not every install path captures it yet.
 */
export interface SourceProvenance {
  /** Registry the package source was fetched from (e.g. https://registry.npmjs.org). */
  registry: string;
  /** Tarball URL of the exact artifact installed + audited. */
  tarballUrl: string;
  /** Subresource integrity of the tarball (e.g. `sha512-…`). */
  integrity: string;
  /** True once the downloaded tarball's hash was checked against `integrity`. */
  integrityVerified?: boolean;
  /** The version spec originally requested (e.g. `sequelize@6.37.8`). */
  requestedSpec: string;
  /** How the resolved version was pinned (e.g. `npm-package-lock`, `pypi-json`). */
  resolvedFrom: string;
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
  /**
   * Provenance of the audited package source. Undefined when the install path
   * didn't capture it; consumers must handle absence.
   */
  sourceProvenance?: SourceProvenance;
}

// ── Source Code Review (0sec review) ──

/**
 * Review profile selects the prompt + harness strategy.
 *
 * - `default`: application-layer review (web, JS/TS/Python/Go business logic).
 * - `c-library`: foundational C/C++ libraries — memory safety, integer
 *   bugs, allocation paths. Pairs with the tier-1/2/3 harness scaffolder.
 * - `linux-kernel`: Linux kernel source review — syscall/ioctl/netlink
 *   surface, copy_from_user discipline, refcount races, skb cow/share
 *   violations (Dirty Frag class), TOCTOU on inode fields. Static-only;
 *   verification phase is 0sec#271 (kernel oracle) and 0sec#272
 *   (syzkaller harness scaffold).
 * - `cardano-onchain`: Cardano on-chain smart-contract review (Aiken /
 *   Plutus / Plutarch). EUTXO validator *logic* bugs — double satisfaction,
 *   missing signer checks, unconserved value, unauthorized mint, datum
 *   trust, staking/withdrawal tricks. No memory-safety surface; verification
 *   is a transaction the validator wrongly admits.
 * - `solana-onchain`: Solana on-chain program review (Anchor / native Rust).
 *   Account-model *authorization* bugs — missing signer/owner checks, account
 *   substitution / type confusion, missing PDA seed+bump validation, arbitrary
 *   CPI / unchecked program id, missing Anchor `has_one`/constraint binding,
 *   integer overflow/rounding in AMM/lending math, missing rent/close-account
 *   checks, duplicate-mutable-account, unvalidated `remaining_accounts`. No
 *   memory-safety surface (Rust + BPF VM); verification is an instruction the
 *   program wrongly processes against a substituted account.
 * - `evm-onchain`: EVM on-chain smart-contract review (Solidity / Foundry /
 *   Hardhat) — "0contract". DeFi/bridge *value-logic* bugs — reentrancy
 *   (classic/cross-function/read-only/cross-contract), access-control /
 *   missing-auth / init front-run, oracle & price manipulation (spot vs
 *   manipulable TWAP, stale feeds), rounding / first-depositor share inflation,
 *   signature / permit / EIP-712 replay, cross-chain message verification &
 *   replay (source-chain/nonce/domain binding), delegatecall / proxy storage
 *   collision, unchecked external-call return, MEV/sandwich, unbounded-loop DoS.
 *   No memory-safety surface (EVM VM); verification is a Foundry test that
 *   drains or corrupts. Distinct from cardano-onchain (EUTXO) and solana-onchain
 *   (account model).
 * - `cairo-onchain`: Cairo / Starknet on-chain smart-contract review (Cairo 1+,
 *   Scarb, starknet-foundry). Starknet DeFi *value-logic* bugs — caller /
 *   ownership auth gaps (missing `assert(get_caller_address() == owner)`),
 *   fixed-point share-conversion rounding (the zkLend / Vesu class), reentrancy
 *   via `call_contract`, storage / mapping default-value trust, unchecked
 *   external-call results, L1↔L2 message & `l1_handler` access control, oracle
 *   staleness. No memory-safety surface (STARK-proven VM); `felt252` wraps mod p
 *   but `u256`/`u128` overflow-panic, and failure is `assert`/`panic` (a revert)
 *   so classic "unchecked return" idioms mostly do NOT apply. Verification is a
 *   starknet-foundry (`snforge`) test that drains/corrupts. Distinct from
 *   evm-onchain (Solidity/message-call), cardano-onchain (EUTXO), and
 *   solana-onchain (account model).
 * - `move-onchain`: Move on-chain smart-contract review (Sui Move / Aptos Move).
 *   Move resource / capability *value-logic* bugs — object / capability
 *   ownership & instance-binding gaps (the Cetus / Scallop unconstrained-object
 *   class), arithmetic overflow / truncation in shared math libs (the Cetus
 *   `integer_mate` `checked_shlw` $223M class), uninitialized / reward-index
 *   accounting (the Scallop `last_index` class), public-transfer / capability
 *   leakage, shared-object consensus races, `init` / one-time-witness misuse,
 *   coin / balance conservation. No memory-safety surface (linear-resource VM);
 *   native `+ - *` abort on overflow (so the real class is bit-shifts / casts /
 *   unsound hand-rolled `checked_*` helpers), and failure is `abort` (a revert).
 *   Verification is a `sui move test` / `aptos move test` unit test that
 *   drains/corrupts. Distinct from the account/EUTXO/message-call profiles.
 * - `cardano-haskell`: Cardano FIRST-PARTY Haskell node-stack review
 *   (cardano-ledger, plutus / the Plutus script evaluator, ouroboros-network,
 *   cardano-wallet, cardano-cli/cardano-api, cardano-base, plutus-apps).
 *   Off-chain INFRASTRUCTURE bugs — partial functions / decoder panics on
 *   untrusted input (DoS), FFI memory-safety across `foreign import`/`Ptr`
 *   (the cardano-base `encryptedDerivePublic` OOB class), `unsafePerformIO`/
 *   `unsafeCoerce` misuse, lazy-eval space leaks, integer/`Natural` underflow
 *   & div-by-zero, Plutus-VM budget/eval flaws, ledger STS rule gaps, and
 *   MVar/STM deadlock/race. Distinct from `cardano-onchain` (validator logic
 *   on a memory-safe VM). Semgrep is Haskell-blind, so this profile is
 *   LLM-review-driven (source reading, not scanner triage).
 * - `xnu-kernel`: Apple XNU (macOS/iOS) kernel source review — Mach
 *   trap + MIG surface, IOKit user-client externalMethod dispatch,
 *   BSD syscall/copyin discipline, Mach port refcount + OOL descriptor
 *   bugs, Mach VM aliasing. Static-only hypotheses; verification on
 *   Apple hardware (KASAN research kernel) is decoupled, not in-loop.
 * - `xnu-re`: review of DECOMPILED Apple kext pseudo-C (closed kexts from
 *   a kernelcache, where the real LPE surface lives). Input is type-less
 *   r2ghidra output (see scripts/xnu-re-extract.sh); the profile is tuned
 *   to read offset-soup + recover IOKit ABI fields, and gates findings
 *   behind binary re-verification.
 */
export type ReviewProfile = "default" | "c-library" | "linux-kernel" | "cardano-onchain" | "solana-onchain" | "evm-onchain" | "cairo-onchain" | "move-onchain" | "cardano-haskell" | "xnu-kernel" | "xnu-re";

/**
 * A known bug to anchor a review on for variant analysis. Project Zero's
 * Naptime / Big Sleep framing: anchoring the agent on ONE concrete, confirmed
 * bug and asking "where else does this exact pattern occur?" is dramatically
 * more precise than open-ended "find bugs" discovery. The anchor can be sourced
 * from a recent CVE, a fix-commit-intel record, or any known vulnerability
 * pattern. Only `pattern` is required; the other fields sharpen the search.
 */
export interface ReviewAnchor {
  /** The structural root cause to hunt variants of, e.g. "missing skb_cow_data before in-place AEAD decrypt". */
  pattern: string;
  /** CVE id or advisory identifier, if known, e.g. "CVE-2026-31431". */
  id?: string;
  /** Where the original bug lives, e.g. "net/ipv4/esp4.c:123" or "ESP/IPsec input path". */
  origin?: string;
  /** The fix marker that closed the original — its absence elsewhere is the variant signal. */
  fix?: string;
}

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
  /** PR/MR discussion thread (untrusted) to review against. */
  conversation?: string;
  /**
   * Known bug(s) to anchor the review on for variant analysis. When provided,
   * the linux-kernel review reframes from open-ended discovery to hunting
   * structural VARIANTS of these exact patterns across the tree (Project Zero
   * Naptime / Big Sleep framing — the precision unlock). Sourced from a recent
   * CVE, a fix-commit-intel record, or any known vulnerability pattern. Empty
   * or omitted = unchanged open-ended review. Only meaningful for the
   * `"linux-kernel"` profile.
   */
  anchors?: ReviewAnchor[];
  /**
   * External candidate vulnerable spans to seed the agent's worklist before
   * static scanner prioritisation runs. Today the only first-class producer is
   * GemmaForge (`gemmaforge scan`, schema `gemmaforge.leads/v1`). The parser
   * lives in `@0sec/core` (`seed-findings.ts`); it normalises any compliant
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

/**
 * Which cross-validating hunt produced a foxguard lead. The two lead sources on
 * the linux-kernel review path are the foxguard SARIF variant-hunt
 * (`runKernelVariantHunt` → `kernel-variant-*`) and the incomplete-fix sibling
 * hunt (`huntIncompleteFixSiblings` → `incfix:*`); `unknown` is the fail-soft
 * fallback when neither marker is present.
 */
export type CrossValidatedLeadSource =
  | "foxguard-variant-hunt"
  | "incomplete-fix"
  | "unknown";

/**
 * One ranked/deduped cross-validated foxguard lead, exposed as structured data.
 * Mirrors the fields the review prompt's "investigate FIRST" block renders as
 * text, so downstream consumers (console / TUI / cloud) can read the leads
 * directly instead of parsing them back out of the prompt string.
 */
export interface CrossValidatedLead {
  title: string;
  severity: Severity;
  /** Producer-assessed confidence in [0,1]; absent when the hunt set none. */
  confidence?: number;
  /** Stable dedupe key when the producing hunt set one (`kernel-variant-*` / `incfix:*`). */
  fingerprint?: string;
  /** Which hunt produced the lead. */
  source: CrossValidatedLeadSource;
}

/**
 * Structured view of the ranked/deduped foxguard leads that also feed the review
 * prompt (0sec FoxGuard cross-validation, Phase 2). Additive: the prompt
 * injection is unchanged; this surfaces the SAME leads as typed data. Populated
 * (possibly empty) on the linux-kernel review path; empty for other profiles.
 */
export interface CrossValidatedLeads {
  /** Ranked (severity → confidence) + deduped leads, highest-priority first. */
  leads: CrossValidatedLead[];
  /** Total ranked/deduped lead count (may exceed what the prompt slice shows). */
  total: number;
}

export interface ReviewReport {
  repo: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  semgrepFindings: number;
  summary: ReportSummary;
  findings: Finding[];
  /** Non-fatal stage failures retained alongside any partial findings. */
  warnings?: Array<{ stage: string; message: string }>;
  /** True when the primary review agent failed; partial static results may remain. */
  researchFailed?: boolean;
  /**
   * Ranked/deduped cross-validated foxguard leads surfaced as structured data,
   * in ADDITION to the review-prompt injection (0sec FoxGuard cross-validation,
   * Phase 2). Present (possibly empty) on the linux-kernel review path so
   * downstream consumers can read the leads instead of parsing prompt text.
   */
  crossValidatedLeads?: CrossValidatedLeads;
  /** LLM token usage (input + output). Undefined when no LLM agent ran. */
  usage?: TokenUsage;
  /** Estimated USD cost from token usage at the configured model rates. */
  estimatedCostUsd?: number;
}
