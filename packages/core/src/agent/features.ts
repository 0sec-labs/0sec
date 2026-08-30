/**
 * Feature flags for A/B testing agent improvements.
 * Set via environment variables: 0SEC_FEATURE_<NAME>=0 to disable.
 *
 * NOTE on defaults:
 *   - "stable" features (early stop, loop detection, context compaction,
 *     script templates, progress handoff) default ON.
 *   - "experimental" features (playbooks, memory, web search) default OFF.
 *   - "v0.6.0 FP moat layers" (povGate, reachabilityGate, multiModal,
 *     selfConsistencyVerify) ALSO default OFF — they need explicit enablement
 *     in CI before any FP-moat A/B claim can be made.
 *   - "always-on triage filters" (`holdingItWrong`, `evidenceGate`) default
 *     ON — they're the only filters that ran in every v0.6.0 ablation, so
 *     they need to be ablatable.
 *
 * ## Enabling the full FP moat for an A/B
 *
 * The "explicit enablement" noted above now has one documented form, so an
 * A/B run does not depend on reconstructing the flag set by reading source:
 *
 *   0SEC_FEATURE_PRESET=fp-moat 0sec scan …
 *   0sec scan --features fp-moat …
 *
 * The preset's membership lives in `agent/feature-presets.ts` and is pinned by
 * test. Applying it never overwrites a flag that is already set, so
 * `0SEC_FEATURE_POV_GATE=0` alongside the preset gives you a clean
 * single-layer ablation.
 *
 * Enabling layers is only half of a defensible claim; the other half is being
 * able to show which layers ran on a given finding. That is
 * `triage/provenance.ts` (`summarizeTriageProvenance`), which reads the
 * recorded `layerVerdicts` rather than these flags — deliberately, since a
 * finding is usually re-read under a different environment than it was
 * produced in. It also reports which layers emit no telemetry at all
 * (`structured_verify`, `consensus`, `kernel_oracle` — see
 * `UNINSTRUMENTED_LAYERS`), because a layer we cannot observe cannot be part
 * of a moat claim.
 */
import { FEATURE_PRESETS, resolveFeaturePreset } from "./feature-presets.js";

export const features = {
  /** Early-stop at 50% budget if no findings, retry with different strategy */
  get earlyStopRetry(): boolean { return env("0SEC_FEATURE_EARLY_STOP", true); },
  /** Detect A-A-A and A-B-A-B loop patterns, inject warning */
  get loopDetection(): boolean { return env("0SEC_FEATURE_LOOP_DETECTION", true); },
  /** Compress middle messages when context exceeds 30k tokens */
  get contextCompaction(): boolean { return env("0SEC_FEATURE_CONTEXT_COMPACTION", true); },
  /**
   * Re-send the opaque, model-bound Responses output item array on the next
   * turn. Default ON; set to 0 only for matched retained-reasoning A/B runs.
   */
  get retainedReasoning(): boolean { return env("0SEC_FEATURE_RETAINED_REASONING", true); },
  /** Exploit script templates in shell prompt (blind SQLi, SSTI, auth chain) */
  get scriptTemplates(): boolean { return env("0SEC_FEATURE_SCRIPT_TEMPLATES", true); },
  /** Dynamic vulnerability playbooks injected after recon phase */
  get dynamicPlaybooks(): boolean { return env("0SEC_FEATURE_DYNAMIC_PLAYBOOKS", false); },
  /** Just-in-time atomic DO/DON'T rules injected on a matching tool action */
  get ruleInjection(): boolean { return env("0SEC_FEATURE_RULE_INJECTION", false); },
  /** Agent writes plan/creds to disk, injected at reflection checkpoints */
  get externalMemory(): boolean { return env("0SEC_FEATURE_EXTERNAL_MEMORY", false); },
  /** Inject prior attempt findings when retrying (LLM-summarized progress handoff) */
  get progressHandoff(): boolean { return env("0SEC_FEATURE_PROGRESS_HANDOFF", true); },
  /** Allow the agent to search the web for CVE details, docs, and technique references */
  get webSearch(): boolean { return env("0SEC_FEATURE_WEB_SEARCH", false); },
  /** Interactive PTY sessions for exploits requiring interactivity (reverse shells, DB clients, SSH) */
  get ptySession(): boolean { return env("0SEC_FEATURE_PTY_SESSION", false); },
  /**
   * Persistent, COMPUTE-ONLY Python REPL (`python_exec`, Phase-0). A framed
   * python3 kernel keeps state across calls for payload/parse/crypto/encode
   * work; networking is blocked at the socket source whenever an engagement is
   * active. Default OFF — opt in via 0SEC_FEATURE_PYTHON_EXEC=1. Getter so
   * the CLI `--features` flag (set after this module is imported) is honored at
   * tool-dispatch time.
   */
  get pythonExec(): boolean { return env("0SEC_FEATURE_PYTHON_EXEC", false); },
  /**
   * Expose the path-confined `analyze_binary` bridge to 0verse. Default OFF:
   * a model may request a long-running binary analysis only after an operator
   * opts in with 0SEC_FEATURE_ZEROVERSE=1.
   */
  get zeroverse(): boolean { return env("0SEC_FEATURE_ZEROVERSE", false); },
  /**
   * EGATS specialist routing (#557, HPTSA-inspired). When ON, an EGATS branch
   * whose hypothesis names a concrete vuln class (SQLi/XSS/SSRF/SSTI/IDOR/
   * auth-bypass) runs as a per-class SPECIALIST: a class system prompt built
   * from the technique sections in prompts.ts, the matching methodology skill
   * auto-loaded into context, and a class-tuned tool subset. Hypotheses that
   * are ambiguous (zero or multiple classes) fall back to the generic branch
   * agent — beam search / scoring are untouched. Emits an `egats_specialist`
   * event per routed node.
   *
   * Default OFF: this changes how branch mini-loops are configured, so it must
   * be explicitly opted into before any A/B / multiplier claim on the
   * benchmark harness. Implemented as a getter so the CLI `--features` flag
   * (which sets the env var inside the command action, AFTER this module has
   * been imported) is honored at routing time. Enable via
   * 0SEC_FEATURE_SPECIALIST_ROUTING=1.
   */
  get specialistRouting(): boolean {
    return env("0SEC_FEATURE_SPECIALIST_ROUTING", false);
  },
  /** Self-consistency voting: run the structured verify pipeline N times and take the majority vote */
  get selfConsistencyVerify(): boolean { return env("0SEC_FEATURE_CONSENSUS_VERIFY", false); },
  /** Multi-modal agreement: cross-validate findings against foxguard (Rust pattern scanner) */
  get multiModalAgreement(): boolean { return env("0SEC_FEATURE_MULTIMODAL", false); },
  /** Reachability gate: suppress findings whose sink is not reachable from an application entry point */
  get reachabilityGate(): boolean { return env("0SEC_FEATURE_REACHABILITY_GATE", false); },
  /**
   * Publishability / in-scope gate (issue #537 / #539). Decides
   * disclosure-worthiness per finding: SECURITY.md threat-model exclusion
   * (by_design), global advisory dedup (duplicate) with the fix-bypass
   * exception, latest-version (fixed), and public-API reachability
   * (unreachable). Never auto-drops high-severity/high-impact findings — those
   * are routed to needs_verify + human review via canAutoSuppress.
   *
   * Default OFF: this gate can suppress reproducible findings, so it must be
   * explicitly opted into before any A/B claim. Disable/enable via
   * 0SEC_FEATURE_PUBLISHABILITY_GATE.
   */
  get publishabilityGate(): boolean { return env("0SEC_FEATURE_PUBLISHABILITY_GATE", false); },
  /** PoV gate: require a working, executable PoC per finding or downgrade to info */
  get povGate(): boolean { return env("0SEC_FEATURE_POV_GATE", false); },
  /**
   * Intra-scan semantic dedupe post-pass (anchored incremental LLM
   * clustering over the final finding set, `triage/semantic-dedupe.ts`).
   * Marks duplicates with a canonical mapping + cluster reason instead of
   * dropping them. Default OFF: it spends an LLM call per ≤50-finding batch
   * after the scan, so it must be explicitly opted into before any A/B
   * claim. Toggle via 0SEC_FEATURE_SEMANTIC_DEDUPE.
   */
  get semanticDedupe(): boolean { return env("0SEC_FEATURE_SEMANTIC_DEDUPE", false); },
  /**
   * Finding-specific remediation written by the model
   * (`generateRemediationWithLLM`) instead of the static category knowledge
   * base. Default OFF: it spends one extra LLM call per non-false-positive
   * finding at report-assembly time, which is real money on a noisy scan and
   * buys nothing on a scan with no findings.
   *
   * Worth turning on for disclosure-bound work: the static KB emits the same
   * generic snippet for every finding in a category, whereas the model sees
   * this finding's evidence and can name the actual sink. The call is
   * fail-open — any error falls back to the KB answer — so enabling it can
   * degrade cost, never correctness.
   */
  get llmRemediation(): boolean { return env("0SEC_FEATURE_LLM_REMEDIATION", false); },
  /**
   * Per-finding impact assessment (`assessImpact`, `triage/impact-assessment.ts`)
   * written by the model: reachability tier, weaponizability, blast radius,
   * business-impact tier. Default OFF — one extra LLM call per non-false-positive
   * finding at report time.
   *
   * When on, the assessment feeds three things it is otherwise absent from:
   * a real CVSS exploitability vector (AV/PR/UI from the reachability tier
   * rather than the AV:N/severity-floor guess), the advisory's Impact +
   * attack-prerequisites section, and the vendor-notification impact line. When
   * off, all three fall back to today's category/severity heuristics — so this
   * flag strictly adds fidelity, never changes the no-assessment output.
   */
  get impactAssessment(): boolean { return env("0SEC_FEATURE_IMPACT_ASSESSMENT", false); },
  /**
   * Incremental finding ranking post-pass (decimal-insertion between ranked
   * anchors, `triage/incremental-rank.ts`). Orders the report by comparative
   * promise (exploitability × impact × evidence strength). Default OFF: it
   * spends an LLM call per ≤50-finding batch; opt in before any A/B claim.
   * Toggle via 0SEC_FEATURE_INCREMENTAL_RANK.
   */
  get incrementalRank(): boolean { return env("0SEC_FEATURE_INCREMENTAL_RANK", false); },
  /**
   * Static-finding PoC generation (#666 / EPIC #674 Part A). For findings that
   * ship with NO executable PoC (`pocSteps` empty — the static / code-analysis
   * path), run an agentic PoC-gen pass that builds + runs a minimal PoC in the
   * scan substrate (reuses the PoV mini-loop). On reproduce it synthesizes a
   * runnable `pocSteps` graph so the verify runner stops skipping the finding;
   * on no-repro it flags the finding `poc:none` for manual / inconclusive
   * review instead of silently dropping it. Root cause: 112 high/crit findings
   * with `poc_steps IS NULL` were silently `skipped` by the verify fan-out.
   *
   * Default OFF: it spends LLM + execution budget per static finding and must
   * be explicitly opted into before any A/B claim (A/B-able via the #656
   * harness). Toggle via 0SEC_FEATURE_POC_GEN_STATIC.
   */
  get pocGenStatic(): boolean { return env("0SEC_FEATURE_POC_GEN_STATIC", false); },
  /**
   * Inline validation / validate-on-save (#554). When ON, the native attack
   * loop runs a fast deterministic category oracle the moment a high/critical
   * finding is saved (`onFindingSaved` hook → `verifyOracleByCategory`, the
   * cheap end of the #553 PoV-gate→oracle delegation). The verdict is injected
   * back into the loop as a context note (confirmed → stop piling on;
   * unconfirmed → "do not assume success"), stamped on `finding.inlineValidation`
   * so EGATS `scoreEvidence` lets a confirmed finding dominate the regex signals
   * and the batch oracle/PoV gate can skip the redundant re-run. Inline errors
   * are inconclusive, never false-positive. Emits `inline_validation` events.
   *
   * Default OFF: it adds a per-finding network probe inside the attack loop and
   * changes EGATS scoring, so it must be explicitly opted into before any A/B /
   * cost_per_flag claim. Implemented as a getter so the CLI `--features` flag
   * (which sets the env var inside the command action, AFTER this module is
   * imported) is honored at loop time. Enable via
   * 0SEC_FEATURE_INLINE_VALIDATION=1.
   */
  get inlineValidation(): boolean {
    return env("0SEC_FEATURE_INLINE_VALIDATION", false);
  },
  /**
   * WordPress plugin/theme fingerprinter + OSV CVE lookup.
   * Exposes the `wp_fingerprint` tool to the attack agent. Off by default —
   * can be disabled via `--features no-wp_fingerprint` / env if needed.
   * WordPress detection is cheap and the resulting plugin/CVE hints are
   * broadly useful on real web targets, so the default is ON. See
   * packages/core/src/agent/wp-fingerprint.ts for the implementation.
   *
   * Implemented as a getter so the CLI `--features` flag — which sets the env
   * var inside the command action, AFTER this module has been imported — is
   * still honored at tool-dispatch time.
   */
  get wpFingerprint(): boolean {
    return env("0SEC_FEATURE_WP_FINGERPRINT", true);
  },

  /**
   * MongoDB ObjectID forge tool. Exposes the `mongo_objectid` tool to the
   * attack agent so it can compute valid 24-char hex ObjectIds with arbitrary
   * timestamps + counters (e.g. forge the "first user" ObjectId in an IDOR
   * challenge by setting timestamp = appStartTimestamp and counter = 0).
   *
   * Default ON — this is a pure-computation utility with no network or
   * filesystem side effects, so there's no reason to gate it off. Disable
   * via 0SEC_FEATURE_MONGO_OBJECTID_FORGE=0 or `--no-mongo-objectid-forge`
   * for ablation. Implemented as a getter so the CLI `--features` flag
   * (which sets the env var inside the command action, AFTER this module
   * has been imported) is still honored at tool-dispatch time. Matches
   * the wpFingerprint pattern above. See packages/core/src/agent/objectid-forge.ts.
   */
  get mongoObjectIdForge(): boolean {
    return env("0SEC_FEATURE_MONGO_OBJECTID_FORGE", true);
  },

  /**
   * Live cloud-surface testing (0sec#925). Exposes `cloud_s3_probe` and
   * `cloud_validate_credentials` to the attack agent so it can test S3 buckets
   * for public access + orphaned-bucket takeover and safely validate harvested
   * AWS credentials (read-only). All probes are anonymous or read/verify-only —
   * no writes, no data exfiltration beyond minimal proof.
   *
   * Default OFF (opt-in via 0SEC_FEATURE_CLOUD_SURFACE=1). Probing a target
   * org's bucket-name space or validating its harvested credentials is recon
   * AGAINST THAT ORG, so it is deny-by-default at two layers: this enablement
   * flag, AND an engagement-scope check in the tool handlers (a configured
   * ScopePolicy that authorizes the bucket endpoint — see cloud-surface.ts
   * `bucketInScope`). The read-only action allowlist (`assertReadOnlyAction`)
   * stays on top of both. Getter so the CLI `--features` flag (set AFTER this
   * module loads) is honored at dispatch time — matches the wpFingerprint /
   * mongoObjectIdForge pattern above. See packages/core/src/agent/cloud-surface.ts.
   */
  get cloudSurface(): boolean {
    return env("0SEC_FEATURE_CLOUD_SURFACE", false);
  },

  /**
   * #978 (ADR-060) — agent fan-out. When ON, the agent gets the `start_scan`
   * tool: it can dispatch CHILD scans (via the same POST /scans the UI uses)
   * that run independently and report up the scan tree — the recursive
   * sub-agent orchestration. Default OFF: fan-out multiplies scans/cost, so it
   * stays opt-in even though the orchestrator enforces budget + a tree-level
   * cap (max children/depth). Enable with 0SEC_FEATURE_AGENT_FANOUT=1.
   * Getter so the CLI `--features` flag is honored at dispatch time.
   */
  get agentFanout(): boolean {
    return env("0SEC_FEATURE_AGENT_FANOUT", false);
  },

  /**
   * Anti-honeypot flag-shape validator. When the agent calls the `done`
   * tool with a proposed `FLAG{...}`, the tool runs `validateFlagShape`
   * first; low-confidence ("looks like a decoy") flags are rejected once
   * with a hint to keep exploring. The agent can override by retrying the
   * same flag — the heuristic is a speed bump, not a hard wall.
   *
   * Default ON because legitimate flags pass the shape check trivially
   * and the false-positive rate on real flags should be near zero. Turn
   * off via `0SEC_FEATURE_DECOY_DETECTION=0` or the CLI flag
   * `--no-decoy-detection` for ablation/testing.
   *
   * Implemented as a getter so the CLI flag (which flips the env var
   * inside the command action, AFTER this module has been imported) is
   * still honored at tool-dispatch time. Matches the wpFingerprint
   * pattern above. See GitHub issue #82 and
   * packages/core/src/agent/flag-validator.ts.
   */
  get decoyDetection(): boolean {
    return env("0SEC_FEATURE_DECOY_DETECTION", true);
  },

  // ── Always-on triage filters (default ON, ablatable for A/B testing) ──

  /**
   * `holding-it-wrong` regex blocklist (`packages/core/src/triage/holding-it-wrong.ts`).
   * Matches finding text against documented I/O / eval / compile / persistence
   * sink names and rejects findings that look like "the function did its job".
   *
   * Default ON because that's the existing v0.6.0 behavior. Can be disabled
   * via 0SEC_FEATURE_HOLDING_IT_WRONG=0 to test whether this filter is
   * suppressing real signal — the ceiling-analysis from 2026-04-06 identified
   * this as the strongest candidate for the unexplained XBOW finding-density
   * collapse from 14 → 4 between `features=none` and `features=all`.
   */
  get holdingItWrong(): boolean { return env("0SEC_FEATURE_HOLDING_IT_WRONG", true); },

  /**
   * `evidence_completeness <= 0.5` reject (`packages/core/src/agentic-scanner.ts:591`).
   * Drops findings whose extracted feature vector says the agent didn't
   * gather enough cross-source evidence (request + response + analysis + ...).
   *
   * Default ON because that's the existing v0.6.0 behavior. Can be disabled
   * via 0SEC_FEATURE_EVIDENCE_GATE=0 for ablation.
   */
  get evidenceGate(): boolean { return env("0SEC_FEATURE_EVIDENCE_GATE", true); },

  /**
   * Learned per-finding triage router (`packages/core/src/triage/learned-router.ts`).
   * When enabled, findings are scored by hand-coded rules derived from the
   * XGBoost model trained on triage-dataset-v2.jsonl (1514 rows). High-confidence
   * findings auto-accept (skipping expensive layers); low-confidence findings
   * auto-reject; the middle band gets routed to a subset of layers based on
   * the scan's slice type (xbow-wb, xbow-bb, npm).
   *
   * Default OFF until the router is validated via A/B testing on xbow-bench
   * and npm-bench. See 0sec#113 for the design doc.
   */
  get learnedRouter(): boolean { return env("0SEC_FEATURE_LEARNED_ROUTER", false); },

  /**
   * Dynamic per-finding triage routing (`packages/core/src/triage/router/`).
   * When enabled, every finding is sent through a `RouterModel` that
   * decides which subset of the 11 triage layers to invoke for that
   * specific finding. v0 ships an explicit-rule router encoded from the
   * 0sec#72 per-profile ablation; a learned classifier replaces the
   * rules in a follow-up PR without touching the dispatch site.
   *
   * Distinct from `learnedRouter` above: `learnedRouter` is the XGBoost
   * TP/FP score model that decides accept/reject; `dynamicTriageRouting`
   * is the per-layer dispatch decision. Both can be on at the same time;
   * the dispatch router gates which layers run AFTER the TP/FP score
   * model has spoken.
   *
   * Default OFF — opt in via 0SEC_FEATURE_DYNAMIC_TRIAGE=1. See
   * 0sec#113 for the design doc and 0sec#67 for the joint paper plan.
   */
  get dynamicTriageRouting(): boolean { return env("0SEC_FEATURE_DYNAMIC_TRIAGE", false); },

  /**
   * Opt-in cloud-sink webhook integration (`packages/core/src/cloud-sink.ts`).
   * When enabled AND the user has set 0SEC_CLOUD_SINK + 0SEC_CLOUD_SCAN_ID,
   * every finding and the final scan report are POSTed to the configured
   * remote endpoint in real time.
   *
   * Default ON so the env-var trio is sufficient to enable streaming, but the
   * flag exists so operators can force-disable the integration in environments
   * where outbound HTTP from the scanner is not desired (e.g. air-gapped CI).
   * Disable via 0SEC_FEATURE_CLOUD_SINK=0.
   */
  get cloudSink(): boolean { return env("0SEC_FEATURE_CLOUD_SINK", true); },

  /**
   * Pre-recon CVE check (`packages/core/src/pre-recon-cve.ts`).
   * In white-box mode (`--repo` set), runs `npm audit` / `pip-audit`
   * against the source tree before the attack agent starts and injects
   * any high/critical advisories into the system prompt as priority
   * leads. Defends against expensive thrash on CVE-tagged challenges
   * where the agent has source access but no concrete leads.
   *
   * Default ON in white-box mode (no-op in black-box). Disable via
   * 0SEC_FEATURE_PRE_RECON_CVE=0 for ablation.
   */
  get preReconCve(): boolean { return env("0SEC_FEATURE_PRE_RECON_CVE", true); },

  /**
   * Deterministic web-recon pre-pass (`packages/core/src/stages/web-recon-prepass.ts`).
   * On web scans, runs cheap non-destructive HTTP/DNS probes before the attack
   * agent's first turn: baseline web checks, stack fingerprint → version→CVE
   * lookup, JS source-map/secret scan, DNS/email posture, passive subdomain
   * enumeration, and (Next.js only, on positive proof) framework-CVE active
   * checks. It EMITS findings directly for what it can prove and injects a
   * "pursue these leads" block into the system prompt for what it can only hint.
   *
   * Default ON (no-op in non-web modes). Gated behind 0SEC_FEATURE_WEB_RECON
   * so it can be disabled for ablation or offline runs. Implemented as a getter
   * so the CLI `--features` flag (which sets the env var inside the command
   * action, AFTER this module has been imported) is honored at stage time.
   */
  get webRecon(): boolean {
    return env("0SEC_FEATURE_WEB_RECON", true);
  },

  /**
   * Best-effort target-history preflight for source review. When a local repo
   * path is known, 0sec infers repository/package/product hints, queries live
   * prior-vulnerability intel, and injects a compact audit-graph summary into
   * the review prompt before the agent starts.
   *
   * Default ON for white-box/source-review modes. Disable via
   * 0SEC_FEATURE_TARGET_HISTORY_PRESEED=0 for offline or ablation runs.
   */
  get targetHistoryPreseed(): boolean {
    return env("0SEC_FEATURE_TARGET_HISTORY_PRESEED", true);
  },

  /**
   * Preserve credential / exploit-bearing messages verbatim during
   * `compactMessagesWithLLM` (`packages/core/src/agent/native-loop.ts`).
   * When the conversation is compacted, middle messages whose serialized
   * text matches the critical-message regex (passwords, credentials,
   * shells, exploits, login/auth tokens, etc.) are appended verbatim
   * after the LLM summary block, instead of being replaced by a paraphrase.
   *
   * Default ON: the win on long-tail challenges where a credential is
   * recovered in turn 12 and needed in turn 38 is large, and the cost
   * (a handful of extra messages preserved verbatim in the user
   * compaction-summary block) is small. BoxPwnr-inspired: see
   * `src/boxpwnr/solvers/single_loop_compactation.py` in 0ca/BoxPwnr,
   * and 0sec#229 for the design discussion.
   *
   * Implemented as a getter so the CLI `--features` flag — which sets
   * the env var inside the command action AFTER this module is imported
   * — is still honored at compaction time. Disable via
   * 0SEC_FEATURE_PRESERVE_CRITICAL_MESSAGES=0 for ablation.
   */
  get preserveCriticalMessages(): boolean {
    return env("0SEC_FEATURE_PRESERVE_CRITICAL_MESSAGES", true);
  },

  /**
   * Two-stage budget-warning injection in the agent loop (#408).
   *
   * Strix's `base_agent.py:186-211` injects a soft warning at 85% of the
   * turn budget and a sharper warning at `maxTurns − 3` so the model gets
   * a clean signal to call `done` (or `save_finding`+`done`) instead of
   * being cut off mid-thought when the hard turn limit triggers. Each
   * warning fires AT MOST ONCE per run; the small turn-state field
   * `budgetWarningsFired` lives on the loop's local closure.
   *
   * Default ON per the issue acceptance criteria — the warnings are a
   * single short user-message injection at two specific turn boundaries,
   * and the win on long benchmarks (clean handoff instead of stray
   * exploration on the last turn) is well-documented in Strix's
   * implementation. Disable via 0SEC_FEATURE_BUDGET_WARNINGS=0 for
   * ablation. Implemented as a getter so the CLI `--features` flag —
   * which sets the env var inside the command action AFTER this module
   * is imported — is still honored at injection time (matches the
   * wpFingerprint / preserveCriticalMessages pattern).
   */
  get budgetWarnings(): boolean {
    return env("0SEC_FEATURE_BUDGET_WARNINGS", true);
  },

  /**
   * Per-file orchestration for the research and audit stages (#285).
   *
   * When enabled (default), the research and audit stages call the agent
   * once per source file with a focused per-file system prompt rather than
   * one shared session that nominally walks all files but in practice
   * skips, dedupes, or condenses past the first ~30. Mirrors the
   * per-finding verify loop pattern from pov-gate.ts.
   *
   * Trade-off: total token spend grows roughly N × per-file budget instead
   * of capped at a single session's budget. For a 50-file package, that
   * could be a 5-10× cost increase on research. Disable via
   * `0SEC_FEATURE_PER_ITEM_ORCHESTRATION=0` to revert to the shared-session
   * behavior — useful for cost-bounded benchmarks.
   *
   * Implemented as a getter so the env var is honored at orchestration time
   * (matches the wpFingerprint / mongoObjectIdForge pattern).
   */
  get perItemOrchestration(): boolean {
    return env("0SEC_FEATURE_PER_ITEM_ORCHESTRATION", true);
  },

  /**
   * JIT skill loading (`packages/core/src/agent/skills/`).
   * When enabled, the agent gains `list_skills` and `load_skill` tools
   * that let it browse a registry of focused methodology guides and load
   * them into working context mid-scan. Skills replace the monolithic
   * playbook injection with targeted, on-demand knowledge (#410, #457).
   *
   * Default OFF until the skill registry is validated via A/B testing.
   * Implemented as a getter so the CLI `--features` flag — which sets
   * the env var inside the command action, AFTER this module has been
   * imported — is still honored at tool-dispatch time.
   */
  get jitSkills(): boolean {
    return env("0SEC_FEATURE_JIT_SKILLS", false);
  },

  /**
   * Execution-journal shadow mode (#494, first additive slice).
   *
   * When ON, the live agent loop ALSO writes append-only journal entries
   * (`tool_call`, `tool_result`, `finding`, `done`) to
   * `~/.0sec/runs/<scanId>/journal.jsonl` as it runs — a durable,
   * replayable trace alongside the existing in-memory conversation window.
   * This is strictly additive: the loop continues to drive off its own
   * conversation state, the journal is write-only here, and a failed
   * journal write is swallowed so it can never abort a scan. The journal is
   * NOT yet the source of truth — routing the loop off `rehydrateContext`
   * is the next slice (see docs/research/agent-execution-journal-design.md).
   *
   * Default OFF: shadow writes add a small per-turn fsync cost and the
   * format is still settling, so it must be explicitly opted into for the
   * moat-ablation harness before any A/B claim. Implemented as a getter so
   * the CLI `--features` flag (which sets the env var inside the command
   * action, AFTER this module has been imported) is honored at loop time.
   * Enable via 0SEC_FEATURE_EXECUTION_JOURNAL=1 or `--features
   * execution-journal`.
   */
  get executionJournal(): boolean {
    return env("0SEC_FEATURE_EXECUTION_JOURNAL", false);
  },

  /**
   * Execution-journal context routing (#494, slice 2).
   *
   * When ON, the native agent loop seeds its initial/resume conversation
   * context from the on-disk execution journal via
   * `rehydrateContext(loadJournal(...))` instead of (or fronting) the
   * truncated 40-message DB session blob. This is the slice that finally
   * routes the loop's context OFF the journal — the IronCurtain "every
   * agent begins with a fresh context window and rehydrates from disk"
   * primitive becomes load-bearing.
   *
   * Independent of `executionJournal` (the shadow-WRITE flag) on purpose so
   * the moat-ablation harness can toggle write and route separately for a
   * clean A/B. Rehydrate is a READER, though, so it only does anything when
   * a journal was written for the run — it reads `~/.0sec/runs/<scanId>/
   * journal.jsonl` regardless of how it got there (shadow mode this slice,
   * or specialists in a later slice). When the journal is missing, empty, or
   * corrupt the loop falls back to the existing DB-blob / fresh-prompt
   * seeding and never crashes; the fallback is logged. A FRESH run (no
   * journal yet) rehydrates to empty state, which is byte-equivalent to
   * today's initial-prompt seeding — so `journalRehydrate` only changes
   * behaviour on RESUME of an already-journaled run.
   *
   * Default OFF: this changes the loop's source of truth for resume, so it
   * must be explicitly opted into before any A/B claim. Implemented as a
   * getter so the CLI `--features` flag (which sets the env var inside the
   * command action, AFTER this module has been imported) is honored at loop
   * time. Enable via 0SEC_FEATURE_JOURNAL_REHYDRATE=1 or `--features
   * journal-rehydrate`.
   */
  get journalRehydrate(): boolean {
    return env("0SEC_FEATURE_JOURNAL_REHYDRATE", false);
  },

  /**
   * Loot / foothold ledger for opportunistic exploit chaining (#567).
   *
   * When ON, the attack/discovery/verify agents maintain a typed `LootLedger`
   * (credential | token | path | endpoint | hash | cookie) populated from
   * `save_finding` evidence AND from evidence-bearing tool results
   * (http_request / crawl / submit_form / send_prompt / browser / read_file /
   * bash). A compact "known footholds" block is re-injected into the agent's
   * context each turn (re-rendered from structured state, so it survives
   * compaction), and a `use_loot` tool lets the agent retrieve full artifact
   * values on demand to replay them in follow-up requests. This is the cheap,
   * deterministic alternative to EGATS tree-search (which is disabled) — it
   * stays inside the existing single agent loop, adds no new search layer.
   *
   * Default ON: it's purely additive (extra context awareness + one read-only
   * tool), matches the `preserveCriticalMessages` rationale — recovering a
   * credential in turn 12 that's needed in turn 38 is a large win on long-tail
   * challenges — and the cost (a short, size-capped block per turn) is small.
   * Disable via 0SEC_FEATURE_LOOT_LEDGER=0 or `--no-loot-ledger` for
   * ablation. Implemented as a getter so the CLI `--features` flag (which sets
   * the env var inside the command action, AFTER this module has been
   * imported) is honored at tool-dispatch / injection time — matches the
   * wpFingerprint / preserveCriticalMessages pattern.
   */
  get lootLedger(): boolean {
    return env("0SEC_FEATURE_LOOT_LEDGER", true);
  },

  /**
   * Typed TODO / plan ledger (`packages/core/src/agent/task-ledger.ts`).
   *
   * When ON, the agent gets a `plan` tool that maintains a typed, validated
   * task list (add / start / complete / drop / note / list), and the loop
   * re-injects a compact plan block re-rendered from that structured state —
   * so the plan survives `compactMessagesWithLLM` eating the message that
   * carried it. Prior art: Tencent Xuanwu's Atuin moved 68.7% → 84.0% on
   * CyberGym holding the model fixed, and agent-maintained TODO lists are a
   * named component of that harness design.
   *
   * Default ON, on the same reasoning as `lootLedger` above: it is additive
   * (one tool schema plus a size-capped block), it is structured state
   * re-rendered per turn rather than a new search or reasoning layer, and the
   * failure mode of an unused tool is a few hundred wasted schema tokens
   * rather than wrong behavior. Note for whoever publishes benchmark numbers
   * next: this DOES change the default tool list, so re-baseline before
   * quoting a figure across this change. Disable via 0SEC_FEATURE_AGENT_PLAN=0
   * or `--features no-agent-plan` for ablation. Getter so the CLI `--features`
   * flag (which sets the env var AFTER this module is imported) is honored at
   * tool-dispatch time.
   */
  get agentPlan(): boolean {
    return env("0SEC_FEATURE_AGENT_PLAN", false);
  },

  /**
   * Task-drift detection (`packages/core/src/agent/drift.ts`).
   *
   * When ON, the loop tracks lexical "anchor contact" between each turn's
   * activity and the objective + open plan tasks, and injects a re-anchoring
   * message when contact has been absent for several consecutive turns. It is
   * a pure function of the trajectory — no LLM call, no network, no per-turn
   * cost. Complements `loopDetection`, which catches an agent repeating itself;
   * drift is the opposite shape (novel activity every turn, none of it on-task)
   * and is invisible to the loop detector.
   *
   * Default OFF, unlike `agentPlan` above, and the asymmetry is deliberate: the
   * plan tool is a capability the model chooses to use, whereas this INJECTS
   * unsolicited steering into a running agent based on a lexical heuristic
   * whose false-positive rate has not been measured. The measurement needs
   * labelled trajectories (replay stored benchmark runs, human-mark which fires
   * were genuine derails) and that corpus does not exist yet — see the honest
   * limitations section in the module doc, particularly that a legitimate pivot
   * to a newly-discovered lead is lexically indistinguishable from a derail.
   * Repo convention is explicit that behavior-steering features stay opt-in
   * until A/B'd, and this is squarely one. Enable via
   * 0SEC_FEATURE_DRIFT_DETECTION=1 or `--features drift-detection`.
   */
  get driftDetection(): boolean {
    return env("0SEC_FEATURE_DRIFT_DETECTION", false);
  },

  /**
   * OAST out-of-band interaction collaborator + oracle (#659).
   *
   * When ON, the attack/verify agents get `oast_register` / `oast_poll` to
   * confirm blind/out-of-band classes (blind SSRF/XSS, OOB RCE/SQLi, XXE-OOB,
   * JNDI) via a hosted DNS+HTTP callback server we control, with
   * correlation-token matching. A confirmed callback is disclosure-grade
   * evidence and feeds the loot ledger.
   *
   * Default OFF — the tools are inert without a deployed collaborator. Enable
   * with 0SEC_FEATURE_OAST=1 AND point 0SEC_OAST_URL at the self-hosted
   * collaborator server (see packages/core/src/oast/server.ts). Getter (not a
   * const) so the CLI `--features` flag is honored at tool-dispatch time.
   */
  get oastCollaborator(): boolean {
    return env("0SEC_FEATURE_OAST", false);
  },

  /**
   * Anthropic prompt caching (`cache_control: {type: "ephemeral"}`) over the
   * stable request prefix — tool schemas, system prompt, and the settled part
   * of the conversation. See `runtime/prompt-cache.ts` for the placement
   * strategy and the wire contract it encodes.
   *
   * Default ON — and unlike every other flag in this file, that default is not
   * an A/B judgement call. Where a moat layer trades cost for recall, caching
   * is strictly dominant on the axes we care about: the same prompt, the same
   * tokens, the same model output, at ~0.1x input price and materially lower
   * per-turn prefill latency on every turn after the first. The engine
   * re-sends the entire transcript each turn (stateless Messages API), so the
   * saving compounds with conversation length — precisely where the pain is.
   * There is no recall or behaviour dimension to ablate here, which is why
   * this ships enabled rather than waiting on a benchmark.
   *
   * It is also gated on provider support and fails closed: only providers
   * verified to honour `cache_control` receive it, so a non-Anthropic wire can
   * never see an Anthropic-shaped field regardless of this flag (see
   * `providerSupportsPromptCache`).
   *
   * Disable via 0SEC_FEATURE_PROMPT_CACHE=0 — worth doing only to isolate a
   * suspected provider-side caching bug, or to measure the uncached baseline.
   * Implemented as a getter so a late env mutation (CLI `--features`, which
   * runs after this module is imported) is honoured at request-build time.
   */
  get promptCache(): boolean {
    return env("0SEC_FEATURE_PROMPT_CACHE", true);
  },
};

/**
 * Resolve a flag's effective default, letting `0SEC_FEATURE_PRESET` raise it.
 *
 * Consulted only when the flag's own env var is unset, so an explicit
 * `0SEC_FEATURE_POV_GATE=0` still beats `0SEC_FEATURE_PRESET=fp-moat` —
 * that precedence is what makes single-layer ablation possible (see
 * `feature-presets.ts`).
 *
 * Doing this here rather than in the CLI is deliberate: the preset then works
 * for EVERY entry point that reads these flags — the CLI, the cloud worker,
 * the benchmark runner — with no per-caller wiring to forget. A CI job can set
 * one variable and know the whole engine honours it.
 */
function presetRaisesDefault(key: string): boolean {
  const raw = process.env["0SEC_FEATURE_PRESET"];
  if (!raw) return false;
  const preset = resolveFeaturePreset(raw);
  if (!preset) return false;
  return FEATURE_PRESETS[preset].includes(key);
}

function env(key: string, defaultValue: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return defaultValue || presetRaisesDefault(key);
  return val !== "0" && val !== "false";
}
