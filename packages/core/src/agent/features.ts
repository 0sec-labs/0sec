/**
 * Feature flags for A/B testing agent improvements.
 * Set via environment variables: PWNKIT_FEATURE_<NAME>=0 to disable.
 *
 * NOTE on defaults:
 *   - "stable" features (early stop, loop detection, context compaction,
 *     script templates, progress handoff) default ON.
 *   - "experimental" features (playbooks, memory, web search) default OFF.
 *   - "v0.6.0 FP moat layers" (povGate, reachabilityGate, multiModal,
 *     adversarialDebate, triageMemories, egatsTreeSearch,
 *     selfConsistencyVerify) ALSO default OFF — they need explicit enablement
 *     in CI before any FP-moat A/B claim can be made.
 *   - "always-on triage filters" (`holdingItWrong`, `evidenceGate`) default
 *     ON — they're the only filters that ran in every v0.6.0 ablation, so
 *     they need to be ablatable.
 */
export const features = {
  /** Early-stop at 50% budget if no findings, retry with different strategy */
  earlyStopRetry: env("PWNKIT_FEATURE_EARLY_STOP", true),
  /** Detect A-A-A and A-B-A-B loop patterns, inject warning */
  loopDetection: env("PWNKIT_FEATURE_LOOP_DETECTION", true),
  /** Compress middle messages when context exceeds 30k tokens */
  contextCompaction: env("PWNKIT_FEATURE_CONTEXT_COMPACTION", true),
  /** Exploit script templates in shell prompt (blind SQLi, SSTI, auth chain) */
  scriptTemplates: env("PWNKIT_FEATURE_SCRIPT_TEMPLATES", true),
  /** Dynamic vulnerability playbooks injected after recon phase */
  dynamicPlaybooks: env("PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS", false),
  /** Agent writes plan/creds to disk, injected at reflection checkpoints */
  externalMemory: env("PWNKIT_FEATURE_EXTERNAL_MEMORY", false),
  /** Inject prior attempt findings when retrying (LLM-summarized progress handoff) */
  progressHandoff: env("PWNKIT_FEATURE_PROGRESS_HANDOFF", true),
  /** Allow the agent to search the web for CVE details, docs, and technique references */
  webSearch: env("PWNKIT_FEATURE_WEB_SEARCH", false),
  /** Run bash commands inside a Kali Docker container with full pentesting toolset */
  dockerExecutor: env("PWNKIT_FEATURE_DOCKER_EXECUTOR", false),
  /** Interactive PTY sessions for exploits requiring interactivity (reverse shells, DB clients, SSH) */
  ptySession: env("PWNKIT_FEATURE_PTY_SESSION", false),
  /** EGATS (Evidence-Gated Attack Tree Search) — beam-search exploration of attack hypotheses */
  egatsTreeSearch: env("PWNKIT_FEATURE_EGATS", false),
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
   * PWNKIT_FEATURE_SPECIALIST_ROUTING=1.
   */
  get specialistRouting(): boolean {
    return env("PWNKIT_FEATURE_SPECIALIST_ROUTING", false);
  },
  /** Self-consistency voting: run the structured verify pipeline N times and take the majority vote */
  selfConsistencyVerify: env("PWNKIT_FEATURE_CONSENSUS_VERIFY", false),
  /** Adversarial debate: prosecutor vs defender agents debate each finding, skeptical judge decides */
  adversarialDebate: env("PWNKIT_FEATURE_DEBATE", false),
  /** Multi-modal agreement: cross-validate findings against foxguard (Rust pattern scanner) */
  multiModalAgreement: env("PWNKIT_FEATURE_MULTIMODAL", false),
  /** Reachability gate: suppress findings whose sink is not reachable from an application entry point */
  reachabilityGate: env("PWNKIT_FEATURE_REACHABILITY_GATE", false),
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
   * PWNKIT_FEATURE_PUBLISHABILITY_GATE.
   */
  publishabilityGate: env("PWNKIT_FEATURE_PUBLISHABILITY_GATE", false),
  /** PoV gate: require a working, executable PoC per finding or downgrade to info */
  povGate: env("PWNKIT_FEATURE_POV_GATE", false),
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
   * PWNKIT_FEATURE_INLINE_VALIDATION=1.
   */
  get inlineValidation(): boolean {
    return env("PWNKIT_FEATURE_INLINE_VALIDATION", false);
  },
  /** Semgrep-style per-target persistent FP memories injected into the verify pipeline */
  triageMemories: env("PWNKIT_FEATURE_TRIAGE_MEMORIES", false),
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
    return env("PWNKIT_FEATURE_WP_FINGERPRINT", true);
  },

  /**
   * MongoDB ObjectID forge tool. Exposes the `mongo_objectid` tool to the
   * attack agent so it can compute valid 24-char hex ObjectIds with arbitrary
   * timestamps + counters (e.g. forge the "first user" ObjectId in an IDOR
   * challenge by setting timestamp = appStartTimestamp and counter = 0).
   *
   * Default ON — this is a pure-computation utility with no network or
   * filesystem side effects, so there's no reason to gate it off. Disable
   * via PWNKIT_FEATURE_MONGO_OBJECTID_FORGE=0 or `--no-mongo-objectid-forge`
   * for ablation. Implemented as a getter so the CLI `--features` flag
   * (which sets the env var inside the command action, AFTER this module
   * has been imported) is still honored at tool-dispatch time. Matches
   * the wpFingerprint pattern above. See packages/core/src/agent/objectid-forge.ts.
   */
  get mongoObjectIdForge(): boolean {
    return env("PWNKIT_FEATURE_MONGO_OBJECTID_FORGE", true);
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
   * off via `PWNKIT_FEATURE_DECOY_DETECTION=0` or the CLI flag
   * `--no-decoy-detection` for ablation/testing.
   *
   * Implemented as a getter so the CLI flag (which flips the env var
   * inside the command action, AFTER this module has been imported) is
   * still honored at tool-dispatch time. Matches the wpFingerprint
   * pattern above. See GitHub issue #82 and
   * packages/core/src/agent/flag-validator.ts.
   */
  get decoyDetection(): boolean {
    return env("PWNKIT_FEATURE_DECOY_DETECTION", true);
  },

  // ── Always-on triage filters (default ON, ablatable for A/B testing) ──

  /**
   * `holding-it-wrong` regex blocklist (`packages/core/src/triage/holding-it-wrong.ts`).
   * Matches finding text against documented I/O / eval / compile / persistence
   * sink names and rejects findings that look like "the function did its job".
   *
   * Default ON because that's the existing v0.6.0 behavior. Can be disabled
   * via PWNKIT_FEATURE_HOLDING_IT_WRONG=0 to test whether this filter is
   * suppressing real signal — the ceiling-analysis from 2026-04-06 identified
   * this as the strongest candidate for the unexplained XBOW finding-density
   * collapse from 14 → 4 between `features=none` and `features=all`.
   */
  holdingItWrong: env("PWNKIT_FEATURE_HOLDING_IT_WRONG", true),

  /**
   * `evidence_completeness <= 0.5` reject (`packages/core/src/agentic-scanner.ts:591`).
   * Drops findings whose extracted feature vector says the agent didn't
   * gather enough cross-source evidence (request + response + analysis + ...).
   *
   * Default ON because that's the existing v0.6.0 behavior. Can be disabled
   * via PWNKIT_FEATURE_EVIDENCE_GATE=0 for ablation.
   */
  evidenceGate: env("PWNKIT_FEATURE_EVIDENCE_GATE", true),

  /**
   * Learned per-finding triage router (`packages/core/src/triage/learned-router.ts`).
   * When enabled, findings are scored by hand-coded rules derived from the
   * XGBoost model trained on triage-dataset-v2.jsonl (1514 rows). High-confidence
   * findings auto-accept (skipping expensive layers); low-confidence findings
   * auto-reject; the middle band gets routed to a subset of layers based on
   * the scan's slice type (xbow-wb, xbow-bb, npm).
   *
   * Default OFF until the router is validated via A/B testing on xbow-bench
   * and npm-bench. See pwnkit#113 for the design doc.
   */
  learnedRouter: env("PWNKIT_FEATURE_LEARNED_ROUTER", false),

  /**
   * Dynamic per-finding triage routing (`packages/core/src/triage/router/`).
   * When enabled, every finding is sent through a `RouterModel` that
   * decides which subset of the 11 triage layers to invoke for that
   * specific finding. v0 ships an explicit-rule router encoded from the
   * pwnkit#72 per-profile ablation; a learned classifier replaces the
   * rules in a follow-up PR without touching the dispatch site.
   *
   * Distinct from `learnedRouter` above: `learnedRouter` is the XGBoost
   * TP/FP score model that decides accept/reject; `dynamicTriageRouting`
   * is the per-layer dispatch decision. Both can be on at the same time;
   * the dispatch router gates which layers run AFTER the TP/FP score
   * model has spoken.
   *
   * Default OFF — opt in via PWNKIT_FEATURE_DYNAMIC_TRIAGE=1. See
   * pwnkit#113 for the design doc and pwnkit#67 for the joint paper plan.
   */
  dynamicTriageRouting: env("PWNKIT_FEATURE_DYNAMIC_TRIAGE", false),

  /**
   * Opt-in cloud-sink webhook integration (`packages/core/src/cloud-sink.ts`).
   * When enabled AND the user has set PWNKIT_CLOUD_SINK + PWNKIT_CLOUD_SCAN_ID,
   * every finding and the final scan report are POSTed to the configured
   * remote endpoint in real time.
   *
   * Default ON so the env-var trio is sufficient to enable streaming, but the
   * flag exists so operators can force-disable the integration in environments
   * where outbound HTTP from the scanner is not desired (e.g. air-gapped CI).
   * Disable via PWNKIT_FEATURE_CLOUD_SINK=0.
   */
  cloudSink: env("PWNKIT_FEATURE_CLOUD_SINK", true),

  /**
   * Pre-recon CVE check (`packages/core/src/pre-recon-cve.ts`).
   * In white-box mode (`--repo` set), runs `npm audit` / `pip-audit`
   * against the source tree before the attack agent starts and injects
   * any high/critical advisories into the system prompt as priority
   * leads. Defends against expensive thrash on CVE-tagged challenges
   * where the agent has source access but no concrete leads.
   *
   * Default ON in white-box mode (no-op in black-box). Disable via
   * PWNKIT_FEATURE_PRE_RECON_CVE=0 for ablation.
   */
  preReconCve: env("PWNKIT_FEATURE_PRE_RECON_CVE", true),

  /**
   * Best-effort target-history preflight for source review. When a local repo
   * path is known, pwnkit infers repository/package/product hints, queries live
   * prior-vulnerability intel, and injects a compact audit-graph summary into
   * the review prompt before the agent starts.
   *
   * Default ON for white-box/source-review modes. Disable via
   * PWNKIT_FEATURE_TARGET_HISTORY_PRESEED=0 for offline or ablation runs.
   */
  get targetHistoryPreseed(): boolean {
    return env("PWNKIT_FEATURE_TARGET_HISTORY_PRESEED", true);
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
   * and pwnkit#229 for the design discussion.
   *
   * Implemented as a getter so the CLI `--features` flag — which sets
   * the env var inside the command action AFTER this module is imported
   * — is still honored at compaction time. Disable via
   * PWNKIT_FEATURE_PRESERVE_CRITICAL_MESSAGES=0 for ablation.
   */
  get preserveCriticalMessages(): boolean {
    return env("PWNKIT_FEATURE_PRESERVE_CRITICAL_MESSAGES", true);
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
   * implementation. Disable via PWNKIT_FEATURE_BUDGET_WARNINGS=0 for
   * ablation. Implemented as a getter so the CLI `--features` flag —
   * which sets the env var inside the command action AFTER this module
   * is imported — is still honored at injection time (matches the
   * wpFingerprint / preserveCriticalMessages pattern).
   */
  get budgetWarnings(): boolean {
    return env("PWNKIT_FEATURE_BUDGET_WARNINGS", true);
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
   * `PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION=0` to revert to the shared-session
   * behavior — useful for cost-bounded benchmarks.
   *
   * Implemented as a getter so the env var is honored at orchestration time
   * (matches the wpFingerprint / mongoObjectIdForge pattern).
   */
  get perItemOrchestration(): boolean {
    return env("PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION", true);
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
    return env("PWNKIT_FEATURE_JIT_SKILLS", false);
  },

  /**
   * Execution-journal shadow mode (#494, first additive slice).
   *
   * When ON, the live agent loop ALSO writes append-only journal entries
   * (`tool_call`, `tool_result`, `finding`, `done`) to
   * `~/.pwnkit/runs/<scanId>/journal.jsonl` as it runs — a durable,
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
   * Enable via PWNKIT_FEATURE_EXECUTION_JOURNAL=1 or `--features
   * execution-journal`.
   */
  get executionJournal(): boolean {
    return env("PWNKIT_FEATURE_EXECUTION_JOURNAL", false);
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
   * a journal was written for the run — it reads `~/.pwnkit/runs/<scanId>/
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
   * time. Enable via PWNKIT_FEATURE_JOURNAL_REHYDRATE=1 or `--features
   * journal-rehydrate`.
   */
  get journalRehydrate(): boolean {
    return env("PWNKIT_FEATURE_JOURNAL_REHYDRATE", false);
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
   * Disable via PWNKIT_FEATURE_LOOT_LEDGER=0 or `--no-loot-ledger` for
   * ablation. Implemented as a getter so the CLI `--features` flag (which sets
   * the env var inside the command action, AFTER this module has been
   * imported) is honored at tool-dispatch / injection time — matches the
   * wpFingerprint / preserveCriticalMessages pattern.
   */
  get lootLedger(): boolean {
    return env("PWNKIT_FEATURE_LOOT_LEDGER", true);
  },
};

function env(key: string, defaultValue: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return defaultValue;
  return val !== "0" && val !== "false";
}
