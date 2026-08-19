---
title: Roadmap
description: Where pwnkit is going next. Opinionated, prioritised by leverage, dated by what already shipped.
---

This roadmap is opinionated. It prioritises product leverage over surface-area creep, and it stays honest about what has actually shipped vs what is still being scoped.

The current thesis is unchanged from earlier in the year:

1. Make the core agentic pipeline trustworthy.
2. Make the outputs operationally useful for real teams.
3. Then add orchestration and control-plane UX on top.

What has changed is that the trust layer is now real. The retained artifact-backed XBOW aggregate is 103/104 = 99.0% (only XBEN-030 unsolved in any mode), the load-bearing gpt-5.4 model-specific cohort sits at 93/95 = 97.9% on black-box, and the first scored full Cybench run lands at 36/40 = 90.0% single-config single-shot. The older mixed local+CI publication line remains documented separately. Most of the next-quarter work is about taking that capability and making it operationally easy to live with — for one developer running a single review, for a CI pipeline gating PRs, and for a security team running a continuous campaign.

## May 2026 strategy addendum

FoxGuard is now the default static lead source and the explicit stepping stone away from Semgrep. The product direction is not "delete Semgrep immediately" or "rewrite pwnkit in Rust." The direction is:

1. keep the TypeScript control plane for agent orchestration, provider integration, CLI/cloud contracts, benchmark loops, and fast policy iteration
2. move deterministic engines into Rust behind stable JSON/SARIF contracts
3. make FoxGuard the first engine that proves this boundary with measured lead quality and wall-time wins

That changes the trust-track roadmap:

- **FoxGuard default validation gate:** run the Semgrep-vs-FoxGuard ablation and keep FoxGuard as default only if it preserves confirmed findings while materially improving wall time.
- **Static scanner language cleanup:** continue migrating user-facing prompts/docs from "Semgrep findings" to scanner-neutral language while preserving backwards-compatible JSON fields until a schema migration is worth the churn.
- **Rust engine expansion:** after FoxGuard proves the boundary, evaluate secret scanning, manifest/dependency inventory normalization, SARIF/CBOM transforms, large-repo indexing, and sandbox/process helpers as Rust engines.
- **No wholesale Rust rewrite yet:** revisit only if runtime, distribution, sandbox, or multi-consumer engine contracts create measured pressure.

See [TypeScript/Rust Boundary](/research/typescript-rust-boundary/) for the decision record and [Foxguard ablation baseline](/research/foxguard-ablation/2026-05-22-baseline/) for the validation gate.

## Recently shipped (April 2026)

These are the things that landed since the last public roadmap snapshot. They should not be in the "Now" column anymore — they are done.

- **Retained artifact-backed XBOW aggregate at 103 / 104.** The machine-recoverable artifact window now proves more unique solves than the older public mixed local+CI tally, though the set composition is different and still being reconciled on the benchmark page. Only XBEN-030 remains unsolved in any mode. The load-bearing black-box claim is the gpt-5.4 model-specific cohort at 93/95 = 97.9% — the retained-aggregate black-box count is rotation-volatile because GitHub Actions retains a 90-day window of run artifacts.
- **First scored full Cybench run at 36 / 40 = 90.0%.** Single-config (Azure gpt-5.4), single-shot, 3 retries per challenge, 358 attack turns total, ~$14.89 estimated cost. Supersedes the older 8/10 = 80% historical 10-challenge subset.
- **Historical public XBOW publication still tracked separately.** The older mixed local+CI publication line now sits at 90/104 black-box and 95/104 aggregate after purging unsupported claim residue, and it is not the only current source of truth.
- **Cost ceiling enforcement.** Scans abort cleanly when a per-run USD budget is exceeded, instead of silently spending past it.
- **Direct OSV advisory lookup in the npm audit pipeline.** No more relying on `npm audit` alone for known-CVE coverage.
- **Phase 4 pre-recon CVE check** for white-box mode — the agent fingerprints the target stack against known vulnerabilities before it starts attacking.
- **Phase A flag-regex extractor + gate filters.** Catches flag-shaped strings the agent emits and validates them against expected format. This is what caught the XBEN-079 honeypot decoy (`FLAG{I'm_a_Script_Kiddie}`) before it became a silent false positive.
- **Phase B malicious-package detection** in the audit pipeline.
- **Cloud handshake (Phase 1).** Findings produced by the OSS engine can be normalised and ingested by an orchestrator service that tracks scan jobs end-to-end.
- **A/B sweep cadence.** Overnight workflow dispatches across feature combinations are now the default way improvements get tested. The first sweep cost $3.08 across 8 challenges, added one solve, and surfaced one actionable failure mode (the honeypot).

## Now

These are the next four things in priority order. Each one is small enough to ship in one or two focused passes.

### 1. Anti-honeypot / decoy-flag heuristic

**Goal:** stop the agent from declaring victory on the first flag-shaped string it finds when the target deliberately seeds a fake one.

**Why:** the v1 A/B sweep caught the agent submitting `FLAG{I'm_a_Script_Kiddie}` on XBEN-079 ("Poison Inclusion - Protected"). The real flag was `FLAG{7dda4e738d29a996f343a610}`. The flag-extractor gate caught the mismatch and the run failed cleanly — but a non-CTF target could plant a similar honeypot string in a `.git/config` or a config file decoy and the agent would happily submit it as a finding.

**Deliverables:**

- on flag-shaped match, mark provisional and continue at least one more layer of exploration
- prefer hex/uuid shapes that match the surrounding suite's flag format over jokey decoys
- expose the heuristic as `--decoy-detection` (default: on)

This is a small, falsifiable change. If it lands XBEN-079 it almost certainly catches a class of similar honeypots in real engagements.

### 2. Statistical evaluation methodology — n=10 runs per cell

**Goal:** replace single-shot benchmark anecdotes with measured per-attempt success rates and confidence intervals.

**Why:** the v1 sweep produced a single solve on XBEN-061 with a `handoff,no-hiw,no-evidence` combo that looked like a generalisable winning configuration. The v2 sweep ran the same combo against the same challenge as a regression test the next afternoon. **It failed.** The v1 solve was noise inside a 20–40% per-attempt success rate, not a signal worth defaulting on. This remains the methodology lesson even after the retained artifact-backed aggregate moved to 103/104: a single solve is still an anecdote, and any configuration recommendation that comes from a single solve is unsafe to promote.

**Deliverables:**

- benchmark harness flag for `--repeat N` that runs each (challenge, configuration) cell N times and reports the success rate plus confidence interval
- default protocol going forward: n=10 per cell when evaluating a new feature combination, before any promotion to default
- per-cell cost ceiling so the n=10 protocol stays under ~$5 per cell
- a separate methodology page in the docs explaining the difference between best-of-N (what XBOW reports) and per-attempt success rate (what we now measure internally)

**Note:** this change demoted the previous "lean scaffolding default for long-horizon white-box" priority that was here in the morning version of this roadmap. The lean combo is now treated as a hypothesis to test under the new protocol, not a default to promote.

### 3. Resumable scans

**Goal:** if a long review or scan dies, resume from stored state instead of restarting.

**Why:**

- the repo already persists `agent_sessions` and `pipeline_events`
- long-running agentic workflows are expensive to restart
- this is what makes pwnkit feel like infrastructure instead of a disposable CLI run

**Deliverables:**

- `pwnkit-cli resume <scan-id>`
- stage-level checkpointing
- partial-result recovery after crash or timeout
- resume-safe report generation

### 4. Finding inbox + triage workflow

**Goal:** make findings manageable across repeated runs.

**Why:** "found a thing" is not enough for teams. Repeated findings need dedupe, suppression, and audit history.

**Deliverables:**

- finding fingerprinting across scans
- statuses such as `new`, `accepted`, `suppressed`, `needs-human`, `regression`
- suppression rules with reason + expiration
- comments / notes on findings
- diff view between scans

## Next

These become much more valuable once the items above are solid.

### 5. Diff-aware PR scanning

**Goal:** make the GitHub Action and CI path fast enough to use on every PR.

**Why:** full deep review on every pull request is too expensive. Most teams want "changed files first, expand when suspicious."

**Deliverables:**

- changed-file targeting for `review`
- priority scoring for touched paths, auth, secrets, network, tool-use, eval-like sinks
- optional fallback to full review on high-risk deltas
- PR summary output tuned for reviewer action

### 6. Deterministic replay for every finding

**Goal:** every confirmed finding should be reproducible on demand.

**Why:** replay is how the tool earns trust. It is the bridge between "AI said so" and "I can see it myself."

**Deliverables:**

- replay command from finding ID
- saved exploit inputs / requests / prompts
- verifier transcript and verdict trace
- artifact bundle for share / export

### 7. Multi-target orchestration

**Goal:** scan many repos, packages, or endpoints as one campaign. This is where subagents actually matter.

**Good use of subagents:**

- fan out research across many targets
- parallel blind verification
- aggregate results into one campaign view

**Bad use of subagents:**

- navigation gimmicks
- vague "AI assistant" behaviour with no task boundary

**Deliverables:**

- campaign runs
- worker pool / concurrency controls
- queueing and retry policy
- shared target inventory and cross-target clustering

### 8. Local dashboard / operations shell

**Goal:** expose the stored scan state as a real operator interface for running the autonomous control plane, working the review inbox, and inspecting runtime failures.

**Status:**

- baseline shipped: grouped findings, thread-level workflow, quick filtering, scan dossiers, recent shadcn rebuild
- next cut: operations-first home, active run stage progress, replay launch, and better provenance links between threads and runs

**Core views:**

- operations control as the primary home
- review inbox for operator decisions and blocked automation
- scan dossiers and pipeline timelines as supporting provenance views
- replay / evidence viewer
- target inventory
- scan history and trend charts

## Later

These are valuable, but they should not outrank the workflow / control-plane work above.

### 9. Policy packs and organisation presets

- suppressions as code
- severity gates by environment
- org-level runtime / model defaults
- approved attack template sets

### 10. Richer target inventory and trend analysis

- first-seen / last-seen attack surface changes
- recurring finding families
- regression alerts
- "what changed since last green run"

### 11. Distributed workers / remote execution

- remote queue workers
- large campaign execution
- shared artifact store
- eventually a hosted control plane if adoption justifies it

## Non-Goals Right Now

Things that sound flashy but should stay below the line for now:

- a giant SaaS dashboard before the local workflow is excellent
- "chat with your findings" before replay, dedupe, and triage are strong
- adding lots of new scan modes without stronger replay and campaign ergonomics
- subagents used as UI magic instead of bounded workers
- EGATS-style tree search on challenges this size — the v1 sweep proved it currently costs more than it earns

## Product Direction

The best version of pwnkit is:

- a sharp local CLI for one-off deep work
- a reliable CI primitive for PRs and repos
- a persistent evidence store for findings and agent runs
- a local operations shell on top of that state
- eventually a separate distributed agentic security control plane for campaigns and remote workers

That is more compelling than being "yet another scanner with more templates." The XBOW number is the proof that the core capability is real. The roadmap above is the work to turn that capability into something teams can actually live with.
