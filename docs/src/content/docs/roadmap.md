---
title: Roadmap
description: Current implementation pointers and historical plans for the 0sec engine. Roadmap items are not release or managed-service availability guarantees.
---

## Current implementation pointers

This page retains dated strategy notes below. Use the current guides for
executable instructions; the older “Now” and “Next” lists are not a live
inventory of missing commands.

| Area | Current entry point | Remaining boundary |
| --- | --- | --- |
| Interactive work | [Console](/console/) | The terminal interface for running scans and reviewing findings. |
| Saved scan continuation | [Scan Workflows](/scan-workflows/) | Resume routing and available state vary by producer; it is not universal recovery for every command. |
| Findings and triage | [Commands](/commands/#findings) and [Finding Triage](/triage/) | Triage state is not proof that a vulnerability was reproduced or fixed. |
| Diff-aware review and CI | [Integrations](/integrations/) and [GitHub CI](/ci/github-action/) | Local/scripted CI support does not imply a published composite action. |
| Deterministic verification | [Verification Results](/verification-result/) | Replay requires executable inputs and valid setup; it does not cover every candidate automatically. |
| Research adapters | [Research Workflows](/research-workflows/) | Imported evidence is distinct from execution performed by 0sec. |


## 0cloud

**0cloud is not yet released.** It remains in development; no public
onboarding, download path, or launch date is promised. All references to a
managed control plane on this site describe architectural components that have
not shipped as a user-accessible service.

## Desktop

**The native Desktop application is not yet released.** It is in development;
no public download or install path is available. All desktop references on this
site describe an in-progress interface. Use the CLI [Console](/console/) for
the released terminal interface.

Documentation follows the source checkout. Check `0sec --version` and
`0sec <command> --help` against your installed release before using newly
documented flags.

This roadmap prioritises product leverage over surface-area creep, and stays
honest about what has shipped vs what is still being scoped. The thesis is
unchanged:

1. Make the core agentic pipeline trustworthy.
2. Make the outputs operationally useful for real teams.
3. Then add orchestration and control-plane UX on top.

The trust layer is now real. The retained artifact-backed XBOW aggregate is
103/104 = 99.0% (only XBEN-030 unsolved in any mode); the load-bearing gpt-5.4
black-box cohort is 93/95 = 97.9%; the first scored full Cybench run is 36/40 =
90.0% single-config, single-shot. (The older mixed local+CI publication line is
documented separately.) Most next-quarter work is about making that capability
easy to live with — for one developer, for a CI pipeline gating PRs, and for a
security team running a continuous campaign.

## August 2026 product-discovery checkpoint

**Historical checkpoint, August 2026:** no commercial vertical had been selected
in this strategy note.
The original platform rationale follows. 0sec was framed as an
open-source, evidence-backed cyber reasoning system: given an authorized
objective, a scoped target, tools, and a verifier, it plans, investigates, tests,
and returns replayable evidence. That's a platform thesis — it doesn't by itself
prove which company problem is urgent enough to buy.

### Platform primitives

1. scenario / objective
2. target adapter
3. scoped tool policy
4. reasoning and execution loop
5. verifier / evidence oracle
6. replayable evidence bundle

Web testing, source review, package audit, MCP testing, and agent assurance are
applications of those primitives. New modes should strengthen one of them, not
turn the CLI into a pile of unrelated product claims.

### Commercial hypotheses

- **Generic autonomous web pentesting** — a core OSS capability, but a crowded
  commercial category. Benchmark strength alone doesn't establish a paid wedge.
- **Agent-action assurance** — a candidate paid workflow: can a company prove a
  tool-using agent *cannot* perform a named prohibited action after a model,
  prompt, tool, or MCP change? The `agent-assure` command supplies the initial
  scope-bound, externally observed action primitive.
- **Managed operation** — if a workflow proves repeat use, the managed layer
  sells scheduling, protected-target access, shared evidence, triage,
  integrations, and support around the public engine. It must not depend on a
  private fork of the scanner.

### Validation before committing

Don't pick a vertical from benchmarks, downloads, or a feature inventory. For
each candidate workflow: interview ten companies with the real target and a named
security owner; sell three paid pilots, not free evals; require an authorized
staging target, a concrete success/prohibited-action definition, and a replayable
evidence review; count collected revenue, a remediation decision, and a requested
re-run as the leading evidence; build only blockers that recur across ≥2 pilots.
The decision is deliberately reversible until then.

## May 2026 strategy addendum

FoxGuard is now the default static lead source and the stepping stone away from
Semgrep. The direction is not "delete Semgrep immediately" or "rewrite 0sec in
Rust." It's:

1. keep the TypeScript control plane for agent orchestration, provider
   integration, CLI/cloud contracts, benchmark loops, and fast policy iteration;
2. move deterministic engines into Rust behind stable JSON/SARIF contracts;
3. make FoxGuard the first engine that proves this boundary with measured lead
   quality and wall-time wins.

Trust-track implications:

- **FoxGuard validation gate** — run the Semgrep-vs-FoxGuard ablation; keep
  FoxGuard as default only if it preserves confirmed findings while materially
  improving wall time.
- **Scanner language cleanup** — migrate prompts/docs from "Semgrep findings" to
  scanner-neutral language, keeping JSON fields backwards-compatible until a
  schema migration is worth the churn.
- **Rust engine expansion** — after FoxGuard proves the boundary, evaluate secret
  scanning, dependency inventory normalization, SARIF/CBOM transforms, large-repo
  indexing, and sandbox/process helpers as Rust engines.
- **No wholesale Rust rewrite yet** — revisit only under measured runtime,
  distribution, sandbox, or multi-consumer pressure.

See [TypeScript/Rust Boundary](/research/typescript-rust-boundary/).

## Implemented, pending release

- **Isolated improvement workers and promotion canaries.** The `0sec evolve`
  CLI provides config-driven source candidate
  proposals with explicit `allowModelSourceAccess` consent, three-lane
  evaluation (development/held-out/negative-control) in network-none Docker
  containers, content-addressed immutable snapshots, pure-function promotion
  gates, canary trials, rollback, and hash-chained registries with atomic
  artifact publication. Config replaces the previous blanket "no automatic
  source-code promotion" with configured autonomy (`autoPromote`). Executed as
  sandboxed versioned workers — never live in-process self-patching. See
  [Improvement Plane](/improvement-plane/).
- **Operational feedback curation.** `0sec evolve feedback capture/approve/status/release`
  for evidence-backed observations with operator-curated `ValidationFixture`
  arrays (positives, heldOut, negativeControls), source access consent, and
  content-digest drift detection.
- **Skill/router artifact bridge.** `artifact-bridge.mjs` authorizes candidate
  artifacts against the evolution registry before skill-refine or active-learning
  loops may promote them.
- `0sec lens-synth --status` and `--rollback` for inspecting and retiring
  promoted overlay lenses.

## Recently shipped (April 2026)

- **Retained artifact-backed XBOW aggregate at 103/104.** Only XBEN-030 remains
  unsolved in any mode. The load-bearing black-box claim is the gpt-5.4 cohort at
  93/95 = 97.9%; the retained-aggregate black-box count is rotation-volatile
  because GitHub Actions keeps a 90-day artifact window.
- **First scored full Cybench run at 36/40 = 90.0%.** Single-config (Azure
  gpt-5.4), single-shot, 3 retries per challenge, 358 attack turns, ~$14.89.
  Supersedes the older 8/10 subset.
- **Historical public XBOW line tracked separately** — 90/104 black-box, 95/104
  aggregate after purging unsupported claim residue.
- **Cost ceiling enforcement** — scans abort cleanly when a per-run USD budget is
  exceeded.
- **Direct OSV advisory lookup** in the npm audit pipeline — no more relying on
  `npm audit` alone.
- **Phase 4 pre-recon CVE check** for white-box mode — fingerprints the stack
  against known vulns before attacking.
- **Phase A flag-regex extractor + gate filters** — caught the XBEN-079 honeypot
  decoy (`FLAG{I'm_a_Script_Kiddie}`) before it became a silent false positive.
- **Phase B malicious-package detection** in the audit pipeline.
- **Orchestrator handshake (Phase 1)** — OSS-engine findings can be normalised and
  ingested by an orchestrator that tracks scan jobs end-to-end.
- **A/B sweep cadence** — overnight feature-combination sweeps are now the default
  way improvements get tested.

## Now

Historical priorities from the original roadmap. Current implemented portions
are called out below; this is not a release schedule.

### 1. Anti-honeypot / decoy-flag heuristic

**Goal:** stop the agent declaring victory on the first flag-shaped string when
the target seeds a fake one.

**Why:** on XBEN-079 the agent submitted `FLAG{I'm_a_Script_Kiddie}` (real flag:
`FLAG{7dda4e738d29a996f343a610}`). The flag-extractor gate caught the mismatch —
but a non-CTF target could plant a decoy in `.git/config` and the agent would
submit it.

**Current implementation:** the `done` tool's decoy-shape heuristic is enabled
by default and can be disabled with `--no-decoy-detection`. It rejects a
low-confidence flag once; a repeated submission can override it. This is a
benchmark-oriented speed bump, not an independent verifier or a proof gate
for real-world findings.

### 2. Statistical evaluation methodology — n=10 per cell

**Goal:** replace single-shot anecdotes with per-attempt success rates and
confidence intervals.

**Why:** the v1 sweep's single XBEN-061 solve with a `handoff,no-hiw,no-evidence`
combo looked like a winner. The v2 sweep re-ran it as a regression test — **it
failed.** That solve was noise inside a 20-40% per-attempt rate. A single solve
is an anecdote; any config recommendation from one solve is unsafe to promote.

**Deliverables:** `--repeat N` harness flag reporting success rate + CI; default
n=10 per cell before any promotion to default; per-cell cost ceiling (~$5); a
methodology page on best-of-N (what XBOW reports) vs per-attempt success rate
(what we measure).

### 3. Resumable scans

**Goal:** resume a dead long-running scan from stored state instead of
restarting.

**Why:** the repo already persists `agent_sessions` and `pipeline_events`;
restarting long agentic workflows is expensive. This is what makes 0sec feel like
infrastructure.

**Current implementation:** `0sec resume <scan-id>` and journal continuation
exist. The remaining goal is reliable recovery across all workflows, not the
addition of a missing command. Read [Scan Workflows](/scan-workflows/) for
supported routing, state requirements, and caveats.

### 4. Finding inbox + triage workflow

**Goal:** make findings manageable across repeated runs.

**Why:** "found a thing" isn't enough for teams. Repeated findings need dedupe,
suppression, and audit history.

**Current implementation:** the `findings` command exposes grouped findings,
triage filtering, and lifecycle inspection. The CLI's human triage values are
`new`, `accepted`, and `suppressed`, separate from finding verification state.
The broader suppression-expiry, comments, and cross-run workflow described
here remains a design goal unless documented by a current command.

## Next

More valuable once the above is solid.

### 5. Diff-aware PR scanning

**Goal:** make the GitHub Action fast enough to run on every PR — changed files
first, expand when suspicious.

**Current implementation:** `review --diff-base <ref> --changed-only` scopes
static leads and prioritization to changed files. See [GitHub CI](/ci/github-action/)
for the supported automation path. Broader PR policy and automatic fallback
behavior are goals, not implied by the presence of these flags.

### 6. Deterministic replay for every finding

**Goal:** every confirmed finding reproducible on demand — the bridge between "AI
said so" and "I can see it myself."

**Deliverables:** replay from finding ID; saved exploit inputs/requests/prompts;
verifier transcript and verdict trace; shareable artifact bundle.

### 7. Multi-target orchestration

**Goal:** scan many repos, packages, or endpoints as one campaign. Concurrent
subagents already fan out **within a single run** (`spawn_agents`); this item is
the campaign-scale layer above that.

**Good use:** fan research across many targets; parallel blind verification;
aggregate into one campaign view. **Bad use:** navigation gimmicks; vague "AI
assistant" behaviour with no task boundary.

**Deliverables:** campaign runs; worker-pool / concurrency controls; queueing and
retry policy; shared target inventory and cross-target clustering.

### 8. Local dashboard / operations shell

**Goal:** expose stored scan state as a real operator interface for running the
control plane, working the review inbox, and inspecting runtime failures.

**Current implementation:** local dashboard and console interfaces exist.
Desktop is in development; see [Roadmap](/roadmap/#desktop) for current
status. Use [Console](/console/) for the released terminal interface.

## Later

Valuable, but shouldn't outrank the workflow/control-plane work above.

### 9. Policy packs and organisation presets

Suppressions as code; severity gates by environment; org-level runtime/model
defaults; approved attack template sets.

### 10. Richer target inventory and trend analysis

First-/last-seen attack-surface changes; recurring finding families; regression
alerts; "what changed since last green run."

### 11. Distributed workers / remote execution

Remote queue workers; large campaign execution; shared artifact store; eventually
a hosted control plane if adoption justifies it.

## Non-goals right now

- treating the existence of a UI or backend scaffold as general managed-service availability
- replacing reproduction evidence with a chat summary or lifecycle label
- new scan modes without stronger replay and campaign ergonomics
- subagents used as UI magic instead of bounded workers
- EGATS-style tree search on challenges this size — the v1 sweep proved it costs
  more than it earns

## Product direction

The best version of 0sec is a sharp local CLI for one-off deep work; a reliable
CI primitive for PRs and repos; a persistent evidence store for findings and
agent runs; a local operations shell on that state; and eventually a separate
distributed agentic security control plane for campaigns and remote workers. That
beats being "yet another scanner with more templates." The XBOW number proves the
core capability is real; the roadmap above is the work to make it something teams
can live with.
