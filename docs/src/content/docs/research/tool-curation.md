---
title: "Tool Curation for Security Agents"
description: "Why 0sec is trimming and namespacing its 56-tool registry toward per-phase loadouts with deferred loading, and the concrete plan to get there."
---

> **Research + decision log (2026-08-30).** An audit of 0sec's model-facing tool surface against the current guidance on tool-use accuracy, plus the plan we are committing to. Every repo claim is anchored to a `packages/<path>:<line>` reference; external claims cite a URL.

## Executive summary

1. **We register 56 tools, and the default interactive console advertises 40 of them to the model in one context.** The registry lists 56 tool names (`packages/core/src/agent/tools/index.ts`, `TOOL_REGISTRY_ORDER`). The console defaults to the `audit` role (`packages/cli/src/commands/console.ts:164`) and builds its tool set via `getToolsForRole(role, …)` with **no** `hasScope` flag (`packages/core/src/console/turn-engine.ts:1670`), so `audit` resolves to `allEnabledTools` rather than the lean scoped set — roughly 40 tool schemas in front of the model on every turn.
2. **This lands well outside the safe zone.** The current guidance from both Anthropic and independent benchmarks puts reliable tool selection at roughly **10–20 always-loaded tools**, with accuracy degrading past 30–50 and token cost accruing on every turn. Forty is over the line.
3. **The lean lanes are already healthy — the console is the outlier.** Discovery and attack advertise `networkTools` = 16; verify is 16–20; report is 3; subagents get a hardcoded 6. The problem is specifically the audit-default console path, not the engine's per-role discipline, which is sound.
4. **There is a filter bug inflating the count further.** `allEnabledTools` (`packages/core/src/agent/tools.ts:8382-8414`) gates ~10 feature families behind their flags but does **not** filter `web_search` / `pty_session` by their default-OFF flags, so the console advertises 2 tools it should not — the observed 40 should be 38.
5. **The registry has clear redundancy** — bash-vs-`run_command`, three todo tools for one concept, four scanner wrappers, five `intel_*` verbs, three `spawn_*` variants — that consolidates cleanly into namespaced high-level verbs.
6. **We already have the pattern we need.** JIT skills (`list_skills` / `load_skill`, `packages/core/src/agent/tools/skills.ts`) let the model discover methodology on demand. There is no equivalent `list_tools` / `load_tool` layer for tools yet. Building one is the highest-leverage structural change.

The decision (Section 7): fix the flag bug now, consolidate the redundant families into namespaced verbs, hold each reasoning context to ~10–20 tools via per-phase loadouts, and add a deferred `list_tools` / `load_tool` front door for the long tail while keeping the 3–5 hottest tools always-on.

## 1. The problem: what the model actually sees

### 1.1 The registry

`TOOL_REGISTRY_ORDER` in `packages/core/src/agent/tools/index.ts` enumerates **56** tool names, assembled from per-domain definition modules (recon, findings, system, access-control, exploit, intel, skills, scanner, detections, cloud, orchestrator, oast, python, binary, ask-operator, todos). The split into per-domain files is deliberate — it lets parallel feature PRs edit disjoint files — but it also makes the total surface easy to grow without anyone watching the aggregate count.

### 1.2 The console default path

The interactive console picks `audit` as its default role:

- `packages/cli/src/commands/console.ts:164` — `let role: ConsoleRole = "audit";`
- `packages/core/src/console/turn-engine.ts:1670` — `getToolsForRole(role, { allowScanners: config.allowScanners })`, with **no `hasScope`** passed.

That matters because of how `getToolsForRole` resolves `audit`:

```ts
// packages/core/src/agent/tools.ts (roleTools map)
audit:  opts?.hasScope ? scopedSourceTools : allEnabledTools,
review: opts?.hasScope ? scopedSourceTools : allEnabledTools,
```

Without `hasScope`, `audit` falls through to `allEnabledTools` — the "everything the flags permit" set — rather than the tight `scopedSourceTools` set intended for a scoped source audit. Net effect: **~40 tool schemas advertised to the model on every console turn.**

### 1.3 The lean lanes are fine

For contrast, the non-console lanes are already disciplined:

| Lane / role | Tools advertised | Source |
| --- | --- | --- |
| discovery | 16 (`networkTools`) | `tools.ts:8421` |
| attack | 16 (`networkTools`) | `tools.ts:8422` |
| verify | 16 (no scope) – 20 (with scope: `+fileTools`) | `tools.ts:8424` |
| report | 3 | report role set |
| subagents | 6 — `["bash","save_finding","done"]` + `report_status` + `send_message` + `check_messages` | hardcoded |
| **console (audit default)** | **~40 (`allEnabledTools`)** | `console.ts:164` + `turn-engine.ts:1670` |

The engine already knows how to hand a loop a curated set — the kernel-verify loop is the extreme case, a single allowlisted tool (`kernel_run`). The console is the one context that opted into the firehose.

### 1.4 The flag-filter bug (40 vs 38)

`allEnabledTools` (`packages/core/src/agent/tools.ts:8382-8414`) is a big `Object.keys(TOOL_DEFINITIONS).filter(...)` that correctly gates many families behind their feature flags:

- `list_skills` / `load_skill` behind `jitSkills`
- `use_loot` behind `lootLedger`
- `plan` behind `agentPlan`
- scanner wrappers behind `allowScanners` / `SCANNER_TOOL_NAMES`
- cloud tools behind `cloudSurface`
- `start_scan` behind `agentFanout`
- OAST tools behind `oastCollaborator`
- `python_exec` behind `pythonExec`
- 0verse binary tools behind `zeroverse`
- `write_todos` and `self_extend` excluded outright

What it does **not** do is filter `web_search` and `pty_session` by their default-OFF flags. Both are default-off capabilities, but because they have no exclusion clause in this filter they leak into `allEnabledTools` regardless. So the console shows **40 tools when it should show 38**. This is a straightforward one-clause fix (add the two flag checks, matching the existing pattern for `python_exec`) and it is the cheapest win in this whole document.

## 2. The evidence: why 30–50 tools is the wrong number

### 2.1 Anthropic's own guidance

Anthropic's tool-search documentation states that tool-selection accuracy degrades once an agent is presented with more than roughly **30–50 tools**, and recommends switching to a tool-search / deferred-loading approach at **≥10 tools or ~10K tokens of tool definitions**:

- https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool
- https://code.claude.com/docs/en/agent-sdk/tool-search

The cost is not only accuracy. Tool schemas are re-sent on **every** turn, so they are a standing tax on the context window. Anthropic's figures: a setup wiring in ~5 MCP servers can spend on the order of **55K tokens on tool definitions before any work happens**, and tool search cuts that by **>85%** by loading only the definitions the model actually needs.

Anthropic's "Writing effective tools for AI agents" (https://www.anthropic.com/engineering/writing-tools-for-agents) is blunt about the direction: *"more tools don't always lead to better outcomes."* Its recommendations map directly onto our plan — consolidate overlapping operations into a smaller number of **high-level verbs**, **namespace** related tools, and return **token-efficient responses**.

### 2.2 Independent benchmarks show non-linear collapse

This is not a soft "gets a bit worse" curve. Independent measurements show the failure is non-linear:

- The Berkeley Function-Calling Leaderboard (BFCL) style measurements show accuracy falling from ~**43% to ~2%** as the available tool count grew from **4 to 51** (https://www.anthropic.com/engineering/advanced-tool-use).
- The "over-tooled agent" write-up (https://tianpan.co/blog/2026-04-19-over-tooled-agent-problem) documents the same shape and the token-tax dynamic.
- Retrieval-based tool selection (load only the relevant subset per task) has been shown to roughly **triple accuracy while halving token usage** versus loading everything (arxiv 2605.18857).

The consistent finding across sources: the model does not degrade gracefully when handed a large flat tool menu — it collapses, and it pays for the privilege in tokens.

### 2.3 The safe zone

Synthesizing the above, the practical safe zone for *always-loaded* tools is roughly **10–20**. Beyond that, the recommendation is not "prune to 20 and stop" but "keep the hot set small and put the long tail behind a discovery layer." Our lean lanes (16–20) already sit inside this band; the console (40) does not.

## 3. Our redundancy: what consolidates

An audit of the 56-tool registry surfaces several families where multiple tools express one concept. Collapsing these into namespaced verbs both shrinks the count and makes selection easier (fewer near-synonyms for the model to disambiguate).

| Redundant set | Count | Consolidation | Notes |
| --- | --- | --- | --- |
| `bash` + `run_command` | 2 | keep one primitive | `run_command` is ≈ `bash` with an allow-list; the distinction is a policy flag, not a separate verb |
| `plan` + `update_todos` + `write_todos` | 3 | one planning tool | three tools for one concept; `write_todos` is already a dispatchable **alias** of `update_todos` (excluded from `allEnabledTools` at `tools.ts`) |
| `run_sqlmap` / `run_nmap` / `run_ffuf` / `run_nuclei` | 4 | `run_scanner({ tool, args })` | one dispatch verb over the scanner family; the wrappers differ only by binary |
| `intel_*` (5 verbs) | 5 | `intel({ action })` | five actions collapse to one namespaced verb with an `action` discriminator |
| `discover_api_surface` | 1 | fold into `surface_sweep` | `discover_api_surface` is a strict subset of `surface_sweep` |
| `spawn_agent` / `spawn_agents` / `spawn_persistent_agent` | 3 | one spawn verb | three variants of "spawn a sub-agent"; parameterize lifetime/fan-out |

None of these consolidations removes capability — they remove *surface*. The scanner and intel collapses in particular convert a fan of near-identical schemas into a single verb with a discriminated argument, which is exactly the "high-level verbs + namespace" pattern Anthropic recommends.

## 4. The pattern we already have: JIT skills

0sec already ships progressive disclosure — for methodology, not for tools. The JIT-skills feature (`packages/core/src/agent/tools/skills.ts`, gated by the `jitSkills` flag) exposes two tools:

- `list_skills` — enumerate available methodology guides
- `load_skill` — *"Load a skill's methodology guide into your working context. Use list_skills first to see what's available."* (`skills.ts:28`)

The model discovers and pulls in methodology on demand instead of carrying every guide in the base prompt. This is the same shape as tool search: a cheap index tool plus an on-demand loader, keeping the base context small.

**There is no equivalent `list_tools` / `load_tool` layer for tools yet.** The long tail of tools (scanners, cloud, OAST, intel, binary) is either always-on or gated by a static feature flag — there is no mechanism for the model to pull a rarely-used tool into context for one task and drop it after. Building that layer, mirroring JIT skills, is the structural fix for the long tail.

## 5. The plan

1. **Fix the flag-filter bug.** Add `web_search` and `pty_session` flag checks to the `allEnabledTools` filter (`tools.ts:8382-8414`) so the console honors their default-OFF flags. Immediate, low-risk, 40 → 38.
2. **Target ~10–20 always-loaded tools per reasoning context.** Adopt the safe-zone band as an explicit budget for any single model context, and treat the console-audit default (~40) as a bug to be paid down, not a baseline.
3. **Consolidate the scanner / intel / spawn families into namespaced verb tools** (Section 3): `run_scanner({tool,args})`, `intel({action})`, one spawn verb, one planning tool, fold `discover_api_surface` into `surface_sweep`, and pick a single shell primitive.
4. **Per-phase loadouts.** Extend the discipline the engine already applies per role — recon / exploit / triage / report each get a curated static set sized to the band. 0sec already has per-role sets (`networkTools`, `fileTools`, the report set); this formalizes and completes that.
5. **Deferred loading front door.** Add `list_tools` / `load_tool`, mirroring JIT skills, for the long tail (scanners, cloud, OAST, intel, binary). Keep the **3–5 hottest tools always-on** (e.g. a shell primitive, `http_request`, `save_finding`, `read_file`) so the common path never pays a load round-trip.
6. **Invest in tool descriptions.** Write descriptions with task-matching keywords so both the model and any retrieval layer can select correctly. Per Anthropic's writing-tools guidance, description quality is a first-class lever, not a nicety.

### Tradeoffs

- **Deferred loading (step 5) costs a round-trip.** `list_tools` → `load_tool` → use is one extra hop before the model can act with a cold tool. That is acceptable for the long tail (rarely-used tools) but not for the hot path — hence the always-on core.
- **Per-phase static loadouts (step 4) avoid the round-trip** at the cost of some up-front curation and the risk of a phase occasionally needing a tool outside its set. The two mechanisms are complementary: static loadouts for the predictable hot set of each phase, deferred loading for the unpredictable long tail. Most phases should need the loader rarely.
- **Consolidation (step 3) trades explicitness for surface.** A single `run_scanner({tool})` is one more argument for the model to get right than four named wrappers — but it is four fewer schemas to disambiguate, and the disambiguation cost dominates at our scale.

## 6. Target per-context tool counts

| Context | Today | Target | Mechanism |
| --- | --- | --- | --- |
| console (audit default) | ~40 (`allEnabledTools`, incl. 2-tool bug) | ~15–18 | flag fix + per-phase loadout + deferred long tail |
| discovery / attack | 16 (`networkTools`) | ~12–16 | already in band; trim via consolidation |
| verify | 16–20 | ~12–16 | already in band |
| report | 3 | 3 | unchanged |
| subagents | 6 (hardcoded) | 6 | unchanged |
| kernel-verify | 1 (`kernel_run`) | 1 | reference for single-tool discipline |
| always-on core (new) | n/a | 3–5 | shell + `http_request` + `save_finding` + `read_file` |

Every context lands inside the 10–20 band, and the largest offender (console) comes down by roughly half.

## 7. Decision

We will:

1. **Fix the `web_search` / `pty_session` flag-filter bug** in `allEnabledTools` (`tools.ts:8382-8414`) so the console honors default-OFF flags. This is the immediate, isolated first change.
2. **Hold every reasoning context to ~10–20 always-loaded tools**, adopting the safe-zone band as an explicit design budget.
3. **Consolidate the redundant scanner / intel / spawn / todo / shell families into namespaced verb tools** per Section 3, removing surface without removing capability.
4. **Build a `list_tools` / `load_tool` deferred-loading layer for the long tail**, mirroring the existing JIT-skills pattern, while keeping a 3–5 tool always-on core so the common path never pays a load round-trip.
5. **Complete per-phase loadouts** so recon / exploit / triage / report each carry a curated static set, extending the per-role discipline the engine already has.

**Why.** Both Anthropic's guidance and independent benchmarks agree that a large flat tool menu degrades selection accuracy non-linearly (BFCL 43% → 2% from 4 → 51 tools) and taxes the context on every turn, while retrieval-based selection roughly triples accuracy at half the tokens. Our lean lanes already prove the discipline works inside our own codebase; the console default is the outlier. We already own the exact progressive-disclosure pattern (JIT skills) needed to extend that discipline to the long tail. The changes are ordered cheapest-first (bug fix) to most-structural (deferred loading) so each ships and pays off independently.

## 8. Open questions

1. **Where is the always-on / deferred line?** We propose a 3–5 tool always-on core, but the exact membership (does `search_files` belong on the hot path? `query_findings`?) needs per-phase telemetry on tool-call frequency before we hardcode it.
2. **Static loadout vs. deferred loader as the primary mechanism.** Per-phase static sets avoid round-trips but risk a phase missing a tool it occasionally needs. How often does a phase reach outside its set in practice? If it's frequent, the loader should lead; if rare, static loadouts should.
3. **Retrieval quality for `load_tool`.** If `list_tools` returns a ranked/filtered subset rather than the full menu, we need a selection signal (keyword match on descriptions, embedding retrieval, or phase heuristics). Which is worth the complexity at 56 tools — is a flat `list_tools` enough until the registry is much larger?
4. **Consolidation vs. observability.** Collapsing `run_sqlmap`/`run_nmap`/… into `run_scanner({tool})` changes how tool usage shows up in telemetry and audit logs. Do our dashboards and finding provenance depend on the per-wrapper tool names? If so, the discriminator must be preserved in the event stream.
5. **Should the console stop defaulting to `audit`?** The bug is that audit-without-scope resolves to `allEnabledTools`. Even after the loadout work, is `audit` the right console default, or should the console default to a purpose-built interactive loadout instead of a source-audit role?
6. **Argument-error rate after consolidation.** Namespaced verbs move complexity from tool-selection into argument-selection. We should measure malformed-argument / rejected-call rates before and after consolidation to confirm the trade is net-positive (cf. the kernel-verify discipline of rejecting malformed submissions without spending a budget slot).
