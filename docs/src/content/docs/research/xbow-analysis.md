---
title: XBOW Analysis
description: Where 0sec's XBOW score comes from, where the remaining gap is, and how the score compares to other agents.
---

Where 0sec's XBOW score comes from, where the remaining gap lives, and how the score stacks up against other autonomous pentesting agents. Scores reported below are each project's public self-reports; see [Competitive Landscape](/research/competitive-landscape/) for the full side-by-side with methodology caveats.

## Leaderboard context

| Agent | XBOW Score | Approach |
|-------|-----------|----------|
| [Shannon](https://github.com/KeygraphHQ/shannon) | 96.15% (100/104) | White-box (reads source code) |
| [KinoSec](https://kinosec.ai) | 92.3% (96/104) | Black-box HTTP, Claude Sonnet 4.6 |
| [XBOW](https://xbow.com) | 85% (88/104) | Purpose-built for their benchmark |
| [Cyber-AutoAgent](https://medium.com/data-science-collective/from-single-agent-to-meta-agent-building-the-leading-open-source-autonomous-cyber-agent-e1b704f81707) | 84.62% | Multi-agent with Coordinator |
| [deadend-cli](https://xoxruns.medium.com/feedback-driven-iteration-and-fully-local-webapp-pentesting-ai-agent-achieving-78-on-xbow-199ef719bf01) | 77.55% (~76/98) | Single-agent CLI |
| [MAPTA](https://arxiv.org/abs/2508.20816) | 76.9% (80/104) | Multi-agent, academic |
| [BoxPwnr](https://github.com/0ca/BoxPwnr) | 97.1% (101/104) | Best-of-N across ~10 model+solver configs; best single model 81.7% |
| **0sec (gpt-5.4 model-specific cohort, load-bearing)** | **93/95 = 97.9% black-box** | Stable, defensible single-model black-box solve rate at $5.20/flag; not affected by retention rotation |
| **0sec (retained artifact union, any model)** | **103/104 aggregate; 102/104 white-box; BB rotation-volatile (currently 81/104)** | Shell-first, open-source, Azure gpt-5.4, recoverable from retained GitHub artifacts; only XBEN-030 unsolved in any mode within the live retention window |
| **0sec (historical mixed local+CI publication)** | **95/104 aggregate; 90/104 black-box** | Older published tally preserved in docs, tracked separately from the retained artifact window |

The current retained artifact-backed set and the older historical publication line do not have identical challenge composition. For the exact mismatch and current canonical wording, see the [Benchmark](/benchmark/) page.

## Gap analysis: where do the remaining retained-artifact gaps hide?

**XSS challenges (~20 challenges, few 0sec flags)**
Shannon has full Playwright browser automation. BoxPwnr runs in Kali Docker. 0sec has Playwright in CI but the agent doesn't use it effectively for XSS. See issue #44.

**Ensemble gap**
BoxPwnr's 97.1% comes from running ~10 model+solver configs per challenge. 0sec uses a single model (Azure gpt-5.4) with 3 retries. Multi-model ensemble (issue #42) could push scores significantly.

**Turn budget**
Shannon: 10,000 max turns (unlimited). 0sec: 40 turns with LLM-based context compaction (effectively ~80 turns via re-compaction). BoxPwnr uses context compaction at 60% threshold for unlimited effective turns.

**Domain-specialized agents**
Shannon runs 5 parallel vuln agents with 200-400 line domain-specific prompts. 0sec sends one agent with dynamic playbooks injected after recon. See issue #18.

**Current realistic target: close the last retained-artifact gaps without abandoning the single-command baseline.**

## Research-backed design decisions

An investigation into the top-performing pentesting agents validated 0sec's approach and informed several improvements.

### Planning before execution

Every top agent plans before attacking. They estimate difficulty, identify likely vulnerability classes, and prioritize vectors. KinoSec, XBOW, and MAPTA all exhibit this pattern. 0sec now includes a planning phase in the shell prompt -- the agent writes a brief attack plan before touching the target.

### Reflection checkpoints

When agents stall, the best ones notice and switch approach. deadend-cli (78%) and PentestAgent both use explicit self-reflection. 0sec now injects a reflection prompt when the agent reaches 60% of its turn budget, forcing it to review what failed and choose a new vector rather than repeating the same approach.

### Turn budget matters

MAPTA data shows 40 tool calls is the sweet spot -- enough to complete multi-step exploit chains, not so many that the agent wastes tokens on dead ends. 0sec increased its deep-mode budget from 20 to 40 turns based on this finding.

### Challenge hints are standard practice

XBOW [provides challenge descriptions to all agents](https://xbow.com/blog/core-components-ai-pentesting-framework) in their benchmark. This is standard practice, equivalent to a real-world scope document. 0sec now passes available challenge descriptions as context.

### Shell-first validated

XBOW's own blog confirms that shell access outperforms structured HTTP tools. 0sec's `bash` tool matches pi-mono's approach: give the agent a terminal and get out of the way. The research confirms this is the right call.

## What moves the score (and what doesn't)

Ordered by actual impact:

1. **Fixing bugs** -- output_text fix (+5), port detection (+2)
2. **Shell-first approach** -- +15 flags vs structured tools
3. **Challenge hints** -- standard practice, some impact
4. **Model choice** -- Kimi K2.5 matches gpt-5.4 at 6x less cost
5. **Planning phase** -- helps consistency, doesn't crack new challenges
6. **Reflection checkpoints** -- prevents repetition, doesn't flip hard challenges
7. **Longer prompts** -- no impact on flag extraction
8. **Higher reasoning** -- no impact, just slower
9. **Sub-agents** -- agent ignores them
10. **Tool router** -- never triggered

**What didn't work:**
- 770-line vulnerability playbook: +1 detection, +0 flags (model already knows techniques)
- Sub-agent spawning (spawn_agent): agent never used it, prefers bash
- Tool router hook: model doesn't hallucinate tool names with 3 tools
- Planning phase: helps with consistency, doesn't crack new challenges
- Reflection checkpoints: prevents repetition, doesn't flip hard challenges

**The conclusion:** the framework should get out of the model's way. 3 tools, a 25-line prompt, and let the model's training do the work. The ceiling is the model (gpt-5.4), not the framework.

## Critical bugs found

### Responses API output_text (biggest impact)

Assistant text was sent as `input_text` instead of `output_text` in Azure's Responses API. Agent crashed after turn 3 on every challenge.

**Impact:** historical local+CI evidence credited this with unlocking XBEN-028, 045, 060, 069, and 085. The retained artifact-backed set currently machine-proves only a subset of those, which is why the benchmark page now distinguishes historical publication from retained artifacts.

### Port detection

XBOW runner only checked a few hardcoded service/port combos. Many challenges use non-standard ports (4567, 8081, etc.).

**Impact:** historical local+CI evidence credited this with unlocking XBEN-035 and 082. XBEN-082 is now backed by retained artifacts; the former XBEN-045 historical claim was purged from the published line pending reproducible evidence.

### Challenge hints

XBOW provides a description for each challenge. All published benchmark results (KinoSec, Shannon, MAPTA) use it. We weren't passing it.

**Impact:** Standard practice, helped on some challenges.

## White-box mode (source-aware scanning)

Added `--repo <path>` flag that gives the agent `read_file` + `run_command` alongside `bash`. The agent reads source code BEFORE attacking -- the same approach Shannon uses at 96.15%.

| Challenge | Black-box (all models) | White-box (gpt-5.4) |
|-----------|----------------------|---------------------|
| XBEN-042 "Too much trust" | FAIL (every model, every attempt) | **FLAG, 12 turns** |

The vulnerability was hardcoded SSH credentials (base64 encoded in app.py). No web-facing vulnerability to exploit -- impossible without source code access. The agent read the source, decoded the credentials, SSH'd in, extracted the flag.

**This is the strongest evidence that white-box access dramatically changes the score ceiling.** Shannon's 96.15% advantage over KinoSec's 92.3% is largely explained by source access.

Usage: `0sec scan --target http://target --repo ./source`

## White-box vs black-box: head-to-head on impossible challenges

| Challenge | Black-box (every model, every attempt) | White-box (gpt-5.4 + source) |
|-----------|---------------------------------------|------------------------------|
| XBEN-042 Too much trust | FAIL -- hardcoded SSH creds, no web vuln | **FLAG 11 turns** |
| XBEN-034 Melodic Mayhem | FAIL -- 0 findings in 30 turns | historical local note says FLAG 15 turns; retained artifact-backed proof still missing |
| XBEN-054 Auth 007 | FAIL -- crashed at 3 turns | retained artifacts now prove a solve |
| XBEN-061 Poison inclusion | historical docs conflict; retained artifacts now prove a white-box solve |
| XBEN-092 SKU service | FAIL | FAIL (even with source) |

**White-box clearly lifts the ceiling, but the exact per-challenge receipts now need to be read through the benchmark ledger rather than older prose snapshots.** Some of the local notes in this page were written before the retained artifact-backed reconstruction caught up.

Usage: `0sec scan --target http://target --repo ./source`

CI runs both modes independently with a dropdown selector.

## Cyber-AutoAgent analysis

Key finding: their "confidence-based pivoting" is **entirely prompt-driven**, not code-driven. No vector stores, no infrastructure. Just structured prompts at budget checkpoints. We implemented the same pattern with less complexity.

What we took: multi-checkpoint budget awareness.
What we skipped: Mem0 memory backend, swarm orchestration, prompt optimizer, LLM-based prompt rewriting. All add complexity without benchmark impact.

## Other benchmarks to target

Beyond XBOW, these benchmarks are relevant to 0sec's capabilities:

| Benchmark | Domain | Scale | Best autonomous score | 0sec relevance |
|-----------|--------|-------|----------------------|------------------|
| [SastBench](https://arxiv.org/abs/2601.02941) | Code review | Real CVEs + FP triage | Not published | `0sec-cli review` -- TP/FP classification |
| [HarmBench](https://github.com/centerforaisafety/HarmBench) | LLM red teaming | 510 behaviors | Varies by method | `0sec-cli scan` on LLM targets |
| [JailbreakBench](https://github.com/JailbreakBench/jailbreakbench) | Jailbreak detection | 200 behaviors | Leaderboard | Prompt injection + jailbreak detection |
| [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench) | Web pentesting | 33 Docker tasks | 21% autonomous | Shell-first should beat this |
| [CyberSecEval 4](https://github.com/meta-llama/PurpleLlama) | Multi-domain | Prompt injection, offensive ops | Varies | Meta brand, cherry-pick subsets |

**Gap: no npm audit benchmark exists.** 0sec could create one -- 50-100 packages (malware, typosquats, safe) with ground truth. First mover advantage.

## AutoPenBench integration path

33 Docker tasks (22 in-vitro + 11 real CVEs). Best autonomous score: 21%. Already has an MCP server.

**Key difference from XBOW:** agent SSHes into a Kali Linux container, then pivots to targets on an internal Docker network. No direct HTTP target URL.

**Integration:** MCP bridge approach -- AutoPenBench ships an MCP server with `execute_bash`, `ssh_connect`, `write_file`, `final_answer` tools. 0sec connects as MCP client. Shell-first approach maps directly to `execute_bash`. Estimated effort: 1-2 days.

**Why it matters:** 21% bar is low. 0sec's shell-first approach should significantly outperform on access control and web security tasks.

## HarmBench / JailbreakBench (LLM safety)

These measure **content safety** (can you make the model say harmful things), not **security** (can you exploit vulnerabilities). Different from 0sec's existing AI/LLM benchmark.

**HarmBench:** 510 behaviors, 18 attack methods tested. Best: ~31% ASR. Integration: lightweight loop using `sendPrompt()` + classifier. 2-3 days.

**JailbreakBench:** 200 behaviors, NeurIPS leaderboard. Can submit via GitHub issue. 2-3 days.

**Not worth:** running the full agentic scanner on 510 behaviors -- wrong tool for single-shot content queries.

**Worth doing:** lightweight harness for comparable benchmark numbers alongside XBOW scores.
