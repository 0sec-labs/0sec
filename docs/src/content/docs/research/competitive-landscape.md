---
title: Competitive Landscape
description: Side-by-side comparison of 0sec against other autonomous pentesting agents on the XBOW benchmark, with methodology caveats.
---

How 0sec compares against other autonomous pentesting agents on the [XBOW validation suite](https://github.com/xbow-engineering/validation-benchmarks) (104 Docker CTF challenges). Numbers are each project's public self-reports — cross-project scores are protocol-sensitive and shouldn't be treated as a matched-conditions leaderboard. Current as of May 2026.

> **0sec status (May 2026, wave 2 reframe):** the load-bearing black-box claim is the **gpt-5.4 model-specific cohort at 93/95 = 97.9%** — the stable, defensible per-model solve rate, undamaged by retention rotation. The retained artifact-backed aggregate (any model) is **103/104 = 99.0%** with white-box at **102/104 = 98.1%** (field-leading); only XBEN-030 is unsolved in any mode within the live retention window. The retained-aggregate black-box count (currently 81/104) is rotation-volatile because GitHub Actions retains a 90-day window of run artifacts; older "unknown"-model proofs age out as new gpt-5.4 sweeps occupy the window — the gpt-5.4 cohort number is the right surface for pure-black-box comparison. Cost: gpt-5.4 ≈ **$0.48 / run, $5.20 / flag** on XBOW. Older docs also preserve a historical mixed local+CI publication line of **90/104 black-box** and **95/104 aggregate**; see [Results](/benchmark/) for the exact distinction and challenge-set mismatch.
>
> **Cybench (May 2026):** first scored full 40-challenge run at **36/40 = 90.0%** single-config (Azure gpt-5.4), single-shot. BoxPwnr's published 40/40 = 100% is best-of-N across ~10 model+solver configs.

For 0sec's own score breakdown see [Results](/benchmark/); for the Shannon-specific gap analysis see [XBOW Analysis](/research/xbow-analysis/).

## Competitor breakdown

| Agent | Score | Model | Approach | Cost | Key differentiator |
|-------|-------|-------|----------|------|--------------------|
| [BoxPwnr](https://github.com/0ca/BoxPwnr) | 97.1% (101/104) | Claude, GPT-5, others | Modular shell-first | Unknown | Context compaction + loop detection |
| [Shannon](https://github.com/KeygraphHQ/shannon) | 96.15% (100/104) | Claude Opus/Sonnet/Haiku 3-tier | White-box, multi-agent | ~$50/scan | Source-to-sink taint analysis |
| [KinoSec](https://kinosec.ai) | 92.3% (96/104) | Claude Sonnet 4.6 | Black-box only | Unknown (proprietary) | 50-turn hard cap, pure HTTP |
| [Cyber-AutoAgent](https://medium.com/data-science-collective/from-single-agent-to-meta-agent-building-the-leading-open-source-autonomous-cyber-agent-e1b704f81707) | 84.62% (88/104) | Not disclosed | Single meta-agent | Unknown | Self-rewriting prompts |
| [deadend-cli](https://xoxruns.medium.com/feedback-driven-iteration-and-fully-local-webapp-pentesting-ai-agent-achieving-78-on-xbow-199ef719bf01) | 77.55% (~76/98) | Kimi K2.5 | Single-agent CLI | $122/104 challenges | ADaPT recursive decomposition |
| [MAPTA](https://arxiv.org/abs/2508.20816) | 76.9% (80/104) | GPT-5 | 3-role multi-agent | $21.38 total | Evidence-gated branching |

### BoxPwnr (97.1%)

Current XBOW leader by Francisco Oca (0ca). Modular framework with four components: Orchestrator (run management), Solver (LLM interaction), Executor (Docker sandbox), and Platform (challenge interface). Six solver strategies: `single_loop_xmltag` (default, shell-first), `single_loop`, `single_loop_compactation` (context compaction at 60% window), `claude_code` delegation, `codex` delegation, and `hacksynth` (multi-agent). The default strategy uses XML-tag shell-first execution -- the LLM emits bash commands inside `<COMMAND>` tags, which run in a full Kali Linux Docker container with all security tools pre-installed.

Key techniques: context compaction triggers at 60% window fill (summarize and continue), loop/oscillation detection catches the agent repeating failed commands, and progress handoff between attempts preserves findings across retries. Cost tracking is built into the orchestrator. Supports Claude, GPT-5, DeepSeek, Grok-4, Gemini 3, and Kimi K2.5.

Beyond XBOW, BoxPwnr has solved HTB 250/523 (47.8%), PortSwigger 163/270 (60.4%), Cybench 40/40 (100%), and picoCTF 373/509 (73.3%). The breadth of benchmark coverage across five platforms is unmatched. Notably, the same author created the patched XBOW fork that 0sec uses for its benchmark environment.

### Shannon (96.15%)

13-agent Temporal workflow system. Runs 5 parallel vulnerability+exploit agent pairs (injection, XSS, auth, authz, SSRF), each with 200-400 line domain-specific prompts. The white-box pipeline starts with source-to-sink taint analysis -- 6 pre-recon sub-agents scan architecture, entry points, security patterns, XSS sinks, SSRF sources, and data security before any exploit agent fires. Structured exploitation queues route findings between agents. The 3-tier model strategy uses Opus for planning, Sonnet for exploitation, and Haiku for classification. At ~$50 per scan and 10,000 max turns, Shannon buys accuracy with compute.

### KinoSec (92.3%)

Proprietary black-box agent. Uses Claude Sonnet 4.6 with a hard 50-turn budget. No source code access, no Playwright, pure HTTP. The score is remarkable given the constraints -- it implies near-perfect exploitation efficiency on every challenge it attempts. Closed-source, so architecture details are limited, but the 50-turn cap suggests extremely focused prompt engineering and tool selection.

### Cyber-AutoAgent (84.62%)

The biggest leap on the leaderboard: 46% to 84.62% through architecture changes alone. Single meta-agent with self-rewriting prompts -- the agent modifies its own system prompt based on challenge feedback. Uses a tool router hook to dynamically select tools and mem0 vector memory to persist knowledge across turns. No multi-agent coordination overhead. The self-rewriting prompt mechanism is the standout innovation: the agent literally edits its instructions mid-run.

### deadend-cli (77.55%)

Single-agent CLI using ADaPT (Adaptive Decomposition and Planning for Tasks) recursive decomposition. Breaks complex challenges into sub-tasks, solves them sequentially, and backtracks on failure. Custom Playwright integration with RFC-bypass for browser-based challenges. Runs on Kimi K2.5 at $122 for all 104 challenges ($1.17/challenge). Notable for solving blind SQLi challenges that trip up most agents. Proves you don't need multi-agent to reach 78%.

### MAPTA (76.9%)

Academic 3-role system: coordinator, sandbox executor, and validator. The coordinator plans attack strategy, the sandbox runs exploits in isolation, and the validator checks whether output constitutes a real flag. Evidence-gated branching means the system only pursues exploitation paths backed by concrete evidence from prior steps -- no speculative tool calls. Runs on GPT-5 for $21.38 total across all 104 challenges ($0.21/challenge). Published as a research paper with full methodology.

## 0sec's differentiators

### Reachability gate matches Endor Labs' "Code API" moat (open-source)

Endor Labs' disclosed ~95% false-positive elimination depends on a proprietary "Code API" reachability signal — they check whether a flagged sink is actually callable from an application entry point before they spend LLM tokens on it. 0sec implements the same idea as a zero-dependency grep/pattern-based first pass in `packages/core/src/triage/reachability.ts`. This is the only open-source reachability gate for LLM pentest findings we are aware of. The [2026-04-11 single-feature ablation](/research/2026-04-11-ablation/) found reachability to be the best-performing moat layer on the stubborn-14 slice at $1.61 per flag (+3 flags vs default).

### foxguard × 0sec cross-validation (unique)

Endor Labs' triage accuracy comes from forcing neural + rules to agree. 0sec has the open-source version: for every finding, run [foxguard](https://github.com/0sec-labs/foxguard) (Rust pattern scanner) against the same source tree and require agreement. Both fire → strong signal. Foxguard silent → likely false positive. Nobody else in the open-source pentest-agent space runs a second, independent scanner for cross-validation — this is unique to the 0sec / foxguard / opensoar trinity.

Implementation: `packages/core/src/triage/multi-modal.ts`.

### Artifact-backed XBOW aggregate at 103/104, with a per-model black-box cohort at 97.9%

A single-config single-shot number and a best-of-N union over many configs answer different questions on the same benchmark and are not directly comparable; see [Methodology](/methodology/) for why 0sec publishes both surfaces.

BoxPwnr's headline 97.1% is a best-of-N aggregate across ~10 model+solver configurations (527 traces / 104 challenges ≈ 5 attempts each). Their **best single model (GLM-5 + `single_loop`) scores 81.7%**. 0sec's retained artifact-backed aggregate is **103/104 = 99.0%** with only XBEN-030 unsolved in any mode within the live retention window. The load-bearing black-box surface is the **gpt-5.4 model-specific cohort at 93/95 = 97.9%** — a single-model single-shot solve rate, not a best-of-N aggregate. Cost: ~$0.48 per run, $5.20 per flag.

The retained-aggregate black-box count is rotation-volatile (currently 81/104) because the 90-day GitHub Actions artifact retention window rotates older "unknown"-model proofs out as new gpt-5.4 sweeps land. The gpt-5.4 cohort number is the stable claim; the historical mixed local+CI publication line preserves an older **95/104 aggregate** and **90/104 black-box** for continuity. The benchmark page is the canonical place where those distinctions are spelled out.

## The meta-finding

Architecture matters less than tools + memory + search.

Shannon's 13-agent system scores 96%. Cyber-AutoAgent's single agent with self-rewriting prompts scores 84.62%. MAPTA's 3-agent academic system scores 76.9%. deadend-cli's single agent scores 77.55%.

The common thread across top performers is not agent count. It is:

1. **Tool quality** -- real security tools (sqlmap, Playwright, curl) beat structured wrappers
2. **Memory** -- persisting context across turns (mem0, relay, checkpoints) prevents repeated work
3. **Search** -- exploring multiple exploit paths (tree search, parallel pairs, backtracking) catches what linear execution misses

Shell + external memory can match multi-agent at 7.4% of the cost. Context quality drops past 40% fill -- relay or reset is the fix.

## Evidence-based improvement techniques

Ranked by expected impact and implementation complexity. Estimates based on challenge-level gap analysis against the XBOW benchmark.

| Rank | Technique | Expected impact | Cost multiplier | Status |
|------|-----------|----------------|-----------------|--------|
| 1 | Early-stop + retry at turn 20 | +3-5 flags | 1x | **Shipped** |
| 2 | Blind SQLi script templates | +2-4 flags | 1x | **Shipped** |
| 3 | Patched fork for all 104 challenges | +10-15 flags | 1x | **Shipped** |
| 4 | Context compaction at 60% window | +3-5 flags | 1x | **Shipped** |
| 5 | Loop/oscillation detection | +2-3 flags | 1x | **Shipped** |
| 6 | Dynamic playbooks after recon (13 playbooks) | +3-5 flags | 1x | **Shipped** |
| 7 | EGATS tree search | +5-9 flags | 2-3x | **Shipped** |
| 8 | Best-of-N strategy racing | +5-8 flags | 3x | **Shipped** |
| 9 | Progress handoff on retry | +3-5 flags | 1x | **Shipped** |
| 10 | Reachability gate | FP reduction | 1x | **Shipped** |
| 11 | foxguard multi-modal agreement | FP reduction | 1x | **Shipped** |
| 12 | Consensus (self-consistency) verify | FP reduction | Nx verify cost | **Shipped** |
| 13 | Triage memories (Semgrep-style) | FP reduction | 1x | **Shipped** |
| 14 | PoV gate | FP reduction | 1x | **Shipped** |
| 15 | External working memory | +2-3 flags | 1x | Planned |
| 16 | RAG from prior solves | +2-4 flags | 1x | Planned |
| 17 | Adversarial debate verification | FP reduction | 2x verify cost | **Shipped** |

### Shipped

**Early-stop + retry at turn 20.** When the agent has not made progress by turn 20, kill the run and restart with a fresh context window. Prevents the agent from burning 80 turns on a dead-end approach. Based on MAPTA's finding that 40 tool calls is the sweet spot -- if you're halfway through with nothing, reset.

**Blind SQLi script templates.** Pre-built exploitation scripts for time-based and boolean-based blind SQL injection. The agent injects these into the shell rather than trying to write sqlmap commands from scratch. deadend-cli's blind SQLi solves motivated this -- the challenge type has high variance without templates.

**Patched XBOW fork for broad 104-challenge coverage.** Several XBOW challenges had environment bugs (broken Docker configs, missing dependencies, timing issues). The patched fork removes most of that infrastructure drag and is still the right substrate for the 104-challenge suite, but individual cases like XBEN-099 still needed separate investigation on top. This is still one of the highest-impact changes: +10-15 flags from challenges that were previously unsolvable due to benchmark bugs.

**Loop/oscillation detection.** Detects when the agent is repeating the same failed commands or oscillating between two ineffective approaches. When a loop is detected, the agent is forced to change strategy or escalate. Based on BoxPwnr's oscillation detection mechanism, which catches the most common failure mode in long-running pentesting sessions -- the agent trying the same exploit with minor variations indefinitely.

**Context compaction at 60% window.** When the context window reaches 60% capacity, summarize the current state (discovered endpoints, credentials, attack progress) and continue with a compacted context. Prevents the quality degradation that occurs past 40-60% fill. Based on BoxPwnr's `single_loop_compactation` solver, which triggers compaction at 60% and has proven effective across hundreds of challenges. More aggressive than the originally planned 30k-token relay -- compaction preserves the full conversation thread rather than doing a hard reset.

**Dynamic playbooks after recon.** `packages/core/src/agent/playbooks.ts` — 13 playbooks (sqli, ssti, idor, xss, ssrf, lfi, auth_bypass, blind_exploitation, cve_exploitation, command_injection, deserialization, request_smuggling, creative_idor). `detectPlaybooks()` matches tool-result text against per-type patterns and injects at most 3 into the conversation. The XSS playbook alone cracked XBEN-011 and XBEN-018.

**EGATS tree search.** `packages/core/src/agent/egats.ts` — evidence-gated attack tree search. Each node is a hypothesis; a mini agent loop gathers evidence; only branches whose evidence score clears the threshold are expanded. Beam search keeps the top-K branches per level.

**Best-of-N strategy racing.** `packages/core/src/racing.ts` — runs the same target with multiple different strategies in parallel (aggressive, methodical, creative, each with its own system-prompt override and temperature hint), takes the first vulnerability. Inspired by BoxPwnr running ~10 solver configs.

**Progress handoff.** `packages/core/src/agent/native-loop.ts` + `agentic-scanner.ts` — the prior attempt's structured progress (endpoints, credentials, confirmed vulns, failed approaches, tech stack) is injected into the retry's "Prior Attempt Results" section.

**Reachability gate.** `packages/core/src/triage/reachability.ts` — suppresses findings whose sink is not reachable from an application entry point. The open-source version of Endor Labs' "Code API" moat.

**foxguard multi-modal agreement.** `packages/core/src/triage/multi-modal.ts` — for every 0sec finding, run foxguard against the same source tree and require agreement before auto-accepting. Endor Labs' rules-plus-neural architecture, open-source.

**Consensus (self-consistency) verification.** `packages/core/src/triage/verify-pipeline.ts` — `runSelfConsistencyVerify` runs the structured verify pipeline N times in parallel, takes the majority vote, with early termination when a verdict locks up an unreachable lead.

**Triage memories.** `packages/core/src/triage/memories.ts` — Semgrep-style per-target persistent FP context. User marks a finding as FP with a reason; the reason becomes a `TriageMemory` scoped to `global`, `package`, or `target`. Strong matches auto-reject future findings without any LLM call.

**PoV gate.** `packages/core/src/triage/pov-gate.ts` — a narrowly-scoped mini agent loop must produce a concrete executable exploit; no PoV → severity downgrade to `info`. Based on "All You Need Is A Fuzzing Brain" (arXiv:2509.07225).

**Adversarial debate verification.** `packages/core/src/triage/adversarial.ts` — prosecutor vs. defender agents debate each finding with fresh contexts; a skeptical judge decides. Based on Anthropic's debate paper (arXiv:2402.06782). The point is uncorrelated error modes vs. single-pass verify.

### Planned

**External working memory.** Persist structured notes (discovered endpoints, credentials, observed behaviors) in a memory store the agent can query. Prevents the agent from re-discovering information it already found. Inspired by Cyber-AutoAgent's mem0 integration.

**RAG from prior solves.** Build a vector index of successful exploit chains from prior runs. When the agent encounters a similar challenge, retrieve relevant prior solves as context. Bootstraps experience without increasing the model's context window.

## Key research papers

| Paper | Reference | Key finding for 0sec |
|-------|-----------|----------------------|
| Meta-analysis of AI pentesting agents | arXiv:2602.17622 | Architecture matters less than tools + memory + search |
| MAPTA | arXiv:2508.20816 | 3-role system with evidence-gated branching, 40 tool calls is the sweet spot, $0.21/challenge |
| Co-RedTeam | Published 2025 | Multi-agent red teaming with shared memory improves coverage |
| TermiAgent | Published 2025 | Terminal-native agents outperform structured-tool agents on security tasks |
| CurriculumPT | Published 2025 | Curriculum learning for penetration testing -- easy challenges first improves hard-challenge performance |
| CHAP | NDSS 2026 | Challenge-aware heuristic attack planning, presented at top security venue |

The meta-analysis (arXiv:2602.17622) is the most directly relevant. Its core claim -- that the combination of tool quality, memory persistence, and search breadth predicts performance better than agent count or model choice -- aligns with 0sec's shell-first philosophy. The paper surveyed all major agents on the XBOW benchmark and found that single-agent systems with good tools consistently outperform multi-agent systems with mediocre tools.

MAPTA's evidence-gated branching is the clearest academic validation of "don't speculate, verify." Their system refuses to pursue an exploitation path unless prior steps produced concrete evidence. This is the principle behind 0sec's early-stop mechanism: if you haven't found evidence of progress by turn 20, you're speculating.

CHAP at NDSS 2026 introduces challenge-aware heuristic planning -- the agent classifies the challenge type before attacking and selects a heuristic attack plan. This is the academic version of 0sec's planned dynamic playbooks feature.

## What we've shipped

### Attack-phase techniques
| Feature | Based on | Notes |
|---------|----------|-------|
| Early-stop + retry | MAPTA turn budget data | `native-loop.ts`, `agentic-scanner.ts` |
| Blind SQLi templates | deadend-cli | `prompts.ts` |
| Patched XBOW fork | Challenge-level bug analysis | +10-15 flags |
| Shell-first architecture | TermiAgent, meta-analysis | Foundation -- 7.4% cost of multi-agent |
| Loop detection | BoxPwnr oscillation detection | `native-loop.ts` |
| Context compaction (LLM-based, multi-recompaction) | BoxPwnr | `native-loop.ts` |
| Dynamic playbooks (13 types) | CurriculumPT, Cyber-AutoAgent | `agent/playbooks.ts` |
| EGATS attack tree search | MAPTA | `agent/egats.ts` |
| Best-of-N strategy racing | BoxPwnr | `racing.ts` |
| Progress handoff on retry | BoxPwnr | `native-loop.ts`, `agentic-scanner.ts` |

### Triage-stage techniques (FP reduction moat)
See [FP Reduction Moat](/research/fp-reduction-moat/) for the full stack and published numbers.

| Feature | Based on | Notes |
|---------|----------|-------|
| Holding-it-wrong filter | Internal CVE-hunt analysis | `triage/holding-it-wrong.ts` |
| Feature extractor (45 features) | VulnBERT hybrid | `triage/feature-extractor.ts` |
| Reachability gate | Endor Labs "Code API" moat | `triage/reachability.ts` |
| Per-class exploit oracles | MAPTA evidence-gated branching | `triage/oracles.ts` |
| foxguard multi-modal agreement | Endor Labs rules+neural | `triage/multi-modal.ts` |
| Structured 4-step verify | GitHub Security Lab taskflow-agent | `triage/verify-pipeline.ts` |
| Consensus (self-consistency) verify | Self-consistency decoding | `triage/verify-pipeline.ts` |
| PoV gate | Fuzzing Brain (arXiv:2509.07225) | `triage/pov-gate.ts` |
| Triage memories | Semgrep Assistant | `triage/memories.ts` |
| Adversarial debate | Anthropic Debate (arXiv:2402.06782) | `triage/adversarial.ts` |

## What's next

**Near-term:**
- External working memory — agent writes plan/creds to disk, injected at reflection checkpoints
- Layer 2 CodeBERT fine-tune on D2A labels

**Medium-term:**
- RAG from prior solves — requires a corpus of successful runs to bootstrap
- Tree-sitter-based interprocedural reachability to replace the grep-based first pass
