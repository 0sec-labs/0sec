---
title: Research
description: How 0sec makes its decisions, what data backs them, and the experiments behind the open cybersecurity harness.
---

0sec is the open cybersecurity harness, built by the Swiss Applied AI Cybersecurity Research Lab. Our approach is evidence-first: a team of AI agents explores a target in parallel, and a separate blind agent reproduces every finding before it counts. This section documents the reasoning and the data behind that design.

The proof is in the real, disclosed CVEs at [0.security](https://0.security) — not vendor benchmarks. Most experiments here run against the [XBOW benchmark](https://github.com/xbow-engineering/validation-benchmarks) (104 Docker CTF challenges) as a reproducible harness.

For benchmark scores, methodology, and competitor comparisons, see the [Benchmarks](/benchmark/) section. For product-facing mechanism docs (agent loop, triage, verification), see [Architecture](/architecture/).

## Essays & rationale

Evergreen writeups on design decisions and techniques that shipped.

### [Shell-First Rationale](/research/shell-first/)

Why bash beats structured tools for pentesting, with A/B test data on prompt length, reasoning effort, tool routing, concurrent subagents, and multi-checkpoint budgets.

### [Agent Techniques](/research/agent-techniques/)

What shipped in the agent loop: early-stop retry, exploit templates, loop detection, context compaction, dynamic playbooks, attack-tree search, strategy racing, and progress handoff.

### [Model Comparison](/research/model-comparison/)

Head-to-head testing of gpt-5.4, Kimi K2.5, Qwen3 Coder, DeepSeek, GLM, and free OpenRouter models. Cost, speed, and flag extraction across multiple XBOW challenges.

### [FP Reduction Moat](/research/fp-reduction-moat/)

The full false-positive reduction stack, measured effects per benchmark slice, why the layers are ordered the way they are, and how the dataset / feature foundation supports the shipped runtime layers.

### [TypeScript/Rust Boundary](/research/typescript-rust-boundary/)

Why 0sec keeps TypeScript for orchestration while moving deterministic engines such as FoxGuard into Rust behind stable contracts.

## Triage ML

Design and reference material for the learned triage pipeline.

### [Finding Triage ML](/research/finding-triage-ml/)

Implementation notes for reachability, consensus verify, PoV generation, memories, adversarial debate, and multi-modal agreement with foxguard.

### [Dynamic Routing Design](/research/dynamic-routing-design/)

A learned per-finding classifier that picks which subset of triage layers to run, motivated by the 2026-04-11 ablation finding that no static policy wins on all three benchmark slices.

### [Dynamic Triage Routing (v0)](/research/dynamic-triage-routing/)

The shipped v0 rule-based router, its four decision rules, the routing-trace dataset shape, and the upgrade path to a learned classifier.

### [Triage Dataset](/research/triage-dataset/)

How benchmark runs and verified findings are converted into labeled JSONL for triage-model training.

### [Feature Extractor](/research/feature-extractor/)

The 45 handcrafted features exposed by `extractFeatures()` and how they fit into the hybrid triage direction.

### [Journal + Orchestrator Design](/research/journal-orchestrator-design/)

Design doc for an append-only execution journal and an orchestrator that separates "what to do next" from "what has been done."

## Experiment logs

Dated, archival records of specific experiments. Kept for transparency and auditability — not necessarily current guidance.

### [2026-05-09 Control Flow, Not Prompts](/research/2026-05-09-control-flow-not-prompts/)

Audit of 0sec's agent loop against the "agents need control flow, not more prompts" thesis, and the five deterministic-chokepoint fixes it produced.

### [2026-05-08 Cost per Flag](/research/2026-05-08-cost-per-flag/)

Why autonomous-pentest reporting should publish a dollar-per-flag axis alongside the solve percentage, and how 0sec computes its number.

### [2026-05-06 HackerOne Program Audit](/research/2026-05-06-h1-ai-readiness/)

Aggregate analysis of 590 HackerOne programs scored on automation policy, scope shape, and Safe Harbor status — where AI pentest agents can actually operate under the May 2026 CoC update.

### [2026-04-11 Triage Ablation Results](/research/2026-04-11-ablation/)

The 21-profile triage ablation with batch-1 and batch-2 numbers, methodology notes, and links to raw run artifacts.

### [XBEN-099 Investigation](/research/xben-099-investigation/)

Root-cause investigation into why XBEN-099 failed on the patched fork and the proposed fix.

### [Unsolved Eight Investigation](/research/unsolved-eight-investigation/)

Source-level investigation into an earlier 8-challenge XBOW holdout set. Useful for exploit-path reasoning, but not the canonical current unsolved list.

## The big picture

0sec is not a template runner or a static analyzer. It is a harness for autonomous agents that think like pentesters — they work in a terminal, explore in parallel, and every finding they report is reproduced by an independent blind agent before it ships. The framework's job is to get out of the model's way and hold the process honest, so that what comes out the other end is a real, reproducible vulnerability.
