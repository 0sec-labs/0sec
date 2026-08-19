---
title: Research
description: Why 0sec uses a shell-first approach, what data backs our decisions, and experiments from building the pentesting agent.
---

This section is the single source of truth for "why we made these decisions and what data backs them up." Most experiments run against the [XBOW benchmark](https://github.com/xbow-engineering/validation-benchmarks) (104 Docker CTF challenges).

For benchmark scores, methodology, and competitor comparisons, see the [Benchmarks](/benchmark/) section. For product-facing mechanism docs (agent loop, triage, verification), see [Architecture](/architecture/).

## Essays & rationale

Evergreen writeups on design decisions and techniques that shipped.

### [Shell-First Rationale](/research/shell-first/)

Why bash beats structured tools for pentesting. Includes A/B test data on prompt length, reasoning effort, sub-agent spawning, tool routing, and multi-checkpoint budgets.

### [Agent Techniques](/research/agent-techniques/)

What shipped in the agent loop: planning, reflection checkpoints, context compaction, dynamic playbooks, progress handoff, and EGATS.

### [Model Comparison](/research/model-comparison/)

Head-to-head testing of gpt-5.4, Kimi K2.5, Qwen3 Coder, DeepSeek, GLM, and free OpenRouter models. Cost, speed, and flag extraction across multiple XBOW challenges.

### [FP Reduction Moat](/research/fp-reduction-moat/)

The full false-positive reduction stack, why the layers are ordered the way they are, and how the dataset / feature foundation supports the shipped runtime layers.

### [TypeScript/Rust Boundary](/research/typescript-rust-boundary/)

Why 0sec should keep TypeScript for orchestration while moving deterministic engines such as FoxGuard into Rust behind stable contracts.

## Triage ML

Design and reference material for the learned triage pipeline.

### [Finding Triage ML](/research/finding-triage-ml/)

Implementation notes for reachability, consensus verify, PoV generation, memories, adversarial debate, and multi-modal agreement with foxguard.

### [Dynamic Routing Design](/research/dynamic-routing-design/)

A learned per-finding classifier that picks which subset of triage layers to run, motivated by the 2026-04-11 ablation finding that no static policy wins on all three benchmark slices.

### [Triage Dataset](/research/triage-dataset/)

How benchmark runs and verified findings are converted into labeled JSONL for triage-model training.

### [Feature Extractor](/research/feature-extractor/)

The 45 handcrafted features exposed by `extractFeatures()` and how they fit into the hybrid triage direction.

## Experiment logs

Dated, archival records of specific experiments. Kept for auditability — not necessarily current guidance.

### [2026-05-06 HackerOne Program Audit](/research/2026-05-06-h1-ai-readiness/)

Aggregate analysis of 590 HackerOne programs scored on automation policy, scope shape, and Safe Harbor status. Where AI pentest agents can actually operate under the May 2026 CoC update, and a platform-side misconfiguration that affects 23 paid programs.

### [2026-04-11 Triage Ablation Results](/research/2026-04-11-ablation/)

The 21-profile triage ablation with batch-1 and batch-2 numbers, methodology notes, and links to raw run artifacts.

### [XBEN-099 Investigation](/research/xben-099-investigation/)

Root-cause investigation into why XBEN-099 fails for 0sec on the patched fork, what Shannon does differently, and the proposed fix.

### [Unsolved Eight Investigation](/research/unsolved-eight-investigation/)

Source-level investigation into an earlier 8-challenge XBOW holdout set. Useful for exploit-path reasoning, but not the canonical current retained-artifact unsolved list.

## The big picture

0sec is not a template runner or static analyzer. It's an autonomous agent that thinks like a pentester. Pentesters use terminals, not GUIs with dropdowns.

The scanner should feel like giving a skilled pentester SSH access. One command. Full autonomy. Real findings with proof.

**The conclusion:** the framework should get out of the model's way. 3 tools, a 25-line prompt, and let the model's training do the work. The ceiling is the model, not the framework.
