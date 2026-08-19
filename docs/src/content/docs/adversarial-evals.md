---
title: Adversarial evals
description: How pwnkit extends its pentest wedge into attack-driven adversarial evaluation for AI systems.
---

`pwnkit` already behaves like an adversarial evaluator in practice.
It attacks systems, attempts exploitation, and only reports what it can support with evidence.

This document makes that category explicit.

## What is already shipped

The category is not hypothetical anymore.

Today the benchmark package already includes concrete adversarial-eval
artifacts for:

- tool misuse through attacker-controlled tool parameters
- indirect prompt injection through untrusted tool output

Those harnesses are synthetic and deterministic on purpose. They give
`pwnkit` a repeatable way to score whether the scanner catches realistic
agent-control failures before we widen the surface further.

## Why this matters

Most AI eval tooling answers:

- did the model produce the expected output?
- did a judge model score the answer well?
- did the trace stay within policy?

Those are useful questions.
They are not enough for high-stakes AI systems.

The harder question is:

> can this system be pushed into unsafe or unauthorized behavior under realistic pressure?

That is where `pwnkit` has a structural advantage.

## Target classes

An adversarial eval mode should focus on:

- LLM / agent HTTP APIs
- MCP servers
- tool-using agent backends
- authenticated staging applications with AI features enabled

## What makes this different from generic evals

- attack-driven, not judge-driven
- exploit/evidence based, not vibes
- built for repeated pressure, not one-shot scoring
- capable of finding real security and control-boundary failures

## Proposed surface

The dedicated adversarial eval surface still builds on the existing wedge.

That means:

- no separate product that ignores the pentest engine
- no generic dashboard-first abstraction
- no degradation into “prompt tests with nicer charts”

Instead, the mode should define:

- a target model for AI systems
- a report format that emphasizes evidence and recurrence
- attack classes and success criteria tuned for agentic systems

## Output differences from a traditional pentest

A traditional vuln report centers on exploitability and severity.

An adversarial eval report should also capture:

- target class and environment
- attack objective
- recurrence across runs
- whether the failure is specific to agent/tool composition
- whether the issue reflects authorization, tool-use, or instruction-hijack failure

## Relationship to pwnkit cloud

`pwnkit` is the public execution wedge.

`pwnkit cloud` is the managed orchestration and recurring-run surface.

The adversarial eval category should be legible on both:

- locally and in CI through `pwnkit`
- as a managed recurring product through `pwnkit cloud`
