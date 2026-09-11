---
title: TypeScript/Rust Boundary
description: Why 0sec should keep TypeScript for orchestration while moving deterministic engines such as FoxGuard into Rust behind stable contracts.
---

0sec should use a hybrid TypeScript/Rust architecture:

- **TypeScript owns orchestration.** Agent loops, provider adapters, prompt assembly, event streaming, CLI/cloud contracts, dashboard integration, and JSON-heavy workflows stay where iteration speed is highest.
- **Rust owns engines.** FoxGuard, deterministic analyzers, parsers, sandboxed runners, SARIF/CBOM-heavy transforms, and other hot or trust-sensitive components move behind stable command-line, JSON, SARIF, or native bindings.

## Decision

Keep 0sec's control plane in TypeScript while treating FoxGuard as the first Rust engine in a larger engine boundary. The next milestone is making FoxGuard's default static-lead role measurable enough that Semgrep can stay as an explicit compatibility path instead of the primary source scanner.

<span id="why-typescript-stays-in-the-control-plane"></span>
## TypeScript control plane

0sec's differentiator is agent control flow around evidence:

- provider routing and model quirks
- shell-first execution
- checkpointing and resume
- finding normalization
- triage policy
- benchmark loops
- CLI, docs, and cloud-facing schemas

Those parts change often and sit naturally in the Node/TypeScript ecosystem: OpenAI-compatible SDKs, streaming APIs, npm package inspection, YAML/JSON config, dashboard contracts, and fast test iteration. A Rust rewrite would rebuild the least differentiated layer while slowing down benchmark and product iteration.

<span id="why-rust-should-grow"></span>
## Rust components

Rust is valuable where 0sec needs to be fast, deterministic, memory-safe, and easy to trust locally:

- static lead generation
- AST and manifest parsing
- dependency inventory normalization
- secret scanning
- SARIF/CBOM transforms
- sandbox/process boundary helpers
- large-repo indexing
- kernel and variant-hunting bridges

FoxGuard is the stepping stone. It proves that Rust can own independent static signal while 0sec keeps the orchestration layer flexible.

## Boundary rules

Move a module to Rust when it has most of these properties:

- deterministic input/output behavior
- stable schema boundaries
- heavy file-system, parsing, or indexing work
- meaningful memory-safety or process-isolation value
- reuse outside the TypeScript agent loop
- measurable runtime cost in TypeScript

Keep a module in TypeScript when it has most of these properties:

- provider-specific orchestration
- prompt or policy iteration
- frequent benchmark-driven changes
- UI/cloud/API coupling
- mostly JSON transformation with low runtime cost
- high need for developer velocity

## Rewrite triggers

Revisit a larger Rust port only if one of these becomes true:

- TypeScript runtime overhead is measured as material to scan latency or cost.
- The process/sandbox boundary cannot be made trustworthy from the current architecture.
- Distribution requires a single static binary for the core product, not just for engines.
- A stable Rust engine API has at least two real consumers.
- Cloud and local runners converge on a narrow enough execution contract that orchestration churn drops.

Until then, a full rewrite is premature.

## Near-term plan

1. Keep 0sec's agent and pipeline orchestration in TypeScript.
2. Keep FoxGuard as the default static lead generator while preserving `0SEC_STATIC=semgrep` for comparison and compatibility.
3. Require ablation evidence before removing Semgrep from any additional runtime path.
4. Add Rust engines only behind stable JSON/SARIF contracts.
5. Consider a `0sec-engine` or `0sec-runner` binary after the engine contracts stabilize.

## Product framing

> 0sec combines an autonomous pentest agent with auditable, deterministic local engines.
