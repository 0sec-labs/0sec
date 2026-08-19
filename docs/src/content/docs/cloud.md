---
title: pwnkit cloud
description: How the managed pwnkit cloud layer relates to the OSS agent and docs site.
---

`pwnkit cloud` is the managed recurring-run surface built on top of the
public `pwnkit` engine.

The split is intentional:

- `pwnkit` is the OSS execution wedge: CLI, benchmarks, verification
  pipeline, and the public docs in this repo.
- `pwnkit cloud` is the managed layer: recurring scans, authenticated
  targets, operator review, artifact bundles, and orchestration around
  the same engine.

Nothing about the cloud product depends on a private fork of the agent.
The scanner, benchmarks, and core verification logic remain in the OSS
repo.

## What the cloud layer adds

- recurring scans instead of one-off local runs
- orchestration across protected or authenticated targets
- operator workflow for triage and review
- customer-facing evidence packaging
- managed storage and scheduling around the public engine

## What stays public and OSS

- CLI scanning
- benchmarks and methodology
- blind verification
- triage and reporting primitives
- docs for the public engine

This is why the marketing site can cite public benchmark receipts while
the managed layer sells reliability, continuity, and operations.

## Where to read next

- [Adversarial Evals](/adversarial-evals/) for the category framing
- [Architecture](/architecture/) for the public execution model
- [Benchmark](/benchmark/) for public performance and methodology
