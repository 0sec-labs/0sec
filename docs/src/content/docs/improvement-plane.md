---
title: Improvement Plane
description: Evaluate and promote future 0sec worker artifacts without mutating a live engagement.
---

0sec does not rewrite its source, dependencies, scope, verifier, or tool
permissions during a live engagement. A target-facing worker consumes
untrusted source, HTTP, MCP, and model output; allowing that material to alter
the running worker would break scope control, replay, and evidence provenance.

The improvement plane evaluates a candidate for a **future immutable worker**.
It never deploys a candidate into an active scan.

```text
sealed candidate artifacts
  -> three-lane evaluation receipt
  -> promotion assessment
  -> immutable ledger snapshot
  -> human approval or controlled policy canary
  -> future worker version
```

## Engagement boundary

Every live run remains pinned to its own code, model, policy, scope, and
model-visible tool set. Resume and replay use that retained identity. A new
candidate can be evaluated while an engagement is active, but it cannot change
the active worker.

The non-negotiable boundaries are:

- no source or dependency installation from target-facing agent output;
- no scope, credential, budget, verifier, or tool-permission expansion during a
  run;
- no candidate execution with engagement credentials or production target
  egress;
- no overwrite of retained evidence;
- no automatic source-code promotion.

Configuration hot reload is not source mutation. A future signed policy bundle
may be selected at a checkpoint only when its transition is retained in the run
lineage; the current CLI does not perform live policy promotion.

## Sealed evaluation lanes

[`bench improvement-project`](/benchmark/#offline-0research-projection) already
projects three completed champion/challenger tournaments into a sealed result:

1. **Development** — calibration and candidate iteration.
2. **Held-out** — generalization evidence, not tuning evidence.
3. **Negative control** — false-positive tracking on known negatives.

The projection binds corpus, evaluator, candidate, CI, and evidence digests.
Malformed artifacts, symlinks, evaluator drift, corpus drift, case substitution,
and invalid receipts fail closed.

## Assessing a candidate

After `bench improvement-project` produces `result.json`, bind the champion and
challenger artifacts into a promotion assessment:

```bash
0sec bench improvement-assess \
  --result improvement-bundle/result.json \
  --base-artifact champion-artifact.tar.gz \
  --candidate-artifact challenger-artifact.tar.gz \
  --output-dir promotion-assessment
```

The command writes a create-once directory:

```text
promotion-assessment/
  promotion-decision.json
  ledger.json
  COMPLETE
```

The ledger records `candidate_recorded` followed by `promotion_decided`. Each
entry contains its predecessor digest and its own SHA-256 digest. Retain the
terminal digest in an independent store to make cross-store tampering evident.

Generic artifacts are treated as source changes and receive
`requires_human_approval`; the CLI deliberately has no flag that can relabel an
arbitrary source artifact as safe policy data.

## Promotion gates

The current default policy rejects a candidate unless every check passes:

| Gate | Requirement |
| --- | --- |
| Identity | Candidate ID matches the sealed result. |
| Artifact binding | Distinct SHA-256 base and candidate artifacts. |
| CI | Passing retained CI attestation. |
| Evaluator | Identical evaluator digest before and after evaluation. |
| Evidence | At least one retained evidence reference. |
| Sample size | At least 10 observations in every sealed lane. |
| Development lift | At least +5 percentage points success rate. |
| Held-out lift | At least +3 percentage points success rate. |
| Precision | Negative-control false-positive rate rises by at most 2 percentage points. |
| Cost | Held-out cost per success is at most 1.5× the champion. |

A passing **policy** candidate is only `eligible_for_canary`; it is not
deployed. A passing **source** candidate always requires explicit human
approval. Any failed check produces `rejected`.

## Candidate-worker contract

The assessment command does not execute candidate code. A future candidate
worker must be disposable and separate from the engagement plane:

- sealed input artifact and explicit command;
- fresh workspace or VM/container;
- no engagement credentials;
- no production target egress;
- bounded CPU, wall-clock, disk, and model budget;
- retained stdout, stderr, evaluator receipt, and artifact digests;
- promotion decision only, never direct deployment.

This separation lets 0sec improve from verified experiments without turning
attacker-controlled scan content into persistent control of the security
harness.

## External hosts

DSH, Codex, and Claude Code are optional MCP clients. They may present a narrow
0sec tool profile, but they do not own promotion, scope, evidence, or replay.
See [Architecture](/architecture/#mcp-integration) and
[Benchmark methodology](/methodology/) for host and repeated-run controls.
