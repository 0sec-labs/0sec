---
title: Improvement Plane
description: Evaluate and promote future 0sec worker artifacts without mutating a live engagement.
---

0sec never rewrites its source, dependencies, scope, verifier, or tool
permissions during a live engagement. A target-facing worker consumes untrusted
source, HTTP, MCP, and model output; letting any of that alter the running worker
would break scope control, replay, and evidence provenance.

The improvement plane evaluates a candidate for a **future immutable worker.** It
never deploys a candidate into an active scan.

```text
sealed candidate artifacts
  -> three-lane evaluation receipt
  -> promotion assessment
  -> immutable ledger snapshot
  -> human approval or controlled policy canary
  -> future worker version
```

## Engagement boundary

Every live run stays pinned to its own code, model, policy, scope, and
model-visible tool set; resume and replay reuse that identity. A candidate can be
evaluated while an engagement is active, but it cannot change the active worker.

Non-negotiable:

- no source or dependency installs from target-facing agent output;
- no scope, credential, budget, verifier, or tool-permission expansion mid-run;
- no candidate execution with engagement credentials or production target egress;
- no overwrite of retained evidence;
- no automatic source-code promotion.

Config hot reload is not source mutation. A future signed policy bundle may be
selected at a checkpoint only when the transition is retained in the run lineage;
the current CLI does no live policy promotion.

## Sealed evaluation lanes

[`bench improvement-project`](/benchmark/#offline-0research-projection) projects
three completed champion/challenger tournaments into a sealed result:

1. **Development** — calibration and candidate iteration.
2. **Held-out** — generalization evidence, not tuning evidence.
3. **Negative control** — false-positive tracking on known negatives.

The projection binds corpus, evaluator, candidate, CI, and evidence digests.
Malformed artifacts, symlinks, evaluator drift, corpus drift, case substitution,
and invalid receipts all fail closed.

## Assessing a candidate

After `bench improvement-project` writes `result.json`, bind the champion and
challenger artifacts into a promotion assessment:

```bash
0sec bench improvement-assess \
  --result improvement-bundle/result.json \
  --base-artifact champion-artifact.tar.gz \
  --candidate-artifact challenger-artifact.tar.gz \
  --output-dir promotion-assessment
```

It writes a create-once directory:

```text
promotion-assessment/
  promotion-decision.json
  ledger.json
  COMPLETE
```

The ledger records `candidate_recorded` then `promotion_decided`. Each entry
carries its predecessor digest and its own SHA-256. Keep the terminal digest in
an independent store so cross-store tampering is evident.

Generic artifacts are treated as source changes and get
`requires_human_approval`. There's deliberately no flag that relabels an
arbitrary source artifact as safe policy data.

## Promotion gates

The default policy rejects a candidate unless **every** check passes:

| Gate | Requirement |
| --- | --- |
| Identity | Candidate ID matches the sealed result. |
| Artifact binding | Distinct SHA-256 base and candidate artifacts. |
| CI | Passing retained CI attestation. |
| Evaluator | Identical evaluator digest before and after evaluation. |
| Evidence | At least one retained evidence reference. |
| Sample size | ≥10 observations in every sealed lane. |
| Development lift | ≥ +5 pp success rate. |
| Held-out lift | ≥ +3 pp success rate. |
| Precision | Negative-control FP rate rises by at most 2 pp. |
| Cost | Held-out cost per success at most 1.5× the champion. |

A passing **policy** candidate is only `eligible_for_canary` — not deployed. A
passing **source** candidate always needs explicit human approval. Any failed
check → `rejected`.

## Candidate-worker contract

The assessment command doesn't execute candidate code. A future candidate worker
must be disposable and separate from the engagement plane:

- sealed input artifact and explicit command;
- fresh workspace or VM/container;
- no engagement credentials;
- no production target egress;
- bounded CPU, wall-clock, disk, and model budget;
- retained stdout, stderr, evaluator receipt, and artifact digests;
- promotion decision only, never direct deployment.

This lets 0sec improve from verified experiments without turning
attacker-controlled scan content into persistent control of the harness.

## External hosts

DSH, Codex, and Claude Code are optional MCP clients. They may present a narrow
0sec tool profile, but they don't own promotion, scope, evidence, or replay. See
[Architecture](/architecture/#mcp-integration) and
[Benchmark methodology](/methodology/).
