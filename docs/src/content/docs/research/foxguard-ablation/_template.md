---
title: "Foxguard ablation — template"
description: "Methodology, slices, metrics, and validation gate for evaluating Foxguard as the default source-code static analyzer."
draft: true
---

> **Template.** Copy this file to a dated artifact log
> (`YYYY-MM-DD-<slice>.md`) when you run an ablation. The dated file is
> the published record; this template stays as the methodology spec.
>
> The first dated artifact in this folder is the empty baseline
> [`2026-05-22-baseline.md`](./2026-05-22-baseline.md), filled with
> `<pending>` markers and committed alongside the harness so the validation
> gate has an honest starting point.

## Why

Foxguard is now the default source-code static lead generator, with
Semgrep preserved as `PWNKIT_STATIC=semgrep` for compatibility and
comparison. Foxguard claims 5–22× speed-up on framework-sized repos
and ships 170+ built-in rules across 11 languages. Before removing any
additional Semgrep runtime path, we measure.

This page describes the methodology. It is **not** the result. Results
live in the dated sibling files in this folder.

## What is *not* on the table

- Removing semgrep from any other call site (`audit.ts`, `review.ts`,
  agent shell allowlist, `/disclose` canary verify). Out of scope.
- Tracking Foxguard's `main` branch. Out of scope — we pin to a
  specific release (see `FOXGUARD_PINNED_TAG` in
  `packages/core/src/shared-analysis.ts`).
- Removing Semgrep from the agent shell allowlist. Even if Foxguard
  is the default static lead generator, Semgrep remains a useful
  operator-invoked fallback while model verb recall and rule coverage
  are still being measured.

## Slices

Three slices, all reproducible locally via
`packages/benchmark/scripts/foxguard-ablation.mjs`:

| Slice | Why this slice | Target |
|---|---|---|
| `self-scan` | TS/JS in the language families pwnkit ships in. Catches regressions from our own dogfood. | pwnkit repo itself. |
| `xbow-bb-wave` | PHP-heavy black-box wave. PHP/Java sink coverage in Foxguard's built-ins is the open question from pwnkit#254. | `0ca/xbow-validation-benchmarks-patched` BB wave. |
| `npm-bench-wave` | JS taint focus on a known-truth corpus. | First 9 packages of npm-bench (3 malicious, 3 vulnerable, 3 safe). |

The sample sizes are small on purpose — this is a *validation gate*, not a
benchmark publication. If the gate passes, we run the full ablation
matrix and publish numbers like the
[2026-04-11 triage ablation](/research/2026-04-11-ablation/) page.

## Metrics

Per slice, per static-analyzer (`semgrep` and `foxguard`):

| Metric | Captured by | Why it matters |
|---|---|---|
| Total findings | `report.semgrepFindings` (count) | Crude noise indicator. |
| Confirmed findings | `report.findings.filter(status='confirmed').length` | The actual triage value — what survives the agent verify wave. |
| Wall time | Harness `Date.now()` deltas | Promotion gate input. |
| FP rate (sampled) | Hand-labelled `perFindingForLabel[].label` | Honest precision number. Operator reviews each row and sets `label` to `true-positive`, `false-positive`, or `needs-context`. |

The hand-labelling step is the load-bearing one. The harness emits
JSON with `label: "<pending>"` per finding so missing labels grep
loudly. Until every row is labelled, the FP rate column in the
dated artifact stays `<pending>`.

## Validation gate

We keep Foxguard as the default static lead generator **only if both
conditions hold on the source-code slice**:

1. **Confirmed findings ≥ semgrep's confirmed findings** (i.e. we
   don't lose the agent's "this was real" signal).
2. **Wall time ≥ 2× faster** than semgrep on the same slice (the
   speed-up Foxguard sells; anything less makes the default risky.

If either condition fails, we revert the default to Semgrep, close
pwnkit#254 as **evaluated, not defaulted**, and document the failure
mode in a dated artifact.

If conditions pass on `self-scan` but the XBOW BB or npm-bench
slices show category-coverage regressions (PHP sinks missing, JS
taint hops degraded), we still close as evaluated — those slices
exist precisely to catch the "fast but misses things that matter"
failure mode.

## Decision-recording slots

When a dated artifact is published, it must fill these slots:

```markdown
## Result

| Slice | Static | Findings | Confirmed | Wall (s) | FP rate |
|---|---|---:|---:|---:|---:|
| self-scan      | semgrep   | <pending> | <pending> | <pending> | <pending> |
| self-scan      | foxguard  | <pending> | <pending> | <pending> | <pending> |
| xbow-bb-wave   | semgrep   | <pending> | <pending> | <pending> | <pending> |
| xbow-bb-wave   | foxguard  | <pending> | <pending> | <pending> | <pending> |
| npm-bench-wave | semgrep   | <pending> | <pending> | <pending> | <pending> |
| npm-bench-wave | foxguard  | <pending> | <pending> | <pending> | <pending> |

## Decision

- Confirmed-findings gate (≥ semgrep on source-code): <pass | fail>
- Wall-time gate (≥ 2× faster on source-code): <pass | fail>
- Category-coverage gate (no PHP/JS regression): <pass | fail>

**Decision:** <keep foxguard default | revert to semgrep default | further investigation>

**Follow-up issue (if applicable):** pwnkit#<number>
```

## How to re-run

```sh
# Dry-run shows the planned commands without executing them.
node packages/benchmark/scripts/foxguard-ablation.mjs --slice all --dry-run

# Real run — manually triggered, never in CI.
node packages/benchmark/scripts/foxguard-ablation.mjs \
  --slice all \
  --xbow-path ../xbow-validation-benchmarks-patched \
  --npm-bench-cache /tmp/pwnkit-npm-bench-cache
```

The harness writes
`packages/benchmark/results/foxguard-ablation-YYYY-MM-DD.json`. Copy
the relevant numbers into a new dated `.md` file in this folder.

## Pinned Foxguard version

`FOXGUARD_PINNED_TAG` in
[`packages/core/src/shared-analysis.ts`](https://github.com/0sec-labs/pwnkit/blob/main/packages/core/src/shared-analysis.ts)
is the single source of truth. If you bump it, document the bump in a
new dated artifact and re-run the gate.

## Relationship to the TypeScript/Rust boundary

This gate is the first proof point for the hybrid architecture described
in [TypeScript/Rust Boundary](/research/typescript-rust-boundary/):
pwnkit keeps orchestration in TypeScript, while deterministic engines
such as FoxGuard move to Rust behind stable JSON/SARIF contracts.

## Related issues

- pwnkit#254 — sibling runner + ablation (this work)
- pwnkit#116 — prior ablation pattern (egats removal) — informs how
  we structure dated artifacts and the decision-recording slots above
