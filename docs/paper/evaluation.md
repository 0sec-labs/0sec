# Evaluation Notes for pwnkit Paper Draft

This file is a paper-support companion for `docs/paper/pwnkit.md`.

It consolidates the current measured numbers and their source paths so the
submission draft can quote one canonical table set.

## 1) XBOW Ledger Snapshot (as-of 2026-04-10)

Source: `packages/benchmark/results/benchmark-ledger.json`.

| Surface | Black-box | White-box | Aggregate |
|---|---:|---:|---:|
| Retained artifact-backed | 74/104 | 79/104 | 99/104 |
| Historical mixed publication | 90/104 | 5 white-box-only | 95/104 |

Important note: these are intentionally distinct reporting lines and should not
be merged into one score.

## 2) 2026-04-11 Triage Ablation (21 runs)

Primary sources:

- `docs/src/content/docs/research/2026-04-11-ablation.md`
- `docs/src/content/docs/research/fp-reduction-moat.md`

### 2.1 XBOW white-box (limit=50)

| Profile | Flags | Findings | Cost | USD/flag |
|---|---:|---:|---:|---:|
| none | 43/50 | 67 | 14.34 | 0.33 |
| no-triage | 44/50 | 67 | 17.17 | 0.39 |
| moat-only | 41/50 | 25 | 26.89 | 0.66 |
| moat | 41/50 | 25 | 21.82 | 0.53 |

Interpretation: moat is a precision/recall-cost tradeoff in white-box mode.

### 2.2 XBOW black-box (limit=25)

| Profile | Flags | Findings | Cost | USD/flag |
|---|---:|---:|---:|---:|
| none | 18/25 | 27 | 13.72 | 0.76 |
| no-triage | 19/25 | 34 | 10.37 | 0.55 |
| moat-only | 18/25 | 13 | 11.22 | 0.62 |
| moat | 19/25 | 14 | 10.04 | 0.53 |

Interpretation: moat dominates none on findings efficiency and USD/flag in
black-box mode.

### 2.3 npm-bench (81 packages)

| Profile | F1 | TPR | FPR | Safe correct |
|---|---:|---:|---:|---:|
| none | 0.973 | 1.00 | 0.11 | 24/27 |
| no-triage | 0.964 | 1.00 | 0.15 | 23/27 |
| moat-only | 0.964 | 1.00 | 0.15 | 23/27 |
| moat | 0.956 | 1.00 | 0.19 | 22/27 |
| default | 0.956 | 1.00 | 0.19 | 22/27 |

Interpretation: moat is near no-op over default here; slice behavior differs
from XBOW web slices.

### 2.4 Single-layer isolation on stubborn-14

| Profile | Flags | Delta vs default-ref | Cost | USD/flag |
|---|---:|---:|---:|---:|
| wb-default-ref | 2/14 | - | 7.24 | 3.62 |
| feat-pov | 4/14 | +2 | 9.56 | 2.39 |
| feat-reach | 5/14 | +3 | 8.04 | 1.61 |
| feat-multi | 3/14 | +1 | 7.55 | 2.52 |
| feat-debate | 5/14 | +3 | 13.26 | 2.65 |
| feat-mem | 4/14 | +2 | 13.40 | 3.35 |
| feat-egats | 1/14 | -1 | 15.93 | 15.93 |
| feat-cons | 3/14 | +1 | 8.01 | 2.67 |

Interpretation: `egats` is the clear negative outlier in this slice.

## 3) Triage Dataset and Router Artifacts

### 3.1 Triage dataset v1

Source: `packages/benchmark/results/triage-dataset-v1.stats.json`.

- Total samples: 969
- Label balance: 884 TP / 85 FP (TP fraction 0.912)
- Layer verdict coverage: 44 rows with layer verdicts (instrumentation rollout
  caveat noted in stats file)

### 3.2 Router v2 metadata

Source: `packages/benchmark/results/triage-router-v2-meta.json`.

- Samples: 1514
- Features: 55
- 5-fold CV mean F1: 0.9617
- 5-fold CV mean precision: 0.9604
- 5-fold CV mean recall: 0.9631
- 5-fold CV mean AUC: 0.8924

These are model-selection artifacts, not final deployment efficacy claims.

## 4) Methodology Claims to Keep Tight in Paper

Use wording consistent with current artifacts:

1. "Retained artifact-backed" and "historical mixed publication" are separate
   lines.
2. Prefer "as-of date" snapshots, not timeless claims.
3. Where possible, report per-slice outcomes rather than a single merged score.
4. Treat router metrics as intermediate unless there is a direct online A/B run
   tying router policy to benchmark outcomes.
