---
title: Benchmark
description: Public security benchmark results, test conditions, and reproduction commands.
---

Published vulnerability disclosures are listed at [0.security](https://0.security). The CTF results below measure performance on smaller, controlled challenges. Compare scores using the same benchmark fork, model, turn cap, and retry protocol.

<span id="where-0sec-stands-honest-condition-specific"></span>
## Results

| Benchmark | Score | Conditions & caveats |
|-----------|-------|----------------------|
| [XBOW](https://github.com/xbow-engineering/validation-benchmarks) web CTFs | **93 / 95 = 97.9%** black-box | gpt-5.4 model-specific cohort — per-model single-shot solve rate, not a best-of-N union. ~$0.48/run, **$5.20/flag**. |
| [Cybench](https://github.com/andyzorigin/cybench) | **36 / 40 = 90.0%** | First full-suite run, single-config (Azure gpt-5.4), single-shot, 3 retries. BoxPwnr's 40/40 is best-of-N across ~10 configs — not directly comparable. |
| npm audit (81 packages) | **F1 = 0.973** | `none` profile, 100% TPR, FPR 0.11. Self-published ground-truth set; see the [ablation log](/research/2026-04-11-ablation/). |
| AI/LLM suite (10 challenges) | 10 / 10 | Self-authored regression suite, not an independent benchmark. |
| [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench) / [HarmBench](https://www.harmbench.org/) | Not scored yet | Harness built; no published score. |

The XBOW headline uses the gpt-5.4 cohort (93/95). The wider retained-artifact aggregate changes as artifacts rotate. Results below use a single model and configuration; cross-model costs are unpublished. [Methodology](/methodology/) explains per-attempt rates and Wilson confidence intervals.

## Running the canonical harness

`0sec bench run` is the single benchmark orchestrator. Integrations own only suite-specific target lifecycle and official grading; every run still produces the same manifest, attempt receipts, scorecard, tournament, and evidence contract.

```bash
# Core web/source-audit corpus.
0sec bench run --integration core --variants variants.json

# XBOW: Docker lifecycle + fresh per-attempt flag, scored by the shared oracle.
0sec bench run \
  --integration xbow \
  --xbow-path /path/to/xbow \
  --variants variants.json \
  --attempt-policy independent-repeat \
  --pass-at-k 10 \
  --schedule case-major

# CyberGym: official differential oracle, strict one graded submit per task.
0sec bench run \
  --integration cybergym \
  --cybergym-harness /path/to/cybergym \
  --cybergym-subset results/cybergym-fair-v1.subset.txt \
  --variants variants.json
```

`--attempt-policy pass-at-k` is the default and stops a case after proof. `independent-repeat` retains every scheduled fresh attempt for a per-attempt rate. `case-major` interleaves variants by task while keeping Docker and CyberGym execution serial.

Cybench, npm audit, AutoPenBench, and HarmBench retain their specialized suite commands until they are migrated through the same integration contract.

## Related

- **[0.security](https://0.security)**
- [Methodology](/methodology/) — per-attempt rate, Wilson CI, single-model caveats
- [XBOW Analysis](/research/xbow-analysis/) — how the XBOW score is built, and its limits
- [Competitive Landscape](/research/competitive-landscape/) — where other agents sit, briefly