# 0sec: Methodology-Aware Evaluation and Cost-Aware Triage for Autonomous Pentesting Agents

**Draft - work in progress.** Not yet submitted.

---

## Abstract

Autonomous pentesting agents are usually communicated through single benchmark percentages. In practice, those percentages are unstable without explicit disclosure of retry protocol, benchmark substrate, model/runtime, turn budget, and evidence policy. We present 0sec, an open-source agentic pentesting framework that combines shell-first exploitation, blind verification, and a layered triage stack, and we frame it as both a systems artifact and a methodology artifact.

0sec reports benchmark evidence in three explicit lines: a model-specific cohort (per-model single-shot solve rate), retained artifact-backed totals (machine-reconstructible union over retained CI artifacts of any model), and historical mixed local+CI publication totals. As of the current public ledger (2026-05-06), the retained artifact-backed XBOW aggregate is 103/104 (99.0%) with 102/104 white-box solves; only XBEN-030 remains unsolved in any mode within the live retention window. The load-bearing black-box claim is the gpt-5.4 model-specific cohort at 93/95 (97.9%) — the retained-aggregate black-box count is rotation-volatile because GitHub Actions retains a 90-day window of run artifacts and older "unknown"-model proofs age out as new model-specific sweeps occupy the window. A first scored full Cybench run (2026-05-06) lands at 36/40 (90.0%) single-config single-shot. A 21-run triage ablation (2026-04-11) shows no static policy dominates across slices: in XBOW white-box, full-moat triage is a precision/recall-cost tradeoff; in XBOW black-box, moat is Pareto-superior to no-triage baselines on findings efficiency and dollars per solved challenge; in npm-bench, moat is close to a no-op over default scaffolding.

The key result is methodological: for non-deterministic autonomous security agents, protocol disclosure and retained-evidence lineage are not reporting accessories; they are part of the core technical contribution.

Code and artifacts: proprietary, 0sec Labs. The GitHub repo is archived and private.

---

## 1. Introduction

"Solved X%" claims for autonomous pentesting agents are only meaningful if the measurement protocol is clear. In this domain, score movement can come from changes in retry protocol, benchmark fork, run budget, model provider, or evidence accounting, even when the underlying agent logic is unchanged.

This draft organizes 0sec around two claims:

1. **Systems claim.** Shell-first tool use plus explicit triage/verification produces practical offensive coverage while controlling noise.
2. **Methodology claim.** Benchmark claims should expose protocol details and uncertainty, and should separate machine-backed evidence from historical publication lines.

### 1.1 Contributions

1. **Reproducible benchmark protocol for non-deterministic agents.** Repeat-N support, Wilson CIs, and cost ceilings are implemented in runner code and documented as first-class methodology.
2. **Machine-auditable benchmark ledger model.** Retained artifact-backed and historical mixed publication lines are separated in a ledger (`benchmark-ledger.json`) instead of merged into one headline.
3. **Productionized multi-layer triage stack.** Deterministic, oracle, and LLM-based layers are implemented behind flags and integrated in the scanner path.
4. **Per-layer verdict telemetry.** Findings can carry layer-by-layer timing/cost/verdict records for offline analysis and future router supervision.
5. **Mode-dependent ablation reporting.** The moat story is reported as measured (tradeoff in white-box, strict win in black-box, weak on npm-bench), including negative results.
6. **Learned routing foundations.** Dataset collection, feature extraction, and learned-router artifacts are in-repo for per-finding triage policy.

---

## 2. System

0sec executes a multi-stage pipeline:

```text
Plan -> Discover -> Attack -> Triage -> Verify -> Report
```

Core implementation entrypoints include `packages/core/src/agentic-scanner.ts` and `packages/core/src/unified-pipeline.ts`.

### 2.1 Shell-first execution

For web targets, 0sec intentionally keeps attack tools minimal (`bash`, `save_finding`, `done`) and treats structured HTTP wrappers as optional. The design hypothesis is that LLM priors over shell and pentest tooling reduce orchestration overhead in multi-step exploit chains.

### 2.2 Triage and blind verification

Findings are post-processed before reporting. Triage layers may pass, downgrade, suppress, or enrich findings; verification stages independently re-check exploitability. The intended effect is to reduce noisy candidate findings without relying on a single opaque model judgment.

### 2.3 Runtime and deployment surface

The same core logic is available through:

- `0sec-cli`,
- Docker image distribution,
- GitHub Action integration,
- multiple runtime adapters (API and subprocess-style runtimes).

---

## 3. Methodology and Evidence Policy

The benchmark methodology is documented in `docs/src/content/docs/methodology.md` and implemented under `packages/benchmark/src/`.

### 3.1 Reporting regimes

0sec differentiates:

- **single-shot** (one attempt per challenge),
- **best-of-K** (challenge solved if any attempt succeeds),
- **repeat-N per-attempt rate** with 95% Wilson CI.

For internal decision-making, repeat-N with CI is treated as more reliable than single-shot or best-of-K anecdotes.

### 3.2 Retained vs historical lines

The benchmark ledger tracks two non-equivalent evidence surfaces:

- **Retained artifact-backed**: union over retained CI artifacts, machine-reconstructible.
- **Historical mixed publication**: older local+CI publication line, preserved for continuity.

Keeping these separate avoids accidental inflation from mixing non-reconstructible history into current machine-backed tallies.

### 3.3 Reproducibility metadata

Interpretable benchmark claims require at least:

- benchmark fork/ref,
- model/runtime selection,
- turn budget and timeout,
- feature/profile flags,
- retry protocol,
- cost ceiling and stop conditions.

---

## 4. Triage Architecture and Routing

Current triage modules are implemented under `packages/core/src/triage/` and summarized in `docs/src/content/docs/triage.md`.

Representative layers include:

1. holding-it-wrong filter,
2. handcrafted feature extraction,
3. reachability gate,
4. multimodal cross-check,
5. category-specific deterministic oracles,
6. PoV gate,
7. structured verify pipeline,
8. self-consistency consensus verify,
9. triage memories,
10. adversarial debate,
11. optional EGATS tree search.

### 4.1 Telemetry and supervision

Recent scanner instrumentation can attach per-layer verdict telemetry to findings (layer, verdict, timing, optional cost/severity changes), enabling supervision for routing policies.

### 4.2 Learned router track

The dynamic-routing direction is documented in `docs/src/content/docs/research/dynamic-routing-design.md`, with model artifacts such as `packages/benchmark/results/triage-router-v2-meta.json`. The motivation is empirical: a static scan-level profile does not optimize all benchmark slices simultaneously.

---

## 5. Empirical Snapshot (As Currently Published)

### 5.1 XBOW benchmark posture (ledger as-of 2026-05-06)

From `packages/benchmark/results/benchmark-ledger.json`:

- gpt-5.4 model-specific cohort (load-bearing black-box claim): **93/95 = 97.9%** — stable, defensible per-model single-shot solve rate at $0.48/run and $5.20/flag,
- retained artifact-backed aggregate (any model): **103/104 = 99.0%** — only XBEN-030 unsolved in any mode within the live retention window,
- retained white-box (any model): **102/104 = 98.1%** — field-leading,
- retained-aggregate black-box (any model): **rotation-volatile (currently 81/104)** — the 90-day GitHub Actions artifact retention window rotates older "unknown"-model proofs out as new gpt-5.4 sweeps occupy the window; the model-specific cohort above is the stable surface for like-for-like comparison,
- historical mixed publication: **95/104 aggregate**, **90/104 black-box** — preserved for continuity.

### 5.2 Cybench benchmark posture (first scored full 40-challenge run, 2026-05-06)

From `packages/benchmark/results/benchmark-ledger.json`:

- 0sec: **36/40 = 90.0%** — single-config (Azure gpt-5.4), single-shot, 3 retries per challenge, 358 attack turns, ~$14.89 estimated cost across the run. 40/40 challenges started successfully (zero startup failures).
- Reference: BoxPwnr's published 40/40 = 100% is best-of-N across ~10 model+solver configs; the comparable single-model number from BoxPwnr is not directly published. 0sec's 36/40 is the closest single-config single-shot result currently in the open literature.

### 5.3 Triage ablation posture (21-run matrix, 2026-04-11)

From `docs/src/content/docs/research/2026-04-11-ablation.md` and `docs/src/content/docs/research/fp-reduction-moat.md`:

- **XBOW white-box (limit=50):** full moat reduces findings volume substantially but costs solved flags versus top no-triage baseline.
- **XBOW black-box (limit=25):** moat matches/improves solved flags while reducing findings and dollars-per-flag versus weaker baselines.
- **npm-bench (81 packages):** moat and default are close; TPR remains high across profiles; slice behavior differs from web benchmarks.

### 5.4 Dataset and router artifacts

From `packages/benchmark/results/triage-dataset-v1.stats.json` and `packages/benchmark/results/triage-router-v2-meta.json`:

- triage dataset v1: **969 samples** (with documented label-source caveats),
- router v2 metadata: **1514 samples**, **55 features**, 5-fold CV mean F1 ~0.962.

These numbers should be treated as intermediate research artifacts, not final deployment claims.

---

## 6. Limitations and Threats to Validity

1. **Benchmark-to-production gap.** CTF-like suites are useful but do not fully represent enterprise environments.
2. **Stochastic variance.** Single-run outcomes can overstate reliability; repeat protocols are mandatory for robust comparisons.
3. **Slice-dependent behavior.** White-box, black-box, and package slices have distinct optimization fronts.
4. **Label noise in package supervision.** Package-level safe/malicious labels can be coarse for per-finding classification.
5. **Cost-performance tradeoff.** Additional triage depth can improve signal but increase latency and spend.
6. **Doc/code drift risk.** Rapid iteration can create temporary mismatch between narrative docs and current implementation details.

---

## 7. Related Work (Short)

Adjacent systems and references cited by 0sec docs include BoxPwnr, Shannon, KinoSec, MAPTA, Endor Labs AI SAST disclosures, Semgrep Assistant disclosures, and hybrid triage approaches (for example VulnBERT-style feature+model fusion).

Long-form notes are split into `docs/paper/related_work.md`.

---

## 8. Reproducibility Pointers

Representative commands:

```bash
pnpm lint
pnpm test
pnpm --filter @0sec/benchmark xbow --help
pnpm --filter @0sec/benchmark xbow --repeat 10 --json
pnpm run consolidate-xbow
```

Primary artifacts and code:

- `docs/src/content/docs/methodology.md`
- `docs/src/content/docs/benchmark.md`
- `docs/src/content/docs/research/2026-04-11-ablation.md`
- `docs/src/content/docs/research/fp-reduction-moat.md`
- `packages/benchmark/results/benchmark-ledger.json`
- `packages/benchmark/results/triage-dataset-v1.stats.json`
- `packages/benchmark/results/triage-router-v2-meta.json`
- `packages/benchmark/src/xbow-runner.ts`
- `packages/benchmark/src/wilson.ts`
- `packages/core/src/agentic-scanner.ts`
- `packages/core/src/triage/`

Detailed evaluation tables are split into `docs/paper/evaluation.md`.

---

## Status

This draft consolidates current architecture, benchmark methodology, and ablation evidence into a submission-shaped narrative. Before any arXiv submission, all claim lines should be revalidated against latest ledger + workflow artifacts and frozen to a specific commit/date.
