"""Multi-run (pass@k) pooling for the ground-truth / post-cutoff CVE evals.

The typed, unit-tested half of ``--repeat N`` — kept in ``src`` alongside
:mod:`zeroverse.groundtruth` so it is checked by ``mypy --strict`` and pytest,
separate from the engine-heavy runners in ``benchmarks/*/run.py``.

Why repeat at all
-----------------
A single pass is a **sample**, not a measurement. The roadmap's motivating
incident: an XBEN-061 solve that vanished on rerun because "the v1 solve was
noise inside a 20-40% per-attempt success rate". Vulnerability discovery is a
search over a huge space, and the same model with the same prompt explores a
different slice each time. One run therefore reports a point on a distribution
and calls it a capability.

Repeating exposes the distribution, and pooling exploits it: run-to-run
*inconsistency* is diversity, and unioning independent runs finds strictly more
than any one of them. This is the same effect Aikido measured in their Aug-2026
CVE benchmark, where DeepSeek V4 Pro went 17/32 on its first pass to 28/32
pooled over three.

The part a recall-only benchmark cannot see
-------------------------------------------
Pooling is **not** free, and the asymmetry is the whole point of this module:

  * On a **vulnerable** item, pooling takes the BEST outcome across runs — any
    single run that reproduced the bug means the pooled operator found it. Union
    of discovery. Recall goes UP with k.
  * On a **clean** item (a ``-DFIXED`` control), pooling takes the WORST outcome
    across runs — a union of findings unions the false alarms too, so one bad
    run in k poisons the pooled result. FP rate also goes UP with k.

So "pool 3 cheap runs instead of 1 expensive run" buys recall and *pays for it
in precision*. A benchmark with no negative controls can only observe the first
half of that trade and will overstate pooling. Our corpora carry matched
``-DFIXED`` controls precisely so both halves are measured here, together.

:func:`pool_report` reports both curves plus a per-attempt success rate with a
Wilson score interval, so a k=1 number can be read as an estimate with a CI
rather than an anecdote.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any

from .groundtruth import (
    CLEAN_CONFIRMED_FP,
    CLEAN_HYP_FP,
    CLEAN_OK,
    VULN_CONFIRMED,
    VULN_HYPOTHESIS,
    VULN_MISS,
    CorpusItem,
    ItemScore,
)

# Bump MINOR for additive fields, MAJOR for removals/renames.
POOLING_SCHEMA_VERSION = "1.0"

# Outcome ranks, worst -> best, for the VULNERABLE side. Pooling takes the max:
# any run that reproduced the bug means the pooled operator found it.
_VULN_RANK = {VULN_MISS: 0, VULN_HYPOTHESIS: 1, VULN_CONFIRMED: 2}

# Outcome ranks, best -> worst, for the CLEAN side. Pooling takes the max of
# BADNESS: any run that cried wolf means the pooled operator cried wolf.
_CLEAN_BADNESS = {CLEAN_OK: 0, CLEAN_HYP_FP: 1, CLEAN_CONFIRMED_FP: 2}


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion — ``(low, high)``.

    Preferred over the normal approximation because the eval runs at small n
    (5 vulnerable items x a handful of repeats) and at proportions near 0 and 1,
    exactly where the naive interval breaks: it produces bounds outside [0, 1]
    and collapses to zero width at p=0 or p=1, which would read as certainty
    from a run that established nothing.

    ``trials == 0`` yields ``(0.0, 0.0)`` — no evidence, not a claim.
    """
    if trials <= 0:
        return (0.0, 0.0)
    if successes < 0 or successes > trials:
        raise ValueError(f"successes {successes} out of range for {trials} trials")
    p = successes / trials
    z2 = z * z
    denom = 1.0 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denom
    margin = (z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials))) / denom
    return (round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4))


@dataclass
class PooledItem:
    """One corpus item's behaviour across ``n_runs`` independent attempts."""

    item_id: str
    label: str
    n_runs: int
    outcomes: list[str]          # per-run outcome, in run order
    pooled_outcome: str          # best (vulnerable) / worst (clean) across runs
    n_hit: int                   # runs that confirmed (vuln) or cried wolf (clean)
    consistent: bool             # every run agreed with the pooled outcome
    flaky: bool                  # hit in >=1 run but not all — the diversity signal

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def pool_item(item: CorpusItem, scores: list[ItemScore]) -> PooledItem:
    """Pool one item's per-run scores.

    ``scores`` must be that item's :class:`ItemScore` from each run, in run order.
    The pooling direction flips on the item's ground-truth label — see the module
    docstring: discovery unions, and so do false alarms.
    """
    if not scores:
        raise ValueError(f"{item.id}: no run scores to pool")
    outcomes = [s.outcome for s in scores]

    if item.is_vulnerable:
        pooled = max(outcomes, key=lambda o: _VULN_RANK.get(o, 0))
        n_hit = sum(1 for o in outcomes if o == VULN_CONFIRMED)
    else:
        pooled = max(outcomes, key=lambda o: _CLEAN_BADNESS.get(o, 0))
        n_hit = sum(1 for o in outcomes if o == CLEAN_CONFIRMED_FP)

    return PooledItem(
        item_id=item.id,
        label=item.label,
        n_runs=len(scores),
        outcomes=outcomes,
        pooled_outcome=pooled,
        n_hit=n_hit,
        consistent=all(o == pooled for o in outcomes),
        flaky=0 < n_hit < len(scores),
    )


@dataclass
class PoolingMetrics:
    """Recall and false-positive curves across k, with per-attempt CIs.

    Read the two ``*_gain`` fields together: they are the two halves of the same
    trade. A pooling strategy is only a win if the recall gain is worth the FP
    gain for the pipeline downstream of it.
    """

    n_runs: int
    n_vulnerable: int
    n_clean: int
    # --- vulnerable side (recall) -----------------------------------------
    per_attempt_confirmed: int       # confirmed finds summed over all runs
    per_attempt_trials: int          # n_vulnerable * n_runs
    recall_per_attempt: float        # pass@1 estimate
    recall_per_attempt_ci95: tuple[float, float]
    recall_pooled: float             # pass@k — found by ANY run
    recall_consistent: float         # confirmed by EVERY run (the stable core)
    recall_gain: float               # pooled - per_attempt
    flaky_items: list[str]           # found in some runs, missed in others
    # --- clean side (the cost of pooling) ---------------------------------
    fp_per_attempt_items: int
    fp_trials: int                   # n_clean * n_runs
    fp_rate_per_attempt: float
    fp_rate_per_attempt_ci95: tuple[float, float]
    fp_rate_pooled: float            # cried wolf in ANY run
    fp_rate_gain: float              # pooled - per_attempt
    flaky_clean_items: list[str]
    items: list[PooledItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["items"] = [i.to_dict() for i in self.items]
        return d


def _safe_div(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def pool_report(items: list[CorpusItem], runs: list[list[ItemScore]]) -> PoolingMetrics:
    """Pool ``runs`` (one scored pass each, same corpus) into the pass@k scoreboard.

    Every run must cover every item — a partial run would silently deflate both
    the recall and the FP curve, so it is rejected rather than tolerated.
    """
    if not runs:
        raise ValueError("no runs to pool")
    n_runs = len(runs)
    per_run_by_id = []
    for idx, run in enumerate(runs):
        by_id = {s.item_id: s for s in run}
        missing = [i.id for i in items if i.id not in by_id]
        if missing:
            raise ValueError(f"run {idx} is missing scores for {sorted(missing)}")
        per_run_by_id.append(by_id)

    pooled = [pool_item(i, [by_id[i.id] for by_id in per_run_by_id]) for i in items]
    by_item = {p.item_id: p for p in pooled}

    vuln = [i for i in items if i.is_vulnerable]
    clean = [i for i in items if not i.is_vulnerable]

    # Vulnerable side.
    attempt_conf = sum(by_item[i.id].n_hit for i in vuln)
    attempt_trials = len(vuln) * n_runs
    recall_attempt = _safe_div(attempt_conf, attempt_trials)
    pooled_conf = sum(1 for i in vuln if by_item[i.id].pooled_outcome == VULN_CONFIRMED)
    consistent_conf = sum(
        1 for i in vuln
        if by_item[i.id].n_hit == n_runs and by_item[i.id].pooled_outcome == VULN_CONFIRMED
    )
    recall_pooled = _safe_div(pooled_conf, len(vuln))

    # Clean side — same arithmetic, opposite sign of desirability.
    fp_attempt = sum(by_item[i.id].n_hit for i in clean)
    fp_trials = len(clean) * n_runs
    fp_rate_attempt = _safe_div(fp_attempt, fp_trials)
    fp_pooled_items = sum(
        1 for i in clean if by_item[i.id].pooled_outcome == CLEAN_CONFIRMED_FP
    )
    fp_rate_pooled = _safe_div(fp_pooled_items, len(clean))

    return PoolingMetrics(
        n_runs=n_runs,
        n_vulnerable=len(vuln),
        n_clean=len(clean),
        per_attempt_confirmed=attempt_conf,
        per_attempt_trials=attempt_trials,
        recall_per_attempt=recall_attempt,
        recall_per_attempt_ci95=wilson_interval(attempt_conf, attempt_trials),
        recall_pooled=recall_pooled,
        recall_consistent=_safe_div(consistent_conf, len(vuln)),
        recall_gain=round(recall_pooled - recall_attempt, 4),
        flaky_items=[i.id for i in vuln if by_item[i.id].flaky],
        fp_per_attempt_items=fp_attempt,
        fp_trials=fp_trials,
        fp_rate_per_attempt=fp_rate_attempt,
        fp_rate_per_attempt_ci95=wilson_interval(fp_attempt, fp_trials),
        fp_rate_pooled=fp_rate_pooled,
        fp_rate_gain=round(fp_rate_pooled - fp_rate_attempt, 4),
        flaky_clean_items=[i.id for i in clean if by_item[i.id].flaky],
        items=pooled,
    )


def representative_scores(
    items: list[CorpusItem], runs: list[list[ItemScore]]
) -> list[ItemScore]:
    """Pick, per item, the REAL :class:`ItemScore` matching its pooled outcome.

    This is what lets pooled results flow through the existing
    :func:`zeroverse.groundtruth.aggregate` scorer instead of growing a second,
    divergent metrics path. Every returned score is an actually-observed run's
    score — nothing is synthesised or averaged — so finding counts and precision
    stay real numbers from a real scan.

    For a vulnerable item that is the best run; for a clean control it is the
    WORST run, so the pooled FP rate reflects the union of false alarms exactly
    as :func:`pool_report` reports it.
    """
    per_run_by_id = [{s.item_id: s for s in run} for run in runs]
    out: list[ItemScore] = []
    for item in items:
        scores = [by_id[item.id] for by_id in per_run_by_id if item.id in by_id]
        if not scores:
            raise ValueError(f"{item.id}: no run scores to pool")
        pooled = pool_item(item, scores)
        out.append(next(s for s in scores if s.outcome == pooled.pooled_outcome))
    return out


def format_pooling_report(m: PoolingMetrics) -> str:
    """Render the pass@k scoreboard as markdown. No hand-edited numbers."""
    lo, hi = m.recall_per_attempt_ci95
    flo, fhi = m.fp_rate_per_attempt_ci95
    lines = [
        f"## Pass@{m.n_runs} pooling ({m.n_vulnerable} vulnerable, {m.n_clean} clean controls)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Recall, per attempt (pass@1) | {m.recall_per_attempt:.1%} "
        f"[{lo:.1%}, {hi:.1%}] 95% CI |",
        f"| Recall, pooled (pass@{m.n_runs}) | {m.recall_pooled:.1%} |",
        f"| Recall, consistent (all {m.n_runs} runs) | {m.recall_consistent:.1%} |",
        f"| **Recall gain from pooling** | **{m.recall_gain:+.1%}** |",
        f"| FP rate, per attempt | {m.fp_rate_per_attempt:.1%} "
        f"[{flo:.1%}, {fhi:.1%}] 95% CI |",
        f"| FP rate, pooled (pass@{m.n_runs}) | {m.fp_rate_pooled:.1%} |",
        f"| **FP rate cost of pooling** | **{m.fp_rate_gain:+.1%}** |",
        "",
    ]
    if m.n_runs == 1:
        lines += [
            "> Single run: pooled == per-attempt by construction, and the gain rows "
            "are 0 by definition. The CI is still the honest read of this run — "
            "re-run with `--repeat N` to measure the distribution.",
            "",
        ]
    if m.flaky_items:
        lines += [
            f"**Flaky finds** (found in some runs, missed in others): "
            f"{', '.join(m.flaky_items)}. These are the items a single-shot number "
            "reports as a coin flip — the diversity that pooling converts into recall.",
            "",
        ]
    if m.flaky_clean_items:
        lines += [
            f"**Flaky false positives** (clean control flagged in some runs): "
            f"{', '.join(m.flaky_clean_items)}. Each of these is a control that "
            f"pooling turns into a permanent false positive at k={m.n_runs}.",
            "",
        ]
    return "\n".join(lines)
