"""Multi-run (pass@k) pooling math — zeroverse.pooling.

The asymmetry under test is the module's reason to exist: pooling unions
DISCOVERY on vulnerable items (recall up) and unions FALSE ALARMS on the clean
controls (FP rate up). A recall-only benchmark sees the first and misses the
second; these tests pin both, so a future change that quietly makes pooling look
free has to break a test to do it.
"""

from __future__ import annotations

import pytest

from zeroverse.groundtruth import (
    CLEAN_CONFIRMED_FP,
    CLEAN_HYP_FP,
    CLEAN_OK,
    VULN_CONFIRMED,
    VULN_HYPOTHESIS,
    VULN_MISS,
    CorpusItem,
    ItemScore,
)
from zeroverse.pooling import (
    format_pooling_report,
    pool_item,
    pool_report,
    representative_scores,
    wilson_interval,
)


def vuln_item(item_id: str) -> CorpusItem:
    return CorpusItem(
        id=item_id, name=item_id, label="vulnerable", tier="real-cve",
        cwe="CWE-787", cve="CVE-2026-0001", provenance="test", in_seed_set=False,
        expected_function="parse",
    )


def clean_item(item_id: str) -> CorpusItem:
    return CorpusItem(
        id=item_id, name=item_id, label="clean", tier="real-cve",
        cwe="", cve="", provenance="test", in_seed_set=False,
    )


def score(item_id: str, label: str, outcome: str) -> ItemScore:
    return ItemScore(
        item_id=item_id, label=label, outcome=outcome, n_findings=1,
        n_confirmed=1 if outcome in (VULN_CONFIRMED, CLEAN_CONFIRMED_FP) else 0,
        matched_confirmed=1 if outcome == VULN_CONFIRMED else 0,
        matched_hypothesis=1 if outcome == VULN_HYPOTHESIS else 0,
        confirmed_fp=1 if outcome == CLEAN_CONFIRMED_FP else 0,
    )


class TestWilsonInterval:
    def test_zero_trials_is_no_claim_not_certainty(self) -> None:
        assert wilson_interval(0, 0) == (0.0, 0.0)

    def test_does_not_collapse_at_the_boundaries(self) -> None:
        # The whole reason we use Wilson: at p=0 and p=1 the normal
        # approximation gives a zero-width interval, i.e. false certainty.
        lo, hi = wilson_interval(0, 5)
        assert lo == 0.0 and hi > 0.3, "0/5 must not read as 'never happens'"
        lo, hi = wilson_interval(5, 5)
        assert hi == 1.0 and lo < 0.7, "5/5 must not read as 'always happens'"

    def test_stays_inside_the_unit_interval(self) -> None:
        for k in range(0, 8):
            lo, hi = wilson_interval(k, 7)
            assert 0.0 <= lo <= hi <= 1.0

    def test_narrows_as_evidence_accumulates(self) -> None:
        lo_small, hi_small = wilson_interval(5, 10)
        lo_big, hi_big = wilson_interval(500, 1000)
        assert (hi_big - lo_big) < (hi_small - lo_small)

    def test_rejects_impossible_counts(self) -> None:
        with pytest.raises(ValueError):
            wilson_interval(6, 5)


class TestPoolItem:
    def test_vulnerable_item_takes_the_best_run(self) -> None:
        item = vuln_item("v1")
        pooled = pool_item(item, [
            score("v1", "vulnerable", VULN_MISS),
            score("v1", "vulnerable", VULN_CONFIRMED),
            score("v1", "vulnerable", VULN_HYPOTHESIS),
        ])
        assert pooled.pooled_outcome == VULN_CONFIRMED
        assert pooled.n_hit == 1
        assert pooled.flaky is True
        assert pooled.consistent is False

    def test_clean_item_takes_the_WORST_run(self) -> None:
        # The asymmetry. One bad run in three poisons the pooled control.
        item = clean_item("c1")
        pooled = pool_item(item, [
            score("c1", "clean", CLEAN_OK),
            score("c1", "clean", CLEAN_OK),
            score("c1", "clean", CLEAN_CONFIRMED_FP),
        ])
        assert pooled.pooled_outcome == CLEAN_CONFIRMED_FP
        assert pooled.n_hit == 1
        assert pooled.flaky is True

    def test_clean_hypothesis_noise_ranks_below_a_confirmed_fp(self) -> None:
        item = clean_item("c1")
        pooled = pool_item(item, [
            score("c1", "clean", CLEAN_OK),
            score("c1", "clean", CLEAN_HYP_FP),
        ])
        assert pooled.pooled_outcome == CLEAN_HYP_FP
        # hypothesis noise is not a confirmed false positive, so it is not a "hit"
        assert pooled.n_hit == 0

    def test_unanimous_runs_are_consistent_and_not_flaky(self) -> None:
        item = vuln_item("v1")
        pooled = pool_item(item, [score("v1", "vulnerable", VULN_CONFIRMED)] * 3)
        assert pooled.consistent is True
        assert pooled.flaky is False
        assert pooled.n_hit == 3

    def test_empty_runs_rejected(self) -> None:
        with pytest.raises(ValueError):
            pool_item(vuln_item("v1"), [])


class TestPoolReport:
    def test_inconsistency_becomes_recall_the_aikido_effect(self) -> None:
        # Three items, each found by exactly one different run. Every single run
        # scores 1/3; pooled scores 3/3. This is DeepSeek 17->28 in miniature.
        items = [vuln_item("v1"), vuln_item("v2"), vuln_item("v3")]
        runs = [
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_MISS),
             score("v3", "vulnerable", VULN_MISS)],
            [score("v1", "vulnerable", VULN_MISS),
             score("v2", "vulnerable", VULN_CONFIRMED),
             score("v3", "vulnerable", VULN_MISS)],
            [score("v1", "vulnerable", VULN_MISS),
             score("v2", "vulnerable", VULN_MISS),
             score("v3", "vulnerable", VULN_CONFIRMED)],
        ]
        m = pool_report(items, runs)
        assert m.recall_per_attempt == pytest.approx(1 / 3, abs=1e-4)
        assert m.recall_pooled == 1.0
        assert m.recall_consistent == 0.0
        assert m.recall_gain == pytest.approx(2 / 3, abs=1e-4)
        assert sorted(m.flaky_items) == ["v1", "v2", "v3"]

    def test_pooling_also_unions_false_positives(self) -> None:
        # The half a recall-only benchmark cannot see: same structure as above,
        # but on clean controls, and the "gain" is a cost.
        items = [clean_item("c1"), clean_item("c2")]
        runs = [
            [score("c1", "clean", CLEAN_CONFIRMED_FP), score("c2", "clean", CLEAN_OK)],
            [score("c1", "clean", CLEAN_OK), score("c2", "clean", CLEAN_CONFIRMED_FP)],
        ]
        m = pool_report(items, runs)
        assert m.fp_rate_per_attempt == 0.5      # 2 FP items over 4 attempts
        assert m.fp_rate_pooled == 1.0           # both controls poisoned at k=2
        assert m.fp_rate_gain == 0.5
        assert sorted(m.flaky_clean_items) == ["c1", "c2"]

    def test_single_run_pooled_equals_per_attempt(self) -> None:
        items = [vuln_item("v1"), clean_item("c1")]
        runs = [[score("v1", "vulnerable", VULN_CONFIRMED),
                 score("c1", "clean", CLEAN_OK)]]
        m = pool_report(items, runs)
        assert m.n_runs == 1
        assert m.recall_pooled == m.recall_per_attempt == 1.0
        assert m.recall_gain == 0.0
        assert m.fp_rate_gain == 0.0
        # A k=1 run still gets an honest interval rather than a bare 100%.
        assert m.recall_per_attempt_ci95[0] < 1.0

    def test_consistent_core_is_reported_separately_from_pooled(self) -> None:
        # v1 is stable, v2 is a coin flip. Pooled says 100%; the stable core
        # says 50%. Both are true and the difference is the point.
        items = [vuln_item("v1"), vuln_item("v2")]
        runs = [
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_CONFIRMED)],
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_MISS)],
        ]
        m = pool_report(items, runs)
        assert m.recall_pooled == 1.0
        assert m.recall_consistent == 0.5
        assert m.flaky_items == ["v2"]

    def test_located_hypothesis_never_counts_as_a_confirmed_find(self) -> None:
        # PoV-is-truth carries through pooling: a bug only ever hypothesised is
        # pooled as located, not as recall.
        items = [vuln_item("v1")]
        runs = [
            [score("v1", "vulnerable", VULN_HYPOTHESIS)],
            [score("v1", "vulnerable", VULN_MISS)],
        ]
        m = pool_report(items, runs)
        assert m.items[0].pooled_outcome == VULN_HYPOTHESIS
        assert m.recall_pooled == 0.0
        assert m.per_attempt_confirmed == 0

    def test_partial_run_is_rejected_not_silently_deflated(self) -> None:
        items = [vuln_item("v1"), vuln_item("v2")]
        runs = [
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_CONFIRMED)],
            [score("v1", "vulnerable", VULN_CONFIRMED)],   # v2 missing
        ]
        with pytest.raises(ValueError, match="missing scores"):
            pool_report(items, runs)

    def test_no_runs_rejected(self) -> None:
        with pytest.raises(ValueError):
            pool_report([vuln_item("v1")], [])

    def test_trials_account_for_every_attempt(self) -> None:
        items = [vuln_item("v1"), vuln_item("v2"), clean_item("c1")]
        runs = [
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_MISS),
             score("c1", "clean", CLEAN_OK)],
        ] * 4
        m = pool_report(items, runs)
        assert m.per_attempt_trials == 2 * 4
        assert m.fp_trials == 1 * 4


class TestFormatPoolingReport:
    def test_renders_both_halves_of_the_trade(self) -> None:
        items = [vuln_item("v1"), vuln_item("v2"), clean_item("c1")]
        runs = [
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_MISS),
             score("c1", "clean", CLEAN_CONFIRMED_FP)],
            [score("v1", "vulnerable", VULN_MISS),
             score("v2", "vulnerable", VULN_CONFIRMED),
             score("c1", "clean", CLEAN_OK)],
        ]
        out = format_pooling_report(pool_report(items, runs))
        assert "Recall gain from pooling" in out
        assert "FP rate cost of pooling" in out
        assert "Flaky finds" in out
        assert "Flaky false positives" in out

    def test_single_run_is_labelled_as_such(self) -> None:
        items = [vuln_item("v1")]
        out = format_pooling_report(
            pool_report(items, [[score("v1", "vulnerable", VULN_CONFIRMED)]])
        )
        assert "--repeat N" in out


class TestRepresentativeScores:
    def test_picks_the_best_run_for_a_vulnerable_item(self) -> None:
        items = [vuln_item("v1")]
        runs = [
            [score("v1", "vulnerable", VULN_MISS)],
            [score("v1", "vulnerable", VULN_CONFIRMED)],
        ]
        rep = representative_scores(items, runs)
        assert [s.outcome for s in rep] == [VULN_CONFIRMED]

    def test_picks_the_worst_run_for_a_clean_control(self) -> None:
        items = [clean_item("c1")]
        runs = [
            [score("c1", "clean", CLEAN_OK)],
            [score("c1", "clean", CLEAN_CONFIRMED_FP)],
        ]
        rep = representative_scores(items, runs)
        assert [s.outcome for s in rep] == [CLEAN_CONFIRMED_FP]

    def test_returned_scores_are_real_observations_not_synthesised(self) -> None:
        # The representative must be an object that came out of an actual run,
        # so downstream finding counts stay honest.
        items = [vuln_item("v1")]
        winner = score("v1", "vulnerable", VULN_CONFIRMED)
        runs = [[score("v1", "vulnerable", VULN_MISS)], [winner]]
        assert representative_scores(items, runs)[0] is winner

    def test_aggregate_over_representatives_matches_pooled_rates(self) -> None:
        from zeroverse.groundtruth import aggregate

        items = [vuln_item("v1"), vuln_item("v2"), clean_item("c1")]
        runs = [
            [score("v1", "vulnerable", VULN_CONFIRMED),
             score("v2", "vulnerable", VULN_MISS),
             score("c1", "clean", CLEAN_OK)],
            [score("v1", "vulnerable", VULN_MISS),
             score("v2", "vulnerable", VULN_CONFIRMED),
             score("c1", "clean", CLEAN_CONFIRMED_FP)],
        ]
        m = pool_report(items, runs)
        agg = aggregate(items, representative_scores(items, runs))
        assert agg.recall_confirmed == m.recall_pooled == 1.0
        assert agg.fp_rate_confirmed == m.fp_rate_pooled == 1.0
