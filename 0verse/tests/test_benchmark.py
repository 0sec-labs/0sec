"""M6 #33 — benchmark harness result-parsing + honest aggregation on fixture data.

No engines run here: feed canned ``BenchTrial`` NDJSON (as the runner would emit)
and assert the winner logic is honest — a 0verse win on a gated target, a tie
inside the noise floor, a baseline parity/win reported as such, and a target
neither lane cracks reported as ``neither``."""

from __future__ import annotations

import json

from zeroverse import benchmark
from zeroverse.benchmark import BENCHMARK_SCHEMA_VERSION, BenchTrial


def _trial(target: str, lane: str, *, crash: bool, ttc: float | None,
           budget: int = 60, confirmed: bool = False) -> dict[str, object]:
    return BenchTrial(
        schema_version=BENCHMARK_SCHEMA_VERSION, target=target, lane=lane,
        crash_found=crash, confirmed_pov=confirmed, time_to_crash_s=ttc,
        budget_s=budget, execs=1000, execs_per_sec=500.0,
    ).to_dict()


def _ndjson(rows: list[dict[str, object]]) -> str:
    return "\n".join(json.dumps(r) for r in rows)


def test_parse_roundtrip_and_schema_guard() -> None:
    text = _ndjson([_trial("t", "0verse", crash=True, ttc=3.0)])
    trials = benchmark.parse_results(text)
    assert len(trials) == 1 and trials[0].lane == "0verse"


def test_zeroverse_wins_gated_target() -> None:
    rows = [
        _trial("magic_gated", "0verse", crash=True, ttc=4.0, confirmed=True),
        _trial("magic_gated", "baseline", crash=False, ttc=None),
    ]
    comps = benchmark.summarize(benchmark.parse_results(_ndjson(rows)))
    assert len(comps) == 1 and comps[0].winner == "0verse"


def test_tie_inside_noise_floor() -> None:
    rows = [
        _trial("ungated", "0verse", crash=True, ttc=1.5),
        _trial("ungated", "baseline", crash=True, ttc=2.0),  # within TIE_EPSILON_S
    ]
    comps = benchmark.summarize(benchmark.parse_results(_ndjson(rows)))
    assert comps[0].winner == "tie"


def test_baseline_can_win() -> None:
    rows = [
        _trial("flat", "0verse", crash=True, ttc=20.0),
        _trial("flat", "baseline", crash=True, ttc=5.0),  # baseline clearly faster
    ]
    comps = benchmark.summarize(benchmark.parse_results(_ndjson(rows)))
    assert comps[0].winner == "baseline"  # honest: no cherry-picking


def test_neither_cracks() -> None:
    rows = [
        _trial("hard", "0verse", crash=False, ttc=None),
        _trial("hard", "baseline", crash=False, ttc=None),
    ]
    comps = benchmark.summarize(benchmark.parse_results(_ndjson(rows)))
    assert comps[0].winner == "neither"


def test_tally_and_table() -> None:
    rows = [
        _trial("a", "0verse", crash=True, ttc=2.0), _trial("a", "baseline", crash=False, ttc=None),
        _trial("b", "0verse", crash=True, ttc=2.0), _trial("b", "baseline", crash=True, ttc=2.3),
    ]
    comps = benchmark.summarize(benchmark.parse_results(_ndjson(rows)))
    score = benchmark.tally(comps)
    assert score["0verse"] == 1 and score["tie"] == 1
    table = benchmark.format_table(comps)
    assert "| target |" in table and "Scoreboard" in table


def test_incompatible_schema_rejected() -> None:
    bad = json.dumps({"schema_version": "2.0", "target": "x", "lane": "0verse",
                      "crash_found": False, "budget_s": 60})
    try:
        benchmark.parse_results(bad)
    except ValueError as e:
        assert "incompatible benchmark schema" in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")
