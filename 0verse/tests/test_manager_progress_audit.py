from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/linux/audit-manager-progress.py"
WRAPPER = Path(__file__).parents[1] / "scripts/linux/audit-live-manager-progress.sh"
REACHABILITY_WRAPPER = (
    Path(__file__).parents[1] / "scripts/linux/audit-live-syzkaller-lanes.sh"
)
SPEC = importlib.util.spec_from_file_location("audit_manager_progress", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_parse_syzkaller_prometheus_metrics() -> None:
    executions, coverage = MODULE.parse_metrics(
        "syz_corpus_cover 8941\nsyz_exec_total 5.083133e+06\n"
    )
    assert executions == 5_083_133
    assert coverage == 8_941


def test_parse_requires_both_metrics() -> None:
    with pytest.raises(ValueError, match="syz_corpus_cover"):
        MODULE.parse_metrics("syz_exec_total 10\n")


def test_live_wrapper_tracks_only_active_managers() -> None:
    wrapper = WRAPPER.read_text(encoding="utf-8")
    active = {
        "keyrings",
        "futexpi",
        "pipe",
        "unix",
        "vsock",
        "afalg",
        "tls",
        "kcsan-kcm",
        "kcsan-aio",
        "kcsan-unix",
        "lifetime-exact94",
        "aio-exact94",
    }
    for lane in active:
        assert f"{lane}=http://127.0.0.1:" in wrapper
    assert "sched=http://" not in wrapper
    assert "drivers=http://" not in wrapper

    reachability = REACHABILITY_WRAPPER.read_text(encoding="utf-8")
    reachability_lanes = active - {"kcsan-aio", "kcsan-unix"}
    for lane in reachability_lanes:
        assert f"run {lane}" in reachability
    assert "run kcsan-aio " not in reachability
    assert "run kcsan-unix " not in reachability
    assert "run sched " not in reachability
    assert "run drivers " not in reachability


@pytest.mark.parametrize(
    ("prior", "executions", "now", "expected"),
    [
        (None, 10, 100, ("BASELINE", 0, 0, True)),
        ({"executions": 10, "sampled_at": 100}, 10, 101, ("TOO_SOON", 0, 1, False)),
        ({"executions": 10, "sampled_at": 100}, 20, 200, ("LIVE", 10, 100, True)),
        ({"executions": 10, "sampled_at": 100}, 10, 200, ("STALLED", 0, 100, True)),
        ({"executions": 10, "sampled_at": 100}, 2, 200, ("RESET", -8, 100, True)),
    ],
)
def test_progress_state_machine(prior, executions, now, expected) -> None:
    assert MODULE.classify_progress(prior, executions, now, 60) == expected


def test_coverage_stagnation_survives_multiple_samples() -> None:
    assert MODULE.classify_coverage(None, 10, 100) == (0, 100, 0)
    prior = {"coverage": 10, "sampled_at": 100, "coverage_changed_at": 80}
    assert MODULE.classify_coverage(prior, 10, 140) == (0, 80, 60)
    assert MODULE.classify_coverage(prior, 11, 140) == (1, 140, 0)
