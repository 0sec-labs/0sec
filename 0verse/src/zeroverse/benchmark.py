"""Benchmark result model + parsing/aggregation (M6 #33).

The honest-comparison harness (``benchmarks/fuzzbench/compare.py``) runs 0verse's
harness-synth + seed/dictionary/CMPLOG + oracle lane against a **baseline AFL++**
lane (the same synthesized harness, but default AFL++: no CMPLOG, no mined
dictionary, no structured seeds) on the same targets, and emits one NDJSON
``BenchTrial`` per (target, lane). This module is the *parsing + aggregation* half
— kept in ``src`` so it is type-checked and unit-tested against fixtures, separate
from the (engine-heavy, un-typed) runner.

No cherry-picking is baked in: ``summarize`` reports a ``tie`` or a ``baseline``
win exactly as the numbers say. The headline metric is **time-to-first-crash**
(``time_to_crash_s``); a lane that does not crash within the budget is recorded as
such (``crash_found = False``), never as a silent loss.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Bump MINOR for additive fields, MAJOR for removals/renames.
BENCHMARK_SCHEMA_VERSION = "1.0"

LANES = ("0verse", "baseline")


@dataclass
class BenchTrial:
    """One (target, lane) measurement."""

    schema_version: str
    target: str
    lane: str                          # "0verse" | "baseline"
    crash_found: bool
    confirmed_pov: bool                # crash_found AND oracle-confirmed (0verse lane)
    time_to_crash_s: float | None      # wall-clock to first crash, or None if none
    budget_s: int
    execs: int
    execs_per_sec: float
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "lane": self.lane,
            "crash_found": self.crash_found,
            "confirmed_pov": self.confirmed_pov,
            "time_to_crash_s": self.time_to_crash_s,
            "budget_s": self.budget_s,
            "execs": self.execs,
            "execs_per_sec": self.execs_per_sec,
            "note": self.note,
        }


def trial_from_dict(d: dict[str, Any]) -> BenchTrial:
    version = str(d.get("schema_version", ""))
    if version.split(".", 1)[0] != BENCHMARK_SCHEMA_VERSION.split(".", 1)[0]:
        raise ValueError(f"incompatible benchmark schema {version!r}")
    lane = str(d["lane"])
    if lane not in LANES:
        raise ValueError(f"unknown lane {lane!r}")
    ttc = d.get("time_to_crash_s")
    return BenchTrial(
        schema_version=version,
        target=str(d["target"]),
        lane=lane,
        crash_found=bool(d["crash_found"]),
        confirmed_pov=bool(d.get("confirmed_pov", False)),
        time_to_crash_s=None if ttc is None else float(ttc),
        budget_s=int(d["budget_s"]),
        execs=int(d.get("execs", 0)),
        execs_per_sec=float(d.get("execs_per_sec", 0.0)),
        note=str(d.get("note", "")),
    )


def parse_results(text: str) -> list[BenchTrial]:
    """Parse an NDJSON results stream into validated trials."""
    out: list[BenchTrial] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(trial_from_dict(json.loads(line)))
    return out


@dataclass
class Comparison:
    """0verse vs baseline on one target, with an honest winner."""

    target: str
    zeroverse: BenchTrial | None
    baseline: BenchTrial | None
    winner: str                        # "0verse" | "baseline" | "tie" | "neither"
    margin_s: float | None             # baseline_ttc - zeroverse_ttc when both crashed

    @property
    def detail(self) -> str:
        return _winner_detail(self.zeroverse, self.baseline, self.winner)


# A target where both lanes crash within a hair of each other is an honest tie,
# not a 0verse win — don't claim a win inside the measurement noise floor.
TIE_EPSILON_S = 2.0


def _winner(zv: BenchTrial | None, bl: BenchTrial | None) -> tuple[str, float | None]:
    zc = bool(zv and zv.crash_found)
    bc = bool(bl and bl.crash_found)
    if not zc and not bc:
        return "neither", None
    if zc and not bc:
        return "0verse", None
    if bc and not zc:
        return "baseline", None
    # both crashed — compare time-to-first-crash
    assert zv is not None and bl is not None
    zt = zv.time_to_crash_s if zv.time_to_crash_s is not None else float(zv.budget_s)
    bt = bl.time_to_crash_s if bl.time_to_crash_s is not None else float(bl.budget_s)
    margin = round(bt - zt, 2)
    if abs(margin) <= TIE_EPSILON_S:
        return "tie", margin
    return ("0verse" if zt < bt else "baseline"), margin


def _winner_detail(zv: BenchTrial | None, bl: BenchTrial | None, winner: str) -> str:
    def fmt(t: BenchTrial | None) -> str:
        if t is None:
            return "—"
        if not t.crash_found:
            return f"no crash in {t.budget_s}s"
        ttc = "?" if t.time_to_crash_s is None else f"{t.time_to_crash_s:.1f}s"
        return f"crash@{ttc}"

    return f"0verse={fmt(zv)} baseline={fmt(bl)} → {winner}"


def summarize(trials: list[BenchTrial]) -> list[Comparison]:
    """Pair trials by target and decide a winner per target. Honest by construction:
    a tie is reported as a tie, a baseline win as a baseline win."""
    by_target: dict[str, dict[str, BenchTrial]] = {}
    for t in trials:
        by_target.setdefault(t.target, {})[t.lane] = t
    comps: list[Comparison] = []
    for target in sorted(by_target):
        lanes = by_target[target]
        zv = lanes.get("0verse")
        bl = lanes.get("baseline")
        winner, margin = _winner(zv, bl)
        comps.append(Comparison(target=target, zeroverse=zv, baseline=bl,
                                winner=winner, margin_s=margin))
    return comps


def tally(comps: list[Comparison]) -> dict[str, int]:
    """Count outcomes across targets — the honest scoreboard."""
    out = {"0verse": 0, "baseline": 0, "tie": 0, "neither": 0}
    for c in comps:
        out[c.winner] = out.get(c.winner, 0) + 1
    return out


def format_table(comps: list[Comparison]) -> str:
    """Render a markdown comparison table — drop-in for ``docs/BENCHMARKS.md``."""
    rows = [
        "| target | 0verse TTE | baseline TTE | winner | margin |",
        "|--------|-----------|--------------|--------|--------|",
    ]
    for c in comps:
        def cell(t: BenchTrial | None) -> str:
            if t is None:
                return "—"
            if not t.crash_found:
                return f"none (>{t.budget_s}s)"
            return "?" if t.time_to_crash_s is None else f"{t.time_to_crash_s:.1f}s"

        margin = "" if c.margin_s is None else f"{c.margin_s:+.1f}s"
        rows.append(
            f"| `{c.target}` | {cell(c.zeroverse)} | {cell(c.baseline)} | "
            f"**{c.winner}** | {margin} |"
        )
    score = tally(comps)
    rows.append("")
    rows.append(
        f"_Scoreboard: 0verse {score['0verse']} · baseline {score['baseline']} · "
        f"tie {score['tie']} · neither {score['neither']} (n={len(comps)})._"
    )
    return "\n".join(rows)
