"""Tests for the Magma ground-truth scorer (PART A — at-scale credibility).

Covers reached / confirmed-PoV / unmatched-FP / precision math, the catalogue
loader, function-level matching incl. co-located bugs, and the fixed-build FP
probe — with fixture ground truth, no Docker/Ghidra needed.
"""

from __future__ import annotations

import json
from pathlib import Path

from zeroverse.magma import (
    MAGMA_SCHEMA_VERSION,
    MagmaBug,
    MagmaTargetScore,
    aggregate_magma,
    bug_functions,
    bugs_for_target,
    estimated_cost_usd,
    format_magma_report,
    load_catalogue,
    normalize_fn,
    score_target,
)


def _bug(target: str, bug: str, function: str, **kw: object) -> MagmaBug:
    return MagmaBug(target=target, bug=bug, file=f"{target}.c", function=function, **kw)  # type: ignore[arg-type]


def _f(function: str, *, confirmed: bool) -> dict[str, object]:
    return {"function": function, "confirmed": confirmed, "hypothesis": not confirmed}


# --- catalogue model -------------------------------------------------------

def test_schema_version_is_a_string() -> None:
    assert isinstance(MAGMA_SCHEMA_VERSION, str)


def test_unscorable_bug_has_no_function() -> None:
    assert _bug("libpng", "PNG001", "png_check").scorable is True
    assert _bug("php", "PHP001", "").scorable is False


def test_normalize_strips_magma_prefix() -> None:
    # libpng's --with-libpng-prefix=MAGMA_ renames the symbol in the binary.
    assert normalize_fn("MAGMA_png_combine_row") == "png_combine_row"
    assert normalize_fn("png_combine_row") == "png_combine_row"
    assert normalize_fn("PNG_Handle_tRNS") == "png_handle_trns"


def test_magma_prefixed_finding_matches_catalogue_bug() -> None:
    bugs = [_bug("libpng", "PNG004", "png_combine_row")]
    # the binary surfaces the symbol-renamed name; it must still match + confirm.
    s = score_target("libpng", bugs, [_f("MAGMA_png_combine_row", confirmed=True)])
    assert s.bug_sites_confirmed == 1
    assert s.confirmed_sites == ["png_combine_row"]


def test_bug_functions_dedups_and_lowercases() -> None:
    bugs = [
        _bug("x", "A", "Foo"), _bug("x", "B", "foo"), _bug("x", "C", "Bar"),
        _bug("x", "D", ""),  # unscorable, excluded
    ]
    assert bug_functions(bugs) == {"foo", "bar"}


# --- score_target: vulnerable build ----------------------------------------

def test_reached_but_not_confirmed() -> None:
    bugs = [_bug("libpng", "PNG001", "png_handle_tRNS")]
    s = score_target("libpng", bugs, [_f("png_handle_tRNS", confirmed=False)])
    assert s.bug_sites_reached == 1
    assert s.bug_sites_confirmed == 0
    assert s.unmatched_confirmed == 0


def test_confirmed_at_bug_site() -> None:
    bugs = [_bug("libpng", "PNG001", "png_handle_tRNS")]
    s = score_target("libpng", bugs, [_f("png_handle_tRNS", confirmed=True)])
    assert s.bug_sites_reached == 1
    assert s.bug_sites_confirmed == 1
    assert s.confirmed_sites == ["png_handle_trns"]
    assert s.unmatched_confirmed == 0


def test_confirmed_off_bug_site_is_unmatched_fp() -> None:
    bugs = [_bug("libpng", "PNG001", "png_handle_tRNS")]
    s = score_target("libpng", bugs, [_f("some_other_fn", confirmed=True)])
    assert s.bug_sites_confirmed == 0
    assert s.unmatched_confirmed == 1


def test_colocated_bugs_collapse_to_one_site() -> None:
    # XML001 + XML006 share xmlSnprintfElementContent -> ONE distinct bug-site.
    bugs = [
        _bug("libxml2", "XML001", "xmlSnprintfElementContent"),
        _bug("libxml2", "XML006", "xmlSnprintfElementContent"),
    ]
    assert len(bugs_for_target(bugs, "libxml2")) == 2
    s = score_target("libxml2", bugs, [_f("xmlSnprintfElementContent", confirmed=True)])
    assert s.n_bugs == 2
    assert s.n_bug_sites == 1
    assert s.bug_sites_confirmed == 1


def test_unscorable_bugs_excluded_from_denominator() -> None:
    bugs = [_bug("php", "PHP001", ""), _bug("php", "PHP002", "exif_process")]
    s = score_target("php", bugs, [])
    assert s.n_bugs == 2
    assert s.n_bug_sites == 1
    assert s.n_unscorable == 1


# --- score_target: clean (fixed) build -------------------------------------

def test_clean_build_any_confirmation_is_fp() -> None:
    bugs = [_bug("libpng", "PNG001", "png_handle_tRNS")]
    s = score_target("libpng", bugs, [_f("png_handle_tRNS", confirmed=True)],
                     label="clean")
    assert s.bug_sites_confirmed == 0
    assert s.unmatched_confirmed == 1


def test_clean_build_no_confirmation_is_zero_fp() -> None:
    bugs = [_bug("libpng", "PNG001", "png_handle_tRNS")]
    s = score_target("libpng", bugs, [_f("png_handle_tRNS", confirmed=False)],
                     label="clean")
    assert s.unmatched_confirmed == 0


# --- aggregate -------------------------------------------------------------

def test_aggregate_metrics_math() -> None:
    png = score_target(
        "libpng",
        [_bug("libpng", "PNG001", "a"), _bug("libpng", "PNG002", "b"),
         _bug("libpng", "PNG003", "c")],
        [_f("a", confirmed=True), _f("b", confirmed=False), _f("zzz", confirmed=True)],
        wall_s=10.0, input_tokens=100, output_tokens=20,
    )
    # 3 sites; reached {a,b}=2; confirmed {a}=1; unmatched {zzz}=1
    assert png.n_bug_sites == 3
    assert png.bug_sites_reached == 2
    assert png.bug_sites_confirmed == 1
    assert png.unmatched_confirmed == 1

    clean = score_target("libpng", [_bug("libpng", "PNG001", "a")],
                         [_f("a", confirmed=True)], label="clean", wall_s=5.0)
    m = aggregate_magma([png, clean])
    assert m.n_vuln_targets == 1
    assert m.n_clean_targets == 1
    assert m.total_bug_sites == 3
    assert m.total_bugs == 3
    assert m.sites_reached == 2
    assert m.sites_confirmed == 1
    assert m.reach_rate == round(2 / 3, 4)
    assert m.confirmed_rate == round(1 / 3, 4)
    assert m.confirmed_pov_rate == 0.5  # 1/2
    assert m.unmatched_confirmed == 1
    assert m.clean_confirmed_fp == 1
    # precision: 1 TP confirmed, 2 FP confirmed (vuln unmatched + clean) -> 1/3
    assert m.precision_confirmed == round(1 / 3, 4)
    assert m.input_tokens == 100
    assert m.output_tokens == 20
    assert m.wall_s == 15.0


def test_aggregate_empty_is_safe() -> None:
    m = aggregate_magma([])
    assert m.reach_rate == 0.0
    assert m.confirmed_rate == 0.0
    assert m.precision_confirmed == 0.0


# --- cost ------------------------------------------------------------------

def test_estimated_cost_is_monotone_and_nonzero() -> None:
    assert estimated_cost_usd(0, 0) == 0.0
    assert estimated_cost_usd(1_000_000, 0) > 0
    assert estimated_cost_usd(0, 1_000_000) > estimated_cost_usd(1_000_000, 0)


# --- report ----------------------------------------------------------------

def _one_score() -> MagmaTargetScore:
    return score_target("libpng", [_bug("libpng", "PNG001", "a")],
                        [_f("a", confirmed=True)], wall_s=3.0,
                        input_tokens=1000, output_tokens=100)


def test_report_prices_a_measured_run() -> None:
    s = _one_score()
    md = format_magma_report(
        aggregate_magma([s]), [s], llm="codex", lane="real-llm-capability",
        accounting={"status": "measured", "calls_ok": 4, "calls_failed": 0},
    )
    assert "1100 tokens" in md
    assert "est.)" in md


def test_report_refuses_a_dollar_figure_for_an_unmeasured_run() -> None:
    # A lane whose every call failed must not render "0 tokens (~$0.0 est.)".
    s = _one_score()
    md = format_magma_report(
        aggregate_magma([s]), [s], llm="codex", lane="real-llm-capability",
        accounting={"status": "all-calls-failed", "calls_ok": 0, "calls_failed": 9},
    )
    assert "$" not in md
    assert "all-calls-failed" in md
    assert "0 ok / 9 failed LLM calls" in md


# --- catalogue loader ------------------------------------------------------

def test_load_catalogue_roundtrip(tmp_path: Path) -> None:
    data = {
        "bugs": [
            {"target": "libpng", "bug": "PNG001", "file": "png.c",
             "function": "png_handle_tRNS", "in_seed_set": False},
            {"target": "php", "bug": "PHP001", "file": "phar.c",
             "function": "", "in_seed_set": False},
        ]
    }
    p = tmp_path / "cat.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    bugs = load_catalogue(p)
    assert len(bugs) == 2
    assert bugs[0].scorable is True
    assert bugs[1].scorable is False


def test_real_catalogue_loads() -> None:
    cat = (Path(__file__).resolve().parents[1]
           / "benchmarks" / "groundtruth" / "CATALOGUE-magma.json")
    if not cat.exists():
        return
    bugs = load_catalogue(cat)
    assert len(bugs) >= 100
    # the catalogue is fully held-out vs 0verse seeds
    assert all(not b.in_seed_set for b in bugs)
    # XML001 is the bug reproduced + scored standalone in the real-cve tier
    xml001 = [b for b in bugs if b.bug == "XML001"]
    assert xml001 and xml001[0].function == "xmlSnprintfElementContent"
