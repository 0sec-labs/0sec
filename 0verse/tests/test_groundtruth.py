"""Tests for the ground-truth eval scorer + corpus manifest (M6 eval harness).

Covers the recall / FP / precision / confirmed-PoV math, the manifest loader, and
the held-out tagging — with fixture ground truth, no Ghidra needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse.groundtruth import (
    CLEAN_CONFIRMED_FP,
    CLEAN_HYP_FP,
    CLEAN_OK,
    GROUNDTRUTH_CAPABILITY_LANE,
    GROUNDTRUTH_CI_LANE,
    GROUNDTRUTH_SCHEMA_VERSION,
    VULN_CONFIRMED,
    VULN_HYPOTHESIS,
    VULN_MISS,
    CorpusItem,
    aggregate,
    format_report,
    heldout_summary,
    item_from_dict,
    lane_label,
    load_manifest,
    score_item,
)


def _vuln(**kw: object) -> CorpusItem:
    base: dict[str, object] = {
        "id": "v", "name": "v", "label": "vulnerable", "tier": "real-cve",
        "cwe": "CWE-120", "cve": "CVE-X", "provenance": "p", "in_seed_set": False,
        "expected_function": "vulnfn", "expected_sink": "strcpy",
    }
    base.update(kw)
    return CorpusItem(**base)  # type: ignore[arg-type]


def _clean(**kw: object) -> CorpusItem:
    base: dict[str, object] = {
        "id": "c", "name": "c", "label": "clean", "tier": "real-cve", "cwe": "",
        "cve": "CVE-X", "provenance": "p", "in_seed_set": False,
    }
    base.update(kw)
    return CorpusItem(**base)  # type: ignore[arg-type]


def _f(function: str, sink: str, *, confirmed: bool, hypothesis: bool) -> dict[str, object]:
    return {"function": function, "source": "read", "sink": sink,
            "confirmed": confirmed, "hypothesis": hypothesis}


# --- CorpusItem validation -------------------------------------------------

def test_vulnerable_item_requires_expected_function() -> None:
    with pytest.raises(ValueError, match="expected_function"):
        CorpusItem(id="x", name="x", label="vulnerable", tier="real-cve", cwe="",
                   cve="", provenance="", in_seed_set=False)


def test_unknown_label_and_tier_rejected() -> None:
    with pytest.raises(ValueError, match="unknown label"):
        CorpusItem(id="x", name="x", label="bogus", tier="real-cve", cwe="",
                   cve="", provenance="", in_seed_set=False)
    with pytest.raises(ValueError, match="unknown tier"):
        CorpusItem(id="x", name="x", label="clean", tier="bogus", cwe="",
                   cve="", provenance="", in_seed_set=False)


# --- score_item: vulnerable side ------------------------------------------

def test_vuln_confirmed_at_location() -> None:
    item = _vuln()
    s = score_item(item, [_f("vulnfn", "strcpy", confirmed=True, hypothesis=True)])
    assert s.outcome == VULN_CONFIRMED
    assert s.matched_confirmed == 1
    assert s.confirmed_fp == 0


def test_vuln_located_but_unconfirmed_is_hypothesis() -> None:
    # surfaced at the right place but no reproducing PoV — counts as located, even
    # when the funnel did not set the hypothesis flag.
    item = _vuln()
    s = score_item(item, [_f("vulnfn", "strcpy", confirmed=False, hypothesis=False)])
    assert s.outcome == VULN_HYPOTHESIS
    assert s.matched_hypothesis == 1


def test_vuln_miss_when_nothing_at_location() -> None:
    item = _vuln()
    s = score_item(item, [_f("otherfn", "memcpy", confirmed=False, hypothesis=True)])
    assert s.outcome == VULN_MISS


def test_confirmed_at_wrong_location_counts_as_fp() -> None:
    item = _vuln()
    s = score_item(item, [_f("otherfn", "strcpy", confirmed=True, hypothesis=True)])
    assert s.outcome == VULN_MISS          # nothing confirmed at the right place
    assert s.confirmed_fp == 1             # the mislocated confirmation is an FP


def test_sink_mismatch_blocks_match() -> None:
    item = _vuln(expected_sink="strcpy")
    s = score_item(item, [_f("vulnfn", "memcpy", confirmed=True, hypothesis=True)])
    assert s.outcome == VULN_MISS
    assert s.confirmed_fp == 1


def test_location_match_is_case_insensitive() -> None:
    item = _vuln(expected_function="VulnFn", expected_sink="StrCpy")
    s = score_item(item, [_f("vulnfn", "strcpy", confirmed=True, hypothesis=True)])
    assert s.outcome == VULN_CONFIRMED


def test_no_expected_sink_matches_on_function_only() -> None:
    item = _vuln(expected_sink=None)
    s = score_item(item, [_f("vulnfn", "anything", confirmed=True, hypothesis=True)])
    assert s.outcome == VULN_CONFIRMED


# --- score_item: clean side ------------------------------------------------

def test_clean_no_findings_is_ok() -> None:
    s = score_item(_clean(), [])
    assert s.outcome == CLEAN_OK
    assert s.confirmed_fp == 0


def test_clean_hypothesis_only_is_hyp_fp() -> None:
    s = score_item(_clean(), [_f("f", "memcpy", confirmed=False, hypothesis=True)])
    assert s.outcome == CLEAN_HYP_FP
    assert s.confirmed_fp == 0


def test_clean_confirmed_is_confirmed_fp() -> None:
    s = score_item(_clean(), [_f("f", "strcpy", confirmed=True, hypothesis=True)])
    assert s.outcome == CLEAN_CONFIRMED_FP
    assert s.confirmed_fp == 1


# --- aggregate -------------------------------------------------------------

def test_aggregate_metrics_math() -> None:
    items = [
        _vuln(id="v1"), _vuln(id="v2"), _vuln(id="v3"), _vuln(id="v4"),
        _clean(id="c1"), _clean(id="c2"),
    ]
    conf = _f("vulnfn", "strcpy", confirmed=True, hypothesis=True)
    hyp = _f("vulnfn", "strcpy", confirmed=False, hypothesis=True)
    clean_conf = _f("f", "strcpy", confirmed=True, hypothesis=True)
    scores = [
        score_item(items[0], [conf]),        # confirmed
        score_item(items[1], [hyp]),         # located-hypothesis
        score_item(items[2], []),            # miss
        score_item(items[3], [conf]),        # confirmed
        score_item(items[4], []),            # clean ok
        score_item(items[5], [clean_conf]),  # confirmed-fp
    ]
    m = aggregate(items, scores)
    assert m.n_vulnerable == 4
    assert m.n_clean == 2
    assert m.confirmed_finds == 2
    assert m.located_finds == 3            # 2 confirmed + 1 hypothesis
    assert m.misses == 1
    assert m.recall_confirmed == 0.5       # 2/4
    assert m.recall_located == 0.75        # 3/4
    assert m.confirmed_pov_rate == round(2 / 3, 4)
    assert m.confirmed_fps_items == 1
    assert m.fp_rate_confirmed == 0.5      # 1/2
    # precision over confirmed findings: 2 TP, 1 FP (the clean confirmed) -> 2/3
    assert m.confirmed_tp_findings == 2
    assert m.confirmed_fp_findings == 1
    assert m.precision_confirmed == round(2 / 3, 4)


def test_aggregate_empty_is_safe() -> None:
    m = aggregate([], [])
    assert m.recall_confirmed == 0.0
    assert m.precision_confirmed == 0.0


# --- held-out --------------------------------------------------------------

def test_heldout_fully_disjoint() -> None:
    items = [_vuln(id="a"), _vuln(id="b")]
    h = heldout_summary(items)
    assert h.fully_held_out is True
    assert h.held_out == 2
    assert h.seeded_ids == []


def test_heldout_flags_seeded_items() -> None:
    items = [_vuln(id="a", in_seed_set=True), _vuln(id="b", in_seed_set=False)]
    h = heldout_summary(items)
    assert h.fully_held_out is False
    assert h.in_seed_set == 1
    assert h.seeded_ids == ["a"]


# --- lane discipline (PART B — MockLLM is the CI floor, never a capability #) --

def test_mock_lane_is_ci_floor_not_capability() -> None:
    label, is_cap = lane_label("mock")
    assert label == GROUNDTRUTH_CI_LANE
    assert is_cap is False
    label, is_cap = lane_label(None)
    assert label == GROUNDTRUTH_CI_LANE
    assert is_cap is False


def test_real_llm_lane_is_capability() -> None:
    for prov in ("codex", "claude", "openai", "glm"):
        label, is_cap = lane_label(prov)
        assert label == GROUNDTRUTH_CAPABILITY_LANE
        assert is_cap is True


def test_format_report_stamps_lane_banner() -> None:
    items = [_vuln(id="v1")]
    scores = [score_item(items[0], [])]
    m = aggregate(items, scores)
    h = heldout_summary(items)
    rendered = format_report(m, h, scores, lane=GROUNDTRUTH_CI_LANE)
    assert GROUNDTRUTH_CI_LANE in rendered
    assert rendered.startswith("> **Lane:")
    # default (no lane) keeps the old header-first shape
    assert format_report(m, h, scores).startswith("### Headline metrics")


# --- manifest loader -------------------------------------------------------

def test_load_manifest_roundtrip(tmp_path: Path) -> None:
    data = {
        "schema_version": GROUNDTRUTH_SCHEMA_VERSION,
        "items": [
            _vuln(id="v1").to_dict(),
            _clean(id="c1").to_dict(),
        ],
    }
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    man = load_manifest(p)
    assert len(man.items) == 2
    assert len(man.vulnerable) == 1
    assert len(man.clean) == 1


def test_load_manifest_rejects_duplicate_ids(tmp_path: Path) -> None:
    data = {
        "schema_version": GROUNDTRUTH_SCHEMA_VERSION,
        "items": [_vuln(id="dup").to_dict(), _clean(id="dup").to_dict()],
    }
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate corpus id"):
        load_manifest(p)


def test_load_manifest_rejects_bad_schema(tmp_path: Path) -> None:
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"schema_version": "2.0", "items": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="incompatible manifest schema"):
        load_manifest(p)


def test_item_from_dict_ignores_unknown_keys() -> None:
    d = _vuln(id="z").to_dict()
    d["extra_future_field"] = "ignored"
    it = item_from_dict(d)
    assert it.id == "z"


def test_real_corpus_manifest_loads_and_is_held_out() -> None:
    """The shipped corpus manifest is valid and its real-cve tier is held-out."""
    manifest_path = (
        Path(__file__).resolve().parents[1] / "benchmarks" / "groundtruth" / "manifest.json"
    )
    if not manifest_path.exists():
        pytest.skip("corpus manifest not present")
    man = load_manifest(manifest_path)
    assert man.items, "manifest has items"
    real = [i for i in man.items if i.tier == "real-cve"]
    assert real, "manifest has a real-cve tier"
    assert all(not i.in_seed_set for i in real), "real-cve items are held-out"
    # every real-cve item carries a CVE id for provenance
    assert all(i.cve.startswith("CVE-") for i in real)
