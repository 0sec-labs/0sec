"""Tests for the post-training-cutoff CVE corpus (#49).

Covers the three credibility pieces the eval rests on: the manifest **loads**
(reusing ``zeroverse.groundtruth.load_manifest``), the **post-cutoff validator**
accepts a verifiable post-cutoff CVE and rejects a stale / unverifiable one, the
manifest agrees with ``provenance.json``, and the **scorer reuse** scores these
items correctly. No engine, no network — pure data + math.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse.groundtruth import (
    CorpusItem,
    aggregate,
    load_manifest,
    score_item,
    validate_post_cutoff,
)

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "benchmarks" / "cve2026" / "manifest.json"
PROVENANCE = ROOT / "benchmarks" / "cve2026" / "provenance.json"


def _cutoff() -> str:
    return str(json.loads(MANIFEST.read_text())["training_cutoff"])


# --- manifest loads + is well-formed --------------------------------------

def test_cve2026_manifest_loads() -> None:
    man = load_manifest(MANIFEST)
    assert man.items, "empty manifest"
    # vulnerable/fixed pairs, all real-cve, all held out
    assert len(man.vulnerable) == len(man.clean)
    for it in man.items:
        assert it.tier == "real-cve"
        assert it.cve.startswith("CVE-2026-")
        assert it.in_seed_set is False
        assert it.publish_date and it.nvd_url and it.fix_commit


def test_every_vuln_has_a_fixed_control() -> None:
    man = load_manifest(MANIFEST)
    vuln_pairs = {i.pair_id for i in man.vulnerable}
    clean_pairs = {i.pair_id for i in man.clean}
    assert vuln_pairs == clean_pairs, "every vulnerable item needs a -DFIXED control"


# --- post-cutoff validator -------------------------------------------------

def test_manifest_passes_post_cutoff_gate() -> None:
    man = load_manifest(MANIFEST)
    issues = validate_post_cutoff(man.items, _cutoff())
    assert issues == [], f"manifest must be all post-cutoff: {[i.to_dict() for i in issues]}"


def _vuln(**kw: object) -> CorpusItem:
    base: dict[str, object] = {
        "id": "v", "name": "v", "label": "vulnerable", "tier": "real-cve",
        "cwe": "CWE-787", "cve": "CVE-2026-9999", "provenance": "p", "in_seed_set": False,
        "expected_function": "f", "expected_sink": "memcpy",
        "publish_date": "2026-06-01", "nvd_url": "https://nvd.nist.gov/x",
        "fix_commit": "https://github.com/x/y/commit/abc",
    }
    base.update(kw)
    return CorpusItem(**base)  # type: ignore[arg-type]


def test_validator_flags_pre_cutoff_date() -> None:
    issues = validate_post_cutoff([_vuln(publish_date="2025-11-01")], "2026-01-31")
    assert any("not after the training cutoff" in i.problem for i in issues)


def test_validator_flags_missing_provenance() -> None:
    issues = validate_post_cutoff([_vuln(nvd_url="", fix_commit="")], "2026-01-31")
    problems = {i.problem for i in issues}
    assert "missing nvd_url" in problems
    assert "missing fix_commit reference" in problems


def test_validator_flags_unparseable_date() -> None:
    issues = validate_post_cutoff([_vuln(publish_date="June 2026")], "2026-01-31")
    assert any("unparseable" in i.problem for i in issues)


def test_validator_ignores_non_real_cve_tier() -> None:
    item = _vuln(tier="sanity-floor", cve="", nvd_url="", fix_commit="", publish_date="")
    assert validate_post_cutoff([item], "2026-01-31") == []


def test_validator_rejects_bad_cutoff() -> None:
    with pytest.raises(ValueError, match="cutoff is not an ISO date"):
        validate_post_cutoff([_vuln()], "not-a-date")


# --- manifest <-> provenance.json cross-check ------------------------------

def test_provenance_matches_manifest() -> None:
    man = load_manifest(MANIFEST)
    prov = json.loads(PROVENANCE.read_text())
    by_cve = {c["cve"]: c for c in prov["cves"]}
    assert prov["training_cutoff"] == _cutoff()
    for it in man.items:
        assert it.cve in by_cve, f"{it.cve} missing from provenance.json"
        rec = by_cve[it.cve]
        assert rec["publish_date"] == it.publish_date
        assert rec["nvd_url"] == it.nvd_url


# --- scorer reuse on these items ------------------------------------------

def test_scorer_reuse_confirmed_and_fp() -> None:
    man = load_manifest(MANIFEST)
    vuln = man.vulnerable[0]
    clean = next(i for i in man.clean if i.pair_id == vuln.pair_id)

    assert vuln.expected_function is not None
    hit = {"function": vuln.expected_function, "source": "read",
           "sink": vuln.expected_sink, "confirmed": True, "hypothesis": True}
    sv = score_item(vuln, [hit])
    sc = score_item(clean, [])              # fixed build, no finding
    metrics = aggregate([vuln, clean], [sv, sc])
    assert metrics.confirmed_finds == 1
    assert metrics.recall_confirmed == 1.0
    assert metrics.fp_rate_confirmed == 0.0

    # a confirmed PoV on the FIXED build is a false positive
    sc_fp = score_item(clean, [{**hit, "function": clean.pair_id}])
    assert sc_fp.confirmed_fp == 1
