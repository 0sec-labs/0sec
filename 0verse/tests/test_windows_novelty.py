"""Hermetic tests for the driver novelty/CVE gate (no network)."""

from __future__ import annotations

from zeroverse.windows_novelty import (
    KNOWN_ADVISORY,
    KNOWN_CVE,
    NO_PUBLIC_RECORD,
    DriverIdentity,
    SearchHit,
    StaticSearcher,
    assess_novelty,
    classify_hits,
)


def test_query_builder_dedups_and_includes_vendor_and_family() -> None:
    ident = DriverIdentity("RwDrv.sys", vendor="ChristianWurm", device_family="RwDrv")
    qs = ident.search_queries()
    assert any(q == "RwDrv.sys CVE" for q in qs)
    assert any(q.startswith("ChristianWurm ") for q in qs)
    assert len(qs) == len({q.lower() for q in qs})  # de-duped
    # device_family == stem here, so no separate family query is added
    assert ident.stem == "rwdrv"


def test_known_cve_from_relevant_hit() -> None:
    ident = DriverIdentity("segwindrvx64.sys", vendor="Insyde Software")
    hits = [
        SearchHit(
            query="segwindrvx64.sys CVE",
            title="CVE-2024-33228 · segwindrvx64.sys of Insyde SEG Windows Driver",
            url="https://nvd.nist.gov/vuln/detail/CVE-2024-33228",
            snippet="allows attackers to escalate privileges via crafted IOCTL",
        )
    ]
    verdict, cves, _adv, known = classify_hits(ident, hits)
    assert verdict == KNOWN_CVE
    assert cves == ("CVE-2024-33228",)
    assert known  # nvd url is also a known-signal


def test_generic_byovd_roundup_not_attributed() -> None:
    # A generic 'hunting vulnerable drivers' article that never names THIS driver
    # must NOT mark it KNOWN — attribution requires the filename stem or family.
    ident = DriverIdentity("obscureoemx64.sys", vendor="ObscureOEM")
    hits = [
        SearchHit(
            query="obscureoemx64.sys CVE",
            title="Hunting Vulnerable Kernel Drivers - loldrivers BYOVD roundup",
            url="https://example.com/byovd",
            snippet="a survey of vulnerable drivers including RwDrv and dbutil",
        )
    ]
    verdict, cves, _adv, known = classify_hits(ident, hits)
    assert verdict == NO_PUBLIC_RECORD
    assert cves == ()
    assert known == ()


def test_known_advisory_without_cve_id() -> None:
    ident = DriverIdentity("rtkio64.sys")
    hits = [
        SearchHit(
            query="rtkio64.sys vulnerable driver IOCTL",
            title="rtkio64.sys — loldrivers.io entry",
            url="https://www.loldrivers.io/drivers/rtkio64",
            snippet="known vulnerable driver used in BYOVD",
        )
    ]
    verdict, cves, _adv, known = classify_hits(ident, hits)
    assert verdict == KNOWN_ADVISORY
    assert cves == ()
    assert known


def test_no_public_record_verdict_and_caveat() -> None:
    ident = DriverIdentity("madeupdriver_zzz.sys")
    assessment = assess_novelty(ident, StaticSearcher(hits=()))
    assert assessment.verdict == NO_PUBLIC_RECORD
    assert assessment.label() == NO_PUBLIC_RECORD
    d = assessment.to_dict()
    assert d["caveat"]  # honest caveat present exactly on the no-record verdict
    assert "not proof of novelty" in str(d["caveat"]).lower()
    assert d["cve_ids"] == []


def test_assess_pools_and_labels_known_cve() -> None:
    ident = DriverIdentity("segwindrvx64.sys", vendor="Insyde Software")
    searcher = StaticSearcher(
        hits=(
            SearchHit(
                query="",  # empty query matches every derived query
                title="CVE-2024-33228 GHSA-42xq-25q2-4fv9 segwindrvx64.sys Insyde",
                url="https://github.com/advisories/GHSA-42xq-25q2-4fv9",
                snippet="arbitrary kernel read write via IOCTL",
            ),
        )
    )
    a = assess_novelty(ident, searcher)
    assert a.verdict == KNOWN_CVE
    assert a.cve_ids == ("CVE-2024-33228",)
    assert a.advisory_ids == ("GHSA-42XQ-25Q2-4FV9",)
    assert a.label().startswith("KNOWN-CVE(")
    assert a.is_known
    # caveat is blank on a KNOWN verdict (only surfaced for NO-PUBLIC-RECORD)
    assert a.to_dict()["caveat"] == ""


def test_verdicts_are_never_a_novelty_claim() -> None:
    # No verdict value asserts novelty; the strongest is NO-PUBLIC-RECORD-FOUND.
    for verdict in (KNOWN_CVE, KNOWN_ADVISORY, NO_PUBLIC_RECORD):
        assert "NOVEL" not in verdict.upper()
    # And the no-record verdict explicitly is not a synonym for novel.
    assert NO_PUBLIC_RECORD == "NO-PUBLIC-RECORD-FOUND"
